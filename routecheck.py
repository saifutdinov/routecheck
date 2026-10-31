#!/usr/bin/env python3
"""routecheck: find where the route to an IP breaks and in which network.

Local probes (ping, TCP, MTU, traceroute), the target's BGP/RPKI state
(RIPEstat), mtr from remote probes in chosen countries/networks (Globalping),
then a comparison of working and broken paths by AS. Stdlib only.
"""

import argparse
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

GP = "https://api.globalping.io/v1/measurements"
RIPE = "https://stat.ripe.net/data/{}/data.json?{}"
WIN = sys.platform == "win32"
TRACE_PROBES = 3  # probes per hop, the default of both traceroute -q and tracert
LOCAL = "этот компьютер"  # source label of the local trace

Hop = dict  # {"ip", "host", "asn", "loss", "rtt"}
Path = dict  # {"source", "proto", "hops", "diag", "error"?}


# ---------- I/O ----------


def http_json(url: str, body: dict | None = None, timeout: float = 20) -> dict:
    headers = {"User-Agent": "routecheck/0.1", "Content-Type": "application/json"}
    if url.startswith(GP) and os.environ.get("GLOBALPING_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GLOBALPING_TOKEN"]
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data, headers), timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{url}: HTTP {e.code} {e.read().decode(errors='replace')[:300]}") from e


# Windows console tools print in the OEM code page (cp866 for Russian), not the ANSI one
ENCODING = "oem" if WIN else None


def run(cmd: list[str], timeout: float) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding=ENCODING, errors="replace", timeout=timeout
        ).stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout or b""
        return out.decode(ENCODING or "utf-8", errors="replace") if isinstance(out, bytes) else out
    except FileNotFoundError as e:
        hint = " (sudo apt install traceroute или sudo dnf install traceroute)" if cmd[0] == "traceroute" else ""
        raise RuntimeError(f"не найдена команда {cmd[0]}{hint}") from e


def cymru(queries: list[str]) -> list[list[str]]:
    """Team Cymru bulk whois; returns rows split by '|'."""
    if not queries:
        return []
    with socket.create_connection(("whois.cymru.com", 43), 10) as s:
        s.sendall(("begin\nverbose\n" + "\n".join(queries) + "\nend\n").encode())
        buf = b""
        while chunk := s.recv(4096):
            buf += chunk
    return [[c.strip() for c in line.split("|")] for line in buf.decode().splitlines() if "|" in line]


def ip_owners(ips: list[str]) -> dict[str, int]:
    rows = cymru(sorted(set(ips)))
    return {r[1]: int(r[0].split()[0]) for r in rows if len(r) == 7 and r[0] != "NA"}


def as_names(asns: set[int]) -> dict[int, str]:
    rows = cymru([f"AS{a}" for a in sorted(set(asns))])
    return {int(r[0]): r[4] for r in rows if len(r) == 5 and r[0].isdigit()}


def rdns(ips: list[str]) -> dict[str, str | None]:
    def one(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return None

    with cf.ThreadPoolExecutor(16) as ex:
        return dict(zip(ips, ex.map(one, ips), strict=True))


def ix_ports(ips: list[str]) -> tuple[dict[str, tuple[int, str]], list[str]]:
    """IX peering-LAN address -> (member ASN, IX name). Such LANs are not in BGP, PeeringDB knows them."""
    found, errs = {}, []
    for ip in ips:
        try:
            rows = http_json(f"https://www.peeringdb.com/api/netixlan?ipaddr4={ip}")["data"]
        except (OSError, RuntimeError, ValueError) as e:
            errs.append(f"PeeringDB {ip}: {e}")
            continue
        if rows:
            found[ip] = (rows[0]["asn"], rows[0]["name"].split(":")[0])
    return found, errs


def resolve(target: str) -> str:
    try:
        return str(ipaddress.IPv4Address(target))
    except ValueError:
        return socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]


# ---------- local probes ----------


def ping_cmd(ip: str, size: int | None, count: int, platform: str = sys.platform) -> list[str]:
    """ping with a fixed count, optionally a payload of `size` bytes with Don't Fragment set."""
    if platform == "win32":
        return ["ping", "-n", str(count), "-w", "2000", *(["-f", "-l", str(size)] if size else []), ip]
    mac = platform == "darwin"
    df = (["-D"] if mac else ["-M", "do"]) + ["-s", str(size)] if size else []
    return ["ping", "-n", "-c", str(count), *df, "-t" if mac else "-w", "6", ip]


def ping_loss(text: str, count: int) -> float:
    """Loss in % from ping output on any OS and language: only real echo replies carry TTL."""
    replies = sum(1 for line in text.splitlines() if re.search(r"\bttl[=:]\s*\d+", line, re.IGNORECASE))
    return max(0.0, 100.0 * (count - replies) / count)


def ping(ip: str, size: int | None = None, count: int = 4) -> float:
    return ping_loss(run(ping_cmd(ip, size, count), 20), count)


def tcp_connect(ip: str, port: int, timeout: float = 5) -> tuple[float | None, str | None]:
    t = time.monotonic()
    try:
        socket.create_connection((ip, port), timeout).close()
        return round((time.monotonic() - t) * 1000, 1), None
    except OSError as e:
        return None, str(e) or type(e).__name__


def parse_traceroute(text: str) -> list[Hop]:
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*\d+\s+(.*)$", line)
        if not m:
            continue
        fields = m.group(1).split()
        ips = [f for f in fields if is_ip(f)]
        # Windows prints "<1 ms" / "<1 мс"; loss is counted from stars, so an unknown unit only loses the RTT
        rtts = [float(x) for x in re.findall(r"([\d.]+)\s*(?:ms|мс)", m.group(1))]
        stars = fields.count("*")
        hops.append(
            {
                "ip": ips[0] if ips else None,
                "host": None,
                "asn": None,
                "loss": 100 * min(stars, TRACE_PROBES) / TRACE_PROBES if ips else 100.0,
                "rtt": round(sum(rtts) / len(rtts), 1) if rtts else None,
            }
        )
    return hops


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def trace_cmds(ip: str, max_hops: int, platform: str = sys.platform) -> list[list[str]]:
    """Commands to try in order; tracert is ICMP and needs no admin rights."""
    if platform == "win32":
        return [["tracert", "-d", "-h", str(max_hops), "-w", "1000", ip]]
    base = ["traceroute", "-n", "-q", str(TRACE_PROBES), "-w", "1", "-m", str(max_hops)]
    # ICMP traceroute needs root on Linux; fall back to UDP there
    return [base + ["-I", ip], base + [ip]]


def local_trace(ip: str, max_hops: int) -> list[Hop]:
    for cmd in trace_cmds(ip, max_hops):
        if hops := parse_traceroute(run(cmd, 150)):
            return hops
    return []


def local_checks(ip: str, port: int | None, max_hops: int) -> tuple[dict, Path]:
    path = {"source": LOCAL, "proto": "ICMP", "hops": []}
    with cf.ThreadPoolExecutor() as ex:
        trace = ex.submit(local_trace, ip, max_hops)
        r = {"ping_loss": ping(ip), "mtu_loss": ping(ip, size=1472)}
        if port:
            r["tcp_ms"], r["tcp_error"] = tcp_connect(ip, port)
        try:
            path["hops"] = trace.result()
        except RuntimeError as e:  # no traceroute installed: keep ping and TCP results
            path["error"] = str(e)
    return r, path


# ---------- remote probes (Globalping) ----------


def globalping(ip: str, protocol: str, port: int | None, locations: list[dict] | str) -> tuple[str, list[Path]]:
    opts = {"protocol": protocol, "packets": 5}
    if protocol == "TCP":
        opts["port"] = port
    mid = http_json(GP, {"type": "mtr", "target": ip, "locations": locations, "measurementOptions": opts})["id"]
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        time.sleep(1)
        m = http_json(f"{GP}/{mid}")
        if m["status"] != "in-progress":
            return mid, [remote_path(r, protocol if protocol == "ICMP" else f"TCP {port}") for r in m["results"]]
    raise TimeoutError(f"Globalping {mid}: нет результата за 120 с")


def remote_path(r: dict, proto: str) -> Path:
    p, res = r["probe"], r["result"]
    hops = [
        {
            "ip": h["resolvedAddress"],
            "host": h["resolvedHostname"],
            "asn": (h["asn"] or [None])[0],
            "loss": h["stats"]["loss"],
            "rtt": h["stats"]["avg"],
        }
        for h in res.get("hops") or []
    ]
    path = {"source": f"{p['city']}, {p['country']} ({p['network']})", "proto": proto, "hops": hops}
    if res["status"] != "finished":
        path["error"] = (res.get("rawOutput") or res["status"]).strip()[:300]
    return path


def remote_checks(ip: str, locations: list[str], probes: int, port: int | None) -> list[Path]:
    mid, paths = globalping(ip, "ICMP", None, [{"magic": loc, "limit": probes} for loc in locations])
    if port:
        paths += globalping(ip, "TCP", port, mid)[1]  # passing the id reuses the same probes
    return paths


# ---------- BGP (RIPEstat) ----------


def bgp_info(ip: str) -> dict:
    net = http_json(RIPE.format("network-info", f"resource={ip}"))["data"]
    info = {"prefix": net.get("prefix") or None, "origins": [int(a) for a in net.get("asns") or []]}
    if not info["prefix"]:
        return info
    vis = http_json(RIPE.format("routing-status", f"resource={info['prefix']}"))["data"]["visibility"]["v4"]
    info["visibility"] = [vis["ris_peers_seeing"], vis["total_ris_peers"]]
    info["rpki"] = {
        a: http_json(RIPE.format("rpki-validation", f"resource={a}&prefix={info['prefix']}"))["data"]["status"]
        for a in info["origins"]
    }
    return info


def upstreams(asn: int) -> list[tuple[int, int]]:
    """Neighbours on the collectors' side of the AS (upstreams and peers), strongest first."""
    n = http_json(RIPE.format("asn-neighbours", f"resource=AS{asn}"))["data"]["neighbours"]
    return sorted(((x["asn"], x["power"]) for x in n if x["type"] == "left"), key=lambda x: -x[1])


def ris_paths(prefix: str) -> list[tuple[str, list[int]]]:
    """(collector location, AS path) for every RIPE RIS peer that sees the prefix."""
    d = http_json(RIPE.format("looking-glass", f"resource={prefix}"))["data"]
    return [
        (r["location"], [int(a) for a in p["as_path"].split() if a.isdigit()]) for r in d["rrcs"] for p in r["peers"]
    ]


# ---------- metadata ----------


def _maxmind(d: dict) -> tuple[str, str]:
    loc = d["data"]["located_resources"][0]["locations"][0]
    return loc["country"], loc["city"]


GEO_SOURCES = {
    "MaxMind GeoLite": ("https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={}", _maxmind),
    "ip-api.com": ("http://ip-api.com/json/{}?fields=countryCode,city", lambda d: (d["countryCode"], d["city"])),
    "ipapi.co": ("https://ipapi.co/{}/json/", lambda d: (d["country_code"], d["city"])),
    "ipwho.is": ("https://ipwho.is/{}", lambda d: (d["country_code"], d["city"])),
}


def geoip(ip: str) -> dict[str, list | str]:
    """Country and city from several GeoIP databases: name -> [cc, city] or an error string."""
    sources = dict(GEO_SOURCES)
    if os.environ.get("IPINFO_TOKEN"):
        sources["IPinfo Lite"] = (
            "https://api.ipinfo.io/lite/{}?token=" + os.environ["IPINFO_TOKEN"],
            lambda d: (d["country_code"], ""),
        )

    def one(src: tuple) -> list | str:
        url, parse = src
        try:
            cc, city = parse(http_json(url.format(ip)))
            return [cc, city or ""] if cc and cc != "?" else "нет данных"
        except (OSError, RuntimeError, ValueError, KeyError, IndexError) as e:
            return f"{type(e).__name__}: {e}"[:120]

    with cf.ThreadPoolExecutor() as ex:
        return dict(zip(sources, ex.map(one, sources.values()), strict=True))


def _entities(es: list | None):
    for e in es or []:
        yield e
        yield from _entities(e.get("entities"))


def rdap(ip: str) -> dict:
    """Registration record from the responsible RIR/NIR (rdap.org redirects to it)."""
    d = http_json(f"https://rdap.org/ip/{ip}")
    org, abuse = None, set()
    for e in _entities(d.get("entities")):
        card = {v[0]: v[3] for v in (e.get("vcardArray") or [None, []])[1]}
        if "abuse" in e.get("roles", []) and card.get("email"):
            abuse.add(card["email"])
        if not org and "registrant" in e.get("roles", []) and "MNT" not in e.get("handle", ""):
            org = card.get("fn")
    return {
        "name": d.get("name"),
        "org": org,
        "country": d.get("country"),
        "abuse": sorted(abuse),
        "whois": d.get("port43"),
    }


def country_networks(cc: str) -> list[dict]:
    """Networks of a country by estimated user share (APNIC Labs)."""
    return http_json(f"https://stats.labs.apnic.net/cgi-bin/aspopjson?c={cc}")


def public_ip() -> str:
    with urllib.request.urlopen("https://api.ipify.org", timeout=10) as r:
        return r.read().decode().strip()


def reverse_checks(source_ip: str, target_asn: int | None, target_cc: str | None, probes: int) -> list[Path]:
    """mtr from inside the target's network (or at least its country) back to the source."""
    for loc in [f"AS{target_asn}" if target_asn else None, target_cc]:
        if not loc:
            continue
        try:
            paths = globalping(source_ip, "ICMP", None, [{"magic": loc, "limit": probes}])[1]
        except RuntimeError as e:
            if "no_probes_found" in str(e):
                continue
            raise
        for p in paths:
            p["proto"], p["target"], p["via"] = "ICMP", source_ip, loc
        return paths
    return []


# ---------- analysis (pure) ----------


def as_path(hops: list[Hop]) -> list[int]:
    path = []
    for h in hops:
        if h["asn"] and (not path or path[-1] != h["asn"]):
            path.append(h["asn"])
    return path


def diagnose(hops: list[Hop], target_ip: str) -> dict:
    alive = [i for i, h in enumerate(hops) if h["ip"] and h["loss"] < 100]
    d = {
        "reached": any(hops[i]["ip"] == target_ip for i in alive),
        "last": alive[-1] if alive else None,
        "loss_from": None,
    }
    # loss that persists to the last answering hop is real; loss that disappears
    # further on is just a router rate-limiting its ICMP replies
    for i in alive:
        if all(hops[j]["loss"] > 0 for j in alive if j >= i):
            d["loss_from"] = i
            break
    # private hops after entering a network belong to it, so judge by the last known AS
    d["last_asn"] = next((hops[i]["asn"] for i in reversed(alive) if hops[i]["asn"]), None)
    return d


def asl(asn: int | None, names: dict[int, str]) -> str:
    return f"AS{asn} {names.get(asn, '')}".strip() if asn else "AS?"


LEGAL = {"JSC", "PJSC", "OJSC", "CJSC", "AO", "PAO", "OOO", "LLC", "LTD", "LIMITED", "GMBH", "AB", "AG", "SA", "SAU"}
LEGAL |= {"SL", "SLU", "INC", "BV", "PLC", "CO", "SRL", "SPA", "SAS", "NV", "OY", "KG"}


def org(asn: int | None, names: dict[int, str]) -> str:
    """Readable network name: 'VODAFONE_ES - VODAFONE ESPANA S.A.U., ES' -> 'Vodafone Espana'."""
    if not asn:
        return "неизвестная сеть"
    handle, _, descr = names.get(asn, "").partition(" - ")
    descr = re.sub(r",\s*[A-Z]{2}$", "", descr)
    source = descr if " " in descr.strip() else re.sub(r"-ASN?(-AP)?$", "", handle)
    words = [w for w in re.split(r"[\s,_]+", source) if w.strip("&") and w.upper().replace(".", "") not in LEGAL]
    name = " ".join(words)
    if not name:
        return f"AS{asn}"
    return name.title() if name.isupper() and len(name) > 4 else name


def orgs(asns, names: dict[int, str]) -> str:
    return ", ".join(org(a, names) for a in asns)


def verdict(
    d: dict,
    hops: list[Hop],
    target_asn: int | None,
    names: dict[int, str],
    neighbours: set[int] = frozenset(),
    mine: bool = False,
) -> tuple[str, str]:
    """(status, plain explanation) for one trace; status is ok, warn or fail."""
    if d["reached"]:
        if d["loss_from"] is None:
            return "ok", "адрес отвечает, потерь нет"
        h = hops[d["loss_from"]]
        return "warn", (
            f"адрес отвечает, но теряется {hops[d['last']]['loss']:.0f}% пакетов; "
            f"потери начинаются в сети {org(h['asn'], names)} ({h['ip']})"
        )
    if d["last"] is None:
        return "fail", "не ответил ни один узел: проблема рядом с точкой проверки или трафик режут сразу"
    last = d["last_asn"]
    if target_asn and last == target_asn:
        if mine:
            return "ok", (
                f"дошли до вашего провайдера ({org(last, names)}); дальше молчит ваш роутер "
                "или NAT провайдера, это нормально"
            )
        return "warn", (
            f"дошли до сети {org(last, names)}, но сам адрес не ответил: устройства нет, "
            "оно выключено или не отвечает на такие запросы"
        )
    if last in neighbours:
        return "warn", (
            f"дошли до {org(last, names)}, соседа сети {org(target_asn, names)}; дальше адрес не ответил. "
            "Маршрут до сети, скорее всего, в порядке"
        )
    return (
        "fail",
        f"обрыв: последний ответ от сети {org(last, names)} ({hops[d['last']]['ip']}), дальше пакеты пропадают",
    )


def headline(
    paths: list[Path],
    target_asn: int | None,
    near: set[int],
    names: dict[int, str],
    local: dict | None = None,
    port: int | None = None,
) -> tuple[str, str]:
    """One-sentence answer for the forward checks."""
    done = [p for p in paths if p["hops"]]
    ok = [p for p in done if p["diag"]["reached"]]
    if not paths:
        return "info", "Маршрут не проверялся: добавьте -f СТРАНА или уберите --no-local."
    # no trace got through, yet the address answers locally; not when a remote TCP trace failed,
    # then the port itself is blocked somewhere
    if not ok and local and not any(p["proto"].startswith("TCP") for p in done):
        if local["ping_loss"] < 100 and all(p["source"] == LOCAL for p in done):
            return "ok", (
                "Адрес доступен: отвечает на ping. Трассировка не дошла до конца: не хватило --max-hops "
                "или узлы на пути не отвечают на трассировку."
            )
        if local["ping_loss"] == 100 and local.get("tcp_ms"):
            return "ok", (
                f"Адрес доступен: порт {port} отвечает ({local['tcp_ms']} мс). Ping и трассировка не доходят, "
                "потому что ICMP режут на пути или у цели. На работу сервиса это не влияет."
            )
    if not done:
        return "fail", "Ни одна проверка маршрута не выполнилась."
    if len(ok) == len(done):
        return "ok", f"Адрес доступен из всех точек проверки ({len(done)})."
    if not ok:
        if all(p["diag"]["last_asn"] in near for p in done):
            return "warn", (
                f"Сеть {org(target_asn, names)} доступна из всех точек проверки ({len(done)}), но сам адрес "
                "не отвечает. Скорее всего, на нём нет устройства или оно не отвечает на такие запросы."
            )
        return "fail", (
            "Адрес недоступен ни из одной точки проверки. Скорее всего, проблема на стороне цели "
            "(её сеть, маршрутизация или файрвол), а не где-то на пути."
        )
    bad = ", ".join(f"{p['source']} ({proto_text(p)})" for p in done if not p["diag"]["reached"])
    return "fail", f"Адрес доступен из {len(ok)} проверок из {len(done)}. Не работает: {bad}."


def proto_text(p: Path) -> str:
    return "ping" if p["proto"].startswith("ICMP") else f"порт {p['proto'].split()[-1]}"


def compare(paths: list[Path], names: dict[int, str]) -> list[str]:
    """Findings from working vs broken paths: per probe across protocols, then per protocol across probes."""
    out = []
    by_source: dict[str, dict[str, bool]] = {}
    for p in paths:
        if p["hops"]:
            by_source.setdefault(p["source"], {})[p["proto"]] = p["diag"]["reached"]
    for source, reached in by_source.items():
        closed = [proto.replace("TCP", "порт") for proto, ok in reached.items() if not ok]
        if reached.get("ICMP") and closed:
            out.append(
                f"{source}: ping доходит, а подключение ({', '.join(closed)}) нет. Значит, маршрут в порядке, "
                "а блокируют сам порт или протокол: фильтрация на пути (DPI, в России ТСПУ), файрвол "
                "или геоблок у цели, либо порт закрыт."
            )
    for proto in dict.fromkeys(p["proto"] for p in paths):
        group = [p for p in paths if p["proto"] == proto and p["hops"]]
        good = [as_path(p["hops"]) for p in group if p["diag"]["reached"]]
        bad = [p for p in group if not p["diag"]["reached"]]
        if not bad or not good:
            continue  # all-good or all-bad is what the headline says
        good_ases = {a for g in good for a in g}
        for p in bad:
            last = p["diag"]["last_asn"]
            nxt = {g[g.index(last) + 1] for g in good if last in g and g.index(last) + 1 < len(g)}
            if nxt:
                out.append(
                    f"{p['source']}: трафик доходит до {org(last, names)}, а в работающих маршрутах дальше идёт "
                    f"{orgs(sorted(nxt), names)}. Скорее всего, проблема на стыке этих сетей "
                    "(или на обратном пути)."
                )
        if len(bad) >= 2:
            common = set.intersection(*(set(as_path(p["hops"])) for p in bad)) - good_ases
            if common:
                out.append(
                    f"{orgs(sorted(common), names)}: есть во всех неработающих маршрутах и ни в одном работающем. "
                    "Проверьте в первую очередь (если точки в разных регионах, это может быть совпадением)."
                )
    return out


def global_findings(local: dict | None, bgp: dict | None, port: int | None, traced: bool = True) -> list[str]:
    """`traced`: some trace reached the target; otherwise the headline already explains filtered ping."""
    out = []
    if local:
        if local["ping_loss"] == 100 and local.get("tcp_ms") and traced:
            out.append(f"Ping не проходит, а порт {port} отвечает: ping просто запрещён, сам сервис доступен.")
        if local["ping_loss"] < 100 and local["mtu_loss"] == 100:
            out.append(
                "Маленькие пакеты проходят, а полноразмерные (1500 байт) нет. Так бывает, когда на пути ломается "
                "подбор размера пакета (MTU): сайты могут зависать при загрузке. С VPN или PPPoE это бывает нормой."
            )
    if bgp:
        if not bgp["prefix"]:
            out.append("Адрес не анонсируется в интернет: ни один маршрутизатор RIPE RIS не знает, как до него дойти.")
        seen, total = bgp.get("visibility") or (0, 0)
        if total and seen / total < 0.9:
            out.append(
                f"Маршрут к сети видят только {seen} из {total} точек наблюдения RIPE RIS: "
                "часть интернета не знает, как дойти до адреса."
            )
        for asn, st in (bgp.get("rpki") or {}).items():
            if st.startswith("invalid"):
                out.append(
                    f"Маршрут к {bgp['prefix']} (AS{asn}) не проходит проверку RPKI ({st}). Многие провайдеры такие "
                    "маршруты отбрасывают, поэтому из одних сетей адрес доступен, а из других нет. "
                    "Исправить может только владелец сети."
                )
    return out


def dedup(path: list[int]) -> list[int]:
    """Drop AS prepends."""
    return [a for i, a in enumerate(path) if i == 0 or path[i - 1] != a]


def transit_summary(paths: list[tuple[str, list[int]]], origin: int) -> list[tuple[int, int]]:
    """Which AS hands the prefix over to the rest of the world, by number of RIS peers."""
    c = Counter(p[-2] for p in (dedup(p) for _, p in paths) if len(p) >= 2 and p[-1] == origin)
    return c.most_common()


def regional_paths(paths: list[tuple[str, list[int]]], countries: set[str]) -> dict[str, list[list[int]]]:
    """Distinct AS paths seen by collectors in the given countries ("Moscow, RU" -> RU)."""
    out: dict[str, list[list[int]]] = {}
    for loc, p in paths:
        if loc.rsplit(",", 1)[-1].strip() in countries:
            seen = out.setdefault(loc, [])
            if (p := dedup(p)) not in seen:
                seen.append(p)
    return out


def majority_country(geo: dict[str, list | str]) -> str | None:
    ccs = [v[0] for v in geo.values() if isinstance(v, list) and v[0]]
    return Counter(ccs).most_common(1)[0][0] if ccs else None


def meta_findings(geo: dict, transit: list[tuple[int, int]], names: dict[int, str]) -> list[str]:
    out = []
    ccs = {v[0] for v in geo.values() if isinstance(v, list) and v[0]}
    if len(ccs) > 1:
        out.append(
            f"Базы геолокации расходятся в стране ({', '.join(sorted(ccs))}). Сервисы с геоблокировкой могут "
            "считать этот адрес другой страной и блокировать его."
        )
    total = sum(n for _, n in transit)
    if total >= 20 and transit[0][1] / total >= 0.9:
        name = org(transit[0][0], names)
        out.append(
            f"В интернет сеть выходит почти только через {name} ({transit[0][1] * 100 // total}% маршрутов). "
            f"Если у {name} проблемы, сеть недоступна целиком."
        )
    return out


def org_chain(hops: list[Hop]) -> list[dict]:
    """Answering hops grouped into consecutive networks; an IX hop marks where the next network was entered."""
    chain: list[dict] = []
    for h in hops:
        if not h["asn"] or h["loss"] >= 100:
            continue
        if chain and chain[-1]["asn"] == h["asn"]:
            chain[-1]["rtt"] = h["rtt"]
        else:
            chain.append({"asn": h["asn"], "ix": h.get("ix"), "rtt": h["rtt"]})
    return chain


def chain_text(chain: list[dict], names: dict[int, str]) -> str:
    if not chain:
        return "ни один узел с известной сетью не ответил"
    parts = []
    for s in chain:
        if s["ix"]:
            parts.append(f"точка обмена {s['ix']}")
        parts.append(org(s["asn"], names))
    rtt = chain[-1]["rtt"]
    return " → ".join(parts) + (f" ({rtt:.0f} мс)" if rtt is not None else "")


# ---------- report ----------

ICON = {"ok": "✔", "warn": "⚠", "fail": "✖", "info": "ℹ"}


def geo_text(geo: dict) -> str:
    groups: dict[str, list[str]] = {}
    for src, v in geo.items():
        if isinstance(v, list):
            groups.setdefault(", ".join(x for x in (v[1], v[0]) if x), []).append(src)
    if len(groups) == 1:
        return f"{next(iter(groups))} (все базы согласны)"
    return "; ".join(f"{place} ({', '.join(srcs)})" for place, srcs in groups.items()) or "неизвестно"


def route_health(bgp: dict | None) -> str:
    if not bgp or not bgp["prefix"]:
        return "адрес не анонсируется в интернет"
    seen, total = bgp.get("visibility") or (0, 0)
    states = set((bgp.get("rpki") or {}).values())
    if any(s.startswith("invalid") for s in states):
        sign = "⚠ не проходит проверку RPKI"
    elif states == {"valid"}:
        sign = "подписан (RPKI valid)"
    else:
        sign = "без подписи RPKI (это не ошибка)"
    return f"{bgp['prefix']}, её видят {seen} из {total} точек наблюдения RIPE RIS, маршрут {sign}"


def print_check(p: Path, target_asn: int | None, names: dict[int, str], neighbours=frozenset(), mine=False) -> None:
    if not p["hops"]:
        print(f"  ? {p['source']} · {proto_text(p)}: {p.get('error', 'нет данных')}")
        return
    status, text = verdict(p["diag"], p["hops"], target_asn, names, neighbours, mine)
    print(f"  {ICON[status]} {p['source']} · {proto_text(p)}")
    print(f"      {chain_text(org_chain(p['hops']), names)}")
    print(f"      {text}")


def print_summary(r: dict, names: dict[int, str]) -> None:
    t_asn, bgp, reg = r["target_asn"], r["bgp"], r["rdap"]
    title = f"{r['target']}" + (f" ({r['ip']})" if r["target"] != r["ip"] else "")
    print(f"{title} · {org(t_asn, names)} (AS{t_asn}), {r['country'] or '?'}\n")
    status, text = r["headline"]
    print(f"{ICON[status]} ИТОГ\n  {text}")

    print("\nЧЬЯ СЕТЬ")
    if reg:
        legal = f", юрлицо {reg['org']}" if reg["org"] else ""
        print(f"  Владелец:  {org(t_asn, names)} (AS{t_asn}){legal}, зарегистрирован в {reg['country'] or '?'}")
        print(f"  Жалобы:    {', '.join(reg['abuse']) or 'не указаны'}")
    print(f"  Где:       {geo_text(r['geoip'])}")
    mine = next((n for n in r["country_networks"] if n["asn"] == f"AS{t_asn}"), None)
    if mine:
        print(f"  Размер:    {mine['rank']}-й провайдер {r['country']}, около {mine['country-percent']}% пользователей")
    print(f"  Сеть:      {route_health(bgp)}")

    if r["transit"] or r["regional_paths"]:
        print("\nКАК СЕТЬ ПОДКЛЮЧЕНА К ИНТЕРНЕТУ")
        if r["transit"]:
            total = sum(n for _, n in r["transit"])
            if r["transit"][0][1] * 10 >= total:
                exits = ", ".join(f"{org(x, names)} {n * 100 // total}%" for x, n in r["transit"][:3])
                print(f"  Основные выходы: {exits}")
            else:
                print("  Главного провайдера нет: сеть подключена напрямую ко множеству сетей")
        for loc, ps in r["regional_paths"].items():
            print(f"  Как её видно из {loc}:")
            for p in ps[:3]:
                print(f"    {' → '.join(org(x, names) for x in p)}")

    local = r["local"]
    if local or r["paths"]:
        print("\nПРОВЕРКИ МАРШРУТА")
    if local:
        parts = [f"ping {'✔' if local['ping_loss'] < 100 else '✖'} потери {local['ping_loss']:.0f}%"]
        if r["port"]:
            parts.append(
                f"порт {r['port']} ✔ {local['tcp_ms']} мс"
                if local["tcp_ms"]
                else f"порт {r['port']} ✖ {local['tcp_error']}"
            )
        parts.append(f"пакеты 1500 байт {'✔' if local['mtu_loss'] < 100 else '✖'}")
        print(f"  С этого компьютера: {' · '.join(parts)}")
    for p in r["paths"]:
        print_check(p, t_asn, names, r["neighbours"])

    if r["source_ip"]:
        print(f"\nОБРАТНЫЙ ПУТЬ: от сети цели к вам ({r['source_ip']}, {org(r['source_asn'], names)})")
        for p in r["reverse"]:
            print_check(p, r["source_asn"], names, mine=True)
        if not r["reverse"]:
            print(f"  нет проб ни в сети цели, ни в её стране ({r['country']})")

    if r["findings"]:
        print("\nЧТО ЕЩЁ ЗАМЕТИЛИ")
        for f in r["findings"]:
            print(f"  • {f}")
    if r["errors"]:
        print("\nНе удалось получить: " + "; ".join(e[:90] for e in r["errors"]))
    if not r["details"]:
        print("\nПодробно по каждому узлу: --details, сырые данные: --json")


def print_details(r: dict, names: dict[int, str]) -> None:
    print("\n\n==================== ПОДРОБНОСТИ ====================")
    reg = r["rdap"]
    if reg:
        print(f"RDAP ({reg['whois'] or '?'}): {reg['name']}, {reg['org'] or '?'}, {reg['country'] or '?'}")
    print("GeoIP:")
    for src, v in r["geoip"].items():
        print(f"  {src:<16} {' '.join(x for x in v if x) if isinstance(v, list) else 'ошибка: ' + v}")
    if r["country_networks"]:
        print(f"Крупнейшие сети {r['country']} (APNIC Labs, доля пользователей):")
        for n in r["country_networks"][:5]:
            print(f"  {n['asn']:<9} {n['country-percent']:>3}%  {n['descr']}")
    if r["upstreams"]:
        print(f"Соседи AS{r['target_asn']} со стороны интернета (RIPEstat, сила связи):")
        print("  " + ", ".join(f"{org(x, names)} AS{x} ({p})" for x, p in r["upstreams"]))
    for loc, ps in r["regional_paths"].items():
        print(f"AS-пути с коллектора RIS {loc}:")
        for p in ps:
            print("  " + " > ".join(f"AS{x}" for x in p))
    for p, t_asn, mine in [(p, r["target_asn"], False) for p in r["paths"]] + [
        (p, r["source_asn"], True) for p in r["reverse"]
    ]:
        print(f"\n-- {p['source']} · {proto_text(p)}{' · обратно' if mine else ''}")
        if p.get("error"):
            print(f"  ошибка пробы: {p['error']}")
        for i, h in enumerate(p["hops"], 1):
            rtt = f"{h['rtt']:.1f} ms" if h["rtt"] is not None else ""
            print(
                f"  {i:>2}  {h['ip'] or '*':<16} {asl(h['asn'], names) if h['ip'] else '':<34.34} "
                f"{h['loss']:>4.0f}% {rtt:>9}  {h['host'] or ''}"
            )
        if p["hops"]:
            print(f"  => {verdict(p['diag'], p['hops'], t_asn, names, r['neighbours'], mine)[1]}")


def main() -> int:
    # redirected output on Windows defaults to cp1251/cp1252, which cannot encode the report's ✔ ⚠ →
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Где и в какой сети обрывается маршрут до IP.")
    ap.add_argument("target", help="IPv4 или имя хоста")
    ap.add_argument("-p", "--port", type=int, help="TCP-порт для проверки, например 443")
    ap.add_argument(
        "-f",
        "--from",
        dest="locations",
        action="append",
        default=[],
        help="откуда проверять через Globalping: страна, город, ASN, провайдер, "
        'комбинации через + ("RU", "Germany", "AS12389", "Moscow+Rostelecom"). Можно несколько раз',
    )
    ap.add_argument("-n", "--probes", type=int, default=2, help="проб на каждую локацию (по умолчанию 2)")
    ap.add_argument(
        "-r",
        "--region",
        action="append",
        default=[],
        help="код страны, для которой показать AS-пути с коллекторов RIPE RIS "
        "(страна цели и коды из --from добавляются сами). Можно несколько раз",
    )
    ap.add_argument(
        "--reverse",
        nargs="?",
        const="auto",
        metavar="IP",
        help="трассировать обратно из сети цели до IP (без значения: до вашего внешнего IP)",
    )
    ap.add_argument("--max-hops", type=int, default=30)
    ap.add_argument("--no-local", action="store_true", help="не запускать локальные проверки")
    ap.add_argument("-v", "--details", action="store_true", help="показать каждый узел маршрута и сырые BGP-данные")
    ap.add_argument("--json", action="store_true", help="вывести сырые данные в JSON")
    a = ap.parse_args()

    ip = resolve(a.target)
    if not a.json:
        print(f"Проверяю {a.target} ({ip})... это займёт до пары минут", file=sys.stderr)
    errors, res, local, paths = [], {}, None, []

    def collect(jobs: dict) -> None:
        for name, fut in jobs.items():
            try:
                res[name] = fut.result()
            except Exception as e:  # one failed source must not hide the others
                errors.append(f"{name}: {e}")

    with cf.ThreadPoolExecutor() as ex:
        slow = {}
        if not a.no_local:
            slow["локально"] = ex.submit(local_checks, ip, a.port, a.max_hops)
        if a.locations:
            slow["Globalping"] = ex.submit(remote_checks, ip, a.locations, a.probes, a.port)
        quick = {"BGP": ex.submit(bgp_info, ip), "GeoIP": ex.submit(geoip, ip), "RDAP": ex.submit(rdap, ip)}
        if a.reverse == "auto":
            quick["внешний IP"] = ex.submit(public_ip)
        collect(quick)
        # the second wave needs the target's AS, prefix and country
        bgp, geo, reg = res.get("BGP"), res.get("GeoIP", {}), res.get("RDAP")
        target_asn = bgp["origins"][0] if bgp and bgp["origins"] else None
        target_cc = majority_country(geo) or (reg or {}).get("country")
        second = {}
        if target_asn:
            second["соседи AS"] = ex.submit(upstreams, target_asn)
        if bgp and bgp["prefix"]:
            second["RIS"] = ex.submit(ris_paths, bgp["prefix"])
        if target_cc:
            second["APNIC Labs"] = ex.submit(country_networks, target_cc)
        source_ip = res.get("внешний IP") if a.reverse == "auto" else a.reverse
        if source_ip:
            second["обратный путь"] = ex.submit(reverse_checks, source_ip, target_asn, target_cc, a.probes)
        collect(second)
        collect(slow)
    if "локально" in res:
        local, local_path = res["локально"]
        paths.append(local_path)
    paths += res.get("Globalping", [])
    back = res.get("обратный путь", [])

    local_hops = [h for h in (paths[0]["hops"] if local else []) if h["ip"]]
    owners = ip_owners([h["ip"] for h in local_hops] + [ip])
    hosts = rdns([h["ip"] for h in local_hops])
    for h in local_hops:
        h["asn"], h["host"] = owners.get(h["ip"]), hosts.get(h["ip"])
    target_asn = target_asn or owners.get(ip)
    all_hops = [h for p in paths + back for h in p["hops"]]
    unknown = sorted(
        {h["ip"] for h in all_hops if h["ip"] and not h["asn"] and ipaddress.ip_address(h["ip"]).is_global}
    )
    ixs, ix_errors = ix_ports(unknown)
    errors += ix_errors
    for h in all_hops:
        if h["ip"] in ixs:
            h["asn"], h["ix"] = ixs[h["ip"]]
            h["host"] = f"[IX {h['ix']}] {h['host'] or ''}".strip()
    source_asn = ip_owners([source_ip]).get(source_ip) if source_ip else None

    ris = res.get("RIS", [])
    transit = transit_summary(ris, target_asn) if target_asn else []
    countries = {target_cc, *a.region, *(t.split("+")[0] for t in a.locations)}
    regional = regional_paths(ris, {c.upper() for c in countries if c and len(c) == 2})
    ups = res.get("соседи AS", [])[:6]
    nets = res.get("APNIC Labs") or []
    names = as_names(
        {h["asn"] for p in paths + back for h in p["hops"] if h["asn"]}
        | {x for x, _ in ups + transit[:5]}
        | {x for ps in regional.values() for p in ps[:5] for x in p}
        | {target_asn, source_asn} - {None}
    )
    for p in paths + back:
        p["diag"] = diagnose(p["hops"], p.get("target", ip))
    neighbours = {x for x, _ in res.get("соседи AS", [])}
    r = {
        "target": a.target,
        "ip": ip,
        "port": a.port,
        "target_asn": target_asn,
        "country": target_cc,
        "headline": headline(paths, target_asn, neighbours | {target_asn}, names, local, a.port),
        "bgp": bgp,
        "rdap": reg,
        "geoip": geo,
        "country_networks": nets[:20],
        "upstreams": ups,
        "neighbours": neighbours,
        "transit": transit,
        "regional_paths": regional,
        "local": local,
        "paths": paths,
        "source_ip": source_ip,
        "source_asn": source_asn,
        "reverse": back,
        "findings": global_findings(local, bgp, a.port, any(p["diag"]["reached"] for p in paths))
        + meta_findings(geo, transit, names)
        + compare(paths, names),
        "errors": errors,
        "details": a.details,
    }
    if a.json:
        json.dump(r | {"neighbours": sorted(neighbours)}, sys.stdout, ensure_ascii=False, indent=1)
        print()
    else:
        print_summary(r, names)
        if a.details:
            print_details(r, names)
    return 0 if all(p["diag"]["reached"] for p in paths if p["hops"]) else 1  # forward paths only


if __name__ == "__main__":
    sys.exit(main())
