import pytest

from routecheck import (
    compare,
    diagnose,
    headline,
    majority_country,
    meta_findings,
    org,
    org_chain,
    parse_traceroute,
    ping_cmd,
    ping_loss,
    regional_paths,
    trace_cmds,
    transit_summary,
    verdict,
)

TARGET = "1.1.1.1"


def hop(ip, asn, loss=0.0):
    return {"ip": ip, "host": None, "asn": asn, "loss": loss, "rtt": 10.0 if loss < 100 else None}


SILENT = {"ip": None, "host": None, "asn": None, "loss": 100.0, "rtt": None}


def path(source, hops):
    return {"source": source, "proto": "ICMP", "hops": hops, "diag": diagnose(hops, TARGET)}


def test_parse_macos_traceroute():
    hops = parse_traceroute(
        "traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 48 byte packets\n"
        " 1  192.168.18.1  2.607 ms  1.784 ms  1.841 ms\n"
        " 2  * * *\n"
        " 3  * * 188.114.108.16  14.611 ms\n"
    )
    assert [h["ip"] for h in hops] == ["192.168.18.1", None, "188.114.108.16"]
    assert [round(h["loss"]) for h in hops] == [0, 100, 67]


@pytest.mark.parametrize(
    "hops, reached, loss_from",
    [
        # loss on a middle router that disappears later is ICMP rate limiting
        ([hop("10.0.0.1", None), hop("2.2.2.2", 2, 60), hop(TARGET, 13335)], True, None),
        ([hop("10.0.0.1", None), hop("2.2.2.2", 2, 20), hop(TARGET, 13335, 30)], True, 1),
        ([hop("10.0.0.1", None), hop("2.2.2.2", 2), SILENT, SILENT], False, None),
    ],
)
def test_diagnose(hops, reached, loss_from):
    d = diagnose(hops, TARGET)
    assert (d["reached"], d["loss_from"]) == (reached, loss_from)


def test_break_inside_target_network():
    hops = [hop("2.2.2.2", 2), hop("1.1.1.250", 13335), SILENT]
    status, text = verdict(diagnose(hops, TARGET), hops, 13335, {13335: "CLOUDFLARENET - Cloudflare, Inc., US"})
    assert status == "warn" and "дошли до сети Cloudflare" in text


def test_compare_points_at_junction_and_suspect():
    good = path("DE", [hop("5.5.5.5", 5), hop("3.3.3.3", 3), hop(TARGET, 13335)])
    bad1 = path("RU-1", [hop("7.7.7.7", 7), hop("9.9.9.9", 9), hop("3.3.3.4", 3), SILENT])
    bad2 = path("RU-2", [hop("8.8.4.4", 8), hop("9.9.9.8", 9), SILENT])
    found = compare([good, bad1, bad2], {3: "TRANSIT", 13335: "CF"})
    assert any(f.startswith("RU-1: трафик доходит до Transit") and "дальше идёт Cf" not in f for f in found)
    assert any(f.startswith("AS9: есть во всех неработающих") for f in found)


def test_icmp_ok_tcp_blocked_from_same_probe():
    icmp = path("RU", [hop("7.7.7.7", 7), hop(TARGET, 13335)])
    tcp = path("RU", [hop("7.7.7.7", 7), hop("1.1.1.250", 13335), SILENT]) | {"proto": "TCP 443"}
    found = compare([icmp, tcp], {})
    assert any(f.startswith("RU: ping доходит, а подключение (порт 443) нет") for f in found)


RIS = [
    ("Moscow, RU", [41722, 20485, 1273, 1273, 12430]),
    ("Moscow, RU", [8359, 1273, 12430]),
    ("New York, NY, US", [3257, 1273, 12430]),
    ("London, GB", [8218, 12430]),
]


def test_transit_summary_counts_handover_as_ignoring_prepends():
    assert transit_summary(RIS, 12430) == [(1273, 3), (8218, 1)]


def test_regional_paths_by_collector_country():
    assert regional_paths(RIS, {"RU", "US"}) == {
        "Moscow, RU": [[41722, 20485, 1273, 12430], [8359, 1273, 12430]],
        "New York, NY, US": [[3257, 1273, 12430]],
    }


def test_geoip_disagreement_and_single_transit():
    geo = {"a": ["UA", "Simferopol"], "b": ["RU", "Simferopol"], "c": ["RU", ""], "d": "HTTPError: 429"}
    assert majority_country(geo) == "RU"
    found = meta_findings(geo, [(8359, 95), (3216, 5)], {8359: "MTS"})
    assert any(f.startswith("Базы геолокации расходятся в стране (RU, UA)") for f in found)
    assert any("почти только через MTS (95% маршрутов)" in f for f in found)
    assert meta_findings({"a": ["ES", "Madrid"], "b": ["ES", "Barcelona"]}, [], {}) == []


def test_no_findings_when_all_reach():
    assert compare([path("DE", [hop(TARGET, 13335)])], {}) == []


def test_route_reaches_target_neighbour_but_address_silent():
    hops = [hop("7.7.7.7", 7), hop("87.245.234.65", 9002), SILENT]
    status, text = verdict(diagnose(hops, TARGET), hops, 12430, {}, {9002})
    assert status == "warn" and "соседа сети AS12430" in text
    status, text = headline([path("RU", hops)], 12430, {9002, 12430}, {})
    assert status == "warn" and "доступна из всех точек проверки (1), но сам адрес не отвечает" in text


def test_private_hops_after_entering_network_count_as_that_network():
    hops = [hop("7.7.7.7", 7), hop("198.51.100.1", 64500), hop("10.14.6.2", None), SILENT]
    d = diagnose(hops, "198.51.100.77")
    assert d["last_asn"] == 64500
    assert verdict(d, hops, 64500, {}, mine=True)[0] == "ok"


@pytest.mark.parametrize(
    "raw, name",
    [
        ("VODAFONE_ES - VODAFONE ESPANA S.A.U., ES", "Vodafone Espana"),
        ("TimeWeb-AS - JSC _TIMEWEB_, RU", "Timeweb"),
        ("CW - IDDQD-AS, EU", "CW"),
        ("HURRICANE - Hurricane Electric LLC, US", "Hurricane Electric"),
        ("CITYTELECOM-AS", "Citytelecom"),
        ("SGGS-AS-AP", "SGGS"),
        ("MEERFARBIG - meerfarbig GmbH & Co. KG, DE", "meerfarbig"),
        ("", "AS64500"),
    ],
)
def test_org_readable_names(raw, name):
    assert org(64500, {64500: raw}) == name


def test_org_chain_groups_networks_and_marks_ix():
    ix_hop = hop("185.1.192.76", 64501) | {"ix": "DE-CIX Madrid"}
    chain = org_chain([hop("10.0.0.1", None), hop("2.2.2.2", 1273), hop("2.2.2.3", 1273), ix_hop, SILENT])
    assert [(s["asn"], s["ix"]) for s in chain] == [(1273, None), (64501, "DE-CIX Madrid")]


def test_headline_mixed_lists_failing_checks():
    ok = path("DE", [hop(TARGET, 13335)])
    bad = path("RU", [hop("7.7.7.7", 7), SILENT])
    status, text = headline([ok, bad], 13335, {13335}, {})
    assert status == "fail" and text.endswith("Не работает: RU (ping).")


TRACERT_EN = """
Tracing route to 1.1.1.1 over a maximum of 30 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     8 ms     7 ms     9 ms  10.0.0.1
  3     *        *        *     Request timed out.
  4    13 ms     *       12 ms  1.1.1.1

Trace complete.
"""

TRACERT_RU = """
Трассировка маршрута к 1.1.1.1
с максимальным числом прыжков 30:

  1    <1 мс    <1 мс    <1 мс  192.168.1.1
  2     *        *        *     Превышен интервал ожидания для запроса.
  3    12 мс    11 мс    12 мс  1.1.1.1

Трассировка завершена.
"""


@pytest.mark.parametrize(
    "text, ips, losses, first_rtt",
    [
        (TRACERT_EN, ["192.168.1.1", "10.0.0.1", None, "1.1.1.1"], [0, 0, 100, 33], 1.0),
        (TRACERT_RU, ["192.168.1.1", None, "1.1.1.1"], [0, 100, 0], 1.0),
        # garbled units (console code page mismatch) must not turn answering hops into dead ones
        (TRACERT_RU.replace("мс", "??"), ["192.168.1.1", None, "1.1.1.1"], [0, 100, 0], None),
    ],
)
def test_parse_windows_tracert(text, ips, losses, first_rtt):
    hops = parse_traceroute(text)
    assert [h["ip"] for h in hops] == ips
    assert [round(h["loss"]) for h in hops] == losses
    assert hops[0]["rtt"] == first_rtt


PING_WIN_EN = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=13ms TTL=57
Reply from 1.1.1.1: bytes=32 time<1ms TTL=57
Request timed out.
Reply from 192.168.1.1: Destination host unreachable.

Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
"""
PING_WIN_RU = """
Обмен пакетами с 1.1.1.1 по с 32 байтами данных:
Ответ от 1.1.1.1: число байт=32 время=13мс TTL=57
Ответ от 1.1.1.1: число байт=32 время=12мс TTL=57
Ответ от 1.1.1.1: число байт=32 время=12мс TTL=57
Ответ от 1.1.1.1: число байт=32 время=14мс TTL=57
"""
PING_WIN_DF = "Pinging 1.1.1.1 with 1472 bytes of data:\n" + "Packet needs to be fragmented but DF set.\n" * 4
PING_MAC = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=13.058 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=13.512 ms
Request timeout for icmp_seq 2
64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=12.900 ms

4 packets transmitted, 3 packets received, 25.0% packet loss
"""
PING_LINUX_DF = "PING 1.1.1.1 (1.1.1.1) 1472(1500) bytes of data.\n" + (
    "From 10.0.0.1 icmp_seq=1 Frag needed and DF set (mtu = 1492)\n" * 4
)


@pytest.mark.parametrize(
    "text, loss",
    [(PING_WIN_EN, 50), (PING_WIN_RU, 0), (PING_WIN_DF, 100), (PING_MAC, 25), (PING_LINUX_DF, 100), ("", 100)],
)
def test_ping_loss_counts_only_real_replies(text, loss):
    assert ping_loss(text, 4) == loss


@pytest.mark.parametrize(
    "platform, size, cmd",
    [
        ("win32", None, ["ping", "-n", "4", "-w", "2000", "1.1.1.1"]),
        ("win32", 1472, ["ping", "-n", "4", "-w", "2000", "-f", "-l", "1472", "1.1.1.1"]),
        ("darwin", 1472, ["ping", "-n", "-c", "4", "-D", "-s", "1472", "-t", "6", "1.1.1.1"]),
        ("linux", 1472, ["ping", "-n", "-c", "4", "-M", "do", "-s", "1472", "-w", "6", "1.1.1.1"]),
        ("linux", None, ["ping", "-n", "-c", "4", "-w", "6", "1.1.1.1"]),
    ],
)
def test_ping_cmd_per_platform(platform, size, cmd):
    assert ping_cmd("1.1.1.1", size, 4, platform) == cmd


def test_trace_cmds_per_platform():
    assert trace_cmds("1.1.1.1", 5, "win32") == [["tracert", "-d", "-h", "5", "-w", "1000", "1.1.1.1"]]
    unix = trace_cmds("1.1.1.1", 5, "linux")
    assert unix[0][0] == "traceroute" and "-I" in unix[0] and "-I" not in unix[1]


def test_headline_icmp_filtered_but_port_answers():
    silent = path("этот компьютер", [SILENT, SILENT])
    local = {"ping_loss": 100.0, "mtu_loss": 100.0, "tcp_ms": 1.9}
    status, text = headline([silent], 13335, {13335}, {}, local, 443)
    assert status == "ok" and text.startswith("Адрес доступен: порт 443 отвечает (1.9 мс)")
    # a failed remote TCP trace means the port itself is blocked somewhere: no all-clear
    tcp = path("RU", [hop("7.7.7.7", 7), SILENT]) | {"proto": "TCP 443"}
    assert headline([silent, tcp], 13335, {13335}, {}, local, 443)[0] == "fail"
    assert headline([silent], 13335, {13335}, {}, local | {"tcp_ms": None}, 443)[0] == "fail"
