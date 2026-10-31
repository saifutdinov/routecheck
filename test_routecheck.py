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
    regional_paths,
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
