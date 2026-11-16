import json
from pathlib import Path

import pytest

from maasspec.engine import analyze_path, spectra_from_feed
from maasspec.feeds.threatfox import ThreatFoxFeed
from maasspec.selectors import is_unroutable, selector_findings


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "169.254.1.1", "0.0.0.0",
        "100.64.0.1", "100.127.255.254", "224.0.0.1", "239.255.255.250", "255.255.255.255",
        "192.0.2.5", "198.51.100.7", "203.0.113.9", "198.18.0.1", "240.0.0.1",
        "::1", "::", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1",
    ],
)
def test_addresses_that_are_not_public_unicast_are_unroutable(address: str) -> None:
    assert is_unroutable(address)


@pytest.mark.parametrize(
    "address", ["93.184.216.34", "8.8.8.8", "100.63.255.255", "100.128.0.1", "2606:4700:4700::1111", "not an ip", ""]
)
def test_public_addresses_and_non_addresses_are_not_unroutable(address: str) -> None:
    assert not is_unroutable(address)


def test_a_static_scan_scores_multicast_and_cgnat_as_private() -> None:
    drafts, _ = selector_findings(["call 224.0.0.251 then 100.64.1.1 then 93.184.216.34"])
    by_value = {d.value: d for d in drafts}
    for value in ("224.0.0.251", "100.64.1.1"):
        assert by_value[value].confidence == 0.35 and "scope:private" in by_value[value].tags
    assert by_value["93.184.216.34"].confidence == 0.55


def test_a_url_with_userinfo_or_a_port_normalises_to_its_host() -> None:
    drafts, _ = selector_findings(
        [
            "https://user:pass@Evil.Example/gate",
            "http://evil2.example:8080/x",
            "https://user@[2001:db8::1]:444/p",
        ]
    )
    assert {d.value: d.normalized for d in drafts if d.subtype == "url"} == {
        "https://user:pass@Evil.Example/gate": "evil.example",
        "http://evil2.example:8080/x": "evil2.example",
        "https://user@[2001:db8::1]:444/p": "2001:db8::1",
    }
    assert all(d.selectors[0].normalized == d.normalized for d in drafts if d.subtype == "url")


def test_threatfox_ip_port_in_multicast_and_cgnat_space_is_private() -> None:
    rows = [
        {"id": "1", "ioc": "224.0.0.9:80", "ioc_type": "ip:port", "confidence_level": 100},
        {"id": "2", "ioc": "100.64.0.9:80", "ioc_type": "ip:port", "confidence_level": 100},
        {"id": "3", "ioc": "93.184.216.34:80", "ioc_type": "ip:port", "confidence_level": 100},
    ]
    data = json.dumps({"query_status": "ok", "data": rows}).encode()
    found = [s.findings[0] for s in spectra_from_feed(ThreatFoxFeed(), data) if s.findings]
    assert [f.confidence <= 0.35 for f in found] == [True, True, False]
    assert ["scope:private" in f.tags for f in found] == [True, True, False]


def test_a_config_ip_port_in_multicast_space_is_private(tmp_path: Path) -> None:
    report = {"CAPE": {"configs": [{"Rat": {"C2": ["224.0.0.9:80", "100.64.0.9", "93.184.216.34:80"]}}]}}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    found = {f.value: f for f in analyze_path(path).findings if f.type == "c2"}
    assert found["224.0.0.9:80"].confidence == 0.35
    assert found["100.64.0.9"].confidence == 0.35
    assert found["93.184.216.34:80"].confidence == 0.6
