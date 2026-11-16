import json
from pathlib import Path

from maasspec.engine import MAX_REPORT_BYTES, analyze_path

PAYLOAD = "ab" * 32
CONFIG_SHA = "11" * 32
REPORT = {
    "malfamily": "lumma",
    "CAPE": {
        "payloads": [{"sha256": PAYLOAD, "md5": "cd" * 16, "cape_type": "Example Payload"}],
        "configs": [
            {
                "ExampleRAT": {
                    "CNCs": [
                        "c2.example.test:443",
                        "https://panel.example.test/gate",
                        "93.184.216.34:8080",
                        "10.0.0.7:80",
                    ],
                    "Key": "0123456789abcdef",
                    "Mutex": "ExampleMutex_01",
                    "Version": "1.2",
                    "Contact": "ops@example.test",
                    "Nested": {"Campaign": "spring-26", "Notes": "nothing to see"},
                },
                "_associated_config_hashes": [
                    {"sha256": CONFIG_SHA, "md5": "22" * 16, "sha1": "33" * 20, "sha512": "x"},
                ],
            }
        ],
    },
}


def _analyze(tmp_path: Path, report: dict, name: str = "report.json"):
    path = tmp_path / name
    path.write_text(json.dumps(report), encoding="utf-8")
    return analyze_path(path)


def _kinds(spectrum) -> set[tuple[str, str | None]]:
    return {(f.type, f.subtype) for f in spectrum.findings}


def test_parser_output_becomes_findings_with_a_family_claim(tmp_path: Path) -> None:
    spectrum = _analyze(tmp_path, REPORT)
    assert spectrum.input.type == "cape_report"
    family = spectrum.summary.family
    assert (family.name, family.confidence, family.method) == ("ExampleRAT", 0.6, "cape_parser")
    kinds = _kinds(spectrum)
    assert {
        ("config", "cape_parser_config"),
        ("c2", "domain"),
        ("c2", "url"),
        ("c2", "ip_port"),
        ("crypto_material", "key"),
        ("config", "mutex"),
        ("config", "campaign"),
        ("config", "version"),
        ("credential_pattern", "email"),
        ("embedded_artifact", "cape_payload"),
    } <= kinds
    config = [f for f in spectrum.findings if "cape_config" in f.tags]
    assert config and all(f.confidence <= 0.6 for f in config)
    assert all({"sandbox", "cape"} <= set(f.tags) for f in config)
    assert all(f.proposed_grade is not None for f in config)


def test_c2_rows_keep_their_selectors_and_private_addresses_are_downgraded(tmp_path: Path) -> None:
    spectrum = _analyze(tmp_path, REPORT)
    c2 = {f.value: f for f in spectrum.findings if f.type == "c2"}
    assert set(c2) == {
        "c2.example.test:443",
        "https://panel.example.test/gate",
        "93.184.216.34:8080",
        "10.0.0.7:80",
    }
    assert {s.kind for s in c2["c2.example.test:443"].selectors} == {"domain", "domain_port"}
    assert {s.kind for s in c2["https://panel.example.test/gate"].selectors} == {"url", "domain"}
    public, private = c2["93.184.216.34:8080"], c2["10.0.0.7:80"]
    assert public.confidence == 0.6 and public.proposed_grade.information_credibility == "2"
    assert private.confidence <= 0.35 and "scope:private" in private.tags
    assert private.proposed_grade.information_credibility == "4"
    assert spectrum.summary.c2_count == 4


def test_the_payload_a_config_came_from_is_an_artifact_with_hash_selectors(tmp_path: Path) -> None:
    spectrum = _analyze(tmp_path, REPORT)
    artifacts = {a.id: a for a in spectrum.artifacts}
    assert artifacts["art_cape_config_1"].sha256 == CONFIG_SHA
    assert artifacts["art_cape_payload_1"].sha256 == PAYLOAD
    assert artifacts["art_cape_config_1"].description.endswith("Not fetched.")
    parsed = next(f for f in spectrum.findings if f.subtype == "cape_parser_config")
    assert {s.kind: s.value for s in parsed.selectors} == {"sha256": CONFIG_SHA, "md5": "22" * 16, "sha1": "33" * 20}
    assert parsed.source.artifact_id == "art_cape_config_1"
    key = next(f for f in spectrum.findings if f.subtype == "key")
    assert key.value == "0123456789abcdef" and key.source.section == "ExampleRAT.Key"


def test_parser_family_beats_malfamily_but_network_rows_keep_their_cap(tmp_path: Path) -> None:
    report = {**REPORT, "network": {"hosts": [{"ip": "93.184.216.35"}]}, "signatures": [{"name": "stealer_behavior"}]}
    spectrum = _analyze(tmp_path, report)
    assert spectrum.summary.family.name == "ExampleRAT"
    network = [f for f in spectrum.findings if "cape" in f.tags and "cape_config" not in f.tags and f.type in {"c2", "behavior"}]
    assert network and all(f.confidence <= 0.45 for f in network)


def test_a_report_with_only_a_cape_section_is_recognised(tmp_path: Path) -> None:
    spectrum = _analyze(tmp_path, {"CAPE": {"configs": [{"Tiny": {"C2": "c2.example.test"}}]}})
    assert spectrum.input.type == "cape_report"
    assert ("c2", "domain") in _kinds(spectrum)


def test_odd_shapes_do_not_crash_and_stay_bounded(tmp_path: Path) -> None:
    deep: dict = {}
    cursor = deep
    for _ in range(12):
        cursor["Deeper"] = {}
        cursor = cursor["Deeper"]
    cursor["C2"] = "deep.example.test"
    report = {
        "CAPE": {
            "payloads": ["not a dict", {"sha256": "nope"}, {"sha256": PAYLOAD}],
            "configs": [
                "text",
                {"_only_hashes": []},
                {"Many": {f"Field{i}": f"value {i} https://h{i}.example.test/x" for i in range(400)}},
                {"Deep": deep},
                {"NotADict": ["a", "b"]},
            ],
        }
    }
    spectrum = _analyze(tmp_path, report)
    assert spectrum.input.type == "cape_report"
    assert len(spectrum.findings) < 450
    assert not any("deep.example.test" == f.normalized for f in spectrum.findings)
    assert [a.id for a in spectrum.artifacts if a.id.startswith("art_cape_payload")] == ["art_cape_payload_2"]


def test_a_report_larger_than_the_scan_window_is_read_whole(tmp_path: Path) -> None:
    report = {**REPORT, "behavior": {"processes": ["x" * 9_000_000]}}
    spectrum = _analyze(tmp_path, report)
    assert spectrum.input.type == "cape_report"
    assert spectrum.metadata["scan_window_truncated"] is False
    assert spectrum.summary.family.name == "ExampleRAT"


def test_large_json_that_is_not_a_report_stays_a_raw_file(tmp_path: Path) -> None:
    spectrum = _analyze(tmp_path, {"blob": "x" * 9_000_000}, name="big.json")
    assert spectrum.input.type == "sample"
    assert spectrum.metadata["scan_window_truncated"] is True


def test_the_report_size_cap_is_stated() -> None:
    assert MAX_REPORT_BYTES == 128 * 1024 * 1024
