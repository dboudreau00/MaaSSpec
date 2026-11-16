import hashlib
import json
from datetime import UTC, datetime

import pytest

from maasspec.engine import canonical_record_bytes, spectra_from_feed
from maasspec.feeds import ADAPTERS
from maasspec.feeds.base import FeedFormatError, FetchOptions
from maasspec.feeds.malwarebazaar import MalwareBazaarFeed
from maasspec.feeds.threatfox import ThreatFoxFeed
from maasspec.feeds.unpacme import UnpacMeFeed
from maasspec.models import Spectrum

STAMP = datetime(2026, 11, 16, tzinfo=UTC)
KEY = "k" * 40
SHA_A = "ab" * 32
SHA_B = "cd" * 32

MB_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": SHA_A,
            "sha1_hash": "cd" * 20,
            "md5_hash": "ef" * 16,
            "first_seen": "2026-11-15 10:00:00",
            "last_seen": None,
            "file_name": "invoice.exe",
            "file_size": 12345,
            "file_type_mime": "application/x-dosexec",
            "file_type": "exe",
            "reporter": "example_reporter",
            "origin_country": "CA",
            "anonymous": 0,
            "signature": "ExampleFamily",
            "imphash": "12" * 16,
            "tlsh": "T1ABCDEF0123",
            "ssdeep": "96:abc/def:ghi",
            "tags": ["exe", "Stealer"],
            "delivery_method": "web_download",
            "code_sign": [
                {
                    "subject_cn": "Example Ltd",
                    "issuer_cn": "Example CA",
                    "serial_number": "00ff",
                    "cscb_listed": "yes",
                }
            ],
            "yara_rules": [{"rule_name": "example_rule", "author": "someone"}],
            "vendor_intel": {"CAPE": {"detection": "x"}, "UnpacMe": []},
            "intelligence": {"clamav": ["Example.Gen"], "downloads": "5", "uploads": "1"},
        }
    ],
}

MB_CSV = (
    "################################################\n"
    "# MalwareBazaar recent additions (synthetic test fixture)\n"
    "# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,"
    "mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh\n"
    "################################################\n"
    f'"2026-11-15 10:00:00","{SHA_A}","{"ef" * 16}","{"cd" * 20}","rep","a.exe","exe",'
    '"application/x-dosexec","ExampleFamily","Example.Gen","n/a","","96:abc:def","T1ABCDEF"\n'
)

TF_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "id": "1001",
            "ioc": "93.184.216.34:443",
            "threat_type": "botnet_cc",
            "ioc_type": "ip:port",
            "malware": "win.example",
            "malware_printable": "Example RAT",
            "malware_alias": None,
            "confidence_level": 100,
            "first_seen": "2026-11-15 10:00:00 UTC",
            "reference": None,
            "reporter": "r",
            "tags": ["rat"],
            "malware_samples": [{"sha256_hash": SHA_A, "md5_hash": "cd" * 16}],
        },
        {
            "id": "1002",
            "ioc": "https://panel.example.test/gate.php",
            "ioc_type": "url",
            "threat_type": "payload_delivery",
            "malware_printable": "Example RAT",
            "confidence_level": 50,
        },
        {"id": "1003", "ioc": "10.0.0.5:80", "ioc_type": "ip:port", "confidence_level": 90},
        {"id": "1004", "ioc": "c2.example.test", "ioc_type": "domain", "confidence_level": 75},
        {"id": "1005", "ioc": SHA_B, "ioc_type": "sha256_hash"},
        {"id": "1006", "ioc": "whatever", "ioc_type": "new_kind", "confidence_level": 80},
    ],
}

UP_SUBMISSION = {
    "id": "abcDEF123456",
    "status": "complete",
    "sha256": "11" * 32,
    "time": 1763290000.0,
    "results": [
        {"hashes": {"sha256": "11" * 32, "md5": "22" * 16, "sha1": "33" * 20}, "analysis": {}},
        {
            "hashes": {"sha256": "44" * 32, "md5": "55" * 16, "sha1": "66" * 20},
            "analysis": {},
            "malware_id": [
                {
                    "name": "Example.Loader",
                    "source": "yara",
                    "confidence": "high",
                    "reference": "https://example.test/r",
                }
            ],
            "urls": ["https://c2.example.test/gate"],
            "strings": {
                "ascii": [
                    "contact operator@example.test now",
                    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                ],
                "wide": [],
                "stack": [],
            },
            "deepmatch": [{"x": 1}],
        },
    ],
}

UP_FEED = {
    "results": [
        {
            "id": "feed123456",
            "sha256": "77" * 32,
            "status": "complete",
            "created": 1763290000.0,
            "children": 2,
            "downloader": True,
            "malwareid": [{"match": "Example.Family", "type": "yara"}],
        }
    ]
}


def _spectra(adapter, payload, **kwargs) -> list[Spectrum]:
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return list(spectra_from_feed(adapter, data, now=STAMP, **kwargs))


def _kinds(spectrum: Spectrum) -> set[tuple[str, str | None]]:
    return {(item.type, item.subtype) for item in spectrum.findings}


def test_malwarebazaar_api_record_becomes_a_claim_spectrum() -> None:
    [spectrum] = _spectra(MalwareBazaarFeed(), MB_RESPONSE)
    Spectrum.model_validate(spectrum.model_dump())
    record = MB_RESPONSE["data"][0]
    assert spectrum.input.type == "feed_record"
    assert spectrum.input.sha256 == hashlib.sha256(canonical_record_bytes(record)).hexdigest()
    assert spectrum.metadata["claimed_sample_sha256"] == SHA_A
    assert spectrum.metadata["claims_not_verified"] is True
    assert {
        ("embedded_artifact", "sample_hash"),
        ("family_indicator", "signature"),
        ("family_indicator", "yara_rule"),
        ("behavior", "delivery_method"),
        ("crypto_material", "code_signing_certificate"),
    } <= _kinds(spectrum)
    sample = next(f for f in spectrum.findings if f.subtype == "sample_hash")
    assert {s.kind for s in sample.selectors} >= {"sha256", "sha1", "md5", "imphash", "tlsh", "ssdeep"}
    assert "tag:stealer" in sample.tags
    assert all("claimed" in f.tags for f in spectrum.findings)
    assert all(f.proposed_grade is not None for f in spectrum.findings)
    assert spectrum.summary.family.name == "ExampleFamily"
    assert "risk:cscb_listed" in spectrum.summary.risk_signals
    reference = next(a for a in spectrum.artifacts if a.id == "art_sample_ref")
    assert reference.sha256 == SHA_A and reference.type == "sample_reference"


def test_the_same_record_gets_the_same_analysis_id() -> None:
    [first] = _spectra(MalwareBazaarFeed(), MB_RESPONSE)
    [second] = list(
        spectra_from_feed(
            MalwareBazaarFeed(),
            json.dumps(MB_RESPONSE).encode(),
            now=datetime(2027, 1, 1, tzinfo=UTC),
        )
    )
    assert first.analysis_id == second.analysis_id


def test_malwarebazaar_error_status_is_refused() -> None:
    with pytest.raises(FeedFormatError, match="hash_not_found"):
        _spectra(MalwareBazaarFeed(), {"query_status": "hash_not_found"})


def test_malwarebazaar_csv_export_is_read_by_header() -> None:
    [spectrum] = _spectra(MalwareBazaarFeed(), MB_CSV.encode())
    assert spectrum.metadata["claimed_sample_sha256"] == SHA_A
    assert spectrum.summary.family.name == "ExampleFamily"
    sample = next(f for f in spectrum.findings if f.subtype == "sample_hash")
    assert sample.context["file_name"] == "a.exe"
    assert sample.context["clamav"] == ["Example.Gen"]


def test_a_record_without_a_valid_hash_is_kept_as_an_error() -> None:
    [spectrum] = _spectra(MalwareBazaarFeed(), {"query_status": "ok", "data": [{"sha256_hash": "nope"}]})
    assert spectrum.findings == []
    assert spectrum.errors and spectrum.errors[0].severity == "warning"


def test_threatfox_maps_each_ioc_type() -> None:
    spectra = _spectra(ThreatFoxFeed(), TF_RESPONSE)
    assert len(spectra) == 6
    first, url, private, domain, hashed, unknown = spectra
    assert _kinds(first) >= {("c2", "ip_port"), ("family_indicator", "malware_family")}
    c2 = next(f for f in first.findings if f.type == "c2")
    assert c2.confidence == 0.7
    assert {s.kind for s in c2.selectors} == {"ipv4", "ipv4_port"}
    assert first.summary.family.name == "Example RAT"
    assert first.summary.primary_capabilities == ["botnet_cc"]
    assert first.metadata["claimed_sample_sha256"] == SHA_A
    assert any(a.id == "art_sample_ref_1" for a in first.artifacts)
    assert next(f for f in url.findings if f.type == "c2").confidence == 0.35
    assert any(s.kind == "domain" and s.value == "panel.example.test" for s in url.findings[0].selectors)
    low = private.findings[0]
    assert low.confidence <= 0.35 and "scope:private" in low.tags
    assert low.proposed_grade.information_credibility == "4"
    assert domain.findings[0].proposed_grade.information_credibility == "2"
    assert url.findings[0].proposed_grade.information_credibility == "3"
    assert _kinds(hashed) == {("embedded_artifact", "sample_hash")}
    assert hashed.findings[0].confidence == 0.35
    assert _kinds(unknown) == {("other", "new_kind")}
    assert any(e.severity == "info" for e in unknown.errors)


def test_threatfox_no_result_is_refused() -> None:
    with pytest.raises(FeedFormatError, match="no_result"):
        _spectra(ThreatFoxFeed(), {"query_status": "no_result", "data": "Your search did not yield any results"})


def test_threatfox_old_export_names_are_accepted() -> None:
    document = {
        "1001": [
            {"ioc_value": "c2.example.test", "ioc_type": "domain", "first_seen_utc": "x",
             "confidence_level": 80, "tags": "rat,loader"}
        ]
    }
    [spectrum] = _spectra(ThreatFoxFeed(), document)
    assert spectrum.metadata["feed_record_id"] == "1001"
    assert spectrum.findings[0].value == "c2.example.test"
    assert "tag:loader" in spectrum.findings[0].tags


def test_threatfox_csv_export_is_read_by_header() -> None:
    text = (
        "# first_seen_utc,ioc_id,ioc_value,ioc_type,threat_type,fk_malware,malware_alias,"
        "malware_printable,last_seen_utc,confidence_level,reference,tags,anonymous,reporter\n"
        '"2026-11-15 10:00:00","2001","c2.example.test","domain","botnet_cc","win.x","",'
        '"Example RAT","","75","","rat","0","rep"\n'
    )
    [spectrum] = _spectra(ThreatFoxFeed(), text.encode())
    assert spectrum.metadata["feed_record_id"] == "2001"
    assert spectrum.summary.family.name == "Example RAT"


def test_unpacme_submission_links_layers_and_reuses_the_selector_scan() -> None:
    [spectrum] = _spectra(UnpacMeFeed(), UP_SUBMISSION)
    Spectrum.model_validate(spectrum.model_dump())
    layers = {a.id: a for a in spectrum.artifacts if a.id.startswith("art_unpack_")}
    assert layers["art_unpack_0"].type == "submitted_sample"
    assert layers["art_unpack_1"].type == "unpacked_layer"
    assert layers["art_unpack_1"].parent_artifact_id == "art_unpack_0"
    assert spectrum.summary.family.name == "Example.Loader"
    assert spectrum.summary.family.confidence == 0.7
    child = [f for f in spectrum.findings if f.source and f.source.artifact_id == "art_unpack_1"]
    assert {("c2", "url"), ("credential_pattern", "email"), ("wallet", "bitcoin")} <= {
        (f.type, f.subtype) for f in child
    }
    assert all(f.confidence <= 0.8 for f in child)
    assert all("unpacked" in f.tags and "claimed" in f.tags for f in child)
    assert any("not normalized" in e.message for e in spectrum.errors)


def test_unpacme_public_feed_yields_one_spectrum_per_entry() -> None:
    [spectrum] = _spectra(UnpacMeFeed(), UP_FEED)
    assert spectrum.metadata["claimed_sample_sha256"] == "77" * 32
    assert "capability:downloader" in spectrum.findings[0].tags
    assert spectrum.summary.family.name == "Example.Family"


def test_unpacme_rejects_a_document_without_results() -> None:
    with pytest.raises(FeedFormatError):
        _spectra(UnpacMeFeed(), {"id": "x"})


def test_import_stops_at_the_limit_and_refuses_junk() -> None:
    many = {"query_status": "ok", "data": [{"sha256_hash": SHA_A}, {"sha256_hash": SHA_B}]}
    assert len(_spectra(MalwareBazaarFeed(), many, limit=1)) == 1
    with pytest.raises(FeedFormatError):
        _spectra(MalwareBazaarFeed(), b"\xff\xfe not text")
    with pytest.raises(FeedFormatError):
        _spectra(ThreatFoxFeed(), b"{not json")


# ---- fetchers: one request each, through maasspec.net, no live calls ----


class _Response:
    def read(self, n: int = -1) -> bytes:
        return b"{}"

    def close(self) -> None:
        return None


def _recorder():
    calls = []

    def opener(request, timeout):
        calls.append(request)
        return _Response()

    return calls, opener


def test_malwarebazaar_fetch_is_one_authenticated_post() -> None:
    calls, opener = _recorder()
    MalwareBazaarFeed().fetch("recent", None, FetchOptions(), key=KEY, opener=opener)
    [request] = calls
    assert request.full_url == "https://mb-api.abuse.ch/api/v1/"
    assert request.method == "POST"
    assert request.get_header("Auth-key") == KEY
    assert request.data == b"query=get_recent&selector=time"
    assert KEY not in request.full_url


def test_malwarebazaar_fetch_validates_before_sending() -> None:
    calls, opener = _recorder()
    feed = MalwareBazaarFeed()
    for query, term, options in [
        ("hash", "not-a-hash", FetchOptions()),
        ("recent", None, FetchOptions(selector="999")),
        ("tag", "bad/tag", FetchOptions()),
        ("tag", "ok", FetchOptions(limit=5000)),
        ("nope", None, FetchOptions()),
    ]:
        with pytest.raises(ValueError):
            feed.fetch(query, term, options, key=KEY, opener=opener)
    with pytest.raises(ValueError, match="MAASSPEC_ABUSECH_KEY"):
        feed.fetch("recent", None, FetchOptions(), key=None, opener=opener)
    with pytest.raises(ValueError):
        feed.fetch("recent", None, FetchOptions(), key="bad key\n", opener=opener)
    assert calls == []


def test_threatfox_fetch_bodies() -> None:
    calls, opener = _recorder()
    feed = ThreatFoxFeed()
    feed.fetch("recent", None, FetchOptions(days=3), key=KEY, opener=opener)
    feed.fetch("hash", SHA_A.upper(), FetchOptions(), key=KEY, opener=opener)
    feed.fetch("malware", "Example RAT", FetchOptions(limit=10), key=KEY, opener=opener)
    feed.fetch("search", "203.0.113.9", FetchOptions(exact=True), key=KEY, opener=opener)
    bodies = [json.loads(call.data) for call in calls]
    assert bodies == [
        {"query": "get_iocs", "days": 3},
        {"query": "search_hash", "hash": SHA_A},
        {"query": "malwareinfo", "malware": "Example RAT", "limit": 10},
        {"query": "search_ioc", "search_term": "203.0.113.9", "exact_match": True},
    ]
    assert all(call.full_url == "https://threatfox-api.abuse.ch/api/v1/" for call in calls)
    with pytest.raises(ValueError):
        feed.fetch("recent", None, FetchOptions(days=9), key=KEY, opener=opener)


def test_unpacme_fetch_needs_no_key_and_quotes_the_id() -> None:
    calls, opener = _recorder()
    feed = UnpacMeFeed()
    feed.fetch("feed", None, FetchOptions(), opener=opener)
    feed.fetch("results", "abcDEF123456", FetchOptions(), opener=opener)
    assert [c.full_url for c in calls] == [
        "https://api.unpac.me/api/v1/public/feed",
        "https://api.unpac.me/api/v1/public/results/abcDEF123456",
    ]
    assert all(c.get_header("Authorization") is None for c in calls)
    for bad in ("../x", "a/b?c", "short", ""):
        with pytest.raises(ValueError):
            feed.fetch("results", bad, FetchOptions(), opener=opener)


def test_every_adapter_is_registered_with_a_host_and_queries() -> None:
    assert set(ADAPTERS) == {"malwarebazaar", "threatfox", "unpacme"}
    for adapter in ADAPTERS.values():
        assert adapter.hosts and adapter.queries


def test_threatfox_md5_ioc_is_mapped_and_a_bad_hash_is_flagged() -> None:
    good, bad = _spectra(
        ThreatFoxFeed(),
        {
            "query_status": "ok",
            "data": [
                {"id": "1", "ioc": "ef" * 16, "ioc_type": "md5_hash", "confidence_level": 80},
                {"id": "2", "ioc": "xyz", "ioc_type": "md5_hash", "confidence_level": 80},
            ],
        },
    )
    assert _kinds(good) == {("embedded_artifact", "sample_hash")} and good.errors == []
    assert _kinds(bad) == {("other", "md5_hash")}
    assert any("did not validate" in e.message for e in bad.errors)
