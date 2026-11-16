import io
import json
import sys
from pathlib import Path

import pytest

from maasspec import cli
from maasspec.models import Spectrum

KEY = "noct_sk_test_" + "Zz9Yy8Xx" * 4
RESPONSE = {
    "query_status": "ok",
    "data": [{"sha256_hash": "ab" * 32, "signature": "ExampleFamily"}, {"sha256_hash": "cd" * 32}],
}


def _stdin(monkeypatch: pytest.MonkeyPatch, data: bytes) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))


def test_feed_import_pipes_stdin_to_jsonl(monkeypatch, capsysbinary) -> None:
    _stdin(monkeypatch, json.dumps(RESPONSE).encode())
    assert cli.main(["feed", "import", "malwarebazaar"]) == 0
    captured = capsysbinary.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 2
    assert [Spectrum.model_validate_json(line).input.type for line in lines] == ["feed_record"] * 2
    assert b"2 spectra written" in captured.err


def test_the_full_pipe_import_then_ingest(monkeypatch, capsysbinary, tmp_path: Path) -> None:
    out = tmp_path / "spectra.jsonl"
    export = tmp_path / "response.json"
    export.write_text(json.dumps(RESPONSE), encoding="utf-8")
    assert cli.main(["feed", "import", "malwarebazaar", str(export), "--out", str(out)]) == 0

    posted = []

    class FakeClient:
        def __init__(self, url: str, key: str) -> None:
            assert url == "https://case.example.test" and key == KEY

        def submit_spectrum(self, spectrum: Spectrum) -> bytes:
            posted.append(str(spectrum.analysis_id))
            return b'{"batch_id":"b%d"}\n' % len(posted)

    monkeypatch.setattr(cli, "IngestClient", FakeClient)
    monkeypatch.setenv("MAASSPEC_NOCTORNAL_URL", "https://case.example.test")
    monkeypatch.setenv("MAASSPEC_INGEST_KEY", KEY)
    _stdin(monkeypatch, out.read_bytes())
    capsysbinary.readouterr()
    assert cli.main(["ingest", "-"]) == 0
    assert len(posted) == 2 and len(set(posted)) == 2
    assert capsysbinary.readouterr().out == b'{"batch_id":"b1"}\n{"batch_id":"b2"}\n'


def test_ingest_stops_at_the_first_rejection(monkeypatch, capsysbinary, tmp_path: Path) -> None:
    export = tmp_path / "response.json"
    export.write_text(json.dumps(RESPONSE), encoding="utf-8")
    out = tmp_path / "spectra.jsonl"
    cli.main(["feed", "import", "malwarebazaar", str(export), "--out", str(out)])

    calls = []

    class RejectingClient:
        def __init__(self, url: str, key: str) -> None:
            pass

        def submit_spectrum(self, spectrum: Spectrum) -> bytes:
            calls.append(1)
            raise cli.net.HttpError("HTTP 401.")

    monkeypatch.setattr(cli, "IngestClient", RejectingClient)
    monkeypatch.setenv("MAASSPEC_NOCTORNAL_URL", "https://case.example.test")
    monkeypatch.setenv("MAASSPEC_INGEST_KEY", KEY)
    capsysbinary.readouterr()
    assert cli.main(["ingest", str(out)]) == 1
    assert len(calls) == 1
    err = capsysbinary.readouterr().err
    assert b"was not accepted" in err and KEY.encode() not in err


def test_ingest_needs_its_environment(monkeypatch, capsys) -> None:
    monkeypatch.delenv("MAASSPEC_NOCTORNAL_URL", raising=False)
    monkeypatch.delenv("MAASSPEC_INGEST_KEY", raising=False)
    assert cli.main(["ingest", "-"]) == 2
    assert "MAASSPEC_INGEST_KEY" in capsys.readouterr().err


def test_import_reports_a_bad_response_without_a_traceback(monkeypatch, capsys) -> None:
    _stdin(monkeypatch, b'{"query_status": "no_results"}')
    assert cli.main(["feed", "import", "malwarebazaar"]) == 1
    assert "no_results" in capsys.readouterr().err


def test_fetch_without_a_key_is_a_usage_error(monkeypatch, capsys) -> None:
    monkeypatch.delenv(cli.KEY_ENV, raising=False)
    assert cli.main(["feed", "fetch", "malwarebazaar", "recent"]) == 2
    assert cli.KEY_ENV in capsys.readouterr().err


def test_validate_accepts_a_stream_and_rejects_a_bad_line(monkeypatch, capsys, tmp_path: Path) -> None:
    export = tmp_path / "response.json"
    export.write_text(json.dumps(RESPONSE), encoding="utf-8")
    stream = tmp_path / "spectra.jsonl"
    assert cli.main(["feed", "import", "malwarebazaar", str(export), "--out", str(stream)]) == 0
    capsys.readouterr()
    assert cli.main(["validate", str(stream)]) == 0
    assert "valid (2)" in capsys.readouterr().out
    _stdin(monkeypatch, b'{"not": "a spectrum"}\n')
    assert cli.main(["validate", "-"]) == 1
    assert "Line 1" in capsys.readouterr().err


def test_feed_list_names_every_feed(capsys) -> None:
    assert cli.main(["feed", "list"]) == 0
    text = capsys.readouterr().out
    for name in ("malwarebazaar", "threatfox", "unpacme"):
        assert name in text
