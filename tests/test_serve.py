import http.client
import io
import json
import socket
import threading
import urllib.error
from dataclasses import dataclass, field

import pytest

from maasspec import cli
from maasspec.serve import make_server

TOKEN = "t" * 32
ABUSECH = "a" * 40
INGEST_KEY = "noct_sk_test_" + "Qq7Ww3Ee" * 4
TF = {
    "query_status": "ok",
    "data": [
        {"id": "1", "ioc": "c2.example.test", "ioc_type": "domain", "threat_type": "botnet_cc",
         "malware_printable": "Example RAT", "confidence_level": 80},
        {"id": "2", "ioc": "93.184.216.34:443", "ioc_type": "ip:port", "confidence_level": 100},
        {"id": "3", "ioc": "https://panel.example.test/gate.php", "ioc_type": "url", "confidence_level": 50},
    ],
}
SAMPLE = b"MAASSPEC_FAMILY_EXAMPLE\npanel https://panel.example.test/gate.php\n"


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self, n: int = -1) -> bytes:
        return self.body if n < 0 else self.body[:n]

    def close(self) -> None:
        return None


@dataclass
class App:
    port: int
    env: dict
    handlers: dict = field(default_factory=dict)
    requests: list = field(default_factory=list)


@pytest.fixture
def app(tmp_path):
    ui = tmp_path / "ui"
    (ui / "assets").mkdir(parents=True)
    (ui / "index.html").write_text("<!doctype html><title>MaaSSpec</title>", encoding="utf-8")
    (ui / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside the ui folder", encoding="utf-8")
    state = App(
        port=0,
        env={
            "MAASSPEC_ABUSECH_KEY": ABUSECH,
            "MAASSPEC_NOCTORNAL_URL": "https://case.example.test",
            "MAASSPEC_INGEST_KEY": INGEST_KEY,
        },
    )

    def opener(request, timeout):
        state.requests.append(request)
        host = request.full_url.split("/")[2]
        return state.handlers[host](request)

    server, _ = make_server(ui, port=0, env=state.env, opener=opener, token=TOKEN)
    state.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state
    server.shutdown()
    server.server_close()


def call(app, method, path, *, body=None, headers=None, token=True):
    sent = {"X-MaaSSpec-Token": TOKEN} if token else {}
    sent.update(headers or {})
    connection = http.client.HTTPConnection("127.0.0.1", app.port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        return response.status, response, response.read()
    finally:
        connection.close()


def post_json(app, path, payload):
    status, _, data = call(app, "POST", path, body=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    return status, json.loads(data)


def raw(app, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", app.port), timeout=10) as sock:
        sock.sendall(request)
        return sock.recv(4096).split(b"\r\n", 1)[0]


def tf_spectra(app):
    app.handlers["threatfox-api.abuse.ch"] = lambda request: _Response(json.dumps(TF).encode())
    _, fetched = post_json(app, "/api/feeds/fetch", {"feed": "threatfox", "query": "recent", "days": 1})
    status, imported = post_json(app, "/api/feeds/import", {"fetchId": fetched["fetchId"]})
    assert status == 200
    return imported["spectra"]


def test_static_files_headers_and_traversal(app) -> None:
    status, response, body = call(app, "GET", "/", token=False)
    assert status == 200 and b"MaaSSpec" in body
    assert "script-src 'self'" in response.getheader("Content-Security-Policy")
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    assert response.getheader("Cache-Control") == "no-store"
    status, response, _ = call(app, "GET", "/assets/app.js", token=False)
    assert status == 200 and response.getheader("Content-Type").startswith("text/javascript")
    assert call(app, "GET", "/some/route", token=False)[2].startswith(b"<!doctype")
    assert call(app, "GET", "/missing.js", token=False)[0] == 404
    for path in ("/..%2fsecret.txt", "/%2e%2e/secret.txt", "/..%5csecret.txt", "/assets/..%2f..%2fsecret.txt"):
        assert b"outside the ui folder" not in call(app, "GET", path, token=False)[2], path


def test_the_api_needs_the_token_a_loopback_host_and_no_foreign_origin(app) -> None:
    assert call(app, "GET", "/api/status", token=False)[0] == 401
    assert call(app, "GET", "/api/status", headers={"X-MaaSSpec-Token": "wrong"}, token=False)[0] == 401
    assert call(app, "GET", "/api/status", headers={"Host": "evil.example"})[0] == 403
    assert call(app, "GET", "/api/status", headers={"Origin": "http://evil.example"})[0] == 403
    assert call(app, "GET", "/api/status", headers={"Origin": f"http://127.0.0.1:{app.port}"})[0] == 200
    assert call(app, "GET", "/api/nope")[0] == 404
    assert call(app, "POST", "/api/nope", body=b"{}")[0] == 404


def test_status_reports_state_but_never_key_values(app) -> None:
    status, _, data = call(app, "GET", "/api/status")
    assert status == 200
    text = data.decode()
    assert ABUSECH not in text and INGEST_KEY not in text
    info = json.loads(text)
    assert info["env"] == {
        "ingestUrl": "MAASSPEC_NOCTORNAL_URL",
        "ingestKey": "MAASSPEC_INGEST_KEY",
        "abusech": "MAASSPEC_ABUSECH_KEY",
    }
    assert info["ingest"] == {"url": "https://case.example.test", "keySet": True}
    assert set(info["feeds"]) == {"malwarebazaar", "threatfox", "unpacme"}
    assert info["feeds"]["threatfox"]["keySet"] is True and "recent" in info["feeds"]["threatfox"]["queries"]
    assert info["feeds"]["unpacme"] == {"needsKey": False, "keySet": False, "queries": info["feeds"]["unpacme"]["queries"]}


def test_parse_lists_and_rejects(app) -> None:
    spectra = tf_spectra(app)
    stream = "\n".join(json.dumps(s) for s in spectra).encode()
    status, _, data = call(app, "POST", "/api/spectra/parse", body=stream)
    assert status == 200 and len(json.loads(data)["spectra"]) == 3
    listed = json.loads(call(app, "GET", "/api/spectra")[2])["spectra"]
    assert len(listed) == 3
    for bad in (b"", b'{"not": "a spectrum"}', b"\xff\xfe"):
        status, _, data = call(app, "POST", "/api/spectra/parse", body=bad)
        assert status == 400 and "error" in json.loads(data), bad


def test_analyze_cleans_the_name_and_never_keeps_the_file(app) -> None:
    status, _, data = call(app, "POST", "/api/analyze?filename=..%2F..%2Fevil%20name%3F.txt", body=SAMPLE)
    spectrum = json.loads(data)["spectra"][0]
    assert status == 200 and spectrum["input"]["filename"] == "evil name_.txt"
    assert spectrum["summary"]["family"]["name"] == "example"
    status, _, data = call(app, "POST", "/api/analyze?filename=CON", body=SAMPLE)
    assert status == 200 and json.loads(data)["spectra"][0]["input"]["filename"] == "CON"


def test_import_a_saved_feed_response(app) -> None:
    body = json.dumps(TF).encode()
    status, _, data = call(app, "POST", "/api/import?feed=threatfox&limit=2", body=body)
    spectra = json.loads(data)["spectra"]
    assert status == 200 and len(spectra) == 2 and spectra[0]["input"]["type"] == "feed_record"
    assert call(app, "POST", "/api/import?feed=nope", body=body)[0] == 400
    assert call(app, "POST", "/api/import?feed=threatfox&limit=abc", body=body)[0] == 400
    assert call(app, "POST", "/api/import?feed=threatfox&limit=0", body=body)[0] == 400
    assert call(app, "POST", "/api/import?feed=threatfox", body=b'{"query_status":"no_result"}')[0] == 400


def test_fetch_uses_the_server_key_and_holds_the_response(app) -> None:
    spectra = tf_spectra(app)
    assert len(spectra) == 3 and spectra[0]["metadata"]["feed"] == "threatfox"
    request = app.requests[0]
    assert request.get_header("Auth-key") == ABUSECH
    assert json.loads(request.data) == {"query": "get_iocs", "days": 1}


def test_fetch_errors_are_plain_and_secret_free(app) -> None:
    ok = {"feed": "threatfox", "query": "recent"}
    assert post_json(app, "/api/feeds/fetch", {**ok, "days": 9})[0] == 400
    assert post_json(app, "/api/feeds/fetch", {**ok, "days": "3"})[0] == 400
    assert post_json(app, "/api/feeds/fetch", {"feed": "nope", "query": "recent"})[0] == 400
    assert post_json(app, "/api/feeds/fetch", {"feed": "threatfox", "query": "hash", "term": "zz"})[0] == 400
    assert post_json(app, "/api/feeds/import", {"fetchId": "unknown"})[0] == 404

    def down(request):
        raise urllib.error.URLError("dns failure")

    app.handlers["threatfox-api.abuse.ch"] = down
    status, payload = post_json(app, "/api/feeds/fetch", ok)
    assert status == 502 and "unreachable" in payload["error"] and ABUSECH not in payload["error"]
    del app.env["MAASSPEC_ABUSECH_KEY"]
    status, payload = post_json(app, "/api/feeds/fetch", ok)
    assert status == 409 and "MAASSPEC_ABUSECH_KEY" in payload["error"]


def test_unpacme_needs_no_key(app) -> None:
    del app.env["MAASSPEC_ABUSECH_KEY"]
    app.handlers["api.unpac.me"] = lambda request: _Response(b'{"results":[]}')
    status, payload = post_json(app, "/api/feeds/fetch", {"feed": "unpacme", "query": "feed"})
    assert status == 200 and payload["bytes"] == 14
    assert app.requests[0].full_url == "https://api.unpac.me/api/v1/public/feed"


def test_send_stops_at_the_first_failure(app) -> None:
    ids = [s["analysis_id"] for s in tf_spectra(app)]
    replies = [
        lambda request: _Response(b'{"batch_id":"bt_1","accepted":true,"duplicate":false}'),
        lambda request: (_ for _ in ()).throw(
            urllib.error.HTTPError(request.full_url, 422, "bad", {}, io.BytesIO(b'{"detail":"schema"}'))
        ),
    ]
    app.requests.clear()
    app.handlers["case.example.test"] = lambda request: replies[len(app.requests) - 1](request)
    status, payload = post_json(app, "/api/send", {"ids": ids})
    results = payload["results"]
    assert status == 200 and [r["status"] for r in results] == ["ok", "failed", "not_sent"]
    assert results[0] == {"id": ids[0], "status": "ok", "batchId": "bt_1", "accepted": True, "duplicate": False}
    assert results[1]["httpStatus"] == 422 and "schema" in results[1]["message"]
    assert len(app.requests) == 2
    first = app.requests[0]
    assert first.get_header("Authorization") == f"Bearer {INGEST_KEY}"
    assert first.get_header("Idempotency-key") == ids[0]
    assert INGEST_KEY not in json.dumps(payload)


def test_send_checks_its_inputs_and_configuration(app) -> None:
    ids = [s["analysis_id"] for s in tf_spectra(app)]
    assert post_json(app, "/api/send", {"ids": []})[0] == 400
    assert post_json(app, "/api/send", {"ids": [1]})[0] == 400
    status, payload = post_json(app, "/api/send", {"ids": ["not-held", ids[0]]})
    assert [r["status"] for r in payload["results"]] == ["failed", "not_sent"] and status == 200
    assert not [r for r in app.requests if "case.example.test" in r.full_url]
    del app.env["MAASSPEC_INGEST_KEY"]
    status, payload = post_json(app, "/api/send", {"ids": ids})
    assert status == 409 and "MAASSPEC_INGEST_KEY" in payload["error"]
    app.env["MAASSPEC_INGEST_KEY"] = INGEST_KEY
    app.env["MAASSPEC_NOCTORNAL_URL"] = "http://attacker.example"
    assert post_json(app, "/api/send", {"ids": ids})[0] == 409


def test_body_limits_and_framing(app) -> None:
    head = f"POST /api/analyze HTTP/1.1\r\nHost: 127.0.0.1:{app.port}\r\nX-MaaSSpec-Token: {TOKEN}\r\n"
    assert b"411" in raw(app, (head + "\r\n").encode())
    assert b"413" in raw(app, (head + "Content-Length: 99999999999\r\n\r\n").encode())
    assert b"413" in raw(
        app,
        (
            f"POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:{app.port}\r\nX-MaaSSpec-Token: {TOKEN}\r\n"
            "Content-Length: 2000000\r\n\r\n"
        ).encode(),
    )


def test_make_server_needs_a_built_ui_and_the_cli_says_so(tmp_path, capsys) -> None:
    with pytest.raises(ValueError, match="not built"):
        make_server(tmp_path, port=0)
    assert cli.main(["serve", "--ui-dir", str(tmp_path), "--port", "0"]) == 1
    assert "not built" in capsys.readouterr().err
    assert cli.main(["serve", "--port", "70000"]) == 2


def test_serve_prints_a_loopback_url_with_a_token_and_stops_on_ctrl_c(tmp_path, capsys, monkeypatch) -> None:
    (tmp_path / "index.html").write_text("<!doctype html>", encoding="utf-8")

    def interrupt(self, poll_interval=0.5):
        raise KeyboardInterrupt

    monkeypatch.setattr("http.server.ThreadingHTTPServer.serve_forever", interrupt)
    assert cli.main(["serve", "--ui-dir", str(tmp_path), "--port", "0"]) == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith("MaaSSpec UI: http://127.0.0.1:") and "/#t=" in line
    assert len(line.rsplit("#t=", 1)[1]) >= 30
