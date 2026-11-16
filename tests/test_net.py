import urllib.error
import urllib.request

import pytest

from maasspec import net


class _Response:
    def __init__(self, body: bytes = b"ok") -> None:
        self.body = body

    def read(self, n: int = -1) -> bytes:
        return self.body if n < 0 else self.body[:n]

    def close(self) -> None:
        return None


def _ok(request, timeout):
    return _Response()


def test_https_to_an_allowed_host_works() -> None:
    assert net.request("https://api.example.test/x", allow_hosts={"api.example.test"}, opener=_ok) == b"ok"


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example.test/x",
        "http://api.example.test/x",
        "https://user:pw@api.example.test/x",
        "file:///etc/passwd",
        "https:///x",
    ],
)
def test_refuses_what_the_policy_does_not_allow(url: str) -> None:
    with pytest.raises(net.HttpError):
        net.request(url, allow_hosts={"api.example.test"}, opener=_ok)


def test_loopback_http_needs_the_opt_in() -> None:
    url = "http://127.0.0.1:8000/x"
    with pytest.raises(net.HttpError):
        net.request(url, allow_hosts={"127.0.0.1"}, opener=_ok)
    assert net.request(url, allow_hosts={"127.0.0.1"}, allow_loopback_http=True, opener=_ok) == b"ok"
    with pytest.raises(net.HttpError):
        net.request(
            "http://127.0.0.1.evil.example/x",
            allow_hosts={"127.0.0.1.evil.example"},
            allow_loopback_http=True,
            opener=_ok,
        )


def test_refuses_a_header_with_a_line_break() -> None:
    with pytest.raises(net.HttpError):
        net.request(
            "https://api.example.test/x",
            allow_hosts={"api.example.test"},
            headers={"Auth-Key": "abc\r\nX-Evil: 1"},
            opener=_ok,
        )


def test_caps_the_response() -> None:
    def big(request, timeout):
        return _Response(b"x" * 100)

    with pytest.raises(net.HttpError, match="cap"):
        net.request("https://api.example.test/x", allow_hosts={"api.example.test"}, max_bytes=10, opener=big)


def test_a_redirect_is_refused_and_errors_carry_no_secrets() -> None:
    handler = net._NoRedirect()
    request = urllib.request.Request("https://api.example.test/x")
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/")

    def refused(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 302, "redirect refused", {}, None)

    with pytest.raises(net.HttpError) as caught:
        net.request(
            "https://api.example.test/x?token=SECRET",
            allow_hosts={"api.example.test"},
            headers={"Auth-Key": "SECRETKEYVALUE"},
            opener=refused,
        )
    assert "SECRET" not in str(caught.value)


def test_an_unreachable_host_is_a_plain_error() -> None:
    def down(request, timeout):
        raise urllib.error.URLError("dns failure with details")

    with pytest.raises(net.HttpError, match="unreachable"):
        net.request("https://api.example.test/x", allow_hosts={"api.example.test"}, opener=down)
