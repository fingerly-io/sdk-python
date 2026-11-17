"""The upstream option is a bare origin, and failure logs never name it."""

from __future__ import annotations

import socket

import pytest
from conftest import Recorder, json_response
from raw_upstream import real
from test_proxy import BROWSER, PROXY_KEY, both, proxy

from fingerly import FingerlyProxy


@pytest.mark.parametrize(
    "upstream",
    [
        "https://upstream.invalid/prefix",
        "https://upstream.invalid/a/../b",
        "https://upstream.invalid//",
        "https://upstream.invalid?",
        "https://upstream.invalid?x=1",
        "https://upstream.invalid#",
        "https://upstream.invalid#f",
        "https://user:pass@upstream.invalid",
        "https://@upstream.invalid",
        "https://upstream.invalid\n",
        "https://upstream.invalid ",
        " https://upstream.invalid",
        "https://upstream.invalid\r\nx-injected: 1",
        "https://upstream.invalid\t",
        "https://upstréam.invalid",
        "ftp://upstream.invalid",
        "https://",
        "upstream.invalid",
        "",
    ],
)
def test_refuses_anything_but_a_bare_https_origin(upstream: str) -> None:
    for allow in (False, True):
        with pytest.raises(TypeError, match="upstream must") as raised:
            FingerlyProxy(
                proxy_key=PROXY_KEY,
                upstream=upstream,
                allow_insecure_loopback=allow,
                client_ip=lambda _: "",
            )
        assert "upstream.invalid" not in str(raised.value)
        assert PROXY_KEY not in str(raised.value)


@pytest.mark.parametrize(
    ("upstream", "expected"),
    [
        ("https://upstream.invalid", "https://upstream.invalid/api/v1/ingest"),
        ("https://upstream.invalid/", "https://upstream.invalid/api/v1/ingest"),
        (
            "https://upstream.invalid:8443",
            "https://upstream.invalid:8443/api/v1/ingest",
        ),
        ("https://UPSTREAM.invalid", "https://upstream.invalid/api/v1/ingest"),
    ],
)
def test_the_target_is_rebuilt_from_scheme_host_and_port(
    upstream: str, expected: str
) -> None:
    recorder = Recorder(json_response({}))
    for adapter, call in both(proxy(recorder, upstream=upstream)):
        assert call(adapter, headers=BROWSER)[0] == 200
    assert {str(request.url) for request in recorder.requests} == {expected}


def test_an_unreachable_upstream_is_not_named(caplog: pytest.LogCaptureFixture) -> None:
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    caplog.set_level("DEBUG", logger="fingerly.proxy")
    for adapter, call in both(real(f"http://127.0.0.1:{port}")):
        got, _, payload = call(adapter, headers=BROWSER)
        assert got == 502
        assert b"127.0.0.1" not in payload
    assert caplog.records
    for record in caplog.records:
        text = record.getMessage()
        for leak in ("127.0.0.1", str(port), "ingest", "http", PROXY_KEY):
            assert leak not in text
