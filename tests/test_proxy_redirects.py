"""No upstream redirect is followed or relayed, whatever transport is supplied."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from conftest import Recorder
from raw_upstream import RawUpstream, answering, real
from test_proxy import BROWSER, both, proxy


@pytest.fixture
def target() -> Iterator[RawUpstream]:
    server = answering("200")
    yield server
    server.close()


@pytest.mark.parametrize("status", [300, 301, 302, 303, 304, 307, 308, 399])
def test_a_redirect_answer_is_a_bad_gateway(status: int) -> None:
    recorder = Recorder(
        httpx.Response(status, headers={"location": "https://elsewhere.invalid/"})
    )
    for adapter, call in both(proxy(recorder)):
        got, headers, payload = call(adapter, headers=BROWSER)
        assert (got, payload) == (502, b"Bad gateway")
        assert headers["cache-control"] == "no-store"
        assert "location" not in headers
    assert recorder.calls == 2


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_no_redirect_is_followed_with_the_key(status: int, target: RawUpstream) -> None:
    first = answering(str(status), f"location: {target.origin}/collect\r\n")
    try:
        for supplied in (False, True):
            options: dict[str, Any] = {}
            if supplied:
                # The proxy's own client wraps a supplied transport with
                # redirects off, so the transport cannot turn them on.
                options["transport"] = httpx.HTTPTransport()
                options["async_transport"] = httpx.AsyncHTTPTransport()
            for adapter, call in both(real(first.origin, **options)):
                got, headers, _ = call(adapter, headers=BROWSER)
                assert got == 502
                assert headers["cache-control"] == "no-store"
        assert first.hits == 4
        assert target.hits == 0
    finally:
        first.close()


def test_a_redirect_log_names_no_upstream(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG", logger="fingerly.proxy")
    recorder = Recorder(httpx.Response(307, headers={"location": "https://x.invalid"}))
    for adapter, call in both(proxy(recorder, upstream="https://upstream.invalid")):
        call(adapter, headers=BROWSER)
    assert caplog.records
    for record in caplog.records:
        assert "upstream.invalid" not in record.getMessage()
        assert "x.invalid" not in record.getMessage()
