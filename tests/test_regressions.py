"""Failures found by driving the built package through real servers."""

from __future__ import annotations

import hmac
import io
from hashlib import sha256
from typing import Any

import httpx
import pytest
from conftest import SECRET_KEY, Recorder, error_response, run
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

from fingerly import (
    AsyncFingerly,
    Fingerly,
    FingerlyAPIError,
    FingerlyProxy,
    ProxyRequest,
    verify_webhook,
)
from fingerly._http import Reply
from fingerly._proxy import Headers, _relay
from fingerly._transport import retry_after_seconds

PROXY_KEY = "fly_px_development_regressions"
PUBLIC_KEY = "fly_pk_development_regressions"
LIMITS = httpx.Limits(max_connections=4)


class TestWebhookTimestampOfAnyLength:
    @pytest.mark.parametrize("digits", [400, 5000])
    def test_is_a_failed_verification_not_an_exception(self, digits: int) -> None:
        # Anyone can post to a webhook URL. 400 digits overflowed the float
        # comparison and 5000 passed the interpreter's int parsing limit, so
        # the handler answered 500 where the docs promise False.
        timestamp = "1" * digits
        mac = hmac.new(b"whsec", f"{timestamp}.".encode(), sha256).hexdigest()
        assert not verify_webhook("whsec", b"{}", timestamp, f"sha256={mac}")


class TestDigitsThatAreNotNumbers:
    def test_retry_after_superscript_is_unreadable(self) -> None:
        # str.isdigit() accepts it and float() does not.
        assert retry_after_seconds("²") is None

    def test_api_error_survives_it(self) -> None:
        recorder = Recorder.of(
            lambda _: httpx.Response(
                429, content=b"{}", headers=[(b"retry-after", "²".encode())]
            )
        )
        client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
        with pytest.raises(FingerlyAPIError) as caught:
            client.events.get("abc")
        assert caught.value.retry_after is None

    def test_declared_length_superscript_does_not_raise(self) -> None:
        proxy = FingerlyProxy(proxy_key=PROXY_KEY, client_ip=lambda _: "203.0.113.7")
        request = ProxyRequest(
            "POST",
            "/x",
            Headers([("x-api-key", PUBLIC_KEY), ("content-length", "²")]),
        )
        assert proxy.screen(request).refusal is None


def _wsgi_call(proxy: FingerlyProxy, **environ: Any) -> tuple[str, bytes]:
    """Calls the WSGI adapter directly and returns the status line and body."""
    started: list[str] = []
    base = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/x",
        "HTTP_X_API_KEY": PUBLIC_KEY,
        "REMOTE_ADDR": "203.0.113.7",
    }
    chunks = proxy.wsgi(
        {**base, **environ}, lambda status, _headers: started.append(status)
    )
    return started[0], b"".join(chunks)


class _RawSocket:
    """A ``wsgi.input`` that has no end of its own, as development servers give."""

    def read(self, _size: int = -1) -> bytes:
        raise AssertionError("read past the end of the request; this would hang")


class _BrokenChunks:
    """A ``wsgi.input`` whose server found the chunked framing invalid."""

    def read(self, _size: int = -1) -> bytes:
        raise OSError("Invalid chunk header")


class TestWsgiBodies:
    def test_no_length_and_no_chunking_means_no_body(self) -> None:
        # `flask run` and wsgiref hand over the raw socket, so reading here
        # held the thread until the client gave up.
        recorder = Recorder(error_response("consent_required", 422))
        proxy = FingerlyProxy(
            proxy_key=PROXY_KEY,
            client_ip=lambda _: "203.0.113.7",
            transport=recorder.transport(),
        )
        status, _ = _wsgi_call(proxy, **{"wsgi.input": _RawSocket()})
        assert status.startswith("422")
        assert recorder.requests[0].content == b""

    def test_a_chunked_body_is_still_read_without_a_length(self) -> None:
        recorder = Recorder(error_response("consent_required", 422))
        proxy = FingerlyProxy(
            proxy_key=PROXY_KEY,
            client_ip=lambda _: "203.0.113.7",
            transport=recorder.transport(),
        )
        _wsgi_call(
            proxy,
            HTTP_TRANSFER_ENCODING="chunked",
            **{"wsgi.input": io.BytesIO(b"{}")},
        )
        assert recorder.requests[0].content == b"{}"

    def test_a_body_the_server_cannot_read_is_a_400(self) -> None:
        # A visitor can send broken framing at will, and each one otherwise
        # became an error-level traceback in the server's log.
        recorder = Recorder(error_response("consent_required", 422))
        proxy = FingerlyProxy(
            proxy_key=PROXY_KEY,
            client_ip=lambda _: "203.0.113.7",
            transport=recorder.transport(),
        )
        status, body = _wsgi_call(
            proxy,
            HTTP_TRANSFER_ENCODING="chunked",
            **{"wsgi.input": _BrokenChunks()},
        )
        assert status.startswith("400")
        assert body == b"Bad Request"
        assert recorder.calls == 0


class TestVisitorWhoLeaves:
    def test_http_middleware_gets_a_response_to_hand_back(self) -> None:
        # Starlette's BaseHTTPMiddleware raises "No response returned" when an
        # app finishes silently, so with `@app.middleware("http")` every tab
        # closed during an identification was an error-level traceback.
        proxy = FingerlyProxy(proxy_key=PROXY_KEY, client_ip=lambda _: "203.0.113.7")

        async def passthrough(request: Any, call_next: Any) -> Any:
            return await call_next(request)

        app = Starlette(
            middleware=[Middleware(BaseHTTPMiddleware, dispatch=passthrough)]
        )
        app.add_route("/x", proxy.asgi, methods=["POST"])  # type: ignore[arg-type]

        async def drive() -> list[Any]:
            sent: list[Any] = []

            async def receive() -> dict[str, Any]:
                return {"type": "http.disconnect"}

            async def send(message: Any) -> None:
                sent.append(message)

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/x",
                "raw_path": b"/x",
                "root_path": "",
                "query_string": b"",
                "headers": [(b"x-api-key", PUBLIC_KEY.encode())],
            }
            await app(scope, receive, send)
            return sent

        assert run(drive())[0]["status"] == 499

    def test_a_server_that_refuses_the_write_is_not_an_error(self) -> None:
        # ASGI 2.4 lets a server raise OSError for a send on a closed connection.
        proxy = FingerlyProxy(proxy_key=PROXY_KEY, client_ip=lambda _: "203.0.113.7")

        async def drive() -> None:
            async def receive() -> dict[str, Any]:
                return {"type": "http.disconnect"}

            async def send(_message: Any) -> None:
                raise ConnectionResetError

            scope = {
                "type": "http",
                "method": "POST",
                "path": "/x",
                "root_path": "",
                "headers": [(b"x-api-key", PUBLIC_KEY.encode())],
            }
            await proxy.asgi(scope, receive, send)

        run(drive())


class TestHeaderValuesOnTheWire:
    def test_a_surrogate_escaped_value_does_not_raise(self) -> None:
        # Sanic decodes header bytes with surrogateescape.
        recorder = Recorder(error_response("consent_required", 422))
        proxy = FingerlyProxy(
            proxy_key=PROXY_KEY,
            client_ip=lambda _: "203.0.113.7",
            transport=recorder.transport(),
        )
        request = ProxyRequest(
            "POST",
            "/x",
            Headers([("x-api-key", PUBLIC_KEY), ("user-agent", "caf\udce9")]),
        )
        assert proxy.forward(proxy.screen(request), request, b"{}").status == 422


class TestRelayedHeaders:
    def test_a_value_the_server_cannot_write_is_dropped(self) -> None:
        # ASGI and WSGI servers write headers as Latin-1, so this raised
        # while answering, after the upstream exchange had succeeded.
        headers = httpx.Headers(
            [(b"x-request-id", "€".encode()), (b"ratelimit-limit", b"10")]
        )
        relayed = dict(_relay(Reply(200, headers, b"{}")).headers)
        assert "x-request-id" not in relayed
        assert relayed["ratelimit-limit"] == "10"


class TestDotSegmentRequestIds:
    @pytest.mark.parametrize(
        ("request_id", "expected"),
        [(".", b"/api/v1/events/%2E"), ("..", b"/api/v1/events/%2E%2E")],
    )
    def test_stays_inside_the_events_path(
        self, request_id: str, expected: bytes
    ) -> None:
        # httpx removes dot segments, so "." read the event list instead.
        # Request ids come from the browser.
        recorder = Recorder(error_response("invalid_request_id", 422))
        client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
        with pytest.raises(FingerlyAPIError, match="HTTP 422"):
            client.events.get(request_id)
        assert recorder.requests[0].url.raw_path == expected


class TestEndpointsRefusedAtConstruction:
    @pytest.mark.parametrize(
        "endpoint",
        [
            "http://x:abc",
            "http://a.b:99999",
            "http://[::1",
            "https://a.b\n",
            "http://exa mple.com",
        ],
    )
    def test_fails_before_any_request(self, endpoint: str) -> None:
        with pytest.raises(TypeError, match="endpoint must be"):
            Fingerly(secret_key=SECRET_KEY, endpoint=endpoint)
        with pytest.raises(TypeError, match="endpoint must be"):
            FingerlyProxy(
                proxy_key=PROXY_KEY, upstream=endpoint, client_ip=lambda _: ""
            )


class TestScreeningRedaction:
    def test_repr_does_not_print_the_key_it_will_present(self) -> None:
        proxy = FingerlyProxy(secret_key=SECRET_KEY, client_ip=lambda _: "203.0.113.7")
        screening = proxy.screen(ProxyRequest("POST", "/x", Headers([])))
        assert screening.api_key == SECRET_KEY
        assert SECRET_KEY not in repr(screening)
        assert SECRET_KEY not in str(screening)


class TestOneTlsContext:
    def test_every_small_pool_shares_it(self) -> None:
        # Each context loads the whole CA bundle: 64 pools cost 49 MB and up
        # to 0.9 s, under the pool lock or on the event loop, at every recycle.
        client = Fingerly(secret_key=SECRET_KEY)
        reader = AsyncFingerly(secret_key=SECRET_KEY)
        pools: list[Any] = [client._pool, reader._pool]
        built = [pool._shards._build(LIMITS) for pool in pools for _ in range(2)]
        contexts = {id(item._transport._pool._ssl_context) for item in built}
        assert len(contexts) == 1
