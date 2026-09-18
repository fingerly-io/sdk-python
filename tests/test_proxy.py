"""The same-origin proxy, exercised identically under ASGI and WSGI.

Every behavioural test runs through both adapters, so the two standards
cannot drift apart.
"""

from __future__ import annotations

import gzip
import io
from collections.abc import MutableMapping
from typing import Any, Optional

import httpx
import pytest
from conftest import Recorder, json_response, run

from fingerly import FingerlyProxy, ProxyRequest

PROXY_KEY = "fly_px_us_development_test"
PUBLIC_KEY = "fly_pk_us_development_test"
IDENTIFY = "/api/fingerly/api/v1/identify"
SUPPLEMENT = "/api/fingerly/api/v1/events/request-1/supplement"


def proxy(recorder: Recorder, **options: Any) -> FingerlyProxy:
    """A proxy whose upstream calls land in the recorder, under both standards."""
    options.setdefault("proxy_key", PROXY_KEY)
    options.setdefault("client_ip", lambda request: "203.0.113.10")
    return FingerlyProxy(
        transport=recorder.transport(),
        async_transport=recorder.transport(),
        **options,
    )


def call_wsgi(
    app: Any,
    path: str = IDENTIFY,
    method: str = "POST",
    headers: Optional[dict[str, str]] = None,
    body: bytes = b"{}",
    script_name: str = "",
) -> tuple[int, dict[str, str], bytes]:
    """Drives a WSGI app and returns its status, headers and body."""
    environ = {
        "REQUEST_METHOD": method,
        "SCRIPT_NAME": script_name,
        "PATH_INFO": path,
        "CONTENT_LENGTH": str(len(body)),
        "REMOTE_ADDR": "198.51.100.1",
        "wsgi.input": io.BytesIO(body),
    }
    for name, value in (headers or {}).items():
        if name.lower() == "content-type":
            environ["CONTENT_TYPE"] = value
        else:
            environ["HTTP_" + name.upper().replace("-", "_")] = value

    captured: dict[str, Any] = {}

    def start_response(status: str, response_headers: list[tuple[str, str]]) -> None:
        captured["status"] = int(status.split(" ", 1)[0])
        captured["headers"] = {name.lower(): value for name, value in response_headers}

    chunks = app(environ, start_response)
    return captured["status"], captured["headers"], b"".join(chunks)


def call_asgi(
    app: Any,
    path: str = IDENTIFY,
    method: str = "POST",
    headers: Optional[dict[str, str]] = None,
    body: bytes = b"{}",
    root_path: str = "",
    chunks: int = 1,
) -> tuple[int, dict[str, str], bytes]:
    """Drives an ASGI app and returns its status, headers and body."""

    async def drive() -> tuple[int, dict[str, str], bytes]:
        scope: dict[str, Any] = {
            "type": "http",
            "method": method,
            "path": path,
            "root_path": root_path,
            "client": ("198.51.100.1", 54321),
            "headers": [
                (name.lower().encode(), value.encode())
                for name, value in (headers or {}).items()
            ],
        }
        pieces = _split(body, chunks)
        messages = [
            {
                "type": "http.request",
                "body": piece,
                "more_body": index < len(pieces) - 1,
            }
            for index, piece in enumerate(pieces)
        ]
        sent: list[dict[str, Any]] = []

        async def receive() -> MutableMapping[str, Any]:
            return messages.pop(0)

        async def send(message: MutableMapping[str, Any]) -> None:
            sent.append(dict(message))

        await app(scope, receive, send)
        start = next(m for m in sent if m["type"] == "http.response.start")
        payload = b"".join(
            m.get("body", b"") for m in sent if m["type"] == "http.response.body"
        )
        return (
            start["status"],
            {name.decode().lower(): value.decode() for name, value in start["headers"]},
            payload,
        )

    return run(drive())


def _split(body: bytes, chunks: int) -> list[bytes]:
    """Splits a body into contiguous pieces, as a streaming client would send it."""
    if chunks <= 1:
        return [body]
    size = max(1, -(-len(body) // chunks))
    return [body[start : start + size] for start in range(0, len(body), size)] or [b""]


def both(app_proxy: FingerlyProxy) -> list[tuple[Any, Any]]:
    """The two adapters and the caller that drives each one."""
    return [(app_proxy.asgi, call_asgi), (app_proxy.wsgi, call_wsgi)]


class TestConstruction:
    def test_requires_a_proxy_key_and_a_client_ip(self) -> None:
        with pytest.raises(TypeError):
            FingerlyProxy(client_ip=lambda request: "")
        with pytest.raises(TypeError):
            FingerlyProxy(
                client_ip=lambda request: "", proxy_key=PROXY_KEY, secret_key="x"
            )
        with pytest.raises(TypeError):
            FingerlyProxy(client_ip=None, proxy_key=PROXY_KEY)  # type: ignore[arg-type]

    def test_rejects_a_key_of_the_wrong_kind(self) -> None:
        for key in [PUBLIC_KEY, "fly_sk_us_development_test", "nonsense"]:
            with pytest.raises(TypeError):
                FingerlyProxy(client_ip=lambda request: "", proxy_key=key)

    @pytest.mark.parametrize("prefix", ["metrics", "", "/a?b", "/a#b", 7])
    def test_rejects_an_unusable_prefix(self, prefix: Any) -> None:
        with pytest.raises(TypeError):
            FingerlyProxy(client_ip=lambda r: "", proxy_key=PROXY_KEY, prefix=prefix)

    @pytest.mark.parametrize("limits", [{"max_body_bytes": 0}, {"timeout": -1}])
    def test_rejects_unusable_limits(self, limits: dict[str, Any]) -> None:
        with pytest.raises(TypeError):
            FingerlyProxy(client_ip=lambda r: "", proxy_key=PROXY_KEY, **limits)


class TestForwarding:
    @pytest.mark.parametrize("path", [IDENTIFY, SUPPLEMENT])
    def test_forwards_both_proxyable_routes(self, path: str) -> None:
        for adapter, call in both(
            proxy(recorder := Recorder(json_response({"ok": 1})))
        ):
            status, _, body = call(
                adapter, path=path, headers={"x-api-key": PUBLIC_KEY}
            )
            assert status == 200
            assert body == b'{"ok": 1}'
        assert [str(request.url) for request in recorder.requests] == [
            f"https://us.api.fingerly.io{path.replace('/api/fingerly', '')}"
        ] * 2

    def test_sends_only_vetted_visitor_metadata(self) -> None:
        recorder = Recorder(json_response({"request_id": "one"}))
        headers = {
            "x-api-key": PUBLIC_KEY,
            "origin": "https://shop.test",
            "user-agent": "Firefox",
            "cookie": "session=secret",
            "authorization": "Bearer secret",
            "idempotency-key": "idem-1",
        }
        for adapter, call in both(proxy(recorder)):
            call(adapter, headers=headers)

        for upstream in recorder.requests:
            assert upstream.headers["x-api-key"] == PUBLIC_KEY
            assert upstream.headers["x-fingerly-proxy-key"] == PROXY_KEY
            assert upstream.headers["x-fingerly-client-ip"] == "203.0.113.10"
            assert upstream.headers["x-fingerly-origin"] == "https://shop.test"
            assert upstream.headers["x-fingerly-user-agent"] == "Firefox"
            assert upstream.headers["idempotency-key"] == "idem-1"
            assert "cookie" not in upstream.headers
            assert "authorization" not in upstream.headers

    def test_marks_responses_uncacheable_and_drops_connection_headers(self) -> None:
        """httpx decodes the body, so replaying content-encoding would lie."""
        plain = b'{"ok":1}'
        upstream = httpx.Response(
            200,
            content=gzip.compress(plain),
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
                "transfer-encoding": "chunked",
                "cache-control": "public, max-age=600",
                "ratelimit-remaining": "99",
            },
        )
        for adapter, call in both(proxy(Recorder(upstream))):
            _, headers, body = call(adapter, headers={"x-api-key": PUBLIC_KEY})
            assert body == plain
            assert headers["content-length"] == str(len(plain))
            assert headers["cache-control"] == "no-store"
            assert headers["ratelimit-remaining"] == "99"
            assert "content-encoding" not in headers
            assert "transfer-encoding" not in headers

    def test_honours_the_mount_prefix_from_either_standard(self) -> None:
        recorder = Recorder(json_response({}))
        mounted = proxy(recorder, prefix="/metrics")
        asgi_status, _, _ = call_asgi(
            mounted.asgi,
            path="/api/v1/identify",
            root_path="/metrics",
            headers={"x-api-key": PUBLIC_KEY},
        )
        wsgi_status, _, _ = call_wsgi(
            mounted.wsgi,
            path="/api/v1/identify",
            script_name="/metrics",
            headers={"x-api-key": PUBLIC_KEY},
        )
        assert (asgi_status, wsgi_status) == (200, 200)
        assert recorder.calls == 2

    def test_serves_a_deployment_under_a_sub_uri(self) -> None:
        # A sub-URI puts the deployment's own prefix in root_path or
        # SCRIPT_NAME, and the configured prefix knows nothing about it. The
        # application-relative path is what both standards agree on.
        recorder = Recorder(json_response({}))
        mounted = proxy(recorder, prefix="/metrics")
        asgi_status, _, _ = call_asgi(
            mounted.asgi,
            path="/shop/metrics/api/v1/identify",
            root_path="/shop",
            headers={"x-api-key": PUBLIC_KEY},
        )
        wsgi_status, _, _ = call_wsgi(
            mounted.wsgi,
            path="/metrics/api/v1/identify",
            script_name="/shop",
            headers={"x-api-key": PUBLIC_KEY},
        )
        assert (asgi_status, wsgi_status) == (200, 200)
        assert recorder.calls == 2

    def test_serves_a_sub_uri_deployment_that_also_mounts_the_proxy(self) -> None:
        # Both prefixes in the mount: the proxy sees the stripped form.
        recorder = Recorder(json_response({}))
        mounted = proxy(recorder, prefix="/metrics")
        asgi_status, _, _ = call_asgi(
            mounted.asgi,
            path="/shop/metrics/api/v1/identify",
            root_path="/shop/metrics",
            headers={"x-api-key": PUBLIC_KEY},
        )
        wsgi_status, _, _ = call_wsgi(
            mounted.wsgi,
            path="/api/v1/identify",
            script_name="/shop/metrics",
            headers={"x-api-key": PUBLIC_KEY},
        )
        assert (asgi_status, wsgi_status) == (200, 200)
        assert recorder.calls == 2

    def test_reassembles_a_streamed_asgi_body(self) -> None:
        recorder = Recorder(json_response({}))
        payload = b'{"signals":"' + b"x" * 300 + b'"}'
        call_asgi(
            proxy(recorder).asgi,
            headers={"x-api-key": PUBLIC_KEY},
            body=payload,
            chunks=4,
        )
        assert recorder.requests[0].content == payload


class TestRefusals:
    def test_refuses_anything_but_post(self) -> None:
        for adapter, call in both(proxy(recorder := Recorder(json_response({})))):
            status, headers, _ = call(
                adapter, method="GET", headers={"x-api-key": PUBLIC_KEY}
            )
            assert status == 405
            assert headers["allow"] == "POST"
        assert recorder.calls == 0

    @pytest.mark.parametrize(
        "path",
        [
            "/api/fingerly/api/v1/events/request-1",
            "/api/fingerly/api/v1/events",
            "/api/fingerly/api/v1/events/a/b/supplement",
            "/api/fingerly/api/v1/identify/extra",
            "/api/fingerly/api/v2/identify",
            "/api/fingerly/admin",
            "/elsewhere/api/v1/identify",
        ],
    )
    def test_refuses_every_route_that_is_not_proxyable(self, path: str) -> None:
        for adapter, call in both(proxy(recorder := Recorder(json_response({})))):
            status, _, _ = call(adapter, path=path, headers={"x-api-key": PUBLIC_KEY})
            assert status == 404
        assert recorder.calls == 0

    @pytest.mark.parametrize(
        "public_key",
        [
            None,
            "",
            "fly_pk_eu_development_test",
            "fly_pk_us_production_test",
            "fly_sk_us_development_test",
            "invalid",
        ],
    )
    def test_refuses_a_public_key_from_another_deployment(
        self, public_key: Optional[str]
    ) -> None:
        headers = {} if public_key is None else {"x-api-key": public_key}
        for adapter, call in both(proxy(recorder := Recorder(json_response({})))):
            status, _, _ = call(adapter, headers=headers)
            assert status == 401
        assert recorder.calls == 0

    def test_refuses_an_oversized_declared_body(self) -> None:
        for adapter, call in both(
            proxy(recorder := Recorder(json_response({})), max_body_bytes=4)
        ):
            status, _, _ = call(
                adapter, headers={"x-api-key": PUBLIC_KEY}, body=b"far too long"
            )
            assert status == 413
        assert recorder.calls == 0

    def test_refuses_an_oversized_streamed_body(self) -> None:
        """A chunked ASGI body declares no length, so the limit is enforced live."""
        recorder = Recorder(json_response({}))
        status, _, _ = call_asgi(
            proxy(recorder, max_body_bytes=4).asgi,
            headers={"x-api-key": PUBLIC_KEY},
            body=b"far too long",
            chunks=4,
        )
        assert status == 413
        assert recorder.calls == 0

    def test_never_reads_events_through_the_proxy(self) -> None:
        """Event reads need a secret key and must be unreachable from a browser."""
        for adapter, call in both(proxy(recorder := Recorder(json_response({})))):
            for path in [
                "/api/fingerly/api/v1/events",
                "/api/fingerly/api/v1/events/x",
            ]:
                status, _, _ = call(
                    adapter, path=path, method="GET", headers={"x-api-key": PUBLIC_KEY}
                )
                assert status in (404, 405)
        assert recorder.calls == 0


class TestClientIp:
    def test_passes_a_neutral_request_to_the_callback(self) -> None:
        seen: list[ProxyRequest] = []

        def client_ip(request: ProxyRequest) -> str:
            seen.append(request)
            return str(request.headers.get("cf-connecting-ip", ""))

        for adapter, call in both(
            proxy(Recorder(json_response({})), client_ip=client_ip)
        ):
            call(
                adapter,
                headers={"x-api-key": PUBLIC_KEY, "CF-Connecting-IP": "203.0.113.7"},
            )

        assert len(seen) == 2
        for request in seen:
            assert request.method == "POST"
            assert request.path == IDENTIFY
            # Header lookup is case-insensitive under both standards.
            assert request.headers["cf-connecting-ip"] == "203.0.113.7"
            assert request.peer_host == "198.51.100.1"

    @pytest.mark.parametrize("address", ["1.2.3.4\r\nx-evil: 1", "hé", 7, None])
    def test_refuses_a_callback_result_that_could_inject_a_header(
        self, address: Any
    ) -> None:
        recorder = Recorder(json_response({}))
        injected = proxy(recorder, client_ip=lambda request: address)
        for adapter, call in both(injected):
            with pytest.raises(TypeError):
                call(adapter, headers={"x-api-key": PUBLIC_KEY})
        assert recorder.calls == 0


class TestDeprecatedSecretKey:
    def test_forwards_the_secret_key_without_a_public_key(self) -> None:
        recorder = Recorder(json_response({}))
        legacy = proxy(
            recorder, proxy_key=None, secret_key="fly_sk_us_development_test"
        )
        for adapter, call in both(legacy):
            status, _, _ = call(adapter, headers={})
            assert status == 200
        for upstream in recorder.requests:
            assert upstream.headers["x-api-key"] == "fly_sk_us_development_test"
            assert "x-fingerly-proxy-key" not in upstream.headers


class TestLifecycle:
    def test_closing_is_idempotent(self) -> None:
        instance = proxy(Recorder(json_response({})))
        instance.close()
        instance.close()
        run(instance.aclose())
        run(instance.aclose())

    def test_acknowledges_asgi_lifespan(self) -> None:
        """Mounted apps never see lifespan, but a root app must answer it."""

        async def drive() -> list[dict[str, Any]]:
            messages: list[dict[str, Any]] = [
                {"type": "lifespan.startup"},
                {"type": "lifespan.shutdown"},
            ]
            sent: list[dict[str, Any]] = []

            async def receive() -> MutableMapping[str, Any]:
                return messages.pop(0)

            async def send(message: MutableMapping[str, Any]) -> None:
                sent.append(dict(message))

            await proxy(Recorder(json_response({}))).asgi(
                {"type": "lifespan"}, receive, send
            )
            return sent

        assert [message["type"] for message in run(drive())] == [
            "lifespan.startup.complete",
            "lifespan.shutdown.complete",
        ]
