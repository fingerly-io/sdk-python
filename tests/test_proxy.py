"""The same-origin proxy, exercised identically under ASGI and WSGI.

Every behavioural test runs through both adapters, so the two standards
cannot drift apart.
"""

from __future__ import annotations

import gzip
import io
from collections.abc import AsyncIterator, Iterator, MutableMapping
from typing import Any, Optional

import httpx
import pytest
from conftest import Recorder, json_response, run

import fingerly
from fingerly import FingerlyProxy, ProxyRequest
from fingerly._proxy import PROXY_VERSION

PROXY_KEY = "fly_px_development_test"
PUBLIC_KEY = "fly_pk_development_test"
PATH = "/k7x2qm4a"
INGEST = "https://api.fingerly.io/api/v1/ingest"


def proxy(recorder: Recorder, **options: Any) -> FingerlyProxy:
    """A proxy whose upstream calls land in the recorder, under both standards."""
    options.setdefault("proxy_key", PROXY_KEY)
    options.setdefault("path", PATH)
    options.setdefault("client_ip", lambda request: "203.0.113.10")
    return FingerlyProxy(
        transport=recorder.transport(),
        async_transport=recorder.transport(),
        **options,
    )


def call_wsgi(
    app: Any,
    path: str = PATH,
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
    path: str = PATH,
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
        for key in [PUBLIC_KEY, "fly_sk_development_test", "nonsense"]:
            with pytest.raises(TypeError):
                FingerlyProxy(client_ip=lambda request: "", proxy_key=key)

    @pytest.mark.parametrize(
        "path", ["k7x2qm4a", "", "/", "//", " / ", "/a?b", "/a#b", 7]
    )
    def test_rejects_an_unusable_path(self, path: Any) -> None:
        with pytest.raises(TypeError):
            FingerlyProxy(client_ip=lambda r: "", proxy_key=PROXY_KEY, path=path)

    def test_normalizes_trailing_slashes_off_the_path(self) -> None:
        for adapter, call in both(
            proxy(recorder := Recorder(json_response({})), path=" /k7x2qm4a// ")
        ):
            status, _, _ = call(adapter, headers={"x-api-key": PUBLIC_KEY})
            assert status == 200
        assert recorder.calls == 2

    def test_reports_the_package_version(self) -> None:
        assert f"python/{fingerly.__version__}" == PROXY_VERSION

    @pytest.mark.parametrize("limits", [{"max_body_bytes": 0}, {"timeout": -1}])
    def test_rejects_unusable_limits(self, limits: dict[str, Any]) -> None:
        with pytest.raises(TypeError):
            FingerlyProxy(client_ip=lambda r: "", proxy_key=PROXY_KEY, **limits)


class TestForwarding:
    @pytest.mark.parametrize(
        "payload", [b'{"signals":{}}', b'{"token":"deferred","signals":{}}']
    )
    def test_forwards_both_calls_to_the_one_ingest_url(self, payload: bytes) -> None:
        # The identification and the deferred report share one path, and the
        # API tells them apart by the body, so the proxy never looks inside.
        for adapter, call in both(
            proxy(recorder := Recorder(json_response({"ok": 1})))
        ):
            status, _, body = call(
                adapter, headers={"x-api-key": PUBLIC_KEY}, body=payload
            )
            assert status == 200
            assert body == b'{"ok": 1}'
        assert [str(request.url) for request in recorder.requests] == [INGEST] * 2
        assert [request.content for request in recorder.requests] == [payload] * 2

    def test_forwards_to_the_configured_versions_ingest_url(self) -> None:
        recorder = Recorder(json_response({}))
        for adapter, call in both(proxy(recorder, api_version="v2")):
            status, _, _ = call(adapter, headers={"x-api-key": PUBLIC_KEY})
            assert status == 200
        assert [str(request.url) for request in recorder.requests] == [
            "https://api.fingerly.io/api/v2/ingest"
        ] * 2

    def test_answers_whatever_was_routed_to_it_without_a_path(self) -> None:
        recorder = Recorder(json_response({}))
        for adapter, call in both(proxy(recorder, path=None)):
            for path in [PATH, "/anything/at/all", ""]:
                status, _, _ = call(
                    adapter, path=path, headers={"x-api-key": PUBLIC_KEY}
                )
                assert status == 200
        assert [str(request.url) for request in recorder.requests] == [INGEST] * 6

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
            assert upstream.headers["x-fingerly-proxy-version"] == "python/0.1.0"
            assert "cookie" not in upstream.headers
            assert "authorization" not in upstream.headers

    def test_relays_only_the_allowlisted_headers(self) -> None:
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
                "ratelimit-limit": "100",
                "ratelimit-remaining": "99",
                "retry-after": "3",
                "x-request-id": "one",
                "fingerly-balance-micros": "100",
                "set-cookie": "a=b",
                "x-powered-by": "fingerly",
            },
        )
        for adapter, call in both(proxy(Recorder(upstream))):
            _, headers, body = call(adapter, headers={"x-api-key": PUBLIC_KEY})
            assert body == plain
            assert headers == {
                "content-type": "application/json",
                "ratelimit-limit": "100",
                "ratelimit-remaining": "99",
                "retry-after": "3",
                "x-request-id": "one",
                "cache-control": "no-store",
                "content-length": str(len(plain)),
            }
            # Nothing relayed may name Fingerly: a blocker can match a header.
            assert "fingerly" not in " ".join(headers).lower()
            assert "fingerly" not in " ".join(headers.values()).lower()

    def test_answers_the_path_with_a_trailing_slash(self) -> None:
        recorder = Recorder(json_response({}))
        for adapter, call in both(proxy(recorder)):
            status, _, _ = call(
                adapter, path=PATH + "/", headers={"x-api-key": PUBLIC_KEY}
            )
            assert status == 200
        assert recorder.calls == 2

    @pytest.mark.parametrize("path", ["", "/"])
    def test_honours_a_mount_at_the_path_from_either_standard(self, path: str) -> None:
        # Mounted at its own path, the proxy sees the path already stripped
        # into root_path or SCRIPT_NAME, with nothing or a slash left over.
        recorder = Recorder(json_response({}))
        mounted = proxy(recorder)
        asgi_status, _, _ = call_asgi(
            mounted.asgi,
            path=path,
            root_path=PATH,
            headers={"x-api-key": PUBLIC_KEY},
        )
        wsgi_status, _, _ = call_wsgi(
            mounted.wsgi,
            path=path,
            script_name=PATH,
            headers={"x-api-key": PUBLIC_KEY},
        )
        assert (asgi_status, wsgi_status) == (200, 200)
        assert recorder.calls == 2

    def test_serves_a_deployment_under_a_sub_uri(self) -> None:
        # A sub-URI puts the deployment's own prefix in root_path or
        # SCRIPT_NAME, and the configured path knows nothing about it. The
        # application-relative path is what both standards agree on.
        recorder = Recorder(json_response({}))
        mounted = proxy(recorder)
        asgi_status, _, _ = call_asgi(
            mounted.asgi,
            path="/shop" + PATH,
            root_path="/shop",
            headers={"x-api-key": PUBLIC_KEY},
        )
        wsgi_status, _, _ = call_wsgi(
            mounted.wsgi,
            path=PATH,
            script_name="/shop",
            headers={"x-api-key": PUBLIC_KEY},
        )
        assert (asgi_status, wsgi_status) == (200, 200)
        assert recorder.calls == 2

    def test_serves_a_sub_uri_deployment_that_also_mounts_the_proxy(self) -> None:
        # Both prefixes in the mount: the proxy sees the stripped form.
        recorder = Recorder(json_response({}))
        mounted = proxy(recorder)
        asgi_status, _, _ = call_asgi(
            mounted.asgi,
            path="/shop" + PATH + "/",
            root_path="/shop" + PATH,
            headers={"x-api-key": PUBLIC_KEY},
        )
        wsgi_status, _, _ = call_wsgi(
            mounted.wsgi,
            path="",
            script_name="/shop" + PATH,
            headers={"x-api-key": PUBLIC_KEY},
        )
        assert (asgi_status, wsgi_status) == (200, 200)
        assert recorder.calls == 2

    def test_never_reads_past_the_declared_wsgi_length(self) -> None:
        """A raw socket, as `flask run` hands over, blocks on the byte after it.

        PEP 3333 forbids reading past CONTENT_LENGTH. This stream raises where
        a socket would hang until the client gave up.
        """

        class Socket(io.BytesIO):
            def read(self, size: Optional[int] = -1) -> bytes:
                left = len(self.getvalue()) - self.tell()
                if size is None or size < 0 or size > left:
                    raise AssertionError("read past CONTENT_LENGTH would block")
                return super().read(size)

        recorder = Recorder(json_response({}))
        payload = b'{"signals":{}}'
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": PATH,
            "CONTENT_LENGTH": str(len(payload)),
            "HTTP_X_API_KEY": PUBLIC_KEY,
            "wsgi.input": Socket(payload),
        }
        statuses: list[str] = []
        proxy(recorder).wsgi(environ, lambda status, headers: statuses.append(status))
        assert statuses == ["200 OK"]
        assert recorder.requests[0].content == payload

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
            "/k7x2qm4a/admin",
            "/k7x2qm4a/api/v1/identify",
            "/k7x2qm4ax",
            "/other",
            "/",
            "",
        ],
    )
    def test_refuses_every_path_but_the_configured_one(self, path: str) -> None:
        for adapter, call in both(proxy(recorder := Recorder(json_response({})))):
            status, _, _ = call(adapter, path=path, headers={"x-api-key": PUBLIC_KEY})
            assert status == 404
        assert recorder.calls == 0

    @pytest.mark.parametrize("path", ["/admin", PATH])
    def test_refuses_what_lies_under_a_mount_at_the_path(self, path: str) -> None:
        # Mounted at its own path, only the mount itself is the path. ASGI is
        # given the whole path here, as Starlette 0.47 and newer report it.
        recorder = Recorder(json_response({}))
        mounted = proxy(recorder)
        asgi_status, _, _ = call_asgi(
            mounted.asgi,
            path=PATH + path,
            root_path=PATH,
            headers={"x-api-key": PUBLIC_KEY},
        )
        wsgi_status, _, _ = call_wsgi(
            mounted.wsgi, path=path, script_name=PATH, headers={"x-api-key": PUBLIC_KEY}
        )
        assert (asgi_status, wsgi_status) == (404, 404)
        assert recorder.calls == 0

    def test_refuses_an_unknown_path_before_the_method(self) -> None:
        for adapter, call in both(proxy(recorder := Recorder(json_response({})))):
            status, _, _ = call(adapter, path="/other", method="GET")
            assert status == 404
        assert recorder.calls == 0

    @pytest.mark.parametrize(
        "public_key",
        [
            None,
            "",
            "fly_pk_production_test",
            "fly_sk_development_test",
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
            for path, method in [
                (PATH, "GET"),
                (PATH + "/events", "GET"),
                (PATH + "/events/x", "GET"),
                (PATH + "/events", "POST"),
            ]:
                status, _, _ = call(
                    adapter, path=path, method=method, headers={"x-api-key": PUBLIC_KEY}
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
            assert request.path == PATH
            assert request.mount == ""
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
        legacy = proxy(recorder, proxy_key=None, secret_key="fly_sk_development_test")
        for adapter, call in both(legacy):
            status, _, _ = call(adapter, headers={})
            assert status == 200
        for upstream in recorder.requests:
            assert upstream.headers["x-api-key"] == "fly_sk_development_test"
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


class TestNoSharedState:
    def test_never_replays_an_upstream_cookie_for_the_next_visitor(self) -> None:
        upstream = httpx.Response(
            200,
            content=b"{}",
            headers={"set-cookie": "balancer=visitor-one; Path=/"},
        )
        recorder = Recorder(upstream)
        for adapter, call in both(proxy(recorder)):
            for _ in range(3):
                call(adapter, headers={"x-api-key": PUBLIC_KEY})
        assert recorder.calls == 6
        assert all("cookie" not in request.headers for request in recorder.requests)


class Chunks(httpx.SyncByteStream, httpx.AsyncByteStream):
    """A response body for either client, optionally failing after its chunks."""

    def __init__(
        self, chunks: list[bytes], failure: Optional[Exception] = None
    ) -> None:
        self._chunks = chunks
        self._failure = failure

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks
        if self._failure is not None:
            raise self._failure

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk
        if self._failure is not None:
            raise self._failure


class TestUpstreamFailures:
    """Upstream trouble is a 502 or 504 with one log line, never a 500."""

    @pytest.mark.parametrize(
        ("failure", "status", "body", "reason"),
        [
            (httpx.ConnectError, 502, b"Bad gateway", "could not connect"),
            (httpx.ReadError, 502, b"Bad gateway", "connection lost"),
            (httpx.RemoteProtocolError, 502, b"Bad gateway", "malformed response"),
            (httpx.ReadTimeout, 504, b"Gateway timeout", "timed out"),
            (httpx.ConnectTimeout, 504, b"Gateway timeout", "timed out"),
            (httpx.PoolTimeout, 504, b"Gateway timeout", "timed out"),
        ],
    )
    def test_answers_a_transport_failure_without_raising(
        self,
        failure: type,
        status: int,
        body: bytes,
        reason: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        def raising(request: httpx.Request) -> httpx.Response:
            raise failure("detail that must not leak", request=request)

        caplog.set_level("WARNING", logger="fingerly.proxy")
        for adapter, call in both(proxy(Recorder.of(raising))):
            got, headers, payload = call(adapter, headers={"x-api-key": PUBLIC_KEY})
            assert (got, payload) == (status, body)
            assert headers["cache-control"] == "no-store"
            assert headers["content-type"] == "text/plain; charset=utf-8"
            assert "fingerly" not in payload.lower().decode()
        assert len(caplog.records) == 2
        for record in caplog.records:
            assert reason in record.getMessage()
            assert "detail that must not leak" not in record.getMessage()
            assert record.exc_info is None

    def test_refuses_an_upstream_body_over_the_cap(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from fingerly._http import MAX_RESPONSE_BYTES

        oversized = b"x" * (MAX_RESPONSE_BYTES + 1)
        recorder = Recorder.of(
            lambda request: httpx.Response(200, stream=Chunks([oversized]))
        )
        caplog.set_level("WARNING", logger="fingerly.proxy")
        for adapter, call in both(proxy(recorder)):
            status, _, payload = call(adapter, headers={"x-api-key": PUBLIC_KEY})
            assert (status, payload) == (502, b"Bad gateway")
        assert all("over 4 MiB" in r.getMessage() for r in caplog.records)

    def test_never_relays_a_truncated_body_as_a_success(self) -> None:
        def truncated(request: httpx.Request) -> httpx.Response:
            failure = httpx.RemoteProtocolError("peer closed", request=request)
            return httpx.Response(200, stream=Chunks([b'{"request_id":'], failure))

        for adapter, call in both(proxy(Recorder.of(truncated))):
            status, _, payload = call(adapter, headers={"x-api-key": PUBLIC_KEY})
            assert (status, payload) == (502, b"Bad gateway")
