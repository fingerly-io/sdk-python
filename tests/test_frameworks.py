"""The proxy mounted in real frameworks, not a hand-rolled server.

ASGI servers disagree about what ``path`` holds under a mount, and a mistake
there is invisible to a driver written against the same assumption as the code.
These tests drive Starlette and Flask themselves, through httpx's own ASGI and
WSGI transports, so the disagreement is exercised rather than assumed.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from conftest import run

from fingerly import FingerlyProxy

starlette_applications = pytest.importorskip("starlette.applications")
starlette_routing = pytest.importorskip("starlette.routing")
flask = pytest.importorskip("flask")
dispatcher = pytest.importorskip("werkzeug.middleware.dispatcher")

PROXY_KEY = "fly_px_us_development_test"
PUBLIC_KEY = "fly_pk_us_development_test"
BROWSER_HEADERS = {
    "x-api-key": PUBLIC_KEY,
    "origin": "https://shop.test",
    "cf-connecting-ip": "203.0.113.5",
    "cookie": "session=secret",
}


class Upstream:
    """Stands in for the Fingerly API and keeps what reached it."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, json={"request_id": "identified"})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


def build(upstream: Upstream, **options: Any) -> FingerlyProxy:
    """A proxy mounted at /metrics whose upstream is the fake above."""
    options.setdefault("proxy_key", PROXY_KEY)
    options.setdefault("prefix", "/metrics")
    return FingerlyProxy(
        client_ip=lambda request: request.headers.get("cf-connecting-ip", ""),
        transport=upstream.transport(),
        async_transport=upstream.transport(),
        **options,
    )


class TestStarlette:
    def starlette_client(self, proxy: FingerlyProxy) -> httpx.AsyncClient:
        app = starlette_applications.Starlette(
            routes=[starlette_routing.Mount("/metrics", app=proxy.asgi)]
        )
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://shop.test"
        )

    def test_forwards_identify_from_a_mounted_app(self) -> None:
        upstream = Upstream()

        async def drive() -> httpx.Response:
            async with self.starlette_client(build(upstream)) as client:
                return await client.post(
                    "/metrics/api/v1/identify",
                    headers=BROWSER_HEADERS,
                    content=b'{"signals":{}}',
                )

        response = run(drive())
        assert response.status_code == 200
        assert response.json() == {"request_id": "identified"}
        assert response.headers["cache-control"] == "no-store"

        forwarded = upstream.requests[0]
        assert str(forwarded.url) == "https://us.api.fingerly.io/api/v1/identify"
        assert forwarded.headers["x-fingerly-client-ip"] == "203.0.113.5"
        assert forwarded.headers["x-fingerly-proxy-key"] == PROXY_KEY
        assert "cookie" not in forwarded.headers

    def test_forwards_from_a_deployment_under_a_sub_uri(self) -> None:
        # Nested mounts, which is what a sub-URI deployment looks like: the
        # outer prefix belongs to the deployment and the proxy's configuration
        # knows nothing about it.
        upstream = Upstream()
        inner = starlette_applications.Starlette(
            routes=[starlette_routing.Mount("/metrics", app=build(upstream).asgi)]
        )
        app = starlette_applications.Starlette(
            routes=[starlette_routing.Mount("/shop", app=inner)]
        )

        async def drive() -> httpx.Response:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://shop.test"
            ) as client:
                return await client.post(
                    "/shop/metrics/api/v1/identify",
                    headers=BROWSER_HEADERS,
                    content=b'{"signals":{}}',
                )

        response = run(drive())
        assert response.status_code == 200
        assert str(upstream.requests[0].url) == (
            "https://us.api.fingerly.io/api/v1/identify"
        )

    def test_refuses_event_reads_and_unknown_routes(self) -> None:
        upstream = Upstream()

        async def drive() -> list[int]:
            async with self.starlette_client(build(upstream)) as client:
                return [
                    (
                        await client.post(
                            f"/metrics{path}", headers=BROWSER_HEADERS, content=b"{}"
                        )
                    ).status_code
                    for path in [
                        "/api/v1/events",
                        "/api/v1/events/request-1",
                        "/api/v1/admin",
                    ]
                ]

        assert run(drive()) == [404, 404, 404]
        assert upstream.requests == []

    def test_refuses_a_browser_key_from_another_deployment(self) -> None:
        upstream = Upstream()

        async def drive() -> int:
            async with self.starlette_client(build(upstream)) as client:
                response = await client.post(
                    "/metrics/api/v1/identify",
                    headers={"x-api-key": "fly_pk_eu_production_test"},
                    content=b"{}",
                )
                return response.status_code

        assert run(drive()) == 401
        assert upstream.requests == []


class TestFlask:
    def flask_client(self, proxy: FingerlyProxy) -> httpx.Client:
        app = flask.Flask(__name__)

        @app.get("/")  # type: ignore[untyped-decorator]  # flask is untyped
        def home() -> str:
            return "the host app"

        app.wsgi_app = dispatcher.DispatcherMiddleware(
            app.wsgi_app, {"/metrics": proxy.wsgi}
        )
        return httpx.Client(
            transport=httpx.WSGITransport(app=app.wsgi_app),
            base_url="https://shop.test",
        )

    def test_forwards_identify_beside_the_host_app(self) -> None:
        upstream = Upstream()
        with self.flask_client(build(upstream)) as client:
            identified = client.post(
                "/metrics/api/v1/identify",
                headers=BROWSER_HEADERS,
                content=b'{"signals":{}}',
            )
            home = client.get("/")

        assert identified.status_code == 200
        assert identified.json() == {"request_id": "identified"}
        assert identified.headers["cache-control"] == "no-store"
        # Mounting the proxy must not disturb the application it sits beside.
        assert (home.status_code, home.text) == (200, "the host app")

        forwarded = upstream.requests[0]
        assert str(forwarded.url) == "https://us.api.fingerly.io/api/v1/identify"
        assert forwarded.headers["x-fingerly-client-ip"] == "203.0.113.5"
        assert "cookie" not in forwarded.headers

    def test_forwards_from_a_deployment_under_a_sub_uri(self) -> None:
        # DispatcherMiddleware rather than httpx's script_name, because httpx
        # leaves the mount in PATH_INFO and PEP 3333 does not: a harness that
        # disagreed with the spec would test the wrong thing.
        upstream = Upstream()
        app = flask.Flask(__name__)
        app.wsgi_app = dispatcher.DispatcherMiddleware(
            app.wsgi_app, {"/metrics": build(upstream).wsgi}
        )
        deployed = dispatcher.DispatcherMiddleware(
            app.wsgi_app, {"/shop": app.wsgi_app}
        )

        with httpx.Client(
            transport=httpx.WSGITransport(app=deployed), base_url="https://shop.test"
        ) as client:
            response = client.post(
                "/shop/metrics/api/v1/identify",
                headers=BROWSER_HEADERS,
                content=b'{"signals":{}}',
            )

        assert response.status_code == 200
        assert str(upstream.requests[0].url) == (
            "https://us.api.fingerly.io/api/v1/identify"
        )

    def test_forwards_a_supplement_report(self) -> None:
        upstream = Upstream()
        with self.flask_client(build(upstream)) as client:
            response = client.post(
                "/metrics/api/v1/events/request-1/supplement",
                headers=BROWSER_HEADERS,
                content=b"{}",
            )
        assert response.status_code == 200
        assert str(upstream.requests[0].url) == (
            "https://us.api.fingerly.io/api/v1/events/request-1/supplement"
        )

    def test_refuses_event_reads_and_oversized_bodies(self) -> None:
        upstream = Upstream()
        with self.flask_client(build(upstream, max_body_bytes=8)) as client:
            read = client.post(
                "/metrics/api/v1/events", headers=BROWSER_HEADERS, content=b"{}"
            )
            oversized = client.post(
                "/metrics/api/v1/identify",
                headers=BROWSER_HEADERS,
                content=b"a body well past the limit",
            )
        assert (read.status_code, oversized.status_code) == (404, 413)
        assert upstream.requests == []
