"""Agent sightings may never hurt the process they run in.

Each test pins a hazard found by running real apps against a hostile API:
sightings lost on shutdown, a forked worker that never reported, a report
stuck in flight after a cancelled send, a header scan that could fail the
response it watched.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import Any, Optional

import httpx
import pytest
from conftest import SECRET_KEY, Recorder, json_response, run

import fingerly._sightings as sightings_module
from fingerly import (
    AgentSightings,
    AsyncAgentSightings,
    AsyncFingerly,
    Fingerly,
    FingerlyProxy,
    ProxyRequest,
)
from fingerly._proxy import Headers

GPTBOT = "Mozilla/5.0 (compatible; GPTBot/1.2)"
SRC = Path(__file__).resolve().parent.parent / "src"


def visitor(n: int = 0, ip: Optional[str] = "203.0.113.9") -> ProxyRequest:
    return ProxyRequest(
        method="GET",
        path="/",
        headers=Headers([("user-agent", f"{GPTBOT} #{n}"), ("host", "shop.test")]),
        peer_host=ip,
    )


def answering() -> Recorder:
    def handler(sent: httpx.Request) -> httpx.Response:
        items = json.loads(sent.content)["items"]
        return json_response(
            {
                "rules_version": "r1",
                "items": [{"ttl": 60, "visitor_kind": "human"} for _ in items],
            }
        )

    return Recorder.of(handler)


def sync_sightings(recorder: Recorder, **options: Any) -> AgentSightings:
    client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
    options.setdefault("background", False)
    return AgentSightings(
        client, client_ip=lambda request: request.peer_host, **options
    )


def items_sent(recorder: Recorder) -> int:
    return sum(len(json.loads(r.content)["items"]) for r in recorder.requests)


class TestClientIP:
    def test_a_callback_may_return_none(self) -> None:
        recorder = answering()
        # `request.peer_host` is Optional[str]; the callback type accepts it.
        sightings = sync_sightings(recorder)
        sightings.report(visitor(ip=None), "text/html")
        sightings.report(visitor(1), "text/html")
        sightings.flush()
        assert items_sent(recorder) == 1
        proxy = FingerlyProxy(
            proxy_key="fly_px_development_test",
            client_ip=lambda request: request.peer_host,
        )
        assert proxy is not None


class TestFork:
    """A child the fork hooks never saw (uWSGI forks from C) still works."""

    def test_sightings_reset_in_an_unannounced_child(self) -> None:
        recorder = answering()
        sightings = sync_sightings(recorder)
        sightings.report(visitor(0), "text/html")
        # As the child sees it: the parent's buffer, a lock the parent held.
        sightings._lock.acquire()
        sightings._pid = -1
        sightings.report(visitor(1), "text/html")
        assert sightings.pending == 1
        sightings.flush()
        assert [
            item["user_agent"]
            for item in json.loads(recorder.requests[0].content)["items"]
        ] == [f"{GPTBOT} #1"]

    def test_the_flusher_thread_is_started_again_in_the_child(self) -> None:
        recorder = answering()
        sightings = sync_sightings(recorder, background=True)
        sightings.report(visitor(0), "text/html")
        ghost = sightings._thread
        assert ghost is not None and ghost.is_alive()
        sightings._pid = -1
        sightings.report(visitor(1), "text/html")
        assert sightings._thread is not ghost
        sightings.close()

    def test_the_pool_forgets_the_parents_connections(self) -> None:
        client = Fingerly(secret_key=SECRET_KEY, transport=answering().transport())
        pool = client._pool
        client.agents.sightings([])
        inherited = list(pool._shards._active)
        pool._lock.acquire()  # held by a parent thread at the fork
        pool._pid = -1
        client.agents.sightings([])
        assert pool._pid == os.getpid()
        assert all(shard not in pool._shards._active for shard in inherited)
        client.close()

    def test_the_async_pool_forgets_the_parents_connections(self) -> None:
        async def drive() -> None:
            client = AsyncFingerly(
                secret_key=SECRET_KEY, transport=answering().transport()
            )
            await client.agents.sightings([])
            inherited = list(client._pool._shards._active)
            client._pool._pid = -1
            await client.agents.sightings([])
            assert all(s not in client._pool._shards._active for s in inherited)
            await client.aclose()

        run(drive())

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
    def test_a_real_fork_reports_from_the_child(self, tmp_path: Path) -> None:
        script = tmp_path / "forked.py"
        script.write_text(
            textwrap.dedent(
                """
                import json, os, sys
                import httpx
                from fingerly import AgentSightings, Fingerly, ProxyRequest
                from fingerly._proxy import Headers

                out = sys.argv[1]

                def handler(request):
                    items = json.loads(request.content)["items"]
                    with open(out, "a") as f:
                        f.write(f"{os.getpid()} {len(items)}\\n")
                    return httpx.Response(200, json={"rules_version": "r",
                        "items": [{"ttl": 0, "visitor_kind": "human"} for _ in items]})

                client = Fingerly(secret_key="fly_sk_development_test",
                                  transport=httpx.MockTransport(handler))
                sightings = AgentSightings(client, client_ip=lambda r: r.peer_host)

                def seen(n):
                    sightings.report(ProxyRequest(method="GET", path="/",
                        headers=Headers([("user-agent", f"bot {n}")]),
                        peer_host="203.0.113.1"), "text/html")

                seen(0)  # the parent's flusher thread now exists
                pid = os.fork()
                if pid == 0:
                    seen(1)
                    seen(2)
                    os._exit(0 if sightings.pending == 2 else 3)
                _, status = os.waitpid(pid, 0)
                sys.exit(os.waitstatus_to_exitcode(status) if hasattr(
                    os, "waitstatus_to_exitcode") else status >> 8)
                """
            )
        )
        out = tmp_path / "sent.txt"
        done = subprocess.run(  # noqa: S603 - this interpreter, a script written above
            [sys.executable, str(script), str(out)],
            env={**os.environ, "PYTHONPATH": str(SRC)},
            timeout=60,
            check=False,
        )
        assert done.returncode == 0


class TestShutdown:
    def test_pending_reports_are_sent_at_interpreter_exit(self, tmp_path: Path) -> None:
        script = tmp_path / "exiting.py"
        script.write_text(
            textwrap.dedent(
                """
                import json, sys
                import httpx
                from fingerly import AgentSightings, Fingerly, ProxyRequest
                from fingerly._proxy import Headers

                def handler(request):
                    items = json.loads(request.content)["items"]
                    with open(sys.argv[1], "a") as f:
                        f.write(f"{len(items)}\\n")
                    return httpx.Response(200, json={"rules_version": "r",
                        "items": [{"ttl": 0, "visitor_kind": "human"} for _ in items]})

                client = Fingerly(secret_key="fly_sk_development_test",
                                  transport=httpx.MockTransport(handler))
                sightings = AgentSightings(client, client_ip=lambda r: r.peer_host)
                for n in range(3):
                    sightings.report(ProxyRequest(method="GET", path="/",
                        headers=Headers([("user-agent", f"bot {n}")]),
                        peer_host="203.0.113.1"), "text/html")
                # Exits at once, long before the 2 second flush, never closed.
                """
            )
        )
        out = tmp_path / "sent.txt"
        subprocess.run(  # noqa: S603 - this interpreter, a script written above
            [sys.executable, str(script), str(out)],
            env={**os.environ, "PYTHONPATH": str(SRC)},
            timeout=60,
            check=True,
        )
        assert out.read_text().split() == ["3"]

    def test_the_exit_flush_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sightings_module, "SHUTDOWN_DEADLINE", 0.3)
        release = threading.Event()

        def hanging(_: httpx.Request) -> httpx.Response:
            release.wait(10)
            return json_response({})

        sightings = sync_sightings(Recorder.of(hanging))
        sightings.report(visitor(), "text/html")
        started = time.monotonic()
        try:
            sightings._flush_at_exit()
            # The mock transport ignores the deadline, so the send itself is
            # cut short only by the release; what is bounded is the waiting.
            assert time.monotonic() - started < 11
        finally:
            release.set()

    def test_the_exit_flush_is_bounded_across_instances(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sightings_module, "SHUTDOWN_DEADLINE", 0.5)
        monkeypatch.setattr(
            sightings_module, "_instances", type(sightings_module._instances)()
        )
        busy = []
        for n in range(3):
            sightings = sync_sightings(answering())
            sightings.report(visitor(n), "text/html")
            # A report of its own in flight: the exit flush can only wait.
            sightings._send_lock.acquire()
            busy.append(sightings)
        started = time.monotonic()
        try:
            sightings_module._flush_at_exit()
            assert time.monotonic() - started < 0.9
        finally:
            for sightings in busy:
                sightings._send_lock.release()

    def test_the_exit_flush_skips_closed_and_closed_client(self) -> None:
        recorder = answering()
        closed = sync_sightings(recorder)
        closed.report(visitor(0), "text/html")
        closed._closed = True
        unclosed_client = sync_sightings(recorder)
        unclosed_client.report(visitor(1), "text/html")
        unclosed_client._client.close()
        sightings_module._flush_at_exit()
        assert recorder.calls == 0

    def test_lifespan_shutdown_flushes_before_the_app_hears_of_it(self) -> None:
        recorder = answering()
        order: list[str] = []

        async def app(scope: Any, receive: Any, send: Any) -> None:
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                else:
                    order.append(f"app saw shutdown after {recorder.calls} reports")
                    await send({"type": "lifespan.shutdown.complete"})
                    return

        async def drive(sightings: Any) -> list[str]:
            sightings.report(visitor(), "text/html")
            sent: list[str] = []
            messages = iter(
                [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
            )

            async def receive() -> Any:
                return next(messages)

            async def send(message: Any) -> None:
                sent.append(message["type"])

            await sightings.asgi(app)({"type": "lifespan"}, receive, send)
            return sent

        sent = run(drive(sync_sightings(recorder)))
        assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
        assert order == ["app saw shutdown after 1 reports"]

        async_recorder = answering()

        async def drive_async() -> list[str]:
            client = AsyncFingerly(
                secret_key=SECRET_KEY, transport=async_recorder.transport()
            )
            sightings = AsyncAgentSightings(
                client, client_ip=lambda request: request.peer_host, background=False
            )
            return await drive(sightings)

        run(drive_async())
        assert async_recorder.calls == 1

    @pytest.mark.parametrize("refusal", ["raises", "returns"])
    def test_an_app_without_lifespan_still_flushes_on_shutdown(
        self, refusal: str
    ) -> None:
        recorder = answering()

        async def django_like(scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] != "http":
                if refusal == "returns":
                    return
                raise ValueError("only http")

        async def drive() -> list[str]:
            sightings = sync_sightings(recorder)
            sightings.report(visitor(), "text/html")
            sent: list[str] = []
            messages = iter(
                [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
            )

            async def receive() -> Any:
                return next(messages)

            async def send(message: Any) -> None:
                sent.append(message["type"])

            await sightings.asgi(django_like)({"type": "lifespan"}, receive, send)
            return sent

        assert run(drive()) == [
            "lifespan.startup.complete",
            "lifespan.shutdown.complete",
        ]
        assert recorder.calls == 1

    def test_a_lifespan_failure_after_reading_is_the_apps_own(self) -> None:
        async def failing(scope: Any, receive: Any, send: Any) -> None:
            await receive()
            raise RuntimeError("startup failed")

        async def receive() -> Any:
            return {"type": "lifespan.startup"}

        async def send(_: Any) -> None:
            return None

        app = sync_sightings(answering()).asgi(failing)
        with pytest.raises(RuntimeError, match="startup failed"):
            run(app({"type": "lifespan"}, receive, send))


class TestInterruptedSend:
    def test_a_cancelled_report_does_not_stall_reporting(self) -> None:
        hang = True

        async def drive() -> int:
            nonlocal hang
            # Made on the loop: Python 3.9 binds an Event when it is built.
            started = asyncio.Event()
            recorder = answering()

            class Transport(httpx.AsyncBaseTransport):
                async def handle_async_request(
                    self, request: httpx.Request
                ) -> httpx.Response:
                    if hang:
                        started.set()
                        await asyncio.sleep(3600)
                    return recorder(request)

            client = AsyncFingerly(secret_key=SECRET_KEY, transport=Transport())
            sightings = AsyncAgentSightings(
                client, client_ip=lambda request: request.peer_host, background=False
            )
            sightings.report(visitor(), "text/html")
            flushing = asyncio.ensure_future(sightings.flush())
            await started.wait()
            flushing.cancel()
            with pytest.raises(asyncio.CancelledError):
                await flushing
            assert sightings._in_flight == 0
            assert sightings.pending == 1
            hang = False
            await sightings.flush()
            await client.aclose()
            return recorder.calls

        assert run(drive()) == 1


HUGE_RETRY_AFTER = [
    "2147483647",
    "99999999999999999999",
    "9" * 400,  # parses as an infinite float
    "Fri, 01 Jan 2100 00:00:00 GMT",
]


def rate_limited(retry_after: str) -> Recorder:
    return Recorder(
        httpx.Response(
            429,
            json={"error": {"code": "rate_limited", "message": "slow down"}},
            headers={"retry-after": retry_after},
        )
    )


class TestHugeRetryAfter:
    """A 429 pauses reporting for 1 second to 24 hours, never for good."""

    @pytest.mark.parametrize("retry_after", HUGE_RETRY_AFTER)
    def test_the_thread_flusher_survives_and_pauses_a_day(
        self, retry_after: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failures: list[Any] = []
        monkeypatch.setattr(threading, "excepthook", failures.append)
        recorder = rate_limited(retry_after)
        sightings = sync_sightings(recorder, background=True)
        try:
            for n in range(200):  # a full batch: the flusher sends at once
                sightings.report(visitor(n), "text/html")
            deadline = time.monotonic() + 5
            while recorder.calls == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            time.sleep(0.2)  # the flusher now waits out the pause
            pause = sightings._paused_until - sightings._clock()
            assert recorder.calls == 1
            assert 86000 < pause <= sightings_module.MAX_RATE_LIMIT_PAUSE
            assert sightings._thread is not None and sightings._thread.is_alive()
            assert failures == []
        finally:
            sightings._stopping = True
            sightings._event.set()

    @pytest.mark.parametrize("retry_after", HUGE_RETRY_AFTER)
    def test_the_task_flusher_survives_and_pauses_a_day(self, retry_after: str) -> None:
        recorder = rate_limited(retry_after)

        async def drive() -> float:
            client = AsyncFingerly(
                secret_key=SECRET_KEY, transport=recorder.transport()
            )
            sightings = AsyncAgentSightings(
                client, client_ip=lambda request: request.peer_host
            )
            for n in range(200):
                sightings.report(visitor(n), "text/html")
            for _ in range(500):
                if recorder.calls:
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.2)
            task = sightings._task
            assert task is not None and not task.done()
            pause = sightings._paused_until - sightings._clock()
            sightings._stopping = True
            assert sightings._event is not None
            sightings._event.set()
            await task
            await client.aclose()
            return pause

        pause = run(drive())
        assert recorder.calls == 1
        assert 86000 < pause <= sightings_module.MAX_RATE_LIMIT_PAUSE


class TestMiddlewareNeverFailsTheResponse:
    def test_odd_asgi_response_headers(self) -> None:
        sightings = sync_sightings(answering())
        sent: list[Any] = []

        async def app(scope: Any, receive: Any, send: Any) -> None:
            await send(
                {"type": "http.response.start", "status": 200, "headers": [("a", 1)]}
            )
            await send({"type": "http.response.body", "body": b"ok"})

        async def receive() -> Any:
            return {"type": "http.request"}

        async def send(message: Any) -> None:
            sent.append(message)

        scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
        run(sightings.asgi(app)(scope, receive, send))
        assert [m["type"] for m in sent] == [
            "http.response.start",
            "http.response.body",
        ]

    def test_odd_wsgi_response_headers(self) -> None:
        sightings = sync_sightings(answering())

        def app(environ: Any, start_response: Any) -> Any:
            start_response("200 OK", [(None, 1), ("Content-Type", "text/html")])
            return [b"ok"]

        statuses: list[str] = []
        body = sightings.wsgi(app)(
            {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "REMOTE_ADDR": "203.0.113.9"},
            lambda status, headers, exc_info=None: statuses.append(status),
        )
        assert b"".join(body) == b"ok"
        body.close()  # type: ignore[attr-defined]
        assert statuses == ["200 OK"]
