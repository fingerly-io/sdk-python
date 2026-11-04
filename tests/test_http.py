"""The shared pool against a real socket: deadline, body cap, connection reuse."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from conftest import SECRET_KEY, Recorder, run

import fingerly._http as pool_module
from fingerly import (
    AsyncFingerly,
    Fingerly,
    FingerlyAPIError,
    FingerlyTimeoutError,
)
from fingerly._http import MAX_RESPONSE_BYTES, AsyncPool, SyncPool


class Upstream:
    """A keep-alive HTTP/1.1 server on a loopback port, in its own thread.

    Attributes:
        mode: ``ok`` answers after ``delay``; ``trickle`` sends the headers,
            then one body byte every 0.1 s for ten seconds.
        peers: The client port of every connection accepted.
    """

    def __init__(self) -> None:
        self.mode = "ok"
        self.delay = 0.0
        self.peers: list[int] = []
        self._ready = threading.Event()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(5)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._server = self._loop.run_until_complete(
            asyncio.start_server(self._serve, "127.0.0.1", 0, backlog=1024)
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()
        self._loop.run_until_complete(self._server.wait_closed())
        pending = asyncio.all_tasks(self._loop)
        for task in pending:
            task.cancel()
        self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        self._loop.close()

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.peers.append(writer.get_extra_info("peername")[1])
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                if length:
                    await reader.readexactly(length)
                if self.mode == "trickle":
                    writer.write(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n")
                    for _ in range(100):
                        writer.write(b" ")
                        await writer.drain()
                        await asyncio.sleep(0.1)
                    continue
                await asyncio.sleep(self.delay)
                body = b'{"ok":1}'
                writer.write(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n"
                    b"content-length: " + str(len(body)).encode() + b"\r\n\r\n" + body
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    def stop(self) -> None:
        def shut() -> None:
            self._server.close()
            self._loop.stop()

        self._loop.call_soon_threadsafe(shut)
        self._thread.join(5)


@pytest.fixture
def upstream() -> Iterator[Upstream]:
    server = Upstream()
    yield server
    server.stop()


def _build_sync(transport: Any) -> httpx.Client:
    return httpx.Client(timeout=5.0, transport=transport)


def _build_async(transport: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=5.0, transport=transport)


class TestDeadline:
    def test_a_trickling_upstream_cannot_extend_a_sync_read(
        self, upstream: Upstream
    ) -> None:
        upstream.mode = "trickle"
        with Fingerly(secret_key=SECRET_KEY, endpoint=upstream.url, timeout=0.5) as f:
            started = time.monotonic()
            with pytest.raises(FingerlyTimeoutError):
                f.events.get("id")
        assert time.monotonic() - started < 1.5

    def test_a_trickling_upstream_cannot_extend_an_async_read(
        self, upstream: Upstream
    ) -> None:
        upstream.mode = "trickle"

        async def read() -> float:
            async with AsyncFingerly(
                secret_key=SECRET_KEY, endpoint=upstream.url, timeout=0.5
            ) as f:
                started = time.monotonic()
                with pytest.raises(FingerlyTimeoutError):
                    await f.events.get("id")
                return time.monotonic() - started

        assert run(read()) < 1.5

    def test_the_sync_pool_stops_at_the_deadline_mid_body(
        self, upstream: Upstream
    ) -> None:
        upstream.mode = "trickle"
        pool = SyncPool(_build_sync, 0.4)
        started = time.monotonic()
        with pytest.raises(httpx.TimeoutException):
            pool.request("POST", upstream.url + "/ingest", content=b"{}")
        assert time.monotonic() - started < 1.0
        pool.close()


class TestBodyCap:
    @pytest.mark.parametrize("declared", [True, False])
    def test_refuses_a_body_over_four_mebibytes(self, declared: bool) -> None:
        oversized = b"x" * (MAX_RESPONSE_BYTES + 1)

        def answer(request: httpx.Request) -> httpx.Response:
            if declared:
                return httpx.Response(200, content=oversized)
            return httpx.Response(200, content=iter([oversized]))

        with (
            Fingerly(
                secret_key=SECRET_KEY, transport=Recorder.of(answer).transport()
            ) as f,
            pytest.raises(FingerlyAPIError) as caught,
        ):
            f.events.get("id")
        assert caught.value.code == "response_too_large"
        assert caught.value.status == 200

    def test_reads_a_body_at_the_cap(self) -> None:
        exact = b"x" * MAX_RESPONSE_BYTES
        pool = SyncPool(
            _build_sync,
            5.0,
            transport=httpx.MockTransport(lambda r: httpx.Response(200, content=exact)),
        )
        assert len(pool.request("GET", "https://api.test/").body) == len(exact)
        pool.close()


class TestConnectionReuse:
    def test_two_hundred_concurrent_requests_reuse_their_connections(
        self, upstream: Upstream
    ) -> None:
        upstream.delay = 0.05

        async def waves() -> tuple[int, int, int]:
            pool = AsyncPool(_build_async, 10.0)

            async def wave() -> None:
                await asyncio.gather(
                    *(
                        pool.request("POST", upstream.url + "/ingest", content=b"{}")
                        for _ in range(200)
                    )
                )

            await wave()
            first = len(upstream.peers)
            for _ in range(3):
                await wave()
            held = pool.connections
            await pool.aclose()
            return first, len(upstream.peers) - first, held

        first, later, held = run(waves())
        assert first <= 256
        # Later waves find the connections the first one opened.
        assert later <= 8
        assert held == first

    def test_the_sync_pool_reuses_connections_across_threads(
        self, upstream: Upstream
    ) -> None:
        upstream.delay = 0.02
        pool = SyncPool(_build_sync, 10.0)

        def work() -> None:
            for _ in range(20):
                pool.request("POST", upstream.url + "/ingest", content=b"{}")

        threads = [threading.Thread(target=work) for _ in range(32)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        pool.close()
        assert len(upstream.peers) <= 40  # 640 requests

    def test_replaces_a_pool_after_its_lifetime(
        self, upstream: Upstream, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A replaced pool reconnects, which is what re-resolves DNS."""
        pool = SyncPool(_build_sync, 5.0)
        pool.request("GET", upstream.url)
        monkeypatch.setattr(pool_module, "RECYCLE_SECONDS", 0.0)
        time.sleep(0.01)
        pool.request("GET", upstream.url)
        monkeypatch.setattr(pool_module, "RECYCLE_SECONDS", 300.0)
        pool.request("GET", upstream.url)
        assert len(upstream.peers) == 2
        # The retired pool closed its connection once idle.
        assert pool.connections == 1
        pool.close()

    def test_a_closed_pool_refuses_new_requests(self) -> None:
        pool = SyncPool(_build_sync, 5.0)
        pool.close()
        pool.close()
        with pytest.raises(RuntimeError):
            pool.request("GET", "https://api.test/")
