"""The connection pool every request goes through, and the limits it enforces.

Three promises live here, for the read clients and the proxy alike.

One deadline bounds the whole exchange: connecting, sending, the response
headers and the body. httpx applies its timeout to each operation instead, so
an upstream that trickles a byte at a time would otherwise hold a request
forever. Under asyncio the exchange runs inside ``asyncio.wait_for``; in a
thread, the sockets the pool opens clamp each operation to the time left.

A response body is capped at :data:`MAX_RESPONSE_BYTES`, checked while it is
read, so nothing is ever buffered without a bound.

The pool holds connections for many concurrent requests without a socket per
request. httpcore's pool scans every connection for each request it queues, so
one pool sized for hundreds of connections spends more time choosing a
connection than sending on it: measured at 100 concurrent requests, 100
keep-alive connections served a tenth of what 20 did. Several small pools
avoid both that and the churn of a 20-connection pool under more load, where
most requests opened a fresh connection. Each small pool is replaced after
:data:`RECYCLE_SECONDS`, which re-resolves DNS, once its requests finish.
"""

from __future__ import annotations

import asyncio
import contextvars
import math
import ssl
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any, Callable, Generic, Optional, TypeVar, Union

import httpx

#: The largest response body read from the API, after decoding.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

#: Connections per small pool. httpcore's cost per queued request grows with
#: the connections in one pool, so each stays this small.
CONNECTIONS_PER_POOL = 4

#: How long one small pool serves new requests before it is replaced, so a
#: changed DNS answer is picked up even while traffic never pauses.
RECYCLE_SECONDS = 300.0

#: Enough for 256 concurrent requests per process to reuse connections.
DEFAULT_LIMITS = httpx.Limits(
    max_connections=256, max_keepalive_connections=256, keepalive_expiry=5.0
)

#: Request headers as text, or as raw bytes the caller has already encoded.
Headers = Union[Mapping[str, str], Sequence[tuple[bytes, bytes]]]

_DEADLINE: contextvars.ContextVar[Optional[float]] = contextvars.ContextVar(
    "fingerly_deadline", default=None
)

#: The shortest wait handed to a socket once the deadline has passed, so the
#: operation fails as a timeout through httpx's own exception mapping.
_EXPIRED = 0.001


class ResponseTooLargeError(Exception):
    """Raised when a response body exceeds :data:`MAX_RESPONSE_BYTES`.

    Attributes:
        status: The status of the response whose body was refused.
    """

    def __init__(self, status: int) -> None:
        super().__init__(f"response body over {MAX_RESPONSE_BYTES} bytes")
        self.status = status


class Reply:
    """A response read in full: status, headers and the decoded body."""

    __slots__ = ("body", "headers", "status")

    def __init__(self, status: int, headers: httpx.Headers, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body


def _clamp(timeout: Optional[float]) -> Optional[float]:
    """Shortens one socket operation to the time left before the deadline."""
    deadline = _DEADLINE.get()
    if deadline is None:
        return timeout
    left = max(deadline - time.monotonic(), _EXPIRED)
    return left if timeout is None else min(timeout, left)


class _DeadlineStream:
    """A network stream whose every operation stops at the deadline."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def read(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        data: bytes = self._inner.read(max_bytes, _clamp(timeout))
        return data

    def write(self, buffer: bytes, timeout: Optional[float] = None) -> None:
        self._inner.write(buffer, _clamp(timeout))

    def start_tls(
        self,
        ssl_context: Any,
        server_hostname: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> _DeadlineStream:
        return _DeadlineStream(
            self._inner.start_tls(ssl_context, server_hostname, _clamp(timeout))
        )

    def close(self) -> None:
        self._inner.close()

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _DeadlineBackend:
    """Opens streams that honour the deadline of the thread using them."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Any = None,
    ) -> _DeadlineStream:
        return _DeadlineStream(
            self._inner.connect_tcp(
                host, port, _clamp(timeout), local_address, socket_options
            )
        )

    def connect_unix_socket(
        self, path: str, timeout: Optional[float] = None, socket_options: Any = None
    ) -> _DeadlineStream:
        return _DeadlineStream(
            self._inner.connect_unix_socket(path, _clamp(timeout), socket_options)
        )

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


_tls_context: Optional[ssl.SSLContext] = None
_tls_context_lock = threading.Lock()


def _shared_tls_context() -> ssl.SSLContext:
    """One TLS context per process, however many small pools there are.

    Each context loads the whole CA bundle. Built per pool, the 64 pools behind
    256 connections took 49 MB and up to 0.9 s, under the pool's lock or on the
    event loop, and again at every recycle.
    """
    global _tls_context
    with _tls_context_lock:
        if _tls_context is None:
            _tls_context = httpx.create_ssl_context()
        return _tls_context


def _sync_transport(limits: httpx.Limits) -> httpx.HTTPTransport:
    """A transport whose sockets stop at the calling thread's deadline."""
    transport = httpx.HTTPTransport(limits=limits, verify=_shared_tls_context())
    pool = getattr(transport, "_pool", None)
    backend = getattr(pool, "_network_backend", None)
    if backend is not None:
        pool._network_backend = _DeadlineBackend(backend)  # type: ignore[union-attr]
    # Without the hook the deadline is still checked between body reads.
    return transport


C = TypeVar("C", httpx.Client, httpx.AsyncClient)


class _Shard(Generic[C]):
    __slots__ = ("born", "busy", "client", "retired")

    def __init__(self, client: C) -> None:
        self.client: C = client
        self.busy = 0
        self.born = time.monotonic()
        self.retired = False


class _Shards(Generic[C]):
    """Chooses a small pool for each request; the bookkeeping both pools share.

    A low-traffic process uses one small pool. Another is opened only when
    every open one is full, up to the configured connection limit.
    """

    def __init__(
        self,
        build: Callable[[Optional[httpx.Limits]], C],
        limits: httpx.Limits,
        fixed: bool,
    ) -> None:
        total = limits.max_connections or DEFAULT_LIMITS.max_connections or 256
        keepalive = (
            total
            if limits.max_keepalive_connections is None
            else limits.max_keepalive_connections
        )
        self._per_pool = min(CONNECTIONS_PER_POOL, total)
        self._max_pools = 1 if fixed else math.ceil(total / self._per_pool)
        self._pool_limits = httpx.Limits(
            max_connections=self._per_pool,
            max_keepalive_connections=min(
                self._per_pool, math.ceil(keepalive / self._max_pools)
            ),
            keepalive_expiry=limits.keepalive_expiry,
        )
        self._build: Callable[[Optional[httpx.Limits]], C] = build
        self._fixed = fixed
        self._active: list[_Shard[C]] = []
        self.closed = False

    def acquire(self) -> tuple[_Shard[C], list[_Shard[C]]]:
        """Picks a pool and returns it with any retired pool now idle."""
        idle: list[_Shard[C]] = []
        if not self._fixed:
            now = time.monotonic()
            for shard in [s for s in self._active if now - s.born > RECYCLE_SECONDS]:
                shard.retired = True
                self._active.remove(shard)
                if shard.busy == 0:
                    idle.append(shard)
        best = min(self._active, key=lambda s: s.busy, default=None)
        if best is None or (
            best.busy >= self._per_pool and len(self._active) < self._max_pools
        ):
            best = _Shard(self._build(None if self._fixed else self._pool_limits))
            self._active.append(best)
        best.busy += 1
        return best, idle

    def release(self, shard: _Shard[C]) -> bool:
        """Returns True when the pool is retired and now idle, to be closed."""
        shard.busy -= 1
        return shard.retired and shard.busy == 0

    def drain(self) -> list[_Shard[C]]:
        """Takes every open pool, for closing."""
        shards, self._active = self._active, []
        self.closed = True
        return shards

    @property
    def connections(self) -> int:
        """Connections currently open across the pools, for diagnostics."""
        total = 0
        for shard in self._active:
            pool = getattr(getattr(shard.client, "_transport", None), "_pool", None)
            total += len(getattr(pool, "connections", ()))
        return total


class SyncPool:
    """The synchronous pool: safe to share between threads."""

    def __init__(
        self,
        build: Callable[[Optional[httpx.BaseTransport]], httpx.Client],
        deadline: float,
        limits: Optional[httpx.Limits] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        def make(pool_limits: Optional[httpx.Limits]) -> httpx.Client:
            if pool_limits is None:
                return build(transport)
            return build(_sync_transport(pool_limits))

        self._deadline = deadline
        self._shards: _Shards[httpx.Client] = _Shards(
            make, limits or DEFAULT_LIMITS, fixed=transport is not None
        )
        self._lock = threading.Lock()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Headers] = None,
        content: Optional[bytes] = None,
        params: Optional[Mapping[str, str]] = None,
    ) -> Reply:
        """Sends one request and reads its body, all within the deadline.

        Raises:
            httpx.TimeoutException: When the deadline passes.
            httpx.HTTPError: On any other transport failure.
            ResponseTooLargeError: When the body exceeds the cap.
            RuntimeError: When the pool has been closed.
        """
        with self._lock:
            if self._shards.closed:
                raise RuntimeError("The Fingerly client has been closed")
            shard, idle = self._shards.acquire()
        for stale in idle:
            stale.client.close()
        deadline = time.monotonic() + self._deadline
        token = _DEADLINE.set(deadline)
        try:
            with shard.client.stream(
                method, url, headers=headers, content=content, params=params
            ) as response:
                _refuse_declared_oversize(response)
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ResponseTooLargeError(response.status_code)
                    chunks.append(chunk)
                    if time.monotonic() > deadline:
                        raise httpx.ReadTimeout("deadline exceeded")
                return Reply(response.status_code, response.headers, b"".join(chunks))
        finally:
            _DEADLINE.reset(token)
            with self._lock:
                finished = self._shards.release(shard)
            if finished:
                shard.client.close()

    def close(self) -> None:
        """Closes every connection. Safe to call more than once."""
        with self._lock:
            shards = self._shards.drain()
        for shard in shards:
            shard.client.close()

    @property
    def connections(self) -> int:
        """Connections currently open, for diagnostics and tests."""
        return self._shards.connections


class AsyncPool:
    """The asyncio pool, bound to the event loop that first uses it."""

    def __init__(
        self,
        build: Callable[[Optional[httpx.AsyncBaseTransport]], httpx.AsyncClient],
        deadline: float,
        limits: Optional[httpx.Limits] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        def make(pool_limits: Optional[httpx.Limits]) -> httpx.AsyncClient:
            if pool_limits is None:
                return build(transport)
            return build(
                httpx.AsyncHTTPTransport(
                    limits=pool_limits, verify=_shared_tls_context()
                )
            )

        self._deadline = deadline
        self._shards: _Shards[httpx.AsyncClient] = _Shards(
            make, limits or DEFAULT_LIMITS, fixed=transport is not None
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Headers] = None,
        content: Optional[bytes] = None,
        params: Optional[Mapping[str, str]] = None,
    ) -> Reply:
        """Sends one request and reads its body, all within the deadline.

        Raises:
            httpx.TimeoutException: When the deadline passes.
            httpx.HTTPError: On any other transport failure.
            ResponseTooLargeError: When the body exceeds the cap.
            RuntimeError: When the pool has been closed.
        """
        if self._shards.closed:
            raise RuntimeError("The Fingerly client has been closed")
        shard, idle = self._shards.acquire()
        try:
            for stale in idle:
                await stale.client.aclose()
            return await asyncio.wait_for(
                _read_async(shard.client, method, url, headers, content, params),
                self._deadline,
            )
        except asyncio.TimeoutError:
            raise httpx.ReadTimeout("deadline exceeded") from None
        finally:
            if self._shards.release(shard):
                await shard.client.aclose()

    async def aclose(self) -> None:
        """Closes every connection. Safe to call more than once."""
        for shard in self._shards.drain():
            await shard.client.aclose()

    @property
    def connections(self) -> int:
        """Connections currently open, for diagnostics and tests."""
        return self._shards.connections


async def _read_async(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: Optional[Headers],
    content: Optional[bytes],
    params: Optional[Mapping[str, str]],
) -> Reply:
    async with client.stream(
        method, url, headers=headers, content=content, params=params
    ) as response:
        _refuse_declared_oversize(response)
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise ResponseTooLargeError(response.status_code)
            chunks.append(chunk)
        return Reply(response.status_code, response.headers, b"".join(chunks))


def _refuse_declared_oversize(response: httpx.Response) -> None:
    """Refuses a body whose declared length is already over the cap.

    The declared length is of the encoded body and the cap is on the decoded
    one, which is never smaller, so this only ever refuses early.
    """
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise ResponseTooLargeError(response.status_code)
