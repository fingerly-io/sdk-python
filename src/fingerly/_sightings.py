"""Agent sightings: report the requests your server served, remember answers.

AI crawlers and fetchers that never run a page's JavaScript are only seen this
way. The SDK forwards raw input and remembers what the server said; it never
classifies a user agent, never checks an address against a list and never
filters requests by what the visitor claims to be.

Nothing here runs on the request the customer is serving: :meth:`lookup` reads
memory only, reporting adds to a bounded buffer, and a background flusher
sends the buffer. Every failure leaves requests served as usual.
"""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import dataclasses
import hashlib
import ipaddress
import itertools
import logging
import os
import threading
import time
import weakref
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import TYPE_CHECKING, Any, Callable, NamedTuple, Optional, TypeVar

import httpx

from ._client import AsyncFingerly, Fingerly
from ._errors import FingerlyAPIError, FingerlyConnectionError, FingerlyTimeoutError
from ._http import REQUEST_PROGRESS, RequestProgress
from ._models import AGENT_UNKNOWN, AgentAnswer, AgentSighting, AgentSightingsResult
from ._proxy import ProxyRequest, _is_ip_literal

if TYPE_CHECKING:
    from ._sightings_middleware import SightingsASGI, SightingsWSGI

logger = logging.getLogger("fingerly.agents")

#: Answers remembered per process by default.
DEFAULT_CACHE_SIZE = 4096
#: The most answers a process may remember, whatever is configured.
MAX_CACHE_SIZE = 65536
#: The most reports held for sending, pending and in flight together.
MAX_PENDING = 1000
#: Items per report, the most the API accepts in one call.
BATCH_ITEMS = 200
#: Pending field bytes that trigger a report, and the most one report carries.
BATCH_BYTES = 64 * 1024
#: Seconds after its oldest item that a pending report is sent.
FLUSH_AFTER = 2.0
#: One deadline, in seconds, over each report.
FLUSH_DEADLINE = 5.0
#: Header values longer than this, in UTF-8 bytes, are not reported.
MAX_HEADER_BYTES = 4096
#: The largest ``count`` the API accepts for one item.
MAX_COUNT = 1_000_000
#: Reporting pauses this long after a ``401`` or ``403``.
AUTH_PAUSE = 60.0
#: Reporting pauses this long after a ``429`` that did not say for how long.
RATE_LIMIT_PAUSE = 60.0
#: The shortest pause after a ``429``, whatever its ``Retry-After`` says.
MIN_RATE_LIMIT_PAUSE = 1.0
#: The longest pause after a ``429``, whatever its ``Retry-After`` says. A
#: larger value, or one too large to sleep on, would stop reporting for the
#: life of the process.
MAX_RATE_LIMIT_PAUSE = 86400.0
#: The longest an answer is remembered, in seconds, whatever its ``ttl``.
MAX_TTL = 86400.0
#: The longest :meth:`AgentSightings.flush` waits for a report in flight.
FLUSH_WAIT = FLUSH_DEADLINE + 1.0
#: The first and the longest pause after a ``503`` or an unreachable API.
BACKOFF_START = 1.0
BACKOFF_MAX = 60.0
#: Each kind of failure is logged at most once per this many seconds.
LOG_EVERY = 60.0
#: The longest the flush at shutdown (interpreter exit, ASGI lifespan) takes.
SHUTDOWN_DEADLINE = 5.0

#: Response content types reported by default.
DEFAULT_CONTENT_TYPES = ("text/html", "application/xhtml+xml")
#: Paths reported whatever their content type or status, unless excluded.
ALWAYS_REPORTED_PATHS = frozenset({"/robots.txt", "/llms.txt", "/llms-full.txt"})

_SIGNATURE_HEADERS = ("signature", "signature-input", "signature-agent")

_Self = TypeVar("_Self", bound="_BaseSightings")


def canonical_ip(value: str) -> str:
    """Prints an address in its canonical text form.

    An IPv4-mapped IPv6 address is printed as the IPv4 address, and IPv6
    follows RFC 5952: lowercase, with the longest run of zero groups
    compressed.

    Raises:
        ValueError: If the value is not one IP literal.
    """
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def sighting_key(
    user_agent: str, client_ip: str, signature_agent: str, signed: bool
) -> str:
    """The answer cache key of one request, as every Fingerly server SDK makes it.

    The first 16 bytes of SHA-256 over the user agent, the canonical address,
    the ``Signature-Agent`` header and whether the request was signed, joined
    by zero bytes, in lowercase hex.

    Raises:
        ValueError: If ``client_ip`` is not one IP literal.
    """
    material = b"\x00".join(
        (
            user_agent.encode("utf-8"),
            canonical_ip(client_ip).encode("ascii"),
            signature_agent.encode("utf-8"),
            b"1" if signed else b"0",
        )
    )
    return hashlib.sha256(material).hexdigest()[:32]


def _wire_text(value: str) -> str:
    """The header as the text the visitor sent.

    Both server standards hand header values over decoded as Latin-1, one
    character per byte, so the bytes are recovered and read as UTF-8, the way
    the API reads them. A value that is not Latin-1 is already text.
    """
    try:
        raw = value.encode("latin-1")
    except UnicodeEncodeError:
        return value.encode("utf-8", "replace").decode("utf-8")
    return raw.decode("utf-8", "replace")


def _utf8_len(value: Optional[str]) -> int:
    return len(value.encode("utf-8")) if value else 0


class _Observed(NamedTuple):
    """One request as it would be reported."""

    key: str
    signed: bool
    item: AgentSighting
    size: int


class _Pending:
    """A report waiting to be sent: the first sighting and a running count."""

    __slots__ = ("count", "first_seen", "item", "key", "signed", "size", "slot")

    def __init__(self, slot: str, observed: _Observed, now: float) -> None:
        self.slot = slot
        self.key = observed.key
        self.signed = observed.signed
        self.item = observed.item
        self.size = observed.size
        self.count = 1
        self.first_seen = now


class _Outcome(NamedTuple):
    """What a failed report does to its batch and to reporting."""

    keep: bool
    pause: Optional[float] = None
    backoff: bool = False
    log: Optional[tuple[str, str]] = None


def _request_of(request: Any) -> Optional[ProxyRequest]:
    """Reads a request in any shape :meth:`AgentSightings.lookup` accepts."""
    from ._asgi import _request_from as from_scope
    from ._wsgi import _request_from as from_environ

    if isinstance(request, ProxyRequest):
        return request
    scope = getattr(request, "scope", None)
    if isinstance(scope, Mapping) and scope.get("type") == "http":
        return from_scope(dict(scope))
    environ = getattr(request, "environ", None)
    if isinstance(environ, Mapping):
        return from_environ(dict(environ))
    if isinstance(request, Mapping):
        if request.get("type") == "http" and "headers" in request:
            return from_scope(dict(request))
        if "REQUEST_METHOD" in request:
            return from_environ(dict(request))
    return None


def _sequence_of_text(value: Sequence[str], name: str) -> tuple[str, ...]:
    if isinstance(value, str) or not all(isinstance(item, str) for item in value):
        raise TypeError(f"{name} must be a sequence of strings")
    return tuple(value)


def _cache_size(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TypeError("cache_size must be a positive integer")
    return min(value, MAX_CACHE_SIZE)


async def _acquire_within(lock: asyncio.Lock, timeout: float) -> bool:
    """Takes ``lock`` within ``timeout`` seconds, or gives up without it."""
    attempt = asyncio.ensure_future(lock.acquire())
    try:
        await asyncio.wait({attempt}, timeout=timeout)
    finally:
        if not attempt.done():
            attempt.cancel()
    # A cancelled attempt never holds the lock.
    return attempt.done() and not attempt.cancelled()


_instances: weakref.WeakSet[_BaseSightings] = weakref.WeakSet()
# Serialises the reset of a process that forked without telling Python.
_fork_guard = threading.Lock()


def _after_fork_in_child() -> None:
    for instance in list(_instances):
        instance._reset_after_fork()


def _flush_at_exit() -> None:
    """Sends what each sync instance still holds when the interpreter exits.

    A gunicorn worker exits this way after SIGTERM. Bounded by
    :data:`SHUTDOWN_DEADLINE` overall, however many instances there are, and
    never raises.
    """
    ends = time.monotonic() + SHUTDOWN_DEADLINE
    for instance in list(_instances):
        left = ends - time.monotonic()
        if left <= 0:
            return
        with contextlib.suppress(Exception):
            instance._flush_at_exit(left)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
atexit.register(_flush_at_exit)


class _BaseSightings:
    """The cache, the buffer and the failure rules both flushers share."""

    def __init__(
        self,
        client_ip: Callable[[ProxyRequest], Optional[str]],
        cache_size: int,
        content_types: Sequence[str],
        include_paths: Sequence[str],
        exclude_paths: Sequence[str],
        background: bool,
        clock: Optional[Callable[[], float]],
    ) -> None:
        if not callable(client_ip):
            raise TypeError("client_ip is required")
        self._client_ip = client_ip
        self._capacity = _cache_size(cache_size)
        self._content_types = frozenset(
            item.strip().lower()
            for item in _sequence_of_text(content_types, "content_types")
        )
        self._include = _sequence_of_text(include_paths, "include_paths")
        self._exclude = _sequence_of_text(exclude_paths, "exclude_paths")
        self._background = bool(background)
        self._clock: Callable[[], float] = clock or time.monotonic
        self._utc_now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
        self._cache: OrderedDict[str, tuple[float, AgentAnswer]] = OrderedDict()
        self._rules_version: Optional[str] = None
        self._serial = itertools.count(1)
        self._reset_state()
        _instances.add(self)

    def _reset_state(self) -> None:
        """Everything that belongs to one process; the cache is kept."""
        self._pid = os.getpid()
        self._lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._pending: OrderedDict[str, _Pending] = OrderedDict()
        self._pending_bytes = 0
        self._in_flight = 0
        self._paused_until = 0.0
        self._backoff = 0.0
        self._dropped = 0
        self._logged: dict[str, float] = {}
        self._stopping = False
        self._closed = False

    def _reset_after_fork(self) -> None:
        """Runs in a forked child: the parent still owns what it buffered."""
        self._reset_state()

    def _check_fork(self) -> None:
        """Resets a child whose fork Python's hooks did not see.

        uWSGI and other servers that fork from C skip ``os.register_at_fork``,
        so the child would keep the parent's buffer, a lock the parent may
        have held and a flusher thread that does not exist in it.
        """
        if self._pid == os.getpid():
            return
        with _fork_guard:
            if self._pid != os.getpid():
                self._reset_after_fork()

    def _flush_at_exit(self, budget: Optional[float] = None) -> None:
        """Sends what is pending as the interpreter exits, where it can.

        Within ``budget`` seconds, :data:`SHUTDOWN_DEADLINE` when None.
        """

    async def _flush_at_shutdown(self) -> None:
        """Sends what is pending when an ASGI server shuts the app down.

        Bounded by :data:`SHUTDOWN_DEADLINE`, never raises, and leaves the
        instance usable: the same app may be started again.
        """

    @property
    def dropped(self) -> int:
        """Requests not reported because the buffer was full, in this process.

        Those requests stay :data:`AGENT_UNKNOWN`. A count that keeps rising
        means reports are not getting through.
        """
        return self._dropped

    @property
    def pending(self) -> int:
        """Reports waiting to be sent, in flight included."""
        self._check_fork()
        with self._lock:
            return len(self._pending) + self._in_flight

    def lookup(self, request: Any) -> AgentAnswer:
        """What the server said sent this request, or :data:`AGENT_UNKNOWN`.

        Reads memory only: it never waits on the network and never raises.
        The answer is there once an earlier request with the same user agent,
        address and ``Signature-Agent`` was reported and answered, until its
        ``ttl`` runs out. A signed request is checked every time, so it is
        always :data:`AGENT_UNKNOWN` here. Serve :data:`AGENT_UNKNOWN` as
        usual.

        Args:
            request: A :class:`ProxyRequest`, an ASGI scope, a WSGI environ,
                or a framework request carrying one as ``scope`` or
                ``environ`` (Starlette, FastAPI, Django, Flask).
        """
        try:
            proxy_request = _request_of(request)
            if proxy_request is None:
                return AGENT_UNKNOWN
            observed = self._observe(proxy_request)
            if observed is None:
                return AGENT_UNKNOWN
            self._check_fork()
            now = self._clock()
            with self._lock:
                hit = self._cache.get(observed.key)
                if hit is None:
                    return AGENT_UNKNOWN
                if hit[0] <= now:
                    del self._cache[observed.key]
                    return AGENT_UNKNOWN
                self._cache.move_to_end(observed.key)
                return hit[1]
        except Exception:
            return AGENT_UNKNOWN

    def report(self, request: Any, content_type: Optional[str]) -> None:
        """Reports one served request, when its response is in scope.

        The middleware calls this after each response. Call it yourself only
        where neither middleware fits. Never raises and never sends anything
        on the calling thread.

        Args:
            request: Any request :meth:`lookup` accepts.
            content_type: The response's ``Content-Type``, or None.
        """
        try:
            proxy_request = _request_of(request)
            if proxy_request is not None:
                self._report(proxy_request, content_type)
        except Exception:
            self._log("report", "Agent sightings could not record a request")

    def _report(self, request: ProxyRequest, content_type: Optional[str]) -> None:
        if not self._in_scope(request.path, content_type):
            return
        observed = self._observe(request)
        if observed is not None:
            self._record(observed)

    def _in_scope(self, path: str, content_type: Optional[str]) -> bool:
        """Whether a response is reported: a fact about the resource only."""
        if any(path.startswith(prefix) for prefix in self._exclude):
            return False
        if path in ALWAYS_REPORTED_PATHS:
            return True
        if any(path.startswith(prefix) for prefix in self._include):
            return True
        media = (content_type or "").split(";", 1)[0].strip().lower()
        return media in self._content_types

    def _observe(self, request: ProxyRequest) -> Optional[_Observed]:
        """The request as it would be reported, or None when it cannot be."""
        user_agent = _wire_text(request.headers.first("user-agent"))
        if _utf8_len(user_agent) > MAX_HEADER_BYTES:
            return None
        client_ip = self._resolve_client_ip(request)
        if client_ip is None:
            return None
        address = canonical_ip(client_ip)
        signature, signature_input, signature_agent = (
            self._signature_header(request, name) for name in _SIGNATURE_HEADERS
        )
        signed = signature is not None and signature_input is not None
        raw_host = request.headers.get("host")
        host = _wire_text(raw_host) if raw_host else None
        method = request.method or None
        item = AgentSighting(
            user_agent=user_agent,
            client_ip=address,
            host=host,
            method=method,
            signature=signature,
            signature_input=signature_input,
            signature_agent=signature_agent,
        )
        size = sum(
            _utf8_len(value)
            for value in (
                user_agent,
                address,
                host,
                method,
                signature,
                signature_input,
                signature_agent,
            )
        )
        key = sighting_key(user_agent, address, signature_agent or "", signed)
        return _Observed(key, signed, item, size)

    @staticmethod
    def _signature_header(request: ProxyRequest, name: str) -> Optional[str]:
        """A Web Bot Auth header, or None when absent, blank or over the limit."""
        value = request.headers.get(name)
        if not value or not value.strip(" \t"):
            return None
        text = _wire_text(value)
        return text if _utf8_len(text) <= MAX_HEADER_BYTES else None

    def _resolve_client_ip(self, request: ProxyRequest) -> Optional[str]:
        """Calls ``client_ip`` and accepts exactly one IPv4 or IPv6 literal."""
        try:
            value = self._client_ip(request)
        except Exception:
            value = None
        if isinstance(value, str) and _is_ip_literal(value):
            return value
        self._log(
            "client_ip",
            "The client IP callback returned no valid address; "
            "the request was not reported",
        )
        return None

    def _record(self, observed: _Observed) -> None:
        """Adds one sighting to the buffer, folding repeats into a count."""
        self._check_fork()
        now = self._clock()
        with self._lock:
            if self._closed:
                return
            if not observed.signed:
                entry = self._pending.get(observed.key)
                if entry is not None:
                    entry.count = min(entry.count + 1, MAX_COUNT)
                    return
            if len(self._pending) + self._in_flight >= MAX_PENDING:
                self._dropped += 1
                return
            slot = (
                f"{observed.key}#{next(self._serial)}"
                if observed.signed
                else observed.key
            )
            self._pending[slot] = _Pending(slot, observed, now)
            self._pending_bytes += observed.size
            # The first item always wakes the flusher, which then sleeps out
            # any pause; a full buffer only wakes it when it may send.
            wake = len(self._pending) == 1 or (
                self._size_due() and now >= self._paused_until
            )
        if wake:
            self._wake()

    def _wake(self) -> None:
        """Tells the background flusher there is something to look at."""

    def _stopped(self) -> bool:
        """Read afresh after a wait: :meth:`close` sets it from elsewhere."""
        return self._stopping

    def _size_due(self) -> bool:
        return len(self._pending) >= BATCH_ITEMS or self._pending_bytes >= BATCH_BYTES

    def _wait_time(self, now: float) -> Optional[float]:
        """Seconds until a report is due, or None when nothing is pending."""
        with self._lock:
            if not self._pending:
                return None
            if self._size_due():
                due = now
            else:
                oldest = next(iter(self._pending.values()))
                due = oldest.first_seen + FLUSH_AFTER
            wait = max(0.0, max(due, self._paused_until) - now)
            # Never a wait a thread or the event loop cannot sleep on.
            return min(wait, MAX_RATE_LIMIT_PAUSE)

    def _take(self, now: float, force: bool) -> Optional[list[_Pending]]:
        """Moves the next batch in flight, when one may be sent now."""
        with self._lock:
            if self._in_flight or not self._pending or now < self._paused_until:
                return None
            if not force and not self._size_due():
                oldest = next(iter(self._pending.values()))
                if now - oldest.first_seen < FLUSH_AFTER:
                    return None
            batch: list[_Pending] = []
            size = 0
            while self._pending and len(batch) < BATCH_ITEMS:
                entry = next(iter(self._pending.values()))
                if batch and size + entry.size > BATCH_BYTES:
                    break
                self._pending.popitem(last=False)
                batch.append(entry)
                size += entry.size
            self._pending_bytes -= size
            self._in_flight = len(batch)
            return batch

    @staticmethod
    def _items_of(batch: Sequence[_Pending]) -> list[AgentSighting]:
        return [dataclasses.replace(entry.item, count=entry.count) for entry in batch]

    def _settle(
        self,
        batch: Sequence[_Pending],
        result: Optional[AgentSightingsResult],
        error: Optional[BaseException],
        progress: Optional[RequestProgress] = None,
    ) -> bool:
        """Applies the answer, or the failure rules, to a batch in flight.

        ``progress`` says how far the request got before ``error``.

        Returns:
            True when the batch was answered, so another may follow.
        """
        now = self._clock()
        if error is None and result is not None:
            if len(result.items) != len(batch):
                with self._lock:
                    self._in_flight = 0
                self._log(
                    "mismatch",
                    "Agent sightings answered a different number of items; "
                    "the batch was dropped",
                )
                return False
            with self._lock:
                self._in_flight = 0
                self._backoff = 0.0
                if result.rules_version != self._rules_version:
                    self._cache.clear()
                    self._rules_version = result.rules_version
                for entry, answer in zip(batch, result.items):
                    if answer.ttl > 0:
                        self._store(entry.key, answer, now + min(answer.ttl, MAX_TTL))
            return True

        outcome = self._classify(error, progress or RequestProgress())
        with self._lock:
            self._in_flight = 0
            if outcome.keep:
                self._restore(batch)
            if outcome.pause is not None:
                self._paused_until = max(self._paused_until, now + outcome.pause)
            if outcome.backoff:
                delay = self._backoff or BACKOFF_START
                self._paused_until = max(self._paused_until, now + delay)
                self._backoff = min(delay * 2, BACKOFF_MAX)
        if outcome.log is not None:
            self._log(*outcome.log)
        return False

    def _classify(
        self, error: Optional[BaseException], progress: RequestProgress
    ) -> _Outcome:
        """The section 6 failure table of the agent sightings contract."""
        if isinstance(error, FingerlyAPIError):
            status = error.status
            if status == 422:
                return _Outcome(
                    keep=False,
                    log=(
                        "invalid",
                        "Agent sightings were refused as invalid (HTTP 422); "
                        "the batch was dropped",
                    ),
                )
            if status in (401, 403):
                return _Outcome(
                    keep=False,
                    pause=AUTH_PAUSE,
                    log=(
                        "auth",
                        f"Agent sightings were refused (HTTP {status}): the secret "
                        "key is wrong or revoked; reporting pauses for 60 s",
                    ),
                )
            if status == 429:
                return _Outcome(keep=True, pause=self._rate_limit_pause(error))
            if status == 503:
                return _Outcome(keep=True, backoff=True)
            return _Outcome(
                keep=False,
                log=(
                    "status",
                    f"Agent sightings failed (HTTP {status}); the batch was dropped",
                ),
            )
        if isinstance(error, FingerlyTimeoutError):
            # Out of time before the report was written, as while connecting
            # or in a TLS handshake: the server cannot have counted it. The
            # async deadline cuts a connect short as a plain timeout, so the
            # transport's progress tells, where it reports any.
            if progress.unsent or isinstance(
                error.__cause__, (httpx.ConnectTimeout, httpx.PoolTimeout)
            ):
                return _Outcome(keep=True, backoff=True)
            # Sent, then no answer in time: the server may have counted it,
            # and sending it again would count it twice.
            return _Outcome(
                keep=False,
                log=(
                    "timeout",
                    "Agent sightings timed out after the report was sent; "
                    "the batch was dropped",
                ),
            )
        if isinstance(error, FingerlyConnectionError):
            if progress.written:
                # Closed, reset or cut short once the report was written: the
                # server may have counted it, as after a timeout. A transport
                # that cannot tell leaves ``written`` unset, and the batch is
                # kept.
                return _Outcome(
                    keep=False,
                    log=(
                        "closed",
                        "Agent sightings lost the connection after the report "
                        "was sent; the batch was dropped",
                    ),
                )
            return _Outcome(keep=True, backoff=True)
        return _Outcome(
            keep=False,
            log=("unexpected", "Agent sightings failed; the batch was dropped"),
        )

    def _rate_limit_pause(self, error: FingerlyAPIError) -> float:
        if error.retry_after is not None:
            # Clamped to between 1 second and 24 hours: 2147483647, a
            # 20-digit number or a date in 2100 must not pause for good.
            return min(
                MAX_RATE_LIMIT_PAUSE, max(MIN_RATE_LIMIT_PAUSE, error.retry_after)
            )
        if error.rate_limit_scope == "daily":
            now = self._utc_now()
            midnight = datetime(
                now.year, now.month, now.day, tzinfo=timezone.utc
            ) + timedelta(days=1)
            return max(0.0, (midnight - now).total_seconds())
        return RATE_LIMIT_PAUSE

    def _abandon(self, batch: Sequence[_Pending], written: bool) -> None:
        """Settles a batch whose send was interrupted rather than answered.

        Without this the batch would stay in flight for good, and no report
        would ever be sent again. One that may have reached the server is
        dropped, as after a timeout; one that cannot have is kept.
        """
        with self._lock:
            self._in_flight = 0
            if not written:
                self._restore(batch)

    def _restore(self, batch: Sequence[_Pending]) -> None:
        """Puts a kept batch back as the oldest reports. Holds the lock."""
        for entry in reversed(batch):
            existing = self._pending.get(entry.slot)
            if existing is not None:
                # The same request was seen again while this one was in
                # flight: one item, the first sighting, both counts.
                existing.count = min(existing.count + entry.count, MAX_COUNT)
                existing.first_seen = min(existing.first_seen, entry.first_seen)
                self._pending_bytes += entry.size - existing.size
                existing.item, existing.size = entry.item, entry.size
            else:
                self._pending[entry.slot] = entry
                self._pending_bytes += entry.size
            self._pending.move_to_end(entry.slot, last=False)

    def _store(self, key: str, answer: AgentAnswer, expires: float) -> None:
        """Remembers one answer, evicting the least recently used. Holds the lock."""
        cache = self._cache
        if key in cache:
            cache.move_to_end(key)
        cache[key] = (expires, answer)
        while len(cache) > self._capacity:
            cache.popitem(last=False)

    def _log(self, kind: str, message: str) -> None:
        """Logs one kind of failure at most once per minute. Never a field."""
        now = self._clock()
        with self._log_lock:
            last = self._logged.get(kind)
            if last is not None and now - last < LOG_EVERY:
                return
            self._logged[kind] = now
        logger.warning(message)


class AgentSightings(_BaseSightings):
    """Reports the requests your server served and remembers the answers.

    Mount :meth:`wsgi` or :meth:`asgi` around your application. After each
    response whose content type is HTML (or that is ``/robots.txt``,
    ``/llms.txt`` or ``/llms-full.txt``) it records the request's user agent,
    address, host, method and Web Bot Auth headers in a bounded buffer. A
    daemon thread sends the buffer to Fingerly, and :meth:`lookup` answers
    later requests from what the server said, without waiting on the network.

    The path, query string, cookies, ``Authorization``, other headers, bodies
    and the response are never sent or logged.

    Example:
        >>> sightings = AgentSightings(
        ...     fingerly,
        ...     client_ip=lambda request: (
        ...         request.headers.get("cf-connecting-ip") or request.peer_host
        ...     ),
        ... )
        >>> app.wsgi_app = sightings.wsgi(app.wsgi_app)
    """

    def __init__(
        self,
        client: Fingerly,
        client_ip: Callable[[ProxyRequest], Optional[str]],
        *,
        cache_size: int = DEFAULT_CACHE_SIZE,
        content_types: Sequence[str] = DEFAULT_CONTENT_TYPES,
        include_paths: Sequence[str] = (),
        exclude_paths: Sequence[str] = (),
        background: bool = True,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        """Validates every option before anything is recorded.

        Args:
            client: The :class:`Fingerly` client whose secret key reports.
            client_ip: Resolves the visitor's address from infrastructure your
                app trusts, exactly as for :class:`FingerlyProxy`. Never read
                the left-most ``X-Forwarded-For`` value: the visitor writes
                it. Return None when there is no address; a request whose
                address cannot be resolved is not reported, and is served as
                usual.
            cache_size: Answers remembered, at most 65536 (larger values are
                lowered to it). Each costs a few hundred bytes.
            content_types: Response content types reported, replacing the
                default ``text/html`` and ``application/xhtml+xml``.
            include_paths: Path prefixes reported whatever their content type.
            exclude_paths: Path prefixes never reported; they win over
                everything else.
            background: Run the daemon flusher. Turn it off where the process
                is frozen between invocations, and call :meth:`flush` before
                each one ends.
            clock: Monotonic seconds; override only in tests.

        Raises:
            TypeError: If an option is invalid.
        """
        if not isinstance(client, Fingerly):
            raise TypeError("client must be a Fingerly client")
        self._client = client
        super().__init__(
            client_ip,
            cache_size,
            content_types,
            include_paths,
            exclude_paths,
            background,
            clock,
        )

    def _reset_state(self) -> None:
        super()._reset_state()
        self._send_lock = threading.Lock()
        self._thread_lock = threading.Lock()
        self._event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def wsgi(self, app: Any) -> SightingsWSGI:
        """Wraps a WSGI application so its responses are reported."""
        from ._sightings_middleware import SightingsWSGI

        return SightingsWSGI(app, self)

    def asgi(self, app: Any) -> SightingsASGI:
        """Wraps an ASGI application so its responses are reported."""
        from ._sightings_middleware import SightingsASGI

        return SightingsASGI(app, self)

    def flush(self) -> None:
        """Sends every pending report now, one batch at a time.

        Waits up to 6 seconds for a report already in flight first. Stops
        early while reporting is paused or when a batch fails, and never
        raises. Call it before a serverless invocation ends.
        """
        self._flush(None)

    def _flush(self, budget: Optional[float]) -> None:
        """:meth:`flush`, ending within ``budget`` seconds when one is given."""
        ends = None if budget is None else time.monotonic() + budget
        try:
            self._check_fork()
            while True:
                left = FLUSH_WAIT if ends is None else ends - time.monotonic()
                if left <= 0 or not self._send_lock.acquire(
                    timeout=min(left, FLUSH_WAIT)
                ):
                    return
                try:
                    deadline = FLUSH_DEADLINE
                    if ends is not None:
                        deadline = min(deadline, ends - time.monotonic())
                    if deadline <= 0:
                        return
                    batch = self._take(self._clock(), force=True)
                    if batch is None or not self._send(batch, deadline):
                        return
                finally:
                    self._send_lock.release()
        except Exception:
            self._log("flush", "Agent sightings could not flush")

    def _flush_at_exit(self, budget: Optional[float] = None) -> None:
        if self._closed or self._pid != os.getpid() or self._client._closed:
            return
        self._stopping = True
        self._event.set()
        self._flush(SHUTDOWN_DEADLINE if budget is None else budget)

    async def _flush_at_shutdown(self) -> None:
        if self._closed or self._client._closed:
            return
        # The sync client blocks, so it runs off the event loop.
        with contextlib.suppress(Exception):
            await asyncio.get_running_loop().run_in_executor(
                None, self._flush, SHUTDOWN_DEADLINE
            )

    def close(self) -> None:
        """Stops the flusher and sends what is pending. Safe to call twice.

        The client stays open: it is yours to close.
        """
        self._check_fork()
        self._stopping = True
        self._event.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(FLUSH_DEADLINE + 1.0)
        self.flush()
        with self._lock:
            self._closed = True

    def __enter__(self: _Self) -> _Self:
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()

    def _wake(self) -> None:
        if not self._background or self._stopping:
            return
        thread = self._thread
        if thread is None or not thread.is_alive():
            with self._thread_lock:
                thread = self._thread
                if thread is None or not thread.is_alive():
                    self._thread = threading.Thread(
                        target=self._run, name="fingerly-agent-sightings", daemon=True
                    )
                    self._thread.start()
        self._event.set()

    def _run(self) -> None:
        """The daemon flusher: sleeps until a report is due, then sends it."""
        while not self._stopping:
            self._event.clear()
            self._event.wait(self._wait_time(self._clock()))
            if self._stopped():
                return
            try:
                with self._send_lock:
                    batch = self._take(self._clock(), force=False)
                    if batch is not None:
                        self._send(batch)
            except Exception:
                self._log("flush", "Agent sightings could not flush")

    def _send(self, batch: list[_Pending], deadline: float = FLUSH_DEADLINE) -> bool:
        """Sends one batch and settles it. Holds the send lock."""
        progress = RequestProgress()
        token = REQUEST_PROGRESS.set(progress)
        try:
            result = self._client.agents.sightings(
                self._items_of(batch), timeout=deadline
            )
        except Exception as error:
            return self._settle(batch, None, error, progress)
        except BaseException:
            # Interrupted, as by KeyboardInterrupt during close().
            self._abandon(batch, progress.written)
            raise
        finally:
            REQUEST_PROGRESS.reset(token)
        return self._settle(batch, result, None)


class AsyncAgentSightings(_BaseSightings):
    """:class:`AgentSightings` for asyncio applications.

    The flusher is a task on the event loop that serves your requests, and it
    reports through an :class:`AsyncFingerly` client. Mount :meth:`asgi`
    around your application; :meth:`lookup` is the same.

    Example:
        >>> sightings = AsyncAgentSightings(fingerly, client_ip=client_ip)
        >>> app = sightings.asgi(app)
    """

    def __init__(
        self,
        client: AsyncFingerly,
        client_ip: Callable[[ProxyRequest], Optional[str]],
        *,
        cache_size: int = DEFAULT_CACHE_SIZE,
        content_types: Sequence[str] = DEFAULT_CONTENT_TYPES,
        include_paths: Sequence[str] = (),
        exclude_paths: Sequence[str] = (),
        background: bool = True,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        """See :meth:`AgentSightings.__init__`; ``client`` is an
        :class:`AsyncFingerly`, and the flusher runs as an asyncio task.

        Raises:
            TypeError: If an option is invalid.
        """
        if not isinstance(client, AsyncFingerly):
            raise TypeError("client must be an AsyncFingerly client")
        self._client = client
        super().__init__(
            client_ip,
            cache_size,
            content_types,
            include_paths,
            exclude_paths,
            background,
            clock,
        )

    def _reset_state(self) -> None:
        super()._reset_state()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._task: Optional[asyncio.Task[None]] = None
        self._event: Optional[asyncio.Event] = None
        self._send_lock: Optional[asyncio.Lock] = None

    def asgi(self, app: Any) -> SightingsASGI:
        """Wraps an ASGI application so its responses are reported."""
        from ._sightings_middleware import SightingsASGI

        return SightingsASGI(app, self)

    async def flush(self) -> None:
        """Sends every pending report now. See :meth:`AgentSightings.flush`.

        Cancelling the task that awaits it cancels it, as with any coroutine;
        nothing else is raised.
        """
        await self._flush(None)

    async def _flush(self, budget: Optional[float]) -> None:
        """:meth:`flush`, ending within ``budget`` seconds when one is given."""
        ends = None if budget is None else time.monotonic() + budget
        try:
            self._check_fork()
            lock = self._lock_for_loop()
            while True:
                left = FLUSH_WAIT if ends is None else ends - time.monotonic()
                if left <= 0 or not await _acquire_within(lock, min(left, FLUSH_WAIT)):
                    return
                try:
                    deadline = FLUSH_DEADLINE
                    if ends is not None:
                        deadline = min(deadline, ends - time.monotonic())
                    if deadline <= 0:
                        return
                    batch = self._take(self._clock(), force=True)
                    if batch is None or not await self._send(batch, deadline):
                        return
                finally:
                    lock.release()
        except Exception:
            self._log("flush", "Agent sightings could not flush")

    async def _flush_at_shutdown(self) -> None:
        if self._closed or self._client._closed:
            return
        await self._flush(SHUTDOWN_DEADLINE)

    async def aclose(self) -> None:
        """Stops the flusher and sends what is pending. Safe to call twice."""
        self._check_fork()
        self._stopping = True
        task = self._task
        if self._event is not None:
            self._event.set()
        if task is not None and not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), FLUSH_DEADLINE + 1.0)
            except Exception:
                task.cancel()
        await self.flush()
        with self._lock:
            self._closed = True

    async def __aenter__(self: _Self) -> _Self:
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        await self.aclose()

    def _lock_for_loop(self) -> asyncio.Lock:
        """The send lock, made on the loop that uses it."""
        loop = asyncio.get_running_loop()
        if self._send_lock is None or self._loop is not loop:
            self._loop = loop
            self._send_lock = asyncio.Lock()
            self._event = asyncio.Event()
            self._task = None
        return self._send_lock

    def _wake(self) -> None:
        if not self._background or self._stopping:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # Recorded off the loop: hand the wake-up to the loop, if any.
            if self._loop is not None and self._event is not None:
                with contextlib.suppress(RuntimeError):
                    self._loop.call_soon_threadsafe(self._event.set)
            return
        self._lock_for_loop()
        if self._task is None or self._task.done():
            self._task = loop.create_task(self._run())
        assert self._event is not None
        self._event.set()

    async def _run(self) -> None:
        """The flusher task: sleeps until a report is due, then sends it."""
        lock = self._lock_for_loop()
        event = self._event
        assert event is not None
        while not self._stopping:
            event.clear()
            wait = self._wait_time(self._clock())
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(event.wait(), wait)
            if self._stopped():
                return
            try:
                async with lock:
                    batch = self._take(self._clock(), force=False)
                    if batch is not None:
                        await self._send(batch)
            except Exception:
                self._log("flush", "Agent sightings could not flush")

    async def _send(
        self, batch: list[_Pending], deadline: float = FLUSH_DEADLINE
    ) -> bool:
        progress = RequestProgress()
        token = REQUEST_PROGRESS.set(progress)
        try:
            result = await self._client.agents.sightings(
                self._items_of(batch), timeout=deadline
            )
        except Exception as error:
            return self._settle(batch, None, error, progress)
        except BaseException:
            # Cancelled, as when the loop shuts down mid-report.
            self._abandon(batch, progress.written)
            raise
        finally:
            REQUEST_PROGRESS.reset(token)
        return self._settle(batch, result, None)
