"""The synchronous and asyncio clients, and the event reads they expose."""

from __future__ import annotations

import asyncio
import threading
import time
import warnings
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from types import TracebackType
from typing import Any, Optional, TypeVar, Union

import httpx

from ._config import (
    DEFAULT_ENDPOINT,
    Secret,
    no_cookies,
    normalize_api_origin,
    normalize_api_version,
    parse_key,
    positive_seconds,
)
from ._enums import VerifyReason
from ._errors import (
    FingerlyAPIError,
    FingerlyConnectionError,
    FingerlyEventAlreadyConsumedError,
    FingerlyTimeoutError,
)
from ._http import MAX_RESPONSE_BYTES, AsyncPool, Reply, ResponseTooLargeError, SyncPool
from ._models import (
    AgentSighting,
    AgentSightingsResult,
    ConsumeResult,
    DeviceCheckBits,
    DeviceCheckWriteResult,
    Event,
    EventPage,
    VerifyResult,
    failed_check,
    parse_agent_sightings,
    parse_consume,
    parse_device_check_bits,
    parse_device_check_write,
    parse_event,
    parse_page,
    parse_verified_event,
)
from ._transport import (
    KeyAuth,
    api_error,
    decode_json,
    device_check_body,
    device_check_error,
    event_path,
    headers_for,
    is_not_found,
    list_params,
    sightings_body,
    verify_options,
)

DEFAULT_TIMEOUT = 10.0

#: How old an event ``events.verify`` accepts by default, in seconds.
DEFAULT_MAX_AGE_SECONDS = 300


def _now() -> datetime:
    """The current instant, timezone-aware, that an event's age is taken from."""
    return datetime.now(timezone.utc)


_Self = TypeVar("_Self", bound="_BaseFingerly")


class _BaseFingerly:
    """Configuration shared by :class:`Fingerly` and :class:`AsyncFingerly`."""

    def __init__(
        self,
        secret_key: str,
        endpoint: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        api_version: str = "v1",
        allow_insecure_loopback: bool = False,
    ) -> None:
        """Validates every option before any client is built.

        Args:
            secret_key: A server-only key, ``fly_sk_{environment}_…``. Its
                prefix names the environment read.
            endpoint: Overrides the Fingerly API origin, for a local API. Only
                a scheme, a host and an optional port, such as
                ``https://api.example.com:8443``; ``https`` is required.
            timeout: One deadline, in seconds, over the whole request:
                connecting, sending, the response headers and the body.
            api_version: API route version; the server must support it.
            allow_insecure_loopback: For local development and tests only:
                lets ``endpoint`` be plain ``http`` on 127.0.0.1, localhost or
                [::1]. Every other ``http`` endpoint is refused either way.

        Raises:
            TypeError: If any option is invalid. Nothing is sent until then.
        """
        # Validate the key even when an endpoint is given, so a public, proxy
        # or management key can never reach an API that would accept it.
        parse_key(secret_key, "sk")
        origin = normalize_api_origin(
            DEFAULT_ENDPOINT if endpoint is None else endpoint,
            allow_insecure_loopback,
            "endpoint",
        )
        self._secret_key = Secret(secret_key)
        self._base_url = f"{origin}/api/{normalize_api_version(api_version)}"
        self._timeout = positive_seconds(timeout, "timeout")

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(endpoint={self._base_url!r}, "
            f"secret_key={self._secret_key!r})"
        )

    def _interpret(self, response: Reply) -> Mapping[str, Any]:
        """Turns a response into a decoded body or the matching error.

        Raises:
            FingerlyAPIError: On any non-2xx response, redirects included:
                requests never follow one, so a 3xx is not an answer.
        """
        if not 200 <= response.status < 300:
            raise api_error(
                response.status,
                response.body,
                self._secret_key,
                response.headers.get("retry-after"),
                response.headers.get("fingerly-ratelimit-scope"),
            )
        return decode_json(response.body, response.status)


class Events:
    """Synchronous event reads. Reached as ``fingerly.events``."""

    def __init__(self, client: Fingerly) -> None:
        self._client = client

    def get(self, request_id: str) -> Event:
        """Fetches one event by request id.

        Args:
            request_id: The ``request_id`` returned by identification.

        Raises:
            FingerlyEventPendingError: ``404 event_pending`` when the
                request id was accepted but the event is not recorded yet;
                ``retry_after`` says when to try again. Not retried here.
            FingerlyAPIError: ``404 event_not_found`` when the request id was
                never issued or the event is past retention, and any other
                non-2xx answer.
            FingerlyTimeoutError: If the request exceeds the client timeout.
        """
        return parse_event(self._client._request(event_path(request_id)))

    def consume(self, request_id: str) -> ConsumeResult:
        """Marks an event as consumed, so it backs one decision only.

        The first call answers with ``first=True``; every later one raises.
        Never retried.

        Args:
            request_id: The ``request_id`` returned by identification.

        Raises:
            TypeError: If the request id is empty. Nothing is sent.
            FingerlyEventAlreadyConsumedError: ``409 event_already_consumed``
                when the event was consumed before; ``consumed_at`` says when.
            FingerlyAPIError: ``404 event_not_found``, and any other non-2xx
                answer.
            FingerlyTimeoutError: If the request exceeds the client timeout.
        """
        path = event_path(request_id) + "/consume"
        return parse_consume(self._client._request(path, method="POST"))

    def verify(
        self,
        request_id: str,
        *,
        max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
        tag: Optional[str] = None,
        consume: bool = True,
    ) -> VerifyResult:
        """Reads an event and checks it can back a backend action.

        The checks run in this order and stop at the first failure: the event
        exists (``not_found``), it occurred at most ``max_age_seconds`` ago
        (``too_old``; a missing or unreadable time fails too), it carries
        ``tag`` exactly when one is given (``tag_mismatch``), it has a
        visitor id (``unidentifiable``) and a score (``unscored``). Only then,
        unless ``consume=False``, is it consumed (``already_consumed``). The
        score's value is never judged: that policy stays with the caller.

        Args:
            request_id: The ``request_id`` returned by identification.
            max_age_seconds: Oldest acceptable event, in seconds.
            tag: The tag the event must carry, or None to skip the check.
            consume: Whether to consume the event when every check passes.

        Raises:
            TypeError: If an option or the request id is unusable. Nothing is
                sent.
            FingerlyEventPendingError: ``404 event_pending``; not a verdict.
            FingerlyAPIError: Any answer other than ``event_not_found`` and,
                on consume, ``event_already_consumed``.
            FingerlyTimeoutError: If a request exceeds the client timeout.
        """
        verify_options(max_age_seconds, tag, consume)
        path = event_path(request_id)
        try:
            payload = self._client._request(path)
        except FingerlyAPIError as error:
            if is_not_found(error):
                return VerifyResult(ok=False, reason=VerifyReason.NOT_FOUND)
            raise
        event, occurred = parse_verified_event(payload)
        reason = failed_check(event, occurred, _now(), max_age_seconds, tag)
        if reason:
            return VerifyResult(ok=False, reason=reason, event=event)
        if consume:
            try:
                self._client._request(path + "/consume", method="POST")
            except FingerlyEventAlreadyConsumedError:
                return VerifyResult(
                    ok=False, reason=VerifyReason.ALREADY_CONSUMED, event=event
                )
            except FingerlyAPIError as error:
                if is_not_found(error):
                    return VerifyResult(ok=False, reason=VerifyReason.NOT_FOUND)
                raise
        return VerifyResult(ok=True, reason=VerifyReason.OK, event=event)

    def list(
        self,
        from_: Union[datetime, str, None] = None,
        to: Union[datetime, str, None] = None,
        page: int = 1,
        limit: int = 10,
        visitor: Optional[str] = None,
        level: Optional[str] = None,
        kind: Optional[str] = None,
        ai_provider: Optional[str] = None,
        ai_purpose: Optional[str] = None,
    ) -> EventPage:
        """Lists events within the retention window, newest first.

        Args:
            from_: Start of the window. Defaults to 24 hours ago.
            to: End of the window. Defaults to now.
            page: 1-based page number.
            limit: Rows per page, at most 200.
            visitor: Restrict to one exact visitor id.
            level: Restrict to ``low``, ``medium`` or ``high``; a
                :class:`SuspectLevel` member works too.
            kind: Restrict to one visitor kind, a :class:`VisitorKind`
                member such as ``VisitorKind.AI_BOT``.
            ai_provider: Restrict to one AI agent operator, exactly as events
                name it (case sensitive), such as ``OpenAI``.
            ai_purpose: Restrict to one AI agent purpose, an
                :class:`AIPurpose` member such as ``AIPurpose.USER_FETCH``.

        Raises:
            TypeError: If a bound, page or limit is unusable.
            FingerlyAPIError: On any non-2xx response.
        """
        params = list_params(
            from_, to, page, limit, visitor, level, kind, ai_provider, ai_purpose
        )
        return parse_page(self._client._request("/events", params))


class AsyncEvents:
    """Asyncio event reads. Reached as ``fingerly.events``."""

    def __init__(self, client: AsyncFingerly) -> None:
        self._client = client

    async def get(self, request_id: str) -> Event:
        """Fetches one event by request id.

        See :meth:`Events.get`; this coroutine takes the same arguments.
        """
        return parse_event(await self._client._request(event_path(request_id)))

    async def consume(self, request_id: str) -> ConsumeResult:
        """Marks an event as consumed. See :meth:`Events.consume`."""
        path = event_path(request_id) + "/consume"
        return parse_consume(await self._client._request(path, method="POST"))

    async def verify(
        self,
        request_id: str,
        *,
        max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
        tag: Optional[str] = None,
        consume: bool = True,
    ) -> VerifyResult:
        """Reads and checks an event, then consumes it. See :meth:`Events.verify`."""
        verify_options(max_age_seconds, tag, consume)
        path = event_path(request_id)
        try:
            payload = await self._client._request(path)
        except FingerlyAPIError as error:
            if is_not_found(error):
                return VerifyResult(ok=False, reason=VerifyReason.NOT_FOUND)
            raise
        event, occurred = parse_verified_event(payload)
        reason = failed_check(event, occurred, _now(), max_age_seconds, tag)
        if reason:
            return VerifyResult(ok=False, reason=reason, event=event)
        if consume:
            try:
                await self._client._request(path + "/consume", method="POST")
            except FingerlyEventAlreadyConsumedError:
                return VerifyResult(
                    ok=False, reason=VerifyReason.ALREADY_CONSUMED, event=event
                )
            except FingerlyAPIError as error:
                if is_not_found(error):
                    return VerifyResult(ok=False, reason=VerifyReason.NOT_FOUND)
                raise
        return VerifyResult(ok=True, reason=VerifyReason.OK, event=event)

    async def list(
        self,
        from_: Union[datetime, str, None] = None,
        to: Union[datetime, str, None] = None,
        page: int = 1,
        limit: int = 10,
        visitor: Optional[str] = None,
        level: Optional[str] = None,
        kind: Optional[str] = None,
        ai_provider: Optional[str] = None,
        ai_purpose: Optional[str] = None,
    ) -> EventPage:
        """Lists events within the retention window, newest first.

        See :meth:`Events.list`; this coroutine takes the same arguments.
        """
        params = list_params(
            from_, to, page, limit, visitor, level, kind, ai_provider, ai_purpose
        )
        return parse_page(await self._client._request("/events", params))


class Agents:
    """Reports the requests your server served. Reached as ``fingerly.agents``.

    Most code uses :class:`AgentSightings`, which batches, remembers the
    answers and never delays a request. This is the call underneath it.
    """

    def __init__(self, client: Fingerly) -> None:
        self._client = client

    def sightings(
        self, items: Sequence[AgentSighting], *, timeout: Optional[float] = None
    ) -> AgentSightingsResult:
        """Reports up to 200 served requests and reads what sent each one.

        Never retried: a report the server may have counted is not sent again.

        Args:
            items: The requests, as raw input, at most 200.
            timeout: Replaces the client timeout for this call, in seconds.

        Raises:
            TypeError: If an item is not an :class:`AgentSighting`. Nothing
                is sent.
            FingerlyAPIError: On any non-2xx answer. A ``429`` carries
                ``retry_after`` and ``rate_limit_scope`` (``daily`` for the
                daily allowance); ``422 invalid_request`` means an item broke
                a limit.
            FingerlyTimeoutError: If the call exceeds its deadline.
            FingerlyConnectionError: If the API could not be reached.
        """
        body = sightings_body(items)
        deadline = None if timeout is None else positive_seconds(timeout, "timeout")
        return parse_agent_sightings(
            self._client._request(
                _SIGHTINGS_PATH, method="POST", content=body, timeout=deadline
            )
        )


class AsyncAgents:
    """Asyncio sightings reports. Reached as ``fingerly.agents``.

    See :class:`Agents`; the coroutine takes the same arguments.
    """

    def __init__(self, client: AsyncFingerly) -> None:
        self._client = client

    async def sightings(
        self, items: Sequence[AgentSighting], *, timeout: Optional[float] = None
    ) -> AgentSightingsResult:
        """Reports served requests. See :meth:`Agents.sightings`."""
        body = sightings_body(items)
        deadline = None if timeout is None else positive_seconds(timeout, "timeout")
        return parse_agent_sightings(
            await self._client._request(
                _SIGHTINGS_PATH, method="POST", content=body, timeout=deadline
            )
        )


_SIGHTINGS_PATH = "/agents/sightings"


class DeviceCheck:
    """Spends the DeviceCheck token held for an iOS event, once.

    Reached as ``fingerly.device_check``. Each held token pays for one Apple
    call: a read or a write, never both. To read the bits and then set them,
    read on one identification and write on the next.

    A ``503 device_check_unavailable`` or a transport failure is retried with
    the identical request: a token kept after an answer that was not definite
    accepts only the request it was first used for.
    """

    def __init__(self, client: Fingerly) -> None:
        self._client = client

    def query(self, request_id: str) -> DeviceCheckBits:
        """Reads the device's two bits from Apple, spending the event's token.

        Args:
            request_id: The ``request_id`` of an iOS identification made within
                the last hour.

        Raises:
            FingerlyDeviceCheckError: On any non-2xx answer; see its ``code``.
            FingerlyTimeoutError: If every attempt timed out.
            FingerlyConnectionError: If the API could not be reached.
        """
        path = device_check_path(request_id) + "/query"
        return parse_device_check_bits(self._spend("POST", path, None))

    def write(
        self,
        request_id: str,
        bit0: Optional[bool] = None,
        bit1: Optional[bool] = None,
    ) -> DeviceCheckWriteResult:
        """Sets bit0, bit1 or both with Apple, spending the event's token.

        A bit left as None keeps its value.

        Raises:
            TypeError: If neither bit is given. Nothing is sent.
            FingerlyDeviceCheckError: On any non-2xx answer; see its ``code``.
            FingerlyTimeoutError: If every attempt timed out.
            FingerlyConnectionError: If the API could not be reached.
        """
        body = device_check_body(bit0, bit1)
        path = device_check_path(request_id)
        return parse_device_check_write(self._spend("PUT", path, body))

    def _spend(
        self, method: str, path: str, body: Optional[bytes]
    ) -> Mapping[str, Any]:
        for attempt in range(len(_DEVICE_CHECK_RETRY_DELAYS) + 1):
            try:
                return self._client._request(path, method=method, content=body)
            except FingerlyAPIError as error:
                if error.status != 503 or attempt == len(_DEVICE_CHECK_RETRY_DELAYS):
                    raise device_check_error(error) from None
                time.sleep(_retry_delay(attempt, error.retry_after))
            except (FingerlyTimeoutError, FingerlyConnectionError):
                if attempt == len(_DEVICE_CHECK_RETRY_DELAYS):
                    raise
                time.sleep(_retry_delay(attempt, None))
        raise AssertionError("unreachable")  # pragma: no cover


class AsyncDeviceCheck:
    """Asyncio DeviceCheck reads and writes. Reached as ``fingerly.device_check``.

    See :class:`DeviceCheck`; the coroutines take the same arguments.
    """

    def __init__(self, client: AsyncFingerly) -> None:
        self._client = client

    async def query(self, request_id: str) -> DeviceCheckBits:
        """Reads the device's two bits. See :meth:`DeviceCheck.query`."""
        path = device_check_path(request_id) + "/query"
        return parse_device_check_bits(await self._spend("POST", path, None))

    async def write(
        self,
        request_id: str,
        bit0: Optional[bool] = None,
        bit1: Optional[bool] = None,
    ) -> DeviceCheckWriteResult:
        """Sets bit0, bit1 or both. See :meth:`DeviceCheck.write`."""
        body = device_check_body(bit0, bit1)
        path = device_check_path(request_id)
        return parse_device_check_write(await self._spend("PUT", path, body))

    async def _spend(
        self, method: str, path: str, body: Optional[bytes]
    ) -> Mapping[str, Any]:
        for attempt in range(len(_DEVICE_CHECK_RETRY_DELAYS) + 1):
            try:
                return await self._client._request(path, method=method, content=body)
            except FingerlyAPIError as error:
                if error.status != 503 or attempt == len(_DEVICE_CHECK_RETRY_DELAYS):
                    raise device_check_error(error) from None
                await asyncio.sleep(_retry_delay(attempt, error.retry_after))
            except (FingerlyTimeoutError, FingerlyConnectionError):
                if attempt == len(_DEVICE_CHECK_RETRY_DELAYS):
                    raise
                await asyncio.sleep(_retry_delay(attempt, None))
        raise AssertionError("unreachable")  # pragma: no cover


#: Pauses before each DeviceCheck retry, in seconds. A ``Retry-After`` answer
#: replaces the pause, up to :data:`_MAX_DEVICE_CHECK_RETRY_DELAY`.
_DEVICE_CHECK_RETRY_DELAYS: tuple[float, ...] = (0.25, 1.0)
_MAX_DEVICE_CHECK_RETRY_DELAY = 5.0

_JSON_BODY = {"content-type": "application/json"}


def device_check_path(request_id: str) -> str:
    """The DeviceCheck path of one event, the id encoded as one segment."""
    return event_path(request_id) + "/device-check"


def _retry_delay(attempt: int, retry_after: Optional[float]) -> float:
    if retry_after is not None:
        return min(retry_after, _MAX_DEVICE_CHECK_RETRY_DELAY)
    return _DEVICE_CHECK_RETRY_DELAYS[attempt]


class Fingerly(_BaseFingerly):
    """The Fingerly server SDK for synchronous code.

    Use it in Django, Flask, scripts and Celery tasks. Build one client and
    reuse it: each holds a pooled connection. Secret keys belong in
    server-side code only.

    Example:
        >>> with Fingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"]) as fingerly:
        ...     page = fingerly.events.list(level="high", limit=50)
    """

    def __init__(
        self,
        secret_key: str,
        endpoint: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        api_version: str = "v1",
        transport: Optional[httpx.BaseTransport] = None,
        limits: Optional[httpx.Limits] = None,
        allow_insecure_loopback: bool = False,
    ) -> None:
        """See :class:`_BaseFingerly` for the shared arguments.

        Args:
            transport: Replacement httpx transport, for tests or a host with
                its own HTTP stack. It is used as given, as one pool.
            limits: Connections this client may hold across its pools. The
                default lets 256 concurrent reads reuse connections.
        """
        super().__init__(
            secret_key, endpoint, timeout, api_version, allow_insecure_loopback
        )

        def build(pool_transport: Optional[httpx.BaseTransport]) -> httpx.Client:
            return httpx.Client(
                base_url=self._base_url,
                headers=headers_for(),
                auth=KeyAuth(self._secret_key),
                timeout=self._timeout,
                follow_redirects=False,
                cookies=no_cookies(),
                transport=pool_transport,
            )

        self._pool = SyncPool(build, self._timeout, limits, transport)
        self.events = Events(self)
        self.device_check = DeviceCheck(self)
        self.agents = Agents(self)

    def close(self) -> None:
        """Closes the pooled connections. Safe to call more than once."""
        self._pool.close()

    @property
    def _closed(self) -> bool:
        return self._pool.closed

    def __enter__(self: _Self) -> _Self:
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.close()

    def _request(
        self,
        path: str,
        params: Optional[Mapping[str, str]] = None,
        *,
        method: str = "GET",
        content: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> Mapping[str, Any]:
        """Performs one request and decodes its body. Never retries.

        ``timeout`` replaces the client's deadline for this request.

        Raises:
            FingerlyTimeoutError: If the request exceeds the client timeout.
            FingerlyConnectionError: If the API could not be reached.
            FingerlyAPIError: On any non-2xx response.
        """
        _warn_if_on_an_event_loop()
        try:
            reply = self._pool.request(
                method,
                path,
                params=params,
                content=content,
                headers=_JSON_BODY if content is not None else None,
                deadline=timeout,
            )
        except httpx.TimeoutException as error:
            raise FingerlyTimeoutError() from error
        except httpx.HTTPError as error:
            raise FingerlyConnectionError("Could not reach the Fingerly API") from error
        except ResponseTooLargeError as error:
            raise _too_large(error) from None
        return self._interpret(reply)


class AsyncFingerly(_BaseFingerly):
    """The Fingerly server SDK for asyncio code.

    Use it in FastAPI, Starlette, aiohttp and Quart. Build one client per
    event loop and reuse it.

    Example:
        >>> async with AsyncFingerly(secret_key=key) as fingerly:
        ...     event = await fingerly.events.get(request_id)
    """

    def __init__(
        self,
        secret_key: str,
        endpoint: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        api_version: str = "v1",
        transport: Optional[httpx.AsyncBaseTransport] = None,
        limits: Optional[httpx.Limits] = None,
        allow_insecure_loopback: bool = False,
    ) -> None:
        """See :class:`_BaseFingerly` for the shared arguments.

        Args:
            transport: Replacement httpx transport, for tests or a host with
                its own HTTP stack. It is used as given, as one pool.
            limits: Connections this client may hold across its pools. The
                default lets 256 concurrent reads reuse connections.
        """
        super().__init__(
            secret_key, endpoint, timeout, api_version, allow_insecure_loopback
        )

        def build(
            pool_transport: Optional[httpx.AsyncBaseTransport],
        ) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers_for(),
                auth=KeyAuth(self._secret_key),
                timeout=self._timeout,
                follow_redirects=False,
                cookies=no_cookies(),
                transport=pool_transport,
            )

        self._pool = AsyncPool(build, self._timeout, limits, transport)
        self.events = AsyncEvents(self)
        self.device_check = AsyncDeviceCheck(self)
        self.agents = AsyncAgents(self)

    async def aclose(self) -> None:
        """Closes the pooled connections. Safe to call more than once."""
        await self._pool.aclose()

    @property
    def _closed(self) -> bool:
        return self._pool.closed

    async def __aenter__(self: _Self) -> _Self:
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        await self.aclose()

    async def _request(
        self,
        path: str,
        params: Optional[Mapping[str, str]] = None,
        *,
        method: str = "GET",
        content: Optional[bytes] = None,
        timeout: Optional[float] = None,
    ) -> Mapping[str, Any]:
        """Performs one request and decodes its body. Never retries.

        ``timeout`` replaces the client's deadline for this request.

        Raises:
            FingerlyTimeoutError: If the request exceeds the client timeout.
            FingerlyConnectionError: If the API could not be reached.
            FingerlyAPIError: On any non-2xx response.
        """
        try:
            reply = await self._pool.request(
                method,
                path,
                params=params,
                content=content,
                headers=_JSON_BODY if content is not None else None,
                deadline=timeout,
            )
        except httpx.TimeoutException as error:
            raise FingerlyTimeoutError() from error
        except httpx.HTTPError as error:
            raise FingerlyConnectionError("Could not reach the Fingerly API") from error
        except ResponseTooLargeError as error:
            raise _too_large(error) from None
        return self._interpret(reply)


_warned_about_event_loop = threading.Event()


def _warn_if_on_an_event_loop() -> None:
    """Warns, once per process, when the sync client blocks an event loop.

    Called from ``async def`` code, every read stops the loop, and with it
    every other request on that worker, until the API answers.
    """
    if _warned_about_event_loop.is_set():
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    _warned_about_event_loop.set()
    warnings.warn(
        "Fingerly is blocking a running event loop; use AsyncFingerly in async code",
        RuntimeWarning,
        stacklevel=4,
    )


def _too_large(error: ResponseTooLargeError) -> FingerlyAPIError:
    """The error for a response body over the cap; the body is never read."""
    return FingerlyAPIError(
        f"Fingerly API response is larger than {MAX_RESPONSE_BYTES // 1048576} MiB",
        error.status,
        code="response_too_large",
    )
