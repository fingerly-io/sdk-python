"""The synchronous and asyncio clients, and the event reads they expose."""

from __future__ import annotations

import asyncio
import threading
import warnings
from collections.abc import Mapping
from datetime import datetime
from types import TracebackType
from typing import Any, Optional, TypeVar, Union

import httpx

from ._config import (
    DEFAULT_ENDPOINT,
    Secret,
    no_cookies,
    normalize_api_version,
    normalize_endpoint,
    parse_key,
    positive_seconds,
)
from ._errors import FingerlyAPIError, FingerlyConnectionError, FingerlyTimeoutError
from ._http import MAX_RESPONSE_BYTES, AsyncPool, Reply, ResponseTooLargeError, SyncPool
from ._models import Event, EventPage, parse_event, parse_page
from ._transport import (
    KeyAuth,
    api_error,
    decode_json,
    event_path,
    headers_for,
    list_params,
)

DEFAULT_TIMEOUT = 10.0

_Self = TypeVar("_Self", bound="_BaseFingerly")


class _BaseFingerly:
    """Configuration shared by :class:`Fingerly` and :class:`AsyncFingerly`."""

    def __init__(
        self,
        secret_key: str,
        endpoint: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        api_version: str = "v1",
    ) -> None:
        """Validates every option before any client is built.

        Args:
            secret_key: A server-only key, ``fly_sk_{environment}_…``. Its
                prefix names the environment read.
            endpoint: Overrides the Fingerly API origin, for a local API.
            timeout: One deadline, in seconds, over the whole request:
                connecting, sending, the response headers and the body.
            api_version: API route version; the server must support it.

        Raises:
            TypeError: If any option is invalid. Nothing is sent until then.
        """
        # Validate the key even when an endpoint is given, so a public, proxy
        # or management key can never reach an API that would accept it.
        parse_key(secret_key, "sk")
        origin = DEFAULT_ENDPOINT if endpoint is None else normalize_endpoint(endpoint)
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

    def list(
        self,
        from_: Union[datetime, str, None] = None,
        to: Union[datetime, str, None] = None,
        page: int = 1,
        limit: int = 10,
        visitor: Optional[str] = None,
        level: Optional[str] = None,
    ) -> EventPage:
        """Lists events within the retention window, newest first.

        Args:
            from_: Start of the window. Defaults to 24 hours ago.
            to: End of the window. Defaults to now.
            page: 1-based page number.
            limit: Rows per page, at most 200.
            visitor: Restrict to one exact visitor id.
            level: Restrict to ``low``, ``medium`` or ``high``.

        Raises:
            TypeError: If a bound, page or limit is unusable.
            FingerlyAPIError: On any non-2xx response.
        """
        params = list_params(from_, to, page, limit, visitor, level)
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

    async def list(
        self,
        from_: Union[datetime, str, None] = None,
        to: Union[datetime, str, None] = None,
        page: int = 1,
        limit: int = 10,
        visitor: Optional[str] = None,
        level: Optional[str] = None,
    ) -> EventPage:
        """Lists events within the retention window, newest first.

        See :meth:`Events.list`; this coroutine takes the same arguments.
        """
        params = list_params(from_, to, page, limit, visitor, level)
        return parse_page(await self._client._request("/events", params))


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
    ) -> None:
        """See :class:`_BaseFingerly` for the shared arguments.

        Args:
            transport: Replacement httpx transport, for tests or a host with
                its own HTTP stack. It is used as given, as one pool.
            limits: Connections this client may hold across its pools. The
                default lets 256 concurrent reads reuse connections.
        """
        super().__init__(secret_key, endpoint, timeout, api_version)

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

    def close(self) -> None:
        """Closes the pooled connections. Safe to call more than once."""
        self._pool.close()

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
        self, path: str, params: Optional[Mapping[str, str]] = None
    ) -> Mapping[str, Any]:
        """Performs one GET and decodes its body. Never retries.

        Raises:
            FingerlyTimeoutError: If the request exceeds the client timeout.
            FingerlyConnectionError: If the API could not be reached.
            FingerlyAPIError: On any non-2xx response.
        """
        _warn_if_on_an_event_loop()
        try:
            reply = self._pool.request("GET", path, params=params)
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
    ) -> None:
        """See :class:`_BaseFingerly` for the shared arguments.

        Args:
            transport: Replacement httpx transport, for tests or a host with
                its own HTTP stack. It is used as given, as one pool.
            limits: Connections this client may hold across its pools. The
                default lets 256 concurrent reads reuse connections.
        """
        super().__init__(secret_key, endpoint, timeout, api_version)

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

    async def aclose(self) -> None:
        """Closes the pooled connections. Safe to call more than once."""
        await self._pool.aclose()

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
        self, path: str, params: Optional[Mapping[str, str]] = None
    ) -> Mapping[str, Any]:
        """Performs one GET and decodes its body. Never retries.

        Raises:
            FingerlyTimeoutError: If the request exceeds the client timeout.
            FingerlyConnectionError: If the API could not be reached.
            FingerlyAPIError: On any non-2xx response.
        """
        try:
            reply = await self._pool.request("GET", path, params=params)
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
