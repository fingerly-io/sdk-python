"""The synchronous and asyncio clients, and the event reads they expose."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from types import TracebackType
from typing import Any, Optional, TypeVar, Union

import httpx

from ._config import (
    normalize_api_version,
    normalize_endpoint,
    parse_key,
    positive_seconds,
    regional_origin,
)
from ._errors import FingerlyConnectionError, FingerlyTimeoutError
from ._models import Event, EventPage, parse_event, parse_page
from ._transport import (
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
            secret_key: A server-only key, ``fly_sk_{eu|us}_{environment}_…``.
                Its prefix selects the regional API and the environment read.
            endpoint: Overrides the regional origin, for a local API.
            timeout: Per-request timeout in seconds.
            api_version: API route version; the server must support it.

        Raises:
            TypeError: If any option is invalid. Nothing is sent until then.
        """
        # Validate the key even when an endpoint is given, so a public, proxy
        # or management key can never reach an API that would accept it.
        scope = parse_key(secret_key, "sk")
        origin = (
            regional_origin(scope) if endpoint is None else normalize_endpoint(endpoint)
        )
        self._secret_key = secret_key
        self._base_url = f"{origin}/api/{normalize_api_version(api_version)}"
        self._timeout = positive_seconds(timeout, "timeout")

    def _interpret(self, response: httpx.Response) -> Mapping[str, Any]:
        """Turns a response into a decoded body or the matching error.

        Raises:
            FingerlyAPIError: On any non-2xx response.
        """
        if response.status_code >= 400:
            raise api_error(response.status_code, response.content, self._secret_key)
        return decode_json(response.content)


class Events:
    """Synchronous event reads. Reached as ``fingerly.events``."""

    def __init__(self, client: Fingerly) -> None:
        self._client = client

    def get(self, request_id: str) -> Event:
        """Fetches one event by request id.

        Args:
            request_id: The ``request_id`` returned by identification.

        Raises:
            FingerlyAPIError: ``404 event_not_found`` when there is no such
                event. One is readable as soon as identification answers, so
                this means a request id that was never issued.
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
    ) -> None:
        """See :class:`_BaseFingerly` for the shared arguments.

        Args:
            transport: Replacement httpx transport, for tests or a host with
                its own HTTP stack.
        """
        super().__init__(secret_key, endpoint, timeout, api_version)
        self._http = httpx.Client(
            base_url=self._base_url,
            headers=headers_for(secret_key),
            timeout=self._timeout,
            follow_redirects=False,
            transport=transport,
        )
        self.events = Events(self)

    def close(self) -> None:
        """Closes the pooled connection. Safe to call more than once."""
        self._http.close()

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
        try:
            response = self._http.get(path, params=params)
        except httpx.TimeoutException as error:
            raise FingerlyTimeoutError() from error
        except httpx.HTTPError as error:
            raise FingerlyConnectionError("Could not reach the Fingerly API") from error
        return self._interpret(response)


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
    ) -> None:
        """See :class:`_BaseFingerly` for the shared arguments.

        Args:
            transport: Replacement httpx transport, for tests or a host with
                its own HTTP stack.
        """
        super().__init__(secret_key, endpoint, timeout, api_version)
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers_for(secret_key),
            timeout=self._timeout,
            follow_redirects=False,
            transport=transport,
        )
        self.events = AsyncEvents(self)

    async def aclose(self) -> None:
        """Closes the pooled connection. Safe to call more than once."""
        await self._http.aclose()

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
            response = await self._http.get(path, params=params)
        except httpx.TimeoutException as error:
            raise FingerlyTimeoutError() from error
        except httpx.HTTPError as error:
            raise FingerlyConnectionError("Could not reach the Fingerly API") from error
        return self._interpret(response)
