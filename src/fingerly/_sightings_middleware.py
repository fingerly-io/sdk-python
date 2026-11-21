"""ASGI and WSGI middleware that report each response after it is sent.

The response is passed through untouched. Recording happens once the last body
chunk has gone out, in memory only; sending the report is the flusher's job,
on its own thread or task, so no request ever waits on Fingerly.
"""

from __future__ import annotations

from collections.abc import Awaitable, Iterable, Iterator, MutableMapping
from typing import TYPE_CHECKING, Any, Callable, Optional

from ._asgi import _request_from as _asgi_request
from ._wsgi import _request_from as _wsgi_request

if TYPE_CHECKING:
    from ._sightings import _BaseSightings

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
Environ = MutableMapping[str, Any]
WSGIApp = Callable[[Environ, Callable[..., Any]], Iterable[bytes]]


class SightingsASGI:
    """An ASGI application that reports the responses of the one it wraps.

    Built by :meth:`AgentSightings.asgi` or :meth:`AsyncAgentSightings.asgi`.
    Lifespan and websocket connections pass straight through.
    """

    def __init__(self, app: ASGIApp, sightings: _BaseSightings) -> None:
        self._app = app
        self._sightings = sightings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        sightings = self._sightings
        content_type: Optional[str] = None
        started = False
        reported = False

        async def watching(message: Message) -> None:
            nonlocal content_type, started, reported
            await send(message)
            kind = message.get("type")
            if kind == "http.response.start":
                started = True
                content_type = _content_type(message.get("headers", ()))
            elif (
                kind == "http.response.body"
                and started
                and not reported
                and not message.get("more_body", False)
            ):
                reported = True
                try:
                    sightings._report(_asgi_request(scope), content_type)
                except Exception:
                    sightings._log(
                        "report", "Agent sightings could not record a request"
                    )

        await self._app(scope, receive, watching)


def _content_type(headers: Iterable[tuple[bytes, bytes]]) -> Optional[str]:
    for name, value in headers:
        if bytes(name).lower() == b"content-type":
            return bytes(value).decode("latin-1")
    return None


class SightingsWSGI:
    """A WSGI application that reports the responses of the one it wraps.

    Built by :meth:`AgentSightings.wsgi`. The request is recorded when the
    server closes the response, once its body has been sent.
    """

    def __init__(self, app: WSGIApp, sightings: _BaseSightings) -> None:
        self._app = app
        self._sightings = sightings

    def __call__(
        self, environ: Environ, start_response: Callable[..., Any]
    ) -> Iterable[bytes]:
        seen: list[Optional[str]] = []

        def watching(
            status: str, headers: list[tuple[str, str]], exc_info: Any = None
        ) -> Any:
            seen[:] = [
                next(
                    (
                        value
                        for name, value in headers
                        if name.lower() == "content-type"
                    ),
                    None,
                )
            ]
            if exc_info is None:
                return start_response(status, headers)
            return start_response(status, headers, exc_info)

        def report() -> None:
            if not seen:
                return
            try:
                self._sightings._report(_wsgi_request(environ), seen[0])
            except Exception:
                self._sightings._log(
                    "report", "Agent sightings could not record a request"
                )

        return _Closing(self._app(environ, watching), report)


class _Closing:
    """The wrapped response body, reporting once the server closes it."""

    def __init__(self, body: Iterable[bytes], after: Callable[[], None]) -> None:
        self._body = body
        self._after = after
        self._done = False

    def __iter__(self) -> Iterator[bytes]:
        return iter(self._body)

    def close(self) -> None:
        try:
            close = getattr(self._body, "close", None)
            if close is not None:
                close()
        finally:
            if not self._done:
                self._done = True
                self._after()
