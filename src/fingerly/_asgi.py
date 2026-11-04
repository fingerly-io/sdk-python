"""The ASGI adapter: read a request, write a response.

Every decision belongs to :class:`~fingerly._proxy.FingerlyProxy`. This module
only translates between ASGI messages and the proxy's own request and response
types, so the two standards cannot drift apart.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, MutableMapping
from typing import TYPE_CHECKING, Any, Callable, Optional

from ._proxy import BodyTooLargeError, Headers, ProxyRequest, ProxyResponse

if TYPE_CHECKING:
    from ._proxy import FingerlyProxy

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


class ASGIProxy:
    """ASGI application serving the browser SDK's same-origin requests.

    Reached as ``proxy.asgi``. Route the dashboard-issued path to it under
    FastAPI, Starlette, Django 3+, Quart, Litestar or any other ASGI
    framework::

        app.add_route("/k7x2qm4a", proxy.asgi)
    """

    def __init__(self, proxy: FingerlyProxy) -> None:
        self._proxy = proxy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Serves one ASGI connection."""
        kind = scope.get("type")
        if kind == "lifespan":
            await _acknowledge_lifespan(receive, send)
            return
        if kind != "http":
            # A websocket cannot be a browser SDK call; refuse without opening it.
            if kind == "websocket":
                await send({"type": "websocket.close", "code": 1000})
            return

        request = _request_from(scope)
        screening = self._proxy.screen(request)
        if screening.refusal is not None:
            await _send(send, screening.refusal)
            return

        try:
            body = await _read_body(receive, self._proxy.max_body_bytes)
        except BodyTooLargeError:
            await _send(send, self._proxy.too_large())
            return
        if body is None:
            return  # The client went away; there is nobody to answer.

        response = await _forward_unless_gone(
            self._proxy.aforward(screening, request, body), receive
        )
        if response is not None:
            await _send(send, response)


async def _forward_unless_gone(
    forwarding: Awaitable[ProxyResponse], receive: Receive
) -> Optional[ProxyResponse]:
    """Forwards, but gives up the moment the visitor disconnects.

    Without this, a visitor who left would still hold an upstream connection
    until the API answered, so connections opened and dropped in a loop would
    pile up upstream work nobody reads.

    Returns:
        The response, or None when the visitor went away first.
    """
    forward = asyncio.ensure_future(forwarding)
    gone = asyncio.ensure_future(_disconnected(receive))
    try:
        await asyncio.wait({forward, gone}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        if not forward.done() and not gone.done():
            # Cancelled from outside: take both down with us.
            forward.cancel()
        gone.cancel()
        await asyncio.gather(gone, return_exceptions=True)
    if forward.done():
        return forward.result()
    forward.cancel()
    await asyncio.gather(forward, return_exceptions=True)
    return None


async def _disconnected(receive: Receive) -> None:
    """Returns when the server reports the client gone.

    Once the body has been read, ``receive`` blocks until the client
    disconnects. A server that answers it with anything else is not reporting
    a disconnect, so this then waits until cancelled.
    """
    message = await receive()
    if message.get("type") != "http.disconnect":
        await asyncio.Event().wait()


def _request_from(scope: Scope) -> ProxyRequest:
    """Builds the neutral request from an ASGI scope."""
    client = scope.get("client")
    return ProxyRequest(
        method=scope.get("method", ""),
        path=_app_path(scope),
        headers=Headers(
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in scope.get("headers", ())
        ),
        peer_host=client[0] if client else None,
        mount=str(scope.get("root_path", "")),
    )


def _app_path(scope: Scope) -> str:
    """Recovers the request path as the mounted application sees it.

    ASGI servers disagree about ``path`` under a mount. Starlette 0.47 and
    newer leave it whole and report the prefix separately in ``root_path``,
    while older versions and some routers strip the prefix off it. Both are
    permitted, so detect which one this is instead of assuming, and answer
    with the application-relative path either way.

    Keeping the mount in would break a deployment under a sub-URI, where
    ``root_path`` also carries a prefix that the configured ``path`` knows
    nothing about. This is the same rule Rack's ``PATH_INFO`` and ASP.NET
    Core's ``Request.Path`` already follow.
    """
    path = str(scope.get("path", ""))
    root_path = str(scope.get("root_path", ""))
    if not root_path:
        return path
    if path == root_path:
        return "/"
    return path[len(root_path) :] if path.startswith(root_path + "/") else path


async def _read_body(receive: Receive, max_bytes: int) -> Optional[bytes]:
    """Reads the request body without buffering more than the limit.

    Returns:
        The bytes, or None when the client disconnected first.

    Raises:
        BodyTooLargeError: As soon as the limit is passed, before the rest arrives.
    """
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > max_bytes:
            raise BodyTooLargeError
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


async def _send(send: Send, response: ProxyResponse) -> None:
    """Writes one response as the two ASGI messages it is made of."""
    await send(
        {
            "type": "http.response.start",
            "status": response.status,
            "headers": [
                (name.encode("latin-1"), value.encode("latin-1"))
                for name, value in response.headers
            ],
        }
    )
    await send({"type": "http.response.body", "body": response.body})


async def _acknowledge_lifespan(receive: Receive, send: Send) -> None:
    """Answers startup and shutdown, so the app is safe to mount as a root."""
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await send({"type": "lifespan.shutdown.complete"})
            return
