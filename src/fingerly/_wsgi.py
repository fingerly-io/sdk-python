"""The WSGI adapter: read a request, write a response.

Every decision belongs to :class:`~fingerly._proxy.FingerlyProxy`. This module
only translates between the WSGI environ and the proxy's own request and
response types, so the two standards cannot drift apart.
"""

from __future__ import annotations

from collections.abc import Iterable, MutableMapping
from typing import TYPE_CHECKING, Any, Callable, Optional

from ._proxy import Headers, ProxyRequest, ProxyResponse

if TYPE_CHECKING:
    from ._proxy import FingerlyProxy

Environ = MutableMapping[str, Any]
StartResponse = Callable[[str, list[tuple[str, str]]], Any]


class WSGIProxy:
    """WSGI application serving the browser SDK's same-origin requests.

    Reached as ``proxy.wsgi``. Mount it at the dashboard-issued path under
    Flask, Django's sync stack, Pyramid or any other WSGI framework::

        from werkzeug.middleware.dispatcher import DispatcherMiddleware

        app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {"/k7x2qm4a": proxy.wsgi})
    """

    def __init__(self, proxy: FingerlyProxy) -> None:
        self._proxy = proxy

    def __call__(
        self, environ: Environ, start_response: StartResponse
    ) -> Iterable[bytes]:
        """Serves one WSGI request."""
        request = _request_from(environ)
        screening = self._proxy.screen(request)
        if screening.refusal is not None:
            return _write(start_response, screening.refusal)

        body = _read_body(environ, self._proxy.max_body_bytes)
        if body is None:
            return _write(start_response, self._proxy.too_large())

        response = self._proxy.forward(screening, request, body)
        return _write(start_response, response)


def _request_from(environ: Environ) -> ProxyRequest:
    """Builds the neutral request from a WSGI environ.

    ``PATH_INFO`` alone, never ``SCRIPT_NAME + PATH_INFO``. WSGI puts the
    mount in ``SCRIPT_NAME``, so ``PATH_INFO`` is already what the mounted
    application sees, and a deployment under a sub-URI puts its own prefix
    there too. Joining them would mean a Flask app served from ``/shop`` never
    matched a proxy configured for ``/k7x2qm4a``. ``SCRIPT_NAME`` is still
    passed on as the mount, for a proxy mounted at its own path.
    """
    return ProxyRequest(
        method=environ.get("REQUEST_METHOD", ""),
        path=environ.get("PATH_INFO", ""),
        headers=_headers_from(environ),
        peer_host=environ.get("REMOTE_ADDR"),
        mount=environ.get("SCRIPT_NAME", ""),
    )


def _headers_from(environ: Environ) -> Headers:
    """Recovers request headers from the environ's mangled keys."""
    items = [
        (key[5:].replace("_", "-"), value)
        for key, value in environ.items()
        if key.startswith("HTTP_") and isinstance(value, str)
    ]
    for key, name in (
        ("CONTENT_TYPE", "content-type"),
        ("CONTENT_LENGTH", "content-length"),
    ):
        value = environ.get(key)
        if value:
            items.append((name, value))
    return Headers(items)


def _read_body(environ: Environ, max_bytes: int) -> Optional[bytes]:
    """Reads the request body without buffering more than the limit.

    One byte past the limit is enough to refuse, so at most ``max_bytes + 1``
    is ever read, bounded further by the declared length when there is one.

    Returns:
        The bytes, or None when the limit was exceeded.
    """
    stream = environ.get("wsgi.input")
    if stream is None:
        return b""
    declared = environ.get("CONTENT_LENGTH", "")
    limit = min(int(declared), max_bytes) if declared.isdigit() else max_bytes
    body: bytes = stream.read(limit + 1)
    return None if len(body) > max_bytes else body


def _write(start_response: StartResponse, response: ProxyResponse) -> Iterable[bytes]:
    """Starts the response and returns its single body chunk."""
    status = f"{response.status} {response.reason}".strip()
    start_response(status, list(response.headers))
    return [response.body]
