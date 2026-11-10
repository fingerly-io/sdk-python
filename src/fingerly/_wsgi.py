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

        try:
            body = _read_body(environ, self._proxy.max_body_bytes)
        except Exception:
            # A visitor can send broken framing at will. Servers report it with
            # types of their own, none shared, and uncaught each one is an
            # error-level traceback in the server's log.
            return _write(start_response, self._proxy.malformed())
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
        raw_path=_raw_path(environ),
    )


def _raw_path(environ: Environ) -> Optional[str]:
    """The path as the client sent it, where the server reports it.

    WSGI does not define one, but most servers pass the request target on as
    ``RAW_URI`` or ``REQUEST_URI``.
    """
    for key in ("RAW_URI", "REQUEST_URI"):
        value = environ.get(key)
        if isinstance(value, str) and value:
            return value.split("?", 1)[0]
    return None


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

    With a declared length, exactly that many bytes are read and never one
    more: PEP 3333 forbids reading past ``CONTENT_LENGTH``, and servers that
    hand over the raw socket (Werkzeug's ``flask run``, wsgiref) block on the
    extra byte until the client gives up. Without one there is a body only when
    it is chunked, and then the server has terminated the stream, so one byte
    past the limit is enough to refuse. Anything else has no body, and reading
    that raw socket would wait for bytes that are never coming.

    Returns:
        The bytes, or None when the limit was exceeded.
    """
    stream = environ.get("wsgi.input")
    if stream is None:
        return b""
    declared = environ.get("CONTENT_LENGTH", "")
    if declared.isdecimal():
        length = int(declared)
        if length > max_bytes:
            return None
        return stream.read(length) if length else b""
    if "HTTP_TRANSFER_ENCODING" not in environ and not environ.get(
        "wsgi.input_terminated"
    ):
        return b""
    body: bytes = stream.read(max_bytes + 1)
    return None if len(body) > max_bytes else body


def _write(start_response: StartResponse, response: ProxyResponse) -> Iterable[bytes]:
    """Starts the response and returns its single body chunk."""
    status = f"{response.status} {response.reason}".strip()
    start_response(status, list(response.headers))
    return [response.body]
