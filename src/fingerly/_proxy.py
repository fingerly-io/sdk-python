"""The same-origin proxy: everything both server standards share.

Content blockers refuse browser requests to third-party APIs, and a refused
identification is a visitor never identified. Mounting this on a path of your
own site makes those requests first-party. The proxy key is what lets the hop
declare the visitor's real address, origin and user agent; a public key alone
never can, so nobody can spoof them.

The decisions live here. ``_asgi`` and ``_wsgi`` only read a request and write
a response, so both standards refuse and forward identically.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Callable, NamedTuple, Optional

import httpx

if TYPE_CHECKING:  # Imported for typing only; the adapters import this module.
    from ._asgi import ASGIProxy
    from ._wsgi import WSGIProxy

from ._config import (
    DEFAULT_ENDPOINT,
    KeyScope,
    normalize_api_version,
    normalize_endpoint,
    parse_key,
    positive_int,
    positive_seconds,
)

DEFAULT_PREFIX = "/api/fingerly"
DEFAULT_MAX_BODY_BYTES = 1_048_576
DEFAULT_TIMEOUT = 5.0

#: Statuses that must not carry a body.
BODILESS_STATUSES = frozenset({204, 205, 304})

#: Upstream headers that describe that connection rather than our response.
#: httpx has already decoded and framed the body, so replaying them would
#: misdescribe the bytes we hand back.
CONNECTION_HEADERS = frozenset(
    {
        "connection",
        "content-encoding",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

_IDENTIFY = "/identify"
_SUPPLEMENT_PREFIX = "/events/"
_SUPPLEMENT_SUFFIX = "/supplement"


class Headers(Mapping[str, str]):
    """Case-insensitive, read-only view of one request's headers.

    Repeated headers are joined with ``", "``, as HTTP defines.
    """

    def __init__(self, items: Iterable[tuple[str, str]]) -> None:
        merged: dict[str, str] = {}
        for name, value in items:
            key = name.lower()
            merged[key] = f"{merged[key]}, {value}" if key in merged else value
        self._items = merged

    def __getitem__(self, key: str) -> str:
        return self._items[key.lower()]

    def __iter__(self) -> Iterable[str]:  # type: ignore[override]
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"Headers({sorted(self._items)})"


@dataclass(frozen=True)
class ProxyRequest:
    """What ``client_ip`` is given, under either server standard.

    Attributes:
        method: The HTTP method.
        path: The request path as the mounted application sees it, with
            anything the server reported separately as a mount prefix removed.
        headers: Case-insensitive request headers.
        peer_host: The socket peer's address, when the server reports one.
            This is your load balancer, not the visitor, whenever one is in
            front of you.
    """

    method: str
    path: str
    headers: Headers
    peer_host: Optional[str] = None


@dataclass(frozen=True)
class ProxyResponse:
    """A response for an adapter to write out.

    Attributes:
        status: The HTTP status code.
        headers: Response headers, in order.
        body: The body bytes, empty for a bodiless status.
    """

    status: int
    headers: Sequence[tuple[str, str]]
    body: bytes

    @property
    def reason(self) -> str:
        """The reason phrase WSGI's status line needs."""
        try:
            return HTTPStatus(self.status).phrase
        except ValueError:
            return ""


class Screening(NamedTuple):
    """The outcome of every check that runs before the body is read.

    Attributes:
        refusal: The response to send, when the request is refused.
        upstream_path: The path to forward to, when it is not.
        api_key: The key to present upstream, when it is not.
    """

    refusal: Optional[ProxyResponse]
    upstream_path: str = ""
    api_key: str = ""


class BodyTooLargeError(Exception):
    """Raised by an adapter's body reader when the limit is exceeded."""


class FingerlyProxy:
    """Same-origin proxy for the browser SDK's identify and supplement calls.

    Mount :attr:`asgi` under FastAPI, Starlette, Django 3+ or Quart, and
    :attr:`wsgi` under Flask, Django's sync stack or any other WSGI app. Both
    serve the same configuration, so one instance covers a project running
    both.

    Only those two routes are forwarded, never event reads: reading events
    needs a secret key and must stay unreachable from a browser. Customer
    cookies and authorization headers are never passed on.

    Example:
        >>> proxy = FingerlyProxy(
        ...     proxy_key=os.environ["FINGERLY_PROXY_KEY"],
        ...     prefix="/metrics",
        ...     client_ip=lambda request: request.headers["cf-connecting-ip"],
        ... )
        >>> app.mount("/metrics", proxy.asgi)
    """

    def __init__(
        self,
        client_ip: Callable[[ProxyRequest], str],
        proxy_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        prefix: str = DEFAULT_PREFIX,
        api_version: str = "v1",
        upstream: Optional[str] = None,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Optional[httpx.BaseTransport] = None,
        async_transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        """Validates every option before either handler exists.

        Args:
            client_ip: Resolves the visitor's address from infrastructure your
                app trusts. Never read the left-most ``X-Forwarded-For`` value:
                the visitor writes it. Called under both standards, so it must
                be synchronous.
            proxy_key: A proxy key, ``fly_px_…``, held only on your server.
            secret_key: Deprecated alternative to ``proxy_key``.
            prefix: The path the proxy answers under, within the
                application. It excludes anything a sub-URI deployment adds,
                and is accepted as either present or already stripped.
            api_version: Version accepted locally and forwarded upstream.
            upstream: Overrides the API origin implied by the key.
            max_body_bytes: Larger request bodies are refused with 413.
            timeout: How long to wait for Fingerly, in seconds.
            transport: Replacement httpx transport for the WSGI handler.
            async_transport: Replacement httpx transport for the ASGI handler.

        Raises:
            TypeError: If a credential, route, limit or callback is invalid.
        """
        if not proxy_key and not secret_key:
            raise TypeError("A Fingerly proxy key is required")
        if proxy_key and secret_key:
            raise TypeError("Pass proxy_key or deprecated secret_key, not both")
        if not callable(client_ip):
            raise TypeError("client_ip is required")

        self._uses_proxy_key = bool(proxy_key)
        self._key: str = proxy_key or secret_key or ""
        self._scope: KeyScope = parse_key(
            self._key, "px" if self._uses_proxy_key else "sk"
        )
        self._upstream = normalize_endpoint(
            upstream if upstream is not None else DEFAULT_ENDPOINT
        )
        self._api_version = normalize_api_version(api_version)
        self._prefix = _normalize_prefix(prefix)
        self._max_body_bytes = positive_int(max_body_bytes, "max_body_bytes")
        self._timeout = positive_seconds(timeout, "timeout")
        self._client_ip = client_ip
        self._transport = transport
        self._async_transport = async_transport
        self._http: Optional[httpx.Client] = None
        self._async_http: Optional[httpx.AsyncClient] = None

    @property
    def asgi(self) -> ASGIProxy:
        """The ASGI application. Mount it under an async framework."""
        from ._asgi import ASGIProxy

        return ASGIProxy(self)

    @property
    def wsgi(self) -> WSGIProxy:
        """The WSGI application. Mount it under a sync framework."""
        from ._wsgi import WSGIProxy

        return WSGIProxy(self)

    @property
    def max_body_bytes(self) -> int:
        """The request body limit the adapters enforce while reading."""
        return self._max_body_bytes

    def screen(self, request: ProxyRequest) -> Screening:
        """Runs every check that can be made before reading the body.

        Args:
            request: The incoming request, as the adapter read it.

        Returns:
            Either a refusal, or the upstream path and the key to present.
        """
        if request.method != "POST":
            return Screening(_refuse(405, "Method Not Allowed", (("allow", "POST"),)))

        upstream_path = self._route_for(request.path)
        if upstream_path is None:
            return Screening(_refuse(404, "Not Found"))

        api_key = self._upstream_key_for(request.headers.get("x-api-key"))
        if api_key is None:
            return Screening(_refuse(401, "Unauthorized"))

        # Refuse on the declared size first; the adapter enforces the real one.
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_body_bytes:
            return Screening(_refuse(413, "Payload Too Large"))

        return Screening(None, upstream_path, api_key)

    def too_large(self) -> ProxyResponse:
        """The response for a body that exceeded the limit while streaming."""
        return _refuse(413, "Payload Too Large")

    def forward(
        self, screening: Screening, request: ProxyRequest, body: bytes
    ) -> ProxyResponse:
        """Forwards a screened request, synchronously.

        Raises:
            TypeError: If ``client_ip`` returns a value unusable as a header.
        """
        response = self._client().post(
            self._upstream + screening.upstream_path,
            headers=self.upstream_headers(request, screening.api_key),
            content=body,
        )
        return _relay(response)

    async def aforward(
        self, screening: Screening, request: ProxyRequest, body: bytes
    ) -> ProxyResponse:
        """Forwards a screened request on the running event loop."""
        response = await self._async_client().post(
            self._upstream + screening.upstream_path,
            headers=self.upstream_headers(request, screening.api_key),
            content=body,
        )
        return _relay(response)

    def upstream_headers(self, request: ProxyRequest, api_key: str) -> dict[str, str]:
        """Builds the upstream headers.

        Nothing is copied wholesale: only the body's content type, the visitor
        metadata Fingerly needs, and an idempotency key when the SDK sent one.

        Raises:
            TypeError: If ``client_ip`` returns a value unusable as a header.
        """
        client_ip = self._client_ip(request)
        if not isinstance(client_ip, str) or not _is_header_safe(client_ip):
            raise TypeError("client_ip must resolve to a plain address")

        headers = {
            "content-type": request.headers.get("content-type", "application/json"),
            "x-api-key": api_key,
            "x-fingerly-client-ip": client_ip,
            "x-fingerly-origin": request.headers.get("origin", ""),
            "x-fingerly-user-agent": request.headers.get("user-agent", ""),
        }
        if self._uses_proxy_key:
            headers["x-fingerly-proxy-key"] = self._key
        idempotency_key = request.headers.get("idempotency-key")
        if idempotency_key:
            headers["idempotency-key"] = idempotency_key
        return headers

    def close(self) -> None:
        """Closes the WSGI handler's pooled connection."""
        if self._http is not None:
            self._http.close()
            self._http = None

    async def aclose(self) -> None:
        """Closes the ASGI handler's pooled connection."""
        if self._async_http is not None:
            await self._async_http.aclose()
            self._async_http = None

    def _route_for(self, path: str) -> Optional[str]:
        """Maps a local path to its upstream path.

        The prefix is tolerated as either present or already stripped, so the
        handler works whether the server reported the whole path or only what
        followed the mount. Both adapters hand over the application-relative
        path, and which of the two shapes that is depends on how the
        application mounted this.

        Returns:
            The upstream path, or None when the route is not proxyable.
        """
        versioned = f"/api/{self._api_version}"
        mount = self._prefix + versioned
        if path.startswith(mount + "/"):
            resource = path[len(mount) :]
        elif path.startswith(versioned + "/"):
            resource = path[len(versioned) :]
        else:
            return None
        if resource != _IDENTIFY and not _is_supplement(resource):
            return None
        return versioned + resource

    def _upstream_key_for(self, presented: Optional[str]) -> Optional[str]:
        """Decides which key to present upstream.

        With a proxy key the browser must supply a public key for the same
        environment, which the proxy forwards alongside its own. The
        deprecated secret-key mode authenticates on its own.

        Returns:
            The key to forward, or None when the caller is unauthorised.
        """
        if not self._uses_proxy_key:
            return self._key
        try:
            browser = parse_key(presented or "", "pk")
        except TypeError:
            return None
        return presented if browser.environment == self._scope.environment else None

    def _client(self) -> httpx.Client:
        """Builds the synchronous upstream client on first use."""
        if self._http is None:
            self._http = httpx.Client(
                timeout=self._timeout,
                follow_redirects=False,
                transport=self._transport,
            )
        return self._http

    def _async_client(self) -> httpx.AsyncClient:
        """Builds the asyncio upstream client on the loop that first uses it."""
        if self._async_http is None:
            self._async_http = httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=False,
                transport=self._async_transport,
            )
        return self._async_http


def _is_supplement(resource: str) -> bool:
    """True for ``/events/{request_id}/supplement`` with one id segment."""
    if not resource.startswith(_SUPPLEMENT_PREFIX):
        return False
    if not resource.endswith(_SUPPLEMENT_SUFFIX):
        return False
    request_id = resource[len(_SUPPLEMENT_PREFIX) : -len(_SUPPLEMENT_SUFFIX)]
    return bool(request_id) and "/" not in request_id


def _normalize_prefix(value: str) -> str:
    """Validates the local mount path and drops trailing slashes.

    Raises:
        TypeError: If the prefix is not an absolute URL path.
    """
    if not isinstance(value, str):
        raise TypeError("prefix must be an absolute URL path")
    prefix = value.rstrip("/")
    if not prefix.startswith("/") or "?" in prefix or "#" in prefix:
        raise TypeError("prefix must be an absolute URL path")
    return prefix


def _is_header_safe(value: str) -> bool:
    """True when a value is printable ASCII, so it cannot inject a header."""
    return all("\x20" <= character <= "\x7e" for character in value)


def _refuse(
    status: int, message: str, extra: Sequence[tuple[str, str]] = ()
) -> ProxyResponse:
    """Builds a plain-text refusal that never reaches Fingerly."""
    body = message.encode("ascii")
    headers = [
        ("content-type", "text/plain; charset=utf-8"),
        ("content-length", str(len(body))),
        ("cache-control", "no-store"),
    ]
    headers.extend(extra)
    return ProxyResponse(status, headers, body)


def _relay(response: httpx.Response) -> ProxyResponse:
    """Returns the upstream response to the browser.

    Connection-scoped headers are dropped because httpx has already decoded
    the body, and the result is marked uncacheable.
    """
    body = b"" if response.status_code in BODILESS_STATUSES else response.content
    headers = [
        (name, value)
        for name, value in response.headers.multi_items()
        if name.lower() not in CONNECTION_HEADERS and name.lower() != "cache-control"
    ]
    headers.append(("cache-control", "no-store"))
    if response.status_code not in BODILESS_STATUSES:
        headers.append(("content-length", str(len(body))))
    return ProxyResponse(response.status_code, headers, body)
