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

import ipaddress
import logging
import threading
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Callable, NamedTuple, Optional

import httpx

from ._http import (
    MAX_RESPONSE_BYTES,
    AsyncPool,
    Reply,
    ResponseTooLargeError,
    SyncPool,
)
from ._transport import USER_AGENT
from ._version import __version__

if TYPE_CHECKING:  # Imported for typing only; the adapters import this module.
    from ._asgi import ASGIProxy
    from ._wsgi import WSGIProxy

from ._config import (
    DEFAULT_ENDPOINT,
    KeyScope,
    Secret,
    no_cookies,
    normalize_api_version,
    normalize_endpoint,
    parse_key,
    positive_int,
    positive_seconds,
)

#: Where the proxy reports what it could not forward: one line per failure,
#: never a stack trace. Attach a handler or raise the level as you like.
logger = logging.getLogger("fingerly.proxy")

#: The one-line answer, and log message, for a misconfigured ``client_ip``.
NO_CLIENT_IP = "The client IP callback returned no valid address"

DEFAULT_MAX_BODY_BYTES = 1_048_576
DEFAULT_TIMEOUT = 5.0

#: What this proxy reports itself as upstream, shown per proxy in the
#: dashboard.
PROXY_VERSION = f"python/{__version__}"

#: Statuses that must not carry a body.
BODILESS_STATUSES = frozenset({204, 205, 304})

#: The response headers relayed to the browser, and nothing else. A content
#: blocker can match a response header by name, so an allowlist is what keeps
#: anything naming Fingerly off the page, whatever the API adds in future.
RELAYED_HEADERS = (
    "content-type",
    "x-request-id",
    "ratelimit-limit",
    "ratelimit-remaining",
    "retry-after",
)


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
        mount: What the server reported separately as the mount, ``root_path``
            under ASGI and ``SCRIPT_NAME`` under WSGI, including any prefix a
            sub-URI deployment adds.
        raw_path: The whole path as the client sent it, still percent-encoded
            and without the query, when the server reports it.
    """

    method: str
    path: str
    headers: Headers
    peer_host: Optional[str] = None
    mount: str = ""
    raw_path: Optional[str] = None


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
        api_key: The key to present upstream, when it is not.
        client_ip: The visitor address ``client_ip`` resolved, when it is not.
    """

    refusal: Optional[ProxyResponse]
    api_key: str = ""
    client_ip: str = ""


class BodyTooLargeError(Exception):
    """Raised by an adapter's body reader when the limit is exceeded."""


class FingerlyProxy:
    """Same-origin proxy for the browser SDK.

    Mount :attr:`asgi` under FastAPI, Starlette, Django 3+ or Quart, and
    :attr:`wsgi` under Flask, Django's sync stack or any other WSGI app. Both
    serve the same configuration, so one instance covers a project running
    both.

    The browser SDK posts both of its calls to one path on your site, and
    this forwards each to Fingerly's one ingest URL, never anywhere else and
    never to event reads: reading events needs a secret key and must stay
    unreachable from a browser. Customer cookies and authorization headers are
    never passed on, and nothing that names Fingerly is relayed back.

    Example:
        >>> proxy = FingerlyProxy(
        ...     proxy_key=os.environ["FINGERLY_PROXY_KEY"],
        ...     path="/k7x2qm4a",
        ...     client_ip=lambda request: request.headers["cf-connecting-ip"],
        ... )
        >>> app.add_route("/k7x2qm4a", proxy.asgi)
    """

    def __init__(
        self,
        client_ip: Callable[[ProxyRequest], str],
        proxy_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        path: Optional[str] = None,
        api_version: str = "v1",
        upstream: Optional[str] = None,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        timeout: float = DEFAULT_TIMEOUT,
        transport: Optional[httpx.BaseTransport] = None,
        async_transport: Optional[httpx.AsyncBaseTransport] = None,
        limits: Optional[httpx.Limits] = None,
    ) -> None:
        """Validates every option before either handler exists.

        Args:
            client_ip: Resolves the visitor's address from infrastructure your
                app trusts. Never read the left-most ``X-Forwarded-For`` value:
                the visitor writes it. Called under both standards, so it must
                be synchronous.
            proxy_key: A proxy key, ``fly_px_…``, held only on your server.
            secret_key: Deprecated alternative to ``proxy_key``.
            path: The path the dashboard issued for this proxy, such as
                ``/k7x2qm4a``, within the application. When set, only that
                path is answered, exactly, and anything else gets 404. It
                excludes anything a sub-URI deployment adds, and is accepted
                as either present or already stripped by the mount. Omit it
                when the framework already routes only that path here.
            api_version: Version of the upstream ingest URL.
            upstream: Overrides the API origin implied by the key.
            max_body_bytes: Larger request bodies are refused with 413.
            timeout: One deadline, in seconds, over the whole upstream
                exchange: connecting, sending, the response headers and the
                body. A trickling upstream cannot extend it.
            transport: Replacement httpx transport for the WSGI handler, used
                as given, as one pool.
            async_transport: Replacement httpx transport for the ASGI handler.
            limits: Upstream connections each handler may hold. The default
                lets 256 concurrent requests per process reuse connections.

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
        raw_key: str = proxy_key or secret_key or ""
        self._scope: KeyScope = parse_key(
            raw_key, "px" if self._uses_proxy_key else "sk"
        )
        self._key = Secret(raw_key)
        self._upstream_url = (
            normalize_endpoint(upstream if upstream is not None else DEFAULT_ENDPOINT)
            + f"/api/{normalize_api_version(api_version)}/ingest"
        )
        self._path = None if path is None else _normalize_path(path)
        self._max_body_bytes = positive_int(max_body_bytes, "max_body_bytes")
        self._timeout = positive_seconds(timeout, "timeout")
        self._client_ip = client_ip
        self._transport = transport
        self._async_transport = async_transport
        self._limits = limits
        self._http: Optional[SyncPool] = None
        self._async_http: Optional[AsyncPool] = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        kind = "proxy_key" if self._uses_proxy_key else "secret_key"
        return (
            f"FingerlyProxy(path={self._path!r}, upstream={self._upstream_url!r}, "
            f"{kind}={self._key!r})"
        )

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
            Either a refusal, or the key to present upstream.
        """
        if not self._answers(request):
            return Screening(_refuse(404, "Not Found"))

        if request.method != "POST":
            return Screening(_refuse(405, "Method Not Allowed", (("allow", "POST"),)))

        api_key = self._upstream_key_for(request.headers.get("x-api-key"))
        if api_key is None:
            return Screening(_refuse(401, "Unauthorized"))

        # Refuse on the declared size first; the adapter enforces the real one.
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_body_bytes:
            return Screening(_refuse(413, "Payload Too Large"))

        client_ip = self._resolve_client_ip(request)
        if client_ip is None:
            return Screening(_refuse(500, NO_CLIENT_IP))

        return Screening(None, api_key, client_ip)

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
        headers = self.upstream_headers(request, screening.api_key, screening.client_ip)
        try:
            reply = self._sync_pool().request(
                "POST", self._upstream_url, headers=_on_the_wire(headers), content=body
            )
        except (httpx.HTTPError, ResponseTooLargeError) as error:
            return self._upstream_failed(error)
        return _relay(reply)

    async def aforward(
        self, screening: Screening, request: ProxyRequest, body: bytes
    ) -> ProxyResponse:
        """Forwards a screened request on the running event loop."""
        headers = self.upstream_headers(request, screening.api_key, screening.client_ip)
        try:
            reply = await self._asyncio_pool().request(
                "POST", self._upstream_url, headers=_on_the_wire(headers), content=body
            )
        except (httpx.HTTPError, ResponseTooLargeError) as error:
            return self._upstream_failed(error)
        return _relay(reply)

    def _upstream_failed(self, error: Exception) -> ProxyResponse:
        """Answers an upstream failure without raising, in one log line.

        A timeout is a 504 and anything else a 502, so no framework turns
        it into a 500 with a stack trace. The body names nothing.
        """
        if isinstance(error, httpx.TimeoutException):
            logger.warning("Proxy upstream timed out after %.1f s", self._timeout)
            return _refuse(504, "Gateway timeout")
        logger.warning("Proxy upstream failed: %s", _failure_reason(error))
        return _refuse(502, "Bad gateway")

    def upstream_headers(
        self, request: ProxyRequest, api_key: str, client_ip: Optional[str] = None
    ) -> dict[str, str]:
        """Builds the upstream headers.

        Nothing is copied wholesale: only the body's content type, the visitor
        metadata Fingerly needs, the version this proxy reports, and an
        idempotency key when the SDK sent one.

        Args:
            request: The incoming request.
            api_key: The key to present upstream.
            client_ip: The visitor's address, resolved by :meth:`screen`;
                resolved here when omitted.

        Raises:
            TypeError: If ``client_ip`` resolves to no valid IP address.
        """
        if client_ip is None:
            client_ip = self._resolve_client_ip(request)
            if client_ip is None:
                raise TypeError(NO_CLIENT_IP)

        headers = {
            "content-type": request.headers.get("content-type", "application/json"),
            "x-api-key": api_key,
            "x-fingerly-client-ip": client_ip,
            "x-fingerly-origin": request.headers.get("origin", ""),
            "x-fingerly-user-agent": request.headers.get("user-agent", ""),
            "x-fingerly-proxy-version": PROXY_VERSION,
        }
        if self._uses_proxy_key:
            headers["x-fingerly-proxy-key"] = self._key.reveal()
        idempotency_key = request.headers.get("idempotency-key")
        if idempotency_key:
            headers["idempotency-key"] = idempotency_key
        return headers

    def close(self) -> None:
        """Closes the WSGI handler's pooled connections."""
        with self._lock:
            pool, self._http = self._http, None
        if pool is not None:
            pool.close()

    async def aclose(self) -> None:
        """Closes the ASGI handler's pooled connections."""
        pool, self._async_http = self._async_http, None
        if pool is not None:
            await pool.aclose()

    def _resolve_client_ip(self, request: ProxyRequest) -> Optional[str]:
        """Calls ``client_ip`` and accepts exactly one IPv4 or IPv6 literal.

        Anything else, an exception included, is a configuration mistake
        rather than a visitor's: it is reported once per process and the
        request is not forwarded, since a wrong address would be scored as
        the visitor's own.
        """
        try:
            value = self._client_ip(request)
        except Exception:
            value = None
        if isinstance(value, str) and _is_ip_literal(value):
            return value
        _report_bad_client_ip()
        return None

    def _answers(self, request: ProxyRequest) -> bool:
        """True when the request is for the one path this proxy serves.

        Without a configured path, whatever the framework routed here is
        answered. With one, it is matched exactly: case-sensitive, with no
        trailing slash, nothing under it, no dot segment and nothing
        percent-encoded. It is accepted in either shape the adapters can hand
        over: present in the application-relative path, when the proxy is
        routed from above it, or already stripped into the mount, when the
        proxy is mounted at it. A sub-URI deployment only adds to the front of
        the mount, so it changes neither.
        """
        if self._path is None:
            return True
        if request.raw_path is not None and not _raw_matches(
            request.raw_path, self._path
        ):
            return False
        if request.mount.endswith(self._path):
            return request.path == ""
        return request.path == self._path

    def _upstream_key_for(self, presented: Optional[str]) -> Optional[str]:
        """Decides which key to present upstream.

        With a proxy key the browser must supply a public key for the same
        environment, which the proxy forwards alongside its own. The
        deprecated secret-key mode authenticates on its own.

        Returns:
            The key to forward, or None when the caller is unauthorised.
        """
        if not self._uses_proxy_key:
            return self._key.reveal()
        try:
            browser = parse_key(presented or "", "pk")
        except TypeError:
            return None
        return presented if browser.environment == self._scope.environment else None

    def _sync_pool(self) -> SyncPool:
        """Builds the synchronous upstream pool on first use."""
        with self._lock:
            if self._http is None:
                timeout = self._timeout

                def build(transport: Optional[httpx.BaseTransport]) -> httpx.Client:
                    return httpx.Client(
                        headers={"user-agent": USER_AGENT},
                        timeout=timeout,
                        follow_redirects=False,
                        cookies=no_cookies(),
                        transport=transport,
                    )

                self._http = SyncPool(
                    build, self._timeout, self._limits, self._transport
                )
            return self._http

    def _asyncio_pool(self) -> AsyncPool:
        """Builds the asyncio upstream pool on the loop that first uses it."""
        if self._async_http is None:
            timeout = self._timeout

            def build(
                transport: Optional[httpx.AsyncBaseTransport],
            ) -> httpx.AsyncClient:
                return httpx.AsyncClient(
                    headers={"user-agent": USER_AGENT},
                    timeout=timeout,
                    follow_redirects=False,
                    cookies=no_cookies(),
                    transport=transport,
                )

            self._async_http = AsyncPool(
                build, self._timeout, self._limits, self._async_transport
            )
        return self._async_http


def _normalize_path(value: str) -> str:
    """Validates the path the dashboard issued and drops trailing slashes.

    It is matched exactly: the proxy answers that path and nothing under it.

    Raises:
        TypeError: If the path is not an absolute URL path.
    """
    if not isinstance(value, str):
        raise TypeError("path must be an absolute URL path such as /k7x2qm4a")
    path = value.strip().rstrip("/")
    if not path.startswith("/") or len(path) < 2 or "?" in path or "#" in path:
        raise TypeError("path must be an absolute URL path such as /k7x2qm4a")
    return path


def _on_the_wire(headers: Mapping[str, str]) -> list[tuple[bytes, bytes]]:
    """Encodes header values as the bytes the visitor's browser sent.

    Both standards hand over header values decoded as Latin-1, so encoding
    them back is lossless. httpx would encode them as ASCII instead and
    raise on a user agent or origin carrying any other byte, which a visitor
    can send at will.
    """
    wire: list[tuple[bytes, bytes]] = []
    for name, value in headers.items():
        try:
            encoded = value.encode("latin-1")
        except UnicodeEncodeError:
            encoded = value.encode("utf-8")
        wire.append((name.encode("ascii"), encoded))
    return wire


def _raw_matches(raw_path: str, path: str) -> bool:
    """True when the path as sent ends in exactly the configured path.

    Servers decode the path before an application sees it, so ``%2F``,
    ``%2e%2e`` or an encoded letter would otherwise reach the same route. The
    configured path is plain, so the raw one must end with it verbatim, and no
    segment may be a dot segment.
    """
    if not raw_path.endswith(path):
        return False
    return all(segment not in (".", "..") for segment in raw_path.split("/"))


def _is_ip_literal(value: str) -> bool:
    """True for one IPv4 or IPv6 address, written plainly and nothing else."""
    if not value or value != value.strip() or "%" in value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


_bad_client_ip_reported = threading.Event()


def _report_bad_client_ip() -> None:
    """Logs a misconfigured ``client_ip`` once per process, not per request."""
    if not _bad_client_ip_reported.is_set():
        _bad_client_ip_reported.set()
        logger.error(
            "%s; requests are answered with 500 until it is fixed", NO_CLIENT_IP
        )


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


def _failure_reason(error: Exception) -> str:
    """A short, stable reason for a failed upstream exchange."""
    if isinstance(error, ResponseTooLargeError):
        return f"response body over {MAX_RESPONSE_BYTES // 1048576} MiB"
    if isinstance(error, httpx.ConnectError):
        return "could not connect"
    if isinstance(error, (httpx.RemoteProtocolError, httpx.DecodingError)):
        return "malformed response"
    if isinstance(error, (httpx.ReadError, httpx.WriteError)):
        return "connection lost"
    return "transport error"


def _relay(reply: Reply) -> ProxyResponse:
    """Returns the upstream response to the browser, allowlisted headers only.

    The body was read in full before this runs, so a truncated answer is a
    failure rather than a success. The length is recomputed because httpx has
    already decoded the body, and the result is marked uncacheable.
    """
    body = b"" if reply.status in BODILESS_STATUSES else reply.body
    headers = [
        (name, reply.headers[name]) for name in RELAYED_HEADERS if name in reply.headers
    ]
    headers.append(("cache-control", "no-store"))
    if reply.status not in BODILESS_STATUSES:
        headers.append(("content-length", str(len(body))))
    return ProxyResponse(reply.status, headers, body)
