# fingerly

Server-side event reads, webhook verification and a same-origin proxy for
Python. Two clients share one API: `Fingerly` for synchronous code such as
Django and Flask, and `AsyncFingerly` for asyncio code such as FastAPI and
Starlette. Python 3.9 or newer. One runtime dependency, `httpx`. The proxy
serves both ASGI and WSGI, so it mounts under either.

```python
import os
from fingerly import Fingerly

fingerly = Fingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"])
page = fingerly.events.list(level="high", limit=50)
event = fingerly.events.get(page.rows[0].request_id)
```

```python
import asyncio
import os
from fingerly import AsyncFingerly


async def main() -> None:
    async with AsyncFingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"]) as fingerly:
        page = await fingerly.events.list(level="high", limit=50)
        for row in page.rows:
            print(row.request_id, row.suspect_score)


asyncio.run(main())
```

In a web app, build the client once and reuse it: see
[Framework guides](#framework-guides) for FastAPI, Django and Flask.

Event reads require `fly_sk_{production|staging|development}_…` keys. Requests
go to `https://api.fingerly.io`; `endpoint` overrides that for a local API.
Public, proxy, management, malformed and unsupported keys are rejected before
network access. Requests do not follow redirects. `get` and `list` each perform
one request and never retry.

`FingerlyAPIError` provides `status`, and optional `code`, `details`,
`request_id` and `retry_after`, the seconds a `429`, a `503` or a
`404 event_pending` asks you to wait
(`None` when the response did not say). The secret key is stripped from all of
them. Every status outside 2xx raises it, a redirect included, since requests
never follow one. `FingerlyTimeoutError` and `FingerlyConnectionError` cover a
deadline and an unreachable API; all three derive from `FingerlyError`.

The archived `document` and `deferred_signals` are included when available.
`suspect_score` is `None` when the request was not scored, and must not be
treated as zero. `Event` declares every documented field as an attribute and
falls back to the decoded body for fields added later, so a new server field
needs no SDK upgrade.

## Read an event you just identified

Send the `requestId` the browser SDK returned to your server and read it there
with `fingerly.events.get(request_id)`, or
`await fingerly.events.get(request_id)` with `AsyncFingerly`. A `404` carries
one of two codes:

- `event_pending` raises `FingerlyEventPendingError`, a `FingerlyAPIError`: the
  request id was accepted but its event is not recorded yet. It is not a
  verdict. Try again after `retry_after` seconds, or verify asynchronously, for
  example from a webhook. The SDK never retries on its own.
- `event_not_found` raises a plain `FingerlyAPIError`: the request id was never
  issued for this key's environment, or the event is past the 30-day
  retention.

The archived `document` arrives moments after the event itself, so check
`has_document` rather than assuming it is there.

## Verify a backend action

Read the event with a server-only key. Check that its tag matches your action,
that it is recent, that its environment is correct, and that it was scored.
Apply your own policy to the server's verdict. Do not authorize an action using
scores or visitor identifiers supplied by the browser. Tags correlate events;
they do not replace your application's authentication or replay protection.
A `FingerlyEventPendingError` means the server has not decided yet: retry after
`retry_after` seconds or verify asynchronously, and do not refuse the action as
fraud on that answer alone. The framework guides below answer it with `503` and
`Retry-After`.

## Webhooks

```python
import os

from flask import Flask, abort, request

from fingerly import verify_webhook

app = Flask(__name__)


@app.post("/webhooks/fingerly")
def fingerly_webhook():
    if not verify_webhook(
        secret=os.environ["FINGERLY_WEBHOOK_SECRET"],
        payload=request.get_data(),
        timestamp=request.headers.get("x-fingerly-timestamp"),
        signature=request.headers.get("x-fingerly-signature"),
    ):
        abort(400)
    delivery = request.get_json()
    print(delivery["type"])
    return "", 204
```

Verify the exact raw bytes before JSON parsing. Signatures cover the timestamp
and body. The default replay tolerance is 300 seconds; persist processed webhook
IDs to deduplicate deliveries. During signing-secret rotation, any matching
signature in the comma-separated header is accepted; only the first 32 are
read. The function never raises for malformed input: bad input is a failed
verification, not an exception.

## Closing

Each client holds pooled connections. Build one and reuse it; build one per
event loop for `AsyncFingerly`.

> **Never call `Fingerly` from `async def` code.** It blocks the event loop for
> the whole request, so every other request on that worker waits behind it:
> five reads against a slow API stall a FastAPI worker for five timeouts in a
> row. Use `AsyncFingerly` there, or a plain `def` route, which FastAPI and
> Starlette run in a thread. `Fingerly` raises a `RuntimeWarning`, once per
> process, when it finds itself on a running event loop.

| | `Fingerly` | `AsyncFingerly` |
| --- | --- | --- |
| Calls | `fingerly.events.get(id)` | `await fingerly.events.get(id)` |
| Closing | `fingerly.close()` or `with Fingerly(...) as fingerly:` | `await fingerly.aclose()` or `async with AsyncFingerly(...) as fingerly:` |

## Same-origin proxy

Content blockers refuse browser requests to third-party APIs, and a refused
identification is a visitor never identified. Mount the proxy on a path of your
own site and those requests become first-party. The proxy key is what lets that
hop declare the visitor's real address, origin and user agent; a public key
alone never can, so nobody can spoof them.

Create a proxy in the dashboard (**Integration > Proxy keys**). It issues the
proxy key and a random path, such as `/k7x2qm4a`, for you to serve it on. One
`FingerlyProxy` holds the configuration and exposes both server standards, so a
project running each gets the same behaviour from one instance.

```python
from fingerly import FingerlyProxy

proxy = FingerlyProxy(
    proxy_key=os.environ["FINGERLY_PROXY_KEY"],
    path="/k7x2qm4a",
    client_ip=lambda request: (
        request.headers.get("cf-connecting-ip") or request.peer_host
    ),
)
```

`path` is the path the dashboard issued, within your application. With it set,
the proxy answers that one path, exactly, and anything else gets `404`,
including anything under it, a trailing slash, another letter case, a dot
segment or a percent-encoded spelling of the same path. It excludes anything a
sub-URI deployment adds, and a path the mount has already stripped works too,
so the same configuration serves an app at the root and one served from
`/shop`. It is optional: leave it
out and the proxy answers whatever your framework routes to it, which is safe
only where the framework routes that one path and nothing else. There is no
default path. Use the one the dashboard issued rather than inventing one:
blockers look for words such as `fingerprint`, `tracking` and `fingerly`.

Serve `proxy.asgi` under an async framework (FastAPI, Starlette, Django's
ASGI stack, Quart, Litestar) and `proxy.wsgi` under a sync one (Flask, Django's
WSGI stack, Pyramid). Under Starlette and FastAPI use `app.add_route`, not a
`Mount`: Starlette answers a mount's bare path with a redirect to its slashed
form, the browser SDK posts to the bare one, and the proxy does not answer the
slashed one. The [framework guides](#framework-guides) show each in full.

Then point the browser SDK at the same path:

```ts
const fingerly = await load({ apiKey: 'fly_pk_…', endpoints: '/k7x2qm4a' })
```

### What the proxy does

The browser SDK posts both of its calls, the identification and the report
that follows it, to that one path. The proxy forwards each, as it is, to
Fingerly's one ingest URL, `https://api.fingerly.io/api/v1/ingest`, and to
nothing else. A path other than the configured one gets `404`, and any method
but `POST` gets `405`. Event reads need a secret key and stay unreachable from
a browser by construction.

The browser must present a public key from the same environment as the proxy
key, or the request gets `401`. Bodies over 1 MiB get `413`, enforced
while streaming rather than after buffering. Responses are marked `no-store`.

Only the content type, the visitor metadata Fingerly needs, and an
`idempotency-key` are forwarded. Customer cookies and authorization headers are
never passed on. The proxy reports itself upstream as `python/<version>` in
`x-fingerly-proxy-version`, which the dashboard shows per proxy, and sends
`fingerly-python/<version>` as its user agent.

When Fingerly cannot be reached in time the proxy answers `504 Gateway
timeout`, and on any other upstream failure, such as a refused connection, a
malformed or truncated response or one over 4 MiB, `502 Bad gateway`. Both are
short plain text marked `no-store`, and each writes one line, with no stack
trace, to the `fingerly.proxy` logger.

Back to the browser it relays only `content-type`, `x-request-id`,
`ratelimit-limit`, `ratelimit-remaining` and `retry-after`, plus its own
`cache-control: no-store` and a `content-length` for the decoded body. A
content blocker can match a response header by name, so an allowlist is what
keeps anything naming Fingerly off the page.

> **`client_ip` is the one thing you must get right.** Resolve it from a header
> your own infrastructure sets, such as your load balancer's or CDN's, and fall
> back to `peer_host`, the socket peer. Trust that header only when traffic can
> reach your app solely through that CDN or load balancer; otherwise a visitor
> can send it themselves. Never read the left-most `X-Forwarded-For` value: the
> visitor writes it. The callback is synchronous, because it is called under
> both standards.

The callback must return exactly one IPv4 or IPv6 address, such as
`203.0.113.7` or `2001:db8::1`. Anything else, including `None`, an empty
string, a list, an address with a port, or an exception, is treated as a
configuration mistake: the request is not forwarded, the visitor gets `500`
with the one line `The client IP callback returned no valid address`, and the
`fingerly.proxy` logger reports it once per process.

`ProxyRequest` gives the callback `headers` (case-insensitive), `path`,
`method`, `peer_host`, `mount` and `raw_path`. `peer_host` is the socket peer,
which is your load balancer rather than the visitor whenever one sits in front
of you.

### A note on mount paths

Both adapters match the path as the mounted application sees it: `PATH_INFO`
under WSGI, and under ASGI the `path` with `root_path` removed when it is still
carrying it. Mounted at its own path, the proxy finds that path in the mount
instead, `SCRIPT_NAME` or `root_path`, with nothing after it.

That last part needs care. ASGI servers disagree about what `path` holds under
a mount: Starlette 0.47 and newer leave it whole and report the prefix
separately in `root_path`, while older versions and some routers strip the
prefix off it. Both are permitted by the spec, so the proxy detects which one
it was given rather than assuming.

Taking the application-relative path rather than the whole one is what makes a
sub-URI deployment work. There, `root_path` or `SCRIPT_NAME` carries a prefix
that belongs to the deployment and that your `path` knows nothing about, so a
proxy matching on the whole path would refuse every request. It is the same
rule Rack's `PATH_INFO` and ASP.NET Core's `Request.Path` already follow.

`tests/test_frameworks.py` drives real Starlette and Flask apps, mounted plainly
and again under a sub-URI, to keep all of it that way.

### Closing

The proxy opens its upstream connections on first use, one pool per standard.
Close whichever you used when your app shuts down: `proxy.close()` for WSGI,
`await proxy.aclose()` for ASGI. A WSGI process can simply exit.

## Framework guides

Each guide is a complete app. Replace `/k7x2qm4a` with the path the dashboard
issued, and set `FINGERLY_SECRET_KEY` and `FINGERLY_PROXY_KEY`. The browser
posts identifications to the proxy path and sends the `requestId` it gets back
to `/verify/<request_id>`, where your server reads the event with its secret
key.

### FastAPI

```python
# main.py; run with: uvicorn main:app
import contextlib
import os

from fastapi import FastAPI, HTTPException, Request

from fingerly import (
    AsyncFingerly,
    FingerlyAPIError,
    FingerlyEventPendingError,
    FingerlyProxy,
)

proxy = FingerlyProxy(
    proxy_key=os.environ["FINGERLY_PROXY_KEY"],
    path="/k7x2qm4a",
    client_ip=lambda request: (
        request.headers.get("cf-connecting-ip") or request.peer_host
    ),
)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # One read client per worker, built on the worker's own event loop.
    app.state.fingerly = AsyncFingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"])
    yield
    await app.state.fingerly.aclose()
    await proxy.aclose()


app = FastAPI(lifespan=lifespan)
app.add_route("/k7x2qm4a", proxy.asgi)


@app.get("/verify/{request_id}")
async def verify(request_id: str, request: Request):
    try:
        event = await request.app.state.fingerly.events.get(request_id)
    except FingerlyEventPendingError as error:
        # Not decided yet, not fraud: ask the caller to come back.
        retry_after = str(round(error.retry_after or 2))
        raise HTTPException(503, headers={"Retry-After": retry_after}) from None
    except FingerlyAPIError as error:
        raise HTTPException(404 if error.status == 404 else 502) from None
    return {"visitor_id": event.visitor_id, "suspect_score": event.suspect_score}
```

The same works under `uvicorn --workers 4` or gunicorn's uvicorn worker: each
worker runs the lifespan and gets its own client and pool.

### Django

Django has no `add_route`, so put the proxy in front of Django in `wsgi.py`
or `asgi.py`, before any URL routing. In a project named `mysite`:

```python
# mysite/identification.py
import os

from fingerly import Fingerly, FingerlyProxy

PROXY_PATH = "/k7x2qm4a"

proxy = FingerlyProxy(
    proxy_key=os.environ["FINGERLY_PROXY_KEY"],
    path=PROXY_PATH,
    client_ip=lambda request: (
        request.headers.get("cf-connecting-ip") or request.peer_host
    ),
)

# One read client per process, shared by every thread.
fingerly = Fingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"])
```

```python
# mysite/wsgi.py, for gunicorn mysite.wsgi or runserver
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

from mysite.identification import PROXY_PATH, proxy  # noqa: E402

django_application = get_wsgi_application()


def application(environ, start_response):
    if environ.get("PATH_INFO") == PROXY_PATH:
        return proxy.wsgi(environ, start_response)
    return django_application(environ, start_response)
```

```python
# mysite/asgi.py, for uvicorn mysite.asgi:application
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

from mysite.identification import PROXY_PATH, proxy  # noqa: E402

django_application = get_asgi_application()


async def application(scope, receive, send):
    if scope["type"] == "http" and scope["path"] == PROXY_PATH:
        await proxy.asgi(scope, receive, send)
    else:
        await django_application(scope, receive, send)
```

```python
# mysite/views.py
from django.http import JsonResponse

from fingerly import FingerlyAPIError, FingerlyEventPendingError
from mysite.identification import fingerly


def verify(request, request_id):
    try:
        event = fingerly.events.get(request_id)
    except FingerlyEventPendingError as error:
        # Not decided yet, not fraud: ask the caller to come back.
        retry_after = str(round(error.retry_after or 2))
        return JsonResponse(
            {"error": error.code}, status=503, headers={"Retry-After": retry_after}
        )
    except FingerlyAPIError as error:
        status = 404 if error.status == 404 else 502
        return JsonResponse({"error": error.code}, status=status)
    return JsonResponse(
        {"visitor_id": event.visitor_id, "suspect_score": event.suspect_score}
    )
```

```python
# mysite/urls.py
from django.urls import path

from mysite import views

urlpatterns = [path("verify/<str:request_id>", views.verify)]
```

`verify` is a plain view, so Django runs it in a thread under ASGI too. In an
`async def` view use `AsyncFingerly` instead, built once per process.

### Flask

```python
# app.py; run with: gunicorn app:app, or flask --app app run
import os

from flask import Flask, abort
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from fingerly import (
    Fingerly,
    FingerlyAPIError,
    FingerlyEventPendingError,
    FingerlyProxy,
)

app = Flask(__name__)
fingerly = Fingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"])
proxy = FingerlyProxy(
    proxy_key=os.environ["FINGERLY_PROXY_KEY"],
    path="/k7x2qm4a",
    client_ip=lambda request: (
        request.headers.get("cf-connecting-ip") or request.peer_host
    ),
)
app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {"/k7x2qm4a": proxy.wsgi})


@app.get("/verify/<request_id>")
def verify(request_id):
    try:
        event = fingerly.events.get(request_id)
    except FingerlyEventPendingError as error:
        # Not decided yet, not fraud: ask the caller to come back.
        retry_after = str(round(error.retry_after or 2))
        return {"error": error.code}, 503, {"Retry-After": retry_after}
    except FingerlyAPIError as error:
        abort(404 if error.status == 404 else 502)
    return {"visitor_id": event.visitor_id, "suspect_score": event.suspect_score}
```

A `DispatcherMiddleware` mount answers everything under its path too, which is
what `path` narrows back down to the one path.

## Timeouts

`timeout` is one deadline over the whole request: connecting, sending, the
response headers and the body. An API that answers a byte at a time cannot
stretch it. The default is 10 seconds for the clients and 5 for the proxy.
Response bodies over 4 MiB are refused rather than buffered: the clients raise
`FingerlyAPIError` with code `response_too_large`.

## Connections

Each client, and each proxy handler, keeps its connections open between
requests and shares them across threads or tasks. Up to 256 concurrent requests
per process reuse connections rather than opening one each; pass
`limits=httpx.Limits(max_connections=…)` to change that. Connections are
replaced every five minutes, so a changed DNS answer is picked up. Redirects
are never followed and no cookies are kept.

## Development and release preparation

```sh
uv sync                                     # 3.9 per .python-version, dev group included
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
uv run python scripts/sync_contract.py --check
uv build                                    # wheel and sdist
```

`uv sync` reads the `dev` dependency group, so there is nothing else to install.
`.python-version` pins the development interpreter to 3.9, the oldest supported
runtime, so the floor is exercised locally rather than only in CI. `uv.lock` is
committed; CI installs with `uv sync --frozen`.

The vendored synthetic contract snapshot makes tests independent of sibling
repositories. To update it from the integration workspace, set
`FINGERLY_CONTRACT_DIR` to its `contract` directory and run
`python scripts/sync_contract.py`. Checks verify the recorded hashes. Never put
production secrets in fixtures.

## Source structure

`_client.py` holds both clients and their event reads. `_http.py` is the
connection pool both clients and the proxy send through, with its deadline and
body cap. `_transport.py` builds requests and interprets responses, so the two clients share one definition of
what a request is and what a failure means. `_models.py` owns `Event`,
`EventPage` and their parsing. `_webhooks.py` verifies signatures. `_proxy.py`
owns every proxy decision, with `_asgi.py` and `_wsgi.py` as thin adapters that
only read a request and write a response, so the two standards cannot drift
apart. `_config.py` validates every caller-supplied option: keys, origins, API
versions and durations, all before any network access. `_errors.py` holds the
exception hierarchy. `_version.py` holds the version everything else reads.
`__init__.py` only exposes the public API.

### API version

Pass `api_version` to select a route version, for example `v1` (the default) or
`v2`. The server must support the chosen version. The version applies to every
API request; it is separate from the endpoint origin. On the proxy it selects
the ingest URL, `/api/v2/ingest`, and nothing on your own site.
