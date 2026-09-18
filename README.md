# fingerly

Server-side event reads, webhook verification and a same-origin proxy for
Python. Two clients share one API: `Fingerly` for synchronous code such as
Django and Flask, and `AsyncFingerly` for asyncio code such as FastAPI and
Starlette. Python 3.9 or newer. One runtime dependency, `httpx`. The proxy
serves both ASGI and WSGI, so it mounts under either.

Version 0.1.0 is prepared for release;
the repository is private and the PyPI package has not been published.

```python
import os
from fingerly import Fingerly

fingerly = Fingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"])
page = fingerly.events.list(level="high", limit=50)
event = fingerly.events.get(page.rows[0].request_id)
```

```python
import os
from fingerly import AsyncFingerly

async with AsyncFingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"]) as fingerly:
    event = await fingerly.events.get(request_id)
```

Event reads require `fly_sk_{eu|us}_{production|staging|development}_…` keys.
The key selects the regional endpoint; `endpoint` overrides it for a local API.
Public, proxy, management, malformed and unsupported keys are rejected before
network access. Requests do not follow redirects. `get` and `list` each perform
one request and never retry.

`FingerlyAPIError` provides `status`, and optional `code`, `details` and
`request_id`. The secret key is stripped from all three. `FingerlyTimeoutError`
and `FingerlyConnectionError` cover a deadline and an unreachable API; all three
derive from `FingerlyError`.

The archived `document` and `deferred_signals` are included when available.
`suspect_score` is `None` when the request was not scored, and must not be
treated as zero. `Event` declares every documented field as an attribute and
falls back to the decoded body for fields added later, so a new server field
needs no SDK upgrade.

## Wait for a fresh identification

Identification returns before archival and warehouse insertion. To wait for a
newly identified event, opt in to bounded polling:

```python
event = fingerly.events.wait_for(request_id, timeout=10.0, interval=0.25)
event = await fingerly.events.wait_for(request_id, timeout=10.0, interval=0.25)
```

Only a structured `404 event_not_found` is retried. Other HTTP and transport
errors fail immediately. A missing event at the deadline raises
`FingerlyTimeoutError` with `operation="event_wait"`. Cancelling the awaiting
task stops the asyncio version at once.

## Verify a backend action

Read the event with a server-only key. Check that its tag matches your action,
that it is recent, that its environment is correct, and that it was scored.
Apply your own policy to the server's verdict. Do not authorize an action using
scores or visitor identifiers supplied by the browser. Tags correlate events;
they do not replace your application's authentication or replay protection.

## Webhooks

```python
from fingerly import verify_webhook

valid = verify_webhook(
    secret=os.environ["FINGERLY_WEBHOOK_SECRET"],
    payload=raw_body,
    timestamp=request.headers.get("x-fingerly-timestamp"),
    signature=request.headers.get("x-fingerly-signature"),
)
```

Verify the exact raw bytes before JSON parsing. Signatures cover the timestamp
and body. The default replay tolerance is 300 seconds; persist processed webhook
IDs to deduplicate deliveries. During signing-secret rotation, any matching
signature in the comma-separated header is accepted. The function never raises
for malformed input: bad input is a failed verification, not an exception.

## Closing

Each client holds a pooled connection. Build one and reuse it; build one per
event loop for `AsyncFingerly`.

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

One `FingerlyProxy` holds the configuration and exposes both server standards,
so a project running each gets the same behaviour from one instance.

```python
from fingerly import FingerlyProxy

proxy = FingerlyProxy(
    proxy_key=os.environ["FINGERLY_PROXY_KEY"],
    prefix="/metrics",
    client_ip=lambda request: request.headers["cf-connecting-ip"],
)
```

`prefix` is the path the proxy answers under, within your application, and it
must match the mount: a proxy built with `prefix="/metrics"` mounted at
`/fingerly` refuses everything with `404`. It excludes anything a sub-URI
deployment adds, and a prefix the mount has already stripped works too, so the
same configuration serves an app at the root and one served from `/shop`.
Choose a neutral path. Blockers look for words such as `fingerprint`,
`tracking` and `fingerly`.

### ASGI: FastAPI, Starlette, Django 3+, Quart, Litestar

```python
app.mount("/metrics", proxy.asgi)
```

### WSGI: Flask, Django's sync stack, Pyramid

```python
from werkzeug.middleware.dispatcher import DispatcherMiddleware

app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {"/metrics": proxy.wsgi})
```

Then point the browser SDK at the same path:

```ts
const fingerly = await load({ apiKey: 'fly_pk_…', endpoints: '/metrics' })
```

### What the proxy does

It forwards only `POST` to `{prefix}/api/v1/identify` and
`{prefix}/api/v1/events/{request_id}/supplement`. Anything else gets `404`, and
any other method gets `405`. Event reads need a secret key and stay unreachable
from a browser by construction.

The browser must present a public key from the same region and environment as
the proxy key, or the request gets `401`. Bodies over 1 MiB get `413`, enforced
while streaming rather than after buffering. Responses are marked `no-store`.

Only the content type, the visitor metadata Fingerly needs, and an
`idempotency-key` are forwarded. Customer cookies and authorization headers are
never passed on. Upstream `content-encoding` and `content-length` are dropped
from the relayed response, because httpx has already decoded the body and those
headers would no longer describe it.

> **`client_ip` is the one thing you must get right.** Resolve it from a header
> your own infrastructure sets, such as your load balancer's or CDN's. Never
> read the left-most `X-Forwarded-For` value: the visitor writes it. The
> callback is synchronous, because it is called under both standards.

`ProxyRequest` gives the callback `headers` (case-insensitive), `path`, `method`
and `peer_host`. `peer_host` is the socket peer, which is your load balancer
rather than the visitor whenever one sits in front of you.

### A note on mount paths

Both adapters match the path as the mounted application sees it: `PATH_INFO`
under WSGI, and under ASGI the `path` with `root_path` removed when it is still
carrying it.

That last part needs care. ASGI servers disagree about what `path` holds under
a mount: Starlette 0.47 and newer leave it whole and report the prefix
separately in `root_path`, while older versions and some routers strip the
prefix off it. Both are permitted by the spec, so the proxy detects which one
it was given rather than assuming.

Taking the application-relative path rather than the whole one is what makes a
sub-URI deployment work. There, `root_path` or `SCRIPT_NAME` carries a prefix
that belongs to the deployment and that your `prefix` knows nothing about, so a
proxy matching on the whole path would refuse every request. It is the same
rule Rack's `PATH_INFO` and ASP.NET Core's `Request.Path` already follow.

`tests/test_frameworks.py` drives real Starlette and Flask apps, mounted plainly
and again under a sub-URI, to keep all of it that way.

### Closing

The proxy opens its upstream connection on first use, one per standard. Close
whichever you used: `proxy.close()` for WSGI, `await proxy.aclose()` for ASGI.

## Timeouts

`timeout` is passed to `httpx` and applies per connect, read, write and pool
operation, which is the Python convention. It is not a single deadline over the
whole request. `wait_for`'s `timeout` *is* a total deadline, because the SDK
owns that loop.

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

`_client.py` holds both clients and their event reads. `_transport.py` builds
requests and interprets responses, so the two clients share one definition of
what a request is and what a failure means. `_models.py` owns `Event`,
`EventPage` and their parsing. `_webhooks.py` verifies signatures. `_proxy.py`
owns every proxy decision, with `_asgi.py` and `_wsgi.py` as thin adapters that
only read a request and write a response, so the two standards cannot drift
apart. `_config.py` validates every caller-supplied option: keys, origins, API
versions and durations, all before any network access. `_errors.py` holds the
exception hierarchy. `__init__.py` only exposes the public API.

### API version

Pass `api_version` to select a route version, for example `v1` (the default) or
`v2`. The server must support the chosen version. The version applies to every
API request; it is separate from the endpoint origin.
