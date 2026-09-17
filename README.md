# fingerly

Server-side event reads and webhook verification for Python. Two clients share
one API: `Fingerly` for synchronous code such as Django and Flask, and
`AsyncFingerly` for asyncio code such as FastAPI and Starlette. Python 3.9 or
newer. One runtime dependency, `httpx`. Version 0.1.0 is prepared for release;
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

## No same-origin proxy

The Node SDK ships `createProxy`, a first-party proxy that keeps content
blockers from refusing identification. It is written against the web `Request`
and `Response` standard, which every JavaScript server runtime implements;
Python has no single equivalent. Serve the proxy from a Cloudflare Worker or a
Node runtime, or build one against the contract in
[proxy integrations](https://docs.fingerly.io/docs/proxy-integrations).

## Timeouts

`timeout` is passed to `httpx` and applies per connect, read, write and pool
operation, which is the Python convention. It is not a single deadline over the
whole request. `wait_for`'s `timeout` *is* a total deadline, because the SDK
owns that loop.

## Development and release preparation

```sh
uv venv --python 3.9 && uv pip install -e ".[dev]"
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
.venv/bin/python scripts/sync_contract.py --check
```

The vendored synthetic contract snapshot makes tests independent of sibling
repositories. To update it from the integration workspace, set
`FINGERLY_CONTRACT_DIR` to its `contract` directory and run
`python scripts/sync_contract.py`. Checks verify the recorded hashes. Never put
production secrets in fixtures.

## Source structure

`_client.py` holds both clients and their event reads. `_transport.py` builds
requests and interprets responses, so the two clients share one definition of
what a request is and what a failure means. `_models.py` owns `Event`,
`EventPage` and their parsing. `_webhooks.py` verifies signatures. `_config.py`
validates every caller-supplied option: keys, origins, API versions and
durations, all before any network access. `_errors.py` holds the exception
hierarchy. `__init__.py` only exposes the public API.

### API version

Pass `api_version` to select a route version, for example `v1` (the default) or
`v2`. The server must support the chosen version. The version applies to every
API request; it is separate from the endpoint origin.
