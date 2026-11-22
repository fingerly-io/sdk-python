# Changelog

## 0.5.0

- Added `AgentSightings` and `AsyncAgentSightings`, which report the
  requests your server served so AI crawlers that never run a page's
  JavaScript are seen. Mount `sightings.wsgi(app)` or `sightings.asgi(app)`;
  each in-scope response (HTML by default, and `/robots.txt`, `/llms.txt`,
  `/llms-full.txt`) is recorded in a bounded buffer and sent in batches from
  a daemon thread or an asyncio task, so no request waits on Fingerly.
  `sightings.lookup(request)` answers from memory with what the server said,
  or `AGENT_UNKNOWN`, and never raises. `include_paths`, `exclude_paths`,
  `content_types` and `cache_size` adjust what is reported and remembered;
  `flush()` and `close()` (`aclose()` for the async one) send what is
  pending. The call underneath is `fingerly.agents.sightings(items)`, and a
  refused call's `FingerlyAPIError` carries `rate_limit_scope`.
- A `429` pauses reporting for its `Retry-After`, held to between 1 second
  and 24 hours, so a huge value or a far-off date never stops reporting for
  the life of the process.
- The sightings middleware hands the server the response as your app made
  it: a streamed body chunk by chunk, and under WSGI a body that keeps its
  `len()` (wsgiref and waitress set `Content-Length` by it) and the server's
  own file wrapper, so files are still sent directly. A file sent with the
  ASGI pathsend or zero-copy extension, as Starlette's `FileResponse` does
  under Granian, is reported.
- A sightings report whose deadline runs out before it was sent, as in a
  stalled connect or TLS handshake, is kept and retried with backoff by both
  flushers; only one the server may have counted is dropped.
- No reported item breaks a limit the API checks, measured as UTF-8 after
  decoding: a request whose user agent or method is over 4096 bytes is not
  reported, a `Host` or Web Bot Auth header over 4096 bytes is left out, and
  a repeat count stops at 1,000,000.
- An answer item the SDK cannot read is `AGENT_UNKNOWN` in its place in
  `AgentSightingsResult.items`; the other answers are kept and remembered,
  instead of the whole report failing.
- `VisitorKind.UNKNOWN` names the answer the API gives a reported request it
  could not use: `ttl` 0, so it is never remembered and `lookup` keeps
  answering `AGENT_UNKNOWN`, while the other requests of the report are
  answered as usual. A `422` now means no request in the report was usable.
- `AsyncAgentSightings` starts its flusher for reports made off the event
  loop, such as from a sync view's thread, instead of waiting for 200 of
  them.
- Pending sightings are sent on a graceful shutdown without any code of
  yours, within 5 seconds in all: as the interpreter exits (a gunicorn or
  uWSGI worker after `SIGTERM`), and when an ASGI server's lifespan shutdown
  arrives, also for an app that does not speak lifespan, whether it refuses
  it as Django's ASGI handler does or ignores it.
- A worker forked from a parent that already used a client, a proxy or the
  sightings, including under uWSGI, which forks without Python's fork hooks,
  starts with its own connections, buffer and flusher.
- Events carry the AI agent behind an `ai_bot` visit: `Event.ai` is an
  `AIAgent` with `name`, `provider`, `purpose`, `runtime`, `declared` and
  `verification` (`method` and `result`), compared with the new
  `VisitorKind`, `AIPurpose`, `AIRuntime`, `AIVerificationMethod` and
  `AIVerificationResult` enums. `events.list` filters by `kind`,
  `ai_provider` and `ai_purpose`.
- `Signal` names `ai_spoofed` and `identity_obfuscated`, and no longer
  lists `vpn_timezone`.
- The proxy forwards the Web Bot Auth `signature`, `signature-input` and
  `signature-agent` headers, each dropped when over 4096 bytes.
- The `client_ip` callback of `FingerlyProxy` and the sightings is typed to
  return `Optional[str]`, so `request.headers.get(...) or request.peer_host`
  type-checks; None was already treated as no address.
- An API body of an unexpected shape raises `FingerlyError` from every
  call, never `TypeError` or `AttributeError`, and an optional field of the
  wrong type reads as `None` rather than holding a value of another type.
- The README and `DeviceCheck` describe one read and one write token per
  identification: a check-then-mark flow reads and writes on the same
  request ID.

## 0.4.1

- `AttestSkippedReason` documents each member: when the iOS and Android SDKs
  send `not_offered`, `unsupported`, `challenge_unavailable`, `key_error`,
  `timeout`, `backoff` and `install_unavailable`.
- The vendored OpenAPI contract declares the enums for the fixed string
  values, and the contract test sends signal groups as event triggers.

## 0.4.0

- Added `str` enums for the fixed values the API and webhooks send:
  `Signal`, `SuspectLevel`, `Confidence`, `EventState`, `Environment`,
  `AttestationState`, `AttestationStatus`, `AttestSkippedReason`,
  `VerifyReason` and `WebhookEventType`. Every member equals and hashes like
  its raw string, so `event.suspect_level == SuspectLevel.HIGH` and
  `Signal.FINGERPRINT_SUPPRESSED in signals` work on parsed events. Model
  fields stay typed `str` and hold the value as sent, so a value a newer
  server adds still parses as a plain string.
- `VerifyReason` is an enum class instead of a `Literal` alias, and
  `VerifyResult.reason` is a `VerifyReason` member: `VerifyReason.OK` (equal
  to `""`) when `ok`, otherwise the failed check. This is a breaking change
  for type checkers; the runtime values are the same strings.
- `Signal` and `SIGNAL_NAMES` match the server: they include
  `repeated_reinstall`, `device_activity_high` and
  `device_activity_very_high`, and no longer list `app_attest_key_churn`.

## 0.3.0

- Added `fingerly.events.verify(request_id, max_age_seconds=300, tag=None,
  consume=True)`, on `Fingerly` and `AsyncFingerly`, which reads an event and
  checks it exists, is recent, carries the expected `tag`, is identifiable and
  scored, then consumes it once, answering a `VerifyResult`; and
  `fingerly.events.consume(request_id)`, answering a `ConsumeResult` or raising
  `FingerlyEventAlreadyConsumedError` with `consumed_at`.
- Added `fingerly.device_check.query(request_id)` and
  `fingerly.device_check.write(request_id, bit0=None, bit1=None)`, on
  `Fingerly` and `AsyncFingerly`, which spend the DeviceCheck token held for
  an iOS event to read or set the device's two bits. Answers are
  `DeviceCheckBits` and `DeviceCheckWriteResult`; errors raise
  `FingerlyDeviceCheckError` with the API `code` and, on `apple_rejected`,
  `apple_status`. A `503` or a transport failure is retried with the identical
  request.
- Refreshed the vendored v3 OpenAPI and contract fixtures, removing retired
  deferred supplement schemas and routes, and added `Event.reason`,
  `Event.url_host`, `Event.url_path`, `Event.identifiable`,
  `Event.parse_document()`, `EventDocument`, `Attestation`, and `SIGNAL_NAMES`
  covering all v3 signals (`attestation_failed`, `attestation_downgrade`,
  `device_inconsistent`, `report_incomplete`, `probe_errors`,
  `fetch_metadata_missing`, `web_ticket_missing`, `web_ticket_invalid`,
  `tampering`, `custom_root_ca`, `secondary_user_profile`), with `attest_skipped` and `downgrade` on
  `Attestation`.
- Updated `FingerlyProxy` (ASGI and WSGI) to enforce the single-path
  `proxy.md` relay contract: sanitize-and-restore validation of
  `x-fingerly-sdk-platform`, rejection with HTTP `400` (`missing_origin`) when
  both `Origin` and a valid `x-fingerly-sdk-platform` are absent (never
  synthesising `x-fingerly-origin`), forwarding of `Sec-Fetch-*` and
  `Sec-CH-UA-*` client metadata headers, optional cross-origin
  `allowed_origins` CORS handling, and verbatim raw-byte forwarding.
- `FingerlyProxy` requires `proxy_key`, checks the browser's same-environment
  public key on every request, and never sends a secret key upstream.

## 0.2.0

- `Event.project_id` is the Fingerly project an event belongs to, on single
  reads and list rows; `None` when the server does not send it. Webhook `data`
  for `identification.completed` and `visitor.suspect` (and
  `identification.refused` when the key was known) carries `project_id`.
- `Event.ip_address` is removed; `Event.ip_network` (an IPv4 /24 or an IPv6
  /40, `None` when absent) replaces it. The API no longer returns the address.
- `Event.deferred_signals` is removed; the API no longer returns the deferred
  report.
- `Event.document` is now an allow-listed view of the archived request, with
  no raw signals, user agent or address.
- The vendored contract snapshot is refreshed.

## 0.1.0

The first release.

- `Fingerly` and `AsyncFingerly` read events with a server-only secret key.
  Every status outside 2xx, redirects included, raises `FingerlyAPIError`
  with `status`, `code`, `details`, `request_id` and `retry_after`; network
  failures raise `FingerlyTimeoutError` or `FingerlyConnectionError`. Reads
  never retry. `Fingerly` warns once per process when it runs on an event
  loop, where `AsyncFingerly` belongs.
- `404 event_pending` on `events.get` (the request id was accepted, the event
  is not recorded yet; `Retry-After` is set) raises
  `FingerlyEventPendingError`, a `FingerlyAPIError` subclass carrying
  `retry_after`. `event_not_found` still means never issued or past retention
  and raises a plain `FingerlyAPIError`. Neither is retried.
- `verify_webhook` checks a delivery's signature and age against the raw
  body, accepts any of the first 32 signatures sent during a rotation, and
  never raises for malformed input.
- `FingerlyProxy` serves the browser SDK's same-origin path under ASGI and
  WSGI. It answers the configured path exactly, as sent (`ProxyRequest`
  carries it as `raw_path`), forwards only vetted headers, byte for byte, relays an allowlist of response headers marked
  `no-store`, refuses bodies over 1 MiB, answers `504` or `502` on upstream
  trouble with one log line on `fingerly.proxy`, cancels the upstream call
  when an ASGI client disconnects, and requires `client_ip` to return one
  IP address.
- One deadline, `timeout`, bounds each whole exchange, and response bodies
  are capped at 4 MiB.
- Connections are pooled for up to 256 concurrent requests per process
  (`limits` changes that), replaced every five minutes to re-resolve DNS,
  never follow redirects and keep no cookies.
- Credentials print as `[redacted]` in `repr`, `vars` and errors, and refuse
  to pickle.
