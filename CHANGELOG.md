# Changelog

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
