# Changelog

## 0.1.0

Not yet published. The first release.

- `Fingerly` and `AsyncFingerly` read events with a server-only secret key.
  Every status outside 2xx, redirects included, raises `FingerlyAPIError`
  with `status`, `code`, `details`, `request_id` and `retry_after`; network
  failures raise `FingerlyTimeoutError` or `FingerlyConnectionError`. Reads
  never retry. `Fingerly` warns once per process when it runs on an event
  loop, where `AsyncFingerly` belongs.
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
