"""Request building and response interpretation.

These are plain functions with no I/O, so the synchronous and asyncio clients
share one definition of what a request looks like and what a failure means.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional, Union
from urllib.parse import quote

from ._config import positive_int
from ._errors import FingerlyAPIError

#: Sent on every request so events record which SDK build made them.
USER_AGENT = "fingerly-python/0.1.0"

_REDACTED = "[redacted]"


def headers_for(secret_key: str) -> dict[str, str]:
    """Builds the headers every authenticated request carries.

    Args:
        secret_key: The server-only read key.
    """
    return {
        "x-api-key": secret_key,
        "accept": "application/json",
        "user-agent": USER_AGENT,
    }


def event_path(request_id: str) -> str:
    """Builds the path for one event, encoding the id into a single segment.

    Args:
        request_id: The ``request_id`` returned by identification.
    """
    return f"/events/{quote(str(request_id), safe='')}"


def list_params(
    from_: Union[datetime, str, None],
    to: Union[datetime, str, None],
    page: Optional[int],
    limit: Optional[int],
    visitor: Optional[str],
    level: Optional[str],
) -> dict[str, str]:
    """Builds the query for a listing, omitting filters the caller left unset.

    Returns:
        The query parameters as strings, ready for httpx.

    Raises:
        TypeError: If a bound, page or limit is unusable.
    """
    params: dict[str, str] = {}
    if from_ is not None:
        params["from"] = rfc3339(from_, "from_")
    if to is not None:
        params["to"] = rfc3339(to, "to")
    if page is not None:
        params["page"] = str(positive_int(page, "page"))
    if limit is not None:
        params["limit"] = str(positive_int(limit, "limit"))
    if visitor is not None:
        params["visitor"] = str(visitor)
    if level is not None:
        params["level"] = str(level)
    return params


def rfc3339(value: Union[datetime, str], name: str) -> str:
    """Renders a window bound in the RFC 3339 form the API expects.

    A naive ``datetime`` is read as UTC, because the API only accepts an
    absolute instant and guessing the caller's local zone would silently shift
    the window.

    Args:
        value: A ``datetime``, or a string to pass through unchanged.
        name: The argument name, used in the error message.

    Raises:
        TypeError: If the value is neither a ``datetime`` nor a string.
    """
    if isinstance(value, str):
        return value
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime or an RFC 3339 string")
    moment = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def decode_json(body: bytes, status: int = 200) -> Mapping[str, Any]:
    """Decodes a successful response body.

    Args:
        body: The raw response body.
        status: The response's HTTP status, carried into any error.

    Raises:
        FingerlyAPIError: If the body is not a JSON object, which means the
            response did not come from the Fingerly API. The body itself is
            never echoed.
    """
    try:
        payload = json.loads(body)
    except ValueError as error:
        raise FingerlyAPIError(
            "Fingerly API returned a non-JSON body", status
        ) from error
    if not isinstance(payload, dict):
        raise FingerlyAPIError("Fingerly API returned an unexpected body", status)
    return payload


def retry_after_seconds(
    value: Optional[str], now: Optional[datetime] = None
) -> Optional[float]:
    """Parses ``Retry-After`` into seconds from now.

    Both forms HTTP allows are read: a number of seconds and an HTTP date. A
    date in the past is zero seconds.

    Args:
        value: The header, or None when the response had none.
        now: Current time; override only in tests.

    Returns:
        The seconds to wait, or None when the header is absent or unreadable.
    """
    if value is None:
        return None
    text = value.strip()
    if text.isdigit():
        return float(text)
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    current = now if now is not None else datetime.now(timezone.utc)
    return max(0.0, (moment - current).total_seconds())


def api_error(
    status: int, body: bytes, secret_key: str, retry_after: Optional[str] = None
) -> FingerlyAPIError:
    """Maps an error response to a redacted :class:`FingerlyAPIError`.

    The raw body is never surfaced: only the status, and the structured fields
    the API documents, with the secret key stripped from each.

    Args:
        status: The HTTP status code.
        body: The raw response body, which may be empty or not JSON at all.
        secret_key: The key to redact from anything carried into logs.
        retry_after: The ``Retry-After`` header, when the response had one.
    """
    code: Optional[str] = None
    details: Any = None
    request_id: Optional[str] = None
    try:
        payload = json.loads(body)
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            code = _redact(error["code"], secret_key)
        if isinstance(error, dict) and error.get("details") is not None:
            # A JSON round-trip redacts nested values without walking the tree.
            details = json.loads(_redact(json.dumps(error["details"]), secret_key))
        if isinstance(payload, dict) and isinstance(payload.get("request_id"), str):
            request_id = _redact(payload["request_id"], secret_key)
    except ValueError:
        # A non-JSON body still reports its HTTP status, and its contents are
        # deliberately dropped rather than surfaced.
        pass
    return FingerlyAPIError(
        f"Fingerly API returned HTTP {status}",
        status,
        code=code,
        details=details,
        request_id=request_id,
        retry_after=retry_after_seconds(retry_after),
    )


def _redact(value: str, secret_key: str) -> str:
    """Strips the secret key from anything an error may carry to logs."""
    return value.replace(secret_key, _REDACTED) if secret_key else value
