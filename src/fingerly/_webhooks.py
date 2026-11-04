"""Webhook signature verification.

Stateless, synchronous and usable from both clients: verifying a delivery is
one HMAC over bytes you already have, so there is nothing to await.
"""

from __future__ import annotations

import hmac
import re
from datetime import datetime, timezone
from hashlib import sha256
from typing import Optional, Union

DEFAULT_TOLERANCE_SECONDS = 300

#: Signatures read from one header. A rotation sends two or three; past this
#: many the rest are ignored, so a huge header costs no more than this.
MAX_SIGNATURES = 32

#: A lowercase hex digest, exactly as Fingerly sends it.
_SIGNATURE = re.compile(r"\Asha256=[a-f0-9]{64}\Z")

#: Whole unsigned seconds; anything else is not a timestamp Fingerly signed.
_TIMESTAMP = re.compile(r"\A[0-9]+\Z")

_PREFIX_LENGTH = len("sha256=")


def verify_webhook(
    secret: str,
    payload: Union[str, bytes],
    timestamp: Optional[str],
    signature: Optional[str],
    tolerance_seconds: float = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[datetime] = None,
) -> bool:
    """Verifies a webhook delivery against the raw request body.

    Pass the exact bytes received, before any JSON parsing: re-serialising
    them changes the digest. During a signing-secret rotation Fingerly sends
    several comma-separated signatures, and any one matching is accepted.
    Only the first 32 are read.

    Verification proves the delivery came from Fingerly and is recent. It does
    not deduplicate, so persist processed event ids as well.

    Args:
        secret: The endpoint's signing secret.
        payload: The raw request body.
        timestamp: The ``x-fingerly-timestamp`` header.
        signature: The ``x-fingerly-signature`` header.
        tolerance_seconds: Replay window, in seconds.
        now: Current time; override only in tests.

    Returns:
        True when a signature matches and the timestamp is within tolerance.
        Malformed or missing input returns False rather than raising, so a
        handler can reject a bad delivery without a try block.
    """
    if not isinstance(secret, (str, bytes)) or not secret:
        return False
    if not isinstance(signature, str) or not isinstance(timestamp, str):
        return False
    if not isinstance(payload, (str, bytes, bytearray)):
        return False

    # Check freshness before spending an HMAC on an obvious replay.
    if not _is_fresh(timestamp, now, tolerance_seconds):
        return False

    expected = _sign(secret, timestamp, payload)
    candidates = signature.split(",", MAX_SIGNATURES)[:MAX_SIGNATURES]
    return any(_matches(candidate, expected) for candidate in candidates)


def _is_fresh(
    timestamp: str, now: Optional[datetime], tolerance_seconds: float
) -> bool:
    """Rejects replays: the signed time must be within tolerance of now."""
    if not _TIMESTAMP.match(timestamp):
        return False
    if isinstance(tolerance_seconds, bool) or not isinstance(
        tolerance_seconds, (int, float)
    ):
        return False
    if tolerance_seconds < 0 or tolerance_seconds != tolerance_seconds:  # NaN
        return False
    if now is not None and not isinstance(now, datetime):
        return False

    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return abs(moment.timestamp() - int(timestamp)) <= tolerance_seconds


def _sign(
    secret: Union[str, bytes], timestamp: str, payload: Union[str, bytes, bytearray]
) -> bytes:
    """Computes the expected digest.

    Fingerly signs the timestamp, a literal dot, then the raw body bytes.

    Returns:
        The hex digest as ASCII bytes, ready for a constant-time compare.
    """
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    body = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    mac = hmac.new(key, f"{timestamp}.".encode(), sha256)
    mac.update(body)
    return mac.hexdigest().encode("ascii")


def _matches(candidate: str, expected: bytes) -> bool:
    """Compares one candidate signature in constant time."""
    value = candidate.strip()
    if not _SIGNATURE.match(value):
        return False
    return hmac.compare_digest(value[_PREFIX_LENGTH:].encode("ascii"), expected)
