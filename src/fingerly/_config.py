"""Validation and normalisation of caller-supplied configuration.

Everything here runs before any network access, so a misconfigured client
fails at construction, never mid-request and never against the wrong host.
"""

from __future__ import annotations

import math
import re
from typing import NamedTuple
from urllib.parse import urlsplit

#: Anchored with ``\A``/``\Z`` because Python's ``$`` also matches before a
#: trailing newline, which would let ``"fly_sk_production_x\n"`` through.
_KEY = re.compile(r"\Afly_(pk|sk|px)_(production|staging|development)_[A-Za-z0-9_-]+\Z")

#: The one Fingerly API origin.
DEFAULT_ENDPOINT = "https://api.fingerly.io"

_KEY_LABEL: dict[str, str] = {"pk": "public", "sk": "secret", "px": "proxy"}

_API_VERSION = re.compile(r"\Av[1-9][0-9]*\Z")


REDACTED = "[redacted]"


class Secret:
    """A credential that never prints.

    Held instead of the raw string, so ``repr``, ``vars``, debuggers, error
    trackers that dump object state and accidental logging all show
    ``[redacted]``. Pickling is refused rather than writing the key out.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """The credential itself, for the one header that carries it."""
        return self._value

    def __repr__(self) -> str:
        return REDACTED

    __str__ = __repr__

    def __reduce__(self) -> str:
        raise TypeError("A Fingerly credential cannot be pickled")


class KeyScope(NamedTuple):
    """The environment a Fingerly key is scoped to.

    Attributes:
        environment: ``production``, ``staging`` or ``development``.
    """

    environment: str


def parse_key(key: str, expected: str) -> KeyScope:
    """Parses a Fingerly key and asserts it is of the expected kind.

    Args:
        key: The raw key, such as ``fly_sk_production_…``.
        expected: The kind the caller requires: ``pk``, ``sk`` or ``px``.

    Returns:
        The environment the key is scoped to.

    Raises:
        TypeError: If the key is malformed or of another kind.
    """
    match = _KEY.match(key) if isinstance(key, str) else None
    if match is None or match.group(1) != expected:
        raise TypeError(f"A valid Fingerly {_KEY_LABEL[expected]} key is required")
    return KeyScope(environment=match.group(2))


def normalize_endpoint(value: str) -> str:
    """Normalises a caller-supplied API origin.

    Credentials, queries and fragments are refused: they would be attached to
    every authenticated request, and embedded credentials would leak on a
    redirect.

    Args:
        value: An HTTP(S) origin, optionally with a base path.

    Returns:
        The origin without trailing slashes.

    Raises:
        TypeError: If the URL is malformed or carries any of the above.
    """
    if not isinstance(value, str):
        raise TypeError("endpoint must be a string")
    parts = urlsplit(value)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise TypeError(
            "endpoint must be an HTTP(S) URL without credentials, query, or fragment"
        )
    return value.rstrip("/")


def normalize_api_version(version: str = "v1") -> str:
    """Validates an API route version before it is spliced into a URL.

    Args:
        version: A version such as ``v1``.

    Raises:
        TypeError: If the version is not of that shape.
    """
    if not isinstance(version, str) or not _API_VERSION.match(version):
        raise TypeError('api_version must be a version such as "v1" or "v2"')
    return version


def positive_seconds(value: float, name: str) -> float:
    """Validates a duration option expressed in seconds.

    Args:
        value: The caller-supplied duration.
        name: The option name, used in the error message.

    Raises:
        TypeError: If the value is not a positive, finite number.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number of seconds")
    if not math.isfinite(value) or value <= 0:
        raise TypeError(f"{name} must be a positive, finite number of seconds")
    return float(value)


def positive_int(value: int, name: str) -> int:
    """Validates a count option.

    Args:
        value: The caller-supplied count.
        name: The option name, used in the error message.

    Raises:
        TypeError: If the value is not a positive integer.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{name} must be a positive integer")
    return value
