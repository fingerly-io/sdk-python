"""Typed views over the payloads the events API returns.

Declared fields give editors and type checkers the documented shape. Anything
the API adds later is still reachable as an attribute through ``raw``, so a
new server field does not require an SDK upgrade.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ._errors import FingerlyError

_INSTANT = re.compile(
    r"\A(?P<date>\d{4}-\d{2}-\d{2})[Tt ](?P<clock>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?:[Zz]|(?P<sign>[+-])(?P<hours>\d{2}):?(?P<minutes>\d{2}))\Z"
)


@dataclass(frozen=True)
class EventTrigger:
    """One signal group that contributed to an event's suspect score.

    Attributes:
        signal: The signal group, such as ``vpn`` or ``bot``.
        weight: The group's combined weight in this score.
        confidence: ``low``, ``medium`` or ``high``.
    """

    signal: str
    weight: int
    confidence: Optional[str] = None


@dataclass(frozen=True)
class Event:
    """A stored identification event.

    ``suspect_score`` is ``None`` when the request was not scored, which must
    not be read as zero. ``document`` and ``deferred_signals`` are archived
    detail whose contents are deliberately opaque, not a public contract.

    Attributes:
        project_id: The Fingerly project the event belongs to, as a UUID
            string. ``None`` when an older server did not send it.
        raw: The decoded response body. Fields this SDK does not declare are
            readable as attributes through it.
    """

    request_id: str
    visitor_id: str
    occurred_at: datetime
    state: str
    environment: str
    platform: str
    sdk_platform: str
    sdk_version: str
    ip_address: str
    has_document: bool
    triggers: Sequence[EventTrigger]
    suspect_score: Optional[int] = None
    suspect_level: Optional[str] = None
    origin: Optional[str] = None
    tag: Optional[str] = None
    project_id: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    anonymity_network: Optional[str] = None
    agent: Optional[str] = None
    agent_version: Optional[str] = None
    os: Optional[str] = None
    device_kind: Optional[str] = None
    visitor_kind: Optional[str] = None
    document: Optional[Mapping[str, Any]] = None
    deferred_signals: Optional[Mapping[str, Any]] = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __getattr__(self, name: str) -> Any:
        """Reads a field the API added after this SDK was released.

        Only reached when normal attribute lookup fails, so it never shadows a
        declared field.

        Raises:
            AttributeError: If the response has no such field.
        """
        # Guard `raw` itself: reaching here for it would recurse forever.
        if name.startswith("_") or name == "raw":
            raise AttributeError(name)
        try:
            return self.raw[name]
        except KeyError:
            raise AttributeError(name) from None


@dataclass(frozen=True)
class EventPage:
    """One page of events, newest first.

    Attributes:
        rows: The events on this page.
        page: The 1-based page number returned.
        page_size: Rows per page the server applied.
    """

    rows: list[Event]
    page: int
    page_size: int


def parse_event(payload: Mapping[str, Any]) -> Event:
    """Builds an :class:`Event` from a decoded response body.

    Args:
        payload: The decoded JSON object for one event.

    Returns:
        The event, with ``occurred_at`` as a timezone-aware ``datetime``.

    Raises:
        FingerlyError: If a field the API always sends is missing or unusable.
    """
    return Event(
        request_id=_require(payload, "request_id", str),
        visitor_id=_require(payload, "visitor_id", str),
        occurred_at=parse_instant(_require(payload, "occurred_at", str)),
        state=_require(payload, "state", str),
        environment=_require(payload, "environment", str),
        platform=_require(payload, "platform", str),
        sdk_platform=_require(payload, "sdk_platform", str),
        sdk_version=_require(payload, "sdk_version", str),
        ip_address=_require(payload, "ip_address", str),
        has_document=bool(payload.get("has_document", False)),
        triggers=[_parse_trigger(row) for row in payload.get("triggers") or ()],
        suspect_score=payload.get("suspect_score"),
        suspect_level=payload.get("suspect_level"),
        origin=payload.get("origin"),
        tag=payload.get("tag"),
        project_id=payload.get("project_id"),
        country_code=payload.get("country_code"),
        country_name=payload.get("country_name"),
        asn=payload.get("asn"),
        asn_name=payload.get("asn_name"),
        anonymity_network=payload.get("anonymity_network"),
        agent=payload.get("agent"),
        agent_version=payload.get("agent_version"),
        os=payload.get("os"),
        device_kind=payload.get("device_kind"),
        visitor_kind=payload.get("visitor_kind"),
        document=payload.get("document"),
        deferred_signals=payload.get("deferred_signals"),
        raw=payload,
    )


def parse_page(payload: Mapping[str, Any]) -> EventPage:
    """Builds an :class:`EventPage` from a decoded response body.

    Raises:
        FingerlyError: If the page or any of its rows is unusable.
    """
    return EventPage(
        rows=[parse_event(row) for row in payload.get("rows") or ()],
        page=int(payload.get("page", 0)),
        page_size=int(payload.get("page_size", 0)),
    )


def parse_instant(value: str) -> datetime:
    """Parses an RFC 3339 timestamp into a timezone-aware ``datetime``.

    ``datetime.fromisoformat`` only accepts a ``Z`` suffix from Python 3.11,
    and before 3.11 it accepts only 3 or 6 fractional digits, so the timestamp
    is normalised first.

    Raises:
        FingerlyError: If the value is not an RFC 3339 timestamp.
    """
    match = _INSTANT.match(value.strip()) if isinstance(value, str) else None
    if match is None:
        raise FingerlyError(f"Not an RFC 3339 timestamp: {value!r}")
    micros = (match.group("fraction") or "").ljust(6, "0")[:6]
    offset = (
        "+00:00"
        if match.group("sign") is None
        else f"{match.group('sign')}{match.group('hours')}:{match.group('minutes')}"
    )
    return datetime.fromisoformat(
        f"{match.group('date')}T{match.group('clock')}.{micros}{offset}"
    )


def _parse_trigger(payload: Mapping[str, Any]) -> EventTrigger:
    """Builds one :class:`EventTrigger`, tolerating a missing confidence."""
    return EventTrigger(
        signal=_require(payload, "signal", str),
        weight=int(payload.get("weight", 0)),
        confidence=payload.get("confidence"),
    )


def _require(payload: Mapping[str, Any], name: str, kind: type) -> Any:
    """Reads a field the API always sends.

    Raises:
        FingerlyError: If the field is absent or of the wrong type. Defaulting
            it would hand the caller a fabricated identity to act on.
    """
    value = payload.get(name)
    if not isinstance(value, kind):
        raise FingerlyError(f"The Fingerly API response is missing {name!r}")
    return value
