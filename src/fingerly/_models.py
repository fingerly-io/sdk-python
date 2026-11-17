"""Typed views over the payloads the events API returns.

Declared fields give editors and type checkers the documented shape. Anything
the API adds later is still reachable as an attribute through ``raw``, so a
new server field does not require an SDK upgrade.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Optional

from ._enums import Signal, VerifyReason
from ._errors import FingerlyError

_INSTANT = re.compile(
    r"\A(?P<date>\d{4}-\d{2}-\d{2})[Tt ](?P<clock>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?:[Zz]|(?P<sign>[+-])(?P<hours>\d{2}):?(?P<minutes>\d{2}))\Z"
)

#: Every :class:`Signal` value, in declaration order. Kept for callers that
#: want plain strings; prefer the :class:`Signal` members.
SIGNAL_NAMES: tuple[str, ...] = tuple(signal.value for signal in Signal)


@dataclass(frozen=True)
class EventTrigger:
    """One signal group that contributed to an event's suspect score.

    Attributes:
        signal: The signal group, such as ``vpn``, ``bot`` or
            ``attestation_failed``; compare with :class:`Signal` members.
        weight: The group's combined weight in this score.
        confidence: ``low``, ``medium`` or ``high``, a :class:`Confidence`
            value.
    """

    signal: str
    weight: int
    confidence: Optional[str] = None


@dataclass(frozen=True)
class Attestation:
    """Platform-neutral hardware attestation verdict from an archived document.

    Attributes:
        state: ``attested``, ``not_attested`` or ``failed``, an
            :class:`AttestationState` value.
        status: ``verified``, ``indeterminate``, ``invalid``, ``absent`` or
            ``unconfigured``, an :class:`AttestationStatus` value.
        attest_skipped: Native only: the app's own reason for sending no
            attestation, an :class:`AttestSkippedReason` value such as
            ``not_offered``, ``unsupported`` or ``timeout``. Diagnostic only;
            it never lowers the score.
        downgrade: Native only: an unproven or rejected report named an
            install an attested device owns, so it was answered
            unidentifiable.
    """

    state: str
    status: str
    platform: Optional[str] = None
    reason: Optional[str] = None
    chain_length: Optional[int] = None
    attestation_security_level: Optional[str] = None
    keymint_security_level: Optional[str] = None
    device_locked: Optional[bool] = None
    verified_boot_state: Optional[str] = None
    nonce: Optional[str] = None
    revocation_checked: bool = False
    package_bound: bool = False
    signer_bound: bool = False
    attest_skipped: Optional[str] = None
    downgrade: bool = False
    mode: Optional[str] = None
    app_id: Optional[str] = None
    environment: Optional[str] = None
    receipt: Optional[str] = None
    risk_metric: Optional[int] = None
    risk_metric_age_h: Optional[int] = None
    device_check: Optional[str] = None
    play_integrity: Optional[Mapping[str, Any]] = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class EventDocument:
    """Allow-listed view of an archived identification submission."""

    schema: int
    request_id: str
    occurred_at: datetime
    sdk_platform: str
    sdk_version: str
    ip_network: Optional[str] = None
    ip: Optional[Mapping[str, Any]] = None
    ip_error: Optional[str] = None
    risk: Optional[Mapping[str, Any]] = None
    attestation: Optional[Attestation] = None
    velocity: Optional[Mapping[str, Any]] = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class Event:
    """A stored identification event.

    ``suspect_score`` is ``None`` when the request was not scored, which must
    not be read as zero. ``visitor_id`` is ``""`` when the submission was
    unidentifiable (``identifiable == false``). ``ip_network`` is the network
    the request came from (an IPv4 /24 or an IPv6 /40, such as
    ``203.0.113.0/24``); the API never returns the address. ``document`` is an
    allow-listed view of the archived request (schema, request id, time, SDK,
    network, IP classification and city-level location, risk, attestation and
    velocity), with no raw signals, user agent or address.

    Closed string sets stay typed ``str`` and hold the value as sent, so a
    value a newer server adds still parses. Compare them with the enum
    members: ``state`` with :class:`EventState`, ``environment`` with
    :class:`Environment`, ``suspect_level`` with :class:`SuspectLevel`.

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
    has_document: bool
    triggers: Sequence[EventTrigger]
    reason: Optional[str] = None
    suspect_score: Optional[int] = None
    suspect_level: Optional[str] = None
    origin: Optional[str] = None
    url_host: Optional[str] = None
    url_path: Optional[str] = None
    tag: Optional[str] = None
    project_id: Optional[str] = None
    ip_network: Optional[str] = None
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
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @property
    def identifiable(self) -> bool:
        """Whether this event resolved to a non-empty visitor identifier."""
        return bool(self.visitor_id)

    def parse_document(self) -> Optional[EventDocument]:
        """Parses ``document`` into a typed :class:`EventDocument`, if present."""
        if self.document is None:
            return None
        return parse_document(self.document)

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


@dataclass(frozen=True)
class DeviceCheckBits:
    """What Apple holds for the device behind an iOS event.

    The bits mean what you decided they mean; Fingerly never reads them.

    Attributes:
        found: False when Apple holds no bits for the device yet. Both bits
            are then False.
        bit0: The first bit.
        bit1: The second bit.
        last_update: When the bits last changed, as ``YYYY-MM``, or None when
            Apple holds no bits.
    """

    found: bool
    bit0: bool
    bit1: bool
    last_update: Optional[str] = None


@dataclass(frozen=True)
class DeviceCheckWriteResult:
    """The bits Apple accepted on a write.

    Attributes:
        bit0: The value set for the first bit, or None when it was left out.
        bit1: The value set for the second bit, or None when it was left out.
    """

    bit0: Optional[bool] = None
    bit1: Optional[bool] = None


@dataclass(frozen=True)
class ConsumeResult:
    """The answer to consuming an event.

    Attributes:
        request_id: The consumed event's request id.
        consumed_at: When it was consumed, as the RFC 3339 string the API sent.
        first: True when this call consumed it.
    """

    request_id: str
    consumed_at: str
    first: bool


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of :meth:`Events.verify`.

    Attributes:
        ok: True when every check passed, and the event was consumed unless
            ``consume=False``.
        reason: A :class:`VerifyReason` member: ``VerifyReason.OK`` (``""``)
            when ``ok``; otherwise the first check that failed: ``not_found``,
            ``too_old``, ``tag_mismatch``, ``unidentifiable``, ``unscored`` or
            ``already_consumed``. It compares equal to those strings.
        event: The event read, or None only for ``not_found``. When its
            ``occurred_at`` was missing or unreadable (reason ``too_old``),
            ``event.occurred_at`` is the earliest UTC ``datetime`` and
            ``event.raw`` holds what the API sent.
    """

    ok: bool
    reason: VerifyReason
    event: Optional[Event] = None


def parse_consume(payload: Mapping[str, Any]) -> ConsumeResult:
    """Builds :class:`ConsumeResult` from a consume answer."""
    return ConsumeResult(
        request_id=_require(payload, "request_id", str),
        consumed_at=_require(payload, "consumed_at", str),
        first=_require(payload, "first", bool),
    )


_UNKNOWN_INSTANT = datetime.min.replace(tzinfo=timezone.utc)


def parse_verified_event(
    payload: Mapping[str, Any],
) -> tuple[Event, Optional[datetime]]:
    """Builds the event ``verify`` checks, tolerating what the checks judge.

    A missing ``visitor_id`` reads as ``""`` (unidentifiable), and a missing or
    unreadable ``occurred_at`` as the earliest instant, so either becomes a
    failed check instead of an exception.

    Returns:
        The event, and its ``occurred_at`` or None when it was unusable.
    """
    occurred: Optional[datetime]
    try:
        occurred = parse_instant(payload.get("occurred_at"))  # type: ignore[arg-type]
    except (FingerlyError, ValueError):
        occurred = None
    patched = dict(payload)
    patched["occurred_at"] = "0001-01-01T00:00:00Z"
    if not isinstance(patched.get("visitor_id"), str):
        patched["visitor_id"] = ""
    event = replace(
        parse_event(patched),
        occurred_at=occurred if occurred is not None else _UNKNOWN_INSTANT,
        raw=payload,
    )
    return event, occurred


def failed_check(
    event: Event,
    occurred: Optional[datetime],
    now: datetime,
    max_age_seconds: int,
    tag: Optional[str],
) -> VerifyReason:
    """The first of ``verify``'s checks before consumption that fails, or ``""``.

    The order is fixed: age, tag, identifiability, scoring. The score's value,
    level and triggers are never looked at.
    """
    if occurred is None or (now - occurred).total_seconds() > max_age_seconds:
        return VerifyReason.TOO_OLD
    if tag is not None and (event.tag or "") != tag:
        return VerifyReason.TAG_MISMATCH
    if not event.visitor_id:
        return VerifyReason.UNIDENTIFIABLE
    if event.suspect_score is None:
        return VerifyReason.UNSCORED
    return VerifyReason.OK


def parse_device_check_bits(payload: Mapping[str, Any]) -> DeviceCheckBits:
    """Builds :class:`DeviceCheckBits` from a query answer."""
    last_update = payload.get("last_update")
    return DeviceCheckBits(
        found=_require(payload, "found", bool),
        bit0=_require(payload, "bit0", bool),
        bit1=_require(payload, "bit1", bool),
        last_update=last_update
        if isinstance(last_update, str) and last_update
        else None,
    )


def parse_device_check_write(payload: Mapping[str, Any]) -> DeviceCheckWriteResult:
    """Builds :class:`DeviceCheckWriteResult` from a write answer."""
    bit0, bit1 = payload.get("bit0"), payload.get("bit1")
    return DeviceCheckWriteResult(
        bit0=bit0 if isinstance(bit0, bool) else None,
        bit1=bit1 if isinstance(bit1, bool) else None,
    )


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
        has_document=bool(payload.get("has_document", False)),
        triggers=[_parse_trigger(row) for row in payload.get("triggers") or ()],
        reason=payload.get("reason"),
        suspect_score=payload.get("suspect_score"),
        suspect_level=payload.get("suspect_level"),
        origin=payload.get("origin"),
        url_host=payload.get("url_host"),
        url_path=payload.get("url_path"),
        tag=payload.get("tag"),
        project_id=payload.get("project_id"),
        ip_network=payload.get("ip_network") or None,
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


def parse_document(payload: Mapping[str, Any]) -> EventDocument:
    """Builds an :class:`EventDocument` from an archived document mapping."""
    sdk_raw = payload.get("sdk")
    sdk: Mapping[str, Any] = sdk_raw if isinstance(sdk_raw, Mapping) else {}
    att_raw = payload.get("attestation")
    attestation = _parse_attestation(att_raw) if isinstance(att_raw, Mapping) else None
    return EventDocument(
        schema=int(payload.get("schema", 1)),
        request_id=_require(payload, "request_id", str),
        occurred_at=parse_instant(_require(payload, "occurred_at", str)),
        sdk_platform=str(sdk.get("platform", "")),
        sdk_version=str(sdk.get("version", "")),
        ip_network=payload.get("ip_network") or None,
        ip=payload.get("ip") if isinstance(payload.get("ip"), Mapping) else None,
        ip_error=payload.get("ip_error"),
        risk=payload.get("risk") if isinstance(payload.get("risk"), Mapping) else None,
        attestation=attestation,
        velocity=(
            payload.get("velocity")
            if isinstance(payload.get("velocity"), Mapping)
            else None
        ),
        raw=payload,
    )


def _parse_attestation(payload: Mapping[str, Any]) -> Attestation:
    """Builds an :class:`Attestation` from an archived attestation mapping."""
    play = payload.get("play_integrity")
    return Attestation(
        state=_require(payload, "state", str),
        status=_require(payload, "status", str),
        platform=payload.get("platform"),
        reason=payload.get("reason"),
        chain_length=payload.get("chain_length"),
        attestation_security_level=payload.get("attestation_security_level"),
        keymint_security_level=payload.get("keymint_security_level"),
        device_locked=payload.get("device_locked"),
        verified_boot_state=payload.get("verified_boot_state"),
        nonce=payload.get("nonce"),
        revocation_checked=bool(payload.get("revocation_checked", False)),
        package_bound=bool(payload.get("package_bound", False)),
        signer_bound=bool(payload.get("signer_bound", False)),
        attest_skipped=payload.get("attest_skipped"),
        downgrade=bool(payload.get("downgrade", False)),
        mode=payload.get("mode"),
        app_id=payload.get("app_id"),
        environment=payload.get("environment"),
        receipt=payload.get("receipt"),
        risk_metric=payload.get("risk_metric"),
        risk_metric_age_h=payload.get("risk_metric_age_h"),
        device_check=payload.get("device_check"),
        play_integrity=play if isinstance(play, Mapping) else None,
        raw=payload,
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
