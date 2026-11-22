"""Typed views over the payloads the events API returns.

Declared fields give editors and type checkers the documented shape. Anything
the API adds later is still reachable as an attribute through ``raw``, so a
new server field does not require an SDK upgrade.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Optional, TypeVar

from ._enums import Signal, VerifyReason
from ._errors import FingerlyError

_Parsed = TypeVar("_Parsed")


def _decoding(
    parse: Callable[[Mapping[str, Any]], _Parsed],
) -> Callable[[Mapping[str, Any]], _Parsed]:
    """Makes a parser raise only :class:`FingerlyError` on an unusable body.

    The parsers check every field they read, so this is the backstop: a body
    shaped in a way nobody foresaw must still surface as the SDK's own error,
    never as a ``TypeError`` or ``AttributeError`` in the caller's handler.
    """

    @functools.wraps(parse)
    def parsing(payload: Mapping[str, Any]) -> _Parsed:
        if not isinstance(payload, Mapping):
            raise FingerlyError("The Fingerly API response is unreadable")
        try:
            return parse(payload)
        except FingerlyError:
            raise
        except (TypeError, ValueError, AttributeError, KeyError, IndexError) as error:
            raise FingerlyError("The Fingerly API response is unreadable") from error

    return parsing


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
class AIVerification:
    """How an AI agent's claimed identity was checked, and what that found.

    Attributes:
        method: ``signature``, ``ip_list``, ``reverse_dns`` or ``none``, an
            :class:`AIVerificationMethod` value.
        result: ``pass``, ``fail`` or ``not_attempted``, an
            :class:`AIVerificationResult` value.
    """

    method: str
    result: str


@dataclass(frozen=True)
class AIAgent:
    """The AI agent behind an ``ai_bot`` event.

    The agent is named by a Web Bot Auth signature when the request carried
    one, otherwise by its user agent. ``verification`` says how far that was
    checked: ``AIVerificationMethod.SIGNATURE`` (the operator's published key
    signed the request) or ``AIVerificationMethod.IP_LIST`` (the address is
    inside the operator's published ranges), with result
    ``AIVerificationResult.PASS``, ``AIVerificationResult.FAIL`` (the name was
    borrowed), or ``AIVerificationResult.NOT_ATTEMPTED`` with method
    ``AIVerificationMethod.NONE`` (the operator publishes nothing to check
    against, or it could not be checked; the name is then only the client's
    claim).

    Closed sets stay typed ``str`` like the other server fields, so a value a
    newer server adds still parses.

    Attributes:
        name: The agent as its operator names it, such as ``ChatGPT-User``.
        provider: The company that operates it, such as ``OpenAI``. An open
            string, not an enum.
        purpose: What its traffic is for, an :class:`AIPurpose` value.
        runtime: Where it runs, an :class:`AIRuntime` value.
        declared: True when the agent named itself, in its user agent or a
            signature.
        verification: How its claim was checked, and what that found.
    """

    name: str
    provider: str
    purpose: str
    runtime: str
    declared: bool
    verification: AIVerification


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
    :class:`Environment`, ``suspect_level`` with :class:`SuspectLevel`,
    ``visitor_kind`` with :class:`VisitorKind`.

    Attributes:
        project_id: The Fingerly project the event belongs to, as a UUID
            string. ``None`` when an older server did not send it.
        ai: The AI agent, present only when ``visitor_kind`` is
            ``VisitorKind.AI_BOT``; ``None`` otherwise.
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
    ai: Optional[AIAgent] = None
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


@dataclass(frozen=True)
class AgentSighting:
    """One request your server served, reported as raw input.

    Sent by :meth:`Agents.sightings`. Nothing is decided about the visitor
    before it is sent: the server classifies it.

    Attributes:
        user_agent: The ``User-Agent`` header as received, ``""`` when the
            request had none. At most 4096 bytes.
        client_ip: The visitor's address from infrastructure you trust: one
            IPv4 or IPv6 literal, never a forwarded list.
        host: The ``Host`` the request was sent to.
        method: The request method; the server reads ``GET`` when absent.
        signature: The ``Signature`` header, when the request had one.
        signature_input: The ``Signature-Input`` header, when it had one.
        signature_agent: The ``Signature-Agent`` header, when it had one.
        count: How many times this exact request was served since it was last
            reported, this one included; the server reads 1 when absent.
    """

    user_agent: str
    client_ip: str
    host: Optional[str] = None
    method: Optional[str] = None
    signature: Optional[str] = None
    signature_input: Optional[str] = None
    signature_agent: Optional[str] = None
    count: Optional[int] = None

    def to_wire(self) -> dict[str, Any]:
        """The JSON object the API reads, without the fields left unset."""
        wire: dict[str, Any] = {
            "user_agent": self.user_agent,
            "client_ip": self.client_ip,
        }
        for name in (
            "host",
            "method",
            "signature",
            "signature_input",
            "signature_agent",
            "count",
        ):
            value = getattr(self, name)
            if value is not None:
                wire[name] = value
        return wire


@dataclass(frozen=True)
class AgentAnswer:
    """What the server said sent one reported request.

    Compare ``visitor_kind`` with :class:`VisitorKind` members and
    ``ai.verification.result`` with :class:`AIVerificationResult` members.
    :data:`AGENT_UNKNOWN` is the answer for a request the server has not
    answered yet: serve it as usual.

    Attributes:
        ttl: Seconds the answer may be reused for the same user agent, address
            and ``Signature-Agent``; 0 for a signed request, checked every time.
        visitor_kind: ``human``, ``ai_bot``, ``automation`` or
            ``search_crawler``, kept as sent so a newer value still parses;
            ``""`` only on :data:`AGENT_UNKNOWN`.
        agent: The agent's name where the server knows it, such as ``GPTBot``.
        ai: The AI agent, present only when ``visitor_kind`` is
            ``VisitorKind.AI_BOT``.
    """

    ttl: int
    visitor_kind: str
    agent: Optional[str] = None
    ai: Optional[AIAgent] = None

    @property
    def known(self) -> bool:
        """False for :data:`AGENT_UNKNOWN`, True for a server answer."""
        return self is not AGENT_UNKNOWN


#: The answer when the server has not answered for a request yet, or it could
#: not be reported. Treat it as "serve as usual". Compare with ``is``.
AGENT_UNKNOWN = AgentAnswer(ttl=0, visitor_kind="")


@dataclass(frozen=True)
class AgentSightingsResult:
    """The server's answer to :meth:`Agents.sightings`.

    Attributes:
        rules_version: Names the classification rules. When it changes, every
            remembered answer is stale.
        items: One answer per reported request, in the order sent;
            :data:`AGENT_UNKNOWN` where the server's answer could not be read.
    """

    rules_version: str
    items: Sequence[AgentAnswer]


@_decoding
def parse_agent_sightings(payload: Mapping[str, Any]) -> AgentSightingsResult:
    """Builds :class:`AgentSightingsResult` from a sightings answer.

    An item that cannot be read, such as one without an integer ``ttl`` or a
    string ``visitor_kind``, is :data:`AGENT_UNKNOWN` in its position, so the
    other answers still line up with the requests they answer.

    Raises:
        FingerlyError: If ``rules_version`` or ``items`` is missing.
    """
    rules_version = _require(payload, "rules_version", str)
    items = _require(payload, "items", list)
    return AgentSightingsResult(
        rules_version=rules_version,
        items=tuple(_agent_answer(item) for item in items),
    )


def _agent_answer(item: Any) -> AgentAnswer:
    """One answer of a sightings report, or :data:`AGENT_UNKNOWN` if unreadable."""
    if not isinstance(item, Mapping):
        return AGENT_UNKNOWN
    ttl = item.get("ttl")
    visitor_kind = item.get("visitor_kind")
    if (
        not isinstance(ttl, int)
        or isinstance(ttl, bool)
        or not isinstance(visitor_kind, str)
    ):
        return AGENT_UNKNOWN
    agent = item.get("agent")
    return AgentAnswer(
        ttl=ttl,
        visitor_kind=visitor_kind,
        agent=agent if isinstance(agent, str) and agent else None,
        ai=_parse_ai(item.get("ai")),
    )


@_decoding
def parse_consume(payload: Mapping[str, Any]) -> ConsumeResult:
    """Builds :class:`ConsumeResult` from a consume answer."""
    return ConsumeResult(
        request_id=_require(payload, "request_id", str),
        consumed_at=_require(payload, "consumed_at", str),
        first=_require(payload, "first", bool),
    )


_UNKNOWN_INSTANT = datetime.min.replace(tzinfo=timezone.utc)


@_decoding
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


@_decoding
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


@_decoding
def parse_device_check_write(payload: Mapping[str, Any]) -> DeviceCheckWriteResult:
    """Builds :class:`DeviceCheckWriteResult` from a write answer."""
    bit0, bit1 = payload.get("bit0"), payload.get("bit1")
    return DeviceCheckWriteResult(
        bit0=bit0 if isinstance(bit0, bool) else None,
        bit1=bit1 if isinstance(bit1, bool) else None,
    )


@_decoding
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
        has_document=_flag(payload, "has_document"),
        triggers=[_parse_trigger(row) for row in _list(payload, "triggers")],
        reason=_optional(payload, "reason", str),
        suspect_score=_optional(payload, "suspect_score", int),
        suspect_level=_optional(payload, "suspect_level", str),
        origin=_optional(payload, "origin", str),
        url_host=_optional(payload, "url_host", str),
        url_path=_optional(payload, "url_path", str),
        tag=_optional(payload, "tag", str),
        project_id=_optional(payload, "project_id", str),
        ip_network=_optional(payload, "ip_network", str) or None,
        country_code=_optional(payload, "country_code", str),
        country_name=_optional(payload, "country_name", str),
        asn=_optional(payload, "asn", str),
        asn_name=_optional(payload, "asn_name", str),
        anonymity_network=_optional(payload, "anonymity_network", str),
        agent=_optional(payload, "agent", str),
        agent_version=_optional(payload, "agent_version", str),
        os=_optional(payload, "os", str),
        device_kind=_optional(payload, "device_kind", str),
        visitor_kind=_optional(payload, "visitor_kind", str),
        ai=_parse_ai(payload.get("ai")),
        document=_optional(payload, "document", Mapping),
        raw=payload,
    )


@_decoding
def parse_page(payload: Mapping[str, Any]) -> EventPage:
    """Builds an :class:`EventPage` from a decoded response body.

    Raises:
        FingerlyError: If the page or any of its rows is unusable.
    """
    return EventPage(
        rows=[parse_event(row) for row in _list(payload, "rows")],
        page=_integer(payload, "page", 0),
        page_size=_integer(payload, "page_size", 0),
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
    try:
        return datetime.fromisoformat(
            f"{match.group('date')}T{match.group('clock')}.{micros}{offset}"
        )
    except ValueError:
        # Shaped right, but no such instant, such as month 13.
        raise FingerlyError(f"Not an RFC 3339 timestamp: {value!r}") from None


@_decoding
def parse_document(payload: Mapping[str, Any]) -> EventDocument:
    """Builds an :class:`EventDocument` from an archived document mapping."""
    sdk_raw = payload.get("sdk")
    sdk: Mapping[str, Any] = sdk_raw if isinstance(sdk_raw, Mapping) else {}
    att_raw = payload.get("attestation")
    attestation = _parse_attestation(att_raw) if isinstance(att_raw, Mapping) else None
    return EventDocument(
        schema=_integer(payload, "schema", 1),
        request_id=_require(payload, "request_id", str),
        occurred_at=parse_instant(_require(payload, "occurred_at", str)),
        sdk_platform=_text(sdk, "platform"),
        sdk_version=_text(sdk, "version"),
        ip_network=_optional(payload, "ip_network", str) or None,
        ip=_optional(payload, "ip", Mapping),
        ip_error=_optional(payload, "ip_error", str),
        risk=_optional(payload, "risk", Mapping),
        attestation=attestation,
        velocity=_optional(payload, "velocity", Mapping),
        raw=payload,
    )


def _parse_attestation(payload: Mapping[str, Any]) -> Attestation:
    """Builds an :class:`Attestation` from an archived attestation mapping."""
    play = payload.get("play_integrity")
    return Attestation(
        state=_require(payload, "state", str),
        status=_require(payload, "status", str),
        platform=_optional(payload, "platform", str),
        reason=_optional(payload, "reason", str),
        chain_length=_optional(payload, "chain_length", int),
        attestation_security_level=_optional(
            payload, "attestation_security_level", str
        ),
        keymint_security_level=_optional(payload, "keymint_security_level", str),
        device_locked=_optional(payload, "device_locked", bool),
        verified_boot_state=_optional(payload, "verified_boot_state", str),
        nonce=_optional(payload, "nonce", str),
        revocation_checked=_flag(payload, "revocation_checked"),
        package_bound=_flag(payload, "package_bound"),
        signer_bound=_flag(payload, "signer_bound"),
        attest_skipped=_optional(payload, "attest_skipped", str),
        downgrade=_flag(payload, "downgrade"),
        mode=_optional(payload, "mode", str),
        app_id=_optional(payload, "app_id", str),
        environment=_optional(payload, "environment", str),
        receipt=_optional(payload, "receipt", str),
        risk_metric=_optional(payload, "risk_metric", int),
        risk_metric_age_h=_optional(payload, "risk_metric_age_h", int),
        device_check=_optional(payload, "device_check", str),
        play_integrity=play if isinstance(play, Mapping) else None,
        raw=payload,
    )


def _parse_ai(payload: Any) -> Optional[AIAgent]:
    """Builds the :class:`AIAgent` of an ``ai_bot`` event, or None when absent.

    Values are kept as sent, so an unknown purpose, runtime or verification
    value parses.
    """
    if not isinstance(payload, Mapping):
        return None
    verification_raw = payload.get("verification")
    verification: Mapping[str, Any] = (
        verification_raw if isinstance(verification_raw, Mapping) else {}
    )
    return AIAgent(
        name=_text(payload, "name"),
        provider=_text(payload, "provider"),
        purpose=_text(payload, "purpose"),
        runtime=_text(payload, "runtime"),
        declared=_flag(payload, "declared"),
        verification=AIVerification(
            method=_text(verification, "method"),
            result=_text(verification, "result"),
        ),
    )


def _parse_trigger(payload: Any) -> EventTrigger:
    """Builds one :class:`EventTrigger`, tolerating a missing confidence."""
    if not isinstance(payload, Mapping):
        raise FingerlyError("The Fingerly API response has an unreadable trigger")
    return EventTrigger(
        signal=_require(payload, "signal", str),
        weight=_integer(payload, "weight", 0),
        confidence=_optional(payload, "confidence", str),
    )


def _optional(payload: Mapping[str, Any], name: str, kind: type) -> Any:
    """Reads a field the API may leave out, or None.

    A value of another type is dropped too, so a field never holds anything
    but the type it is declared with; ``raw`` still has what was sent.
    """
    value = payload.get(name)
    if isinstance(value, bool) and kind is not bool:
        return None
    return value if isinstance(value, kind) else None


def _text(payload: Mapping[str, Any], name: str) -> str:
    """Reads a string field, or ``""`` when it is absent or not a string."""
    value = payload.get(name)
    return value if isinstance(value, str) else ""


def _flag(payload: Mapping[str, Any], name: str) -> bool:
    """Reads a boolean field; anything but ``true`` is False."""
    return payload.get(name) is True


def _integer(payload: Mapping[str, Any], name: str, default: int) -> int:
    """Reads an integer field, or ``default`` when it is absent or unusable."""
    value = payload.get(name)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default


def _list(payload: Mapping[str, Any], name: str) -> list[Any]:
    """Reads a list field, empty when absent.

    Raises:
        FingerlyError: If the field holds something other than a list.
    """
    value = payload.get(name)
    if value is None:
        return []
    if not isinstance(value, list):
        raise FingerlyError(f"The Fingerly API response has an unreadable {name!r}")
    return value


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
