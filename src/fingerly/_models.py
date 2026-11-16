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

#: Canonical v3 risk signal and signal-group names reported in event triggers
#: and archived risk assessments.
SIGNAL_NAMES: tuple[str, ...] = (
    "tor",
    "datacenter_proxy",
    "proxy",
    "datacenter_ip",
    "residential_proxy",
    "residential_proxy_low_confidence",
    "residential_proxy_medium_confidence",
    "residential_proxy_high_confidence",
    "vpn",
    "vpn_public",
    "vpn_timezone",
    "vpn_relay",
    "vpn_mobile",
    "vpn_os_mismatch",
    "vpn_low_confidence",
    "vpn_medium_confidence",
    "vpn_high_confidence",
    "ip_blocklist",
    "ip_blocklist_email_spam",
    "ip_blocklist_attack_source",
    "ip_reputation",
    "ip_abuser",
    "network_anomaly",
    "bogon_ip",
    "anycast_ip",
    "location_spoofing",
    "geo_mismatch",
    "ios_simulator",
    "simulator",
    "android_emulator",
    "emulator",
    "virtual_machine",
    "jailbroken_device",
    "jailbreak",
    "rooted_device",
    "root_apps",
    "play_device_integrity_failed",
    "cloned_app",
    "app_cloner",
    "play_app_unrecognized",
    "device_farm",
    "app_attest_key_churn",
    "mitm_attack",
    "frida_detected",
    "frida",
    "browser_tampering",
    "tampering",
    "antidetect_browser",
    "fingerprint_suppressed",
    "developer_tools",
    "remote_control",
    "bot",
    "automation",
    "bad_bot",
    "fetch_metadata_missing",
    "high_activity",
    "incognito_mode",
    "incognito",
    "privacy_settings",
    "embedded_web_view",
    "active_call",
    "attestation_missing",
    "attestation_failed",
    "attestation_downgrade",
    "device_inconsistent",
    "report_incomplete",
    "probe_errors",
    "custom_root_ca",
    "secondary_user_profile",
)


@dataclass(frozen=True)
class EventTrigger:
    """One signal group that contributed to an event's suspect score.

    Attributes:
        signal: The signal group, such as ``vpn``, ``bot`` or
            ``attestation_failed``.
        weight: The group's combined weight in this score.
        confidence: ``low``, ``medium`` or ``high``.
    """

    signal: str
    weight: int
    confidence: Optional[str] = None


@dataclass(frozen=True)
class Attestation:
    """Platform-neutral hardware attestation verdict from an archived document.

    Attributes:
        state: ``attested``, ``not_attested`` or ``failed``.
        status: ``verified``, ``indeterminate``, ``invalid``, ``absent`` or
            ``unconfigured``.
        attest_skipped: Native only: the app's own reason for sending no
            attestation, such as ``not_offered``, ``unsupported`` or
            ``timeout``. Diagnostic only; it never lowers the score.
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
