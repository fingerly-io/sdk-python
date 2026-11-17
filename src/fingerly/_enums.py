"""Named constants for the closed string sets the API and webhooks use.

Every member is a ``str``: it compares equal to, and hashes like, the raw
value, so ``event.suspect_level == SuspectLevel.HIGH`` and
``Signal.TOR in {"tor"}`` both hold. ``str()`` and f-strings give the raw
value on every supported Python, not ``"SuspectLevel.HIGH"``.

The models keep these fields typed ``str`` and hold the value exactly as the
API sent it, so a value a newer server adds parses instead of raising. Compare
against the members; do not convert with ``SuspectLevel(value)``, which raises
``ValueError`` for a value this release does not know.
"""

from __future__ import annotations

from enum import Enum


class _StrEnum(str, Enum):
    """A ``str`` enum whose text is its value on every Python from 3.9."""

    def __str__(self) -> str:
        return str.__str__(self)

    def __format__(self, format_spec: str) -> str:
        return str.__format__(str.__str__(self), format_spec)


class Signal(_StrEnum):
    """Risk signal and signal-group identifiers.

    ``EventTrigger.signal`` is one of the group names (such as ``VPN``,
    ``BOT`` or ``ATTESTATION_FAILED``); archived risk reports also carry the
    raw detector names that feed each group (such as ``VPN_TIMEZONE``).
    """

    TOR = "tor"
    DATACENTER_PROXY = "datacenter_proxy"
    PROXY = "proxy"
    DATACENTER_IP = "datacenter_ip"
    RESIDENTIAL_PROXY = "residential_proxy"
    RESIDENTIAL_PROXY_LOW_CONFIDENCE = "residential_proxy_low_confidence"
    RESIDENTIAL_PROXY_MEDIUM_CONFIDENCE = "residential_proxy_medium_confidence"
    RESIDENTIAL_PROXY_HIGH_CONFIDENCE = "residential_proxy_high_confidence"
    VPN = "vpn"
    VPN_PUBLIC = "vpn_public"
    VPN_TIMEZONE = "vpn_timezone"
    VPN_RELAY = "vpn_relay"
    VPN_MOBILE = "vpn_mobile"
    VPN_OS_MISMATCH = "vpn_os_mismatch"
    VPN_LOW_CONFIDENCE = "vpn_low_confidence"
    VPN_MEDIUM_CONFIDENCE = "vpn_medium_confidence"
    VPN_HIGH_CONFIDENCE = "vpn_high_confidence"
    IP_BLOCKLIST = "ip_blocklist"
    IP_BLOCKLIST_EMAIL_SPAM = "ip_blocklist_email_spam"
    IP_BLOCKLIST_ATTACK_SOURCE = "ip_blocklist_attack_source"
    IP_REPUTATION = "ip_reputation"
    IP_ABUSER = "ip_abuser"
    NETWORK_ANOMALY = "network_anomaly"
    BOGON_IP = "bogon_ip"
    ANYCAST_IP = "anycast_ip"
    LOCATION_SPOOFING = "location_spoofing"
    GEO_MISMATCH = "geo_mismatch"
    IOS_SIMULATOR = "ios_simulator"
    SIMULATOR = "simulator"
    ANDROID_EMULATOR = "android_emulator"
    EMULATOR = "emulator"
    VIRTUAL_MACHINE = "virtual_machine"
    JAILBROKEN_DEVICE = "jailbroken_device"
    JAILBREAK = "jailbreak"
    ROOTED_DEVICE = "rooted_device"
    ROOT_APPS = "root_apps"
    PLAY_DEVICE_INTEGRITY_FAILED = "play_device_integrity_failed"
    CLONED_APP = "cloned_app"
    APP_CLONER = "app_cloner"
    PLAY_APP_UNRECOGNIZED = "play_app_unrecognized"
    DEVICE_FARM = "device_farm"
    REPEATED_REINSTALL = "repeated_reinstall"
    DEVICE_ACTIVITY_HIGH = "device_activity_high"
    DEVICE_ACTIVITY_VERY_HIGH = "device_activity_very_high"
    MITM_ATTACK = "mitm_attack"
    FRIDA_DETECTED = "frida_detected"
    FRIDA = "frida"
    BROWSER_TAMPERING = "browser_tampering"
    TAMPERING = "tampering"
    ANTIDETECT_BROWSER = "antidetect_browser"
    FINGERPRINT_SUPPRESSED = "fingerprint_suppressed"
    DEVELOPER_TOOLS = "developer_tools"
    REMOTE_CONTROL = "remote_control"
    BOT = "bot"
    AUTOMATION = "automation"
    BAD_BOT = "bad_bot"
    FETCH_METADATA_MISSING = "fetch_metadata_missing"
    WEB_TICKET_MISSING = "web_ticket_missing"
    WEB_TICKET_INVALID = "web_ticket_invalid"
    HIGH_ACTIVITY = "high_activity"
    INCOGNITO_MODE = "incognito_mode"
    INCOGNITO = "incognito"
    PRIVACY_SETTINGS = "privacy_settings"
    EMBEDDED_WEB_VIEW = "embedded_web_view"
    ACTIVE_CALL = "active_call"
    ATTESTATION_MISSING = "attestation_missing"
    ATTESTATION_FAILED = "attestation_failed"
    ATTESTATION_DOWNGRADE = "attestation_downgrade"
    DEVICE_INCONSISTENT = "device_inconsistent"
    REPORT_INCOMPLETE = "report_incomplete"
    PROBE_ERRORS = "probe_errors"
    CUSTOM_ROOT_CA = "custom_root_ca"
    SECONDARY_USER_PROFILE = "secondary_user_profile"


class SuspectLevel(_StrEnum):
    """The band ``Event.suspect_level`` puts the suspect score in."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(_StrEnum):
    """How sure a detection is, as in ``EventTrigger.confidence``."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EventState(_StrEnum):
    """How far a submission has got, as in ``Event.state``.

    A read returns an ``ENRICHED`` or ``UNAVAILABLE`` event; ``PENDING`` is
    what the API answers while it has not finished, which this SDK raises as
    ``FingerlyEventPendingError``.
    """

    PENDING = "pending"
    ENRICHED = "enriched"
    UNAVAILABLE = "unavailable"


class Environment(_StrEnum):
    """The key environment an event was recorded in, as in ``Event.environment``."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"


class AttestationState(_StrEnum):
    """The server's single hardware attestation verdict, ``Attestation.state``."""

    ATTESTED = "attested"
    NOT_ATTESTED = "not_attested"
    FAILED = "failed"


class AttestationStatus(_StrEnum):
    """The detail behind the verdict, ``Attestation.status``."""

    VERIFIED = "verified"
    INDETERMINATE = "indeterminate"
    INVALID = "invalid"
    ABSENT = "absent"
    UNCONFIGURED = "unconfigured"


class AttestSkippedReason(_StrEnum):
    """The app's own reason for sending no attestation, ``Attestation.attest_skipped``.

    Diagnostic only; it never lowers the score.

    - ``NOT_OFFERED``: the challenge offered no attestation: on iOS the SDK
      key has no Apple app ID for App Attest, on Android the app's transport
      returned no challenge offer.
    - ``UNSUPPORTED``: the device cannot make an attested key: App Attest is
      not supported on the iOS device, or Android is older than 7.0 (API 24).
    - ``CHALLENGE_UNAVAILABLE``: no usable challenge ticket: the challenge
      request failed, or on Android the ticket it returned was malformed.
    - ``KEY_ERROR``: the platform key store failed to create, attest or sign
      with the key, or on Android the stored key record could not be read.
    - ``TIMEOUT``: attestation did not finish in time: a key store call ran
      past its budget, or another identification held the attestation step
      too long.
    - ``BACKOFF``: the server rejected a new key from this install (on iOS,
      also when it asked for a replacement), and the SDK is waiting out a
      backoff before it registers another.
    - ``INSTALL_UNAVAILABLE``: the report has no usable install ID, or on iOS
      the stored key record could not be read or saved.
    """

    NOT_OFFERED = "not_offered"
    UNSUPPORTED = "unsupported"
    CHALLENGE_UNAVAILABLE = "challenge_unavailable"
    KEY_ERROR = "key_error"
    TIMEOUT = "timeout"
    BACKOFF = "backoff"
    INSTALL_UNAVAILABLE = "install_unavailable"


class VerifyReason(_StrEnum):
    """Why :meth:`Events.verify` refused an event, or ``OK`` (``""``) when it passed.

    Members, in the order the checks run:

    - ``NOT_FOUND``: no event for the request id (``404 event_not_found``).
    - ``TOO_OLD``: it occurred more than ``max_age_seconds`` ago, or its
      ``occurred_at`` is missing or unreadable.
    - ``TAG_MISMATCH``: its ``tag`` is not exactly the ``tag`` asked for.
    - ``UNIDENTIFIABLE``: its ``visitor_id`` is empty.
    - ``UNSCORED``: its ``suspect_score`` is ``None``.
    - ``ALREADY_CONSUMED``: an earlier call consumed it.
    """

    OK = ""
    NOT_FOUND = "not_found"
    TOO_OLD = "too_old"
    TAG_MISMATCH = "tag_mismatch"
    UNIDENTIFIABLE = "unidentifiable"
    UNSCORED = "unscored"
    ALREADY_CONSUMED = "already_consumed"


class WebhookEventType(_StrEnum):
    """The ``type`` of a webhook delivery.

    ``WEBHOOK_TEST`` is sent only on **Send test event** for one endpoint and
    cannot be subscribed to. Ignore types you do not handle: a newer server
    may send more.
    """

    IDENTIFICATION_COMPLETED = "identification.completed"
    IDENTIFICATION_REFUSED = "identification.refused"
    VISITOR_SUSPECT = "visitor.suspect"
    BILLING_STATUS_CHANGED = "billing.status_changed"
    USAGE_DAILY_SETTLED = "usage.daily_settled"
    WEBHOOK_TEST = "webhook.test"
