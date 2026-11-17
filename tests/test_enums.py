"""The exported enums match the server's closed string sets and stay strings.

The pinned lists below mirror the server sources named beside each one. When
the server checkout sits next to this SDK (the integration workspace) or
``FINGERLY_SERVER_DIR`` names it, the server tests read those sources too, so a
signal added or retired there fails here until the SDK follows.
"""

from __future__ import annotations

import json
import os
import re
from enum import Enum
from pathlib import Path
from typing import Optional

import pytest
from conftest import Recorder, event_body, json_response

import fingerly
from fingerly import (
    SIGNAL_NAMES,
    AttestationState,
    AttestationStatus,
    AttestSkippedReason,
    Confidence,
    Environment,
    EventState,
    Fingerly,
    Signal,
    SuspectLevel,
    VerifyReason,
    WebhookEventType,
)
from fingerly._models import parse_document, parse_event

# server/domain/risk/signals.go (Signal) and groups.go (Group).
SERVER_SIGNALS = {
    "active_call",
    "android_emulator",
    "antidetect_browser",
    "anycast_ip",
    "app_attest_key_churn",
    "app_cloner",
    "attestation_downgrade",
    "attestation_failed",
    "attestation_missing",
    "automation",
    "bad_bot",
    "bogon_ip",
    "bot",
    "browser_tampering",
    "cloned_app",
    "custom_root_ca",
    "datacenter_ip",
    "datacenter_proxy",
    "developer_tools",
    "device_farm",
    "device_inconsistent",
    "embedded_web_view",
    "emulator",
    "fetch_metadata_missing",
    "fingerprint_suppressed",
    "frida",
    "frida_detected",
    "geo_mismatch",
    "high_activity",
    "incognito",
    "incognito_mode",
    "ios_simulator",
    "ip_abuser",
    "ip_blocklist",
    "ip_blocklist_attack_source",
    "ip_blocklist_email_spam",
    "ip_reputation",
    "jailbreak",
    "jailbroken_device",
    "location_spoofing",
    "mitm_attack",
    "network_anomaly",
    "play_app_unrecognized",
    "play_device_integrity_failed",
    "privacy_settings",
    "probe_errors",
    "proxy",
    "remote_control",
    "report_incomplete",
    "residential_proxy",
    "residential_proxy_high_confidence",
    "residential_proxy_low_confidence",
    "residential_proxy_medium_confidence",
    "root_apps",
    "rooted_device",
    "secondary_user_profile",
    "simulator",
    "tampering",
    "tor",
    "virtual_machine",
    "vpn",
    "vpn_high_confidence",
    "vpn_low_confidence",
    "vpn_medium_confidence",
    "vpn_mobile",
    "vpn_os_mismatch",
    "vpn_public",
    "vpn_relay",
    "vpn_timezone",
    "web_ticket_invalid",
    "web_ticket_missing",
}

PINNED: dict[type[Enum], set[str]] = {
    Signal: SERVER_SIGNALS,
    # server/models/enums.go (SuspectLevel).
    SuspectLevel: {"low", "medium", "high"},
    # server/domain/risk/signals.go (Confidence).
    Confidence: {"low", "medium", "high"},
    # server/models/event.go (EventState).
    EventState: {"pending", "enriched", "unavailable"},
    # server/models/enums.go (Environment).
    Environment: {"production", "staging", "development"},
    # server/services/android_trust.go (AttestationAttested and siblings).
    AttestationState: {"attested", "not_attested", "failed"},
    # server/services/android_trust.go (AttestationReport.Status).
    AttestationStatus: {
        "verified",
        "indeterminate",
        "invalid",
        "absent",
        "unconfigured",
    },
    # server/services/android_trust.go (AttestSkippedReasons).
    AttestSkippedReason: {
        "not_offered",
        "unsupported",
        "challenge_unavailable",
        "key_error",
        "timeout",
        "backoff",
        "install_unavailable",
    },
    # server/models/webhook.go (WebhookEventType).
    WebhookEventType: {
        "identification.completed",
        "identification.refused",
        "visitor.suspect",
        "billing.status_changed",
        "usage.daily_settled",
        "webhook.test",
    },
    # Produced by this SDK's own verify checks.
    VerifyReason: {
        "",
        "not_found",
        "too_old",
        "tag_mismatch",
        "unidentifiable",
        "unscored",
        "already_consumed",
    },
}

ENUMS = list(PINNED)


def _server_dir() -> Optional[Path]:
    """The server checkout: ``FINGERLY_SERVER_DIR``, or the workspace sibling."""
    configured = os.environ.get("FINGERLY_SERVER_DIR")
    parents = Path(__file__).resolve().parents
    if configured:
        path = Path(configured)
    elif len(parents) > 4:
        path = parents[4] / "server"
    else:
        return None
    return path if (path / "domain" / "risk" / "signals.go").is_file() else None


SERVER = _server_dir()
needs_server = pytest.mark.skipif(
    SERVER is None, reason="server checkout not found; set FINGERLY_SERVER_DIR"
)


def _go_constants(relative: str, go_type: str) -> set[str]:
    """Every ``Name go_type = "value"`` constant in one server source file."""
    assert SERVER is not None
    source = (SERVER / relative).read_text(encoding="utf-8")
    return set(re.findall(rf'\b{go_type}\s*=\s*"([^"]*)"', source))


def _go_block(relative: str, pattern: str) -> str:
    assert SERVER is not None
    source = (SERVER / relative).read_text(encoding="utf-8")
    match = re.search(pattern, source, re.DOTALL)
    assert match is not None, f"{pattern!r} not found in {relative}"
    return match.group(1)


class TestPinnedValues:
    @pytest.mark.parametrize("enum", ENUMS, ids=lambda enum: enum.__name__)
    def test_values_match_the_server(self, enum: type[Enum]) -> None:
        values = [member.value for member in enum]
        assert len(values) == len(set(values))
        assert set(values) == PINNED[enum]

    @pytest.mark.parametrize("enum", ENUMS, ids=lambda enum: enum.__name__)
    def test_names_are_the_upper_snake_value(self, enum: type[Enum]) -> None:
        for member in enum:
            if member.value == "":
                assert member.name == "OK"
                continue
            assert member.name == re.sub(r"[^A-Za-z0-9]", "_", member.value).upper()

    def test_signal_names_is_every_signal_in_order(self) -> None:
        assert [member.value for member in Signal] == list(SIGNAL_NAMES)

    def test_every_enum_is_exported(self) -> None:
        for enum in ENUMS:
            assert enum.__name__ in fingerly.__all__
            assert getattr(fingerly, enum.__name__) is enum


@needs_server
class TestServerSources:
    def test_signals(self) -> None:
        server = _go_constants("domain/risk/signals.go", "Signal") | _go_constants(
            "domain/risk/groups.go", "Group"
        )
        assert server == {member.value for member in Signal}

    def test_suspect_levels_and_environments(self) -> None:
        assert _go_constants("models/enums.go", "SuspectLevel") == {
            member.value for member in SuspectLevel
        }
        assert _go_constants("models/enums.go", "Environment") == {
            member.value for member in Environment
        }

    def test_confidence(self) -> None:
        assert _go_constants("domain/risk/signals.go", "Confidence") == {
            member.value for member in Confidence
        }

    def test_event_states(self) -> None:
        assert _go_constants("models/event.go", "EventState") == {
            member.value for member in EventState
        }

    def test_webhook_event_types(self) -> None:
        assert _go_constants("models/webhook.go", "WebhookEventType") == {
            member.value for member in WebhookEventType
        }

    def test_attestation(self) -> None:
        trust = "services/android_trust.go"
        states = _go_block(trust, r"(\n\tAttestationAttested\s.*?)\n\)")
        assert set(re.findall(r'"([a-z_]+)"', states)) == {
            member.value for member in AttestationState
        }
        status = _go_block(
            trust, r"// Status is the detail behind State:(.*?)\n\s*Status "
        )
        assert set(re.findall(r"[a-z_]+", status)) - {"or"} == {
            member.value for member in AttestationStatus
        }
        skipped = _go_block(trust, r"AttestSkippedReasons = \[\]string\{(.*?)\}")
        assert set(re.findall(r'"([a-z_]+)"', skipped)) == {
            member.value for member in AttestSkippedReason
        }


class TestStringBehaviour:
    def test_members_are_their_raw_strings(self) -> None:
        raw: str = "high"
        assert raw == SuspectLevel.HIGH
        assert isinstance(SuspectLevel.HIGH, str)
        assert str(Signal.FINGERPRINT_SUPPRESSED) == "fingerprint_suppressed"
        assert f"{WebhookEventType.VISITOR_SUSPECT}" == "visitor.suspect"
        assert f"{SuspectLevel.LOW:>5}" == "  low"
        assert json.dumps({"level": SuspectLevel.MEDIUM}) == '{"level": "medium"}'

    def test_members_hash_like_their_strings(self) -> None:
        assert Signal.TOR in {"tor", "vpn"}
        assert {"high": 1}[SuspectLevel.HIGH] == 1
        by_signal: dict[str, int] = {Signal.BOT: 1}
        assert by_signal["bot"] == 1

    def test_ok_is_falsy_and_every_refusal_truthy(self) -> None:
        assert not VerifyReason.OK
        assert all(member for member in VerifyReason if member is not VerifyReason.OK)

    def test_parsed_fields_compare_with_members(self) -> None:
        event = parse_event(
            event_body(
                suspect_level="high",
                triggers=[
                    {"signal": "fingerprint_suppressed", "weight": 9},
                    {"signal": "vpn", "weight": 5, "confidence": "medium"},
                ],
            )
        )
        signals = [trigger.signal for trigger in event.triggers]
        assert event.suspect_level == SuspectLevel.HIGH
        assert event.state == EventState.ENRICHED
        assert event.environment == Environment.DEVELOPMENT
        assert Signal.FINGERPRINT_SUPPRESSED in signals
        assert event.triggers[1].confidence == Confidence.MEDIUM

    def test_unknown_values_still_parse(self) -> None:
        event = parse_event(
            event_body(
                state="some_future_state",
                suspect_level="extreme",
                triggers=[{"signal": "a_future_signal", "weight": 1}],
            )
        )
        assert event.suspect_level == "extreme"
        assert event.suspect_level not in set(SuspectLevel)
        assert event.triggers[0].signal == "a_future_signal"
        assert type(event.triggers[0].signal) is str

    def test_attestation_compares_with_members(self) -> None:
        document = parse_document(
            {
                "schema": 3,
                "request_id": "request-1",
                "occurred_at": "2026-11-01T00:00:00Z",
                "sdk": {"platform": "android", "version": "0.3.0"},
                "attestation": {
                    "state": "not_attested",
                    "status": "absent",
                    "attest_skipped": "timeout",
                },
            }
        )
        assert document.attestation is not None
        assert document.attestation.state == AttestationState.NOT_ATTESTED
        assert document.attestation.status == AttestationStatus.ABSENT
        assert document.attestation.attest_skipped == AttestSkippedReason.TIMEOUT

    def test_a_level_member_is_sent_as_its_value(self) -> None:
        recorder = Recorder(json_response({"rows": [], "page": 1, "page_size": 10}))
        with Fingerly(
            secret_key="fly_sk_development_enums", transport=recorder.transport()
        ) as client:
            client.events.list(level=SuspectLevel.HIGH)
        assert dict(recorder.requests[0].url.params)["level"] == "high"
