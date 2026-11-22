"""Server-owned fixtures: the SDK must read exactly what the API sends.

The vendored snapshot keeps these tests independent of sibling repositories.
Refresh it with ``python scripts/sync_contract.py``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import Recorder, json_response
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from fingerly import (
    SIGNAL_NAMES,
    AIAgent,
    AIPurpose,
    AIRuntime,
    AIVerification,
    AIVerificationMethod,
    AIVerificationResult,
    Attestation,
    Event,
    EventDocument,
    Fingerly,
    FingerlyAPIError,
    VisitorKind,
    verify_webhook,
)

CONTRACT = Path(__file__).resolve().parent.parent / "contract"
SPEC: dict[str, Any] = json.loads((CONTRACT / "openapi.json").read_text())
FIXTURES: dict[str, Any] = json.loads((CONTRACT / "fixtures.json").read_text())
SECRET_KEY = "fly_sk_development_contract"

# The OpenAPI document declares no $schema, so name the dialect explicitly.
_REGISTRY = Registry().with_resource(
    "fingerly", Resource.from_contents(SPEC, default_specification=DRAFT202012)
)


def validator_for(schema: str) -> Draft202012Validator:
    """Compiles a validator for one named schema in the vendored OpenAPI."""
    return Draft202012Validator(
        {"$ref": f"fingerly#/components/schemas/{schema}"}, registry=_REGISTRY
    )


def responses(*schemas: str) -> list[dict[str, Any]]:
    """Selects the fixtures whose body matches one of the given schemas."""
    return [row for row in FIXTURES["responses"] if row["schema"] in schemas]


def ids(rows: list[dict[str, Any]]) -> list[str]:
    return [row["name"] for row in rows]


class TestResponseFixtures:
    @pytest.mark.parametrize(
        "fixture", FIXTURES["responses"], ids=ids(FIXTURES["responses"])
    )
    def test_fixture_matches_the_published_schema(
        self, fixture: dict[str, Any]
    ) -> None:
        errors = list(validator_for(fixture["schema"]).iter_errors(fixture["body"]))
        assert not errors, [error.message for error in errors]

    @pytest.mark.parametrize(
        "fixture", responses("SDKEventOut"), ids=ids(responses("SDKEventOut"))
    )
    def test_reads_every_event_shape(self, fixture: dict[str, Any]) -> None:
        body = fixture["body"]
        with Fingerly(
            secret_key=SECRET_KEY,
            transport=Recorder(json_response(body)).transport(),
        ) as fingerly:
            event = fingerly.events.get("id")

        assert event.request_id == body["request_id"]
        assert event.visitor_id == body["visitor_id"]
        assert event.suspect_score == body.get("suspect_score")
        assert event.project_id == body.get("project_id")
        assert len(event.triggers) == len(body["triggers"])
        assert event.raw == body

    @pytest.mark.parametrize(
        "fixture", responses("SDKEventsOut"), ids=ids(responses("SDKEventsOut"))
    )
    def test_reads_every_page_shape(self, fixture: dict[str, Any]) -> None:
        body = fixture["body"]
        with Fingerly(
            secret_key=SECRET_KEY,
            transport=Recorder(json_response(body)).transport(),
        ) as fingerly:
            page = fingerly.events.list()

        assert (page.page, page.page_size) == (body["page"], body["page_size"])
        assert [row.request_id for row in page.rows] == [
            row["request_id"] for row in body["rows"]
        ]
        assert [row.project_id for row in page.rows] == [
            row.get("project_id") for row in body["rows"]
        ]

    @pytest.mark.parametrize(
        "fixture", responses("ErrorResponse"), ids=ids(responses("ErrorResponse"))
    )
    def test_maps_every_error_shape(self, fixture: dict[str, Any]) -> None:
        recorder = Recorder(json_response(fixture["body"], fixture["status"]))
        with (
            Fingerly(secret_key=SECRET_KEY, transport=recorder.transport()) as fingerly,
            pytest.raises(FingerlyAPIError) as caught,
        ):
            fingerly.events.get("id")

        assert caught.value.status == fixture["status"]
        assert caught.value.code == fixture["body"]["error"]["code"]
        assert caught.value.request_id == fixture["body"].get("request_id")


def response(name: str) -> dict[str, Any]:
    """The response fixture with the given name."""
    return next(row for row in FIXTURES["responses"] if row["name"] == name)


def read_event(body: dict[str, Any]) -> Event:
    """Reads one event body through the client."""
    with Fingerly(
        secret_key=SECRET_KEY,
        transport=Recorder(json_response(body)).transport(),
    ) as fingerly:
        return fingerly.events.get("id")


class TestAIAgentFixture:
    def test_reads_the_ai_agent(self) -> None:
        event = read_event(response("ai_agent")["body"])

        assert event.visitor_kind == VisitorKind.AI_BOT
        assert event.ai == AIAgent(
            name="ChatGPT-User",
            provider="OpenAI",
            purpose=AIPurpose.USER_FETCH,
            runtime=AIRuntime.PROVIDER_CLOUD,
            declared=True,
            verification=AIVerification(
                method=AIVerificationMethod.NONE,
                result=AIVerificationResult.NOT_ATTEMPTED,
            ),
        )

    def test_ai_is_none_on_an_event_that_is_not_an_agent(self) -> None:
        event = read_event(response("event")["body"])

        assert event.visitor_kind != VisitorKind.AI_BOT
        assert event.ai is None

    def test_values_a_newer_server_adds_still_parse(self) -> None:
        body = copy.deepcopy(response("ai_agent")["body"])
        body["visitor_kind"] = "a_future_kind"
        body["ai"]["purpose"] = "a_future_purpose"
        body["ai"]["runtime"] = "a_future_runtime"
        body["ai"]["verification"] = {
            "method": "a_future_method",
            "result": "a_future_result",
        }
        event = read_event(body)

        assert event.visitor_kind == "a_future_kind"
        assert event.ai is not None
        assert event.ai.purpose == "a_future_purpose"
        assert event.ai.runtime == "a_future_runtime"
        assert event.ai.verification == AIVerification(
            method="a_future_method", result="a_future_result"
        )


class TestWebhookFixtures:
    @pytest.mark.parametrize(
        "fixture", FIXTURES["webhooks"], ids=ids(FIXTURES["webhooks"])
    )
    def test_verifies_server_signing_fixtures(self, fixture: dict[str, Any]) -> None:
        from datetime import datetime, timezone

        assert (
            verify_webhook(
                secret=fixture["secret"],
                payload=fixture["payload"],
                timestamp=fixture["timestamp"],
                signature=fixture["signature"],
                now=datetime.fromtimestamp(int(fixture["timestamp"]), tz=timezone.utc),
            )
            is fixture["valid"]
        )

    def test_rejects_a_stale_server_signing_fixture(self) -> None:
        from datetime import datetime, timezone

        fixture = FIXTURES["webhooks"][0]
        stale = datetime.fromtimestamp(int(fixture["timestamp"]) + 301, tz=timezone.utc)
        assert not verify_webhook(
            secret=fixture["secret"],
            payload=fixture["payload"],
            timestamp=fixture["timestamp"],
            signature=fixture["signature"],
            now=stale,
        )


class TestV3Contract:
    def test_v3_openapi_and_models(self) -> None:
        assert "/api/v1/events/{request_id}/supplement" not in SPEC["paths"]
        assert "SupplementOut" not in SPEC["components"]["schemas"]
        assert "AttestEnvelope" in SPEC["components"]["schemas"]

        v3_signals = [
            "attestation_failed",
            "attestation_downgrade",
            "device_inconsistent",
            "report_incomplete",
            "probe_errors",
            "fetch_metadata_missing",
            "web_ticket_missing",
            "web_ticket_invalid",
            "tampering",
            "custom_root_ca",
            "secondary_user_profile",
        ]
        for sig in v3_signals:
            assert sig in SIGNAL_NAMES
        # An event's triggers are its signal groups; the raw signals are in the
        # document's risk report.
        v3_groups = [
            "attestation_failed",
            "device_inconsistent",
            "report_incomplete",
            "bot",
            "browser_tampering",
            "custom_root_ca",
            "secondary_user_profile",
        ]

        payload: dict[str, Any] = {
            "request_id": "0199a963-e400-7000-8000-000000000099",
            "project_id": "0199a963-e400-7000-8000-0000000000a1",
            "visitor_id": "",
            "occurred_at": "2026-09-17T12:00:00Z",
            "state": "unavailable",
            "reason": "ip_lookup_failed",
            "environment": "development",
            "platform": "android",
            "sdk_platform": "android",
            "sdk_version": "0.3.0",
            "url_host": "shop.test",
            "url_path": "/checkout",
            "suspect_score": None,
            "triggers": [
                {"signal": sig, "weight": 4, "confidence": "high"} for sig in v3_groups
            ],
            "has_document": True,
            "document": {
                "schema": 1,
                "request_id": "0199a963-e400-7000-8000-000000000099",
                "occurred_at": "2026-09-17T12:00:00Z",
                "sdk": {"platform": "android", "version": "0.3.0"},
                "ip_network": "203.0.113.0/24",
                "attestation": {
                    "state": "attested",
                    "platform": "android",
                    "status": "verified",
                    "revocation_checked": True,
                    "package_bound": True,
                    "signer_bound": True,
                },
            },
        }
        errors = list(validator_for("SDKEventOut").iter_errors(payload))
        assert not errors, [err.message for err in errors]

        with Fingerly(
            secret_key=SECRET_KEY,
            transport=Recorder(json_response(payload)).transport(),
        ) as client:
            event = client.events.get(payload["request_id"])

        assert event.visitor_id == ""
        assert event.identifiable is False
        assert event.reason == "ip_lookup_failed"
        assert event.url_host == "shop.test"
        assert event.url_path == "/checkout"
        assert [t.signal for t in event.triggers] == v3_groups
        doc = event.parse_document()
        assert isinstance(doc, EventDocument)
        assert isinstance(doc.attestation, Attestation)
        assert doc.attestation.status == "verified"
        assert doc.attestation.platform == "android"
        assert doc.attestation.attest_skipped is None
        assert doc.attestation.downgrade is False

    def test_reads_attest_skipped_and_downgrade(self) -> None:
        payload: dict[str, Any] = {
            "request_id": "0199a963-e400-7000-8000-000000000098",
            "project_id": "0199a963-e400-7000-8000-0000000000a1",
            "visitor_id": "",
            "occurred_at": "2026-09-17T12:00:00Z",
            "state": "enriched",
            "environment": "development",
            "platform": "ios",
            "sdk_platform": "ios",
            "sdk_version": "0.3.0",
            "suspect_score": 30,
            "suspect_level": "high",
            "triggers": [
                {"signal": "attestation_failed", "weight": 30, "confidence": "high"}
            ],
            "has_document": True,
            "document": {
                "schema": 1,
                "request_id": "0199a963-e400-7000-8000-000000000098",
                "occurred_at": "2026-09-17T12:00:00Z",
                "sdk": {"platform": "ios", "version": "0.3.0"},
                "attestation": {
                    "state": "not_attested",
                    "platform": "ios",
                    "status": "absent",
                    "attest_skipped": "timeout",
                    "downgrade": True,
                },
            },
        }

        with Fingerly(
            secret_key=SECRET_KEY,
            transport=Recorder(json_response(payload)).transport(),
        ) as client:
            event = client.events.get(payload["request_id"])

        doc = event.parse_document()
        assert isinstance(doc, EventDocument)
        assert isinstance(doc.attestation, Attestation)
        assert doc.attestation.attest_skipped == "timeout"
        assert doc.attestation.downgrade is True
