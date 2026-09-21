"""Server-owned fixtures: the SDK must read exactly what the API sends.

The vendored snapshot keeps these tests independent of sibling repositories.
Refresh it with ``python scripts/sync_contract.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import Recorder, json_response
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from fingerly import Fingerly, FingerlyAPIError, verify_webhook

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
