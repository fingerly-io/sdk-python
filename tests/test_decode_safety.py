"""An API body of any shape surfaces as FingerlyError, never as another exception.

Found by reading events from a hostile API: a ``triggers`` or ``rows`` value
of the wrong type escaped as ``AttributeError`` into the request handler, and
a wrong-typed optional field was handed over under a type it lied about.
"""

from __future__ import annotations

from typing import Any

import pytest
from conftest import SECRET_KEY, Recorder, event_body, json_response, run

from fingerly import AsyncFingerly, Fingerly, FingerlyError
from fingerly._models import parse_document


def client_answering(body: Any) -> Fingerly:
    return Fingerly(
        secret_key=SECRET_KEY, transport=Recorder(json_response(body)).transport()
    )


@pytest.mark.parametrize(
    "body",
    [
        event_body(triggers={"signal": "vpn"}),
        event_body(triggers="vpn"),
        event_body(triggers=["vpn"]),
        event_body(triggers=[{"signal": "vpn", "weight": None}], visitor_id=5),
        event_body(occurred_at="2026-13-45T00:00:00Z"),
    ],
)
def test_an_event_read_raises_only_fingerly_error(body: Any) -> None:
    with pytest.raises(FingerlyError):
        client_answering(body).events.get("req")


@pytest.mark.parametrize(
    "body",
    [
        {"rows": {"a": 1}, "page": 1, "page_size": 10},
        {"rows": "abc", "page": 1, "page_size": 10},
        {"rows": [1, 2], "page": 1, "page_size": 10},
    ],
)
def test_a_listing_raises_only_fingerly_error(body: Any) -> None:
    with pytest.raises(FingerlyError):
        client_answering(body).events.list()


def test_verify_raises_only_fingerly_error() -> None:
    client = AsyncFingerly(
        secret_key=SECRET_KEY,
        transport=Recorder(json_response(event_body(triggers="x"))).transport(),
    )
    with pytest.raises(FingerlyError):
        run(client.events.verify("req", consume=False))


def test_a_wrong_typed_optional_field_reads_as_absent() -> None:
    body = event_body(
        tag=5,
        suspect_score="high",
        suspect_level=["high"],
        has_document="no",
        visitor_kind=7,
        document="x",
        triggers=[{"signal": "vpn", "weight": "9", "confidence": 3}],
        ai={"name": None, "provider": 5, "declared": "false", "verification": 1},
    )
    event = client_answering(body).events.get("req")
    assert event.tag is None
    assert event.suspect_score is None
    assert event.suspect_level is None
    assert event.has_document is False
    assert event.visitor_kind is None
    assert event.document is None
    assert event.triggers[0].weight == 0
    assert event.triggers[0].confidence is None
    assert event.ai is not None
    assert (event.ai.name, event.ai.provider) == ("", "")
    assert event.ai.declared is False
    assert event.ai.verification.method == ""
    assert event.raw["tag"] == 5


def test_a_page_without_numbers_reads_as_zero() -> None:
    body: dict[str, Any] = {"rows": [], "page": None, "page_size": "10"}
    page = client_answering(body).events.list()
    assert (page.page, page.page_size) == (0, 0)


def test_an_unreadable_document_raises_only_fingerly_error() -> None:
    with pytest.raises(FingerlyError):
        parse_document({"request_id": "r", "occurred_at": "2026-02-30T00:00:00Z"})
    document = parse_document(
        {"schema": None, "request_id": "r", "occurred_at": "2026-02-03T00:00:00Z"}
    )
    assert document.schema == 1
