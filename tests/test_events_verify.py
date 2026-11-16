"""Consuming events and verifying one before a backend action."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import httpx
import pytest
from conftest import (
    SECRET_KEY,
    Recorder,
    _fresh,
    error_response,
    event_body,
    json_response,
    run,
)

from fingerly import (
    AsyncFingerly,
    ConsumeResult,
    Fingerly,
    FingerlyAPIError,
    FingerlyEventAlreadyConsumedError,
    FingerlyEventPendingError,
    VerifyResult,
)

REQUEST_ID = "0199a963-e400-7000-8000-000000000001"
EVENT_PATH = "/api/v1/events/" + REQUEST_ID
CONSUME_PATH = EVENT_PATH + "/consume"
CONSUMED_AT = "2026-11-17T10:00:00Z"

#: The literal 409 body and the standard error envelope carrying the same time.
ALREADY_CONSUMED_BODIES = [
    {"code": "event_already_consumed", "consumed_at": CONSUMED_AT},
    {
        "error": {
            "code": "event_already_consumed",
            "message": "Event already consumed",
            "status": 409,
            "details": [
                {"field": "consumed_at", "issue": CONSUMED_AT, "location": "body"}
            ],
        }
    },
]


def ago(seconds: float) -> str:
    """An RFC 3339 time that many seconds before now."""
    moment = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return moment.isoformat().replace("+00:00", "Z")


def fresh_event(**overrides: Any) -> dict[str, Any]:
    """An event that passes every verify check."""
    body = event_body(occurred_at=ago(10), suspect_score=12, tag="checkout")
    body.update(overrides)
    return body


def consumed() -> httpx.Response:
    return json_response(
        {"request_id": REQUEST_ID, "consumed_at": CONSUMED_AT, "first": True}
    )


def api(
    get: Optional[httpx.Response] = None, post: Optional[httpx.Response] = None
) -> Recorder:
    """A recorder answering the event read and the consume by route."""

    def answer(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == EVENT_PATH and get:
            return _fresh(get)
        if request.method == "POST" and request.url.path == CONSUME_PATH and post:
            return _fresh(post)
        raise AssertionError(f"unexpected {request.method} {request.url.path}")

    return Recorder.of(answer)


def posts(recorder: Recorder) -> int:
    return sum(1 for request in recorder.requests if request.method == "POST")


def on_both(
    build: Callable[[], Recorder], method: str, *args: Any, **kwargs: Any
) -> list[tuple[Any, Recorder]]:
    """Runs one events call on the sync and the async client.

    Returns:
        For each client, the result or the raised error, and its recorder.
    """
    outcomes: list[tuple[Any, Recorder]] = []
    recorder = build()
    try:
        client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
        outcomes.append((getattr(client.events, method)(*args, **kwargs), recorder))
    except Exception as error:
        outcomes.append((error, recorder))

    recorder = build()

    async def go() -> Any:
        async with AsyncFingerly(
            secret_key=SECRET_KEY, transport=recorder.transport()
        ) as fingerly:
            return await getattr(fingerly.events, method)(*args, **kwargs)

    try:
        outcomes.append((run(go()), recorder))
    except Exception as error:
        outcomes.append((error, recorder))
    return outcomes


class TestConsume:
    def test_decodes_the_first_consumption(self) -> None:
        for result, recorder in on_both(
            lambda: api(post=consumed()), "consume", REQUEST_ID
        ):
            assert result == ConsumeResult(
                request_id=REQUEST_ID, consumed_at=CONSUMED_AT, first=True
            )
            (request,) = recorder.requests
            assert request.method == "POST"
            assert request.url.raw_path == CONSUME_PATH.encode()
            assert request.headers["x-api-key"] == SECRET_KEY
            assert request.content == b""

    def test_escapes_the_request_id_into_one_segment(self) -> None:
        recorder = Recorder(consumed())
        client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
        client.events.consume("a/b.c")
        assert recorder.requests[0].url.raw_path == (
            b"/api/v1/events/a%2Fb%2Ec/consume"
        )

    @pytest.mark.parametrize("body", ALREADY_CONSUMED_BODIES)
    def test_a_second_consumption_raises_the_typed_error(
        self, body: dict[str, Any]
    ) -> None:
        build = lambda: api(post=json_response(body, 409))  # noqa: E731
        for error, _ in on_both(build, "consume", REQUEST_ID):
            assert isinstance(error, FingerlyEventAlreadyConsumedError)
            assert isinstance(error, FingerlyAPIError)
            assert error.status == 409
            assert error.code == "event_already_consumed"
            assert error.consumed_at == CONSUMED_AT
            assert str(error) == "Fingerly API returned HTTP 409"

    def test_a_missing_consumed_at_is_none(self) -> None:
        recorder = Recorder(error_response("event_already_consumed", 409))
        client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
        with pytest.raises(FingerlyEventAlreadyConsumedError) as caught:
            client.events.consume(REQUEST_ID)
        assert caught.value.consumed_at is None

    def test_an_unknown_event_raises_the_plain_api_error(self) -> None:
        build = lambda: api(post=error_response("event_not_found", 404))  # noqa: E731
        for error, _ in on_both(build, "consume", REQUEST_ID):
            assert type(error) is FingerlyAPIError
            assert error.status == 404
            assert error.code == "event_not_found"

    def test_is_never_retried(self) -> None:
        build = lambda: api(post=error_response("unavailable", 503))  # noqa: E731
        for error, recorder in on_both(build, "consume", REQUEST_ID):
            assert isinstance(error, FingerlyAPIError)
            assert recorder.calls == 1

    def test_an_empty_request_id_is_refused_before_any_request(self) -> None:
        for error, recorder in on_both(api, "consume", ""):
            assert isinstance(error, TypeError)
            assert recorder.calls == 0


def verify_both(
    get: Optional[httpx.Response] = None,
    post: Optional[httpx.Response] = None,
    **options: Any,
) -> list[tuple[Any, Recorder]]:
    return on_both(lambda: api(get, post), "verify", REQUEST_ID, **options)


class TestVerify:
    def test_ok_consumes_once_after_the_read(self) -> None:
        get = json_response(fresh_event())
        for result, recorder in verify_both(get, consumed(), tag="checkout"):
            assert isinstance(result, VerifyResult)
            assert result.ok is True
            assert result.reason == ""
            assert result.event is not None
            assert result.event.request_id == REQUEST_ID
            methods = [(r.method, r.url.raw_path) for r in recorder.requests]
            assert methods == [
                ("GET", EVENT_PATH.encode()),
                ("POST", CONSUME_PATH.encode()),
            ]

    def test_not_found_on_the_read(self) -> None:
        get = error_response("event_not_found", 404)
        for result, recorder in verify_both(get):
            assert result == VerifyResult(ok=False, reason="not_found", event=None)
            assert posts(recorder) == 0

    def test_too_old(self) -> None:
        get = json_response(fresh_event(occurred_at=ago(3600)))
        for result, recorder in verify_both(get):
            assert (result.ok, result.reason) == (False, "too_old")
            assert result.event is not None
            assert posts(recorder) == 0

    @pytest.mark.parametrize("occurred_at", ["yesterday", "2026-13-45T00:00:00Z", 5])
    def test_an_unreadable_time_is_too_old(self, occurred_at: Any) -> None:
        get = json_response(fresh_event(occurred_at=occurred_at))
        for result, recorder in verify_both(get):
            assert (result.ok, result.reason) == (False, "too_old")
            assert result.event is not None
            assert result.event.raw["occurred_at"] == occurred_at
            assert posts(recorder) == 0

    def test_a_missing_time_is_too_old(self) -> None:
        body = fresh_event()
        del body["occurred_at"]
        for result, recorder in verify_both(json_response(body)):
            assert (result.ok, result.reason) == (False, "too_old")
            assert posts(recorder) == 0

    def test_a_future_time_passes_the_age_check(self) -> None:
        get = json_response(fresh_event(occurred_at=ago(-120)))
        for result, _ in verify_both(get, consumed()):
            assert result.ok is True

    def test_default_max_age_is_300_seconds(self) -> None:
        for result, _ in verify_both(
            json_response(fresh_event(occurred_at=ago(200))), consumed()
        ):
            assert result.ok is True
        for result, _ in verify_both(json_response(fresh_event(occurred_at=ago(400)))):
            assert result.reason == "too_old"

    def test_max_age_seconds_is_honoured(self) -> None:
        get = json_response(fresh_event(occurred_at=ago(200)))
        for result, _ in verify_both(get, max_age_seconds=100):
            assert result.reason == "too_old"
        get = json_response(fresh_event(occurred_at=ago(400)))
        for result, _ in verify_both(get, consumed(), max_age_seconds=600):
            assert result.ok is True

    @pytest.mark.parametrize("event_tag", ["signup", None, ""])
    def test_tag_mismatch(self, event_tag: Optional[str]) -> None:
        body = fresh_event(tag=event_tag)
        if event_tag is None:
            del body["tag"]
        for result, recorder in verify_both(json_response(body), tag="checkout"):
            assert (result.ok, result.reason) == (False, "tag_mismatch")
            assert result.event is not None
            assert posts(recorder) == 0

    def test_no_tag_option_skips_the_tag_check(self) -> None:
        get = json_response(fresh_event(tag="anything"))
        for result, _ in verify_both(get, consumed()):
            assert result.ok is True

    @pytest.mark.parametrize("visitor_id", ["", None])
    def test_unidentifiable(self, visitor_id: Optional[str]) -> None:
        body = fresh_event(visitor_id=visitor_id)
        if visitor_id is None:
            del body["visitor_id"]
        for result, recorder in verify_both(json_response(body)):
            assert (result.ok, result.reason) == (False, "unidentifiable")
            assert result.event is not None
            assert posts(recorder) == 0

    def test_unscored(self) -> None:
        body = fresh_event()
        del body["suspect_score"]
        for result, recorder in verify_both(json_response(body)):
            assert (result.ok, result.reason) == (False, "unscored")
            assert posts(recorder) == 0
        for result, recorder in verify_both(
            json_response(fresh_event(suspect_score=None))
        ):
            assert result.reason == "unscored"
            assert posts(recorder) == 0

    def test_the_score_value_is_not_judged(self) -> None:
        get = json_response(
            fresh_event(
                suspect_score=100,
                suspect_level="high",
                triggers=[{"signal": "tor", "weight": 100}],
            )
        )
        for result, _ in verify_both(get, consumed()):
            assert result.ok is True

    @pytest.mark.parametrize("body", ALREADY_CONSUMED_BODIES)
    def test_already_consumed(self, body: dict[str, Any]) -> None:
        get = json_response(fresh_event())
        for result, recorder in verify_both(get, json_response(body, 409)):
            assert (result.ok, result.reason) == (False, "already_consumed")
            assert result.event is not None
            assert posts(recorder) == 1

    def test_not_found_on_consume(self) -> None:
        get = json_response(fresh_event())
        post = error_response("event_not_found", 404)
        for result, recorder in verify_both(get, post):
            assert result == VerifyResult(ok=False, reason="not_found", event=None)
            assert posts(recorder) == 1

    def test_other_consume_errors_are_raised(self) -> None:
        get = json_response(fresh_event())
        for error, recorder in verify_both(get, error_response("unavailable", 503)):
            assert isinstance(error, FingerlyAPIError)
            assert error.status == 503
            assert posts(recorder) == 1

    def test_consume_false_never_posts(self) -> None:
        get = json_response(fresh_event())
        for result, recorder in verify_both(get, consume=False):
            assert result.ok is True
            assert result.reason == ""
            assert posts(recorder) == 0

    def test_checks_stop_at_the_first_failure_in_order(self) -> None:
        cases = [
            (
                {
                    "occurred_at": ago(3600),
                    "tag": "other",
                    "visitor_id": "",
                    "suspect_score": None,
                },
                "too_old",
            ),
            ({"tag": "other", "visitor_id": "", "suspect_score": None}, "tag_mismatch"),
            ({"visitor_id": "", "suspect_score": None}, "unidentifiable"),
        ]
        for overrides, reason in cases:
            get = json_response(fresh_event(**overrides))
            for result, recorder in verify_both(get, tag="checkout"):
                assert result.reason == reason
                assert posts(recorder) == 0

    @pytest.mark.parametrize(
        ("get", "kind"),
        [
            (error_response("event_pending", 404), FingerlyEventPendingError),
            (error_response("unauthorized", 401), FingerlyAPIError),
            (error_response("rate_limited", 429), FingerlyAPIError),
            (error_response("internal", 500), FingerlyAPIError),
        ],
    )
    def test_read_errors_other_than_not_found_are_raised(
        self, get: httpx.Response, kind: type
    ) -> None:
        for error, recorder in verify_both(get):
            assert isinstance(error, kind)
            assert recorder.calls == 1

    @pytest.mark.parametrize(
        "options",
        [
            {"max_age_seconds": 0},
            {"max_age_seconds": -5},
            {"max_age_seconds": 1.5},
            {"max_age_seconds": True},
            {"max_age_seconds": "300"},
            {"tag": ""},
            {"tag": 5},
            {"consume": "yes"},
        ],
    )
    def test_invalid_options_are_refused_before_any_request(
        self, options: dict[str, Any]
    ) -> None:
        for error, recorder in verify_both(**options):
            assert isinstance(error, TypeError)
            assert recorder.calls == 0

    def test_an_empty_request_id_is_refused_before_any_request(self) -> None:
        for error, recorder in on_both(api, "verify", ""):
            assert isinstance(error, TypeError)
            assert recorder.calls == 0
