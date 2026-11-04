"""Client construction, routing and the sync/async parity contract."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
from conftest import (
    SECRET_KEY,
    Recorder,
    error_response,
    event_body,
    json_response,
    run,
)

from fingerly import (
    AsyncFingerly,
    Event,
    EventPage,
    Fingerly,
    FingerlyAPIError,
    FingerlyConnectionError,
    FingerlyTimeoutError,
)


def client(recorder: Recorder, **options: Any) -> Fingerly:
    return Fingerly(secret_key=SECRET_KEY, transport=recorder.transport(), **options)


def async_client(recorder: Recorder, **options: Any) -> AsyncFingerly:
    return AsyncFingerly(
        secret_key=SECRET_KEY, transport=recorder.transport(), **options
    )


class TestConstruction:
    def test_rejects_unsupported_keys_before_networking(self) -> None:
        for secret_key in [
            "not-a-fingerly-key",
            "fly_pk_production_test",
            "fly_px_development_test",
            "fly_mk_test",
            "fly_sk_unknown_test",
            "fly_sk_production_",
            "fly_sk_production_test\n",
        ]:
            with pytest.raises(TypeError):
                Fingerly(secret_key=secret_key, endpoint="https://custom.test")
            with pytest.raises(TypeError):
                AsyncFingerly(secret_key=secret_key, endpoint="https://custom.test")

    def test_defaults_to_the_fingerly_api(self) -> None:
        recorder = Recorder(json_response(event_body()))
        with Fingerly(
            secret_key="fly_sk_development_test",
            transport=recorder.transport(),
        ) as fingerly:
            fingerly.events.get("id/a")
        assert recorder.url == "https://api.fingerly.io/api/v1/events/id%2Fa"

    def test_rejects_invalid_endpoints_and_timeouts(self) -> None:
        for endpoint in [
            "file:///private",
            "https://user:pass@host",
            "https://host?key=value",
            "https://host#fragment",
            "not-a-url",
        ]:
            with pytest.raises(TypeError):
                Fingerly(secret_key=SECRET_KEY, endpoint=endpoint)
        for timeout in [0, -1, float("nan"), float("inf"), "5", True]:
            with pytest.raises(TypeError):
                Fingerly(secret_key=SECRET_KEY, timeout=timeout)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "api_version", ["", "1", "v0", "v1/../v2", "v2?k=v", "v2\n"]
    )
    def test_rejects_an_invalid_api_version(self, api_version: str) -> None:
        recorder = Recorder(json_response(event_body()))
        with pytest.raises(TypeError):
            client(recorder, api_version=api_version)
        assert recorder.calls == 0

    def test_uses_the_configured_api_version_for_every_request(self) -> None:
        recorder = Recorder(
            json_response(event_body()),
            json_response({"rows": [], "page": 1, "page_size": 10}),
        )
        with client(recorder, api_version="v2") as fingerly:
            fingerly.events.get("request-1")
            fingerly.events.list(limit=10)
        assert [str(request.url) for request in recorder.requests] == [
            "https://api.fingerly.io/api/v2/events/request-1",
            "https://api.fingerly.io/api/v2/events?page=1&limit=10",
        ]

    def test_sends_the_secret_key_and_identifies_the_sdk(self) -> None:
        recorder = Recorder(json_response(event_body()))
        with client(recorder) as fingerly:
            fingerly.events.get("request-1")
        headers = recorder.requests[0].headers
        assert headers["x-api-key"] == SECRET_KEY
        assert headers["accept"] == "application/json"
        assert headers["user-agent"].startswith("fingerly-python/")


class TestEventReads:
    def test_parses_an_event_and_exposes_undeclared_fields(self) -> None:
        recorder = Recorder(
            json_response(
                event_body(
                    tag="checkout:8412",
                    suspect_score=37,
                    suspect_level="high",
                    triggers=[{"signal": "tor", "weight": 14, "confidence": "high"}],
                    future_field="kept",
                )
            )
        )
        with client(recorder) as fingerly:
            event = fingerly.events.get("request-1")

        assert event.tag == "checkout:8412"
        assert event.suspect_score == 37
        assert event.triggers[0].signal == "tor"
        assert event.triggers[0].confidence == "high"
        assert event.occurred_at == datetime(2026, 9, 17, 12, tzinfo=timezone.utc)
        assert event.future_field == "kept"
        with pytest.raises(AttributeError):
            _ = event.no_such_field

    def test_keeps_an_unscored_event_distinct_from_zero(self) -> None:
        recorder = Recorder(json_response(event_body(suspect_score=None)))
        with client(recorder) as fingerly:
            event = fingerly.events.get("request-1")
        assert event.suspect_score is None
        assert event.suspect_level is None

    def test_encodes_filters_and_renders_dates_as_rfc_3339(self) -> None:
        recorder = Recorder(json_response({"rows": [], "page": 2, "page_size": 20}))
        moment = datetime(2026, 9, 1, 8, 30, tzinfo=timezone.utc)
        with client(recorder) as fingerly:
            page = fingerly.events.list(
                from_=moment,
                to=moment + timedelta(days=1),
                page=2,
                limit=20,
                visitor="visitor-test",
                level="high",
            )

        assert (page.page, page.page_size, page.rows) == (2, 20, [])
        query = dict(recorder.requests[0].url.params)
        assert query == {
            "from": "2026-09-01T08:30:00Z",
            "to": "2026-09-02T08:30:00Z",
            "page": "2",
            "limit": "20",
            "visitor": "visitor-test",
            "level": "high",
        }

    def test_reads_a_naive_datetime_as_utc(self) -> None:
        recorder = Recorder(json_response({"rows": [], "page": 1, "page_size": 10}))
        with client(recorder) as fingerly:
            fingerly.events.list(from_=datetime(2026, 9, 1, 8, 30))
        assert recorder.requests[0].url.params["from"] == "2026-09-01T08:30:00Z"

    def test_rejects_unusable_filters_before_networking(self) -> None:
        recorder = Recorder(json_response({"rows": [], "page": 1, "page_size": 10}))
        with client(recorder) as fingerly:
            for bad in [{"page": 0}, {"limit": -1}, {"limit": 1.5}, {"from_": 123}]:
                with pytest.raises(TypeError):
                    fingerly.events.list(**bad)  # type: ignore[arg-type]
        assert recorder.calls == 0


class TestErrors:
    def test_preserves_structured_error_metadata(self) -> None:
        recorder = Recorder(error_response("event_not_found", 404))
        with client(recorder) as fingerly, pytest.raises(FingerlyAPIError) as caught:
            fingerly.events.get("missing")
        assert caught.value.status == 404
        assert caught.value.code == "event_not_found"
        assert caught.value.request_id == "trace"

    def test_never_exposes_the_body_or_the_secret_key(self) -> None:
        recorder = Recorder(httpx.Response(502, content=SECRET_KEY.encode()))
        with client(recorder) as fingerly, pytest.raises(FingerlyAPIError) as caught:
            fingerly.events.get("missing")
        assert str(caught.value) == "Fingerly API returned HTTP 502"
        assert SECRET_KEY not in str(caught.value)

    def test_redacts_the_secret_key_from_error_metadata(self) -> None:
        recorder = Recorder(
            json_response(
                {
                    "error": {
                        "code": "unauthorized",
                        "details": {"presented": SECRET_KEY},
                    },
                    "request_id": f"trace-{SECRET_KEY}",
                },
                401,
            )
        )
        with client(recorder) as fingerly, pytest.raises(FingerlyAPIError) as caught:
            fingerly.events.get("missing")
        assert caught.value.details == {"presented": "[redacted]"}
        assert caught.value.request_id == "trace-[redacted]"

    @pytest.mark.parametrize(
        ("failure", "expected"),
        [
            (httpx.ReadTimeout, FingerlyTimeoutError),
            (httpx.ConnectTimeout, FingerlyTimeoutError),
            (httpx.ConnectError, FingerlyConnectionError),
            (httpx.RemoteProtocolError, FingerlyConnectionError),
        ],
    )
    def test_maps_transport_failures_to_sdk_errors(
        self, failure: type, expected: type
    ) -> None:
        def raising(request: httpx.Request) -> httpx.Response:
            raise failure("failed", request=request)

        with (
            client(Recorder.of(raising)) as fingerly,
            pytest.raises(expected) as caught,
        ):
            fingerly.events.get("id")
        assert isinstance(caught.value.__cause__, failure)

    def test_does_not_silently_retry(self) -> None:
        recorder = Recorder(error_response("event_not_found", 404))
        with client(recorder) as fingerly:
            for read in (lambda: fingerly.events.get("id"), fingerly.events.list):
                with pytest.raises(FingerlyAPIError):
                    read()
        assert recorder.calls == 2


class TestMissingEvent:
    """An event is readable as soon as identification answers, so a missing
    one means a request id that was never issued: reported at once, in one
    request, rather than waited through."""

    def test_reports_a_missing_event_without_retrying(self) -> None:
        recorder = Recorder(error_response("event_not_found", 404))
        with client(recorder) as fingerly, pytest.raises(FingerlyAPIError) as caught:
            fingerly.events.get("id")
        assert caught.value.status == 404
        assert caught.value.code == "event_not_found"
        assert recorder.calls == 1

    @pytest.mark.parametrize("status", [400, 401, 403, 429, 500, 404])
    def test_propagates_every_other_failure(self, status: int) -> None:
        recorder = Recorder(error_response("other", status))
        with client(recorder) as fingerly, pytest.raises(FingerlyAPIError) as caught:
            fingerly.events.get("id")
        assert caught.value.status == status
        assert recorder.calls == 1


class TestAsyncParity:
    def test_async_reads_match_the_synchronous_client(self) -> None:
        async def read() -> tuple[Event, EventPage, Recorder]:
            recorder = Recorder(
                json_response(event_body(tag="checkout:1")),
                json_response({"rows": [event_body()], "page": 1, "page_size": 10}),
            )
            async with async_client(recorder) as fingerly:
                event = await fingerly.events.get("request-1")
                page = await fingerly.events.list(level="high")
            return event, page, recorder

        event, page, recorder = run(read())
        assert event.tag == "checkout:1"
        assert len(page.rows) == 1
        assert [str(request.url) for request in recorder.requests] == [
            "https://api.fingerly.io/api/v1/events/request-1",
            "https://api.fingerly.io/api/v1/events?page=1&limit=10&level=high",
        ]

    def test_async_surfaces_api_errors_identically(self) -> None:
        async def read() -> None:
            recorder = Recorder(error_response("event_not_found", 404))
            async with async_client(recorder) as fingerly:
                await fingerly.events.get("missing")

        with pytest.raises(FingerlyAPIError) as caught:
            run(read())
        assert (caught.value.status, caught.value.code) == (404, "event_not_found")

    def test_closing_is_idempotent(self) -> None:
        async def close_twice() -> None:
            fingerly = async_client(Recorder(json_response(event_body())))
            await fingerly.aclose()
            await fingerly.aclose()

        run(close_twice())
        fingerly = client(Recorder(json_response(event_body())))
        fingerly.close()
        fingerly.close()


class TestErrorStatus:
    @pytest.mark.parametrize("status", [301, 302, 304, 307, 308])
    def test_raises_for_a_redirect_with_its_own_status(self, status: int) -> None:
        recorder = Recorder(
            httpx.Response(status, headers={"location": "https://elsewhere.test/"})
        )
        with client(recorder) as fingerly, pytest.raises(FingerlyAPIError) as caught:
            fingerly.events.get("id")
        assert caught.value.status == status
        assert recorder.calls == 1

    def test_reports_the_real_status_of_an_unreadable_success(self) -> None:
        recorder = Recorder(httpx.Response(204))
        with client(recorder) as fingerly, pytest.raises(FingerlyAPIError) as caught:
            fingerly.events.get("id")
        assert caught.value.status == 204

    @pytest.mark.parametrize(
        ("header", "expected"),
        [("7", 7.0), ("0", 0.0), (" 12 ", 12.0), ("soon", None), (None, None)],
    )
    def test_carries_retry_after_in_seconds(self, header: Any, expected: Any) -> None:
        headers = {} if header is None else {"retry-after": header}
        response = error_response("rate_limited", 429)
        response.headers.update(headers)
        for fingerly in (client(Recorder(response)),):
            with fingerly, pytest.raises(FingerlyAPIError) as caught:
                fingerly.events.get("id")
            assert caught.value.retry_after == expected

        async def read() -> None:
            async with async_client(Recorder(response)) as reader:
                await reader.events.get("id")

        with pytest.raises(FingerlyAPIError) as caught_async:
            run(read())
        assert caught_async.value.retry_after == expected

    def test_reads_an_http_date_retry_after(self) -> None:
        from fingerly._transport import retry_after_seconds

        now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)
        assert retry_after_seconds("Wed, 04 Nov 2026 12:00:30 GMT", now) == 30.0
        assert retry_after_seconds("Wed, 04 Nov 2026 11:00:00 GMT", now) == 0.0


class TestNoCookies:
    def test_never_sends_a_cookie_the_api_set(self) -> None:
        response = json_response(event_body())
        response.headers["set-cookie"] = "balancer=one; Path=/"
        recorder = Recorder(response)
        with client(recorder) as fingerly:
            fingerly.events.get("one")
            fingerly.events.get("two")

        async def read() -> None:
            async with async_client(recorder) as reader:
                await reader.events.get("three")
                await reader.events.get("four")

        run(read())
        assert recorder.calls == 4
        assert all("cookie" not in request.headers for request in recorder.requests)
