"""DeviceCheck reads and writes: shapes, typed errors and the retry rule."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from conftest import SECRET_KEY, Recorder, error_response, json_response, run

import fingerly._client as client_module
from fingerly import (
    AsyncFingerly,
    DeviceCheckBits,
    DeviceCheckWriteResult,
    Fingerly,
    FingerlyAPIError,
    FingerlyConnectionError,
    FingerlyDeviceCheckError,
)

REQUEST_ID = "0199a963-e400-7000-8000-000000000001"
BASE = "https://api.fingerly.io/api/v1/events/" + REQUEST_ID


@pytest.fixture(autouse=True)
def no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "_DEVICE_CHECK_RETRY_DELAYS", (0.0, 0.0))


def sync_client(recorder: Recorder) -> Fingerly:
    return Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())


def async_client(recorder: Recorder) -> AsyncFingerly:
    return AsyncFingerly(secret_key=SECRET_KEY, transport=recorder.transport())


def query_both(recorder: Recorder) -> list[Any]:
    """Runs the same query on the sync and the async client."""
    results: list[Any] = []
    for build in (sync_client, async_client):
        try:
            if build is sync_client:
                results.append(sync_client(recorder).device_check.query(REQUEST_ID))
            else:

                async def go() -> DeviceCheckBits:
                    async with async_client(recorder) as fingerly:
                        return await fingerly.device_check.query(REQUEST_ID)

                results.append(run(go()))
        except FingerlyAPIError as error:
            results.append(error)
    return results


def write_both(recorder: Recorder, **bits: Any) -> list[Any]:
    results: list[Any] = []
    try:
        results.append(sync_client(recorder).device_check.write(REQUEST_ID, **bits))
    except FingerlyAPIError as error:
        results.append(error)

    async def go() -> DeviceCheckWriteResult:
        async with async_client(recorder) as fingerly:
            return await fingerly.device_check.write(REQUEST_ID, **bits)

    try:
        results.append(run(go()))
    except FingerlyAPIError as error:
        results.append(error)
    return results


def apple_rejected(status: int) -> httpx.Response:
    return json_response(
        {
            "error": {
                "code": "apple_rejected",
                "message": "Apple rejected the request",
                "status": 422,
                "details": [
                    {
                        "field": "apple_status",
                        "location": "upstream",
                        "issue": str(status),
                    }
                ],
            },
            "request_id": "trace",
        },
        422,
    )


class TestShapes:
    def test_query_posts_with_no_body_and_reads_the_bits(self) -> None:
        recorder = Recorder(
            json_response(
                {"found": True, "bit0": True, "bit1": False, "last_update": "2026-10"}
            )
        )
        results = query_both(recorder)
        assert (
            results
            == [
                DeviceCheckBits(
                    found=True, bit0=True, bit1=False, last_update="2026-10"
                )
            ]
            * 2
        )
        for request in recorder.requests:
            assert request.method == "POST"
            assert str(request.url) == BASE + "/device-check/query"
            assert request.headers["x-api-key"] == SECRET_KEY
            assert request.content == b""

    def test_query_without_bits_has_no_last_update(self) -> None:
        recorder = Recorder(
            json_response({"found": False, "bit0": False, "bit1": False})
        )
        assert (
            query_both(recorder)
            == [DeviceCheckBits(found=False, bit0=False, bit1=False, last_update=None)]
            * 2
        )

    def test_write_puts_only_the_named_bits(self) -> None:
        recorder = Recorder(json_response({"bit1": True}))
        results = write_both(recorder, bit1=True)
        assert results == [DeviceCheckWriteResult(bit0=None, bit1=True)] * 2
        for request in recorder.requests:
            assert request.method == "PUT"
            assert str(request.url) == BASE + "/device-check"
            assert request.headers["x-api-key"] == SECRET_KEY
            assert request.headers["content-type"] == "application/json"
            assert json.loads(request.content) == {"bit1": True}

    def test_write_sends_false(self) -> None:
        recorder = Recorder(json_response({"bit0": False, "bit1": True}))
        assert (
            write_both(recorder, bit0=False, bit1=True)
            == [DeviceCheckWriteResult(bit0=False, bit1=True)] * 2
        )
        assert json.loads(recorder.requests[0].content) == {"bit0": False, "bit1": True}

    def test_write_with_no_bit_sends_nothing(self) -> None:
        recorder = Recorder(json_response({}))
        with pytest.raises(TypeError):
            sync_client(recorder).device_check.write(REQUEST_ID)
        with pytest.raises(TypeError):
            sync_client(recorder).device_check.write(REQUEST_ID, bit0=1)  # type: ignore[arg-type]

        async def go() -> None:
            async with async_client(recorder) as fingerly:
                await fingerly.device_check.write(REQUEST_ID)

        with pytest.raises(TypeError):
            run(go())
        assert recorder.calls == 0

    def test_request_id_is_one_segment(self) -> None:
        recorder = Recorder(
            json_response({"found": False, "bit0": False, "bit1": False})
        )
        sync_client(recorder).device_check.query("../a")
        assert recorder.url == (
            "https://api.fingerly.io/api/v1/events/%2E%2E%2Fa/device-check/query"
        )


class TestErrors:
    @pytest.mark.parametrize(
        ("code", "status"),
        [
            ("device_check_not_held", 404),
            ("device_check_spent", 409),
            ("device_check_busy", 409),
            ("credential_unavailable", 409),
            ("bits_required", 422),
        ],
    )
    def test_each_code_is_typed_and_not_retried(self, code: str, status: int) -> None:
        recorder = Recorder(error_response(code, status))
        for result in query_both(recorder) + write_both(recorder, bit0=True):
            assert isinstance(result, FingerlyDeviceCheckError)
            assert result.code == code
            assert result.status == status
            assert result.apple_status is None
            assert result.request_id == "trace"
        assert recorder.calls == 4

    def test_apple_rejected_carries_apples_status(self) -> None:
        recorder = Recorder(apple_rejected(400))
        for result in query_both(recorder) + write_both(recorder, bit0=True):
            assert isinstance(result, FingerlyDeviceCheckError)
            assert result.code == "apple_rejected"
            assert result.status == 422
            assert result.apple_status == 400
        assert recorder.calls == 4

    @pytest.mark.parametrize("status", [429, 500, 502])
    def test_other_failures_are_not_retried(self, status: int) -> None:
        recorder = Recorder(error_response("server_error", status))
        for result in query_both(recorder):
            assert isinstance(result, FingerlyDeviceCheckError)
            assert result.status == status
        assert recorder.calls == 2


class TestRetry:
    def test_503_retries_the_identical_write(self) -> None:
        recorder = Recorder(
            error_response("device_check_unavailable", 503),
            json_response({"bit0": True}),
        )
        assert sync_client(recorder).device_check.write(
            REQUEST_ID, bit0=True
        ) == DeviceCheckWriteResult(bit0=True)
        assert recorder.calls == 2
        first, second = recorder.requests
        assert (first.method, str(first.url), first.content) == (
            second.method,
            str(second.url),
            second.content,
        )
        assert json.loads(second.content) == {"bit0": True}

    def test_503_retries_the_identical_query_async(self) -> None:
        recorder = Recorder(
            error_response("device_check_unavailable", 503),
            error_response("device_check_unavailable", 503),
            json_response({"found": True, "bit0": False, "bit1": True}),
        )

        async def go() -> DeviceCheckBits:
            async with async_client(recorder) as fingerly:
                return await fingerly.device_check.query(REQUEST_ID)

        assert run(go()) == DeviceCheckBits(found=True, bit0=False, bit1=True)
        assert recorder.calls == 3
        assert {(r.method, str(r.url), r.content) for r in recorder.requests} == {
            ("POST", BASE + "/device-check/query", b"")
        }

    def test_503_gives_up_after_three_attempts(self) -> None:
        recorder = Recorder(error_response("device_check_unavailable", 503))
        results = write_both(recorder, bit1=False)
        for result in results:
            assert isinstance(result, FingerlyDeviceCheckError)
            assert result.code == "device_check_unavailable"
        assert recorder.calls == 6

    def test_transport_failure_retries_the_same_request(self) -> None:
        seen: list[httpx.Request] = []

        def flaky(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if len(seen) == 1:
                raise httpx.ConnectError("refused", request=request)
            return json_response({"bit0": True})

        recorder = Recorder.of(flaky)
        assert sync_client(recorder).device_check.write(
            REQUEST_ID, bit0=True
        ) == DeviceCheckWriteResult(bit0=True)
        assert len(seen) == 2
        assert seen[0].content == seen[1].content == b'{"bit0":true}'

    def test_transport_failure_surfaces_after_the_retries(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        recorder = Recorder.of(down)
        with pytest.raises(FingerlyConnectionError):
            sync_client(recorder).device_check.query(REQUEST_ID)
        assert recorder.calls == 3

    def test_409_after_a_503_is_not_retried(self) -> None:
        recorder = Recorder(
            error_response("device_check_unavailable", 503),
            error_response("device_check_spent", 409),
            json_response({"bit0": True}),
        )
        with pytest.raises(FingerlyDeviceCheckError) as raised:
            sync_client(recorder).device_check.write(REQUEST_ID, bit0=True)
        assert raised.value.code == "device_check_spent"
        assert recorder.calls == 2
