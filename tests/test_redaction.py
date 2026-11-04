"""Credentials never print: repr, str, vars, pickling and error messages."""

from __future__ import annotations

import pickle
import pprint
from typing import Any

import httpx
import pytest
from conftest import Recorder, error_response, json_response, run

from fingerly import AsyncFingerly, Fingerly, FingerlyAPIError, FingerlyProxy

SECRET_KEY = "fly_sk_development_redactme0123456789"
PROXY_KEY = "fly_px_development_redactme0123456789"


def _state(value: Any, depth: int = 0, seen: Any = None) -> str:
    """Everything a debugger or an object-dumping error tracker would show."""
    seen = set() if seen is None else seen
    if id(value) in seen or depth > 4:
        return ""
    seen.add(id(value))
    parts = [repr(value), str(value)]
    attributes = getattr(value, "__dict__", None)
    if isinstance(attributes, dict):
        parts.append(pprint.pformat(attributes))
        for item in attributes.values():
            parts.append(_state(item, depth + 1, seen))
    if isinstance(value, (list, tuple)):
        for item in value:
            parts.append(_state(item, depth + 1, seen))
    if isinstance(value, httpx.Headers):
        parts.append(str(dict(value)))
    return "\n".join(parts)


def _objects() -> list[Any]:
    reader = Fingerly(secret_key=SECRET_KEY)
    areader = AsyncFingerly(secret_key=SECRET_KEY)
    proxy = FingerlyProxy(proxy_key=PROXY_KEY, client_ip=lambda r: "203.0.113.1")
    legacy = FingerlyProxy(secret_key=SECRET_KEY, client_ip=lambda r: "203.0.113.1")
    return [reader, reader.events, areader, proxy, proxy.asgi, proxy.wsgi, legacy]


@pytest.mark.parametrize("index", range(7))
def test_no_object_shows_a_credential(index: int) -> None:
    value = _objects()[index]
    dumped = _state(value)
    assert SECRET_KEY not in dumped
    assert PROXY_KEY not in dumped
    assert "[redacted]" in dumped


@pytest.mark.parametrize("index", [0, 2, 3])
def test_pickling_never_writes_a_credential(index: int) -> None:
    with pytest.raises(TypeError):
        pickle.dumps(_objects()[index])


def test_the_key_still_reaches_the_api() -> None:
    recorder = Recorder(json_response({}))
    with Fingerly(secret_key=SECRET_KEY, transport=recorder.transport()) as reader:
        assert repr(reader) == (
            "Fingerly(endpoint='https://api.fingerly.io/api/v1', secret_key=[redacted])"
        )
        with pytest.raises(Exception):  # noqa: B017 - an empty event
            reader.events.get("id")
    assert recorder.requests[0].headers["x-api-key"] == SECRET_KEY


def test_errors_never_show_a_credential() -> None:
    body = {"error": {"code": SECRET_KEY}, "request_id": SECRET_KEY}
    recorder = Recorder(json_response(body, 401))

    async def read() -> None:
        async with AsyncFingerly(
            secret_key=SECRET_KEY, transport=recorder.transport()
        ) as reader:
            await reader.events.get("id")

    with pytest.raises(FingerlyAPIError) as caught:
        run(read())
    assert SECRET_KEY not in _state(caught.value)
    assert SECRET_KEY not in repr(caught.value.code) + str(caught.value.request_id)
    # The generic shape stays readable.
    recorder = Recorder(error_response("unauthorized", 401))
    with (
        Fingerly(secret_key=SECRET_KEY, transport=recorder.transport()) as reader,
        pytest.raises(FingerlyAPIError) as plain,
    ):
        reader.events.get("id")
    assert plain.value.code == "unauthorized"
