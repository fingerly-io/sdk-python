"""The events client accepts only a bare https origin as its endpoint."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import SECRET_KEY, Recorder, event_body, json_response

from fingerly import AsyncFingerly, Fingerly

CLIENTS = [Fingerly, AsyncFingerly]


@pytest.mark.parametrize("cls", CLIENTS)
@pytest.mark.parametrize(
    "endpoint",
    [
        "http://api.invalid",
        "http://192.0.2.10:8080",
        "https://api.invalid/prefix",
        "https://api.invalid/a/../b",
        "https://api.invalid//",
        "https://api.invalid?",
        "https://api.invalid?x=1",
        "https://api.invalid#",
        "https://api.invalid#f",
        "https://user:pass@api.invalid",
        "https://@api.invalid",
        "https://api.invalid\n",
        "https://api.invalid ",
        " https://api.invalid",
        "https://api.invalid\r\nx-injected: 1",
        "https://api.invalid\t",
        "https://é.invalid",
        "ftp://api.invalid",
        "api.invalid",
        "",
    ],
)
def test_refuses_anything_but_a_bare_https_origin(cls: Any, endpoint: str) -> None:
    for allow in (False, True):
        with pytest.raises(TypeError, match="endpoint must") as raised:
            cls(
                secret_key=SECRET_KEY,
                endpoint=endpoint,
                allow_insecure_loopback=allow,
            )
        message = str(raised.value)
        assert "api.invalid" not in message
        assert SECRET_KEY not in message


@pytest.mark.parametrize("cls", CLIENTS)
@pytest.mark.parametrize(
    "endpoint", ["http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9"]
)
def test_plain_http_loopback_needs_the_flag(cls: Any, endpoint: str) -> None:
    with pytest.raises(TypeError, match="allow_insecure_loopback"):
        cls(secret_key=SECRET_KEY, endpoint=endpoint)
    cls(secret_key=SECRET_KEY, endpoint=endpoint, allow_insecure_loopback=True)


def test_the_flag_must_be_a_bool() -> None:
    with pytest.raises(TypeError):
        Fingerly(
            secret_key=SECRET_KEY,
            allow_insecure_loopback="yes",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("https://api.invalid", "https://api.invalid/api/v1/events/id"),
        ("https://api.invalid/", "https://api.invalid/api/v1/events/id"),
        ("https://api.invalid:8443", "https://api.invalid:8443/api/v1/events/id"),
        ("https://API.invalid", "https://api.invalid/api/v1/events/id"),
        ("http://127.0.0.1:9", "http://127.0.0.1:9/api/v1/events/id"),
    ],
)
def test_the_base_url_is_rebuilt_from_scheme_host_and_port(
    endpoint: str, expected: str
) -> None:
    recorder = Recorder(json_response(event_body()))
    with Fingerly(
        secret_key=SECRET_KEY,
        endpoint=endpoint,
        allow_insecure_loopback=True,
        transport=recorder.transport(),
    ) as fingerly:
        fingerly.events.get("id")
    assert recorder.url == expected
