"""One channel upstream, and an https upstream unless loopback is allowed."""

from __future__ import annotations

import pytest
from conftest import Recorder, json_response
from test_proxy import BROWSER, PROXY_KEY, PUBLIC_KEY, both, proxy

from fingerly import FingerlyProxy


class TestOneChannelUpstream:
    def test_origin_wins_over_a_valid_platform(self) -> None:
        recorder = Recorder(json_response({"request_id": "r"}))
        for adapter, call in both(proxy(recorder)):
            status, _, _ = call(
                adapter, headers={**BROWSER, "x-fingerly-sdk-platform": "ios"}
            )
            assert status == 200
            sent = recorder.requests[-1]
            assert sent.headers["x-fingerly-origin"] == "https://shop.test"
            assert "x-fingerly-sdk-platform" not in sent.headers

    def test_a_native_call_keeps_its_platform(self) -> None:
        recorder = Recorder(json_response({}))
        for adapter, call in both(proxy(recorder)):
            status, _, _ = call(
                adapter,
                headers={"x-api-key": PUBLIC_KEY, "x-fingerly-sdk-platform": "android"},
            )
            assert status == 200
            sent = recorder.requests[-1]
            assert sent.headers["x-fingerly-sdk-platform"] == "android"
            assert "x-fingerly-origin" not in sent.headers


class TestHttpsUpstream:
    @pytest.mark.parametrize(
        "upstream",
        ["http://upstream.invalid", "http://192.0.2.10:8080", "http://10.0.0.1"],
    )
    def test_plain_http_on_another_host_is_refused(self, upstream: str) -> None:
        for allow in (False, True):
            with pytest.raises(TypeError, match="upstream must use https") as raised:
                FingerlyProxy(
                    proxy_key=PROXY_KEY,
                    upstream=upstream,
                    allow_insecure_loopback=allow,
                    client_ip=lambda _: "",
                )
            assert upstream not in str(raised.value)

    @pytest.mark.parametrize(
        "upstream", ["http://127.0.0.1:9", "http://localhost:9", "http://[::1]:9"]
    )
    def test_plain_http_loopback_needs_the_flag(self, upstream: str) -> None:
        with pytest.raises(TypeError, match="allow_insecure_loopback"):
            FingerlyProxy(
                proxy_key=PROXY_KEY, upstream=upstream, client_ip=lambda _: ""
            )
        FingerlyProxy(
            proxy_key=PROXY_KEY,
            upstream=upstream,
            allow_insecure_loopback=True,
            client_ip=lambda _: "",
        )

    def test_the_flag_must_be_a_bool(self) -> None:
        with pytest.raises(TypeError):
            FingerlyProxy(
                proxy_key=PROXY_KEY,
                client_ip=lambda _: "",
                allow_insecure_loopback="yes",  # type: ignore[arg-type]
            )
