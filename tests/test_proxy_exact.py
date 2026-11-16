"""Exact path, exact method, and no-store on every refusal."""

from __future__ import annotations

import pytest
from conftest import Recorder, json_response
from test_proxy import BROWSER, PATH, both, call_asgi, call_wsgi, proxy


@pytest.mark.parametrize("method", ["post", "Post", "pOST", "GET", "PUT", "DELETE"])
def test_only_an_exact_post_is_forwarded(method: str) -> None:
    recorder = Recorder(json_response({}))
    for adapter, call in both(proxy(recorder)):
        got, headers, _ = call(adapter, method=method, headers=BROWSER)
        assert got == 405
        assert headers["allow"] == "POST"
        assert headers["cache-control"] == "no-store"
    assert recorder.calls == 0


@pytest.mark.parametrize("method", ["options", "OPTIONS"])
def test_options_without_cors_is_a_405(method: str) -> None:
    recorder = Recorder(json_response({}))
    for adapter, call in both(proxy(recorder)):
        got, headers, _ = call(adapter, method=method, headers=BROWSER)
        assert got == 405
        assert headers["cache-control"] == "no-store"


def test_lowercase_options_is_not_a_preflight() -> None:
    recorder = Recorder(json_response({}))
    app = proxy(recorder, allowed_origins=["https://shop.test"])
    for adapter, call in both(app):
        got, headers, _ = call(adapter, method="options", headers=BROWSER)
        assert got == 405
        assert headers["allow"] == "POST, OPTIONS"
        assert headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "path", [PATH + "/", "/" + PATH, PATH + "x", PATH.upper(), "/x/.." + PATH]
)
def test_near_misses_are_uncacheable_404s(path: str) -> None:
    recorder = Recorder(json_response({}))
    for adapter, call in both(proxy(recorder)):
        got, headers, _ = call(adapter, path=path, headers=BROWSER)
        assert got == 404
        assert headers["cache-control"] == "no-store"
    assert recorder.calls == 0


@pytest.mark.parametrize(
    "raw", [PATH + "%2F", "/x/.." + PATH, "/." + PATH, "/k7x2qm4%61"]
)
def test_raw_targets_that_decode_to_the_path_are_404s(raw: str) -> None:
    recorder = Recorder(json_response({}))
    app = proxy(recorder)
    status, headers, _ = call_asgi(app.asgi, path=PATH, headers=BROWSER, raw_path=raw)
    assert (status, headers["cache-control"]) == (404, "no-store")
    status, headers, _ = call_wsgi(app.wsgi, path=PATH, headers=BROWSER, raw_uri=raw)
    assert (status, headers["cache-control"]) == (404, "no-store")
    assert recorder.calls == 0


@pytest.mark.parametrize(
    "raw",
    [
        "http://shop.test/x/../k7x2qm4a",
        "http://shop.test/k7x2qm4%61",
        "http://shop.test/./k7x2qm4a",
    ],
)
def test_absolute_form_targets_are_matched_raw(raw: str) -> None:
    recorder = Recorder(json_response({}))
    app = proxy(recorder)
    status, headers, _ = call_wsgi(app.wsgi, path=PATH, headers=BROWSER, raw_uri=raw)
    assert (status, headers["cache-control"]) == (404, "no-store")
    assert recorder.calls == 0
