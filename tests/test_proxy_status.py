"""An upstream status outside 200 to 599 is answered 502."""

from __future__ import annotations

import pytest
from conftest import Recorder, json_response
from raw_upstream import answering, real
from test_proxy import BROWSER, both, proxy


@pytest.mark.parametrize("status", [100, 101, 199, 600, 700, 999])
def test_a_status_outside_200_to_599_is_a_bad_gateway(status: int) -> None:
    recorder = Recorder(json_response({}, status=status))
    for adapter, call in both(proxy(recorder)):
        got, headers, payload = call(adapter, headers=BROWSER)
        assert (got, payload) == (502, b"Bad gateway")
        assert headers["cache-control"] == "no-store"


@pytest.mark.parametrize("status", [200, 299, 400, 599])
def test_a_status_at_the_edges_is_relayed(status: int) -> None:
    recorder = Recorder(json_response({}, status=status))
    for adapter, call in both(proxy(recorder)):
        got, headers, _ = call(adapter, headers=BROWSER)
        assert got == status
        assert headers["cache-control"] == "no-store"


@pytest.mark.parametrize("code", ["600", "999"])
def test_a_raw_out_of_range_status_is_a_bad_gateway(code: str) -> None:
    upstream = answering(code)
    try:
        for adapter, call in both(real(upstream.origin)):
            got, headers, _ = call(adapter, headers=BROWSER)
            assert got == 502
            assert headers["cache-control"] == "no-store"
        assert upstream.hits == 2
    finally:
        upstream.close()
