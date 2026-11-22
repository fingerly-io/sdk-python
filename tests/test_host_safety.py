"""Agent sightings may never hurt the process they run in.

Each test pins a hazard found by running real apps against a hostile API:
sightings lost on shutdown, a forked worker that never reported, a report
stuck in flight after a cancelled send, a header scan that could fail the
response it watched.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx
from conftest import SECRET_KEY, Recorder, json_response

from fingerly import (
    AgentSightings,
    Fingerly,
    FingerlyProxy,
    ProxyRequest,
)
from fingerly._proxy import Headers

GPTBOT = "Mozilla/5.0 (compatible; GPTBot/1.2)"


def visitor(n: int = 0, ip: Optional[str] = "203.0.113.9") -> ProxyRequest:
    return ProxyRequest(
        method="GET",
        path="/",
        headers=Headers([("user-agent", f"{GPTBOT} #{n}"), ("host", "shop.test")]),
        peer_host=ip,
    )


def answering() -> Recorder:
    def handler(sent: httpx.Request) -> httpx.Response:
        items = json.loads(sent.content)["items"]
        return json_response(
            {
                "rules_version": "r1",
                "items": [{"ttl": 60, "visitor_kind": "human"} for _ in items],
            }
        )

    return Recorder.of(handler)


def sync_sightings(recorder: Recorder, **options: Any) -> AgentSightings:
    client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
    options.setdefault("background", False)
    return AgentSightings(
        client, client_ip=lambda request: request.peer_host, **options
    )


def items_sent(recorder: Recorder) -> int:
    return sum(len(json.loads(r.content)["items"]) for r in recorder.requests)


class TestClientIP:
    def test_a_callback_may_return_none(self) -> None:
        recorder = answering()
        # `request.peer_host` is Optional[str]; the callback type accepts it.
        sightings = sync_sightings(recorder)
        sightings.report(visitor(ip=None), "text/html")
        sightings.report(visitor(1), "text/html")
        sightings.flush()
        assert items_sent(recorder) == 1
        proxy = FingerlyProxy(
            proxy_key="fly_px_development_test",
            client_ip=lambda request: request.peer_host,
        )
        assert proxy is not None
