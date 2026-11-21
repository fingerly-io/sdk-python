"""Agent sightings: the cache key, the buffer, the flusher and the failure table.

Every behaviour here is fixed by ``contract/agent-sightings.md``, which every
Fingerly server SDK implements identically.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Union

import httpx
import pytest
from conftest import SECRET_KEY, Recorder, error_response, json_response, run

import fingerly._sightings as sightings_module
from fingerly import (
    AGENT_UNKNOWN,
    AgentAnswer,
    AgentSighting,
    AgentSightings,
    AIVerificationMethod,
    AIVerificationResult,
    AsyncAgentSightings,
    AsyncFingerly,
    Fingerly,
    FingerlyAPIError,
    ProxyRequest,
    VisitorKind,
)
from fingerly._proxy import Headers
from fingerly._sightings import (
    BACKOFF_MAX,
    FLUSH_WAIT,
    MAX_CACHE_SIZE,
    MAX_PENDING,
    MAX_TTL,
    canonical_ip,
    sighting_key,
)

CONTRACT = Path(__file__).resolve().parent.parent / "contract"
VECTORS: list[dict[str, Any]] = json.loads(
    (CONTRACT / "agent-sightings-vectors.json").read_text()
)["vectors"]
FIXTURES: dict[str, Any] = json.loads((CONTRACT / "fixtures.json").read_text())
SIGHTINGS_URL = "https://api.fingerly.io/api/v1/agents/sightings"
GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4"


class Clock:
    """A monotonic clock the test moves by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def latin1(text: str) -> str:
    """A header value as both server standards hand it over."""
    return text.encode("utf-8").decode("latin-1")


def request(
    user_agent: Optional[str] = GPTBOT,
    ip: str = "20.171.206.9",
    path: str = "/",
    **headers: str,
) -> ProxyRequest:
    """A request as the adapters build it; extra headers by keyword."""
    items = [("host", "shop.test"), ("cf-connecting-ip", ip)]
    if user_agent is not None:
        items.append(("user-agent", latin1(user_agent)))
    items.extend(
        (name.replace("_", "-"), latin1(value)) for name, value in headers.items()
    )
    return ProxyRequest(method="GET", path=path, headers=Headers(items))


def answering(
    ttl: Union[int, Callable[[dict[str, Any]], int]] = 900,
    rules_version: str = "rules-1",
    visitor_kind: str = "ai_bot",
) -> Recorder:
    """A fake API answering every reported item."""

    def handler(sent: httpx.Request) -> httpx.Response:
        items = json.loads(sent.content)["items"]
        return json_response(
            {
                "rules_version": rules_version,
                "items": [
                    {
                        "ttl": ttl(item) if callable(ttl) else ttl,
                        "visitor_kind": visitor_kind,
                        "agent": "GPTBot",
                        "ai": {
                            "name": "GPTBot",
                            "provider": "OpenAI",
                            "purpose": "training",
                            "runtime": "provider_cloud",
                            "declared": True,
                            "verification": {"method": "ip_list", "result": "pass"},
                        },
                    }
                    for item in items
                ],
            }
        )

    return Recorder.of(handler)


def build(
    recorder: Recorder, clock: Optional[Clock] = None, **options: Any
) -> AgentSightings:
    client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
    options.setdefault("background", False)
    return AgentSightings(
        client,
        client_ip=lambda incoming: incoming.headers.get("cf-connecting-ip", ""),
        clock=clock or Clock(),
        **options,
    )


def sent_items(recorder: Recorder, index: int = -1) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = json.loads(recorder.requests[index].content)["items"]
    return items


def seen(sightings: AgentSightings, incoming: ProxyRequest, times: int = 1) -> None:
    for _ in range(times):
        sightings.report(incoming, "text/html; charset=utf-8")


class TestKey:
    @pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
    def test_reproduces_every_vector(self, vector: dict[str, Any]) -> None:
        assert canonical_ip(vector["client_ip"]) == vector["canonical_ip"]
        key = sighting_key(
            vector["user_agent"],
            vector["client_ip"],
            vector["signature_agent"],
            vector["signed"],
        )
        assert key == vector["key"]

    @pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
    def test_a_request_hashes_to_the_vector_key(self, vector: dict[str, Any]) -> None:
        # The bytes arrive Latin-1 decoded, as ASGI and WSGI deliver them.
        headers: dict[str, str] = {}
        if vector["signature_agent"]:
            headers["signature_agent"] = vector["signature_agent"]
        if vector["signed"]:
            headers["signature"] = "sig1=:AAAA:"
            headers["signature_input"] = 'sig1=("@authority");created=1'
        incoming = request(vector["user_agent"], vector["client_ip"], **headers)
        recorder = answering()
        sightings = build(recorder)
        observed = sightings._observe(incoming)
        assert observed is not None
        assert observed.key == vector["key"]
        assert observed.item.client_ip == vector["canonical_ip"]
        assert observed.item.user_agent == vector["user_agent"]


class TestClient:
    def test_posts_items_and_reads_the_fixture(self) -> None:
        fixture = next(
            row for row in FIXTURES["responses"] if row["name"] == "agent_sightings"
        )
        recorder = Recorder(json_response(fixture["body"]))
        with Fingerly(secret_key=SECRET_KEY, transport=recorder.transport()) as client:
            result = client.agents.sightings(
                [
                    AgentSighting(user_agent="", client_ip="198.51.100.1"),
                    AgentSighting(
                        user_agent=GPTBOT,
                        client_ip="20.171.206.9",
                        host="shop.test",
                        method="GET",
                        count=3,
                    ),
                ]
            )
        sent = recorder.requests[0]
        assert str(sent.url) == SIGHTINGS_URL
        assert sent.method == "POST"
        assert sent.headers["x-api-key"] == SECRET_KEY
        assert sent.headers["content-type"] == "application/json"
        assert json.loads(sent.content) == {
            "items": [
                {"user_agent": "", "client_ip": "198.51.100.1"},
                {
                    "user_agent": GPTBOT,
                    "client_ip": "20.171.206.9",
                    "host": "shop.test",
                    "method": "GET",
                    "count": 3,
                },
            ]
        }

        assert result.rules_version == "0123456789abcdef"
        human, gptbot, user_fetch, signed, googlebot = result.items
        assert human == AgentAnswer(ttl=3600, visitor_kind=VisitorKind.HUMAN)
        assert human.known
        assert gptbot.agent == "GPTBot"
        assert gptbot.ai is not None
        assert gptbot.ai.verification.method == AIVerificationMethod.IP_LIST
        assert gptbot.ai.verification.result == AIVerificationResult.PASS
        assert user_fetch.ai is not None
        assert user_fetch.ai.verification.result == AIVerificationResult.FAIL
        assert signed.ttl == 0
        assert signed.ai is not None
        assert signed.ai.verification.method == AIVerificationMethod.SIGNATURE
        assert googlebot.visitor_kind == VisitorKind.SEARCH_CRAWLER
        assert googlebot.ai is None

    def test_a_refusal_carries_retry_after_and_its_scope(self) -> None:
        refused = error_response("rate_limited", 429)
        refused.headers["retry-after"] = "3600"
        refused.headers["fingerly-ratelimit-scope"] = "daily"
        recorder = Recorder(refused)
        client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
        with pytest.raises(FingerlyAPIError) as caught:
            client.agents.sightings([AgentSighting(user_agent="", client_ip="::1")])
        assert caught.value.status == 429
        assert caught.value.code == "rate_limited"
        assert caught.value.retry_after == 3600
        assert caught.value.rate_limit_scope == "daily"

    def test_the_async_client_posts_the_same_body(self) -> None:
        recorder = answering()

        async def call() -> Any:
            async with AsyncFingerly(
                secret_key=SECRET_KEY, transport=recorder.transport()
            ) as client:
                return await client.agents.sightings(
                    [AgentSighting(user_agent=GPTBOT, client_ip="20.171.206.9")]
                )

        result = run(call())
        assert result.items[0].agent == "GPTBot"
        assert str(recorder.requests[0].url) == SIGHTINGS_URL

    def test_refuses_an_item_that_is_not_a_sighting(self) -> None:
        recorder = answering()
        client = Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
        with pytest.raises(TypeError):
            client.agents.sightings([{"user_agent": "", "client_ip": "::1"}])  # type: ignore[list-item]
        assert recorder.calls == 0


class TestCache:
    def test_answers_from_the_cache_after_a_flush(self) -> None:
        recorder = answering(ttl=900)
        sightings = build(recorder)
        incoming = request()
        assert sightings.lookup(incoming) is AGENT_UNKNOWN
        assert not sightings.lookup(incoming).known
        seen(sightings, incoming)
        sightings.flush()
        answer = sightings.lookup(incoming)
        assert answer.visitor_kind == VisitorKind.AI_BOT
        assert answer.ai is not None
        assert answer.ai.verification.result == AIVerificationResult.PASS

    def test_lru_is_bounded_and_evicts_the_least_recently_used(self) -> None:
        recorder = answering()
        sightings = build(recorder, cache_size=2)
        first, second, third = (request(f"agent/{n}") for n in range(3))
        seen(sightings, first)
        seen(sightings, second)
        sightings.flush()
        assert sightings.lookup(first).known  # first is now the most recent
        seen(sightings, third)
        sightings.flush()
        assert len(sightings._cache) == 2
        assert sightings.lookup(first).known
        assert sightings.lookup(second) is AGENT_UNKNOWN
        assert sightings.lookup(third).known

    def test_capacity_is_clamped_to_the_hard_maximum(self) -> None:
        recorder = answering()
        assert build(recorder, cache_size=10**6)._capacity == MAX_CACHE_SIZE
        assert build(recorder)._capacity == 4096
        for bad in (0, -1, True, 1.5):
            with pytest.raises(TypeError):
                build(recorder, cache_size=bad)

    def test_an_answer_expires_after_its_ttl(self) -> None:
        clock = Clock()
        sightings = build(answering(ttl=10), clock)
        incoming = request()
        seen(sightings, incoming)
        sightings.flush()
        clock.advance(9.9)
        assert sightings.lookup(incoming).known
        clock.advance(0.1)
        assert sightings.lookup(incoming) is AGENT_UNKNOWN
        assert len(sightings._cache) == 0

    def test_ttl_zero_is_never_cached(self) -> None:
        sightings = build(answering(ttl=0))
        incoming = request()
        seen(sightings, incoming)
        sightings.flush()
        assert sightings.lookup(incoming) is AGENT_UNKNOWN
        assert len(sightings._cache) == 0

    def test_a_ttl_is_clamped_to_one_day(self) -> None:
        clock = Clock()
        sightings = build(answering(ttl=30 * 86400), clock)
        incoming = request()
        seen(sightings, incoming)
        sightings.flush()
        assert MAX_TTL == 86400
        clock.advance(86399.9)
        assert sightings.lookup(incoming).known
        clock.advance(0.1)
        assert sightings.lookup(incoming) is AGENT_UNKNOWN

    def test_a_new_rules_version_drops_every_answer(self) -> None:
        version = ["rules-1"]

        def handler(sent: httpx.Request) -> httpx.Response:
            items = json.loads(sent.content)["items"]
            return json_response(
                {
                    "rules_version": version[0],
                    "items": [{"ttl": 900, "visitor_kind": "human"} for _ in items],
                }
            )

        sightings = build(Recorder.of(handler))
        old, new = request("old/1"), request("new/1")
        seen(sightings, old)
        sightings.flush()
        assert sightings.lookup(old).known
        version[0] = "rules-2"
        seen(sightings, new)
        sightings.flush()
        assert sightings.lookup(old) is AGENT_UNKNOWN
        assert sightings.lookup(new).known

    def test_lookup_never_raises(self) -> None:
        def broken(_: ProxyRequest) -> str:
            raise RuntimeError("misconfigured")

        sightings = AgentSightings(
            Fingerly(secret_key=SECRET_KEY, transport=answering().transport()),
            client_ip=broken,
            background=False,
        )
        assert sightings.lookup(request()) is AGENT_UNKNOWN
        assert sightings.lookup(object()) is AGENT_UNKNOWN
        assert sightings.lookup({"type": "websocket"}) is AGENT_UNKNOWN

    def test_lookup_reads_scopes_environs_and_framework_requests(self) -> None:
        sightings = build(answering())
        seen(sightings, request())
        sightings.flush()
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (b"user-agent", GPTBOT.encode()),
                (b"cf-connecting-ip", b"20.171.206.9"),
                (b"host", b"shop.test"),
            ],
        }
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "HTTP_USER_AGENT": GPTBOT,
            "HTTP_CF_CONNECTING_IP": "20.171.206.9",
            "HTTP_HOST": "shop.test",
        }

        class Framework:
            def __init__(self, **attributes: Any) -> None:
                self.__dict__.update(attributes)

        assert sightings.lookup(scope).known
        assert sightings.lookup(environ).known
        assert sightings.lookup(Framework(scope=scope)).known
        assert sightings.lookup(Framework(environ=environ)).known


class TestBuffer:
    def test_repeats_fold_into_one_item_with_a_count(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        seen(sightings, request(), times=3)
        sightings.flush()
        (item,) = sent_items(recorder)
        assert item["count"] == 3
        assert item == {
            "user_agent": GPTBOT,
            "client_ip": "20.171.206.9",
            "host": "shop.test",
            "method": "GET",
            "count": 3,
        }

    def test_cache_hits_keep_counting(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        incoming = request()
        seen(sightings, incoming)
        sightings.flush()
        assert sightings.lookup(incoming).known
        seen(sightings, incoming, times=4)
        sightings.flush()
        (item,) = sent_items(recorder)
        assert item["count"] == 4

    def test_signed_requests_are_never_folded(self) -> None:
        recorder = answering(ttl=0)
        sightings = build(recorder)
        signed = request(
            signature="sig1=:AAAA:",
            signature_input='sig1=("@authority");created=1',
            signature_agent='"https://chatgpt.com"',
        )
        seen(sightings, signed, times=3)
        sightings.flush()
        items = sent_items(recorder)
        assert len(items) == 3
        assert all(item["count"] == 1 for item in items)
        assert items[0]["signature"] == "sig1=:AAAA:"
        assert items[0]["signature_agent"] == '"https://chatgpt.com"'

    def test_the_buffer_is_capped_and_counts_drops(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        for n in range(MAX_PENDING):
            seen(sightings, request(f"agent/{n}"))
        assert sightings.dropped == 0
        seen(sightings, request("one/more"))
        assert sightings.dropped == 1
        assert sightings.lookup(request("one/more")) is AGENT_UNKNOWN
        seen(sightings, request("agent/0"))  # an existing key keeps counting
        assert sightings.dropped == 1
        assert sightings._pending[sightings._observe(request("agent/0")).key].count == 2  # type: ignore[union-attr]
        assert sightings.pending == MAX_PENDING

    def test_in_flight_items_count_toward_the_cap(self) -> None:
        sightings = build(answering())
        for n in range(MAX_PENDING):
            seen(sightings, request(f"agent/{n}"))
        batch = sightings._take(sightings._clock(), force=True)
        assert batch is not None
        assert len(batch) == 200
        seen(sightings, request("one/more"))
        assert sightings.dropped == 1

    def test_never_sends_path_query_cookies_or_authorization(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        incoming = request(
            path="/account/orders",
            cookie="session=secret",
            authorization="Bearer secret",
            x_custom="private",
        )
        seen(sightings, incoming)
        sightings.flush()
        body = recorder.requests[0].content.decode()
        for secret in ("orders", "session", "Bearer", "private", "/account"):
            assert secret not in body


class TestOversize:
    def test_an_oversize_user_agent_is_not_reported(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        incoming = request("x" * 4097)
        seen(sightings, incoming)
        sightings.flush()
        assert recorder.calls == 0
        assert sightings.lookup(incoming) is AGENT_UNKNOWN

    def test_a_user_agent_of_exactly_4096_bytes_is_reported(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        seen(sightings, request("Ö" * 2048))  # two UTF-8 bytes each
        sightings.flush()
        assert recorder.calls == 1

    def test_an_oversize_signature_header_is_left_out(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        incoming = request(
            signature="s" * 4097,
            signature_input='sig1=("@authority")',
            signature_agent="a" * 4097,
        )
        observed = sightings._observe(incoming)
        assert observed is not None
        # Without a Signature the request is not signed, and the oversize
        # Signature-Agent hashes as absent.
        assert observed.key == sighting_key(GPTBOT, "20.171.206.9", "", False)
        seen(sightings, incoming)
        sightings.flush()
        (item,) = sent_items(recorder)
        assert "signature" not in item
        assert "signature_agent" not in item
        assert item["signature_input"] == 'sig1=("@authority")'

    def test_a_blank_signature_header_is_absent(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        incoming = request(
            signature="sig1=:AAAA:", signature_input=" \t ", signature_agent="  "
        )
        observed = sightings._observe(incoming)
        assert observed is not None
        # A blank Signature-Input leaves the request unsigned, and a blank
        # Signature-Agent hashes as absent.
        assert observed.key == sighting_key(GPTBOT, "20.171.206.9", "", False)
        seen(sightings, incoming)
        sightings.flush()
        (item,) = sent_items(recorder)
        assert item["signature"] == "sig1=:AAAA:"
        assert "signature_input" not in item
        assert "signature_agent" not in item

    def test_an_unresolved_client_ip_is_not_reported(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        recorder = answering()
        sightings = build(recorder)
        for value in ("", "203.0.113.1, 198.51.100.2", "fe80::1%eth0", "nope"):
            incoming = request(ip=value)
            with caplog.at_level(logging.WARNING, logger="fingerly.agents"):
                seen(sightings, incoming)
            assert sightings.lookup(incoming) is AGENT_UNKNOWN
        sightings.flush()
        assert recorder.calls == 0
        assert len(caplog.records) == 1
        assert "client IP" in caplog.records[0].getMessage()


class TestFlushTriggers:
    def test_flushes_two_seconds_after_the_oldest_item(self) -> None:
        clock = Clock()
        sightings = build(answering(), clock)
        seen(sightings, request())
        assert sightings._take(clock.now, force=False) is None
        clock.advance(1.9)
        assert sightings._wait_time(clock.now) == pytest.approx(0.1)
        assert sightings._take(clock.now, force=False) is None
        clock.advance(0.1)
        batch = sightings._take(clock.now, force=False)
        assert batch is not None
        assert len(batch) == 1

    def test_flushes_at_200_items(self) -> None:
        clock = Clock()
        sightings = build(answering(), clock)
        for n in range(199):
            seen(sightings, request(f"agent/{n}"))
        assert sightings._take(clock.now, force=False) is None
        seen(sightings, request("agent/199"))
        assert sightings._wait_time(clock.now) == 0
        batch = sightings._take(clock.now, force=False)
        assert batch is not None
        assert len(batch) == 200

    def test_flushes_at_64_kib_and_bounds_each_batch(self) -> None:
        clock = Clock()
        recorder = answering()
        sightings = build(recorder, clock)
        for n in range(16):
            seen(sightings, request(f"{n:04d}" + "x" * 4000))
        assert sightings._take(clock.now, force=False) is None
        seen(sightings, request("0016" + "x" * 4000))
        assert sightings._take(clock.now, force=False) is not None

    def test_one_batch_carries_at_most_64_kib(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        for n in range(40):
            seen(sightings, request(f"{n:04d}" + "x" * 4000))
        sightings.flush()
        sizes = [len(sent_items(recorder, index)) for index in range(recorder.calls)]
        assert sum(sizes) == 40
        assert max(sizes) == 16

    def test_at_most_one_flush_is_in_flight(self) -> None:
        clock = Clock()
        sightings = build(answering(), clock)
        for n in range(400):
            seen(sightings, request(f"agent/{n}"))
        assert sightings._take(clock.now, force=True) is not None
        assert sightings._take(clock.now, force=True) is None

    def test_flush_sends_everything_in_batches_of_200(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        for n in range(450):
            seen(sightings, request(f"agent/{n}"))
        sightings.flush()
        assert [len(sent_items(recorder, i)) for i in range(3)] == [200, 200, 50]
        assert sightings.pending == 0

    def test_the_background_thread_flushes_on_time(self) -> None:
        recorder = answering()
        sightings = build(recorder, clock=None, background=True)
        sightings._clock = time.monotonic
        try:
            seen(sightings, request())
            time.sleep(0.5)
            assert recorder.calls == 0
            deadline = time.monotonic() + 5
            while recorder.calls == 0 and time.monotonic() < deadline:
                time.sleep(0.05)
            assert recorder.calls == 1
            assert sightings._thread is not None
            assert sightings._thread.daemon
        finally:
            sightings.close()

    def test_the_background_thread_flushes_at_200_without_waiting(self) -> None:
        recorder = answering()
        sightings = build(recorder, background=True)
        sightings._clock = time.monotonic
        try:
            for n in range(200):
                seen(sightings, request(f"agent/{n}"))
            deadline = time.monotonic() + 1.5
            while recorder.calls == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert recorder.calls == 1
        finally:
            sightings.close()

    def test_close_flushes_and_then_ignores_records(self) -> None:
        recorder = answering()
        sightings = build(recorder, background=True)
        seen(sightings, request())
        sightings.close()
        assert recorder.calls == 1
        seen(sightings, request("later/1"))
        assert sightings.pending == 0
        sightings.close()
        assert recorder.calls == 1

    def test_flush_waits_at_most_six_seconds_for_a_flush_in_flight(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert FLUSH_WAIT == 6
        monkeypatch.setattr(sightings_module, "FLUSH_WAIT", 0.2)
        recorder = answering()
        sightings = build(recorder)
        seen(sightings, request())
        sightings._send_lock.acquire()  # a flush in flight that never ends
        try:
            started = time.monotonic()
            sightings.flush()  # returns, and does not raise
            assert 0.2 <= time.monotonic() - started < 1.0
        finally:
            sightings._send_lock.release()
        assert recorder.calls == 0
        assert sightings.pending == 1

    def test_the_async_flush_waits_at_most_six_seconds_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sightings_module, "FLUSH_WAIT", 0.2)
        recorder = answering()

        async def scenario() -> float:
            client = AsyncFingerly(
                secret_key=SECRET_KEY, transport=recorder.transport()
            )
            sightings = AsyncAgentSightings(
                client,
                client_ip=lambda incoming: incoming.headers["cf-connecting-ip"],
                background=False,
            )
            sightings.report(request(), "text/html")
            lock = sightings._lock_for_loop()
            await lock.acquire()  # a flush in flight that never ends
            started = time.monotonic()
            await sightings.flush()  # returns, and does not raise
            elapsed = time.monotonic() - started
            lock.release()
            assert sightings.pending == 1
            await sightings.flush()  # the lock was not kept by the timed-out wait
            assert sightings.pending == 0
            await client.aclose()
            return elapsed

        assert 0.2 <= run(scenario()) < 1.0
        assert recorder.calls == 1


def failing(*responses: httpx.Response) -> Recorder:
    """Answers with the given responses, then with answers for every item."""
    queue = list(responses)
    fallback = answering()

    def handler(sent: httpx.Request) -> httpx.Response:
        if queue:
            response = queue.pop(0)
            return httpx.Response(
                response.status_code,
                content=b"".join(response.stream),  # type: ignore[arg-type]
                headers=[
                    (name, value)
                    for name, value in response.headers.multi_items()
                    if name.lower() != "content-length"
                ],
            )
        return fallback(sent)

    return Recorder.of(handler)


def raising(*errors: Exception) -> Recorder:
    """Raises the given transport errors, then answers every item."""
    queue = list(errors)
    fallback = answering()

    def handler(sent: httpx.Request) -> httpx.Response:
        if queue:
            raise queue.pop(0)
        return fallback(sent)

    return Recorder.of(handler)


class Hangup:
    """A local API that reads each report in full, then sends ``reply`` and closes."""

    def __init__(self, reply: bytes) -> None:
        self.received = 0
        self._reply = reply
        self._stopping = False
        self._server = socket.create_server(("127.0.0.1", 0))
        self._server.settimeout(0.1)
        self.url = f"http://127.0.0.1:{self._server.getsockname()[1]}"
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stopping:
            try:
                connection, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(5)
                data = b""
                while b"\r\n\r\n" not in data:
                    data += connection.recv(65536)
                head, _, body = data.partition(b"\r\n\r\n")
                length = next(
                    int(line.split(b":", 1)[1])
                    for line in head.split(b"\r\n")
                    if line.lower().startswith(b"content-length:")
                )
                while len(body) < length:
                    body += connection.recv(65536)
                self.received += 1
                connection.sendall(self._reply)

    def stop(self) -> None:
        self._stopping = True
        self._thread.join(5)
        self._server.close()


#: Response headers, then less of the body than they announce.
CUT_SHORT = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
    b'Content-Length: 100\r\n\r\n{"rules_version":'
)


def refusal(status: int, code: str, **headers: str) -> httpx.Response:
    response = error_response(code, status)
    for name, value in headers.items():
        response.headers[name.replace("_", "-")] = value
    return response


class TestFailures:
    def setup_method(self) -> None:
        self.clock = Clock()

    def prime(self, recorder: Recorder) -> AgentSightings:
        sightings = build(recorder, self.clock)
        seen(sightings, request(), times=2)
        return sightings

    def test_422_drops_the_batch_and_logs_once_a_minute(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        recorder = failing(
            refusal(422, "invalid_request"), refusal(422, "invalid_request")
        )
        sightings = self.prime(recorder)
        with caplog.at_level(logging.WARNING, logger="fingerly.agents"):
            sightings.flush()
            assert sightings.pending == 0
            seen(sightings, request())
            sightings.flush()  # flushing is not paused
        assert recorder.calls == 2
        assert sightings.pending == 0
        assert len(caplog.records) == 1
        assert "422" in caplog.records[0].getMessage()
        assert GPTBOT not in caplog.text
        assert "20.171.206.9" not in caplog.text

    @pytest.mark.parametrize("status", [401, 403])
    def test_auth_drops_the_batch_and_pauses_60_seconds(
        self, status: int, caplog: pytest.LogCaptureFixture
    ) -> None:
        recorder = failing(refusal(status, "unauthorized"))
        sightings = self.prime(recorder)
        with caplog.at_level(logging.WARNING, logger="fingerly.agents"):
            sightings.flush()
        assert sightings.pending == 0
        assert len(caplog.records) == 1
        seen(sightings, request())
        self.clock.advance(59.9)
        sightings.flush()
        assert recorder.calls == 1
        self.clock.advance(0.1)
        sightings.flush()
        assert recorder.calls == 2
        assert sent_items(recorder)[0]["count"] == 1

    def test_429_keeps_the_batch_until_retry_after(self) -> None:
        recorder = failing(refusal(429, "rate_limited", retry_after="30"))
        sightings = self.prime(recorder)
        sightings.flush()
        assert sightings.pending == 1
        seen(sightings, request())  # still counting into the kept item
        seen(sightings, request("other/1"))
        self.clock.advance(29)
        sightings.flush()
        assert recorder.calls == 1
        self.clock.advance(1)
        sightings.flush()
        assert recorder.calls == 2
        first, second = sent_items(recorder)
        assert first["count"] == 3
        assert first["user_agent"] == GPTBOT
        assert second["user_agent"] == "other/1"

    def test_429_daily_without_retry_after_waits_for_the_utc_day(self) -> None:
        recorder = failing(
            refusal(429, "rate_limited", fingerly_ratelimit_scope="daily")
        )
        sightings = self.prime(recorder)
        sightings._utc_now = lambda: datetime(2026, 11, 21, 23, 0, tzinfo=timezone.utc)
        sightings.flush()
        assert sightings.pending == 1
        self.clock.advance(3599)
        sightings.flush()
        assert recorder.calls == 1
        self.clock.advance(1)
        sightings.flush()
        assert recorder.calls == 2

    def test_429_without_retry_after_waits_60_seconds(self) -> None:
        recorder = failing(refusal(429, "rate_limited"))
        sightings = self.prime(recorder)
        sightings.flush()
        self.clock.advance(59)
        sightings.flush()
        assert recorder.calls == 1
        self.clock.advance(1)
        sightings.flush()
        assert recorder.calls == 2

    @pytest.mark.parametrize(
        ("retry_after", "scope", "pause"),
        [
            ("0", None, 1),
            ("Thu, 01 Jan 2026 00:00:00 GMT", None, 1),  # a date already past
            ("-5", None, 60),  # unreadable: as if missing
            ("soon", None, 60),
            ("soon", "daily", 3600),
        ],
        ids=["zero", "past-date", "negative", "unreadable", "unreadable-daily"],
    )
    def test_429_pauses_at_least_one_second(
        self, retry_after: str, scope: Optional[str], pause: int
    ) -> None:
        headers = {"retry_after": retry_after}
        if scope is not None:
            headers["fingerly_ratelimit_scope"] = scope
        recorder = failing(refusal(429, "rate_limited", **headers))
        sightings = self.prime(recorder)
        sightings._utc_now = lambda: datetime(2026, 11, 21, 23, 0, tzinfo=timezone.utc)
        sightings.flush()
        assert sightings.pending == 1
        assert sightings._paused_until == self.clock.now + pause
        self.clock.advance(pause - 0.01)
        sightings.flush()
        assert recorder.calls == 1
        self.clock.advance(0.01)
        sightings.flush()
        assert recorder.calls == 2

    def test_503_keeps_the_batch_and_backs_off_up_to_60_seconds(self) -> None:
        unavailable = [refusal(503, "unavailable") for _ in range(8)]
        recorder = failing(*unavailable)
        sightings = self.prime(recorder)
        waits = []
        sightings.flush()
        for _ in range(8):
            wait = sightings._paused_until - self.clock.now
            waits.append(wait)
            self.clock.advance(wait - 0.01)
            calls = recorder.calls
            sightings.flush()
            assert recorder.calls == calls  # still backing off
            self.clock.advance(0.01)
            sightings.flush()
        assert waits == [1, 2, 4, 8, 16, 32, 60, 60]
        assert BACKOFF_MAX == 60
        assert sightings.pending == 0  # answered at last
        assert sent_items(recorder)[0]["count"] == 2
        assert sightings._backoff == 0

    @pytest.mark.parametrize(
        "error",
        [
            httpx.ConnectError("refused"),
            httpx.ConnectTimeout("connect"),
            httpx.RemoteProtocolError("closed without a response"),
        ],
        ids=["connect-error", "connect-timeout", "closed-without-response"],
    )
    def test_a_transport_error_before_a_response_keeps_the_batch(
        self, error: Exception
    ) -> None:
        recorder = raising(error)
        sightings = self.prime(recorder)
        sightings.flush()
        assert sightings.pending == 1
        assert sightings._paused_until == self.clock.now + 1
        self.clock.advance(1)
        sightings.flush()
        assert sightings.pending == 0
        assert sent_items(recorder)[0]["count"] == 2

    @pytest.mark.parametrize(
        "error",
        [httpx.ReadTimeout("read"), httpx.WriteTimeout("write")],
        ids=["read-timeout", "write-timeout"],
    )
    def test_a_timeout_after_sending_drops_the_batch(self, error: Exception) -> None:
        recorder = raising(error)
        sightings = self.prime(recorder)
        sightings.flush()
        assert sightings.pending == 0
        assert sightings._paused_until <= self.clock.now
        seen(sightings, request())
        sightings.flush()
        assert sent_items(recorder)[0]["count"] == 1

    @pytest.mark.parametrize(
        "reply", [b"", CUT_SHORT], ids=["closed-without-response", "body-cut-short"]
    )
    def test_a_connection_lost_after_the_report_was_written_drops_the_batch(
        self, reply: bytes
    ) -> None:
        server = Hangup(reply)
        client = Fingerly(
            secret_key=SECRET_KEY, endpoint=server.url, allow_insecure_loopback=True
        )
        try:
            sightings = AgentSightings(
                client,
                client_ip=lambda incoming: incoming.headers["cf-connecting-ip"],
                clock=self.clock,
                background=False,
            )
            seen(sightings, request(), times=2)
            sightings.flush()
            assert server.received == 1
            assert sightings.pending == 0
            assert sightings._paused_until <= self.clock.now
        finally:
            client.close()
            server.stop()

    @pytest.mark.parametrize(
        "reply", [b"", CUT_SHORT], ids=["closed-without-response", "body-cut-short"]
    )
    def test_the_async_flusher_drops_it_too(self, reply: bytes) -> None:
        server = Hangup(reply)

        async def scenario() -> int:
            async with AsyncFingerly(
                secret_key=SECRET_KEY, endpoint=server.url, allow_insecure_loopback=True
            ) as client:
                sightings = AsyncAgentSightings(
                    client,
                    client_ip=lambda incoming: incoming.headers["cf-connecting-ip"],
                    clock=self.clock,
                    background=False,
                )
                sightings.report(request(), "text/html")
                await sightings.flush()
                assert sightings._paused_until <= self.clock.now
                return sightings.pending

        try:
            assert run(scenario()) == 0
            assert server.received == 1
        finally:
            server.stop()

    @pytest.mark.parametrize("status", [400, 404, 413, 500, 502, 504])
    def test_any_other_status_drops_the_batch(self, status: int) -> None:
        recorder = failing(refusal(status, "other"))
        sightings = self.prime(recorder)
        sightings.flush()
        assert sightings.pending == 0
        assert sightings._paused_until <= self.clock.now

    def test_an_answer_of_the_wrong_length_drops_the_batch(self) -> None:
        recorder = failing(json_response({"rules_version": "r", "items": []}))
        sightings = self.prime(recorder)
        sightings.flush()
        assert sightings.pending == 0
        assert sightings.lookup(request()) is AGENT_UNKNOWN

    def test_lookup_keeps_answering_during_failures(self) -> None:
        recorder = answering()
        sightings = build(recorder, self.clock)
        seen(sightings, request())
        sightings.flush()
        broken = failing(refusal(503, "unavailable"))
        sightings._client = Fingerly(
            secret_key=SECRET_KEY, transport=broken.transport()
        )
        seen(sightings, request())
        sightings.flush()
        assert sightings.lookup(request()).known


class TestScope:
    def test_reports_html_and_the_agent_files_only(self) -> None:
        sightings = build(answering())
        cases = {
            ("/", "text/html; charset=utf-8"): True,
            ("/page", "application/xhtml+xml"): True,
            ("/page", "TEXT/HTML"): True,
            ("/robots.txt", "text/plain"): True,
            ("/llms.txt", None): True,
            ("/llms-full.txt", "text/markdown"): True,
            ("/robots.txt.bak", "text/plain"): False,
            ("/api/orders", "application/json"): False,
            ("/static/app.css", "text/css"): False,
            ("/health", None): False,
        }
        for (path, content_type), expected in cases.items():
            assert sightings._in_scope(path, content_type) is expected, path

    def test_include_and_exclude_prefixes_and_content_types(self) -> None:
        sightings = build(
            answering(),
            include_paths=["/api/public/"],
            exclude_paths=["/admin", "/robots.txt"],
            content_types=["text/html", "application/json"],
        )
        assert sightings._in_scope("/api/public/feed", "application/rss+xml")
        assert sightings._in_scope("/api/orders", "application/json")
        assert not sightings._in_scope("/admin/users", "text/html")
        assert not sightings._in_scope("/robots.txt", "text/plain")

    def test_configuration_is_validated(self) -> None:
        recorder = answering()
        with pytest.raises(TypeError):
            build(recorder, include_paths="/docs")
        with pytest.raises(TypeError):
            build(recorder, content_types=[1])
        with pytest.raises(TypeError):
            AgentSightings(  # type: ignore[call-arg]
                Fingerly(secret_key=SECRET_KEY, transport=recorder.transport())
            )
        with pytest.raises(TypeError):
            AgentSightings(object(), client_ip=lambda r: "::1")  # type: ignore[arg-type]

    def test_a_forked_child_starts_with_an_empty_buffer(self) -> None:
        recorder = answering()
        sightings = build(recorder)
        seen(sightings, request())
        sightings.flush()
        seen(sightings, request(), times=2)
        sightings._dropped = 3
        sightings._reset_after_fork()
        assert sightings.pending == 0
        assert sightings.dropped == 0
        assert sightings.lookup(request()).known  # answers are kept
        seen(sightings, request())
        sightings.flush()
        assert sent_items(recorder)[0]["count"] == 1


starlette_applications = pytest.importorskip("starlette.applications")
starlette_responses = pytest.importorskip("starlette.responses")
starlette_routing = pytest.importorskip("starlette.routing")
flask = pytest.importorskip("flask")

PAGES: dict[str, tuple[str, str]] = {
    "/": ("<html></html>", "text/html; charset=utf-8"),
    "/robots.txt": ("User-agent: *", "text/plain"),
    "/api/orders": ("[]", "application/json"),
    "/static/app.css": ("body{}", "text/css"),
    "/missing": ("<html>Not found</html>", "text/html"),
}
VISITOR = {"user-agent": GPTBOT, "cf-connecting-ip": "20.171.206.9"}


def starlette_app() -> Any:
    def page(path: str) -> Callable[[Any], Any]:
        async def endpoint(_: Any) -> Any:
            body, media_type = PAGES[path]
            status = 404 if path == "/missing" else 200
            return starlette_responses.Response(
                body, status_code=status, media_type=media_type
            )

        return endpoint

    return starlette_applications.Starlette(
        routes=[starlette_routing.Route(path, page(path)) for path in PAGES]
    )


def flask_app() -> Any:
    app = flask.Flask(__name__)

    def page(path: str) -> Callable[[], Any]:
        def view() -> Any:
            body, media_type = PAGES[path]
            status = 404 if path == "/missing" else 200
            return flask.Response(body, status=status, content_type=media_type)

        return view

    for path in PAGES:
        app.add_url_rule(path, path, page(path))
    return app


def reported_paths(recorder: Recorder) -> int:
    return sum(len(sent_items(recorder, i)) for i in range(recorder.calls))


class TestMiddleware:
    def test_asgi_reports_only_in_scope_responses(self) -> None:
        recorder = answering(ttl=900)

        async def drive() -> tuple[list[int], int, AgentAnswer]:
            client = AsyncFingerly(
                secret_key=SECRET_KEY, transport=recorder.transport()
            )
            sightings = AsyncAgentSightings(
                client,
                client_ip=lambda incoming: incoming.headers["cf-connecting-ip"],
                background=False,
            )
            app = sightings.asgi(starlette_app())
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://shop.test"
            ) as http:
                statuses = []
                for n, path in enumerate(PAGES):
                    headers = {**VISITOR, "user-agent": f"agent/{n}"}
                    response = await http.get(path + "?q=secret", headers=headers)
                    statuses.append(response.status_code)
                pending = sightings.pending
                await sightings.flush()
            answer = sightings.lookup(
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/",
                    "headers": [
                        (b"user-agent", b"agent/0"),
                        (b"cf-connecting-ip", b"20.171.206.9"),
                    ],
                }
            )
            await sightings.aclose()
            await client.aclose()
            return statuses, pending, answer

        statuses, pending, answer = run(drive())
        assert statuses == [200, 200, 200, 200, 404]
        assert pending == 3
        items = sent_items(recorder)
        assert [item["user_agent"] for item in items] == [
            "agent/0",
            "agent/1",
            "agent/4",
        ]
        assert "secret" not in recorder.requests[0].content.decode()
        assert answer.known

    def test_wsgi_reports_only_in_scope_responses(self) -> None:
        recorder = answering()
        sightings = build(recorder, exclude_paths=["/missing"])
        app = flask_app()
        app.wsgi_app = sightings.wsgi(app.wsgi_app)
        http = app.test_client()
        for n, path in enumerate(PAGES):
            response = http.get(path, headers={**VISITOR, "user-agent": f"agent/{n}"})
            assert response.status_code in (200, 404)
            response.close()
        sightings.flush()
        items = sent_items(recorder)
        assert [item["user_agent"] for item in items] == ["agent/0", "agent/1"]
        assert items[0]["host"] == "localhost"

    def test_asgi_passes_lifespan_and_websockets_through(self) -> None:
        calls: list[str] = []

        async def inner(scope: Any, receive: Any, send: Any) -> None:
            calls.append(scope["type"])

        sightings = build(answering())
        app = sightings.asgi(inner)

        async def receive() -> Any:
            return {}

        async def send(_: Any) -> None:
            return None

        run(app({"type": "lifespan"}, receive, send))
        assert calls == ["lifespan"]
        assert sightings.pending == 0

    def test_the_response_never_waits_on_a_report(self) -> None:
        release = threading.Event()
        inner = answering()

        def handler(sent: httpx.Request) -> httpx.Response:
            release.wait(10)
            return inner(sent)

        recorder = Recorder.of(handler)
        sightings = build(recorder, background=True)
        sightings._clock = time.monotonic
        app = flask_app()
        app.wsgi_app = sightings.wsgi(app.wsgi_app)
        http = app.test_client()
        try:
            for n in range(200):  # the 200th starts a flush, which hangs
                http.get("/", headers={**VISITOR, "user-agent": f"agent/{n}"}).close()
            deadline = time.monotonic() + 2
            while recorder.calls == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert recorder.calls == 1
            started = time.monotonic()
            for n in range(20):
                http.get("/", headers={**VISITOR, "user-agent": f"later/{n}"}).close()
            assert time.monotonic() - started < 1.0
        finally:
            release.set()
            sightings.close()

    def test_the_async_flusher_runs_on_the_loop(self) -> None:
        recorder = answering()

        async def drive() -> int:
            client = AsyncFingerly(
                secret_key=SECRET_KEY, transport=recorder.transport()
            )
            async with AsyncAgentSightings(
                client, client_ip=lambda incoming: incoming.headers["cf-connecting-ip"]
            ) as sightings:
                app = sightings.asgi(starlette_app())
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="https://shop.test"
                ) as http:
                    for n in range(200):
                        await http.get("/", headers={**VISITOR, "user-agent": f"a/{n}"})
                    for _ in range(100):
                        if recorder.calls:
                            break
                        await asyncio.sleep(0.01)
                calls = recorder.calls
            await client.aclose()
            return calls

        assert run(drive()) == 1
