"""Shared helpers: httpx transports that answer without a network."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from typing import Any, Callable, Optional, TypeVar

import httpx

SECRET_KEY = "fly_sk_us_development_test"

T = TypeVar("T")


class Recorder:
    """Answers requests from a queue of responses and records what it saw.

    Attributes:
        requests: Every request the client made, in order.
    """

    def __init__(self, *responses: httpx.Response) -> None:
        self._responses: list[httpx.Response] = list(responses)
        self._handler: Optional[Callable[[httpx.Request], httpx.Response]] = None
        self.requests: list[httpx.Request] = []

    @classmethod
    def of(cls, handler: Callable[[httpx.Request], httpx.Response]) -> Recorder:
        """Builds a recorder that computes each response from the request."""
        recorder = cls()
        recorder._handler = handler
        return recorder

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._handler is not None:
            return self._handler(request)
        index = min(len(self.requests) - 1, len(self._responses) - 1)
        return self._responses[index]

    @property
    def calls(self) -> int:
        """How many requests reached the transport."""
        return len(self.requests)

    @property
    def url(self) -> str:
        """The URL of the first request."""
        return str(self.requests[0].url)

    def transport(self) -> httpx.MockTransport:
        """A synchronous-and-async transport backed by this recorder."""
        return httpx.MockTransport(self)


def json_response(body: Any, status: int = 200) -> httpx.Response:
    """Builds a JSON response, as the API would send it."""
    return httpx.Response(
        status,
        content=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )


def error_response(code: str, status: int, request_id: str = "trace") -> httpx.Response:
    """Builds the API's structured error envelope."""
    return json_response(
        {
            "error": {"code": code, "message": "Synthetic", "status": status},
            "request_id": request_id,
        },
        status,
    )


def event_body(**overrides: Any) -> dict[str, Any]:
    """A minimal event body with every field the API always sends."""
    body = {
        "request_id": "0199a963-e400-7000-8000-000000000001",
        "visitor_id": "visitor-test",
        "occurred_at": "2026-09-17T12:00:00Z",
        "state": "enriched",
        "environment": "development",
        "platform": "web",
        "sdk_platform": "web",
        "sdk_version": "0.1.0",
        "ip_address": "203.0.113.10",
        "triggers": [],
        "has_document": False,
    }
    body.update(overrides)
    return body


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """Runs a coroutine on a fresh event loop.

    Keeps the async tests free of a pytest-asyncio dependency.
    """
    return asyncio.run(coroutine)
