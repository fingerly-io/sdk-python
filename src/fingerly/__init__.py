"""Server-side Fingerly SDK: event reads and webhook verification.

Two clients share one API: :class:`Fingerly` for synchronous code such as
Django and Flask, and :class:`AsyncFingerly` for asyncio code such as FastAPI
and Starlette.

Example:
    >>> from fingerly import Fingerly
    >>> fingerly = Fingerly(secret_key=os.environ["FINGERLY_SECRET_KEY"])
    >>> event = fingerly.events.get("01a0a84b-e6a2-7c09-9f51-0b3d7a26c8e4")
"""

from __future__ import annotations

from ._client import AsyncEvents, AsyncFingerly, Events, Fingerly
from ._errors import (
    FingerlyAPIError,
    FingerlyConnectionError,
    FingerlyError,
    FingerlyTimeoutError,
)
from ._models import Event, EventPage, EventTrigger
from ._proxy import FingerlyProxy, ProxyRequest
from ._webhooks import verify_webhook

__version__ = "0.1.0"

__all__ = [
    "AsyncEvents",
    "AsyncFingerly",
    "Event",
    "EventPage",
    "EventTrigger",
    "Events",
    "Fingerly",
    "FingerlyAPIError",
    "FingerlyConnectionError",
    "FingerlyError",
    "FingerlyProxy",
    "FingerlyTimeoutError",
    "ProxyRequest",
    "__version__",
    "verify_webhook",
]
