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

from ._client import (
    AsyncDeviceCheck,
    AsyncEvents,
    AsyncFingerly,
    DeviceCheck,
    Events,
    Fingerly,
)
from ._enums import (
    AttestationState,
    AttestationStatus,
    AttestSkippedReason,
    Confidence,
    Environment,
    EventState,
    Signal,
    SuspectLevel,
    VerifyReason,
    WebhookEventType,
)
from ._errors import (
    FingerlyAPIError,
    FingerlyConnectionError,
    FingerlyDeviceCheckError,
    FingerlyError,
    FingerlyEventAlreadyConsumedError,
    FingerlyEventPendingError,
    FingerlyTimeoutError,
)
from ._models import (
    SIGNAL_NAMES,
    Attestation,
    ConsumeResult,
    DeviceCheckBits,
    DeviceCheckWriteResult,
    Event,
    EventDocument,
    EventPage,
    EventTrigger,
    VerifyResult,
)
from ._proxy import FingerlyProxy, ProxyRequest
from ._version import __version__
from ._webhooks import verify_webhook

__all__ = [
    "SIGNAL_NAMES",
    "AsyncDeviceCheck",
    "AsyncEvents",
    "AsyncFingerly",
    "AttestSkippedReason",
    "Attestation",
    "AttestationState",
    "AttestationStatus",
    "Confidence",
    "ConsumeResult",
    "DeviceCheck",
    "DeviceCheckBits",
    "DeviceCheckWriteResult",
    "Environment",
    "Event",
    "EventDocument",
    "EventPage",
    "EventState",
    "EventTrigger",
    "Events",
    "Fingerly",
    "FingerlyAPIError",
    "FingerlyConnectionError",
    "FingerlyDeviceCheckError",
    "FingerlyError",
    "FingerlyEventAlreadyConsumedError",
    "FingerlyEventPendingError",
    "FingerlyProxy",
    "FingerlyTimeoutError",
    "ProxyRequest",
    "Signal",
    "SuspectLevel",
    "VerifyReason",
    "VerifyResult",
    "WebhookEventType",
    "__version__",
    "verify_webhook",
]
