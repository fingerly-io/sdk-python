"""Exceptions raised by the Fingerly SDK.

Every error this package raises derives from :class:`FingerlyError`, so a
caller can catch that one class and let unrelated failures propagate.
"""

from __future__ import annotations

from typing import Any, Optional


class FingerlyError(Exception):
    """Base class for every error raised by this package."""


class FingerlyTimeoutError(FingerlyError):
    """Raised when an operation does not finish within its time limit.

    Attributes:
        operation: ``event_wait`` for ``events.wait_for`` polling, ``request``
            for a single HTTP request.
    """

    def __init__(self, operation: str = "request") -> None:
        message = (
            "Timed out waiting for the event"
            if operation == "event_wait"
            else "Fingerly request timed out"
        )
        super().__init__(message)
        self.operation = operation


class FingerlyConnectionError(FingerlyError):
    """Raised when the Fingerly API could not be reached at all.

    A DNS failure, a refused connection or a TLS error arrives here. The
    originating exception is kept as ``__cause__``.
    """


class FingerlyAPIError(FingerlyError):
    """Raised for any non-2xx response from the Fingerly API.

    The message carries only the HTTP status. Response bodies are never
    echoed, and any occurrence of the secret key in the metadata is redacted.

    Attributes:
        status: The HTTP status code.
        code: Stable machine-readable code, such as ``event_not_found``.
        details: Extra context from the error body; its shape depends on
            ``code``.
        request_id: Server-side trace id to quote in support requests.
    """

    def __init__(
        self,
        message: str,
        status: int,
        *,
        code: Optional[str] = None,
        details: Any = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details
        self.request_id = request_id

    def __repr__(self) -> str:
        return f"FingerlyAPIError(status={self.status}, code={self.code!r})"
