"""Exceptions raised by the Fingerly SDK.

Every error this package raises derives from :class:`FingerlyError`, so a
caller can catch that one class and let unrelated failures propagate.
"""

from __future__ import annotations

from typing import Any, Optional


class FingerlyError(Exception):
    """Base class for every error raised by this package."""


class FingerlyTimeoutError(FingerlyError):
    """Raised when a request does not finish within its time limit.

    The deadline covers reading the response body, so an API that answers and
    then stalls arrives here just as one that never answered does.
    """

    def __init__(self) -> None:
        super().__init__("Fingerly request timed out")


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
