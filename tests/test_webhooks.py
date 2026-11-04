"""Webhook verification: authenticity, replay windows and malformed input."""

from __future__ import annotations

import hmac
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Optional

import pytest

import fingerly._webhooks as webhooks
from fingerly import verify_webhook

PAYLOAD = b'{"id":"evt_1","type":"identification.completed"}'
TIMESTAMP = "1789646400"


def sign(secret: str, payload: bytes = PAYLOAD, timestamp: str = TIMESTAMP) -> str:
    """Signs a payload exactly as the Fingerly webhook worker does."""
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode(), sha256)
    mac.update(payload)
    return "sha256=" + mac.hexdigest()


def at(seconds: int) -> datetime:
    """A timezone-aware instant offset from the fixture timestamp."""
    return datetime.fromtimestamp(int(TIMESTAMP) + seconds, tz=timezone.utc)


class TestAuthenticity:
    def test_verifies_the_raw_payload(self) -> None:
        assert verify_webhook("secret", PAYLOAD, TIMESTAMP, sign("secret"), now=at(0))

    def test_accepts_str_and_bytes_payloads_alike(self) -> None:
        text = '{"id":"evt_1"}'
        signature = sign("secret", text.encode())
        assert verify_webhook("secret", text, TIMESTAMP, signature, now=at(0))
        assert verify_webhook("secret", text.encode(), TIMESTAMP, signature, now=at(0))

    def test_rejects_a_tampered_body(self) -> None:
        assert not verify_webhook(
            "secret", b'{"id":"evt_2"}', TIMESTAMP, sign("secret"), now=at(0)
        )

    def test_rejects_the_wrong_secret(self) -> None:
        assert not verify_webhook(
            "other", PAYLOAD, TIMESTAMP, sign("secret"), now=at(0)
        )

    def test_accepts_any_signature_sent_during_a_rotation(self) -> None:
        header = f"{sign('new')},{sign('old')}"
        assert verify_webhook("new", PAYLOAD, TIMESTAMP, header, now=at(0))
        assert verify_webhook("old", PAYLOAD, TIMESTAMP, header, now=at(0))
        assert not verify_webhook("other", PAYLOAD, TIMESTAMP, header, now=at(0))

    def test_reads_only_the_first_32_signatures(self) -> None:
        decoys = ["sha256=" + "0" * 64] * 31
        within = ",".join([*decoys, sign("secret")])
        beyond = ",".join([*decoys, "sha256=" + "1" * 64, sign("secret")])
        assert verify_webhook("secret", PAYLOAD, TIMESTAMP, within, now=at(0))
        assert not verify_webhook("secret", PAYLOAD, TIMESTAMP, beyond, now=at(0))

    def test_a_huge_signature_header_costs_no_more_than_32(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        compared: list[str] = []
        real = webhooks._matches

        def counting(candidate: str, expected: bytes) -> bool:
            compared.append(candidate)
            return real(candidate, expected)

        monkeypatch.setattr(webhooks, "_matches", counting)
        header = ",".join(["sha256=" + "0" * 64] * 200_000)
        assert not verify_webhook("secret", PAYLOAD, TIMESTAMP, header, now=at(0))
        assert len(compared) == 32


class TestReplayWindow:
    @pytest.mark.parametrize("offset", [0, 299, -299])
    def test_accepts_a_timestamp_within_tolerance(self, offset: int) -> None:
        assert verify_webhook(
            "secret", PAYLOAD, TIMESTAMP, sign("secret"), now=at(offset)
        )

    @pytest.mark.parametrize("offset", [301, -301])
    def test_rejects_a_timestamp_outside_tolerance(self, offset: int) -> None:
        assert not verify_webhook(
            "secret", PAYLOAD, TIMESTAMP, sign("secret"), now=at(offset)
        )

    def test_honours_a_custom_tolerance(self) -> None:
        assert verify_webhook(
            "secret",
            PAYLOAD,
            TIMESTAMP,
            sign("secret"),
            tolerance_seconds=600,
            now=at(400),
        )

    def test_reads_a_naive_now_as_utc(self) -> None:
        naive = at(0).replace(tzinfo=None)
        assert verify_webhook("secret", PAYLOAD, TIMESTAMP, sign("secret"), now=naive)


class TestMalformedInput:
    @pytest.mark.parametrize(
        "timestamp",
        [None, "", " ", "1.5", "-1", "0x10", "Infinity", "1789646400\n", 1789646400],
    )
    def test_rejects_a_noncanonical_timestamp(self, timestamp: Any) -> None:
        assert not verify_webhook(
            "secret",
            PAYLOAD,
            timestamp,
            sign("secret"),
            now=at(0),
        )

    @pytest.mark.parametrize(
        "signature",
        [
            None,
            "",
            "sha256=",
            "sha256=" + "0" * 63,
            "sha256=" + "F" * 64,
            "md5=" + "0" * 64,
            "0" * 64,
        ],
    )
    def test_rejects_a_malformed_signature(self, signature: Optional[str]) -> None:
        assert not verify_webhook("secret", PAYLOAD, TIMESTAMP, signature, now=at(0))

    @pytest.mark.parametrize("tolerance", [-1, float("nan"), "300", True, None])
    def test_rejects_an_invalid_tolerance(self, tolerance: Any) -> None:
        assert not verify_webhook(
            "secret",
            PAYLOAD,
            TIMESTAMP,
            sign("secret"),
            tolerance_seconds=tolerance,
            now=at(0),
        )

    @pytest.mark.parametrize("secret", [None, "", 123])
    def test_rejects_a_missing_secret(self, secret: Any) -> None:
        assert not verify_webhook(
            secret,
            PAYLOAD,
            TIMESTAMP,
            sign("secret"),
            now=at(0),
        )

    @pytest.mark.parametrize("payload", [None, 123, {"id": "evt_1"}])
    def test_rejects_an_unusable_payload(self, payload: Any) -> None:
        assert not verify_webhook(
            "secret",
            payload,
            TIMESTAMP,
            sign("secret"),
            now=at(0),
        )

    def test_never_raises_for_any_combination_of_bad_input(self) -> None:
        junk: list[Any] = [None, 0, "", b"", "junk"]
        for secret in junk:
            for payload in junk:
                for timestamp in junk:
                    for signature in junk:
                        assert (
                            verify_webhook(
                                secret,
                                payload,
                                timestamp,
                                signature,
                            )
                            is False
                        )
