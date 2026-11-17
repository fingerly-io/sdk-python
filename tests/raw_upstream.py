"""A raw socket upstream on 127.0.0.1, for answers httpx mocks cannot express."""

from __future__ import annotations

import socket
import threading
from typing import Any

from test_proxy import PATH, PROXY_KEY

from fingerly import FingerlyProxy


class RawUpstream:
    """A socket server on 127.0.0.1 that answers every request with fixed bytes.

    Attributes:
        port: The bound port.
        hits: How many requests it received.
    """

    def __init__(self, answer: bytes) -> None:
        self._answer = answer
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(16)
        self.port: int = self._socket.getsockname()[1]
        self.hits = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while True:
            try:
                connection, _ = self._socket.accept()
            except OSError:
                return
            with connection:
                connection.settimeout(2)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    head, _, rest = data.partition(b"\r\n\r\n")
                    length = 0
                    for line in head.split(b"\r\n")[1:]:
                        name, _, value = line.partition(b":")
                        if name.strip().lower() == b"content-length":
                            length = int(value.strip())
                    while len(rest) < length:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        rest += chunk
                    self.hits += 1
                    connection.sendall(self._answer)
                except OSError:
                    continue

    def close(self) -> None:
        self._socket.close()


def answering(status: str, extra: str = "") -> RawUpstream:
    """A raw upstream whose every answer has this status line code."""
    return RawUpstream(
        f"HTTP/1.1 {status} Answer\r\n{extra}content-type: application/json\r\n"
        "content-length: 2\r\nconnection: close\r\n\r\n{}".encode()
    )


def real(upstream: str, **options: Any) -> FingerlyProxy:
    """A proxy that sends over the network to a loopback upstream."""
    options.setdefault("proxy_key", PROXY_KEY)
    options.setdefault("path", PATH)
    options.setdefault("client_ip", lambda request: "203.0.113.10")
    return FingerlyProxy(upstream=upstream, allow_insecure_loopback=True, **options)
