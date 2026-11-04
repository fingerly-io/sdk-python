"""Every place the version appears agrees, and the changelog names it."""

from __future__ import annotations

import re
from importlib.metadata import version
from pathlib import Path

import fingerly
from fingerly._proxy import PROXY_VERSION
from fingerly._transport import USER_AGENT

ROOT = Path(__file__).resolve().parent.parent


def test_versions_agree() -> None:
    assert version("fingerly") == fingerly.__version__
    assert f"python/{fingerly.__version__}" == PROXY_VERSION
    assert f"fingerly-python/{fingerly.__version__}" == USER_AGENT


def test_the_changelog_leads_with_this_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    first = re.search(r"^## (\S+)", changelog, re.MULTILINE)
    assert first is not None
    assert first.group(1) == fingerly.__version__


def test_the_proxy_identifies_itself_upstream() -> None:
    from conftest import Recorder, json_response

    recorder = Recorder(json_response({}))
    proxy = fingerly.FingerlyProxy(
        proxy_key="fly_px_development_test",
        client_ip=lambda request: "203.0.113.1",
        transport=recorder.transport(),
    )
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/p",
        "CONTENT_LENGTH": "2",
        "HTTP_X_API_KEY": "fly_pk_development_test",
        "wsgi.input": __import__("io").BytesIO(b"{}"),
    }
    proxy.wsgi(environ, lambda status, headers: None)
    assert recorder.requests[0].headers["user-agent"] == USER_AGENT
