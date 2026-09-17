#!/usr/bin/env python3
"""Refreshes, or verifies, the vendored server contract snapshot.

The snapshot keeps the test suite independent of sibling repositories. Point
``FINGERLY_CONTRACT_DIR`` at the integration workspace's ``contract`` directory
to pull a newer one.

Usage:
    python scripts/sync_contract.py           # refresh the snapshot
    python scripts/sync_contract.py --check   # fail if it is stale
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

FILES = ("openapi.json", "fixtures.json")
ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str]) -> int:
    """Copies or verifies the contract files.

    Args:
        argv: Command-line arguments; ``--check`` verifies without writing.

    Returns:
        A process exit code.
    """
    check = "--check" in argv
    source = Path(os.environ.get("FINGERLY_CONTRACT_DIR", ROOT / "contract"))
    manifest = json.loads((source / "manifest.json").read_text())

    outputs = {}
    for name in FILES:
        raw = (source / name).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != manifest["files"][name]:
            print(f"Invalid contract hash: {name}", file=sys.stderr)
            return 1
        outputs[name] = raw
    outputs["manifest.json"] = (source / "manifest.json").read_bytes()

    for name, raw in outputs.items():
        target = ROOT / "contract" / name
        if check:
            if not target.exists() or target.read_bytes() != raw:
                print(f"{name} is stale; run scripts/sync_contract.py", file=sys.stderr)
                return 1
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)

    print(
        "Python contract snapshot is current."
        if check
        else "Python contract snapshot refreshed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
