#!/usr/bin/env python3
"""Fail fast when a running preview console is stale or broken.

A long-lived ``preview_server.py`` keeps its module in memory; after a code change
it silently serves the old build. This guard compares the *running* server with
the *on-disk* build:

    python3 scripts/check_preview.py --port 32929      # exit 1 if stale/down

Used by ``make check-preview`` and safe to run in CI (skips when nothing listens).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.preview_server import CONSOLE_BUILD  # noqa: E402


def fetch(url: str, timeout: float = 5.0) -> tuple[int, bytes]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.status, response.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=32929)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    base = f"http://{args.host}:{args.port}"
    try:
        status, body = fetch(f"{base}/healthz")
    except (urllib.error.URLError, OSError) as exc:
        print(f"✖ no console answering on {base} ({exc}) — start it with 'make preview'")
        return 1

    payload = json.loads(body)
    problems: list[str] = []
    if status != 200 or payload.get("status") != "ok":
        problems.append(f"/healthz returned {status}: {payload}")
    if payload.get("console_build") != CONSOLE_BUILD:
        problems.append(
            f"STALE SERVER: running build {payload.get('console_build')!r}, "
            f"on-disk build {CONSOLE_BUILD!r} — restart the preview"
        )
    try:
        page_status, page = fetch(f"{base}/")
        if page_status != 200 or b"asynscan" not in page:
            problems.append(f"/ returned {page_status} with {len(page)} bytes")
        if f"build {CONSOLE_BUILD}".encode() not in page:
            problems.append("index page does not advertise the current build")
    except (urllib.error.URLError, OSError) as exc:
        problems.append(f"/ unreachable: {exc}")

    if problems:
        for problem in problems:
            print(f"✖ {problem}")
        return 1
    if not args.quiet:
        print(
            f"✔ preview healthy on {base} — build {payload['console_build']}, "
            f"started {payload['started_at']}, report {payload['report']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
