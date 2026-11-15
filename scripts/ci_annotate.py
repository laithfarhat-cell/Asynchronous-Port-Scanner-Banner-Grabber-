#!/usr/bin/env python3
"""Turn a pytest JUnit XML report into GitHub Actions annotations.

GitHub only shows a bare "Process completed with exit code 1" when a test step
fails; the interesting part (which test, why) is buried in the log. This script
re-emits every failure as an ``::error`` workflow command so the failure is
visible directly on the pull request — and readable through the annotations API.

Usage
-----
    pytest -q --junitxml=pytest-report.xml
    python scripts/ci_annotate.py pytest-report.xml
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_MESSAGE = 400
MAX_DETAIL = 700


def _clean(text: str) -> str:
    """Workflow commands are line based; data must be single-line and escaped."""
    return (
        text.replace("\r", " ")
        .replace("\n", " ")
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .strip()
    )


def collect_failures(xml_path: Path) -> list[dict[str, str]]:
    root = ET.parse(xml_path).getroot()
    failures: list[dict[str, str]] = []
    for case in root.iter("testcase"):
        node = case.find("failure")
        if node is None:
            node = case.find("error")
        if node is None:
            continue
        detail = " ".join((node.text or "").split())
        failures.append(
            {
                "file": case.get("file") or "tests",
                "line": case.get("line") or "1",
                "name": f"{case.get('classname', '')}::{case.get('name', '')}".strip(":"),
                "message": (node.get("message") or node.get("type") or "failed")[:MAX_MESSAGE],
                "detail": detail[-MAX_DETAIL:],
            }
        )
    return failures


def summarize(xml_paths: list[Path]) -> tuple[int, int]:
    """Return ``(tests, failures)`` across all reports."""
    tests = failed = 0
    for path in xml_paths:
        root = ET.parse(path).getroot()
        for suite in root.iter("testsuite"):
            tests += int(suite.get("tests") or 0)
            failed += int(suite.get("failures") or 0) + int(suite.get("errors") or 0)
    return tests, failed


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    paths = [Path(p) for p in args] or [Path("pytest-report.xml")]
    existing = [p for p in paths if p.is_file()]
    if not existing:
        print(f"::warning::no JUnit report found ({', '.join(str(p) for p in paths)})")
        return 0

    failures: list[dict[str, str]] = []
    for path in existing:
        failures.extend(collect_failures(path))

    tests, failed = summarize(existing)
    print(f"JUnit: {tests} test(s), {failed} failing", file=sys.stderr)

    for failure in failures:
        print(
            f"::error file={failure['file']},line={failure['line']},"
            f"title=pytest: {_clean(failure['name'])}::"
            f"{_clean(failure['message'])} -- {_clean(failure['detail'])}"
        )

    if not failures and failed:
        print(f"::error::{failed} test(s) failed but no <failure> elements were parsed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
