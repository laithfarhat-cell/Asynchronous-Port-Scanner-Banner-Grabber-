#!/usr/bin/env bash
# Reproduce CI locally: the suite must pass from a *clean* checkout.
#
# The failure mode this guards against: tests that quietly depend on files that
# are gitignored (reports/, caches, generated fixtures) pass on a developer
# machine and fail on GitHub Actions, which always starts from a fresh clone.
#
#   ./scripts/verify_clean_clone.sh            # git archive of HEAD into a temp dir
#   ./scripts/verify_clean_clone.sh --keep     # keep the checkout for inspection
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/asynscan-clean.XXXXXX")"
cleanup() { [[ $KEEP -eq 1 ]] && echo "kept: $WORKDIR" || rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "==> exporting HEAD to $WORKDIR (git archive = exactly what CI checks out)"
git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$WORKDIR"

# reports/ must exist in the export (its README is tracked) but contain no
# generated findings: only that README may survive a clean checkout.
if [[ -d "$WORKDIR/reports" ]]; then
    leaked="$(find "$WORKDIR/reports" -type f ! -name 'README.md' -print)"
    if [[ -n "$leaked" ]]; then
        echo "!! generated reports leaked into the export:"; echo "$leaked"
        echo "   check the reports/* rule in .gitignore"; exit 1
    fi
    echo "==> reports/ contains only its README (generated output excluded)"
fi

PYTHON="${PYTHON:-python3}"
echo "==> creating venv with $($PYTHON --version)"
"$PYTHON" -m venv "$WORKDIR/.venv"
"$WORKDIR/.venv/bin/pip" -q install --upgrade pip
"$WORKDIR/.venv/bin/pip" -q install -e "$WORKDIR[dev]"

echo "==> ruff check"
(cd "$WORKDIR" && .venv/bin/ruff check .)

echo "==> pytest (clean tree, no generated reports, no caches)"
(cd "$WORKDIR" && .venv/bin/python -m pytest -q --junitxml=pytest-report.xml)

echo "==> entry point smoke test"
(cd "$WORKDIR" && .venv/bin/asynscan --version && .venv/bin/asynscan -t 127.0.0.1 -p 1-64 --timeout 0.2 -q >/dev/null)

echo "==> preview console from a clean tree (the CI failure this script found)"
(cd "$WORKDIR" && .venv/bin/python -c "
import sys; sys.path.insert(0, '.')
from scripts.preview_server import active_asset
missing = [k for k in ('html', 'json', 'csv') if active_asset(k) is None]
assert not missing, f'no fallback asset for {missing}'
print('all preview assets resolve:', {k: active_asset(k).name for k in ('html', 'json', 'csv')})
")

echo "==> OK: clean checkout is green"
