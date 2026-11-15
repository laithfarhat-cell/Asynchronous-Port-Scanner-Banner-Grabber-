"""Locate the bundled data files (signatures, port presets).

The tool ships data next to the source in a checkout, but a ``pip install``
places it in ``<sys.prefix>/share/asynscan``. Resolution order:

1. ``$ASYNSCAN_DATA_DIR`` (explicit override, Docker sets this)
2. ``<repo>/data`` next to the package (source checkout / zipapp)
3. ``<sys.prefix>/share/asynscan`` (``pip install .`` data-files)
4. ``/usr/local/share/asynscan`` (Docker image)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ENV_VAR = "ASYNSCAN_DATA_DIR"


def candidate_data_dirs() -> list[Path]:
    candidates: list[Path] = []
    env = os.environ.get(_ENV_VAR)
    if env:
        candidates.append(Path(env).expanduser())
    package_root = Path(__file__).resolve().parent
    candidates.append(package_root.parent / "data")          # repo checkout
    candidates.append(package_root / "data")                 # vendored inside package
    candidates.append(Path(sys.prefix) / "share" / "asynscan")
    candidates.append(Path("/usr/local/share/asynscan"))
    return candidates


def data_dir() -> Path:
    """Return the first existing data directory (falls back to the repo path)."""
    for candidate in candidate_data_dirs():
        if candidate.is_dir():
            return candidate
    return candidate_data_dirs()[0]


def data_file(name: str) -> Path | None:
    """Return the path of *name* inside the data directory if it exists."""
    for candidate in candidate_data_dirs():
        path = candidate / name
        if path.is_file():
            return path
    return None
