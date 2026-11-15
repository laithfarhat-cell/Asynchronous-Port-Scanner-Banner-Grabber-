#!/usr/bin/env python3
"""asynscan — asynchronous port scanner, banner grabber and TLS inspector.

This thin wrapper exists so the tool can also be run straight from a checkout:

    python3 main.py -t 192.168.1.0/24 --top-ports 100 -oH report.html

Installed packages use the ``asynscan`` console script instead (see
``pyproject.toml``), which calls the very same :func:`cli.interface.main`.
"""

from __future__ import annotations

import sys

from cli.interface import main

if __name__ == "__main__":
    sys.exit(main())
