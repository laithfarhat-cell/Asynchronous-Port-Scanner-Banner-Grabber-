# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-11-15

### Added
- Asynchronous scan engine on a single event loop with a global `asyncio.Semaphore`,
  per-probe `asyncio.wait_for` timeouts and graceful `SIGINT`/`SIGTERM` cancellation
  that still exports partial reports.
- Descriptor-budget guard: concurrency is clamped against `RLIMIT_NOFILE` and
  `EMFILE`/`ENFILE` triggers a single global back-off plus a report warning.
- Target parsing: IPv4/IPv6 literals, CIDR expansion via `ipaddress`, concurrent A/AAAA
  DNS resolution, `-iL` target files with comments, de-duplication and `--max-hosts` guard rails.
- Port parsing: singles, lists, ranges, `all`, `--top-ports {100,1000}` presets, shuffling.
- Rate limiting: global token bucket (`--rate`), fixed `--delay` and `--jitter`.
- Banner grabber: passive greeting capture, protocol-aware active probes (HTTP/HTTPS HEAD,
  Redis PING + INFO, Memcached version, PostgreSQL SSLRequest, SMTP EHLO, RDP and SMB negotiate),
  opportunistic TLS upgrade on unexpected ports and `--aggressive` multi-protocol spraying.
- Dependency-free DER/X.509 parser (`core/x509.py`): CN, SANs, issuer, validity, expiry,
  self-signed detection, serial, signature algorithm, key type/bits, SHA-256 fingerprint.
- Signature database with 57 regex rules and per-rule service/product/version extraction.
- Reporters: JSON schema v1 (metadata + summary + nested hosts/ports), flat CSV and a
  standalone dark-mode HTML report with search, service filter, sortable columns and HTML escaping.
- `rich` terminal UI: plan panel, live progress with ETA and throughput, streaming findings,
  results table and summary panel; non-TTY mode degrades to periodic progress lines.
- Packaging: `pyproject.toml` with the `asynscan` console script, multi-stage `Dockerfile`
  (non-root), `Makefile`, `.gitignore`, `.dockerignore`, `LICENSE`, `CHANGELOG.md`.
- 141 tests covering parser, grabber, X.509 parsing, scanner semantics, exporters and CLI.

### Developer tooling
- `scripts/preview_server.py`: offline single-page console (demo findings, signature database,
  port presets and CLI reference) bound to `0.0.0.0:32929` for workspace previews, plus
  `/healthz`, `/api/signatures`, `/api/ports` and `/api/help`; `make preview`.
- `examples/demo_report.{json,html}` committed samples so the console (and reviewers) work
  without first running a scan.
- Console build identity: the page and `/healthz` expose `console_build` and `started_at`, and
  `scripts/check_preview.py` (`make check-preview`) fails when a running preview serves a stale
  build or nothing is listening.

### Fixed
- Banner grabbing no longer raises when a peer resets the connection mid-read
  (`ConnectionResetError` / `ECONNRESET`). Partial data is kept and fingerprinted,
  the reason is recorded as `error`, and the port stays `open` — previously this
  escaped `BannerGrabber.grab()` and only survived because the scanner wrapped it.
  Found by CI on Python 3.12/3.13 (faster I/O changes the close/RST race).
- `tests/conftest.py` fixture servers now keep connections open long enough for a
  clean EOF, instead of racing the client into a reset.

### Fixed (packaging)
- `examples/targets.txt` was accidentally excluded by the `.gitignore` rule meant
  for local target lists; the rule is now anchored to the repo root (`/targets.txt`)
  so documentation examples are tracked while your own scan scopes stay private.
  `reports/` remains gitignored on purpose (generated findings).

### Packaging (continued)
- `reports/` now exists in a clean checkout: only `reports/README.md` is tracked
  (documenting how output is generated, how to publish one deliberately, and
  where the reviewed samples live). Generated findings stay ignored via
  `reports/*` + `!reports/README.md`, so `-oA reports/scan` works out of the box.
- `scripts/verify_clean_clone.sh` now fails only when *generated* files leak into
  the export, instead of rejecting the directory outright.

### CI
- Actions pinned to current majors (`checkout@v7`, `setup-python@v7`,
  `upload-artifact@v7`, `setup-buildx-action@v4`, `build-push-action@v7`) to clear the
  Node.js 20 deprecation warnings.

### Known limitations
- TCP only (`SYN`/UDP scanning is out of scope for the asyncio socket model).
- A silent host is reported as `filtered` only when the connect attempt times out;
  ICMP-based differentiation is not performed.
