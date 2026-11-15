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

### Known limitations
- TCP only (`SYN`/UDP scanning is out of scope for the asyncio socket model).
- A silent host is reported as `filtered` only when the connect attempt times out;
  ICMP-based differentiation is not performed.
