"""Semaphore-controlled asyncio scanning engine.

Design notes
------------
* One coroutine per ``(host, port)`` pair, all multiplexed on a single event
  loop. No threads per socket, no ``select`` bookkeeping — the kernel scales.
* A single :class:`asyncio.Semaphore` bounds *in-flight* connections. Each
  probe holds at most **one** file descriptor at a time, except during the
  hand-off to TLS inspection, so ``concurrency <= ulimit -n / 2`` is a safe
  rule of thumb (validated at startup by :func:`check_fd_budget`).
* Timeouts are enforced with :func:`asyncio.wait_for`, so a black-holed host can
  never pin a slot forever.
* ``EMFILE``/``ENFILE`` (local descriptor exhaustion) is caught explicitly,
  backed off globally and retried once, instead of crashing a long scan.
* Cancellation (``SIGINT``) unwinds cleanly: every open writer is closed in a
  ``finally`` block and partial results are preserved.
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import random
import resource
import socket
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from .banner_grabber import BannerGrabber, GrabResult
from .models import STATE_CLOSED, STATE_FILTERED, STATE_OPEN, HostResult, PortResult
from .parser import Target

try:  # POSIX only; Windows falls back to a conservative default.
    _HAS_RESOURCE = sys.platform != "win32"
except ImportError:  # pragma: no cover - Windows
    _HAS_RESOURCE = False

OpenCallback = Callable[[PortResult], None]
ProgressCallback = Callable[["ScanProgress"], None]

#: Descriptor budget we are willing to consume (fraction of the soft limit).
FD_UTILISATION = 0.75
#: Ports above this number are considered "quiet" and yield less often.
_YIELD_EVERY = 250


def file_descriptor_limit() -> int:
    """Best-effort soft ``RLIMIT_NOFILE`` value."""
    if not _HAS_RESOURCE:
        return 8192
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError):  # pragma: no cover
        return 8192
    if soft in (resource.RLIM_INFINITY, -1):
        return 1 << 20
    return int(soft)


def check_fd_budget(concurrency: int) -> tuple[int, list[str]]:
    """Return a safe concurrency value plus human-readable warnings.

    A scan of 2,000 concurrent probes on a ``ulimit -n 1024`` host is the single
    most common way to make an asyncio scanner "hang" or die with ``EMFILE``.
    We detect it up front and clamp instead of failing halfway through.
    """
    limit = file_descriptor_limit()
    safe_default = max(8, int(limit * FD_UTILISATION / 2))
    warnings: list[str] = []
    if concurrency > safe_default:
        warnings.append(
            f"requested concurrency {concurrency} exceeds the descriptor budget "
            f"(soft ulimit -n={limit}); clamped to {safe_default}. "
            f"Run 'ulimit -n 65535' for higher parallelism."
        )
        concurrency = safe_default
    reserved = int(limit * 0.05) + 16
    if concurrency * 2 + reserved > limit:
        warnings.append(
            f"concurrency {concurrency} is close to the fd limit ({limit}); "
            "banner grabbing may hit EMFILE."
        )
    return concurrency, warnings


class RateLimiter:
    """Global token bucket plus optional per-probe jitter/delay.

    ``rate`` is expressed in probes/second (``0`` disables the bucket).
    """

    def __init__(self, rate: float = 0.0, delay: float = 0.0, jitter: float = 0.0) -> None:
        self.rate = max(0.0, float(rate))
        self.delay = max(0.0, float(delay))
        self.jitter = max(0.0, float(jitter))
        self._tokens = 1.0
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate > 0:
            async with self._lock:
                while True:
                    now = time.monotonic()
                    self._tokens = min(1.0, self._tokens + (now - self._updated) * self.rate)
                    self._updated = now
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        break
                    await asyncio.sleep((1.0 - self._tokens) / self.rate)
        if self.delay or self.jitter:
            pause = self.delay + (random.uniform(0, self.jitter) if self.jitter else 0.0)
            if pause:
                await asyncio.sleep(pause)


@dataclass(slots=True)
class ScanProgress:
    """Mutable progress snapshot handed to the UI."""

    total: int = 0
    completed: int = 0
    open_ports: int = 0
    closed: int = 0
    filtered: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self) -> float:
        return max(1e-6, time.monotonic() - self.started_at)

    @property
    def rate(self) -> float:
        return self.completed / self.elapsed

    @property
    def percent(self) -> float:
        return (self.completed / self.total * 100.0) if self.total else 0.0

    @property
    def eta_seconds(self) -> float | None:
        if not self.total or self.completed == 0:
            return None
        remaining = self.total - self.completed
        return remaining / self.rate if self.rate > 0 else None


@dataclass(slots=True)
class ScanSettings:
    """Runtime knobs for :class:`AsyncScanner`."""

    concurrency: int = 500
    timeout: float = 2.0
    retries: int = 0
    delay: float = 0.0
    jitter: float = 0.0
    rate: float = 0.0
    grab_banners: bool = True
    banner_timeout: float = 1.0
    tls: bool = True
    tls_all_ports: bool = False
    active_probes: bool = True
    aggressive: bool = False
    shuffle: bool = False
    shuffle_seed: int | None = None
    resolve_dns: bool = True

    def clamped_concurrency(self) -> tuple[int, list[str]]:
        return check_fd_budget(self.concurrency)


@dataclass(slots=True)
class ScanResult:
    """Full outcome of a scan run (survives ``SIGINT``)."""

    hosts: list[HostResult] = field(default_factory=list)
    progress: ScanProgress = field(default_factory=ScanProgress)
    ports: list[int] = field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    duration: float = 0.0
    cancelled: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    input_hosts: int = 0

    @property
    def open_ports(self) -> list[PortResult]:
        return [port for host in self.hosts for port in host.ports if port.is_open]

    @property
    def total_open(self) -> int:
        return len(self.open_ports)

    @property
    def probed(self) -> int:
        return self.progress.completed

    def top_services(self, limit: int = 10) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for port in self.open_ports:
            label = port.display_service()
            counts[label] = counts.get(label, 0) + 1
        return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]

    def average_latency(self) -> float | None:
        latencies = [p.latency_ms for p in self.open_ports if p.latency_ms is not None]
        return sum(latencies) / len(latencies) if latencies else None


class AsyncScanner:
    """High-throughput TCP scanner with integrated service fingerprinting."""

    def __init__(
        self,
        settings: ScanSettings | None = None,
        grabber: BannerGrabber | None = None,
        *,
        on_open: OpenCallback | None = None,
        on_progress: ProgressCallback | None = None,
        progress_every: float = 0.1,
    ) -> None:
        self.settings = settings or ScanSettings()
        self.concurrency, self.fd_warnings = self.settings.clamped_concurrency()
        self.grabber = grabber or BannerGrabber(
            timeout=self.settings.timeout,
            banner_timeout=self.settings.banner_timeout,
            active_probes=self.settings.active_probes,
            tls_inspection=self.settings.tls,
            tls_all_ports=self.settings.tls_all_ports,
            aggressive=self.settings.aggressive,
        )
        self.on_open = on_open
        self.on_progress = on_progress
        self.progress_interval = progress_every
        self._semaphore = asyncio.Semaphore(self.concurrency)
        self._limiter = RateLimiter(self.settings.rate, self.settings.delay, self.settings.jitter)
        self._progress = ScanProgress()
        self._hosts: dict[str, HostResult] = {}
        self._last_progress_emit = 0.0
        self._emfile_events = 0
        self._results: list[tuple[str, PortResult]] = []

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    @property
    def progress(self) -> ScanProgress:
        return self._progress

    async def scan(
        self,
        targets: Sequence[Target],
        ports: Sequence[int],
    ) -> ScanResult:
        """Scan the cartesian product of *targets* × *ports*."""
        if not targets:
            raise ValueError("no targets to scan")
        if not ports:
            raise ValueError("no ports to scan")

        port_list = list(ports)
        if self.settings.shuffle:
            random.Random(self.settings.shuffle_seed).shuffle(port_list)

        self._progress = ScanProgress(total=len(targets) * len(port_list))
        started_wall = time.time()
        started = time.monotonic()
        cancelled = False

        for target in targets:
            self._hosts.setdefault(
                target.ip,
                HostResult(ip=target.ip, hostname=target.hostname, is_ipv6=target.is_ipv6),
            )

        tasks: list[asyncio.Task[None]] = []
        try:
            for target in targets:
                for port in port_list:
                    tasks.append(asyncio.create_task(self._probe_unit(target, port)))
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            cancelled = True
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            duration = time.monotonic() - started
            self._emit_progress(force=True)

        # Keep every scanned host, even one where nothing answered: "no open
        # ports" is a finding, and the reporter needs the probe counts.
        hosts = list(self._hosts.values())
        hosts.sort(key=lambda host: (-len(host.open_ports), self._ip_sort_key(host.ip)))
        for host in hosts:
            host.ports.sort(key=lambda port: port.port)

        return ScanResult(
            hosts=hosts,
            progress=self._progress,
            ports=list(ports),
            started_at=_iso(started_wall),
            finished_at=_iso(time.time()),
            duration=duration,
            cancelled=cancelled,
            warnings=list(self.fd_warnings),
            input_hosts=len(targets),
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    @staticmethod
    def _ip_sort_key(ip: str) -> tuple[int, int]:
        try:
            parsed = ipaddress.ip_address(ip)
            return (parsed.version, int(parsed))
        except ValueError:
            return (9, 0)

    async def _probe_unit(self, target: Target, port: int) -> None:
        async with self._semaphore:
            await self._limiter.acquire()
            attempt = 0
            result: PortResult | None = None
            while attempt <= self.settings.retries:
                result = await self._probe_port(target, port)
                if result.state == STATE_OPEN:
                    break
                if result.error and "EMFILE" in result.error and attempt < self.settings.retries:
                    await asyncio.sleep(0.05 * (attempt + 1))
                attempt += 1
            assert result is not None
            await self._record(target, result)

    async def _probe_port(self, target: Target, port: int) -> PortResult:
        started = time.monotonic()
        result = PortResult(
            ip=target.ip,
            port=port,
            hostname=target.hostname,
            state=STATE_CLOSED,
            scanned_at=_iso(time.time()),
        )
        reader = None
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=target.ip, port=port, limit=65536),
                timeout=self.settings.timeout,
            )
            result.latency_ms = (time.monotonic() - started) * 1000.0
            result.state = STATE_OPEN

            if self.settings.grab_banners:
                # Banner grabbing must never downgrade an established TCP
                # connection: a silent daemon is still an open port.
                try:
                    grab: GrabResult = await asyncio.wait_for(
                        self.grabber.grab(
                            target.ip,
                            port,
                            hostname=target.hostname,
                            reader=reader,
                            writer=writer,
                        ),
                        timeout=max(self.settings.banner_timeout * 4, self.settings.timeout),
                    )
                    result.service = grab.service
                    result.product = grab.product
                    result.version = grab.version
                    result.banner = grab.banner
                    result.banner_raw = grab.banner_raw
                    result.probe = grab.probe
                    result.tls = grab.tls
                    result.fingerprint = grab.fingerprint
                    if grab.error and not result.error:
                        result.error = grab.error
                except asyncio.TimeoutError:
                    result.error = "banner grab timed out (port remains open)"
                except (OSError, asyncio.IncompleteReadError) as exc:
                    result.error = f"banner grab failed: {exc}"
        except asyncio.TimeoutError:
            result.state = STATE_FILTERED
            result.error = f"timeout after {self.settings.timeout:g}s"
        except socket.gaierror as exc:
            result.state = STATE_FILTERED
            result.error = f"resolution failed: {exc}"
        except ConnectionRefusedError:
            result.state = STATE_CLOSED
        except ConnectionResetError:
            result.state = STATE_CLOSED
            result.error = None
        except OSError as exc:
            if exc.errno in (errno.EMFILE, errno.ENFILE):
                await self._handle_emfile()
                result.state = STATE_FILTERED
                result.error = "EMFILE: local file descriptor limit reached"
            elif exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EADDRNOTAVAIL):
                result.state = STATE_FILTERED
                result.error = exc.strerror or "host unreachable"
            elif exc.errno == errno.ECONNREFUSED:
                result.state = STATE_CLOSED
            else:
                result.state = STATE_FILTERED
                result.error = exc.strerror or str(exc)
        except asyncio.CancelledError:
            raise
        finally:
            if writer is not None:
                try:
                    writer.close()
                except (OSError, RuntimeError):  # pragma: no cover
                    pass
        return result

    async def _handle_emfile(self) -> None:
        """Back off globally when the local fd budget is exhausted."""
        self._emfile_events += 1
        if self._emfile_events == 1:
            self.fd_warnings.append(
                "hit EMFILE/ENFILE: the local file-descriptor limit is too low for this "
                "concurrency; reduce -c or raise 'ulimit -n'."
            )
        await asyncio.sleep(min(0.5, 0.02 * self._emfile_events))

    async def _record(self, target: Target, result: PortResult) -> None:
        host = self._hosts.get(target.ip)
        if host is None:  # pragma: no cover - defensive
            host = HostResult(ip=target.ip, hostname=target.hostname, is_ipv6=target.is_ipv6)
            self._hosts[target.ip] = host

        host.probed += 1
        if result.state == STATE_OPEN:
            host.ports.append(result)
            self._progress.open_ports += 1
            if self.on_open is not None:
                try:
                    self.on_open(result)
                except Exception:  # pragma: no cover - UI callbacks must not kill a scan
                    pass
        elif result.state == STATE_CLOSED:
            host.closed_ports += 1
            self._progress.closed += 1
        else:
            host.filtered_ports += 1
            self._progress.filtered += 1
        if result.error and result.state != STATE_CLOSED:
            self._progress.errors += 1
            if len(host.errors) < 5:
                host.errors.append(f"{result.port}/{result.protocol}: {result.error}")

        self._progress.completed += 1
        if self._progress.completed % _YIELD_EVERY == 0:
            await asyncio.sleep(0)  # let the UI breathe on huge scans
        self._emit_progress()

    def _emit_progress(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_progress_emit < self.progress_interval:
            return
        self._last_progress_emit = now
        if self.on_progress is not None:
            try:
                self.on_progress(self._progress)
            except Exception:  # pragma: no cover
                pass


def _iso(timestamp: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="seconds")


async def scan(
    targets: Sequence[Target],
    ports: Sequence[int],
    settings: ScanSettings | None = None,
    **kwargs,
) -> ScanResult:
    """Convenience wrapper: ``await scan(targets, ports, settings)``."""
    scanner = AsyncScanner(settings, **kwargs)
    return await scanner.scan(targets, ports)
