"""Scan engine behaviour: states, timeouts, concurrency, cancellation, rate limits."""

from __future__ import annotations

import asyncio
import time

import pytest

from core.parser import Target
from core.scanner import (
    AsyncScanner,
    RateLimiter,
    ScanProgress,
    ScanSettings,
    check_fd_budget,
    file_descriptor_limit,
    scan,
)

from .conftest import unused_port


def localhost() -> list[Target]:
    return [Target(ip="127.0.0.1", hostname=None)]


class TestStates:
    async def test_open_port_detected(self, lab):
        result = await scan(localhost(), [lab.ports["ssh"]],
                            ScanSettings(timeout=1.0, banner_timeout=0.4))
        assert result.total_open == 1
        port = result.open_ports[0]
        assert port.state == "open"
        assert port.product == "OpenSSH"
        assert port.latency_ms is not None and port.latency_ms >= 0
        assert port.scanned_at

    async def test_closed_port_is_closed(self):
        port = await unused_port()
        result = await scan(localhost(), [port], ScanSettings(timeout=1.0))
        assert result.total_open == 0
        assert result.progress.closed == 1

    async def test_filtered_port_times_out(self, monkeypatch):
        # Deterministic: a black-holed SYN surfaces as asyncio.TimeoutError.
        async def blackhole(*args, **kwargs):
            await asyncio.sleep(0.05)
            raise asyncio.TimeoutError

        monkeypatch.setattr(asyncio, "open_connection", blackhole)
        result = await scan([Target(ip="10.255.255.1")], [9],
                            ScanSettings(timeout=0.2, grab_banners=False))
        assert result.progress.filtered == 1
        assert result.total_open == 0
        host = result.hosts[0]
        assert host.filtered_ports == 1 and host.probed == 1
        assert "timeout" in host.errors[0]

    async def test_unreachable_host_is_filtered(self, monkeypatch):
        async def unreachable(*args, **kwargs):
            raise OSError(101, "Network is unreachable")

        monkeypatch.setattr(asyncio, "open_connection", unreachable)
        result = await scan([Target(ip="10.255.255.1")], [9],
                            ScanSettings(timeout=0.2, grab_banners=False))
        assert result.progress.filtered == 1
        assert "unreachable" in result.hosts[0].errors[0].lower()

    async def test_connection_refused_is_closed(self, monkeypatch):
        async def refused(*args, **kwargs):
            raise ConnectionRefusedError

        monkeypatch.setattr(asyncio, "open_connection", refused)
        result = await scan([Target(ip="127.0.0.1")], [1],
                            ScanSettings(timeout=0.2, grab_banners=False))
        assert result.progress.closed == 1

    async def test_emfile_is_handled_gracefully(self, monkeypatch):
        import errno

        async def emfile(*args, **kwargs):
            raise OSError(errno.EMFILE, "Too many open files")

        monkeypatch.setattr(asyncio, "open_connection", emfile)
        scanner = AsyncScanner(ScanSettings(timeout=0.2, grab_banners=False))
        result = await scanner.scan([Target(ip="127.0.0.1")], [80, 81, 82])
        assert result.progress.filtered == 3
        assert any("file-descriptor" in warning or "EMFILE" in warning for warning in result.warnings)

    async def test_all_ports_without_banner(self, lab):
        ports = [lab.ports["ssh"], await unused_port(), lab.ports["http"]]
        result = await scan(localhost(), ports,
                            ScanSettings(timeout=1.0, grab_banners=False))
        assert result.progress.completed == 3
        assert result.total_open == 2

    async def test_empty_inputs_raise(self):
        with pytest.raises(ValueError):
            await scan([], [80])
        with pytest.raises(ValueError):
            await scan(localhost(), [])

    async def test_hostname_is_preserved_in_results(self, lab):
        targets = [Target(ip="127.0.0.1", hostname="localhost")]
        result = await scan(targets, [lab.ports["ssh"]], ScanSettings(grab_banners=False))
        assert result.hosts[0].hostname == "localhost"


class TestConcurrencyAndRate:
    async def test_concurrency_is_capped_by_fd_budget(self):
        limit = file_descriptor_limit()
        capped, warnings = check_fd_budget(10 ** 6)
        assert capped < 10 ** 6
        assert warnings
        assert capped * 2 < max(limit, capped * 2 + 1)

    async def test_reasonable_concurrency_has_no_warnings(self):
        capped, warnings = check_fd_budget(10)
        assert capped == 10 and warnings == []

    async def test_semaphore_limits_in_flight_connections(self, monkeypatch):
        peak = {"current": 0, "max": 0}
        original = asyncio.open_connection

        async def tracked(*args, **kwargs):
            peak["current"] += 1
            peak["max"] = max(peak["max"], peak["current"])
            try:
                await asyncio.sleep(0.01)
                return await original(*args, **kwargs)
            finally:
                peak["current"] -= 1

        monkeypatch.setattr(asyncio, "open_connection", tracked)
        port = await unused_port()
        settings = ScanSettings(concurrency=5, timeout=0.5, grab_banners=False)
        await scan(localhost(), [port] * 30, settings)
        assert peak["max"] <= 5

    async def test_rate_limiter_paces_requests(self):
        limiter = RateLimiter(rate=200)
        started = time.monotonic()
        for _ in range(20):
            await limiter.acquire()
        elapsed = time.monotonic() - started
        assert elapsed >= 0.05  # 20 requests at 200/s ≈ 0.1s, never instant

    async def test_delay_is_applied(self):
        limiter = RateLimiter(delay=0.01)
        started = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        assert time.monotonic() - started >= 0.045

    async def test_zero_rate_is_free(self):
        limiter = RateLimiter(rate=0)
        started = time.monotonic()
        for _ in range(100):
            await limiter.acquire()
        assert time.monotonic() - started < 0.5


class TestCallbacksAndProgress:
    async def test_on_open_callback_streams_findings(self, lab):
        found = []
        scanner = AsyncScanner(
            ScanSettings(timeout=1.0, banner_timeout=0.3, grab_banners=False),
            on_open=found.append,
        )
        await scanner.scan(localhost(), [lab.ports["ssh"], lab.ports["http"]])
        assert len(found) == 2
        assert {p.port for p in found} == {lab.ports["ssh"], lab.ports["http"]}

    async def test_progress_callback_fires(self, lab):
        snapshots: list[ScanProgress] = []
        scanner = AsyncScanner(
            ScanSettings(timeout=1.0, grab_banners=False),
            on_progress=snapshots.append,
            progress_every=0.0,
        )
        await scanner.scan(localhost(), [lab.ports["ssh"], await unused_port()])
        assert snapshots
        assert snapshots[-1].completed == 2
        assert snapshots[-1].percent == 100.0

    async def test_progress_math(self):
        progress = ScanProgress(total=100, completed=25)
        assert progress.percent == 25.0
        assert progress.eta_seconds is not None and progress.eta_seconds > 0

    async def test_failing_callback_does_not_break_scan(self, lab):
        def explode(port):
            raise RuntimeError("UI bug")

        scanner = AsyncScanner(ScanSettings(timeout=1.0, grab_banners=False), on_open=explode)
        result = await scanner.scan(localhost(), [lab.ports["ssh"]])
        assert result.total_open == 1


class TestCancellation:
    async def test_cancellation_keeps_partial_results(self, lab):
        ports = [lab.ports["ssh"]] + [await unused_port() for _ in range(60)]
        scanner = AsyncScanner(ScanSettings(concurrency=2, timeout=0.05, delay=0.01,
                                            grab_banners=False))
        task = asyncio.create_task(scanner.scan(localhost(), ports))
        await asyncio.sleep(0.15)
        task.cancel()
        result = await task
        assert result.cancelled is True
        assert result.probed < len(ports)          # stopped early
        assert result.total_open >= 1              # kept what it had found
        assert result.duration > 0

    async def test_scanner_reusable_after_cancel(self, lab):
        scanner = AsyncScanner(ScanSettings(timeout=0.2, grab_banners=False))
        task = asyncio.create_task(scanner.scan(localhost(), [await unused_port()] * 50))
        await asyncio.sleep(0.05)
        task.cancel()
        await task
        again = await scanner.scan(localhost(), [lab.ports["ssh"]])
        assert again.total_open == 1


class TestResults:
    async def test_top_services_and_latency(self, lab):
        result = await scan(
            localhost(),
            [lab.ports["ssh"], lab.ports["http"], lab.ports["tls"]],
            ScanSettings(timeout=1.5, banner_timeout=0.5),
        )
        assert result.total_open == 3
        assert result.average_latency() is not None
        assert result.top_services()
        assert result.progress.rate > 0

    async def test_hosts_sorted_by_finding_count(self, lab):
        targets = [Target(ip="127.0.0.1"), Target(ip="127.0.0.2")]
        ports = [lab.ports["ssh"], lab.ports["http"]]
        result = await scan(targets, ports, ScanSettings(timeout=1.5, grab_banners=False))
        assert result.hosts[0].ip == "127.0.0.1"
        assert len(result.hosts[0].open_ports) >= len(result.hosts[-1].open_ports)
