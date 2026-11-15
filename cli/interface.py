"""Command line interface and live terminal UI.

The CLI is deliberately boring (``argparse``, no config files) while the UI is
not: an amber-on-black security-console look, a live progress bar with ETA, a
streaming table of discovered ports and a summary panel with export paths.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import shlex
import signal
import ssl
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from rich import box
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from core.banner_grabber import SignatureDatabase
from core.models import PortResult
from core.parser import (
    DEFAULT_MAX_HOSTS,
    MAX_PORT,
    ParseReport,
    PortParseError,
    TargetParseError,
    build_targets,
    parse_ports,
    shuffle_ports,
)
from core.scanner import AsyncScanner, ScanResult, ScanSettings, check_fd_budget
from reporters.exporter import (
    ReportMetadata,
    export_reports,
    utc_now,
)

BANNER = r"""
   _____                     _____
  /  _  \  ______  ____  ____/  _  \  ____   ____   ____
 /  /_\  \/  ___/ /    \/  __\  /_\  \/  __\_/ __ \ /  __\
/    |    \___ \\|   |  \  \_/    |    \  ___/\  ___/|  |  \
\____|__  /____  >___|  /\____|__|__  /\/  /\  \___  >__|
        \/     \/     \/             \/    \/      \/
""".strip("\n")

LEVEL_STYLES = {
    "info": "dim",
    "good": "bold green",
    "warn": "bold yellow",
    "error": "bold red",
    "probe": "bold cyan",
}


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asynscan",
        description="Asynchronous port scanner, banner grabber and TLS inspector.",
        epilog=(
            "examples:\n"
            "  asynscan -t 10.0.0.0/24 --top-ports 100 -oH report.html\n"
            "  asynscan -t example.com -p 22,80,443,8080 --timeout 1.5 -oJ out.json -oC out.csv\n"
            "  asynscan -iL targets.txt -p 1-1024 -c 1000 --aggressive --no-tls\n\n"
            "Only scan systems you are explicitly authorised to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    target = parser.add_argument_group("target selection")
    target.add_argument("-t", "--target", action="append", metavar="TARGET",
                        help="IPv4/IPv6 address, hostname or CIDR (repeatable, comma-separated)")
    target.add_argument("-iL", "--input-list", action="append", metavar="FILE",
                        help="file with one target per line ('#' comments allowed)")
    target.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS, metavar="N",
                        help=f"abort when a target set expands past N hosts (default {DEFAULT_MAX_HOSTS})")
    target.add_argument("--no-resolve", action="store_true",
                        help="do not resolve hostnames (IP addresses and CIDRs only)")
    target.add_argument("--dns-timeout", type=float, default=5.0, metavar="SEC",
                        help="per-host DNS resolution timeout (default 5.0)")

    ports = parser.add_argument_group("port selection")
    ports.add_argument("-p", "--ports", metavar="SPEC",
                       help="port spec: '22', '1-1024', '22,80,443', 'all', '-'")
    ports.add_argument("--top-ports", type=int, choices=(100, 1000), metavar="N",
                       help="use a built-in preset: 100 or 1000 most common ports")
    ports.add_argument("--max-ports", type=int, default=MAX_PORT, metavar="N",
                       help="safety cap on the number of ports per host (default 65535)")
    ports.add_argument("--shuffle", action="store_true",
                       help="randomise port order (less predictable scan pattern)")
    ports.add_argument("--seed", type=int, default=None,
                       help="seed for --shuffle, for reproducible ordering")

    perf = parser.add_argument_group("performance & stealth")
    perf.add_argument("-c", "--concurrency", type=int, default=500, metavar="N",
                      help="max concurrent probes (default 500, auto-clamped to fd limits)")
    perf.add_argument("--timeout", type=float, default=2.0, metavar="SEC",
                      help="per-port connect timeout (default 2.0)")
    perf.add_argument("--banner-timeout", type=float, default=1.0, metavar="SEC",
                      help="how long to wait for a banner (default 1.0)")
    perf.add_argument("--retries", type=int, default=0, metavar="N",
                      help="retry closed/filtered probes N times (default 0)")
    perf.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                      help="sleep SEC before every probe (default 0)")
    perf.add_argument("--jitter", type=float, default=0.0, metavar="SEC",
                      help="add 0..SEC random jitter per probe (default 0)")
    perf.add_argument("--rate", type=float, default=0.0, metavar="N",
                      help="global cap of N probes/second (token bucket, 0 = unlimited)")

    fp = parser.add_argument_group("fingerprinting")
    fp.add_argument("--no-banner", action="store_true", help="skip all banner grabbing")
    fp.add_argument("--aggressive", action="store_true",
                    help="extra probes on unknown ports (slower, noisier)")
    fp.add_argument("--no-tls", action="store_true", help="disable TLS/certificate inspection")
    fp.add_argument("--tls-all", action="store_true",
                    help="attempt a TLS handshake on every open port")
    fp.add_argument("--tls-min", choices=("1.0", "1.1", "1.2", "1.3"), default=None,
                    help="minimum TLS version to negotiate (default: library default)")
    fp.add_argument("--no-sni", action="store_true", help="do not send SNI during handshakes")
    fp.add_argument("--signatures", metavar="FILE",
                    help="custom signature database (default data/signatures.json)")

    out = parser.add_argument_group("reporting")
    out.add_argument("-oJ", "--json", metavar="FILE", help="write a JSON report")
    out.add_argument("-oC", "--csv", metavar="FILE", help="write a CSV report")
    out.add_argument("-oH", "--html", metavar="FILE", help="write a standalone HTML report")
    out.add_argument("-oA", "--all", metavar="PREFIX",
                     help="write PREFIX.json, PREFIX.csv and PREFIX.html")
    out.add_argument("--report-dir", default=".", metavar="DIR",
                     help="directory for generated reports (default: current directory)")
    out.add_argument("--show-closed", action="store_true",
                     help="stream closed/filtered ports to the console too")

    ui = parser.add_argument_group("interface")
    ui.add_argument("-q", "--quiet", action="store_true", help="no live UI, only results")
    ui.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ui.add_argument("-v", "--verbose", action="store_true", help="log more scan detail")
    ui.add_argument("--version", action="version", version="asynscan 1.0.0")
    return parser


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if not args.target and not args.input_list:
        parser.error("at least one target is required (-t/--target or -iL/--input-list)")
    if not args.ports and not args.top_ports:
        parser.error("port selection is required (-p/--ports or --top-ports)")
    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    if args.report_dir:
        args.report_dir = str(Path(args.report_dir).expanduser())
    return args


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #
def _risk_style(port: PortResult) -> str:
    """Colour hint based on how interesting a finding usually is."""
    if port.tls and port.tls.expired:
        return "bold red"
    risky = {23, 21, 512, 513, 514, 1433, 3306, 5432, 6379, 11211, 27017, 9200, 2375, 5900}
    if port.port in risky:
        return "bold yellow"
    if port.tls and port.tls.self_signed:
        return "yellow"
    return "white"


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m{secs:02d}s"


class ConsoleUI:
    """Owns the rich Console, the live display and the result tables."""

    def __init__(self, *, quiet: bool = False, no_color: bool = False, verbose: bool = False) -> None:
        self.console = Console(no_color=no_color or bool(os.environ.get("NO_COLOR")), highlight=False)
        self.quiet = quiet
        self.verbose = verbose
        self.progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None, complete_style="cyan", finished_style="green"),
            TextColumn("[bold]{task.completed:>7,}[/]/[dim]{task.total:,}[/]"),
            TextColumn("{task.percentage:>6.2f}%"),
            TextColumn("[dim]open=[bold green]{task.fields[open]}[/] filtered=[yellow]{task.fields[filtered]}[/] {task.fields[rate]} p/s ETA {task.fields[eta]}[/]"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        self._task_id: TaskID | None = None
        self._live: Live | None = None
        self._recent: list[PortResult] = []
        self._recent_limit = 10
        self._interactive = self.console.is_terminal and not quiet
        self._tty_stream = sys.stdout.isatty()

    # -- lifecycle ------------------------------------------------------ #
    def banner(self, argv: Sequence[str]) -> None:
        if self.quiet:
            return
        text = Text(BANNER, style="bold cyan", no_wrap=True)
        subtitle = Text.assemble(
            ("  asynscan ", "bold white"),
            ("1.0.0", "dim"),
            ("  ·  async port scanner · banner grabber · TLS inspector", "dim"),
        )
        self.console.print(Panel(Group(text, subtitle), border_style="cyan", box=box.ROUNDED,
                                 padding=(0, 2)))
        if self.verbose:
            self.console.print(Text("  command: " + " ".join(shlex.quote(a) for a in argv), style="dim"))

    def info(self, message: str, level: str = "info") -> None:
        if self.quiet and level in ("info", "probe"):
            return
        style = LEVEL_STYLES.get(level, "white")
        prefix = {"info": "·", "good": "✔", "warn": "!", "error": "✖", "probe": "»"}.get(level, "·")
        self.console.print(Text(f"  {prefix} {message}", style=style))

    def warning(self, message: str) -> None:
        self.info(message, "warn")

    def error(self, message: str) -> None:
        self.info(message, "error")

    def start_live(self, total: int) -> None:
        if self.quiet:
            return
        if not self._interactive:
            # Non-TTY (CI, pipes, logs): no Live display, just periodic progress.
            self._task_id = None
            self.console.print(Text(f"  scanning {total:,} probe(s)…", style="dim"))
            return
        self._task_id = self.progress.add_task(
            "scanning", total=max(1, total), open=0, filtered=0, rate="0", eta="--"
        )
        self._live = Live(
            self._render_live(),
            console=self.console,
            refresh_per_second=8,
            transient=False,
            redirect_stdout=False,
            redirect_stderr=False,
        )
        self._live.start()

    def _render_live(self) -> RenderableType:
        stream = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            show_edge=False,
            pad_edge=False,
            header_style="bold cyan",
        )
        for column, justify in (
            ("IP", "left"), ("Port", "right"), ("Service", "left"),
            ("Banner / TLS", "left"), ("ms", "right"),
        ):
            stream.add_column(column, justify=justify, no_wrap=(column != "Banner / TLS"))
        if not self._recent:
            stream.add_row("[dim]waiting for open ports…[/]", "", "", "", "")
        for port in self._recent[-self._recent_limit:]:
            stream.add_row(
                port.ip,
                str(port.port),
                Text(port.display_service(), style=_risk_style(port)),
                Text(port.banner_summary(limit=72) or "-", style="dim"),
                f"{port.latency_ms:.1f}" if port.latency_ms is not None else "-",
            )
        return Group(self.progress, Panel(stream, title="[bold]open ports[/]",
                                          border_style="grey35", box=box.ROUNDED))

    def update_progress(self, progress) -> None:
        if self.quiet:
            return
        if self._task_id is None:
            self._log_progress(progress)
            return
        eta = progress.eta_seconds
        values = {
            "completed": progress.completed,
            "open": progress.open_ports,
            "filtered": progress.filtered,
            "rate": f"{progress.rate:,.0f}",
            "eta": _format_duration(eta) if eta is not None else "--",
        }
        self.progress.update(self._task_id, **values)
        if self._live is not None:
            self._live.update(self._render_live(), refresh=True)

    def _log_progress(self, progress) -> None:
        """Throttled progress line for non-interactive sessions (every 25%)."""
        bucket = int(progress.percent // 25)
        if bucket <= getattr(self, "_progress_bucket", 0):
            return
        self._progress_bucket = bucket
        eta = progress.eta_seconds
        self.console.print(
            Text(
                f"  [{progress.percent:5.1f}%] {progress.completed:,}/{progress.total:,} probes · "
                f"{progress.open_ports} open · {progress.rate:,.0f} p/s"
                + (f" · ETA {_format_duration(eta)}" if eta else ""),
                style="dim",
            )
        )

    def on_open(self, port: PortResult) -> None:
        """Stream a finding as it is discovered."""
        self._recent.append(port)
        if self.quiet or not self._interactive:
            self.console.print(
                f"{port.ip}:{port.port}\t{port.display_service()}\t{port.banner_summary(limit=100)}"
            )
            return
        if self._live is not None:
            return  # the live panel already shows it; avoid interleaving
        style = _risk_style(port)
        line = Text.assemble(
            ("  + ", "bold green"),
            (f"{port.ip}:{port.port}", style),
            ("  ", ""),
            (port.display_service(), style),
            (f"  {port.banner_summary(limit=100)}", "dim"),
        )
        self.console.print(line)

    def stop_live(self) -> None:
        if self._live is not None:
            try:
                self._live.update(self._render_live(), refresh=True)
            finally:
                self._live.stop()
                self._live = None

    # -- results -------------------------------------------------------- #
    def print_plan(self, report: ParseReport, ports: Sequence[int], concurrency: int) -> None:
        if self.quiet:
            return
        table = Table.grid(padding=(0, 2))
        table.add_column(style="dim", justify="right")
        table.add_column(style="white")
        table.add_row("targets", f"[bold]{len(report.targets):,}[/] host(s)")
        table.add_row("ports", f"[bold]{len(ports):,}[/] per host")
        table.add_row("probes", f"[bold]{len(report.targets) * len(ports):,}[/]")
        table.add_row("concurrency", f"{concurrency:,}")
        if report.targets:
            preview = ", ".join(t.display for t in report.targets[:6])
            if len(report.targets) > 6:
                preview += f" … (+{len(report.targets) - 6} more)"
            table.add_row("scope", preview)
        self.console.print(Panel(table, title="[bold cyan]scan plan[/]", border_style="cyan",
                                 box=box.ROUNDED, padding=(0, 1)))

    def print_results(self, result: ScanResult, *, show_closed: bool = False) -> None:
        open_ports = result.open_ports
        if not open_ports and not show_closed:
            self.console.print(Panel("[yellow]no open ports found[/]", border_style="yellow",
                                     box=box.ROUNDED, title="results"))
            return
        table = Table(
            title=f"[bold]findings[/] ({len(open_ports)} open port(s))",
            box=box.SIMPLE_HEAD,
            header_style="bold cyan",
            show_lines=False,
            expand=True,
        )
        table.add_column("IP", style="white", no_wrap=True)
        table.add_column("Port", justify="right", style="bold cyan", no_wrap=True)
        table.add_column("State", style="green", no_wrap=True)
        table.add_column("Service", no_wrap=True)
        table.add_column("Banner / TLS Info", overflow="fold")
        table.add_column("Latency (ms)", justify="right", no_wrap=True)

        for host in result.hosts:
            for port in host.ports:
                if not port.is_open and not show_closed:
                    continue
                style = _risk_style(port) if port.is_open else "dim"
                table.add_row(
                    host.ip if not host.hostname else f"{host.ip}\n[dim]{host.hostname}[/]",
                    str(port.port),
                    Text(port.state, style="green" if port.is_open else "dim"),
                    Text(port.display_service(), style=style),
                    Text(port.banner_summary(limit=140) or "-", style="dim"),
                    f"{port.latency_ms:.2f}" if port.latency_ms is not None else "-",
                )
        self.console.print(table)

    def print_summary(self, result: ScanResult, outputs: dict[str, Path]) -> None:
        summary = Table(box=box.ROUNDED, border_style="cyan", show_header=False, expand=False)
        summary.add_column(style="dim", justify="right")
        summary.add_column(style="bold white")
        summary.add_row("duration", _format_duration(result.duration))
        summary.add_row("probes", f"{result.probed:,}")
        summary.add_row("throughput", f"{result.progress.rate:,.0f} probes/s")
        summary.add_row("hosts", f"{len(result.hosts):,} ({result.progress.open_ports} open port(s))")
        summary.add_row("closed / filtered", f"{result.progress.closed:,} / {result.progress.filtered:,}")
        avg = result.average_latency()
        if avg:
            summary.add_row("avg open-port latency", f"{avg:.2f} ms")
        top = result.top_services(limit=5)
        if top:
            summary.add_row("top services", " · ".join(f"{name} ×{count}" for name, count in top))
        status = "[yellow]interrupted[/]" if result.cancelled else "[green]complete[/]"
        self.console.print(Panel(summary, title=f"[bold]scan summary[/] — {status}",
                                 border_style="yellow" if result.cancelled else "green",
                                 box=box.ROUNDED))

        if outputs:
            files = Table.grid(padding=(0, 2))
            files.add_column(style="dim")
            files.add_column(style="bold green")
            for kind, path in outputs.items():
                files.add_row(kind.upper(), str(path))
            self.console.print(Panel(files, title="[bold]reports written[/]", border_style="green",
                                     box=box.ROUNDED))

        for warning in result.warnings:
            self.warning(warning)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
_TLS_VERSION_MAP = {
    "1.0": ssl.TLSVersion.TLSv1,
    "1.1": ssl.TLSVersion.TLSv1_1,
    "1.2": ssl.TLSVersion.TLSv1_2,
    "1.3": ssl.TLSVersion.TLSv1_3,
}


def _resolve_output_paths(args: argparse.Namespace) -> dict[str, str]:
    """Normalise ``-oJ/-oC/-oH/-oA`` into ``{kind: absolute-ish path}``."""
    paths: dict[str, str] = {}
    if args.all:
        prefix = Path(args.all).expanduser()
        if prefix.suffix.lower() in {".json", ".csv", ".html"}:
            prefix = prefix.with_suffix("")
        for kind in ("json", "csv", "html"):
            paths[kind] = f"{prefix}.{kind}"
    for kind, value in (("json", args.json), ("csv", args.csv), ("html", args.html)):
        if value:
            paths[kind] = value

    report_dir = Path(args.report_dir or ".").expanduser()
    resolved: dict[str, str] = {}
    for kind, path in paths.items():
        candidate = Path(path).expanduser()
        if not candidate.is_absolute() and report_dir != Path("."):
            candidate = report_dir / candidate
        resolved[kind] = str(candidate)
    return resolved


def build_metadata(args: argparse.Namespace, ports: Sequence[int], argv: Sequence[str]) -> ReportMetadata:
    return ReportMetadata(
        command=" ".join(["asynscan", *(shlex.quote(a) for a in argv)]),
        targets=list(args.target or []) + list(args.input_list or []),
        ports=list(ports),
        preset=f"top-{args.top_ports}" if args.top_ports else None,
        concurrency=args.concurrency,
        timeout=args.timeout,
        banner_grab=not args.no_banner,
        tls=not args.no_tls,
        rate_limit=args.rate,
        hostname_resolution=not args.no_resolve,
        extra={"aggressive": args.aggressive, "tls_all_ports": args.tls_all},
    )


async def run_scan(args: argparse.Namespace, ui: ConsoleUI, argv: Sequence[str]) -> int:
    # ---- plan ---------------------------------------------------------- #
    try:
        ports = parse_ports(args.ports, args.top_ports, max_ports=args.max_ports)
        if args.shuffle:
            ports = shuffle_ports(ports, args.seed)
        report = await build_targets(
            args.target or [],
            args.input_list or [],
            resolve_dns=not args.no_resolve,
            dns_timeout=args.dns_timeout,
            max_hosts=args.max_hosts,
        )
    except (TargetParseError, PortParseError) as exc:
        ui.error(str(exc))
        return 2
    except OSError as exc:
        ui.error(f"cannot read target list: {exc}")
        return 2

    for warning in report.warnings:
        ui.warning(warning)
    for unresolved in report.unresolved:
        ui.warning(f"unresolved: {unresolved}")
    if report.duplicates_skipped:
        ui.info(f"skipped {report.duplicates_skipped} duplicate target(s)")

    settings = ScanSettings(
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
        jitter=args.jitter,
        rate=args.rate,
        grab_banners=not args.no_banner,
        banner_timeout=args.banner_timeout,
        tls=not args.no_tls,
        tls_all_ports=args.tls_all,
        aggressive=args.aggressive,
        shuffle=args.shuffle,
        shuffle_seed=args.seed,
    )
    concurrency, fd_warnings = check_fd_budget(args.concurrency)
    for warning in fd_warnings:
        ui.warning(warning)
    settings.concurrency = concurrency

    ui.print_plan(report, ports, concurrency)

    signatures = SignatureDatabase.load(args.signatures) if args.signatures else SignatureDatabase.load()
    from core.banner_grabber import BannerGrabber

    grabber = BannerGrabber(
        timeout=args.timeout,
        banner_timeout=args.banner_timeout,
        signatures=signatures,
        active_probes=not args.no_banner,
        tls_inspection=not args.no_tls,
        tls_all_ports=args.tls_all,
        aggressive=args.aggressive,
        sni=not args.no_sni,
        tls_min_version=_TLS_VERSION_MAP.get(args.tls_min or ""),
    ) if not args.no_banner else None

    scanner = AsyncScanner(
        settings,
        grabber,
        on_open=ui.on_open if (ui.quiet or not ui._interactive) else None,
        on_progress=ui.update_progress,
    )

    # ---- run ----------------------------------------------------------- #
    ui.start_live(len(report.targets) * len(ports))
    stop_signal = asyncio.Event()
    scan_task = asyncio.create_task(scanner.scan(report.targets, ports))
    loop = asyncio.get_running_loop()

    def _request_stop(*_: object) -> None:
        if not stop_signal.is_set():
            stop_signal.set()
            ui.info("interrupt received — finishing gracefully (Ctrl+C again to abort hard)", "warn")
            scan_task.cancel()
        else:  # pragma: no cover - second Ctrl+C
            raise KeyboardInterrupt

    installed: list[int] = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
            loop.add_signal_handler(sig, _request_stop)
            installed.append(sig)

    try:
        result = await scan_task
    except (asyncio.CancelledError, KeyboardInterrupt):
        scan_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await scan_task
        # Rebuild a partial result from whatever the scanner recorded.
        result = await _partial_result(scanner, report, ports)
    finally:
        ui.stop_live()
        for sig in installed:  # restore default handling before exporting
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.remove_signal_handler(sig)

    # ---- report -------------------------------------------------------- #
    ui.print_results(result, show_closed=args.show_closed)

    outputs: dict[str, Path] = {}
    paths = _resolve_output_paths(args)
    if paths:
        metadata = build_metadata(args, ports, argv)
        try:
            outputs = await export_reports(result, json_path=paths.get("json"),
                                           csv_path=paths.get("csv"),
                                           html_path=paths.get("html"), metadata=metadata)
        except OSError as exc:
            ui.error(f"failed to write report: {exc}")
            return 3

    ui.print_summary(result, outputs)
    if result.cancelled:
        return 130
    return 0 if result.total_open or not result.hosts else 0


async def _partial_result(scanner: AsyncScanner, report: ParseReport, ports: Sequence[int]) -> ScanResult:
    """Assemble a :class:`ScanResult` from a cancelled scan's collected state."""
    hosts = [host for host in scanner._hosts.values() if host.ports]
    hosts.sort(key=lambda host: (-len(host.open_ports), host.ip))
    for host in hosts:
        host.ports.sort(key=lambda port: port.port)
    return ScanResult(
        hosts=hosts,
        progress=scanner.progress,
        ports=list(ports),
        started_at=utc_now(),
        finished_at=utc_now(),
        duration=scanner.progress.elapsed,
        cancelled=True,
        warnings=list(scanner.fd_warnings),
        input_hosts=len(report.targets),
    )


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_arguments(raw_argv)
    ui = ConsoleUI(quiet=args.quiet, no_color=args.no_color, verbose=args.verbose)
    ui.banner(["asynscan", *raw_argv])

    started = time.monotonic()
    try:
        return asyncio.run(run_scan(args, ui, raw_argv))
    except KeyboardInterrupt:
        ui.stop_live()
        ui.error("aborted by user")
        return 130
    except Exception as exc:  # pragma: no cover - unexpected failure path
        ui.stop_live()
        if args.verbose:
            ui.console.print_exception()
        ui.error(f"fatal: {exc}")
        return 1
    finally:
        if args.verbose:
            ui.info(f"total wall time {_format_duration(time.monotonic() - started)}", "info")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
