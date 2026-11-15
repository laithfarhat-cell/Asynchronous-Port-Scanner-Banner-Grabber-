"""JSON, CSV and standalone HTML report generation.

All exporters consume the same :class:`core.scanner.ScanResult`, so the three
formats can never disagree about what was found.

* :class:`JSONExporter` — machine readable, versioned schema with full metadata.
* :class:`CSVExporter` — flat, spreadsheet-ready, one row per open port.
* :class:`HTMLExporter` — single self-contained file, dark UI, zero CDN calls.
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles

from core.models import HostResult, PortResult
from core.scanner import ScanResult

SCHEMA_VERSION = "1.0"
TOOL_NAME = "asynscan"
TOOL_VERSION = "1.0.0"

CSV_COLUMNS = (
    "timestamp",
    "ip",
    "hostname",
    "port",
    "protocol",
    "state",
    "service",
    "product",
    "version",
    "banner",
    "tls_cn",
    "tls_issuer",
    "tls_expires",
    "latency_ms",
)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def utc_now() -> str:
    """Current UTC timestamp in ISO-8601 (seconds precision)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_utc_now = utc_now  # backwards-compatible private alias


def _clean_banner(text: str | None) -> str:
    """Strip the raw NUL/control noise CSV consumers choke on."""
    if not text:
        return ""
    return " ".join(text.replace("\x00", "").split())


@dataclass(slots=True)
class ReportMetadata:
    """Scan context embedded in every export (essential for a findings report)."""

    command: str = ""
    targets: Sequence[str] = field(default_factory=tuple)
    ports: Sequence[int] = field(default_factory=tuple)
    preset: str | None = None
    concurrency: int = 0
    timeout: float = 0.0
    banner_grab: bool = True
    tls: bool = True
    rate_limit: float = 0.0
    tool_version: str = TOOL_VERSION
    hostname_resolution: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "tool_version": self.tool_version,
            "command": self.command,
            "arguments": {
                "targets": list(self.targets),
                "ports": len(self.ports),
                "port_list": list(self.ports),
                "port_preset": self.preset,
                "concurrency": self.concurrency,
                "timeout": self.timeout,
                "banner_grab": self.banner_grab,
                "tls_inspection": self.tls,
                "rate_limit": self.rate_limit,
                "resolve_dns": self.hostname_resolution,
                **(self.extra or {}),
            },
        }


def build_report(result: ScanResult, metadata: ReportMetadata | None = None) -> dict[str, Any]:
    """Build the canonical report dictionary (JSON schema v1)."""
    metadata = metadata or ReportMetadata(ports=tuple(result.ports))
    open_ports = result.open_ports
    services = result.top_services(limit=1000)

    state_counts: dict[str, int] = {"open": 0, "closed": 0, "filtered": 0}
    for host in result.hosts:
        for port in host.ports:
            state_counts["open" if port.is_open else port.state] = (
                state_counts.get("open" if port.is_open else port.state, 0) + 1
            )

    scan_block: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "started_at": result.started_at,
        "finished_at": result.finished_at or _utc_now(),
        "duration_seconds": round(result.duration, 3),
        "cancelled": result.cancelled,
    }
    scan_block.update(metadata.to_dict())

    summary = {
        "hosts_scanned": len(result.hosts),
        "hosts_with_open_ports": sum(1 for host in result.hosts if host.open_ports),
        "open_ports": len(open_ports),
        "closed_ports": result.progress.closed,
        "filtered_ports": result.progress.filtered,
        "probes": result.probed,
        "average_latency_ms": round(result.average_latency(), 2) if result.average_latency() else None,
        "requests_per_second": round(result.progress.rate, 2),
        "top_services": [{"service": name, "count": count} for name, count in services[:10]],
        "state_counts": state_counts,
    }

    # Only open ports are serialised: the JSON is meant to be actionable, not a
    # 65k-port dump (per-host closed/filtered counters keep the context).
    hosts = [host.to_dict() for host in result.hosts]

    return {
        "scan": scan_block,
        "summary": summary,
        "warnings": list(result.warnings),
        "hosts": hosts,
    }


# --------------------------------------------------------------------------- #
# Exporters
# --------------------------------------------------------------------------- #
class ReportExporter:
    """Base class: async, atomic file writes (never leaves half a report)."""

    extension = ""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path).expanduser()

    def prepare(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        return self.path

    async def _atomic_write(self, content: str, encoding: str = "utf-8") -> Path:
        target = self.prepare()
        tmp = target.with_name(f".{target.name}.tmp")
        async with aiofiles.open(tmp, "w", encoding=encoding, newline="") as handle:
            await handle.write(content)
        os.replace(tmp, target)
        return target

    async def export(self, result: ScanResult, metadata: ReportMetadata | None = None) -> Path:
        raise NotImplementedError


class JSONExporter(ReportExporter):
    """Structured JSON report (schema documented in the README)."""

    extension = "json"

    def __init__(self, path: str | os.PathLike[str], *, indent: int = 2) -> None:
        super().__init__(path)
        self.indent = indent

    def render(self, result: ScanResult, metadata: ReportMetadata | None = None) -> str:
        return json.dumps(build_report(result, metadata), indent=self.indent, ensure_ascii=False) + "\n"

    async def export(self, result: ScanResult, metadata: ReportMetadata | None = None) -> Path:
        return await self._atomic_write(self.render(result, metadata))


class CSVExporter(ReportExporter):
    """Flat one-row-per-open-port CSV, safe for Excel/Sheets/pandas."""

    extension = "csv"

    def render(self, result: ScanResult, metadata: ReportMetadata | None = None) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), extrasaction="ignore")
        writer.writeheader()
        for host in result.hosts:
            for port in host.ports:
                if not port.is_open:
                    continue
                writer.writerow(
                    {
                        "timestamp": port.scanned_at or result.finished_at or _utc_now(),
                        "ip": host.ip,
                        "hostname": host.hostname or "",
                        "port": port.port,
                        "protocol": port.protocol,
                        "state": port.state,
                        "service": port.display_service(),
                        "product": port.product or "",
                        "version": port.version or "",
                        "banner": _clean_banner(port.banner)[:500],
                        "tls_cn": (port.tls.subject_cn if port.tls else "") or "",
                        "tls_issuer": (port.tls.issuer_cn if port.tls else "") or "",
                        "tls_expires": (port.tls.not_after if port.tls else "") or "",
                        "latency_ms": f"{port.latency_ms:.2f}" if port.latency_ms is not None else "",
                    }
                )
        return buffer.getvalue()

    async def export(self, result: ScanResult, metadata: ReportMetadata | None = None) -> Path:
        return await self._atomic_write(self.render(result, metadata))


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --bg: #0b0f14; --panel: #121821; --panel-2: #172230; --border: #22303f;
  --text: #d7e2ee; --muted: #8aa0b4; --accent: #38e1b0; --accent-2: #4aa8ff;
  --danger: #ff6b6b; --warn: #ffc857; --crit: #ff4d6d;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: radial-gradient(1200px 600px at 10% -10%, #12202c 0%, var(--bg) 55%) fixed;
  color: var(--text); font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}}
header {{ padding: 28px 32px 12px; border-bottom: 1px solid var(--border); background: rgba(10,15,20,.7); }}
h1 {{ margin: 0 0 4px; font-size: 22px; letter-spacing: .3px; }}
h1 span {{ color: var(--accent); }}
.sub {{ color: var(--muted); font-size: 13px; font-family: var(--mono); }}
main {{ padding: 22px 32px 60px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 22px; }}
.card {{ background: linear-gradient(160deg, var(--panel-2), var(--panel)); border: 1px solid var(--border);
  border-radius: 12px; padding: 16px 18px; }}
.card .label {{ color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .12em; }}
.card .value {{ font-size: 30px; font-weight: 650; margin-top: 6px; font-family: var(--mono); color: var(--accent); }}
.card.alt .value {{ color: var(--accent-2); }}
.card.warn .value {{ color: var(--warn); }}
.card.danger .value {{ color: var(--danger); }}
.toolbar {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 18px 0 10px; }}
input[type=search], select {{
  background: var(--panel); color: var(--text); border: 1px solid var(--border);
  border-radius: 8px; padding: 9px 12px; font-family: var(--mono); font-size: 13px; min-width: 240px;
}}
input[type=search]::placeholder {{ color: #5d7286; }}
.chip {{ border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px; font-size: 11px;
  color: var(--muted); font-family: var(--mono); }}
table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border);
  border-radius: 12px; overflow: hidden; font-size: 13px; }}
thead th {{ position: sticky; top: 0; background: #0f1620; text-align: left; padding: 11px 12px;
  font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted);
  border-bottom: 1px solid var(--border); cursor: pointer; user-select: none; white-space: nowrap; }}
thead th:hover {{ color: var(--accent); }}
tbody td {{ padding: 9px 12px; border-bottom: 1px solid rgba(34,48,63,.6); vertical-align: top; }}
tbody tr:hover {{ background: var(--panel-2); }}
td.mono, .mono {{ font-family: var(--mono); }}
td.banner {{ max-width: 460px; word-break: break-word; color: #a6bccf; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-family: var(--mono);
  border: 1px solid var(--border); color: var(--accent); background: rgba(56,225,176,.08); }}
.badge.unknown {{ color: var(--muted); background: transparent; }}
.port {{ color: var(--accent-2); font-weight: 600; }}
.tls {{ color: var(--muted); font-size: 12px; }}
.tls .selfsigned {{ color: var(--warn); }}
.tls .expired {{ color: var(--crit); }}
footer {{ color: var(--muted); font-size: 12px; padding: 18px 32px 40px; border-top: 1px solid var(--border); }}
footer code {{ color: var(--accent); }}
.hidden {{ display: none !important; }}
.empty {{ padding: 28px; text-align: center; color: var(--muted); }}
@media (max-width: 720px) {{ main, header, footer {{ padding-left: 16px; padding-right: 16px; }} }}
</style>
</head>
<body>
<header>
  <h1>Async Port Scan <span>// asynscan</span></h1>
  <div class="sub">{started} &middot; duration {duration}s &middot; {probes} probes &middot; {rate} probes/s</div>
</header>
<main>
  <section class="cards">
    <div class="card"><div class="label">Hosts scanned</div><div class="value">{hosts}</div></div>
    <div class="card alt"><div class="label">Hosts with open ports</div><div class="value">{hosts_open}</div></div>
    <div class="card"><div class="label">Open ports</div><div class="value">{open_ports}</div></div>
    <div class="card warn"><div class="label">Filtered</div><div class="value">{filtered}</div></div>
    <div class="card danger"><div class="label">Expired TLS certs</div><div class="value">{expired_certs}</div></div>
  </section>

  <section class="cards">
    <div class="card"><div class="label">Top services</div><div class="value" style="font-size:15px;line-height:1.7">{top_services}</div></div>
    <div class="card alt"><div class="label">Avg. open-port latency</div><div class="value">{avg_latency}</div></div>
    <div class="card"><div class="label">Ports per target</div><div class="value">{port_count}</div></div>
  </section>

  <div class="toolbar">
    <input type="search" id="q" placeholder="Filter by IP, host, port, service, banner, TLS CN...">
    <select id="svc"><option value="">All services</option></select>
    <span class="chip" id="count"></span>
  </div>

  <table id="results">
    <thead>
      <tr>
        <th data-sort="ip">IP</th>
        <th data-sort="hostname">Hostname</th>
        <th data-sort="port" data-type="num">Port</th>
        <th data-sort="service">Service</th>
        <th data-sort="banner">Banner / TLS</th>
        <th data-sort="latency" data-type="num">Latency (ms)</th>
      </tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>

  <div class="empty hidden" id="empty">No open ports matched this filter.</div>
</main>
<footer>
  Generated by <code>asynscan {version}</code> on {generated}. Findings reflect a point-in-time
  observation; banners are self-reported by the target and must be validated manually.<br>
  Handle this report as sensitive security data.
</footer>
<script>
(function () {{
  var rows = Array.prototype.slice.call(document.querySelectorAll('#results tbody tr'));
  var q = document.getElementById('q');
  var svc = document.getElementById('svc');
  var count = document.getElementById('count');
  var empty = document.getElementById('empty');
  var services = {{}};
  rows.forEach(function (tr) {{
    var s = tr.getAttribute('data-service') || 'unknown';
    services[s] = (services[s] || 0) + 1;
  }});
  Object.keys(services).sort().forEach(function (s) {{
    var opt = document.createElement('option');
    opt.value = s; opt.textContent = s + ' (' + services[s] + ')';
    svc.appendChild(opt);
  }});

  function apply() {{
    var term = (q.value || '').toLowerCase().trim();
    var chosen = svc.value;
    var shown = 0;
    rows.forEach(function (tr) {{
      var text = tr.getAttribute('data-search') || '';
      var s = tr.getAttribute('data-service') || 'unknown';
      var ok = (!term || text.indexOf(term) !== -1) && (!chosen || s === chosen);
      tr.classList.toggle('hidden', !ok);
      if (ok) shown++;
    }});
    count.textContent = shown + ' / ' + rows.length + ' open ports';
    empty.classList.toggle('hidden', shown !== 0);
  }}
  q.addEventListener('input', apply);
  svc.addEventListener('change', apply);
  apply();

  var tbody = document.querySelector('#results tbody');
  var dir = {{}};
  document.querySelectorAll('th[data-sort]').forEach(function (th) {{
    th.addEventListener('click', function () {{
      var key = th.getAttribute('data-sort');
      var numeric = th.getAttribute('data-type') === 'num';
      dir[key] = !dir[key];
      var sorted = rows.slice().sort(function (a, b) {{
        var av = a.getAttribute('data-' + key) || '';
        var bv = b.getAttribute('data-' + key) || '';
        if (numeric) {{ return (parseFloat(av) - parseFloat(bv)) * (dir[key] ? 1 : -1); }}
        return av.localeCompare(bv, undefined, {{numeric: true}}) * (dir[key] ? 1 : -1);
      }});
      sorted.forEach(function (tr) {{ tbody.appendChild(tr); }});
    }});
  }});
}})();
</script>
</body>
</html>
"""


class HTMLExporter(ReportExporter):
    """Self-contained dark-mode HTML report (no external assets, CSP friendly)."""

    extension = "html"

    def __init__(self, path: str | os.PathLike[str], *, title: str = "Asynscan Security Report") -> None:
        super().__init__(path)
        self.title = title

    # -- rendering ------------------------------------------------------ #
    def _row(self, host: HostResult, port: PortResult) -> str:
        service = html.escape(port.display_service())
        badge_class = "badge" if port.service else "badge unknown"
        banner_parts: list[str] = []
        if port.banner:
            banner_parts.append(html.escape(_clean_banner(port.banner)[:400]))
        tls_block = ""
        if port.tls:
            bits: list[str] = []
            if port.tls.subject_cn:
                bits.append(f"CN={html.escape(port.tls.subject_cn)}")
            if port.tls.sans:
                bits.append("SAN=" + html.escape(", ".join(port.tls.sans[:4])))
            if port.tls.issuer_cn:
                bits.append(f"issuer={html.escape(port.tls.issuer_cn)}")
            if port.tls.not_after:
                cls = "expired" if port.tls.expired else "selfsigned" if port.tls.self_signed else ""
                bits.append(f'<span class="{cls}">expires {html.escape(port.tls.not_after[:10])}</span>')
            if port.tls.tls_version:
                bits.append(html.escape(port.tls.tls_version))
            if port.tls.self_signed:
                bits.append('<span class="selfsigned">self-signed</span>')
            if port.tls.error and not port.tls.subject_cn:
                bits.append(html.escape(port.tls.error))
            tls_block = f'<div class="tls">{" &middot; ".join(bits)}</div>'
        banner_html = html.escape(banner_parts[0]) if banner_parts else ""
        search_blob = " ".join(
            filter(
                None,
                [
                    host.ip,
                    host.hostname or "",
                    str(port.port),
                    port.service or "",
                    port.product or "",
                    port.version or "",
                    port.banner or "",
                    (port.tls.subject_cn if port.tls else "") or "",
                    " ".join(port.tls.sans[:8]) if port.tls else "",
                ],
            )
        ).lower()
        latency = f"{port.latency_ms:.2f}" if port.latency_ms is not None else ""
        return (
            f'      <tr data-service="{html.escape(port.service or "unknown")}"'
            f' data-search="{html.escape(search_blob)}"'
            f' data-ip="{html.escape(host.ip)}"'
            f' data-hostname="{html.escape(host.hostname or "")}"'
            f' data-port="{port.port}"'
            f' data-service-key="{html.escape(port.display_service())}"'
            f' data-banner="{html.escape(search_blob[:180])}"'
            f' data-latency="{latency or 0}">\n'
            f'        <td class="mono">{html.escape(host.ip)}</td>\n'
            f'        <td class="mono">{html.escape(host.hostname or "-")}</td>\n'
            f'        <td class="port mono">{port.port}/{html.escape(port.protocol)}</td>\n'
            f'        <td><span class="{badge_class}">{service}</span></td>\n'
            f'        <td class="banner">{banner_html}{tls_block}</td>\n'
            f'        <td class="mono">{latency}</td>\n'
            f"      </tr>"
        )

    def render(self, result: ScanResult, metadata: ReportMetadata | None = None) -> str:
        rows: list[str] = []
        expired = 0
        for host in result.hosts:
            for port in host.ports:
                if not port.is_open:
                    continue
                rows.append(self._row(host, port))
                if port.tls and port.tls.expired:
                    expired += 1

        top_services = result.top_services(limit=6)
        top_html = (
            " &middot; ".join(f"{html.escape(name)} <b>{count}</b>" for name, count in top_services)
            or "none"
        )
        avg = result.average_latency()
        duration = f"{result.duration:.2f}"
        started = html.escape(result.started_at or "n/a")
        summary_note = ""
        if result.cancelled:
            summary_note = " &middot; <span style='color:var(--warn)'>scan interrupted</span>"

        return _HTML_TEMPLATE.format(
            title=html.escape(self.title),
            started=started + summary_note,
            duration=duration,
            probes=f"{result.probed:,}",
            rate=f"{result.progress.rate:,.0f}",
            hosts=f"{len(result.hosts):,}",
            hosts_open=f"{sum(1 for h in result.hosts if h.open_ports):,}",
            open_ports=f"{result.total_open:,}",
            filtered=f"{result.progress.filtered:,}",
            expired_certs=f"{expired:,}",
            top_services=top_html,
            avg_latency=f"{avg:.2f} ms" if avg else "n/a",
            port_count=f"{len(result.ports):,}",
            rows="\n".join(rows) if rows else '      <tr><td colspan="6">No open ports found.</td></tr>',
            version=TOOL_VERSION,
            generated=html.escape(_utc_now()),
        )

    async def export(self, result: ScanResult, metadata: ReportMetadata | None = None) -> Path:
        return await self._atomic_write(self.render(result, metadata))


# --------------------------------------------------------------------------- #
# Convenience API
# --------------------------------------------------------------------------- #
async def export_reports(
    result: ScanResult,
    *,
    json_path: str | None = None,
    csv_path: str | None = None,
    html_path: str | None = None,
    metadata: ReportMetadata | None = None,
) -> dict[str, Path]:
    """Write every requested format; returns ``{format: path}``."""
    written: dict[str, Path] = {}
    if json_path:
        written["json"] = await JSONExporter(json_path).export(result, metadata)
    if csv_path:
        written["csv"] = await CSVExporter(csv_path).export(result, metadata)
    if html_path:
        written["html"] = await HTMLExporter(html_path).export(result, metadata)
    return written


def default_report_name(prefix: str = "scan") -> str:
    """``scan_20261115_183000`` — timestamped, sortable, no colons."""
    return f"{prefix}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
