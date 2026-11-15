"""Report exporters: schema stability, CSV shape and the standalone HTML file."""

from __future__ import annotations

import csv
import io
import json
import re

import pytest

from core.models import HostResult, PortResult, TLSInfo
from core.parser import Target
from core.scanner import ScanResult, ScanSettings, scan
from reporters.exporter import (
    CSV_COLUMNS,
    CSVExporter,
    HTMLExporter,
    JSONExporter,
    ReportMetadata,
    build_report,
    export_reports,
)


@pytest.fixture
def sample_result() -> ScanResult:
    tls = TLSInfo(
        subject_cn="scan.test.example",
        sans=["scan.test.example", "www.scan.test.example"],
        issuer_cn="scan.test.example",
        issuer_org="Asynscan Tests",
        not_after="2030-01-01T00:00:00+00:00",
        days_remaining=1000,
        expired=False,
        self_signed=True,
        tls_version="TLSv1.3",
        key_type="RSA",
        key_bits=2048,
        error=None,
    )
    ports = [
        PortResult(ip="10.0.0.5", port=22, state="open", service="ssh", product="OpenSSH",
                   version="9.6p1", banner="SSH-2.0-OpenSSH_9.6p1", latency_ms=1.234,
                   scanned_at="2026-11-15T10:00:00+00:00"),
        PortResult(ip="10.0.0.5", port=443, state="open", service="https", product="nginx",
                   version="1.24.0", banner="HTTP/1.1 200 OK", tls=tls, latency_ms=3.5,
                   scanned_at="2026-11-15T10:00:00+00:00"),
        PortResult(ip="10.0.0.6", port=6379, state="open", service="redis",
                   banner="+PONG", latency_ms=0.5, scanned_at="2026-11-15T10:00:00+00:00"),
    ]
    hosts = [
        HostResult(ip="10.0.0.5", hostname="web.example", ports=ports[:2], probed=100,
                   closed_ports=98),
        HostResult(ip="10.0.0.6", hostname=None, ports=ports[2:], probed=100, closed_ports=99),
    ]
    result = ScanResult(hosts=hosts, ports=[22, 443, 6379], started_at="2026-11-15T10:00:00+00:00",
                        finished_at="2026-11-15T10:00:05+00:00", duration=5.0, input_hosts=2)
    result.progress.completed = 200
    result.progress.open_ports = 3
    result.progress.closed = 197
    return result


@pytest.fixture
def metadata() -> ReportMetadata:
    return ReportMetadata(
        command="asynscan -t 10.0.0.0/30 -p 22,443,6379",
        targets=["10.0.0.0/30"],
        ports=[22, 443, 6379],
        preset=None,
        concurrency=500,
        timeout=2.0,
    )


class TestJSON:
    def test_schema(self, sample_result, metadata):
        report = build_report(sample_result, metadata)
        assert set(report) == {"scan", "summary", "warnings", "hosts"}
        assert report["scan"]["schema_version"] == "1.0"
        assert report["scan"]["tool"] == "asynscan"
        assert report["scan"]["duration_seconds"] == 5.0
        assert report["scan"]["arguments"]["ports"] == 3
        assert report["scan"]["arguments"]["concurrency"] == 500
        assert report["summary"]["open_ports"] == 3
        assert report["summary"]["hosts_scanned"] == 2
        assert report["summary"]["hosts_with_open_ports"] == 2
        assert report["summary"]["top_services"][0]["count"] >= 1
        assert len(report["hosts"]) == 2

    def test_tls_is_nested(self, sample_result, metadata):
        report = build_report(sample_result, metadata)
        https = next(p for p in report["hosts"][0]["ports"] if p["port"] == 443)
        assert https["tls"]["subject_cn"] == "scan.test.example"
        assert "www.scan.test.example" in https["tls"]["sans"]
        assert https["tls"]["self_signed"] is True

    def test_json_is_valid_and_round_trips(self, sample_result, metadata):
        payload = JSONExporter("unused.json").render(sample_result, metadata)
        assert json.loads(payload)["summary"]["open_ports"] == 3

    async def test_written_atomically(self, sample_result, metadata, tmp_path):
        target = tmp_path / "nested" / "report.json"
        path = await JSONExporter(target).export(sample_result, metadata)
        assert path == target and target.is_file()
        assert not list(target.parent.glob(".*.tmp"))  # no leftover temp file


class TestCSV:
    def test_header_and_rows(self, sample_result, metadata):
        text = CSVExporter("unused.csv").render(sample_result, metadata)
        rows = list(csv.DictReader(io.StringIO(text)))
        assert tuple(rows[0].keys()) == CSV_COLUMNS
        assert len(rows) == 3
        assert rows[0]["ip"] == "10.0.0.5" and rows[0]["port"] == "22"
        assert rows[0]["service"] == "OpenSSH/9.6p1"
        assert rows[0]["latency_ms"] == "1.23"

    def test_tls_columns(self, sample_result, metadata):
        rows = list(csv.DictReader(io.StringIO(CSVExporter("x.csv").render(sample_result, metadata))))
        https = next(r for r in rows if r["port"] == "443")
        assert https["tls_cn"] == "scan.test.example"
        assert https["tls_issuer"] == "scan.test.example"
        assert https["tls_expires"].startswith("2030-01-01")

    def test_banner_is_newline_free(self, sample_result, metadata):
        sample_result.hosts[0].ports[0].banner = "line1\r\nline2\nline3"
        text = CSVExporter("x.csv").render(sample_result, metadata)
        assert text.count("\n") == 4  # header + 3 rows, nothing embedded
        assert "line1 line2 line3" in text

    async def test_export(self, sample_result, tmp_path):
        path = await CSVExporter(tmp_path / "out.csv").export(sample_result)
        assert path.is_file() and path.read_text(encoding="utf-8").startswith("timestamp,ip")


class TestHTML:
    def test_is_self_contained(self, sample_result, metadata):
        html = HTMLExporter("x.html").render(sample_result, metadata)
        assert html.startswith("<!DOCTYPE html>")
        assert re.search(r'(?:src|href)=["\']https?://', html) is None
        assert "<script>" in html and "<style>" in html

    def test_contains_findings(self, sample_result, metadata):
        html = HTMLExporter("x.html").render(sample_result, metadata)
        assert "10.0.0.5" in html and "10.0.0.6" in html
        assert "OpenSSH/9.6p1" in html and "nginx/1.24.0" in html
        assert "scan.test.example" in html
        assert html.count("<tr data-service") == 3

    def test_escapes_dangerous_banners(self, sample_result, metadata):
        sample_result.hosts[0].ports[0].banner = '<script>alert("xss")</script>'
        html = HTMLExporter("x.html").render(sample_result, metadata)
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_summary_cards(self, sample_result, metadata):
        html = HTMLExporter("x.html").render(sample_result, metadata)
        for label in ("Hosts scanned", "Open ports", "Filtered", "Expired TLS certs"):
            assert label in html

    async def test_export(self, sample_result, tmp_path):
        path = await HTMLExporter(tmp_path / "r.html").export(sample_result)
        assert path.stat().st_size > 4000


class TestMultiFormat:
    async def test_export_reports_writes_all(self, sample_result, metadata, tmp_path):
        written = await export_reports(
            sample_result,
            json_path=str(tmp_path / "a.json"),
            csv_path=str(tmp_path / "a.csv"),
            html_path=str(tmp_path / "a.html"),
            metadata=metadata,
        )
        assert set(written) == {"json", "csv", "html"}
        assert all(path.is_file() for path in written.values())

    async def test_export_reports_partial(self, sample_result, tmp_path):
        written = await export_reports(sample_result, csv_path=str(tmp_path / "only.csv"))
        assert set(written) == {"csv"}

    async def test_real_scan_round_trip(self, lab, tmp_path):
        result = await scan(
            [Target(ip="127.0.0.1", hostname="localhost")],
            [lab.ports["ssh"], lab.ports["tls"]],
            ScanSettings(timeout=2.0, banner_timeout=0.5),
        )
        written = await export_reports(result, json_path=str(tmp_path / "r.json"),
                                       csv_path=str(tmp_path / "r.csv"),
                                       html_path=str(tmp_path / "r.html"))
        report = json.loads(written["json"].read_text(encoding="utf-8"))
        assert report["summary"]["open_ports"] == 2
        port_data = {p["port"]: p for p in report["hosts"][0]["ports"]}
        assert port_data[lab.ports["ssh"]]["product"] == "OpenSSH"
        assert port_data[lab.ports["tls"]]["tls"]["subject_cn"] == "scan.test.example"
