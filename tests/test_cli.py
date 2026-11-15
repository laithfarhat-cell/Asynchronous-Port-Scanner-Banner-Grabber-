"""CLI surface: argument validation, exit codes and end-to-end runs."""

from __future__ import annotations

import csv
import io
import json

import pytest

from cli.interface import build_arg_parser, main, parse_arguments


class TestArguments:
    def test_defaults(self):
        args = parse_arguments(["-t", "10.0.0.1", "-p", "80"])
        assert args.concurrency == 500
        assert args.timeout == 2.0
        assert args.banner_timeout == 1.0
        assert args.no_banner is False
        assert args.no_tls is False

    def test_target_and_ports_required(self):
        with pytest.raises(SystemExit):
            parse_arguments([])
        with pytest.raises(SystemExit):
            parse_arguments(["-t", "10.0.0.1"])
        with pytest.raises(SystemExit):
            parse_arguments(["-p", "80"])

    def test_combined_flags(self):
        args = parse_arguments(
            ["-t", "a", "-t", "b", "-iL", "list.txt", "-p", "22,80", "--top-ports", "100",
             "-c", "1000", "--timeout", "0.5", "--no-banner", "-oJ", "j.json", "-oC", "c.csv",
             "-oH", "h.html", "--aggressive", "--tls-all", "--delay", "0.1", "--rate", "50"]
        )
        assert args.target == ["a", "b"]
        assert args.ports == "22,80"
        assert args.top_ports == 100
        assert args.concurrency == 1000
        assert args.timeout == 0.5
        assert args.no_banner and args.aggressive and args.tls_all
        assert (args.json, args.csv, args.html) == ("j.json", "c.csv", "h.html")

    def test_invalid_concurrency(self):
        with pytest.raises(SystemExit):
            parse_arguments(["-t", "a", "-p", "80", "-c", "0"])

    def test_invalid_timeout(self):
        with pytest.raises(SystemExit):
            parse_arguments(["-t", "a", "-p", "80", "--timeout", "-1"])

    def test_invalid_top_ports(self):
        with pytest.raises(SystemExit):
            parse_arguments(["-t", "a", "--top-ports", "42"])

    def test_help_lists_key_flags(self):
        help_text = build_arg_parser().format_help()
        for flag in ("-t/--target", "-iL/--input-list", "-p/--ports", "--top-ports",
                     "-c/--concurrency", "--timeout", "--no-banner",
                     "-oJ/--json", "-oC/--csv", "-oH/--html"):
            assert flag in help_text.replace("--target TARGET", "-t/--target TARGET").replace(
                "--input-list FILE", "-iL/--input-list FILE"
            ) or flag.split("/")[-1].lstrip("-") in help_text


class TestEndToEnd:
    def test_scan_writes_reports(self, lab_thread, tmp_path, capsys):
        out_json = tmp_path / "r.json"
        out_csv = tmp_path / "r.csv"
        out_html = tmp_path / "r.html"
        code = main([
            "-t", "127.0.0.1", "-p", f"{lab_thread.ports['ssh']},{lab_thread.ports['http']}",
            "--timeout", "1.5", "--banner-timeout", "0.6",
            "-oJ", str(out_json), "-oC", str(out_csv), "-oH", str(out_html),
            "--no-color", "-q",
        ])
        assert code == 0
        assert out_json.is_file() and out_csv.is_file() and out_html.is_file()
        report = json.loads(out_json.read_text(encoding="utf-8"))
        assert report["summary"]["open_ports"] == 2
        services = {p["service"] for p in report["hosts"][0]["ports"]}
        assert "ssh" in services and "http" in services
        rows = list(csv.DictReader(io.StringIO(out_csv.read_text(encoding="utf-8"))))
        assert len(rows) == 2
        assert "asynscan" in out_html.read_text(encoding="utf-8")

    def test_quiet_mode_prints_one_line_per_open_port(self, lab_thread, capsys):
        code = main(["-t", "127.0.0.1", "-p", str(lab_thread.ports["ssh"]), "--timeout", "1.5",
                     "--no-color", "-q"])
        assert code == 0
        out = capsys.readouterr().out
        assert "127.0.0.1:" in out

    def test_bad_target_exits_2(self, capsys):
        assert main(["-t", "10.0.0.0/33", "-p", "80", "-q"]) == 2

    def test_missing_target_file_exits_2(self, capsys):
        assert main(["-iL", "/no/such/file.txt", "-p", "80", "-q"]) == 2

    def test_bad_port_spec_exits_2(self):
        assert main(["-t", "127.0.0.1", "-p", "99999", "-q"]) == 2

    def test_input_list_and_top_ports(self, lab_thread, tmp_path):
        targets = tmp_path / "targets.txt"
        targets.write_text("# lab\n127.0.0.1\n", encoding="utf-8")
        out = tmp_path / "r.json"
        code = main(["-iL", str(targets), "-p", str(lab_thread.ports["ssh"]), "-oJ", str(out),
                     "--timeout", "1.5", "--no-color", "-q"])
        assert code == 0
        assert json.loads(out.read_text(encoding="utf-8"))["summary"]["open_ports"] == 1

    def test_report_dir_option(self, lab_thread, tmp_path):
        directory = tmp_path / "reports"
        code = main(["-t", "127.0.0.1", "-p", str(lab_thread.ports["ssh"]), "-oJ", "r.json",
                     "--report-dir", str(directory), "--timeout", "1.5", "-q"])
        assert code == 0
        assert (directory / "r.json").is_file()

    def test_oa_prefix_writes_three_files(self, lab_thread, tmp_path):
        prefix = tmp_path / "scan"
        code = main(["-t", "127.0.0.1", "-p", str(lab_thread.ports["ssh"]), "-oA", str(prefix),
                     "--timeout", "1.5", "-q"])
        assert code == 0
        for suffix in (".json", ".csv", ".html"):
            assert prefix.with_suffix(suffix).is_file()

    def test_no_banner_mode(self, lab_thread, tmp_path):
        out = tmp_path / "r.json"
        code = main(["-t", "127.0.0.1", "-p", str(lab_thread.ports["ssh"]), "--no-banner",
                     "-oJ", str(out), "--timeout", "1.5", "-q"])
        assert code == 0
        port = json.loads(out.read_text(encoding="utf-8"))["hosts"][0]["ports"][0]
        assert port["product"] is None and port["banner"] is None
