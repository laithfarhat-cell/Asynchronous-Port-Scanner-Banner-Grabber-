"""Banner grabbing, signature matching and TLS certificate decoding."""

from __future__ import annotations

import asyncio

import pytest

from core.banner_grabber import (
    PORT_SERVICE_MAP,
    BannerGrabber,
    SignatureDatabase,
    guess_service,
    is_tls_port,
    probe_for_port,
    sanitize_banner,
)
from core.x509 import DERError, parse_certificate


class TestSignatures:
    @pytest.fixture(scope="class")
    def db(self) -> SignatureDatabase:
        return SignatureDatabase.load()

    def test_database_loads(self, db):
        assert len(db) >= 40
        ids = db.rule_ids
        for expected in ("ssh-openssh", "http-nginx", "http-apache", "tls-openssl",
                         "mysql", "postgresql", "redis", "smb-smb1", "memcached"):
            assert expected in ids

    @pytest.mark.parametrize(
        "banner,service,product,version",
        [
            ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "ssh", "OpenSSH", "9.6p1"),
            ("SSH-2.0-dropbear_2022.83", "ssh", "dropbear", "2022.83"),
            ("220 (vsFTPd 3.0.5)", "ftp", "vsFTPd", "3.0.5"),
            ("HTTP/1.1 200 OK | Server: nginx/1.24.0", "http", "nginx", "1.24.0"),
            ("Server: Apache/2.4.58 (Ubuntu)", "http", "Apache", "2.4.58"),
            ("Server: Microsoft-IIS/10.0", "http", "Microsoft-IIS", "10.0"),
            ("VERSION 1.6.21", "memcached", None, "1.6.21"),
            ("5.5.5-10.11.6-MariaDB-0+deb11u1", "mysql", "MariaDB", "10.11.6"),
            ("+PONG", "redis", None, None),
            ("-NOAUTH Authentication required.", "redis", None, None),
        ],
    )
    def test_matches(self, db, banner, service, product, version):
        match = db.match(banner)
        assert match is not None, banner
        assert match["service"] == service
        assert match["product"] == product
        assert match["version"] == version

    def test_unknown_banner(self, db):
        assert db.match("something totally custom") is None

    def test_empty_input(self, db):
        assert db.match("") is None
        assert db.match(None) is None

    def test_malformed_rule_is_skipped(self):
        db = SignatureDatabase([{"id": "bad", "pattern": "(unclosed"}, {"id": "ok", "pattern": "^abc"}])
        assert len(db) == 1
        assert db.match("abcdef")["rule"] == "ok"

    def test_custom_database_path(self, tmp_path):
        import json

        path = tmp_path / "sigs.json"
        path.write_text(json.dumps({"signatures": [
            {"id": "custom", "service": "myapp", "pattern": r"MYAPP (?P<version>[\d.]+)"}
        ]}), encoding="utf-8")
        db = SignatureDatabase.load(path)
        assert db.match("MYAPP 4.2.0") == {
            "service": "myapp", "product": None, "version": "4.2.0", "rule": "custom"
        }


class TestHelpers:
    def test_sanitize_binary(self):
        text = sanitize_banner(b"HTTP/1.1 200 OK\r\n\x00\x01Server: nginx\r\n")
        assert "HTTP/1.1 200 OK" in text and "Server: nginx" in text
        assert "\x00" not in text and "\r" not in text

    def test_sanitize_strips_ansi(self):
        assert sanitize_banner(b"\x1b[31mRED\x1b[0m") == "RED"

    def test_sanitize_truncates(self):
        assert len(sanitize_banner(b"A" * 10_000, limit=100)) <= 100

    @pytest.mark.parametrize("port,service", [(22, "ssh"), (443, "https"), (6379, "redis"),
                                              (3306, "mysql"), (5432, "postgresql")])
    def test_port_map(self, port, service):
        assert guess_service(port) == service
        assert PORT_SERVICE_MAP[port] == service

    def test_unknown_port(self):
        assert guess_service(65000) is None

    def test_tls_ports(self):
        assert is_tls_port(443) and is_tls_port(993) and not is_tls_port(80)

    @pytest.mark.parametrize("port", [80, 443, 6379, 11211, 5432, 445, 25, 3389])
    def test_probe_available(self, port):
        assert probe_for_port(port) is not None

    def test_no_probe_for_random_port(self):
        assert probe_for_port(54321) is None

    def test_greeting_protocols_need_no_payload(self):
        # MySQL and VNC speak first, which is exactly why they are read passively.
        assert probe_for_port(3306) is None
        assert guess_service(3306) == "mysql"


class TestX509:
    def test_parse_generated_certificate(self, cert_der):
        cert = parse_certificate(cert_der)
        assert cert.common_name == "scan.test.example"
        assert cert.issuer.get("C") == "US"
        assert "www.scan.test.example" in cert.subject_alt_names
        assert "127.0.0.1" in cert.subject_alt_names
        assert cert.self_signed is True
        assert cert.key_type == "RSA" and cert.key_bits == 2048
        assert cert.version == 3
        assert cert.signature_algorithm == "sha256WithRSAEncryption"
        assert cert.not_before and cert.not_after and cert.not_after > cert.not_before
        assert cert.expired is False
        assert 0 <= cert.days_remaining() <= 30
        assert len(cert.sha256) == 64

    def test_garbage_raises(self):
        with pytest.raises((DERError, IndexError, ValueError)):
            parse_certificate(b"\x00\x01\x02")

    def test_tls_info_summary(self):
        from core.models import TLSInfo

        info = TLSInfo(subject_cn="example.com", issuer_cn="R3", not_after="2030-01-01T00:00:00Z")
        summary = info.summary()
        assert "CN=example.com" in summary and "issuer=R3" in summary and "2030-01-01" in summary


class TestLiveGrabbing:
    async def test_passive_ssh_banner(self, lab, grabber):
        reader, writer = await asyncio.open_connection("127.0.0.1", lab.ports["ssh"])
        result = await grabber.grab("127.0.0.1", lab.ports["ssh"], reader=reader, writer=writer)
        writer.close()
        assert result.service == "ssh"
        assert result.product == "OpenSSH"
        assert result.version == "9.6p1"
        assert result.banner.startswith("SSH-2.0-OpenSSH")

    async def test_active_http_probe(self, lab, grabber):
        port = lab.ports["http"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await grabber.grab("127.0.0.1", port, reader=reader, writer=writer)
        writer.close()
        assert result.service == "http"
        assert result.product == "nginx"
        assert result.probe == "http-head"
        assert "X-Powered-By" in result.banner

    async def test_redis_on_standard_port(self, lab, monkeypatch):
        # Pretend the ephemeral port is 6379 so the port-driven probe is used.
        grabber = BannerGrabber(timeout=2.0, banner_timeout=0.4)
        port = lab.ports["redis"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        monkeypatch.setattr("core.banner_grabber.probe_for_port",
                            lambda p: __import__("core.banner_grabber", fromlist=["PROBES"]).PROBES["redis"])
        result = await grabber.grab("127.0.0.1", 6379, reader=reader, writer=writer)
        writer.close()
        assert "+PONG" in (result.banner or "")

    async def test_redis_on_non_standard_port_needs_aggressive(self, lab, grabber):
        port = lab.ports["redis"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await grabber.grab("127.0.0.1", port, reader=reader, writer=writer)
        writer.close()
        assert result.service is None  # quiet by default: no blind spraying

        active = BannerGrabber(timeout=2.0, banner_timeout=0.4, aggressive=True)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await active.grab("127.0.0.1", port, hostname="localhost",
                                   reader=reader, writer=writer)
        writer.close()
        assert result.fingerprint == "redis"
        assert "+PONG" in (result.banner or "")

    async def test_silent_service_yields_no_banner(self, lab, grabber):
        port = lab.ports["silent"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await grabber.grab("127.0.0.1", port, reader=reader, writer=writer)
        writer.close()
        assert result.banner is None
        assert result.service is None

    async def test_opportunistic_tls_on_unknown_port(self, lab):
        grabber = BannerGrabber(timeout=2.0, banner_timeout=0.4)
        port = lab.ports["tls"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await grabber.grab("127.0.0.1", port, hostname="scan.test.example",
                                    reader=reader, writer=writer)
        writer.close()
        assert result.tls is not None
        assert result.tls.subject_cn == "scan.test.example"
        assert result.tls.self_signed is True
        assert result.tls.tls_version
        assert result.product == "nginx"  # HTTPS HEAD succeeded over TLS

    async def test_tls_inspection_can_be_disabled(self, lab):
        grabber = BannerGrabber(timeout=2.0, banner_timeout=0.4, tls_inspection=False)
        port = lab.ports["tls"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await grabber.grab("127.0.0.1", port, reader=reader, writer=writer)
        writer.close()
        assert result.tls is None

    async def test_connection_reset_mid_banner_is_not_fatal(self, unused_tcp_port):
        """Servers that abort after writing must not raise or lose the banner.

        A RST arrives instead of a FIN whenever the peer closes with unread data
        in its buffer (or a middlebox injects a reset). Python 3.12/3.13 hit this
        on CI while 3.11 did not, because the client closed at a different point.
        """
        import socket
        import struct

        async def aborting_server(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.9\r\n")
            await writer.drain()
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            writer.transport.abort()  # force RST before the peer reads

        server = await asyncio.start_server(aborting_server, "127.0.0.1", unused_tcp_port)
        grabber = BannerGrabber(timeout=1.0, banner_timeout=0.4)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", unused_tcp_port)
            result = await grabber.grab("127.0.0.1", unused_tcp_port, reader=reader, writer=writer)
            writer.close()
        finally:
            server.close()
            await server.wait_closed()
        # Either the bytes arrived (fingerprinted) or the reset was recorded —
        # never an exception, and never a silent loss of evidence.
        assert result.product == "OpenSSH" or result.error
        assert result.service == "ssh"

    async def test_scanner_keeps_open_state_when_grab_resets(self, unused_tcp_port):
        """A reset during fingerprinting must not downgrade an open port."""
        import socket
        import struct

        from core.parser import Target
        from core.scanner import ScanSettings, scan

        async def aborting_server(reader, writer):
            writer.write(b"garbage\r\n")
            await writer.drain()
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            writer.transport.abort()

        server = await asyncio.start_server(aborting_server, "127.0.0.1", unused_tcp_port)
        try:
            result = await scan(
                [Target(ip="127.0.0.1")],
                [unused_tcp_port],
                ScanSettings(timeout=1.0, banner_timeout=0.3),
            )
        finally:
            server.close()
            await server.wait_closed()
        port = result.hosts[0].ports[0]
        assert port.state == "open"
        assert result.total_open == 1

    async def test_no_active_probes_means_passive_only(self, lab):
        grabber = BannerGrabber(timeout=2.0, banner_timeout=0.4, active_probes=False)
        port = lab.ports["ssh"]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await grabber.grab("127.0.0.1", port, reader=reader, writer=writer)
        writer.close()
        assert result.product == "OpenSSH"
        assert result.probe is None
