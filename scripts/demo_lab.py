#!/usr/bin/env python3
"""Spin up a loopback "lab" of fake services and scan it.

Used by the README/demo workflow and handy for local smoke tests:

    python3 scripts/demo_lab.py                 # scan the lab and write reports/demo.*
    python3 scripts/demo_lab.py --keep-open     # keep serving (Ctrl+C to stop)

The services are deliberately shallow imitations (SSH greeting, nginx-style
HTTP response, Redis PING, a silent TCP listener and a TLS endpoint) — enough to
exercise every fingerprinting path without touching the network.
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.banner_grabber import BannerGrabber  # noqa: E402
from core.parser import Target  # noqa: E402
from core.scanner import AsyncScanner, ScanSettings  # noqa: E402
from reporters.exporter import ReportMetadata, export_reports  # noqa: E402

SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"X-Powered-By: PHP/8.2.1\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)


async def ssh_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.write(SSH_BANNER)
    await writer.drain()
    await asyncio.sleep(1)
    writer.close()


async def http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
    except (TimeoutError, asyncio.IncompleteReadError):
        pass
    writer.write(HTTP_RESPONSE)
    await writer.drain()
    writer.close()


async def redis_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=2)
    except (TimeoutError, asyncio.IncompleteReadError):
        writer.close()
        return
    if line.strip().upper() == b"PING":
        writer.write(b"+PONG\r\n")
    elif line.strip().upper().startswith(b"INFO"):
        writer.write(b"$32\r\n# Server\r\nredis_version:7.2.4\r\n\r\n")
    else:
        writer.write(b"-ERR unknown command\r\n")
    await writer.drain()
    writer.close()


async def silent_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    await asyncio.sleep(1)
    writer.close()


def make_certificate(directory: Path) -> tuple[Path, Path] | None:
    """Generate a throwaway self-signed certificate (requires the openssl CLI)."""
    cert, key = directory / "cert.pem", directory / "key.pem"
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "30",
                "-subj", "/CN=demo.asynscan.local/O=asynscan demo/C=US",
                "-addext", "subjectAltName=DNS:demo.asynscan.local,DNS:www.demo.asynscan.local",
            ],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return cert, key


async def serve(keep_open: bool) -> int:
    servers: list[asyncio.AbstractServer] = []
    ports: dict[str, int] = {}

    async def start(name: str, handler, context: ssl.SSLContext | None = None) -> None:
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=context)
        servers.append(server)
        ports[name] = server.sockets[0].getsockname()[1]

    await start("ssh", ssh_handler)
    await start("http", http_handler)
    await start("redis", redis_handler)
    await start("silent", silent_handler)

    with tempfile.TemporaryDirectory() as tmp:
        material = make_certificate(Path(tmp))
        if material:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*material)
            await start("tls", http_handler, context)
        else:
            print("! openssl not available: skipping the TLS service")

    print("demo lab listening on:")
    for name, port in ports.items():
        print(f"  {name:7s} 127.0.0.1:{port}")

    if keep_open:
        async with asyncio.TaskGroup() as group:
            for server in servers:
                group.create_task(server.serve_forever())
        return 0

    targets = [Target(ip="127.0.0.1", hostname="localhost")]
    settings = ScanSettings(concurrency=16, timeout=1.5, banner_timeout=0.6, aggressive=True)
    grabber = BannerGrabber(timeout=1.5, banner_timeout=0.6, aggressive=True)
    result = await AsyncScanner(settings, grabber).scan(targets, sorted(ports.values()))
    metadata = ReportMetadata(
        command="python3 scripts/demo_lab.py",
        targets=["127.0.0.1"],
        ports=sorted(ports.values()),
        concurrency=settings.concurrency,
        timeout=settings.timeout,
    )
    written = await export_reports(
        result,
        json_path=str(ROOT / "reports" / "demo.json"),
        csv_path=str(ROOT / "reports" / "demo.csv"),
        html_path=str(ROOT / "reports" / "demo.html"),
        metadata=metadata,
    )
    print(f"\n{result.total_open} open port(s) found:")
    for port in result.open_ports:
        print(f"  {port.port:5d}  {port.display_service():22s} {port.banner_summary(limit=80)}")
    for kind, path in written.items():
        print(f"\n{kind.upper():5s} {path}")

    for server in servers:
        server.close()
    for server in servers:
        await server.wait_closed()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-open", action="store_true", help="serve until interrupted")
    args = parser.parse_args()
    try:
        return asyncio.run(serve(args.keep_open))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
