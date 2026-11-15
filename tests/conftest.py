"""Shared fixtures: an ephemeral loopback "lab" of fake services.

Each fixture starts a real asyncio server on port 0, so tests never depend on
privileged ports or on the outside network.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import threading
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest
import pytest_asyncio

from core.banner_grabber import BannerGrabber

SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"X-Powered-By: PHP/8.2.1\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)


async def _ssh_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.write(SSH_BANNER)
    await writer.drain()
    with contextlib.suppress(ConnectionError):
        await asyncio.sleep(2.0)
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    writer.write(HTTP_RESPONSE)
    await writer.drain()
    writer.close()


async def _redis_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=2)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        writer.close()
        return
    writer.write(b"+PONG\r\n" if line.strip().upper() == b"PING" else b"-ERR unknown command\r\n")
    await writer.drain()
    writer.close()


async def _silent_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Never greet, never reset: hold the connection, then close cleanly.

    The close must happen far enough in the future that the *client* closes first
    on fast interpreters (3.12/3.13); otherwise the peer close races the reader
    and turns into ECONNRESET instead of a clean EOF.
    """
    with contextlib.suppress(ConnectionError):
        await asyncio.sleep(2.0)
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()


@pytest.fixture(scope="session")
def cert_files(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Self-signed certificate for TLS tests (openssl CLI, skip if absent)."""
    import shutil
    import subprocess

    if shutil.which("openssl") is None:  # pragma: no cover - minimal images
        pytest.skip("openssl CLI not available")
    directory = tmp_path_factory.mktemp("certs")
    cert = directory / "cert.pem"
    key = directory / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "30",
            "-subj", "/CN=scan.test.example/O=Asynscan Tests/C=US",
            "-addext", "subjectAltName=DNS:scan.test.example,DNS:www.scan.test.example,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


class Lab:
    """A small collection of fake services on loopback ephemeral ports."""

    def __init__(self) -> None:
        self.servers: list[asyncio.AbstractServer] = []
        self.ports: dict[str, int] = {}

    async def start(self, name: str, handler: Callable, ssl_context: ssl.SSLContext | None = None) -> int:
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_context)
        self.servers.append(server)
        port = server.sockets[0].getsockname()[1]
        self.ports[name] = port
        return port

    async def close(self) -> None:
        for server in self.servers:
            server.close()
        for server in self.servers:
            await server.wait_closed()


@pytest_asyncio.fixture
async def lab(cert_files: tuple[Path, Path]) -> AsyncIterator[Lab]:
    lab = Lab()
    await lab.start("ssh", _ssh_handler)
    await lab.start("http", _http_handler)
    await lab.start("redis", _redis_handler)
    await lab.start("silent", _silent_handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert, key = cert_files
    context.load_cert_chain(cert, key)
    await lab.start("tls", _http_handler, ssl_context=context)
    try:
        yield lab
    finally:
        await lab.close()


class ThreadLab:
    """Lab servers running on their own event loop in a background thread.

    The CLI calls ``asyncio.run()``, which creates a *new* loop; servers owned by
    the pytest loop would accept SYNs but never run a handler. This fixture keeps
    the fake services alive independently so end-to-end CLI tests are realistic.
    """

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.ports: dict[str, int] = {}
        self._servers: list[asyncio.AbstractServer] = []

    def start(self, name: str, handler: Callable, ssl_context: ssl.SSLContext | None = None) -> int:
        async def _start() -> asyncio.AbstractServer:
            server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_context)
            self._servers.append(server)
            return server

        server = asyncio.run_coroutine_threadsafe(_start(), self.loop).result(10)
        self.ports[name] = server.sockets[0].getsockname()[1]
        return self.ports[name]

    def close(self) -> None:
        async def _close() -> None:
            for server in self._servers:
                server.close()
            for server in self._servers:
                await server.wait_closed()
            current = asyncio.current_task()
            pending = [task for task in asyncio.all_tasks() if task is not current]
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        with contextlib.suppress(Exception):
            asyncio.run_coroutine_threadsafe(_close(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)
        with contextlib.suppress(RuntimeError):
            if not self.loop.is_closed():
                self.loop.close()


@pytest.fixture
def lab_thread(cert_files: tuple[Path, Path]) -> ThreadLab:
    lab = ThreadLab()
    lab.start("ssh", _ssh_handler)
    lab.start("http", _http_handler)
    lab.start("redis", _redis_handler)
    lab.start("silent", _silent_handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert, key = cert_files
    context.load_cert_chain(cert, key)
    lab.start("tls", _http_handler, ssl_context=context)
    try:
        yield lab
    finally:
        lab.close()


@pytest.fixture
def grabber() -> BannerGrabber:
    return BannerGrabber(timeout=2.0, banner_timeout=0.5)


@pytest.fixture(scope="session")
def cert_der(cert_files: tuple[Path, Path]) -> bytes:
    from core.x509 import decode_pem

    return decode_pem(cert_files[0].read_bytes())


@pytest.fixture
def unused_tcp_port() -> int:
    """Reserve a currently-free loopback port (released before the test binds)."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def unused_port() -> int:
    """Return a loopback port that is (almost certainly) closed."""
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    return port
