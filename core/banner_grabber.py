"""Banner grabbing, active protocol probing and TLS certificate inspection.

Three layers of evidence are collected for every open port:

1. **Passive** — chatty daemons (SSH, FTP, SMTP, POP3, IMAP, MySQL, VNC, ...)
   announce themselves immediately. We read for a short, bounded window.
2. **Active** — silent services get one lightweight, protocol-aware probe
   (HTTP ``HEAD``, Redis ``PING``, Memcached ``version``, PostgreSQL SSLRequest,
   SMTP ``EHLO``, RDP/SMB negotiation).
3. **TLS** — for TLS-bearing ports the handshake certificate is decoded (CN,
   SANs, issuer, validity, key info) with the dependency-free parser in
   :mod:`core.x509`.

Everything captured is then matched against ``data/signatures.json``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from re import Pattern

from .models import TLSInfo
from .paths import data_dir, data_file
from .x509 import Certificate, DERError, parse_certificate

# --------------------------------------------------------------------------- #
# Port intelligence
# --------------------------------------------------------------------------- #
#: Ports where a TLS handshake is expected first (the client must speak TLS).
TLS_PORTS: tuple[int, ...] = (
    443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 8443, 8883, 9443,
    10161, 10250, 49152, 49153, 49154, 49155, 49156, 49157,
)

#: A pragmatic port -> service map used when no banner is available.
PORT_SERVICE_MAP: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    67: "dhcp", 69: "tftp", 79: "finger", 80: "http", 88: "kerberos", 110: "pop3",
    111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 500: "isakmp", 512: "exec", 513: "login", 514: "shell",
    515: "printer", 548: "afp", 554: "rtsp", 587: "submission", 623: "ipmi", 631: "ipp",
    636: "ldaps", 873: "rsync", 902: "vmware", 989: "ftps-data", 990: "ftps", 993: "imaps",
    994: "ircs", 995: "pop3s", 1025: "msrpc", 1080: "socks", 1110: "nfs", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2222: "ssh", 2375: "docker", 2376: "docker-ssl", 3000: "http",
    3260: "iscsi", 3306: "mysql", 3389: "rdp", 4443: "https", 4444: "krb524", 4505: "salt",
    5000: "http", 5060: "sip", 5432: "postgresql", 5555: "adb", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5901: "vnc", 5984: "couchdb", 6000: "x11", 6379: "redis", 6443: "kubernetes",
    7001: "weblogic", 7077: "spark", 8000: "http", 8008: "http", 8009: "ajp13", 8069: "http",
    8080: "http", 8081: "http", 8088: "http", 8161: "activemq", 8180: "http", 8200: "vault",
    8443: "https", 8500: "consul", 8888: "http", 8983: "solr", 9000: "http", 9042: "cassandra",
    9090: "http", 9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 9443: "https", 9999: "http", 10000: "webmin", 10250: "kubelet",
    11211: "memcached", 15672: "rabbitmq", 27017: "mongodb", 27018: "mongodb",
    50000: "db2", 50070: "hdfs",
}

#: Ports that speak HTTP and get a ``HEAD /`` probe when they stay silent.
HTTP_PORTS: tuple[int, ...] = (
    80, 81, 591, 2082, 2086, 3000, 5000, 5601, 5984, 7001, 8000, 8008, 8080,
    8081, 8082, 8088, 8090, 8161, 8180, 8200, 8500, 8888, 8983, 9000, 9090,
    9200, 9999, 10000, 15672,
)

_PROBE_TIMEOUT_FLOOR = 0.35


def guess_service(port: int) -> str | None:
    """Port-number based service guess (``None`` when unknown)."""
    return PORT_SERVICE_MAP.get(port)


def is_tls_port(port: int) -> bool:
    return port in TLS_PORTS


# --------------------------------------------------------------------------- #
# Probe definitions
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Probe:
    """An active protocol probe."""

    name: str
    payload: bytes
    #: ``True`` when the probe expects the payload echoed in a length-prefixed
    #: binary protocol (currently informational only).
    read_after: float = 0.6


_RDP_NEGOTIATE = (
    b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
)
_SMB_NEGOTIATE = (
    b"\x00\x00\x00\x85\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe\x00\x00\x00\x00\x00"
    b"\x62\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00"
)

PROBES: dict[str, Probe] = {
    "http": Probe(
        "http-head",
        b"HEAD / HTTP/1.1\r\n"
        b"Host: {host}\r\n"
        b"User-Agent: Mozilla/5.0 (compatible; asynscan/1.0)\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n\r\n",
    ),
    "https": Probe(
        "https-head",
        b"HEAD / HTTP/1.1\r\n"
        b"Host: {host}\r\n"
        b"User-Agent: Mozilla/5.0 (compatible; asynscan/1.0)\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n\r\n",
    ),
    "redis": Probe("redis-ping", b"PING\r\n"),
    "redis-info": Probe("redis-info", b"INFO server\r\n"),
    "memcached": Probe("memcached-version", b"version\r\n"),
    "smtp": Probe("smtp-ehlo", b"EHLO asynscan.local\r\n"),
    "postgresql": Probe(
        "postgres-sslrequest", b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
    ),
    "rdp": Probe("rdp-negotiate", _RDP_NEGOTIATE),
    "smb": Probe("smb-negotiate", _SMB_NEGOTIATE),
    "generic": Probe("generic-crlf", b"\r\n"),
}

#: probe name to use per port (first match wins)
_PORT_PROBE_MAP: dict[int, str] = {}
for _port in HTTP_PORTS:
    _PORT_PROBE_MAP[_port] = "http"
for _port in TLS_PORTS:
    _PORT_PROBE_MAP[_port] = "https"
_PORT_PROBE_MAP.update(
    {
        25: "smtp", 587: "smtp", 2525: "smtp",
        6379: "redis",
        11211: "memcached",
        5432: "postgresql",
        3389: "rdp",
        445: "smb", 139: "smb",
    }
)


#: Ports where a database/daemon probe is *the* way to get an answer; probing
#: before waiting for a passive banner cuts seconds off large scans.
DATABASE_PORTS: frozenset[int] = frozenset({6379, 11211, 5432, 3306, 3389, 445, 139})

#: Order of independent probes tried on unknown ports with --aggressive.
#: Each candidate gets its own connection, so a service that closes after an
#: unexpected payload cannot poison the next attempt.
AGGRESSIVE_CHAIN: tuple[str, ...] = ("redis", "memcached", "http", "generic")


def probe_for_port(port: int) -> Probe | None:
    name = _PORT_PROBE_MAP.get(port)
    return PROBES.get(name) if name else None


# --------------------------------------------------------------------------- #
# Signature database
# --------------------------------------------------------------------------- #
class SignatureDatabase:
    """Regex fingerprint database loaded from ``data/signatures.json``."""

    def __init__(self, rules: Sequence[dict[str, str]] = ()):
        self._rules: list[tuple[str, Pattern[str] | None, str | None, str]] = []
        for rule in rules:
            pattern = rule.get("pattern")
            if not pattern:
                continue
            try:
                compiled = re.compile(pattern, re.MULTILINE)
            except re.error:
                continue  # a broken rule must never break a scan
            self._rules.append((rule.get("id", "sig"), compiled, rule.get("service"), rule.get("description", "")))

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rule_ids(self) -> list[str]:
        return [rule_id for rule_id, _, _, _ in self._rules]

    @property
    def rules(self) -> list[dict[str, str | None]]:
        """Serialisable view of the loaded rules (for UIs, docs and `/api` endpoints)."""
        return [
            {
                "id": rule_id,
                "service": service,
                "pattern": pattern.pattern if pattern is not None else None,
                "description": description,
            }
            for rule_id, pattern, service, description in self._rules
        ]

    @classmethod
    def load(cls, path: os.PathLike[str] | str | None = None) -> SignatureDatabase:
        if path is not None:
            candidate = Path(path).expanduser()
        else:
            candidate = data_file("signatures.json") or (data_dir() / "signatures.json")
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return cls(_BUILTIN_RULES)
        rules = payload.get("signatures") if isinstance(payload, dict) else None
        if not rules:
            return cls(_BUILTIN_RULES)
        return cls(rules)

    def match(self, text: str | None) -> dict[str, str | None] | None:
        """Match *text* and return ``{service, product, version, rule}``."""
        if not text:
            return None
        for rule_id, pattern, service, _description in self._rules:
            assert pattern is not None
            found = pattern.search(text)
            if not found:
                continue
            groups = found.groupdict()
            product = (groups.get("product") or "").strip() or None
            version = (groups.get("version") or "").strip() or None
            return {
                "service": service or product,
                "product": product,
                "version": version,
                "rule": rule_id,
            }
        return None


#: Minimal fallback used only if the JSON database is unavailable.
_BUILTIN_RULES: list[dict[str, str]] = [
    {"id": "ssh", "service": "ssh", "pattern": r"^SSH-(?P<version>[\d.]+)-(?P<product>[\w.-]+)"},
    {"id": "ftp", "service": "ftp", "pattern": r"(?i)(?P<product>vsFTPd|ProFTPD|Pure-FTPd)\s*(?P<version>[\d.]*)?"},
    {"id": "http", "service": "http", "pattern": r"(?i)Server:\s*(?P<product>nginx|Apache|Microsoft-IIS|Caddy)(?:/(?P<version>[\d.]+))?"},
    {"id": "redis", "service": "redis", "pattern": r"(?i)^\+PONG|^-NOAUTH"},
    {"id": "memcached", "service": "memcached", "pattern": r"^VERSION\s+(?P<version>[\d.]+)"},
]


# --------------------------------------------------------------------------- #
# Grab results
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class GrabResult:
    """Everything the grabber learned about one open port."""

    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    banner_raw: str | None = None
    probe: str | None = None
    tls: TLSInfo | None = None
    fingerprint: str | None = None
    error: str | None = None

    def is_empty(self) -> bool:
        return not any((self.service, self.banner, self.tls, self.product))


_BANNER_LIMIT = 4096
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")


def sanitize_banner(data: bytes, limit: int = _BANNER_LIMIT) -> str:
    """Decode raw bytes into a single-line, printable banner string.

    Certificates, binary handshakes and ANSI escape sequences all show up in
    banners; the goal here is a lossless-enough, terminal-safe rendering.
    """
    if not data:
        return ""
    text = data[:limit].decode("latin-1", "replace")
    # Drop ANSI escape sequences before general control-character stripping.
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    text = _CONTROL_RE.sub(" ", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [" ".join(line.split()) for line in text.split("\n")]
    joined = " | ".join(line for line in lines if line)
    return joined.strip()


def _tls_info_from_cert(cert: Certificate, ssl_obj: ssl.SSLSocket | None = None) -> TLSInfo:
    info = TLSInfo(
        subject_cn=cert.common_name,
        sans=cert.subject_alt_names,
        issuer_cn=cert.issuer_cn,
        issuer_org=cert.issuer.get("O"),
        not_before=cert.not_before.isoformat() if cert.not_before else None,
        not_after=cert.not_after.isoformat() if cert.not_after else None,
        days_remaining=cert.days_remaining(),
        expired=cert.expired,
        self_signed=cert.self_signed,
        serial=cert.serial,
        signature_algorithm=cert.signature_algorithm,
        key_type=cert.key_type,
        key_bits=cert.key_bits,
        sha256=cert.sha256,
    )
    if ssl_obj is not None:
        try:
            info.tls_version = ssl_obj.version()
            cipher = ssl_obj.cipher()
            if cipher:
                info.cipher = f"{cipher[0]} ({cipher[1]})".strip()
        except (ValueError, OSError):  # pragma: no cover - socket already closed
            pass
    return info


# --------------------------------------------------------------------------- #
# The grabber
# --------------------------------------------------------------------------- #
class BannerGrabber:
    """Collects banners, probes services and inspects TLS certificates."""

    def __init__(
        self,
        *,
        timeout: float = 2.0,
        banner_timeout: float = 1.0,
        max_bytes: int = _BANNER_LIMIT,
        signatures: SignatureDatabase | None = None,
        active_probes: bool = True,
        tls_inspection: bool = True,
        tls_all_ports: bool = False,
        aggressive: bool = False,
        sni: bool = True,
        tls_min_version: ssl.TLSVersion | None = None,
    ) -> None:
        self.timeout = timeout
        self.banner_timeout = max(_PROBE_TIMEOUT_FLOOR, min(banner_timeout, timeout))
        self.max_bytes = max_bytes
        self.signatures = signatures or SignatureDatabase.load()
        self.active_probes = active_probes
        self.tls_inspection = tls_inspection
        self.tls_all_ports = tls_all_ports
        self.aggressive = aggressive
        self.sni = sni
        self.tls_min_version = tls_min_version or ssl.TLSVersion.TLSv1

    # -- contexts ---------------------------------------------------------- #
    def _ssl_context(self) -> ssl.SSLContext:
        """Permissive context: we inspect certificates, we do not trust them."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = self.tls_min_version
        except (ValueError, AttributeError):  # pragma: no cover - old OpenSSL
            pass
        # Keep broad compatibility with legacy appliances; recon != hardening.
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:  # pragma: no cover - restricted builds
            pass
        return context

    # -- low level I/O ------------------------------------------------------ #
    async def _read_banner(
        self,
        reader: asyncio.StreamReader,
        window: float | None = None,
        limit: int | None = None,
    ) -> bytes:
        """Read up to *limit* bytes within *window* seconds, tolerating silence."""
        deadline = asyncio.get_running_loop().time() + (window or self.banner_timeout)
        limit = limit or self.max_bytes
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(min(4096, limit - total)), timeout=remaining)
            except (asyncio.TimeoutError, TimeoutError):
                break
            except (ConnectionError, OSError):
                # RST mid-read (peer aborted, closed with unread data, or a
                # firewall injected a reset). Whatever arrived before it is
                # still valid evidence: keep it and stop reading.
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            # One short extra read is enough for multi-line greetings.
            if total >= 512:
                break
        return b"".join(chunks)

    async def _send(self, writer: asyncio.StreamWriter, payload: bytes) -> bool:
        try:
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout=self.banner_timeout)
            return True
        except (asyncio.TimeoutError, TimeoutError, OSError, RuntimeError):
            return False

    # -- TLS ---------------------------------------------------------------- #
    async def _open_tls(
        self, ip: str, port: int, hostname: str | None
    ) -> tuple[
        asyncio.StreamReader | None, asyncio.StreamWriter | None, TLSInfo | None, bool
    ]:
        server_hostname = None
        if self.sni and hostname:
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                server_hostname = hostname
        context = self._ssl_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=ip,
                    port=port,
                    ssl=context,
                    server_hostname=server_hostname,
                    limit=65536,
                ),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            return None, None, TLSInfo(error="TLS handshake timeout", handshake_failed=True), False
        except ssl.SSLError as exc:
            # Server answered with plaintext or closed the socket: not fatal.
            return None, None, TLSInfo(error=f"TLS error: {exc.reason or exc}", handshake_failed=True), False
        except (OSError, ConnectionError) as exc:
            return None, None, TLSInfo(error=f"TLS connection failed: {exc}", handshake_failed=True), False

        ssl_obj = writer.get_extra_info("ssl_object")
        tls_info = TLSInfo()
        der: bytes | None = None
        if ssl_obj is not None:
            try:
                der = ssl_obj.getpeercert(binary_form=True)
            except (ValueError, OSError):
                der = None
        if der:
            try:
                tls_info = _tls_info_from_cert(parse_certificate(der), ssl_obj)
            except (DERError, ValueError, IndexError) as exc:
                tls_info = _tls_info_from_cert(Certificate())
                tls_info.error = f"certificate parse error: {exc}"
                self._fill_channel(tls_info, ssl_obj)
        else:
            tls_info.error = "no peer certificate"
            self._fill_channel(tls_info, ssl_obj)
        return reader, writer, tls_info, False

    @staticmethod
    def _fill_channel(tls_info: TLSInfo, ssl_obj: ssl.SSLSocket | None) -> None:
        if ssl_obj is None:
            return
        try:
            tls_info.tls_version = ssl_obj.version()
            cipher = ssl_obj.cipher()
            if cipher:
                tls_info.cipher = f"{cipher[0]} ({cipher[1]})"
        except (ValueError, OSError):  # pragma: no cover
            pass

    # -- main entry --------------------------------------------------------- #
    async def grab(
        self,
        ip: str,
        port: int,
        *,
        hostname: str | None = None,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
    ) -> GrabResult:
        """Grab service information for an *already reachable* open port.

        The caller owns the plaintext socket. Because a plaintext socket cannot
        be re-negotiated as TLS portably, known/opportunistic TLS ports are
        re-connected with an SSL context; everything else reuses the existing
        connection so connect latency is only paid once.
        """
        try:
            return await self._grab(ip, port, hostname, reader, writer)
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError) as exc:
            # A reset while probing is normal on real networks (and on servers
            # that close immediately after writing). The port is open: report
            # what we know plus the reason, never raise at the caller.
            return GrabResult(
                service=guess_service(port),
                error=f"connection lost during grab: {exc.strerror or exc}",
            )

    async def _grab(
        self,
        ip: str,
        port: int,
        hostname: str | None,
        reader: asyncio.StreamReader | None,
        writer: asyncio.StreamWriter | None,
    ) -> GrabResult:
        result = GrabResult(service=guess_service(port))
        if not self.active_probes:
            raw = await self._read_banner(reader) if reader is not None else b""
            if raw:
                result.banner_raw = sanitize_banner(raw, self.max_bytes)
                self._apply_signature(result, result.banner_raw)
            return result

        if self.tls_inspection and is_tls_port(port):
            return await self._grab_tls(ip, port, hostname, result)

        probe_known = probe_for_port(port)
        if probe_known is not None and port in DATABASE_PORTS:
            # Silent binary protocols (Redis, DBs, RDP, SMB) only answer when
            # spoken to; do not burn the banner window waiting first.
            await self._probe_known(ip, port, hostname, reader, writer, result)
            if result.banner:
                return result

        raw = await self._read_banner(reader) if reader is not None else b""
        if raw:
            result.banner_raw = sanitize_banner(raw, self.max_bytes)
            self._apply_signature(result, result.banner_raw)
            if self._looks_like_tls_alert(raw):
                # Plaintext connect succeeded but the peer expects TLS.
                tls_result = await self._grab_tls(ip, port, hostname, result, opportunistic=True)
                if tls_result.tls is not None and not tls_result.tls.handshake_failed:
                    return tls_result

        if not result.banner:
            if probe_known is not None:
                await self._probe_known(ip, port, hostname, reader, writer, result)
            else:
                # One cheap HTTP HEAD: how non-standard web ports are found.
                await self._probe_http(ip, port, hostname, reader, writer, result)

        # TLS on a non-standard port is a very common finding: one extra
        # handshake attempt costs little and often wins big.
        if (
            not result.banner
            and not result.tls
            and self.tls_inspection
            and (self.tls_all_ports or probe_known is None or self.aggressive)
        ):
            tls_result = await self._grab_tls(ip, port, hostname, result, opportunistic=True)
            if tls_result.tls is not None:
                return tls_result

        if not result.banner and self.aggressive:
            await self._probe_chain(ip, port, hostname, result)
        return result

    async def _grab_tls(
        self,
        ip: str,
        port: int,
        hostname: str | None,
        result: GrabResult,
        *,
        opportunistic: bool = False,
    ) -> GrabResult:
        """Reconnect over TLS, decode the certificate and read an HTTPS banner."""
        tls_reader, tls_writer, tls_info, http_only = await self._open_tls(ip, port, hostname)
        if tls_info is not None and (not tls_info.handshake_failed or not opportunistic) or tls_info is not None and tls_info.handshake_failed and not opportunistic:
            result.tls = tls_info
        result.probe = "tls-opportunistic" if opportunistic else "tls-handshake"
        if tls_writer is not None and tls_reader is not None:
            try:
                probe = PROBES["https"].payload.replace(b"{host}", (hostname or ip).encode())
                if await self._send(tls_writer, probe):
                    raw = await self._read_banner(tls_reader)
                    if raw:
                        text = sanitize_banner(raw, self.max_bytes)
                        result.banner_raw = (
                            f"{result.banner_raw} {text}".strip() if result.banner_raw else text
                        )
                        self._apply_signature(result, result.banner_raw)
                        result.probe = "https-head"
            finally:
                self._close(tls_writer)
            if not result.service or result.service in {"https", "tls"}:
                result.service = "https"
            return result
        if http_only:
            # Server replied with plaintext (an HTTP status line): fingerprint it.
            raw = await self._read_banner(tls_reader) if tls_reader else b""
            if raw:
                result.banner_raw = sanitize_banner(raw, self.max_bytes)
                self._apply_signature(result, result.banner_raw)
        return result

    # -- probes ------------------------------------------------------------- #
    async def _probe_known(
        self,
        ip: str,
        port: int,
        hostname: str | None,
        reader: asyncio.StreamReader | None,
        writer: asyncio.StreamWriter | None,
        result: GrabResult,
    ) -> None:
        probe = probe_for_port(port)
        if probe is None or writer is None or reader is None or not probe.payload:
            return
        payload = probe.payload.replace(b"{host}", (hostname or ip).encode())
        if not await self._send(writer, payload):
            return
        # Redis/HTTP answer fast; binary protocols need a little longer.
        window = max(self.banner_timeout, 0.8) if probe.name.startswith(("http", "redis", "memcached")) else self.banner_timeout
        raw = await self._read_banner(reader, window=window)
        result.probe = probe.name
        if raw:
            text = sanitize_banner(raw, self.max_bytes)
            result.banner_raw = f"{result.banner_raw} {text}".strip() if result.banner_raw else text
            self._apply_signature(result, result.banner_raw)
        # ``+PONG`` proves Redis but says nothing about the version; a second
        # command on the same connection (no new TCP handshake) fills it in.
        wants_version = (
            probe.name == "redis-ping" and result.service == "redis" and not result.version
        )
        if wants_version and await self._send(writer, PROBES["redis-info"].payload):
            info_raw = await self._read_banner(reader, window=window)
            if info_raw:
                info_text = sanitize_banner(info_raw, self.max_bytes)
                match = self.signatures.match(info_text)
                if match and match.get("version"):
                    result.version = match["version"]
                    result.fingerprint = match.get("rule") or result.fingerprint
                result.banner_raw = f"{result.banner_raw} {info_text}".strip()

    async def _probe_http(
        self,
        ip: str,
        port: int,
        hostname: str | None,
        reader: asyncio.StreamReader | None,
        writer: asyncio.StreamWriter | None,
        result: GrabResult,
    ) -> None:
        """Single HTTP ``HEAD`` probe used for non-standard web ports."""
        if reader is None or writer is None:
            return
        payload = PROBES["http"].payload.replace(b"{host}", (hostname or ip).encode())
        if not await self._send(writer, payload):
            return
        raw = await self._read_banner(reader, window=min(self.banner_timeout, 1.0))
        if not raw:
            return
        text = sanitize_banner(raw, self.max_bytes)
        if not text[:5].upper().startswith(("HTTP/", "HTTP")):
            # Not a web server: keep the bytes for signature matching, but do
            # not claim them as "the" banner (an error line is not a greeting).
            combined = f"{result.banner_raw} {text}".strip() if result.banner_raw else text
            result.banner_raw = combined
            self._apply_signature(result, combined, soft=True)
            return
        result.probe = "http-head"
        result.banner_raw = f"{result.banner_raw} {text}".strip() if result.banner_raw else text
        self._apply_signature(result, result.banner_raw)

    async def _probe_chain(
        self,
        ip: str,
        port: int,
        hostname: str | None,
        result: GrabResult,
    ) -> None:
        """Try each protocol in :data:`AGGRESSIVE_CHAIN` on a fresh connection.

        Non-standard ports are the norm in real engagements (Redis on 34057,
        memcached on 11511, ...). One payload per connection is slower than a
        single socket, but it survives services that hang up on garbage.
        """
        for name in AGGRESSIVE_CHAIN:
            probe = PROBES.get(name)
            if probe is None or not probe.payload:
                continue
            reader = writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host=ip, port=port), timeout=self.timeout
                )
                payload = probe.payload.replace(b"{host}", (hostname or ip).encode())
                if not await self._send(writer, payload):
                    continue
                raw = await self._read_banner(reader, window=min(self.banner_timeout, 1.0))
            except (asyncio.TimeoutError, OSError, asyncio.IncompleteReadError):
                continue
            finally:
                self._close(writer)
            if not raw:
                continue
            text = sanitize_banner(raw, self.max_bytes)
            # Match this reply on its own: earlier speculative error lines must
            # not hide an anchored signature such as ``^\+PONG``.
            match = self.signatures.match(text)
            if match is None:
                combined = f"{result.banner_raw} {text}".strip() if result.banner_raw else text
                if self.signatures.match(combined) is None:
                    result.banner_raw = combined
                    continue
                text = combined
            result.probe = probe.name
            self._apply_signature(result, text)
            result.banner_raw = f"{result.banner_raw} {text}".strip() if result.banner_raw else text
            result.banner = text[:2048]
            return

    async def _probe_generic(
        self,
        ip: str,
        port: int,
        hostname: str | None,
        reader: asyncio.StreamReader | None,
        writer: asyncio.StreamWriter | None,
        result: GrabResult,
    ) -> None:
        """Last-resort: HTTP HEAD, then a bare CRLF (aggressive mode only)."""
        if reader is None or writer is None:
            return
        for probe in (PROBES["generic"],):
            payload = probe.payload.replace(b"{host}", (hostname or ip).encode())
            if not await self._send(writer, payload):
                return
            raw = await self._read_banner(reader, window=0.8)
            if raw:
                text = sanitize_banner(raw, self.max_bytes)
                result.probe = probe.name
                result.banner_raw = f"{result.banner_raw} {text}".strip() if result.banner_raw else text
                self._apply_signature(result, result.banner_raw)
                if result.banner:
                    return

    # -- helpers ------------------------------------------------------------ #
    @staticmethod
    def _looks_like_tls_alert(raw: bytes) -> bool:
        return len(raw) >= 3 and raw[0] == 0x15 and raw[1] == 0x03

    def _apply_signature(self, result: GrabResult, text: str | None, *, soft: bool = False) -> None:
        """Match *text* against the signature DB; optionally without promoting
        it to the canonical banner (used for speculative probes)."""
        if not text:
            return
        if not soft:
            result.banner = text[:2048]
        match = self.signatures.match(text)
        if not match:
            return
        if match.get("service"):
            result.service = match["service"]
        if match.get("product"):
            result.product = match["product"]
        if match.get("version"):
            result.version = match["version"]
        result.fingerprint = match.get("rule")

    @staticmethod
    def _close(writer: asyncio.StreamWriter | None) -> None:
        if writer is None:
            return
        try:
            writer.close()
        except (OSError, RuntimeError):  # pragma: no cover
            pass
