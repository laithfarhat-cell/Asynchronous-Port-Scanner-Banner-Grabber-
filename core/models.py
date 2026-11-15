"""Shared data models for the scanner.

Keeping the models in one place lets the scanner, banner grabber and reporters
agree on a single, serialisable representation without circular imports.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_FILTERED = "filtered"


class ScanState:
    """String constants for port states (kept as a class for autocompletion)."""

    OPEN = STATE_OPEN
    CLOSED = STATE_CLOSED
    FILTERED = STATE_FILTERED


@dataclass(slots=True)
class TLSInfo:
    """Certificate metadata extracted during a TLS handshake."""

    subject_cn: str | None = None
    sans: list[str] = field(default_factory=list)
    issuer_cn: str | None = None
    issuer_org: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    expired: bool | None = None
    self_signed: bool | None = None
    serial: str | None = None
    signature_algorithm: str | None = None
    tls_version: str | None = None
    cipher: str | None = None
    key_type: str | None = None
    key_bits: int | None = None
    sha256: str | None = None
    error: str | None = None
    #: ``True`` when the TCP connection worked but no TLS session was established.
    handshake_failed: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def summary(self) -> str:
        """One-line human readable summary used by the CLI table."""
        parts: list[str] = []
        if self.subject_cn:
            parts.append(f"CN={self.subject_cn}")
        elif self.sans:
            parts.append(f"SAN={self.sans[0]}")
        if self.issuer_cn:
            parts.append(f"issuer={self.issuer_cn}")
        if self.not_after:
            parts.append(f"expires={self.not_after[:10]}")
        if self.expired:
            parts.append("EXPIRED")
        if self.tls_version:
            parts.append(self.tls_version)
        if self.error and not parts:
            parts.append(f"TLS error: {self.error}")
        return " | ".join(parts)


@dataclass(slots=True)
class PortResult:
    """Outcome of a single (host, port) probe."""

    ip: str
    port: int
    state: str = STATE_CLOSED
    protocol: str = "tcp"
    hostname: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    banner_raw: str | None = None
    probe: str | None = None
    tls: TLSInfo | None = None
    latency_ms: float | None = None
    fingerprint: str | None = None
    error: str | None = None
    scanned_at: str | None = None

    @property
    def is_open(self) -> bool:
        return self.state == STATE_OPEN

    def display_service(self) -> str:
        """Best-effort ``service/version`` label for terminal/report output."""
        if self.product and self.version:
            return f"{self.product}/{self.version}"
        if self.product:
            return self.product
        return self.service or "unknown"

    def banner_summary(self, limit: int = 120) -> str:
        """Compact banner/TLS text for the live CLI table."""
        if self.tls and (self.tls.subject_cn or self.tls.sans or self.tls.error):
            text = self.tls.summary()
            if text:
                return text[:limit]
        if self.banner:
            return " ".join(self.banner.split())[:limit]
        return ""

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "banner_raw": self.banner_raw,
            "probe": self.probe,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "fingerprint": self.fingerprint,
            "scanned_at": self.scanned_at,
        }
        if self.tls is not None:
            data["tls"] = self.tls.to_dict()
        else:
            data["tls"] = None
        if self.error:
            data["error"] = self.error
        return data


@dataclass(slots=True)
class HostResult:
    """Aggregated findings for a single target host."""

    ip: str
    hostname: str | None = None
    #: Only *open* ports are materialised (memory stays flat on /16 × 65k runs).
    ports: list[PortResult] = field(default_factory=list)
    is_ipv6: bool = False
    closed_ports: int = 0
    filtered_ports: int = 0
    probed: int = 0
    #: First few non-fatal diagnostics for this host (capped).
    errors: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.is_open]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "is_ipv6": self.is_ipv6,
            "probed": self.probed,
            "closed_port_count": self.closed_ports,
            "filtered_port_count": self.filtered_ports,
            "open_port_count": len(self.open_ports),
            "ports": [p.to_dict() for p in self.ports],
            "errors": list(self.errors),
        }
