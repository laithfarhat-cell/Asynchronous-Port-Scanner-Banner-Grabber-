"""Target, hostname and port specification parsing.

The parser turns user supplied strings into concrete ``(ip, port)`` work units:

* single IPv4 / IPv6 addresses
* DNS hostnames (resolved concurrently, A **and** AAAA records)
* CIDR networks (expanded with :mod:`ipaddress`)
* newline separated target files (``-iL targets.txt``)
* port lists (``22,80,443``), ranges (``1-1024``), presets (``--top-ports 1000``)

Everything is validated *before* the scan starts so a typo cannot silently
turn into an empty (or enormous) scan.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import socket
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .paths import data_dir, data_file

MAX_PORT = 65535
MIN_PORT = 1

#: Hard default guard so a fat-fingered ``0.0.0.0/0`` cannot start a scan.
DEFAULT_MAX_HOSTS = 65536
DEFAULT_MAX_PORTS = MAX_PORT

_DEFAULT_TOP_PORTS = {
    100: (
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
        49152, 49153, 49154, 49155, 49156, 49157,
    ),
    1000: (),
}


class TargetParseError(ValueError):
    """Raised when a target specification cannot be understood."""


class PortParseError(ValueError):
    """Raised when a port specification cannot be understood."""


@dataclass(slots=True)
class Target:
    """A single scannable host."""

    ip: str
    hostname: str | None = None
    raw: str | None = None
    is_ipv6: bool = False

    @property
    def display(self) -> str:
        if self.hostname and self.hostname != self.ip:
            return f"{self.hostname} ({self.ip})" if not self.is_ipv6 else f"{self.hostname} ([{self.ip}])"
        return f"[{self.ip}]" if self.is_ipv6 else self.ip

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "is_ipv6": self.is_ipv6,
            "input": self.raw,
        }


@dataclass(slots=True)
class ParseReport:
    """Diagnostics collected while building the scan plan."""

    targets: list[Target] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    duplicates_skipped: int = 0
    truncated: bool = False


# --------------------------------------------------------------------------- #
# Port specifications
# --------------------------------------------------------------------------- #
def _data_dir() -> Path:
    return data_dir()


def load_top_ports(count: int = 100) -> list[int]:
    """Return the *count* most common TCP ports (100 or 1000 preset).

    The presets live in ``data/top_ports.json`` so they can be edited without
    touching code; a bundled fallback keeps the tool working from a bare
    checkout or a zipapp.
    """
    if count not in (100, 1000):
        raise PortParseError(f"unsupported --top-ports preset: {count} (use 100 or 1000)")

    path = data_file("top_ports.json") or (_data_dir() / "top_ports.json")
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            ports = payload.get(str(count)) or payload.get(count)
            if ports:
                return sorted({int(p) for p in ports if MIN_PORT <= int(p) <= MAX_PORT})
        except (OSError, ValueError, TypeError):
            pass  # fall back to the embedded list

    return _fallback_preset(count)


def _expand_part(part: str) -> Iterator[int]:
    part = part.strip()
    if not part:
        return
    if "-" in part:
        start_s, _, end_s = part.partition("-")
        try:
            start, end = int(start_s), int(end_s)
        except ValueError as exc:  # pragma: no cover - defensive
            raise PortParseError(f"invalid port range: {part!r}") from exc
        if start > end:
            start, end = end, start
        for port in range(start, end + 1):
            if not MIN_PORT <= port <= MAX_PORT:
                raise PortParseError(f"port out of range in {part!r} (1-{MAX_PORT})")
            yield port
        return
    try:
        port = int(part)
    except ValueError as exc:
        raise PortParseError(f"invalid port: {part!r}") from exc
    if not MIN_PORT <= port <= MAX_PORT:
        raise PortParseError(f"port out of range: {port} (1-{MAX_PORT})")
    yield port


def parse_ports(
    spec: str | None = None,
    top_ports: int | None = None,
    *,
    max_ports: int = DEFAULT_MAX_PORTS,
) -> list[int]:
    """Resolve a port specification into a sorted, de-duplicated list.

    >>> parse_ports("22,80,443")
    [22, 80, 443]
    >>> parse_ports("1-3")[0]
    1
    >>> parse_ports(top_ports=100)[:3]
    [7, 9, 13]
    """
    if spec is None and top_ports is None:
        raise PortParseError("no ports selected: pass -p/--ports or --top-ports")

    ports: set[int] = set()
    if top_ports is not None:
        ports.update(load_top_ports(top_ports))

    if spec:
        lowered = spec.strip().lower()
        if lowered in {"all", "full", "-"}:
            ports.update(range(MIN_PORT, MAX_PORT + 1))
        else:
            for chunk in spec.replace(" ", ",").split(","):
                ports.update(_expand_part(chunk))

    ordered = sorted(ports)
    if not ordered:
        raise PortParseError("port specification resolved to an empty set")
    if max_ports and len(ordered) > max_ports:
        raise PortParseError(
            f"requested {len(ordered)} ports which exceeds --max-ports={max_ports}"
        )
    return ordered


def shuffle_ports(ports: Sequence[int], seed: int | None = None) -> list[int]:
    """Shuffle port order; useful to avoid predictable scan fingerprints."""
    shuffled = list(ports)
    random.Random(seed).shuffle(shuffled)
    return shuffled


# --------------------------------------------------------------------------- #
# Target specifications
# --------------------------------------------------------------------------- #
def _is_ip(text: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _iter_network(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Iterator[str]:
    if network.version == 4:
        # ``hosts()`` already drops network/broadcast for prefix <= 30.
        for host in network.hosts():
            yield str(host)
        return
    # IPv6 networks are usually small (/64 is not scannable anyway); expand the
    # usable addresses without materialising the whole range.
    if network.prefixlen >= 127:
        for host in network:
            yield str(host)
        return
    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1
    for value in range(first, last + 1):
        yield str(ipaddress.IPv6Address(value))


def network_host_count(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
    """Number of scannable addresses in *network* (used for early guard rails)."""
    total = network.num_addresses
    if total <= 2:
        return total
    return total - 2


async def resolve_hostname(
    host: str,
    *,
    timeout: float = 5.0,
    family: int = socket.AF_UNSPEC,
    semaphore: asyncio.Semaphore | None = None,
) -> list[str]:
    """Resolve *host* to a de-duplicated list of IP addresses (A + AAAA).

    Resolution runs in the default executor (``getaddrinfo`` is blocking) and is
    bounded by *timeout*; a semaphore prevents a large ``-iL`` file from opening
    thousands of resolver threads at once.
    """
    loop = asyncio.get_running_loop()
    sem = semaphore or asyncio.Semaphore(50)

    async def _query() -> list[tuple]:
        return await loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)

    async with sem:
        infos = await asyncio.wait_for(_query(), timeout=timeout)

    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        addr = addr.split("%", 1)[0]  # strip IPv6 zone index
        if addr not in addresses:
            addresses.append(addr)
    return addresses


def _read_target_file(path: str) -> list[str]:
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        raise TargetParseError(f"target file not found: {path}")
    raw_lines: list[str] = []
    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Allow "target -p 80" style input files and inline comments.
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            raw_lines.append(line.split()[0])
    return raw_lines


def _parse_hostspec(text: str) -> tuple[str, str | None]:
    """Split ``host`` / ``host:port`` / ``[v6]:port`` into (host, port-or-None)."""
    text = text.strip()
    if not text:
        raise TargetParseError("empty target")
    if text.startswith("["):  # [::1] or [::1]:8080
        host, _, rest = text[1].partition("]")
        if rest.startswith(":"):
            return host, rest[1:]
        return f"[{host}]", None
    if text.count(":") == 1:  # host:port (IPv4 / hostname only)
        host, _, maybe_port = text.partition(":")
        if maybe_port.isdigit():
            return host, maybe_port
    return text, None


async def build_targets(
    targets: Sequence[str] = (),
    input_lists: Sequence[str] = (),
    *,
    resolve_dns: bool = True,
    dns_timeout: float = 5.0,
    dns_concurrency: int = 50,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    dedupe: bool = True,
) -> ParseReport:
    """Expand every target source into a concrete, de-duplicated host list."""
    report = ParseReport()
    raw_entries: list[str] = []
    for target in targets:
        raw_entries.extend(part for part in str(target).strip().split(",") if part.strip())
    for list_path in input_lists:
        raw_entries.extend(_read_target_file(list_path))

    if not raw_entries:
        raise TargetParseError("no targets supplied (use -t/--target and/or -iL/--input-list)")

    pending_hostnames: dict[str, list[int]] = {}
    seen: set[str] = set()
    slot_refs: list[tuple[int, str]] = []  # (index in report.targets, raw input)

    for raw in raw_entries:
        hostspec, inline_port = _parse_hostspec(raw)
        if inline_port:
            report.warnings.append(
                f"{raw!r}: inline port ignored (ports are selected with -p/--ports)"
            )

        address = _is_ip(hostspec)
        if address is not None:
            ip_text = str(address)
            if dedupe and ip_text in seen:
                report.duplicates_skipped += 1
                continue
            seen.add(ip_text)
            report.targets.append(
                Target(ip=ip_text, hostname=None, raw=raw, is_ipv6=address.version == 6)
            )
            continue

        if "/" in hostspec:
            try:
                network = ipaddress.ip_network(hostspec, strict=False)
            except ValueError as exc:
                raise TargetParseError(f"invalid CIDR network {hostspec!r}: {exc}") from exc
            count = network_host_count(network)
            remaining = max_hosts - len(report.targets) if max_hosts else count
            if max_hosts and count > remaining:
                report.warnings.append(
                    f"{network} contains {count} addresses; truncated to {max(remaining, 0)} "
                    f"(--max-hosts={max_hosts})"
                )
                report.truncated = True
            emitted = 0
            for host_ip in _iter_network(network):
                if max_hosts and len(report.targets) >= max_hosts:
                    report.truncated = True
                    break
                if dedupe and host_ip in seen:
                    report.duplicates_skipped += 1
                    continue
                seen.add(host_ip)
                report.targets.append(
                    Target(ip=host_ip, hostname=None, raw=str(network), is_ipv6=network.version == 6)
                )
                emitted += 1
            if emitted == 0:
                report.warnings.append(f"{network} expanded to zero usable addresses")
            continue

        # Hostname (resolve later, concurrently)
        key = hostspec.lower().rstrip(".")
        if key in pending_hostnames:
            report.duplicates_skipped += 1
            continue
        if dedupe and key in seen:
            report.duplicates_skipped += 1
            continue
        seen.add(key)
        pending_hostnames[key] = []
        slot_refs.append((len(report.targets), key))
        report.targets.append(Target(ip=key, hostname=key, raw=raw))

        total = len(report.targets) + len(pending_hostnames)
        if max_hosts and total > max_hosts:
            raise TargetParseError(f"target set exceeds --max-hosts={max_hosts}")

    if pending_hostnames:
        if not resolve_dns:
            for index, key in slot_refs:
                report.targets[index].ip = key
        else:
            sem = asyncio.Semaphore(max(1, dns_concurrency))
            keys = list(pending_hostnames)

            async def _resolve_one(key: str) -> tuple[str, list[str], str | None]:
                try:
                    addrs = await resolve_hostname(key, timeout=dns_timeout, semaphore=sem)
                    if not addrs:
                        return key, [], "no A/AAAA records"
                    return key, addrs, None
                except asyncio.TimeoutError:
                    return key, [], f"DNS timeout after {dns_timeout:g}s"
                except socket.gaierror as exc:
                    return key, [], f"DNS error: {exc}"
                except (OSError, UnicodeError) as exc:  # pragma: no cover - environment specific
                    return key, [], f"resolution failed: {exc}"

            results = await asyncio.gather(*(_resolve_one(k) for k in keys))
            slot_map = {key: index for index, key in slot_refs}
            replacements: list[tuple[int, Target]] = []
            for key, addrs, error in results:
                index = slot_map[key]
                if error:
                    report.unresolved.append(f"{key}: {error}")
                    report.targets[index].ip = key  # keep, scanner will skip it
                    continue
                for position, addr in enumerate(addrs):
                    parsed = _is_ip(addr)
                    target = Target(
                        ip=addr,
                        hostname=key,
                        raw=report.targets[index].raw,
                        is_ipv6=bool(parsed and parsed.version == 6),
                    )
                    if position == 0:
                        replacements.append((index, target))
                    else:
                        replacements.append((len(report.targets), target))

            # Apply replacements without disturbing the CIDR/IP order.
            hostname_indexes = {index for index, _ in slot_refs}
            rebuilt: list[Target] = []
            pending_replacements = dict(replacements)
            extra: list[Target] = []
            for index, target in enumerate(report.targets):
                if index in hostname_indexes:
                    new_target = pending_replacements.get(index)
                    if new_target is None or new_target.ip == target.hostname:
                        continue  # unresolved -> drop from the scan
                    rebuilt.append(new_target)
                else:
                    rebuilt.append(target)
            for index, target in replacements:
                if index >= len(report.targets):
                    extra.append(target)
            rebuilt.extend(extra)
            report.targets = rebuilt

    # Final de-duplication of resolved IPs (two hostnames may share an IP).
    if dedupe:
        unique: list[Target] = []
        final_seen: set[str] = set()
        for target in report.targets:
            if target.ip in final_seen:
                report.duplicates_skipped += 1
                continue
            final_seen.add(target.ip)
            unique.append(target)
        report.targets = unique

    if not report.targets:
        detail = ""
        if report.unresolved:
            detail = " (" + "; ".join(report.unresolved[:5]) + ")"
        raise TargetParseError(f"target resolution produced no scannable hosts{detail}")

    return report


def summarize_plan(targets: Iterable[Target], ports: Sequence[int]) -> str:
    """Human readable plan summary, e.g. ``12 hosts x 1000 ports = 12,000 probes``."""
    host_count = len(list(targets))
    return f"{host_count:,} hosts x {len(ports):,} ports = {host_count * len(ports):,} probes"


# --------------------------------------------------------------------------- #
# Embedded port presets
# --------------------------------------------------------------------------- #
#: ``--top-ports 100`` — the most frequently exposed TCP ports in the wild
#: (roughly Nmap's frequency ordering, trimmed to 100 entries).
_TOP_HIGH_PORTS: tuple[int, ...] = (
    1080, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2222, 2375, 2376, 3000, 3128, 3260, 3306, 3389, 4443, 4444, 4505,
    4506, 5000, 5060, 5432, 5555, 5601, 5672, 5671, 5800, 5900, 5901, 5984,
    6000, 6379, 6443, 7001, 7002, 7077, 8000, 8008, 8009, 8069, 8080, 8081,
    8082, 8088, 8090, 8161, 8180, 8200, 8443, 8500, 8888, 8983, 9000, 9001,
    9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250,
    11211, 15672, 27017, 27018, 50000, 50070,
)

#: ``--top-ports 1000`` — exactly 1000 ports: the curated set above plus the
#: lowest well-known ports as filler. Deterministic and documented so that two
#: runs (or two analysts) always scan the same surface.
def _build_top_1000() -> tuple[int, ...]:
    curated = set(_DEFAULT_TOP_PORTS[100]) | set(_TOP_HIGH_PORTS)
    filler = (port for port in range(MIN_PORT, 1025) if port not in curated)
    while len(curated) < 1000:
        try:
            curated.add(next(filler))
        except StopIteration:  # pragma: no cover - 1024 candidates always suffice
            break
    return tuple(sorted(curated))


_TOP_1000: tuple[int, ...] = _build_top_1000()


def _fallback_preset(count: int) -> list[int]:
    return sorted(_DEFAULT_TOP_PORTS[100]) if count == 100 else list(_TOP_1000)
