"""Minimal, dependency-free ASN.1/DER certificate parser.

Python's :mod:`ssl` module can hand us the peer certificate as DER bytes
(``SSLSocket.getpeercert(binary_form=True)``), but only exposes the *dict* form
when verification is enabled — which is useless during reconnaissance, where
certificates are frequently self-signed, expired or name-mismatched.

Rather than pulling in ``cryptography`` (a compiled dependency that bloats the
Docker image), this module walks the DER structure directly. It supports exactly
what a scanner needs: subject/issuer RDNs, SANs, validity, serial number, key
type/size and signature algorithm.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field

# ASN.1 universal tags we care about
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_OID = 0x06
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31

_NAME_OIDS: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.17": "postalCode",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
}

_SIGNATURE_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.156.10197.1.501": "SM3withSM2",
}

_KEY_OIDS: dict[str, tuple[str, int | None]] = {
    "1.2.840.113549.1.1.1": ("RSA", None),
    "1.2.840.113549.1.1.10": ("RSASSA-PSS", None),
    "1.2.840.10045.2.1": ("EC", None),
    "1.3.101.112": ("Ed25519", 256),
    "1.3.101.113": ("Ed448", 456),
    "1.2.840.113549.1.1.7": ("DSA", None),
}

_CURVE_BITS: dict[str, int] = {
    "1.2.840.10045.3.1.7": 256,   # prime256v1 / secp256r1
    "1.3.132.0.34": 384,          # secp384r1
    "1.3.132.0.35": 521,          # secp521r1
    "1.3.132.0.10": 256,          # secp256k1
    "1.3.132.0.33": 224,          # secp224r1
}

_SAN_DNS, _SAN_IP, _SAN_EMAIL, _SAN_URI = 2, 7, 1, 6


class DERError(ValueError):
    """Raised when the DER structure cannot be decoded."""


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV triple and return ``(tag, value, next_offset)``."""
    if offset >= len(data):
        raise DERError("unexpected end of DER data")
    tag = data[offset]
    offset += 1
    # High-tag-number form is not used by X.509 fields we parse.
    if tag & 0x1F == 0x1F:
        while offset < len(data) and data[offset] & 0x80:
            offset += 1
        offset += 1
    if offset >= len(data):
        raise DERError("truncated length field")
    first = data[offset]
    offset += 1
    if first & 0x80:
        num_bytes = first & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            raise DERError("invalid long-form length")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    else:
        length = first
    if offset + length > len(data):
        raise DERError("length exceeds buffer")
    return tag, data[offset : offset + length], offset + length


def _children(data: bytes) -> list[tuple[int, bytes]]:
    """Split a constructed value into ``(tag, value)`` children."""
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _read_tlv(data, offset)
        items.append((tag, value))
    return items


def _decode_oid(raw: bytes) -> str:
    if not raw:
        raise DERError("empty OID")
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _decode_string(tag: int, raw: bytes) -> str:
    if tag in (0x0C,):  # UTF8String
        return raw.decode("utf-8", "replace")
    if tag in (0x13, 0x16, 0x14):  # PrintableString / IA5String / TeletexString
        return raw.decode("latin-1", "replace")
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", "replace")
    if tag == 0x1C:  # UniversalString
        return raw.decode("utf-32-be", "replace")
    if tag in (0x1B,):  # GeneralString
        return raw.decode("latin-1", "replace")
    return raw.decode("utf-8", "replace")


def _decode_time(tag: int, raw: bytes) -> _dt.datetime | None:
    text = raw.decode("ascii", "replace").strip()
    fmt: str | None = None
    if tag == _TAG_UTC_TIME:
        fmt = "%y%m%d%H%M%SZ" if text.endswith("Z") else "%y%m%d%H%M%S"
    elif tag == _TAG_GENERALIZED_TIME:
        if "." in text:
            text = text.split(".", 1)[0] + ("Z" if text.endswith("Z") else "")
        fmt = "%Y%m%d%H%M%SZ" if text.endswith("Z") else "%Y%m%d%H%M%S"
    if fmt is None:
        return None
    try:
        parsed = _dt.datetime.strptime(text, fmt)
    except ValueError:
        return None
    if fmt.startswith("%y") and parsed.year > 2050:  # RFC 5280: YY >= 50 -> 19YY
        parsed = parsed.replace(year=parsed.year - 100)
    return parsed.replace(tzinfo=_dt.timezone.utc)


def _parse_name(raw: bytes) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Return ``(first-value-per-attribute, ordered attribute list)``."""
    flat: list[tuple[str, str]] = []
    for tag, rdn_set in _children(raw):
        if tag != _TAG_SET:
            continue
        for atv_tag, atv in _children(rdn_set):
            if atv_tag != _TAG_SEQUENCE:
                continue
            parts = _children(atv)
            if len(parts) < 2:
                continue
            oid_tag, oid_raw = parts[0]
            if oid_tag != _TAG_OID:
                continue
            try:
                oid = _decode_oid(oid_raw)
            except DERError:
                continue
            name = _NAME_OIDS.get(oid, oid)
            value_tag, value_raw = parts[1]
            flat.append((name, _decode_string(value_tag, value_raw).strip()))

    summary: dict[str, str] = {}
    for name, value in flat:
        summary.setdefault(name, value)
    return summary, flat


def _parse_san(ext_value: bytes) -> list[str]:
    """Decode a SubjectAltName extension (OCTET STRING containing a SEQUENCE)."""
    try:
        tag, inner, _ = _read_tlv(ext_value, 0)
        if tag != _TAG_SEQUENCE:
            return []
        names: list[str] = []
        for gn_tag, gn_value in _children(inner):
            if gn_tag == (0x80 | _SAN_DNS) or gn_tag == 0x82:
                names.append(gn_value.decode("ascii", "replace"))
            elif gn_tag in (0x87,):  # context [7] iPAddress
                if len(gn_value) == 4:
                    names.append(".".join(str(b) for b in gn_value))
                elif len(gn_value) == 16:
                    import ipaddress

                    names.append(str(ipaddress.IPv6Address(gn_value)))
            elif gn_tag == 0x81 or gn_tag == 0x86:  # rfc822Name IA5
                names.append(gn_value.decode("ascii", "replace"))
        return names
    except (DERError, ValueError):
        return []


def _rdn_tuple(flat: list[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    return tuple(flat)


@dataclass(slots=True)
class Certificate:
    """Decoded certificate fields (all optional — malformed certs are common)."""

    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    subject_alt_names: list[str] = field(default_factory=list)
    not_before: _dt.datetime | None = None
    not_after: _dt.datetime | None = None
    serial: str | None = None
    signature_algorithm: str | None = None
    key_type: str | None = None
    key_bits: int | None = None
    sha256: str | None = None
    version: int = 3
    self_signed: bool = False

    @property
    def common_name(self) -> str | None:
        return self.subject.get("CN")

    @property
    def issuer_cn(self) -> str | None:
        return self.issuer.get("CN") or self.issuer.get("O")

    def days_remaining(self, now: _dt.datetime | None = None) -> int | None:
        if not self.not_after:
            return None
        now = now or _dt.datetime.now(_dt.timezone.utc)
        return (self.not_after - now).days

    @property
    def expired(self) -> bool | None:
        if not self.not_after:
            return None
        return self.not_after < _dt.datetime.now(_dt.timezone.utc)


def parse_certificate(der: bytes) -> Certificate:
    """Decode a DER encoded X.509 certificate."""
    cert = Certificate(sha256=hashlib.sha256(der).hexdigest())
    tag, body, _ = _read_tlv(der, 0)
    if tag != _TAG_SEQUENCE:
        raise DERError("certificate is not a SEQUENCE")

    top = _children(body)
    if len(top) < 3:
        raise DERError("certificate has too few fields")

    tbs_tag, tbs_raw = top[0]
    if tbs_tag != _TAG_SEQUENCE:
        raise DERError("tbsCertificate is not a SEQUENCE")
    sig_alg_tag, sig_alg_raw = top[1]
    if sig_alg_tag == _TAG_SEQUENCE:
        alg_parts = _children(sig_alg_raw)
        if alg_parts and alg_parts[0][0] == _TAG_OID:
            oid = _decode_oid(alg_parts[0][1])
            cert.signature_algorithm = _SIGNATURE_OIDS.get(oid, oid)

    tbs = _children(tbs_raw)
    index = 0
    if tbs and tbs[0][0] == 0xA0:  # [0] EXPLICIT version
        version_children = _children(tbs[0][1])
        if version_children and version_children[0][0] == _TAG_INTEGER:
            cert.version = int.from_bytes(version_children[0][1], "big") + 1
        index = 1
    if index < len(tbs) and tbs[index][0] == _TAG_INTEGER:
        serial = int.from_bytes(tbs[index][1], "big")
        cert.serial = format(serial, "X")
        index += 1
    index += 1  # signature AlgorithmIdentifier (duplicate of the outer one)
    if index < len(tbs) and tbs[index][0] == _TAG_SEQUENCE:
        cert.issuer, issuer_flat = _parse_name(tbs[index][1])
        index += 1
    else:
        issuer_flat = []
    if index < len(tbs) and tbs[index][0] == _TAG_SEQUENCE:  # validity
        validity = _children(tbs[index][1])
        if len(validity) >= 2:
            cert.not_before = _decode_time(validity[0][0], validity[0][1])
            cert.not_after = _decode_time(validity[1][0], validity[1][1])
        index += 1
    if index < len(tbs) and tbs[index][0] == _TAG_SEQUENCE:  # subject
        cert.subject, subject_flat = _parse_name(tbs[index][1])
        index += 1
    else:
        subject_flat = []
    if index < len(tbs) and tbs[index][0] == _TAG_SEQUENCE:  # subjectPublicKeyInfo
        spki = _children(tbs[index][1])
        if len(spki) >= 2 and spki[0][0] == _TAG_SEQUENCE:
            alg = _children(spki[0][1])
            if alg and alg[0][0] == _TAG_OID:
                key_oid = _decode_oid(alg[0][1])
                key_type, bits = _KEY_OIDS.get(key_oid, (key_oid, None))
                cert.key_type = key_type
                if len(alg) > 1 and alg[1][0] == _TAG_OID:
                    curve_oid = _decode_oid(alg[1][1])
                    bits = _CURVE_BITS.get(curve_oid, bits)
                if key_type == "RSA" and spki[1][0] == _TAG_BIT_STRING:
                    inner_tag, inner_raw, _ = _read_tlv(spki[1][1][1:], 0)
                    if inner_tag == _TAG_SEQUENCE:
                        rsa = _children(inner_raw)
                        if rsa and rsa[0][0] == _TAG_INTEGER:
                            bits = int.from_bytes(rsa[0][1], "big").bit_length()
                cert.key_bits = bits
        index += 1
    # [3] EXPLICIT Extensions: [3] -> SEQUENCE OF Extension -> Extension
    extension_seqs: list[bytes] = []
    for ext_tag, ext_value in tbs[index:]:
        if ext_tag != 0xA3:
            continue
        for inner_tag, inner in _children(ext_value):
            if inner_tag != _TAG_SEQUENCE:
                continue
            for maybe_ext_tag, maybe_ext in _children(inner):
                if maybe_ext_tag == _TAG_SEQUENCE:
                    extension_seqs.append(maybe_ext)

    for ext in extension_seqs:
        parts = _children(ext)
        if len(parts) < 2 or parts[0][0] != _TAG_OID:
            continue
        try:
            oid = _decode_oid(parts[0][1])
        except DERError:
            continue
        values = [p for p in parts[1:] if p[0] == _TAG_OCTET_STRING]
        if oid == "2.5.29.17" and values:  # subjectAltName
            cert.subject_alt_names = _parse_san(values[-1][1])

    cert.self_signed = bool(subject_flat) and _rdn_tuple(subject_flat) == _rdn_tuple(issuer_flat)
    return cert


def decode_pem(pem: bytes) -> bytes:
    """Convert a PEM certificate to DER (handy for tests and offline analysis)."""
    lines = [line.strip() for line in pem.decode("ascii", "ignore").splitlines()]
    body = [line for line in lines if line and not line.startswith("-----")]
    import base64

    return base64.b64decode("".join(body))
