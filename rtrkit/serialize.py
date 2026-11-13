"""Byte-exact encode and decode of RTR PDUs, with hostile input refused (RFC 8210, RFC 6810,
and version 2 per the draft pinned as ``rtrkit.pdu.DRAFT_8210BIS``).

Every PDU starts with the 8-octet header of RFC 8210 section 5.1: Protocol Version, PDU Type,
a 16-bit field (Session ID, Error Code, or zero), and a 32-bit Length that counts the whole
PDU including the header. Reserved fields are zero on transmission and ignored on receipt
(section 5), so the decoder never looks at them and every encoder writes zero.

``decode_pdu`` separates two failures that a stream reader must not confuse: a buffer that
is a valid beginning of a PDU (:class:`~rtrkit.pdu.NeedMore`) and bytes that can never be
a PDU (:class:`~rtrkit.pdu.RtrError`, carrying the RFC 8210 section 12 code to report).

Two limits are this library's own, not the RFC's: a PDU longer than ``MAX_PDU_LENGTH`` is
refused before any attempt to buffer it, and a Router Key SPKI must be one complete DER
SEQUENCE (RFC 8210 section 5.1 describes it as the full DER encoding).
"""

from __future__ import annotations

import ipaddress
import struct
from itertools import pairwise

from .pdu import (
    VERSIONS,
    Aspa,
    CacheReset,
    CacheResponse,
    EndOfData,
    ErrorCode,
    ErrorReport,
    Ipv4Prefix,
    Ipv6Prefix,
    NeedMore,
    Pdu,
    PduType,
    ResetQuery,
    RouterKey,
    RtrError,
    SerialNotify,
    SerialQuery,
)

__all__ = [
    "MAX_PDU_LENGTH",
    "decode_pdu",
    "encode_aspa",
    "encode_cache_reset",
    "encode_cache_response",
    "encode_end_of_data",
    "encode_error_report",
    "encode_ipv4_prefix_record",
    "encode_ipv6_prefix_record",
    "encode_pdu",
    "encode_reset_query",
    "encode_router_key_record",
    "encode_serial_notify",
    "encode_serial_query",
]

#: Own cap (not in the RFC): a longer PDU is refused as corrupt before it is buffered.
MAX_PDU_LENGTH = 65535

HEADER = struct.Struct(">BBHI")
_FIXED_LENGTH = {
    PduType.SERIAL_NOTIFY: 12,
    PduType.SERIAL_QUERY: 12,
    PduType.RESET_QUERY: 8,
    PduType.CACHE_RESPONSE: 8,
    PduType.IPV4_PREFIX: 20,
    PduType.IPV6_PREFIX: 32,
    PduType.CACHE_RESET: 8,
}
_SKI_LENGTH = 20
_KNOWN_TYPES = {int(t) for t in PduType}

# RFC 8210 section 6: allowed timer ranges, in seconds.
REFRESH_RANGE = (1, 86400)
RETRY_RANGE = (1, 7200)
EXPIRE_RANGE = (600, 172800)


def _unsigned(value: int, bits: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << bits:
        raise ValueError(f"{name} must be an unsigned {bits}-bit integer, got {value!r}")
    return value


def _version(version: int) -> int:
    if version not in VERSIONS:
        raise ValueError(f"protocol version must be 0, 1 or 2, got {version!r}")
    return version


def _der_sequence_is_complete(data: bytes) -> bool:
    """True when ``data`` is exactly one DER SEQUENCE: tag 0x30, definite length, no slack."""
    if len(data) < 2 or data[0] != 0x30:
        return False
    first = data[1]
    if first < 0x80:
        return len(data) == 2 + first
    count = first & 0x7F
    if count == 0 or count > 4 or len(data) < 2 + count:
        return False
    length = int.from_bytes(data[2 : 2 + count], "big")
    return length >= 0x80 and data[2] != 0 and len(data) == 2 + count + length


def _check_prefix(prefix_len: int, max_len: int, bits: int) -> None:
    if not 0 <= prefix_len <= bits or not 0 <= max_len <= bits:
        raise ValueError(f"prefix and max length must be within 0..{bits}")
    if max_len < prefix_len:
        raise ValueError("max length must not be less than prefix length (RFC 8210 section 5.1)")


def _check_timers(refresh: int, retry: int, expire: int) -> None:
    for name, value, (low, high) in (
        ("refresh", refresh, REFRESH_RANGE),
        ("retry", retry, RETRY_RANGE),
        ("expire", expire, EXPIRE_RANGE),
    ):
        if not low <= value <= high:
            raise ValueError(f"{name} interval {value} outside {low}..{high} (RFC 8210 section 6)")
    if expire <= refresh or expire <= retry:
        raise ValueError("expire must be larger than refresh and retry (RFC 8210 section 6)")


def encode_serial_notify(version: int, session_id: int, serial: int) -> bytes:
    """Serial Notify, RFC 8210 section 5.2: type 0, Length 12."""
    return HEADER.pack(
        _version(version), PduType.SERIAL_NOTIFY, _unsigned(session_id, 16, "session id"), 12
    ) + struct.pack(">I", _unsigned(serial, 32, "serial"))


def encode_serial_query(version: int, session_id: int, serial: int) -> bytes:
    """Serial Query, RFC 8210 section 5.3: type 1, Length 12."""
    return HEADER.pack(
        _version(version), PduType.SERIAL_QUERY, _unsigned(session_id, 16, "session id"), 12
    ) + struct.pack(">I", _unsigned(serial, 32, "serial"))


def encode_reset_query(version: int) -> bytes:
    """Reset Query, RFC 8210 section 5.4: type 2, Length 8, and no session (the field is zero).

    The first PDU a router sends carries the protocol version it implements (section 7), so
    the argument is that version, 0, 1 or 2.
    """
    return HEADER.pack(_version(version), PduType.RESET_QUERY, 0, 8)


def encode_cache_response(version: int, session_id: int) -> bytes:
    """Cache Response, RFC 8210 section 5.5: type 3, Length 8."""
    return HEADER.pack(
        _version(version), PduType.CACHE_RESPONSE, _unsigned(session_id, 16, "session id"), 8
    )


def encode_cache_reset(version: int) -> bytes:
    """Cache Reset, RFC 8210 section 5.9: type 8, Length 8."""
    return HEADER.pack(_version(version), PduType.CACHE_RESET, 0, 8)


def encode_ipv4_prefix_record(
    version: int, prefix: ipaddress.IPv4Network, asn: int, max_len: int, announce: bool
) -> bytes:
    """IPv4 Prefix, RFC 8210 section 5.6: type 4, Length 20.

    Flags bit 0 is 1 for an announcement and 0 for a withdrawal; the other flag bits and the
    trailing zero field are written as zero (sections 5 and 5.1).
    """
    _check_prefix(prefix.prefixlen, max_len, 32)
    return (
        HEADER.pack(_version(version), PduType.IPV4_PREFIX, 0, 20)
        + struct.pack(">BBBB", int(bool(announce)), prefix.prefixlen, max_len, 0)
        + prefix.network_address.packed
        + struct.pack(">I", _unsigned(asn, 32, "asn"))
    )


def encode_ipv6_prefix_record(
    version: int, prefix: ipaddress.IPv6Network, asn: int, max_len: int, announce: bool
) -> bytes:
    """IPv6 Prefix, RFC 8210 section 5.7: type 6, Length 32."""
    _check_prefix(prefix.prefixlen, max_len, 128)
    return (
        HEADER.pack(_version(version), PduType.IPV6_PREFIX, 0, 32)
        + struct.pack(">BBBB", int(bool(announce)), prefix.prefixlen, max_len, 0)
        + prefix.network_address.packed
        + struct.pack(">I", _unsigned(asn, 32, "asn"))
    )


def encode_end_of_data(
    version: int,
    session_id: int,
    serial: int,
    refresh: int | None = None,
    retry: int | None = None,
    expire: int | None = None,
) -> bytes:
    """End of Data: RFC 8210 section 5.8 (version 1, Length 24, three timers) or RFC 6810
    section 5.8 (version 0, Length 12, no timers). Version 2 is the same as version 1
    (draft-ietf-sidrops-8210bis section 5.7).

    Versions 1 and 2 require all three timers and checks them against the ranges of RFC 8210
    section 6. Version 0 has nowhere to put them and refuses them.
    """
    _version(version)
    head = _unsigned(session_id, 16, "session id"), _unsigned(serial, 32, "serial")
    if version == 0:
        if (refresh, retry, expire) != (None, None, None):
            raise ValueError("version 0 End of Data carries no timers (RFC 6810 section 5.8)")
        return HEADER.pack(0, PduType.END_OF_DATA, head[0], 12) + struct.pack(">I", head[1])
    if refresh is None or retry is None or expire is None:
        raise ValueError("End of Data in version 1 or 2 needs refresh, retry and expire")
    _check_timers(refresh, retry, expire)
    return HEADER.pack(version, PduType.END_OF_DATA, head[0], 24) + struct.pack(
        ">IIII", head[1], refresh, retry, expire
    )


def encode_router_key_record(
    version: int, asn: int, ski: bytes, spki: bytes, announce: bool
) -> bytes:
    """Router Key, RFC 8210 section 5.10: type 9, variable Length.

    Versions 1 and 2: the PDU type was added by RFC 8210 (section 1.2). ``ski`` is exactly 20
    octets; ``spki`` is the full DER SubjectPublicKeyInfo SEQUENCE (section 5.1), whose
    format RFC 8608 now defines (RFC 8210 cites RFC 8208, which RFC 8608 obsoletes).
    """
    if version not in (1, 2):
        raise ValueError("Router Key PDUs exist only in protocol version 1 or 2")
    if len(ski) != _SKI_LENGTH:
        raise ValueError("subject key identifier must be 20 octets")
    if not _der_sequence_is_complete(spki):
        raise ValueError("subjectPublicKeyInfo must be one complete DER SEQUENCE")
    length = 8 + _SKI_LENGTH + 4 + len(spki)
    if length > MAX_PDU_LENGTH:
        raise ValueError("Router Key PDU exceeds MAX_PDU_LENGTH")
    return (
        HEADER.pack(version, PduType.ROUTER_KEY, int(bool(announce)) << 8, length)
        + ski
        + struct.pack(">I", _unsigned(asn, 32, "asn"))
        + spki
    )


def check_aspa_providers(customer_asn: int, providers: tuple[int, ...], announce: bool) -> None:
    """Refuse a provider list the draft forbids, as ``ValueError`` (the decoder maps it to code 9).

    draft-ietf-sidrops-8210bis section 5.12: an announcement has at least one provider, in
    increasing numeric order, with no duplicates and no AS0 beside other providers; a
    withdrawal has none. (The customer ASN not appearing among its providers is a rule of
    draft-ietf-sidrops-aspa-profile section 3.3 for the signed object, not of the PDU, so it
    is not checked here.)
    """
    _unsigned(customer_asn, 32, "customer asn")
    if not announce:
        if providers:
            raise ValueError("an ASPA withdrawal carries no provider list")
        return
    if not providers:
        raise ValueError("an ASPA announcement needs at least one provider")
    for asn in providers:
        _unsigned(asn, 32, "provider asn")
    if any(a >= b for a, b in pairwise(providers)):
        raise ValueError("ASPA providers must be in increasing order without duplicates")
    if 0 in providers and len(providers) > 1:
        raise ValueError("AS0 must not appear alongside other ASPA providers")


def encode_aspa(
    version: int, customer_asn: int, providers: tuple[int, ...], announce: bool
) -> bytes:
    """ASPA, draft-ietf-sidrops-8210bis section 5.12: type 11, Length 12 + 4 per provider.

    Version 2 only. Flags bit 0 is the announce flag; a withdrawal has Length 12.
    """
    if version != 2:
        raise ValueError("ASPA PDUs exist only in protocol version 2")
    providers = tuple(providers)
    check_aspa_providers(customer_asn, providers, announce)
    length = 12 + 4 * len(providers)
    if length > MAX_PDU_LENGTH:
        raise ValueError("ASPA PDU exceeds MAX_PDU_LENGTH")
    return (
        HEADER.pack(2, PduType.ASPA, int(bool(announce)) << 8, length)
        + struct.pack(">I", customer_asn)
        + b"".join(struct.pack(">I", p) for p in providers)
    )


def encode_error_report(
    version: int, code: int, erroneous_pdu: bytes = b"", text: str = ""
) -> bytes:
    """Error Report, RFC 8210 section 5.11: type 10, variable Length.

    Refuses to encapsulate an Error Report (an Error Report MUST NOT be sent for one,
    section 5.11). The text is UTF-8; empty text writes a zero Length of Error Text.

    Section 12 of draft-ietf-sidrops-8210bis says errors are sent only with codes defined by the
    specification of the session's version, so codes 9 to 13 are refused below version 2.
    """
    if version < 2 and ErrorCode.ASPA_PROVIDER_LIST_ERROR <= code <= ErrorCode.CACHE_SHUTDOWN:
        raise ValueError(f"error code {code} exists only in protocol version 2")
    if len(erroneous_pdu) >= 2 and erroneous_pdu[1] == PduType.ERROR_REPORT:
        raise ValueError("an Error Report must not be sent for an Error Report (RFC 8210 5.11)")
    body_text = text.encode("utf-8")
    length = 8 + 4 + len(erroneous_pdu) + 4 + len(body_text)
    if length > MAX_PDU_LENGTH:
        raise ValueError("Error Report exceeds MAX_PDU_LENGTH")
    return (
        HEADER.pack(_version(version), PduType.ERROR_REPORT, _unsigned(code, 16, "code"), length)
        + struct.pack(">I", len(erroneous_pdu))
        + erroneous_pdu
        + struct.pack(">I", len(body_text))
        + body_text
    )


def encode_pdu(pdu: Pdu) -> bytes:
    """Encode any PDU record from :mod:`rtrkit.pdu` (RFC 8210 section 5)."""
    match pdu:
        case SerialNotify():
            return encode_serial_notify(pdu.version, pdu.session_id, pdu.serial)
        case SerialQuery():
            return encode_serial_query(pdu.version, pdu.session_id, pdu.serial)
        case ResetQuery():
            return encode_reset_query(pdu.version)
        case CacheResponse():
            return encode_cache_response(pdu.version, pdu.session_id)
        case Ipv4Prefix():
            net = ipaddress.IPv4Network((pdu.prefix, pdu.prefix_len), strict=False)
            return encode_ipv4_prefix_record(pdu.version, net, pdu.asn, pdu.max_len, pdu.announce)
        case Ipv6Prefix():
            net6 = ipaddress.IPv6Network((pdu.prefix, pdu.prefix_len), strict=False)
            return encode_ipv6_prefix_record(pdu.version, net6, pdu.asn, pdu.max_len, pdu.announce)
        case EndOfData():
            return encode_end_of_data(
                pdu.version, pdu.session_id, pdu.serial, pdu.refresh, pdu.retry, pdu.expire
            )
        case CacheReset():
            return encode_cache_reset(pdu.version)
        case RouterKey():
            return encode_router_key_record(pdu.version, pdu.asn, pdu.ski, pdu.spki, pdu.announce)
        case Aspa():
            return encode_aspa(pdu.version, pdu.customer_asn, pdu.providers, pdu.announce)
        case ErrorReport():
            return encode_error_report(pdu.version, pdu.code, pdu.erroneous_pdu, pdu.text)
    raise TypeError(f"not a PDU: {pdu!r}")


def decode_pdu(raw: bytes) -> tuple[Pdu, int]:
    """Decode the first PDU in ``raw`` and return it with the number of bytes it used
    (RFC 8210 section 5, RFC 6810 section 5).

    Raises :class:`~rtrkit.pdu.NeedMore` when ``raw`` is a valid beginning that ends early,
    and :class:`~rtrkit.pdu.RtrError` (with the section 12 code) for anything that can never
    be a PDU: version other than 0, 1 or 2 (code 4), unassigned type, Router Key in version 0
    or ASPA before version 2 (code 5), a bad ASPA provider list (code 9), and a length,
    prefix, timer-shape, SPKI or UTF-8 violation (code 0). Never
    returns a partial record. Reserved flag bits and zero fields are ignored (section 5).
    """
    if len(raw) < 8:
        raise NeedMore(8)
    version, ptype, field, length = HEADER.unpack_from(raw)
    if version not in VERSIONS:
        raise RtrError(
            f"unknown protocol version {version}", ErrorCode.UNSUPPORTED_PROTOCOL_VERSION
        )
    if (
        ptype not in _KNOWN_TYPES
        or (ptype == PduType.ROUTER_KEY and version == 0)
        or (ptype == PduType.ASPA and version < 2)
    ):
        raise RtrError(f"unsupported PDU type {ptype}", ErrorCode.UNSUPPORTED_PDU_TYPE)
    kind = PduType(ptype)
    want = _FIXED_LENGTH.get(kind)
    if kind is PduType.END_OF_DATA:
        want = 12 if version == 0 else 24
    if length < 8 or length > MAX_PDU_LENGTH:
        raise RtrError(f"PDU length {length} out of range")
    if want is not None and length != want:
        raise RtrError(f"{kind.name} has length {length}, expected {want}")
    if kind is PduType.ASPA and (length < 12 or (length - 12) % 4):
        raise RtrError(f"ASPA length {length} is not 12 plus a whole number of providers")
    if length < 8 + 4 + 4 and kind is PduType.ERROR_REPORT:
        raise RtrError("Error Report shorter than its fixed fields")
    if kind is PduType.ROUTER_KEY and length < 8 + _SKI_LENGTH + 4 + 2:
        raise RtrError("Router Key shorter than its fixed fields")
    if len(raw) < length:
        raise NeedMore(length)
    body = bytes(raw[8:length])
    return _decode_body(kind, version, field, body), length


def _decode_body(kind: PduType, version: int, field: int, body: bytes) -> Pdu:
    match kind:
        case PduType.SERIAL_NOTIFY:
            return SerialNotify(version, field, struct.unpack(">I", body)[0])
        case PduType.SERIAL_QUERY:
            return SerialQuery(version, field, struct.unpack(">I", body)[0])
        case PduType.RESET_QUERY:
            return ResetQuery(version)
        case PduType.CACHE_RESPONSE:
            return CacheResponse(version, field)
        case PduType.CACHE_RESET:
            return CacheReset(version)
        case PduType.IPV4_PREFIX | PduType.IPV6_PREFIX:
            return _decode_prefix(kind, version, body)
        case PduType.END_OF_DATA:
            if version == 0:
                return EndOfData(0, field, struct.unpack(">I", body)[0])
            serial, refresh, retry, expire = struct.unpack(">IIII", body)
            return EndOfData(version, field, serial, refresh, retry, expire)
        case PduType.ROUTER_KEY:
            ski = body[:_SKI_LENGTH]
            (asn,) = struct.unpack(">I", body[_SKI_LENGTH : _SKI_LENGTH + 4])
            spki = body[_SKI_LENGTH + 4 :]
            if not _der_sequence_is_complete(spki):
                raise RtrError("Router Key subjectPublicKeyInfo is not one DER SEQUENCE")
            return RouterKey(version, bool(field >> 8 & 1), ski, asn, spki)
        case PduType.ERROR_REPORT:
            return _decode_error_report(version, field, body)
        case PduType.ASPA:
            return _decode_aspa(version, field, body)
    raise RtrError(f"unsupported PDU type {int(kind)}", ErrorCode.UNSUPPORTED_PDU_TYPE)


def _decode_aspa(version: int, field: int, body: bytes) -> Aspa:
    announce = bool(field >> 8 & 1)
    (customer,) = struct.unpack_from(">I", body)
    count = (len(body) - 4) // 4
    providers = struct.unpack(f">{count}I", body[4:])
    try:
        check_aspa_providers(customer, providers, announce)
    except ValueError as error:
        raise RtrError(str(error), ErrorCode.ASPA_PROVIDER_LIST_ERROR) from error
    return Aspa(version, announce, customer, providers)


def _decode_prefix(kind: PduType, version: int, body: bytes) -> Pdu:
    flags, prefix_len, max_len, _zero = body[:4]
    bits = 32 if kind is PduType.IPV4_PREFIX else 128
    addr = body[4 : 4 + bits // 8]
    (asn,) = struct.unpack(">I", body[4 + bits // 8 :])
    if prefix_len > bits or max_len > bits:
        raise RtrError(f"prefix length {prefix_len} or max length {max_len} exceeds {bits}")
    if max_len < prefix_len:
        raise RtrError("max length is less than prefix length")
    announce = bool(flags & 1)
    if kind is PduType.IPV4_PREFIX:
        return Ipv4Prefix(version, announce, prefix_len, max_len, ipaddress.IPv4Address(addr), asn)
    return Ipv6Prefix(version, announce, prefix_len, max_len, ipaddress.IPv6Address(addr), asn)


def _decode_error_report(version: int, code: int, body: bytes) -> ErrorReport:
    (enc_len,) = struct.unpack_from(">I", body)
    if 4 + enc_len + 4 > len(body):
        raise RtrError("Error Report encapsulated PDU length overruns the PDU")
    erroneous = body[4 : 4 + enc_len]
    (text_len,) = struct.unpack_from(">I", body, 4 + enc_len)
    text_raw = body[8 + enc_len :]
    if len(text_raw) != text_len:
        raise RtrError("Error Report text length does not match the PDU length")
    try:
        text = text_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RtrError("Error Report text is not UTF-8") from error
    return ErrorReport(version, code, erroneous, text)
