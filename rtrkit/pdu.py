"""RTR PDU records and the error types the codec raises (RFC 8210, RFC 6810).

These are plain frozen values. Bytes are produced and parsed in :mod:`rtrkit.serialize`;
this module only names what a PDU is and which error code a refusal maps to.

PDU type numbers are RFC 8210 section 5.2 to 5.11 (the figure of each PDU states its
type). Type 5 is not assigned by RFC 8210. Error codes are RFC 8210 section 12.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

__all__ = [
    "VERSIONS",
    "CacheReset",
    "CacheResponse",
    "EndOfData",
    "ErrorCode",
    "ErrorReport",
    "Ipv4Prefix",
    "Ipv6Prefix",
    "NeedMore",
    "Pdu",
    "PduType",
    "ResetQuery",
    "RouterKey",
    "RtrError",
    "SerialNotify",
    "SerialQuery",
]

# RFC 8210 section 7: "neither 0 nor 1" is an unrecognized Protocol Version.
VERSIONS: frozenset[int] = frozenset({0, 1})


class PduType(IntEnum):
    """PDU Type octet (RFC 8210 sections 5.2 to 5.11)."""

    SERIAL_NOTIFY = 0
    SERIAL_QUERY = 1
    RESET_QUERY = 2
    CACHE_RESPONSE = 3
    IPV4_PREFIX = 4
    IPV6_PREFIX = 6
    END_OF_DATA = 7
    CACHE_RESET = 8
    ROUTER_KEY = 9
    ERROR_REPORT = 10


class ErrorCode(IntEnum):
    """Error codes of RFC 8210 section 12. Codes 0, 1, 3 to 8 are fatal; 2 is not."""

    CORRUPT_DATA = 0
    INTERNAL_ERROR = 1
    NO_DATA_AVAILABLE = 2
    INVALID_REQUEST = 3
    UNSUPPORTED_PROTOCOL_VERSION = 4
    UNSUPPORTED_PDU_TYPE = 5
    WITHDRAWAL_OF_UNKNOWN_RECORD = 6
    DUPLICATE_ANNOUNCEMENT = 7
    UNEXPECTED_PROTOCOL_VERSION = 8


class RtrError(ValueError):
    """A PDU the codec refuses. ``code`` is the RFC 8210 section 12 code to report it with."""

    def __init__(self, message: str, code: int = ErrorCode.CORRUPT_DATA) -> None:
        super().__init__(message)
        self.code = int(code)


class NeedMore(ValueError):  # noqa: N818 - a condition, not a fault
    """The buffer is a valid prefix of a PDU but ends early. Not corruption: read more.

    ``needed`` is the least total length, in bytes, the buffer must reach before decoding
    can make progress.
    """

    def __init__(self, needed: int) -> None:
        super().__init__(f"need at least {needed} bytes")
        self.needed = needed


@dataclass(frozen=True, slots=True)
class SerialNotify:
    version: int
    session_id: int
    serial: int


@dataclass(frozen=True, slots=True)
class SerialQuery:
    version: int
    session_id: int
    serial: int


@dataclass(frozen=True, slots=True)
class ResetQuery:
    version: int


@dataclass(frozen=True, slots=True)
class CacheResponse:
    version: int
    session_id: int


@dataclass(frozen=True, slots=True)
class Ipv4Prefix:
    version: int
    announce: bool
    prefix_len: int
    max_len: int
    prefix: IPv4Address
    asn: int


@dataclass(frozen=True, slots=True)
class Ipv6Prefix:
    version: int
    announce: bool
    prefix_len: int
    max_len: int
    prefix: IPv6Address
    asn: int


@dataclass(frozen=True, slots=True)
class EndOfData:
    """End of Data. The three timers exist only in version 1; they are ``None`` in version 0."""

    version: int
    session_id: int
    serial: int
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None


@dataclass(frozen=True, slots=True)
class CacheReset:
    version: int


@dataclass(frozen=True, slots=True)
class RouterKey:
    version: int
    announce: bool
    ski: bytes
    asn: int
    spki: bytes


@dataclass(frozen=True, slots=True)
class ErrorReport:
    version: int
    code: int
    erroneous_pdu: bytes
    text: str


Pdu = (
    SerialNotify
    | SerialQuery
    | ResetQuery
    | CacheResponse
    | Ipv4Prefix
    | Ipv6Prefix
    | EndOfData
    | CacheReset
    | RouterKey
    | ErrorReport
)
