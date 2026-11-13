"""RTR PDU records and the error types the codec raises (RFC 8210, RFC 6810, and version 2 per
the pinned draft).

These are plain frozen values. Bytes are produced and parsed in :mod:`rtrkit.serialize`;
this module only names what a PDU is and which error code a refusal maps to.

PDU type numbers are RFC 8210 section 5.2 to 5.11 (the figure of each PDU states its
type). Type 5 is not assigned by RFC 8210. Error codes are RFC 8210 section 12.

Version 2 and the ASPA PDU (type 11) are not an RFC. They follow
``draft-ietf-sidrops-8210bis`` at the revision in :data:`DRAFT_8210BIS` (PDU type 11 is its
section 5.12, error codes 9 to 13 its section 12), with the ASPA content rules of
:data:`DRAFT_ASPA_PROFILE`. A later revision may move any of it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

__all__ = [
    "DRAFT_8210BIS",
    "DRAFT_ASPA_PROFILE",
    "EXPIRE_RANGE",
    "FATAL_ERRORS",
    "REFRESH_RANGE",
    "RETRY_RANGE",
    "VERSIONS",
    "Aspa",
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

#: The draft revision version 2 and the ASPA PDU are implemented from (read raw from
#: ietf.org/archive/id, 2026-11-13). Re-read before trusting any version-2 byte.
DRAFT_8210BIS = "draft-ietf-sidrops-8210bis-29"
#: The draft whose section 3.3 gives the ASPA provider-list constraints.
DRAFT_ASPA_PROFILE = "draft-ietf-sidrops-aspa-profile-31"

# RFC 8210 section 7 names 0 and 1; draft-ietf-sidrops-8210bis section 5.1 makes 2 current.
VERSIONS: frozenset[int] = frozenset({0, 1, 2})


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
    ASPA = 11  # version 2 only: draft-ietf-sidrops-8210bis section 5.12


class ErrorCode(IntEnum):
    """Error codes of RFC 8210 section 12 (0 to 8) and draft-ietf-sidrops-8210bis section 12 (9 to 13).

    Fatal: 0, 1, 3, 5 to 11 and 13. Not fatal: 2, 4 and 12 (see :data:`FATAL_ERRORS`).
    """

    CORRUPT_DATA = 0
    INTERNAL_ERROR = 1
    NO_DATA_AVAILABLE = 2
    INVALID_REQUEST = 3
    UNSUPPORTED_PROTOCOL_VERSION = 4
    UNSUPPORTED_PDU_TYPE = 5
    WITHDRAWAL_OF_UNKNOWN_RECORD = 6
    DUPLICATE_ANNOUNCEMENT = 7
    UNEXPECTED_PROTOCOL_VERSION = 8
    ASPA_PROVIDER_LIST_ERROR = 9
    TRANSPORT_FAILURE = 10
    ORDERING_ERROR = 11
    CACHE_RESTART = 12
    CACHE_SHUTDOWN = 13


#: Codes the draft marks fatal: the session is dropped and a router flushes the cache's data.
FATAL_ERRORS: frozenset[int] = frozenset({0, 1, 3, 5, 6, 7, 8, 9, 10, 11, 13})


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


# RFC 8210 section 6: allowed timer ranges, in seconds.
REFRESH_RANGE = (1, 86400)
RETRY_RANGE = (1, 7200)
EXPIRE_RANGE = (600, 172800)


@dataclass(frozen=True, slots=True)
class EndOfData:
    """End of Data. The three timers exist only in version 1; they are ``None`` in version 0.

    The decoder keeps timers exactly as sent, even outside the section 6 ranges (what a router
    does with them is not specified), and :attr:`timer_defects` is where it flags them.
    """

    version: int
    session_id: int
    serial: int
    refresh: int | None = None
    retry: int | None = None
    expire: int | None = None

    @property
    def timer_defects(self) -> tuple[str, ...]:
        """Which timers break section 6, by name: ``refresh``, ``retry``, ``expire`` for a value
        outside its range, ``expire-order`` when Expire is not larger than Refresh and Retry.
        Empty for a version 0 PDU (no timers) and for a conforming one."""
        if self.refresh is None or self.retry is None or self.expire is None:
            return ()
        found = [
            name
            for name, value, (low, high) in (
                ("refresh", self.refresh, REFRESH_RANGE),
                ("retry", self.retry, RETRY_RANGE),
                ("expire", self.expire, EXPIRE_RANGE),
            )
            if not low <= value <= high
        ]
        if self.expire <= self.refresh or self.expire <= self.retry:
            found.append("expire-order")
        return tuple(found)


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
class Aspa:
    """ASPA (version 2 only). ``providers`` is empty exactly for a withdrawal."""

    version: int
    announce: bool
    customer_asn: int
    providers: tuple[int, ...]


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
    | Aspa
)
