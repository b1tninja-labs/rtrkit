"""rtrkit -- RPKI-to-Router protocol, both ends.

RTR is the only protocol between an RPKI cache and a router, and Python cannot speak it.
"""

from __future__ import annotations

from . import apps, cli, inject, pdu, serialize, session
from .inject import truncated_record
from .pdu import (
    CacheReset,
    CacheResponse,
    EndOfData,
    ErrorReport,
    Ipv4Prefix,
    Ipv6Prefix,
    NeedMore,
    ResetQuery,
    RouterKey,
    RtrError,
    SerialNotify,
    SerialQuery,
)
from .serialize import (
    decode_pdu,
    encode_cache_reset,
    encode_cache_response,
    encode_end_of_data,
    encode_error_report,
    encode_ipv4_prefix_record,
    encode_ipv6_prefix_record,
    encode_pdu,
    encode_reset_query,
    encode_router_key_record,
    encode_serial_notify,
    encode_serial_query,
)
from .session import connect, serve

__version__ = "0.1.0"

__all__ = [
    "CacheReset",
    "CacheResponse",
    "EndOfData",
    "ErrorReport",
    "Ipv4Prefix",
    "Ipv6Prefix",
    "NeedMore",
    "ResetQuery",
    "RouterKey",
    "RtrError",
    "SerialNotify",
    "SerialQuery",
    "__version__",
    "apps",
    "cli",
    "connect",
    "decode_pdu",
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
    "inject",
    "pdu",
    "serialize",
    "serve",
    "session",
    "truncated_record",
]
