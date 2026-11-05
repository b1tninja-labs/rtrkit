"""rtrkit -- RPKI-to-Router protocol, both ends.

RTR is the only protocol between an RPKI cache and a router, and Python cannot speak it.
"""

from __future__ import annotations

from . import apps, cli, inject, pdu, serialize, session
from .inject import truncated_record
from .serialize import (
    decode_pdu,
    encode_ipv4_prefix_record,
    encode_reset_query,
    encode_router_key_record,
)
from .session import connect, serve

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "apps",
    "cli",
    "connect",
    "decode_pdu",
    "encode_ipv4_prefix_record",
    "encode_reset_query",
    "encode_router_key_record",
    "inject",
    "pdu",
    "serialize",
    "serve",
    "session",
    "truncated_record",
]
