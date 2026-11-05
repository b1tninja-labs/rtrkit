"""endian-exact encode and decode, hostile input refusal (RFC 8210, RFC 6810).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Pdu = Any  # placeholder: give it a real type in the milestone that needs it
    PrefixRecord = Any  # placeholder: give it a real type in the milestone that needs it
    ResetQuery = Any  # placeholder: give it a real type in the milestone that needs it
    RouterKeyRecord = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode_pdu",
    "encode_ipv4_prefix_record",
    "encode_reset_query",
    "encode_router_key_record",
]


def decode_pdu(raw: bytes) -> Pdu:
    """Pending behaviour defined by RFC 8210.

    Not implemented yet. See the ``serialize.decode_pdu()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_pdu() is not implemented: RFC 8210")


def encode_reset_query(session_id: int) -> ResetQuery:
    """Pending behaviour defined by RFC 8210.

    Not implemented yet. See the ``serialize.encode_reset_query()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_reset_query() is not implemented: RFC 8210")


def encode_ipv4_prefix_record(prefix: str, asn: int, max_len: int, flags: int) -> PrefixRecord:
    """Pending behaviour defined by RFC 8210.

    Not implemented yet. See the ``serialize.encode_ipv4_prefix_record()`` row in
    ROADMAP.md; this stub raises on purpose so nothing downstream mistakes it for working
    code.
    """
    raise NotImplementedError("encode_ipv4_prefix_record() is not implemented: RFC 8210")


def encode_router_key_record(asn: int, ski: bytes, spki: bytes) -> RouterKeyRecord:
    """Pending behaviour defined by RFC 8210.

    Not implemented yet. See the ``serialize.encode_router_key_record()`` row in
    ROADMAP.md; this stub raises on purpose so nothing downstream mistakes it for working
    code.
    """
    raise NotImplementedError("encode_router_key_record() is not implemented: RFC 8210")
