"""The payload a router holds from one cache: applying PDUs and the cache-side ordering.

Sans-IO: nothing here reads a socket or a clock. A :class:`PayloadDb` is the set of records
one cache has announced to a router (RFC 8210 sections 5.1, 5.6, 5.7 and 5.10; for ASPA,
draft-ietf-sidrops-8210bis section 5.12, pinned as ``rtrkit.pdu.DRAFT_8210BIS``).

Application rules, each from the section named:

* an announcement of a prefix or router key already active is Duplicate Announcement
  Received (code 7); a withdrawal of one that is not held is Withdrawal of Unknown Record
  (code 6). The draft's section 12 says a party SHOULD send these and may "opt simply to
  ignore the relevant PDU"; this database refuses, because a caller can always catch the
  error and ignore it, and cannot recover a duplicate that was silently absorbed.
* a prefix record is identified by {Prefix, Prefix Length, Max Length, ASN}, a router key by
  {SKI, ASN, Subject Public Key}: the SKI alone is not enough (section 5.11 of the draft).
* an ASPA announcement for a customer already held *replaces* the provider set; it is never a
  duplicate. An ASPA withdrawal removes the whole record, and withdrawing a customer that is
  not held is code 6 (draft section 12, code 6).

:func:`apply_payload` applies a batch all-or-nothing, the transaction behaviour that
section 11.3 of the draft recommends (apply on End of Data; revert a failed synchronisation).
:func:`ordering_key` and :func:`check_order` are the cache-to-router total ordering of
section 11.2.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .pdu import (
    Aspa,
    ErrorCode,
    Ipv4Prefix,
    Ipv6Prefix,
    Pdu,
    PduType,
    RouterKey,
    RtrError,
)

__all__ = ["PayloadDb", "apply_payload", "check_order", "ordering_key"]

PrefixKey = tuple[int, int, int, int, int]  # (family, address, prefix length, max length, asn)
KeyKey = tuple[bytes, int, bytes]  # (ski, asn, spki)


@dataclass(slots=True)
class PayloadDb:
    """Records learned from one cache. Mutated only through :func:`apply_payload`."""

    prefixes: set[PrefixKey] = field(default_factory=set)
    router_keys: set[KeyKey] = field(default_factory=set)
    aspas: dict[int, tuple[int, ...]] = field(default_factory=dict)

    def copy(self) -> PayloadDb:
        return PayloadDb(set(self.prefixes), set(self.router_keys), dict(self.aspas))

    def clear(self) -> None:
        """Flush everything, as a router must after a fatal error (draft section 12)."""
        self.prefixes.clear()
        self.router_keys.clear()
        self.aspas.clear()

    def __len__(self) -> int:
        return len(self.prefixes) + len(self.router_keys) + len(self.aspas)


def _prefix_key(pdu: Ipv4Prefix | Ipv6Prefix) -> PrefixKey:
    family = 4 if isinstance(pdu, Ipv4Prefix) else 6
    return (family, int(pdu.prefix), pdu.prefix_len, pdu.max_len, pdu.asn)


def _apply_one(db: PayloadDb, pdu: Pdu) -> None:
    if isinstance(pdu, Ipv4Prefix | Ipv6Prefix):
        _apply_set(db.prefixes, _prefix_key(pdu), pdu.announce, "prefix")
    elif isinstance(pdu, RouterKey):
        _apply_set(db.router_keys, (pdu.ski, pdu.asn, pdu.spki), pdu.announce, "router key")
    elif isinstance(pdu, Aspa):
        if pdu.announce:
            db.aspas[pdu.customer_asn] = pdu.providers
        elif db.aspas.pop(pdu.customer_asn, None) is None:
            raise RtrError(
                f"ASPA withdrawal for customer AS{pdu.customer_asn} that is not held",
                ErrorCode.WITHDRAWAL_OF_UNKNOWN_RECORD,
            )
    else:
        raise TypeError(f"not a payload PDU: {pdu!r}")


def _apply_set(held: set[Any], key: object, announce: bool, what: str) -> None:
    if announce:
        if key in held:
            raise RtrError(f"duplicate {what} announcement", ErrorCode.DUPLICATE_ANNOUNCEMENT)
        held.add(key)
    elif key in held:
        held.remove(key)
    else:
        raise RtrError(f"withdrawal of an unknown {what}", ErrorCode.WITHDRAWAL_OF_UNKNOWN_RECORD)


def apply_payload(db: PayloadDb, pdus: Iterable[Pdu]) -> None:
    """Apply payload PDUs to ``db`` all or nothing (RFC 8210 sections 5.6, 5.7 and 5.10;
    draft-ietf-sidrops-8210bis sections 5.12, 11.3 and 12).

    Raises :class:`~rtrkit.pdu.RtrError` with code 7 (duplicate announcement) or 6 (withdrawal
    of an unknown record) on the first offending PDU, leaving ``db`` exactly as it was. Anything
    that is not an IPv4 Prefix, IPv6 Prefix, Router Key or ASPA PDU is a ``TypeError``: the
    caller handles Cache Response, End of Data and the rest. The PDUs of one batch see one
    another, so an announcement followed by its withdrawal in one batch is legal.
    """
    work = db.copy()
    for pdu in pdus:
        _apply_one(work, pdu)
    db.prefixes, db.router_keys, db.aspas = work.prefixes, work.router_keys, work.aspas


def ordering_key(pdu: Pdu) -> tuple[object, ...]:
    """The sort key of draft-ietf-sidrops-8210bis section 11.2 for a payload PDU.

    Lower PDU type first; within a type, announcements before withdrawals (section 11.1.3).
    Among prefix announcements: higher address, then higher max length, then higher prefix
    length, then higher ASN first, so AS0 follows the others. Among prefix withdrawals the
    same fields ascend. Router Keys: SKI, SPKI length, SPKI, ASN, all ascending. ASPA: customer
    ASN ascending. Sorting by this key yields the order a cache MUST send in a version 2 session.
    """
    if isinstance(pdu, Ipv4Prefix | Ipv6Prefix):
        addr = int(pdu.prefix)
        fields = (addr, pdu.max_len, pdu.prefix_len, pdu.asn)
        kind = PduType.IPV4_PREFIX if isinstance(pdu, Ipv4Prefix) else PduType.IPV6_PREFIX
        if pdu.announce:
            return (int(kind), 0, *(-f for f in fields))
        return (int(kind), 1, *fields)
    if isinstance(pdu, RouterKey):
        return (
            int(PduType.ROUTER_KEY),
            0 if pdu.announce else 1,
            pdu.ski,
            len(pdu.spki),
            pdu.spki,
            pdu.asn,
        )
    if isinstance(pdu, Aspa):
        return (int(PduType.ASPA), 0 if pdu.announce else 1, pdu.customer_asn)
    raise TypeError(f"not a payload PDU: {pdu!r}")


def check_order(pdus: Iterable[Pdu]) -> None:
    """Raise Ordering Error (code 11) if payload PDUs are not in the section 11.2 order.

    Equal neighbours are accepted (a duplicate is a code 7 matter for :func:`apply_payload`,
    not an ordering one).
    """
    previous = None
    for pdu in pdus:
        key = ordering_key(pdu)
        if previous is not None and key < previous:
            raise RtrError("PDUs are not in the section 11.2 order", ErrorCode.ORDERING_ERROR)
        previous = key
