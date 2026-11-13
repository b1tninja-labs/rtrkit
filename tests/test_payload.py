"""Applying payload PDUs (RFC 8210 sections 5.6, 5.7, 5.10; draft-ietf-sidrops-8210bis-29
sections 5.12, 11.2, 11.3 and 12). The cases are the sentences of those sections, not captures."""

from __future__ import annotations

import ipaddress

import pytest

from rtrkit import Aspa, Ipv4Prefix, Ipv6Prefix, ResetQuery, RouterKey, RtrError
from rtrkit.payload import PayloadDb, apply_payload, check_order, ordering_key

SKI = bytes(range(20))
SPKI = bytes.fromhex("3004" + "05000500")
OTHER_SPKI = bytes.fromhex("3004" + "05000501")


def v4(addr, plen, mlen, asn, announce=True):
    return Ipv4Prefix(2, announce, plen, mlen, ipaddress.IPv4Address(addr), asn)


def test_announce_then_withdraw_prefix():
    db = PayloadDb()
    apply_payload(db, [v4("192.0.2.0", 24, 24, 64496)])
    assert len(db) == 1
    apply_payload(db, [v4("192.0.2.0", 24, 24, 64496, announce=False)])
    assert len(db) == 0


def test_duplicate_announcement_is_code_7_and_leaves_the_database_unchanged():
    db = PayloadDb()
    apply_payload(db, [v4("192.0.2.0", 24, 24, 64496)])
    with pytest.raises(RtrError) as caught:
        apply_payload(db, [v4("198.51.100.0", 24, 24, 1), v4("192.0.2.0", 24, 24, 64496)])
    assert caught.value.code == 7
    assert len(db) == 1  # the first PDU of the failed batch was rolled back


def test_withdrawal_of_unknown_is_code_6():
    with pytest.raises(RtrError) as caught:
        apply_payload(PayloadDb(), [v4("192.0.2.0", 24, 24, 64496, announce=False)])
    assert caught.value.code == 6


def test_prefix_identity_includes_max_length_and_asn():
    db = PayloadDb()
    apply_payload(
        db, [v4("192.0.2.0", 24, 24, 1), v4("192.0.2.0", 24, 25, 1), v4("192.0.2.0", 24, 24, 2)]
    )
    assert len(db) == 3
    with pytest.raises(RtrError) as caught:
        apply_payload(db, [v4("192.0.2.0", 24, 26, 1, announce=False)])
    assert caught.value.code == 6


def test_v4_and_v6_never_collide():
    db = PayloadDb()
    v6 = Ipv6Prefix(2, True, 0, 0, ipaddress.IPv6Address("::"), 1)
    apply_payload(db, [v4("10.0.0.0", 8, 8, 1), v6])
    assert len(db) == 2


def test_router_key_duplicate_compares_ski_spki_and_asn():
    db = PayloadDb()
    key = RouterKey(2, True, SKI, 64496, SPKI)
    other_spki = RouterKey(2, True, SKI, 64496, OTHER_SPKI)
    other_asn = RouterKey(2, True, SKI, 64497, SPKI)
    apply_payload(db, [key, other_spki, other_asn])
    assert len(db) == 3  # same SKI, different SPKI or ASN: not duplicates (section 5.11)
    with pytest.raises(RtrError) as caught:
        apply_payload(db, [key])
    assert caught.value.code == 7
    apply_payload(db, [RouterKey(2, False, SKI, 64496, OTHER_SPKI)])
    assert len(db) == 2
    with pytest.raises(RtrError) as unknown:
        apply_payload(db, [RouterKey(2, False, SKI, 64496, OTHER_SPKI)])
    assert unknown.value.code == 6


def test_aspa_announce_replaces_and_withdraw_removes_the_whole_record():
    db = PayloadDb()
    apply_payload(db, [Aspa(2, True, 64496, (1, 2))])
    apply_payload(db, [Aspa(2, True, 64496, (3,))])  # replacement, not a duplicate
    assert db.aspas == {64496: (3,)}
    apply_payload(db, [Aspa(2, True, 64496, (3,))])  # an identical one replaces too
    apply_payload(db, [Aspa(2, False, 64496, ())])
    assert db.aspas == {}
    with pytest.raises(RtrError) as caught:
        apply_payload(db, [Aspa(2, False, 64496, ())])
    assert caught.value.code == 6


def test_non_payload_pdus_are_a_type_error():
    with pytest.raises(TypeError):
        apply_payload(PayloadDb(), [ResetQuery(2)])


def test_clear_flushes_everything():
    db = PayloadDb()
    apply_payload(
        db, [v4("192.0.2.0", 24, 24, 1), Aspa(2, True, 1, (2,)), RouterKey(2, True, SKI, 1, SPKI)]
    )
    db.clear()
    assert len(db) == 0


def test_ordering_prefix_announcements_high_to_low_and_as0_last():
    ordered = [
        v4("198.51.100.0", 24, 24, 5),
        v4("192.0.2.0", 24, 25, 5),
        v4("192.0.2.0", 24, 24, 9),
        v4("192.0.2.0", 24, 24, 0),
        v4("192.0.2.0", 24, 24, 5, announce=False),  # withdrawals follow announcements
        v4("192.0.2.0", 24, 24, 9, announce=False),
        v4("198.51.100.0", 24, 24, 5, announce=False),
    ]
    check_order(ordered)
    assert sorted(ordered[3:] + ordered[:3], key=ordering_key) == ordered
    with pytest.raises(RtrError) as caught:
        check_order([ordered[1], ordered[0]])
    assert caught.value.code == 11


def test_ordering_withdrawal_as0_first_and_type_order():
    w0 = v4("192.0.2.0", 24, 24, 0, announce=False)
    w5 = v4("192.0.2.0", 24, 24, 5, announce=False)
    check_order([w0, w5])
    with pytest.raises(RtrError):
        check_order([w5, w0])
    key = RouterKey(2, True, SKI, 1, SPKI)
    aspa = Aspa(2, True, 1, (2,))
    v6 = Ipv6Prefix(2, True, 0, 0, ipaddress.IPv6Address("::"), 1)
    check_order([w5, v6, key, aspa])  # lower PDU type precedes higher: 4, 6, 9, 11
    with pytest.raises(RtrError):
        check_order([key, v6])


def test_ordering_router_keys_and_aspa():
    a = RouterKey(2, True, SKI, 1, SPKI)
    c = RouterKey(2, True, SKI, 1, OTHER_SPKI)
    check_order([a, c])  # same SKI and SPKI length: SPKI bytes ascend
    with pytest.raises(RtrError):
        check_order([c, a])
    check_order([Aspa(2, True, 1, (2,)), Aspa(2, True, 2, (3,)), Aspa(2, False, 1, ())])
    with pytest.raises(RtrError):
        check_order([Aspa(2, False, 1, ()), Aspa(2, True, 2, (3,))])
