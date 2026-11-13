"""Version 2 and the ASPA PDU (draft-ietf-sidrops-8210bis-29, sections 5.12 and 12).

Provenance: the draft publishes no test vectors, only the Figure 11 layout. Every byte string
below is written out by hand from that figure and the section 5.12 rules, not produced by
this library. The draft is not an RFC and may change; the pinned revision is
``rtrkit.pdu.DRAFT_8210BIS``.
"""

from __future__ import annotations

import ipaddress

import pytest

from rtrkit import (
    Aspa,
    EndOfData,
    Ipv4Prefix,
    NeedMore,
    RouterKey,
    RtrError,
    decode_pdu,
    encode_aspa,
    encode_end_of_data,
    encode_error_report,
    encode_ipv4_prefix_record,
    encode_pdu,
    encode_reset_query,
    encode_router_key_record,
)
from rtrkit.pdu import DRAFT_8210BIS, DRAFT_ASPA_PROFILE, FATAL_ERRORS, VERSIONS, ErrorCode


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


# Figure 11: version 2, type 11, flags 0x01 (announce), zero, Length, customer 64496, providers.
ASPA_ONE = h("02 0B 0100 00000010 0000FBF0 0000FBF1")
ASPA_TWO = h("02 0B 0100 00000014 0000FBF0 0000FBF1 0000FBF2")
# Section 5.12: a withdrawal has the customer, no providers, and Length 12.
ASPA_WITHDRAW = h("02 0B 0000 0000000C 0000FBF0")


def test_pinned_draft_revisions_are_recorded():
    assert DRAFT_8210BIS == "draft-ietf-sidrops-8210bis-29"
    assert DRAFT_ASPA_PROFILE == "draft-ietf-sidrops-aspa-profile-31"
    assert {0, 1, 2} == VERSIONS


def test_aspa_announce_roundtrip_matches_figure_11():
    pdu, used = decode_pdu(ASPA_TWO)
    assert used == 20
    assert pdu == Aspa(2, True, 64496, (64497, 64498))
    assert encode_aspa(2, 64496, (64497, 64498), True) == ASPA_TWO
    assert encode_pdu(pdu) == ASPA_TWO
    assert decode_pdu(ASPA_ONE)[0] == Aspa(2, True, 64496, (64497,))


def test_aspa_withdrawal_is_length_12_with_no_providers():
    assert decode_pdu(ASPA_WITHDRAW)[0] == Aspa(2, False, 64496, ())
    assert encode_aspa(2, 64496, (), False) == ASPA_WITHDRAW
    with pytest.raises(ValueError, match="no provider"):
        encode_aspa(2, 64496, (64497,), False)
    with pytest.raises(RtrError) as caught:
        decode_pdu(h("02 0B 0000 00000010 0000FBF0 0000FBF1"))
    assert caught.value.code == 9


@pytest.mark.parametrize(
    "providers",
    [
        pytest.param((), id="empty-announcement"),
        pytest.param((64498, 64497), id="not-increasing"),
        pytest.param((64497, 64497), id="duplicate"),
        pytest.param((0, 64497), id="as0-with-others"),
    ],
)
def test_aspa_bad_provider_list_is_error_code_9(providers):
    raw = h("02 0B 0100") + (12 + 4 * len(providers)).to_bytes(4, "big") + h("0000FBF0")
    raw += b"".join(p.to_bytes(4, "big") for p in providers)
    with pytest.raises(RtrError) as caught:
        decode_pdu(raw)
    assert caught.value.code == ErrorCode.ASPA_PROVIDER_LIST_ERROR == 9
    with pytest.raises(ValueError, match=r"provider|AS0|increasing"):
        encode_aspa(2, 64496, providers, True)


def test_aspa_as0_alone_is_legal():
    pdu = decode_pdu(h("02 0B 0100 00000010 0000FBF0 00000000"))[0]
    assert pdu == Aspa(2, True, 64496, (0,))


def test_aspa_is_refused_before_version_2():
    for version in (0, 1):
        raw = bytes([version]) + ASPA_ONE[1:]
        with pytest.raises(RtrError) as caught:
            decode_pdu(raw)
        assert caught.value.code == 5
        with pytest.raises(ValueError, match="version 2"):
            encode_aspa(version, 64496, (64497,), True)


@pytest.mark.parametrize("length", [8, 11, 13, 14, 18])
def test_aspa_length_must_be_12_plus_whole_providers(length):
    raw = h("02 0B 0100") + length.to_bytes(4, "big") + b"\x00" * max(length - 8, 0)
    with pytest.raises(RtrError) as caught:
        decode_pdu(raw)
    assert caught.value.code == 0


def test_aspa_short_buffer_needs_more():
    with pytest.raises(NeedMore) as caught:
        decode_pdu(ASPA_TWO[:15])
    assert caught.value.needed == 20


def test_version_2_end_of_data_has_the_version_1_shape():
    raw = encode_end_of_data(2, 5, 9, 3600, 600, 7200)
    assert raw[:2] == h("02 07")
    assert len(raw) == 24
    assert decode_pdu(raw)[0] == EndOfData(2, 5, 9, 3600, 600, 7200)


def test_version_2_router_key_and_queries():
    ski, spki = bytes(range(20)), h("3004 05000500")
    raw = encode_router_key_record(2, 1, ski, spki, True)
    assert decode_pdu(raw)[0] == RouterKey(2, True, ski, 1, spki)
    assert encode_reset_query(2) == h("02 02 0000 00000008")


def test_version_2_prefix_pdus_are_unchanged_in_shape():
    net = ipaddress.IPv4Network("192.0.2.0/24")
    raw = encode_ipv4_prefix_record(2, net, 64496, 24, True)
    assert raw[:2] == h("02 04")
    assert len(raw) == 20
    assert isinstance(decode_pdu(raw)[0], Ipv4Prefix)


def test_error_codes_9_to_13_are_sent_only_in_version_2_sessions():
    assert encode_error_report(2, 11)[2:4] == h("000B")
    for version in (0, 1):
        with pytest.raises(ValueError, match="version 2"):
            encode_error_report(version, 9)
        assert encode_error_report(version, 8)[2:4] == h("0008")


def test_error_codes_9_to_13_and_which_are_fatal():
    # section 12: 2, 4 and 12 are non-fatal; every other code is fatal
    assert [int(c) for c in ErrorCode if c >= 9] == [9, 10, 11, 12, 13]
    assert {int(c) for c in ErrorCode} - FATAL_ERRORS == {2, 4, 12}
