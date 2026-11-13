"""PDU codec tests (RFC 8210 section 5, RFC 6810 section 5).

Provenance of every byte string: RFC 8210 and RFC 6810 publish no test vectors, only the
field layout of each PDU. Each vector below is written out by hand, octet by octet, from the
figure of that PDU in the section named beside it. None was produced by this library, and
none is a capture from a real cache (that interop evidence is a ROADMAP row).
"""

from __future__ import annotations

import ipaddress
import random

import pytest

from rtrkit import (
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

# A minimal complete DER SEQUENCE standing in for a SubjectPublicKeyInfo: 30 05 | 05 00 (NULL) | 05 00 ...
SPKI = bytes.fromhex("3004" + "05000500")
SKI = bytes(range(1, 21))


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


# RFC 8210 section 5.4 figure: version 1, type 2, zero, Length=8.
RESET_V1 = h("01 02 0000 00000008")
# Section 5.3 figure: version 1, type 1, session 0x1234, Length=12, serial 7.
SERIAL_QUERY_V1 = h("01 01 1234 0000000C 00000007")
# Section 5.2 figure: type 0.
SERIAL_NOTIFY_V1 = h("01 00 1234 0000000C 00000007")
# Section 5.5 figure: type 3, Length=8.
CACHE_RESPONSE_V1 = h("01 03 1234 00000008")
# Section 5.9 figure: type 8, Length=8.
CACHE_RESET_V1 = h("01 08 0000 00000008")
# Section 5.6 figure: type 4, Length=20; flags 1, prefix len 24, max len 24, zero; 192.0.2.0; AS 64496.
IPV4_V1 = h("01 04 0000 00000014 01 18 18 00 C0000200 0000FBF0")
# Section 5.7 figure: type 6, Length=32; 2001:db8::/32 max 48 AS 64496, withdraw (flags 0).
IPV6_V1 = h("01 06 0000 00000020 00 20 30 00 20010DB8000000000000000000000000 0000FBF0")
# Section 5.8 figure: type 7, Length=24, serial 7, refresh 3600, retry 600, expire 7200.
EOD_V1 = h("01 07 1234 00000018 00000007 00000E10 00000258 00001C20")
# RFC 6810 section 5.8 figure: version 0, type 7, Length=12.
EOD_V0 = h("00 07 1234 0000000C 00000007")
# Section 5.10 figure: type 9, flags 1; Length = 8 + 20 + 4 + len(SPKI)=6 -> 38 = 0x26.
ROUTER_KEY_V1 = h("01 09 0100 00000026") + SKI + h("0000FBF0") + SPKI
# Section 5.11 figure: code 0, encapsulated reset query (8 bytes), text "bad".
# Length = 8 + 4 + 8 + 4 + 3 = 27 = 0x1B.
ERROR_V1 = h("01 0A 0000 0000001B 00000008") + RESET_V1 + h("00000003") + b"bad"


def test_decode_reset_query_v1_bytes():
    assert decode_pdu(RESET_V1) == (ResetQuery(1), 8)
    assert encode_reset_query(1) == RESET_V1
    assert encode_reset_query(0) == h("00 02 0000 00000008")


def test_reset_query_takes_a_version_and_no_session():
    # The stub took a session id; section 5.4 has none, the 16-bit field is zero.
    with pytest.raises(ValueError, match="version"):
        encode_reset_query(1234)
    with pytest.raises(TypeError):
        encode_reset_query(1, 2)


def test_decode_serial_pdus():
    assert decode_pdu(SERIAL_QUERY_V1) == (SerialQuery(1, 0x1234, 7), 12)
    assert decode_pdu(SERIAL_NOTIFY_V1) == (SerialNotify(1, 0x1234, 7), 12)
    assert encode_serial_query(1, 0x1234, 7) == SERIAL_QUERY_V1
    assert encode_serial_notify(1, 0x1234, 7) == SERIAL_NOTIFY_V1


def test_decode_cache_response_and_reset():
    assert decode_pdu(CACHE_RESPONSE_V1) == (CacheResponse(1, 0x1234), 8)
    assert decode_pdu(CACHE_RESET_V1) == (CacheReset(1), 8)
    assert encode_cache_response(1, 0x1234) == CACHE_RESPONSE_V1
    assert encode_cache_reset(1) == CACHE_RESET_V1


def test_decode_ipv4_prefix_roundtrip():
    pdu, used = decode_pdu(IPV4_V1)
    assert used == 20
    assert pdu == Ipv4Prefix(1, True, 24, 24, ipaddress.IPv4Address("192.0.2.0"), 64496)
    net = ipaddress.IPv4Network("192.0.2.0/24")
    assert encode_ipv4_prefix_record(1, net, 64496, 24, True) == IPV4_V1
    assert encode_pdu(pdu) == IPV4_V1


def test_decode_ipv6_prefix_roundtrip():
    pdu, used = decode_pdu(IPV6_V1)
    assert used == 32
    assert pdu == Ipv6Prefix(1, False, 32, 48, ipaddress.IPv6Address("2001:db8::"), 64496)
    net = ipaddress.IPv6Network("2001:db8::/32")
    assert encode_ipv6_prefix_record(1, net, 64496, 48, False) == IPV6_V1


def test_decode_end_of_data_v0_length_12_and_v1_length_24():
    assert decode_pdu(EOD_V1) == (EndOfData(1, 0x1234, 7, 3600, 600, 7200), 24)
    assert decode_pdu(EOD_V0) == (EndOfData(0, 0x1234, 7), 12)
    assert encode_end_of_data(1, 0x1234, 7, 3600, 600, 7200) == EOD_V1
    assert encode_end_of_data(0, 0x1234, 7) == EOD_V0


def test_end_of_data_with_the_wrong_length_for_its_version_is_refused():
    with pytest.raises(RtrError):
        decode_pdu(h("00 07 1234 00000018 00000007 00000E10 00000258 00001C20"))
    with pytest.raises(RtrError):
        decode_pdu(h("01 07 1234 0000000C 00000007"))


def test_encode_end_of_data_enforces_section_6_timers():
    with pytest.raises(ValueError, match="refresh"):
        encode_end_of_data(1, 1, 1, 0, 600, 7200)
    with pytest.raises(ValueError, match="retry"):
        encode_end_of_data(1, 1, 1, 3600, 7201, 7300)
    with pytest.raises(ValueError, match="expire"):
        encode_end_of_data(1, 1, 1, 3600, 600, 599)
    with pytest.raises(ValueError, match="larger"):
        encode_end_of_data(1, 1, 1, 3600, 600, 3600)
    with pytest.raises(ValueError, match="no timers"):
        encode_end_of_data(0, 1, 1, 3600, 600, 7200)
    with pytest.raises(ValueError, match="needs"):
        encode_end_of_data(1, 1, 1)


def test_decode_router_key_roundtrip():
    pdu, used = decode_pdu(ROUTER_KEY_V1)
    assert used == 38
    assert pdu == RouterKey(1, True, SKI, 64496, SPKI)
    assert encode_router_key_record(1, 64496, SKI, SPKI, True) == ROUTER_KEY_V1


def test_decode_router_key_v0_refused():
    raw = bytearray(ROUTER_KEY_V1)
    raw[0] = 0
    with pytest.raises(RtrError) as caught:
        decode_pdu(bytes(raw))
    assert caught.value.code == 5
    with pytest.raises(ValueError, match="version 1"):
        encode_router_key_record(0, 1, SKI, SPKI, True)


def test_router_key_rejects_bad_ski_and_spki():
    with pytest.raises(ValueError, match="20"):
        encode_router_key_record(1, 1, SKI[:19], SPKI, True)
    with pytest.raises(ValueError, match="DER"):
        encode_router_key_record(1, 1, SKI, SPKI + b"\x00", True)
    bad = bytearray(ROUTER_KEY_V1)
    # same length, but the SPKI is no longer a SEQUENCE
    bad[8 + 20 + 4] = 0x31
    with pytest.raises(RtrError):
        decode_pdu(bytes(bad))


def test_decode_error_report_roundtrip():
    pdu, used = decode_pdu(ERROR_V1)
    assert used == 27
    assert pdu == ErrorReport(1, 0, RESET_V1, "bad")
    assert encode_error_report(1, 0, RESET_V1, "bad") == ERROR_V1


def test_error_report_without_pdu_or_text():
    raw = h("01 0A 0001 00000010 00000000 00000000")
    assert decode_pdu(raw) == (ErrorReport(1, 1, b"", ""), 16)
    assert encode_error_report(1, 1) == raw


def test_decode_error_report_truncated_erroneous_pdu():
    # Section 5.11: the Erroneous PDU may be truncated; its own length field says how much is here.
    raw = h("01 0A 0000 00000014 00000004 01020000 00000000")
    assert decode_pdu(raw) == (ErrorReport(1, 0, h("01020000"), ""), 20)


def test_decode_error_text_invalid_utf8():
    raw = h("01 0A 0000 00000011 00000000 00000001 FF")
    with pytest.raises(RtrError) as caught:
        decode_pdu(raw)
    assert caught.value.code == 0


def test_error_report_length_fields_must_agree_with_the_pdu_length():
    # encapsulated length claims more than the PDU holds
    with pytest.raises(RtrError):
        decode_pdu(h("01 0A 0000 00000010 00000009 00000000"))
    # text length does not match what remains
    with pytest.raises(RtrError):
        decode_pdu(h("01 0A 0000 00000011 00000000 00000002 41"))


def test_error_report_within_error_report_flagged():
    with pytest.raises(ValueError, match="Error Report"):
        encode_error_report(1, 0, ERROR_V1)


def test_decode_ignores_reserved_flag_bits():
    raw = bytearray(IPV4_V1)
    raw[8] = 0xFF  # flags: bit 0 set (announce), the rest reserved
    raw[11] = 0xAA  # the trailing zero field
    raw[2:4] = b"\xde\xad"  # the zero field of the header
    pdu, _ = decode_pdu(bytes(raw))
    assert pdu == Ipv4Prefix(1, True, 24, 24, ipaddress.IPv4Address("192.0.2.0"), 64496)
    raw[8] = 0xFE
    assert decode_pdu(bytes(raw))[0].announce is False


def test_encode_emits_zero_reserved():
    prefix = encode_ipv4_prefix_record(1, ipaddress.IPv4Network("10.0.0.0/8"), 1, 8, True)
    assert prefix[2:4] == b"\x00\x00"  # header zero field
    assert prefix[8] == 1  # flags: announce, no reserved bit set
    assert prefix[11] == 0  # the trailing zero field
    withdraw = encode_ipv4_prefix_record(1, ipaddress.IPv4Network("10.0.0.0/8"), 1, 8, False)
    assert withdraw[8] == 0
    key = encode_router_key_record(1, 1, SKI, SPKI, True)
    assert key[2:4] == b"\x01\x00"  # flags 1, then the zero octet
    assert encode_reset_query(1)[2:4] == b"\x00\x00"


def test_decode_short_buffer_needs_more_not_corrupt():
    for cut in range(len(IPV4_V1)):
        with pytest.raises(NeedMore) as caught:
            decode_pdu(IPV4_V1[:cut])
        assert not isinstance(caught.value, RtrError)
    assert caught.value.needed == 20
    with pytest.raises(NeedMore) as short:
        decode_pdu(b"\x01\x02")
    assert short.value.needed == 8


def test_decode_consumes_one_pdu_and_leaves_the_rest():
    pdu, used = decode_pdu(RESET_V1 + IPV4_V1)
    assert (pdu, used) == (ResetQuery(1), 8)
    assert decode_pdu((RESET_V1 + IPV4_V1)[used:])[1] == 20


@pytest.mark.parametrize("length", [0, 7])
def test_decode_length_below_8(length):
    raw = h("01 02 0000") + length.to_bytes(4, "big")
    with pytest.raises(RtrError):
        decode_pdu(raw)


def test_decode_length_mismatch_for_fixed_pdu():
    raw = h("01 04 0000 00000018") + IPV4_V1[8:] + h("00000000")
    with pytest.raises(RtrError):
        decode_pdu(raw)
    with pytest.raises(RtrError):
        decode_pdu(h("01 02 0000 0000000C 00000000"))


def test_decode_length_huge_does_not_ask_for_gigabytes():
    with pytest.raises(RtrError):
        decode_pdu(h("01 0A 0000 FFFFFFFF"))
    with pytest.raises(RtrError):
        decode_pdu(h("01 09 0100 00010000"))  # 65536, one past the cap


def test_decode_prefix_len_over_32():
    raw = bytearray(IPV4_V1)
    raw[9] = 33
    raw[10] = 33
    with pytest.raises(RtrError):
        decode_pdu(bytes(raw))
    raw6 = bytearray(IPV6_V1)
    raw6[9] = 129
    raw6[10] = 129
    with pytest.raises(RtrError):
        decode_pdu(bytes(raw6))


def test_decode_maxlen_less_than_prefixlen():
    raw = bytearray(IPV4_V1)
    raw[10] = 23
    with pytest.raises(RtrError):
        decode_pdu(bytes(raw))
    with pytest.raises(ValueError, match="max length"):
        encode_ipv4_prefix_record(1, ipaddress.IPv4Network("192.0.2.0/24"), 1, 23, True)


def test_decode_unknown_type_5():
    with pytest.raises(RtrError) as caught:
        decode_pdu(h("01 05 0000 00000008"))
    assert caught.value.code == 5
    with pytest.raises(RtrError) as other:
        decode_pdu(h("01 0B 0000 00000008"))
    assert other.value.code == 5


def test_decode_unknown_version_3():
    # version 2 is known since draft-ietf-sidrops-8210bis; 3 is not
    with pytest.raises(RtrError) as caught:
        decode_pdu(h("03 02 0000 00000008"))
    assert caught.value.code == 4
    with pytest.raises(RtrError):
        decode_pdu(h("FF 02 0000 00000008"))
    with pytest.raises(ValueError, match="version"):
        encode_reset_query(3)


def test_encode_rejects_out_of_range_integers():
    with pytest.raises(ValueError, match="asn"):
        encode_ipv4_prefix_record(1, ipaddress.IPv4Network("10.0.0.0/8"), 1 << 32, 8, True)
    with pytest.raises(ValueError, match="session"):
        encode_cache_response(1, 65536)
    with pytest.raises(ValueError, match="serial"):
        encode_serial_query(1, 1, -1)


def test_roundtrip_property_over_random_valid_pdus():
    rng = random.Random(8210)
    for _ in range(300):
        version = rng.choice([0, 1])
        choice = rng.randrange(8)
        if choice == 0:
            pdu = SerialQuery(version, rng.randrange(65536), rng.randrange(1 << 32))
        elif choice == 1:
            pdu = ResetQuery(version)
        elif choice == 2:
            plen = rng.randrange(33)
            addr = ipaddress.IPv4Network((rng.randrange(1 << 32), plen), strict=False)
            pdu = Ipv4Prefix(
                version,
                rng.random() < 0.5,
                plen,
                rng.randrange(plen, 33),
                addr.network_address,
                rng.randrange(1 << 32),
            )
        elif choice == 3:
            plen = rng.randrange(129)
            addr6 = ipaddress.IPv6Network((rng.randrange(1 << 128), plen), strict=False)
            pdu = Ipv6Prefix(
                version,
                rng.random() < 0.5,
                plen,
                rng.randrange(plen, 129),
                addr6.network_address,
                rng.randrange(1 << 32),
            )
        elif choice == 4:
            sid, serial = rng.randrange(65536), rng.randrange(1 << 32)
            pdu = (
                EndOfData(0, sid, serial)
                if version == 0
                else EndOfData(1, sid, serial, 3600, 600, 7200)
            )
        elif choice == 5:
            pdu = CacheResponse(version, rng.randrange(65536))
        elif choice == 6:
            pdu = RouterKey(
                1,
                rng.random() < 0.5,
                bytes(rng.randrange(256) for _ in range(20)),
                rng.randrange(1 << 32),
                SPKI,
            )
        else:
            pdu = ErrorReport(
                version,
                rng.randrange(9),
                bytes(rng.randrange(256) for _ in range(rng.randrange(10))),
                "x" * rng.randrange(5),
            )
        raw = encode_pdu(pdu)
        assert decode_pdu(raw) == (pdu, len(raw))


def test_random_garbage_never_returns_a_record_without_consuming_a_whole_pdu():
    rng = random.Random(6810)
    for _ in range(2000):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 48)))
        try:
            pdu, used = decode_pdu(raw)
        except (NeedMore, RtrError):
            continue
        assert 8 <= used <= len(raw)
        assert pdu.version in (0, 1)
