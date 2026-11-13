# ruff: noqa: PT018
"""The sans-IO router and cache sessions, talking to each other and to hand-built bytes.

No vector from a non-Python implementation exists here (ROADMAP row ``decode_pdu() interop
capture``): the router and the cache are written independently from the sections cited in each
test, and the loopback tests show they agree, which is evidence of consistency and not of
interoperability. The byte-level tests build the offending PDUs by hand from RFC 8210 section 5
and draft-ietf-sidrops-8210bis-29 section 5.12.
"""

from __future__ import annotations

import ipaddress

import pytest

from rtrkit import (
    Aspa,
    CacheResponse,
    EndOfData,
    ErrorReport,
    Ipv4Prefix,
    Ipv6Prefix,
    RouterKey,
    decode_pdu,
    encode_cache_response,
    encode_end_of_data,
    encode_error_report,
    encode_ipv4_prefix_record,
    encode_pdu,
    encode_reset_query,
    encode_serial_notify,
)
from rtrkit.cache import NOTIFY_INTERVAL, CacheClosed, CacheSession, CacheStore, Served
from rtrkit.pdu import ErrorCode
from rtrkit.router import (
    CacheResetReceived,
    CacheRestarting,
    Closed,
    Expired,
    NoData,
    Notified,
    RouterSession,
    Synced,
)
from rtrkit.timers import Intervals

SKI = bytes(range(20))
SPKI = bytes.fromhex("3004" + "05000500")


def v4(addr: str, plen: int, mlen: int, asn: int) -> Ipv4Prefix:
    return Ipv4Prefix(1, True, plen, mlen, ipaddress.IPv4Address(addr), asn)


def v6(addr: str, plen: int, mlen: int, asn: int) -> Ipv6Prefix:
    return Ipv6Prefix(1, True, plen, mlen, ipaddress.IPv6Address(addr), asn)


A = v4("192.0.2.0", 24, 24, 64496)
B = v4("198.51.100.0", 24, 24, 64497)
C = v6("2001:db8::", 32, 48, 64498)
KEY = RouterKey(1, True, SKI, 64496, SPKI)
ASPA1 = Aspa(2, True, 64496, (64497,))
ASPA2 = Aspa(2, True, 64496, (64497, 64498))


def pump(router: RouterSession, cache: CacheSession, now: float = 0.0):
    """Move bytes both ways until none are left; return (router events, cache events)."""
    router_events: list = []
    cache_events: list = []
    for _ in range(20):
        out = router.data_to_send()
        back = cache.data_to_send()
        if not out and not back:
            break
        if out:
            cache_events += cache.receive_data(out)
        back = cache.data_to_send()
        if back:
            router_events += router.receive_data(back, now)
    return router_events, cache_events


def connect(store: CacheStore, *, supported=frozenset({0, 1, 2}), version=None, now: float = 0.0):
    router = RouterSession(now, supported=supported, version=version)
    cache = CacheSession(store, supported=supported)
    router.start()
    return router, cache


def synced(events) -> Synced:
    found = [e for e in events if isinstance(e, Synced)]
    assert len(found) == 1, events
    return found[0]


def holds(router: RouterSession) -> set:
    db = router.db
    return {*db.prefixes, *db.router_keys, *db.aspas.items()}


# ---- start and a full load ------------------------------------------------------------------


@pytest.mark.parametrize("version", [0, 1, 2])
def test_reset_query_loads_the_whole_database(version):
    store = CacheStore(7, 41, intervals=Intervals(100, 50, 1000))
    store.update([A, B, C, KEY, ASPA1])
    router, cache = connect(store, supported=frozenset({0, 1, 2}), version=version)
    r_events, c_events = pump(router, cache)
    done = synced(r_events)
    assert (done.reset, done.version, done.serial) == (True, version, 41)
    assert done.session_id == store.session_id_for(version)
    # Router Keys exist from version 1 and ASPA from version 2 (the cache leaves them out below).
    want = 3 + (version >= 1) + (version >= 2)
    assert len(router.db) == want
    assert c_events == [Served("reset", want)]
    assert router.negotiated and router.version == version


def test_the_session_id_differs_by_version():
    store = CacheStore(0xFFFF)
    assert len({store.session_id_for(v) for v in (0, 1, 2)}) == 3  # RFC 8210 5.1: SHOULD NOT reuse
    assert store.session_id_for(2) == 1  # 16-bit wrap


def test_timers_of_end_of_data_reach_the_router():
    store = CacheStore(1, intervals=Intervals(120, 30, 900))
    store.update([A])
    router, cache = connect(store, now=1000.0)
    pump(router, cache, now=1000.0)
    assert router.timers.intervals == Intervals(120, 30, 900)
    assert router.timers.next_query_at() == 1120.0
    assert router.poll(1119.0) == [] and router.data_to_send() == b""
    router.poll(1120.0)
    sent, _ = decode_pdu(router.data_to_send())
    assert (sent.session_id, sent.serial) == (store.session_id_for(2), 0)  # a Serial Query


def test_bytes_arriving_one_at_a_time_give_the_same_result():
    store = CacheStore(3, 9)
    store.update([A, B, C, KEY, ASPA1])
    router, cache = connect(store)
    out = router.data_to_send()
    for i in range(len(out)):
        cache.receive_data(out[i : i + 1])
    back = cache.data_to_send()
    events: list = []
    for i in range(len(back)):
        events += router.receive_data(back[i : i + 1], 0.0)
    assert synced(events).announced == 5 and len(router.db) == 5


# ---- incremental updates --------------------------------------------------------------------


def test_serial_query_gets_the_minimum_set_of_changes():
    # RFC 8210 section 5.3: merged changes; what cancels out is not mentioned at all.
    store = CacheStore(5, 100)
    store.update([A, B, ASPA1])
    router, cache = connect(store, now=0.0)
    pump(router, cache)
    store.update([A, B, C, ASPA1])  # serial 101: adds C
    store.update([A, C, ASPA2])  # serial 102: drops B, replaces the ASPA record
    store.update([A, B, C, ASPA2])  # serial 103: B is back, ASPA2 stays
    assert cache.notify(100.0)
    r_events, _ = router.receive_data(cache.data_to_send(), 100.0), None
    assert [type(e) for e in r_events] == [Notified]
    router.poll(100.0)
    r_events, c_events = pump(router, cache, now=101.0)
    # Since serial 100: C is new and the ASPA record is replaced; B is unchanged overall.
    assert c_events == [Served("serial", 2, 0)]
    done = synced(r_events)
    assert (done.reset, done.serial, done.announced) == (False, 103, 2)
    assert len(router.db) == 4 and router.db.aspas == {64496: (64497, 64498)}


def test_a_withdrawal_and_an_aspa_replacement_are_never_both_sent():
    store = CacheStore(5)
    store.update([A, ASPA1])
    store.update([B, ASPA2])
    withdrawn, announced = store.changes_since(0)
    assert [type(p).__name__ for p in withdrawn] == ["Ipv4Prefix"]
    assert withdrawn[0].prefix == A.prefix and not withdrawn[0].announce
    assert sorted(type(p).__name__ for p in announced) == ["Aspa", "Ipv4Prefix"]


def test_current_serial_gets_an_empty_response():
    store = CacheStore(5, 8)
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    router.poll(4_000.0)  # the refresh interval has passed
    r_events, c_events = pump(router, cache, now=4_000.0)
    assert c_events == [Served("current")]
    assert synced(r_events).announced == 0 and len(router.db) == 1


def test_unchanged_update_keeps_the_serial_and_changes_move_it_with_wraparound():
    store = CacheStore(1, 0xFFFFFFFF)
    assert store.update([A]) == 0xFFFFFFFF  # the first update installs, no increment
    assert store.update([A]) == 0xFFFFFFFF
    assert store.update([A, B]) == 0  # wraps from 2**32 - 1 to 0 (RFC 8210 section 2)
    assert store.changes_since(0xFFFFFFFF) is not None


def test_cache_reset_when_the_serial_is_no_longer_remembered():
    store = CacheStore(5, 1, max_history=2)
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    for extra in (B, C, KEY):
        store.update([A, extra])
    router.poll(4_000.0)
    r_events, c_events = pump(router, cache, now=4_000.0)
    assert Served("cache-reset") in c_events and CacheResetReceived() in r_events
    done = synced(r_events)  # the queued Reset Query was answered in the same exchange
    assert done.reset and done.serial == store.serial


def test_notify_is_rate_limited_and_only_for_a_moved_serial():
    store = CacheStore(5)
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    assert not cache.notify(0.0)  # nothing new since the router's own query
    store.update([A, B])
    assert cache.notify(1.0)
    store.update([A, B, C])
    assert not cache.notify(1.0 + NOTIFY_INTERVAL - 1)  # section 8.2: no more than once a minute
    assert cache.notify(1.0 + NOTIFY_INTERVAL)
    notes = cache.data_to_send()
    first, used = decode_pdu(notes)
    second, _ = decode_pdu(notes[used:])
    assert (first.serial, second.serial) == (1, 2)


# ---- negotiation ----------------------------------------------------------------------------


def test_a_version_1_cache_closes_a_version_2_router_which_retries_at_version_1():
    store = CacheStore(5)
    store.update([A, KEY])
    router = RouterSession(0.0, supported=frozenset({0, 1, 2}))
    cache = CacheSession(store, supported=frozenset({0, 1}))
    router.start()
    r_events, c_events = pump(router, cache)
    (closed,) = [e for e in r_events if isinstance(e, Closed)]
    assert closed.error_code == 4 and closed.retry_version == 1 and not closed.flushed
    assert [type(e) for e in c_events] == [CacheClosed]
    retry = RouterSession(0.0, supported=frozenset({0, 1, 2}), version=closed.retry_version)
    again = CacheSession(store, supported=frozenset({0, 1}))
    retry.start()
    r_events, _ = pump(retry, again)
    assert synced(r_events).version == 1 and len(retry.db) == 2


def test_a_serial_notify_before_negotiation_is_ignored_even_with_an_unknown_version():
    store = CacheStore(5)
    store.update([A])
    router, cache = connect(store)
    stray = bytes([7, 0, 0, 1, 0, 0, 0, 12, 0, 0, 0, 9])  # version 7: nothing we speak
    assert router.receive_data(stray, 0.0) == []
    assert not router.closed
    r_events, _ = pump(router, cache)
    assert synced(r_events).serial == 0


def test_a_version_0_router_stays_at_version_0_against_a_newer_cache():
    store = CacheStore(5)
    store.update([A, KEY, ASPA1])
    cache = CacheSession(store, supported=frozenset({0, 1, 2}))
    # A version 0 router meets a cache that speaks 0, 1 and 2: the session stays at 0 (section 7).
    low = RouterSession(0.0, supported=frozenset({0, 1, 2}), version=0)
    low.start()
    r_events, _ = pump(low, cache)
    assert synced(r_events).version == 0 and len(low.db) == 1  # key and ASPA left out of v0


def test_a_pdu_of_another_version_after_negotiation_is_error_8_and_a_flush():
    store = CacheStore(5)
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    stray = encode_ipv4_prefix_record(1, ipaddress.IPv4Network("203.0.113.0/24"), 1, 24, True)
    events = router.receive_data(stray, 1.0)
    (closed,) = events
    assert (closed.error_code, closed.sent, closed.flushed) == (8, True, True)
    assert len(router.db) == 0
    report, _ = decode_pdu(router.data_to_send())
    assert isinstance(report, ErrorReport) and report.code == 8


# ---- what the router refuses ----------------------------------------------------------------


def started(version: int = 2) -> RouterSession:
    router = RouterSession(0.0, version=version)
    router.start()
    router.data_to_send()
    return router


def response(version, session, *pdus, serial=1, end=True):
    out = encode_cache_response(version, session)
    for pdu in pdus:
        out += encode_pdu(pdu)
    if end:
        out += encode_end_of_data(version, session, serial, 100, 50, 1000)
    return out


def test_payload_is_held_until_end_of_data():
    router = started(1)
    events = router.receive_data(response(1, 9, A, end=False), 0.0)
    assert events == [] and len(router.db) == 0  # draft section 11.3
    events = router.receive_data(encode_end_of_data(1, 9, 3, 100, 50, 1000), 0.0)
    assert synced(events).serial == 3 and len(router.db) == 1


def test_end_of_data_with_another_session_id_is_error_0_and_a_flush():
    router = started(1)
    events = router.receive_data(response(1, 9, A, end=False), 0.0)
    events = router.receive_data(encode_end_of_data(1, 10, 3, 100, 50, 1000), 0.0)
    (closed,) = events
    assert (closed.error_code, closed.flushed, closed.sent) == (0, True, True)


def test_a_serial_response_must_keep_the_session_id():
    store = CacheStore(5)
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    router.poll(4_000.0)
    router.data_to_send()
    events = router.receive_data(encode_cache_response(2, 99), 4_000.0)
    (closed,) = events
    assert closed.error_code == 0 and closed.flushed and len(router.db) == 0


def test_a_withdrawal_of_an_unknown_record_is_error_6_and_nothing_is_applied():
    router = started(1)
    gone = encode_ipv4_prefix_record(1, ipaddress.IPv4Network("203.0.113.0/24"), 1, 24, False)
    out = encode_cache_response(1, 9) + gone + encode_end_of_data(1, 9, 3, 100, 50, 1000)
    (closed,) = router.receive_data(out, 0.0)
    assert closed.error_code == 6 and len(router.db) == 0 and router.serial is None


def test_a_duplicate_announcement_is_error_7_unless_the_session_is_lenient():
    dup = encode_pdu(A)
    out = encode_cache_response(1, 9) + dup + dup + encode_end_of_data(1, 9, 3, 100, 50, 1000)
    strict = started(1)
    (closed,) = strict.receive_data(out, 0.0)
    assert closed.error_code == 7
    lenient = RouterSession(0.0, version=1, lenient=True)
    lenient.start()
    done = synced(lenient.receive_data(out, 0.0))
    assert len(done.ignored) == 1 and len(lenient.db) == 1


def test_version_2_payload_out_of_order_is_error_11():
    router = started(2)
    low, high = v4("10.0.0.0", 8, 8, 1), v4("192.0.2.0", 24, 24, 2)
    low, high = (Ipv4Prefix(2, True, p.prefix_len, p.max_len, p.prefix, p.asn) for p in (low, high))
    # Announcements go from the higher address down (draft section 11.2.1), so low then high is wrong.
    (closed,) = router.receive_data(response(2, 9, low, high), 0.0)
    assert closed.error_code == 11 and closed.flushed
    ok = started(2)
    assert synced(ok.receive_data(response(2, 9, high, low), 0.0)).announced == 2


def test_unsolicited_and_misplaced_pdus_are_error_0():
    for data in (
        encode_cache_response(2, 1),  # nothing was asked
        encode_pdu(Ipv4Prefix(2, True, 24, 24, ipaddress.IPv4Address("192.0.2.0"), 1)),
        encode_end_of_data(2, 1, 1, 100, 50, 1000),
        encode_reset_query(2),  # only a cache receives queries
    ):
        router = RouterSession(0.0)
        router.negotiated = True  # skip negotiation: this is about what follows it
        (closed,) = router.receive_data(data, 0.0)
        assert closed.error_code == 0 and closed.flushed


def test_too_many_pending_pdus_is_error_1():
    router = RouterSession(0.0, version=1, max_pending=2)
    router.start()
    out = response(1, 9, A, B, C, end=False)
    (closed,) = router.receive_data(out, 0.0)
    assert closed.error_code == ErrorCode.INTERNAL_ERROR and closed.flushed


def test_garbage_ends_both_ends_with_the_decoders_code():
    router = started(2)
    (closed,) = router.receive_data(bytes([2, 99, 0, 0, 0, 0, 0, 8]), 0.0)  # type 99
    assert closed.error_code == 5 and closed.sent
    cache = CacheSession(CacheStore(1))
    (shut,) = cache.receive_data(bytes([2, 99, 0, 0, 0, 0, 0, 8]))
    assert shut.error_code == 5 and shut.sent
    assert router.receive_data(b"\x00", 0.0) == [] and cache.receive_data(b"\x00") == []


def test_an_invalid_error_report_is_dropped_without_an_answer_and_flushes():
    router = started(1)
    # Code 12 does not exist in version 1 and the encoder refuses it: write the PDU by hand.
    raw = bytes([1, 10, 0, 12, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0])
    (closed,) = router.receive_data(raw, 0.0)
    assert closed.flushed and not closed.sent and router.data_to_send() == b""


# ---- Error Reports from the cache -----------------------------------------------------------


def test_no_data_available_keeps_the_data_and_retries_with_reset_queries():
    store = CacheStore(5)  # no update yet: nothing to serve
    router, cache = connect(store)
    r_events, c_events = pump(router, cache, now=0.0)
    assert [type(e) for e in r_events] == [NoData] and c_events == [Served("no-data")]
    assert not router.closed and router.timers.failed_at == 0.0
    store.update([A])
    router.poll(100.0)  # before the Retry Interval (600 s by default)
    assert router.data_to_send() == b""
    router.poll(600.0)
    assert router.data_to_send() == encode_reset_query(2)  # section 8.4: Reset Queries


def test_no_data_available_for_a_router_holding_data_does_not_flush_it():
    store = CacheStore(5)
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    held = holds(router)
    report = encode_error_report(2, ErrorCode.NO_DATA_AVAILABLE, b"", "later")
    router.poll(4_000.0)
    router.data_to_send()
    events = router.receive_data(report, 4_000.0)
    assert [type(e) for e in events] == [NoData] and holds(router) == held


def test_cache_restart_retries_on_the_caches_intervals_and_cache_shutdown_flushes():
    store = CacheStore(5, intervals=Intervals(100, 50, 1000))
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    restart = encode_error_report(2, ErrorCode.CACHE_RESTART, b"", "restarting")
    events = router.receive_data(restart, 500.0)
    assert [type(e) for e in events] == [CacheRestarting] and len(router.db) == 1
    assert router.timers.next_query_at() == 550.0  # the cache's own Retry Interval
    shutdown = encode_error_report(2, ErrorCode.CACHE_SHUTDOWN, b"", "bye")
    (closed,) = router.receive_data(shutdown, 600.0)
    assert (closed.error_code, closed.flushed, closed.sent) == (13, True, False)
    assert len(router.db) == 0 and router.timers.intervals.retry == 600  # default Retry Interval


def test_a_fatal_error_report_flushes_and_closes_without_a_reply():
    store = CacheStore(5)
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    (closed,) = router.receive_data(encode_error_report(2, 0, b"", "corrupt"), 1.0)
    assert (closed.error_code, closed.flushed, closed.sent) == (0, True, False)
    assert router.data_to_send() == b"" and len(router.db) == 0


def test_expire_interval_flushes_the_data():
    store = CacheStore(5, intervals=Intervals(100, 50, 700))
    store.update([A])
    router, cache = connect(store, now=0.0)
    pump(router, cache, now=0.0)
    assert Expired() not in router.poll(699.0)
    assert Expired() in router.poll(700.0)
    assert len(router.db) == 0 and router.session_id is None
    assert router.poll(701.0) == []  # one Expired, not one per poll
    assert decode_pdu(router.data_to_send())[0].__class__.__name__ in ("ResetQuery", "SerialQuery")


def test_a_restarted_router_resumes_with_a_serial_query():
    store = CacheStore(5)
    store.update([A])
    first, cache = connect(store)
    pump(first, cache)
    store.update([A, B])
    second = RouterSession(
        0.0, db=first.db, session_id=first.session_id, serial=first.serial, version=2
    )
    second.start()
    again = CacheSession(store)
    r_events, c_events = pump(second, again)
    assert c_events == [Served("serial", 1, 0)] and len(second.db) == 2
    assert synced(r_events).reset is False


# ---- what the cache refuses -----------------------------------------------------------------


def test_a_serial_query_for_another_session_is_error_0():
    store = CacheStore(5)
    store.update([A])
    cache = CacheSession(store)
    query = bytes([2, 1, 0x12, 0x34, 0, 0, 0, 12, 0, 0, 0, 0])
    (closed,) = cache.receive_data(query)
    assert (closed.error_code, closed.sent) == (0, True)


def test_a_router_must_not_send_a_cache_response_or_payload():
    store = CacheStore(5)
    store.update([A])
    for data in (encode_cache_response(2, 1), encode_pdu(Ipv4Prefix(2, True, 24, 24, A.prefix, 1))):
        cache = CacheSession(store)
        (closed,) = cache.receive_data(data)
        assert closed.error_code == 3 and closed.sent


def test_a_cache_with_no_data_answers_error_2_and_stays_open():
    cache = CacheSession(CacheStore(5))
    events = cache.receive_data(encode_reset_query(2))
    assert events == [Served("no-data")] and not cache.closed
    report, _ = decode_pdu(cache.data_to_send())
    assert report.code == 2


def test_two_aspa_records_for_one_customer_are_refused_by_the_store():
    with pytest.raises(ValueError, match="union"):
        CacheStore(1).update([ASPA1, ASPA2])


def test_version_2_responses_come_in_the_mandatory_order():
    store = CacheStore(1)
    store.update([A, B, C, KEY, ASPA1, v4("10.0.0.0", 8, 16, 1)])
    router, cache = connect(store)
    cache.receive_data(router.data_to_send())
    raw = cache.data_to_send()
    pdus = []
    while raw:
        pdu, used = decode_pdu(raw)
        pdus.append(pdu)
        raw = raw[used:]
    assert isinstance(pdus[0], CacheResponse) and isinstance(pdus[-1], EndOfData)
    types = [type(p).__name__ for p in pdus[1:-1]]
    assert types == ["Ipv4Prefix"] * 3 + ["Ipv6Prefix", "RouterKey", "Aspa"]
    addresses = [int(p.prefix) for p in pdus[1:4]]
    assert addresses == sorted(addresses, reverse=True)  # announcements: high to low


def test_serial_notify_for_a_known_session_is_a_hint_not_a_query():
    store = CacheStore(5)
    store.update([A])
    router, cache = connect(store)
    pump(router, cache)
    note = encode_serial_notify(2, store.session_id_for(2), 5)
    assert [type(e) for e in router.receive_data(note, 1.0)] == [Notified]
    assert router.data_to_send() == b""  # poll decides, the notify only makes it due
    router.poll(1.0)
    assert decode_pdu(router.data_to_send())[0].__class__.__name__ == "SerialQuery"
    wrong = encode_serial_notify(2, 4242, 5)
    router2, cache2 = connect(store)
    pump(router2, cache2)
    (closed,) = router2.receive_data(wrong, 1.0)
    assert closed.error_code == 0 and closed.flushed


def test_a_cache_going_away_sends_restart_or_shutdown_only_in_version_2():
    # Draft sections 8.7 and 8.8, and section 12: codes 12 and 13 exist only in version 2.
    store = CacheStore(5, intervals=Intervals(100, 50, 1000))
    store.update([A])
    for restart in (True, False):
        router, cache = connect(store)
        pump(router, cache)
        assert cache.going_away(restart=restart, text="maintenance")
        events = router.receive_data(cache.data_to_send(), 5.0)
        if restart:
            assert [type(e) for e in events] == [CacheRestarting] and len(router.db) == 1
        else:
            (closed,) = events
            assert (closed.error_code, closed.flushed) == (13, True) and len(router.db) == 0
        assert cache.closed and cache.receive_data(b"\x00") == []
    old, cache = connect(store, version=1)
    pump(old, cache)
    assert not cache.going_away(restart=True) and cache.closed
    assert cache.data_to_send() == b""
