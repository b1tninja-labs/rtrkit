"""Router polling timers (RFC 8210 section 6; the version 2 draft repeats the ranges)."""

from __future__ import annotations

import struct

import pytest

from rtrkit import EndOfData
from rtrkit.timers import DEFAULT_EXPIRE, DEFAULT_REFRESH, DEFAULT_RETRY, Intervals, PollTimer


def test_defaults_are_the_recommended_defaults():
    assert (DEFAULT_REFRESH, DEFAULT_RETRY, DEFAULT_EXPIRE) == (3600, 600, 7200)
    assert Intervals() == Intervals(3600, 600, 7200)


@pytest.mark.parametrize(
    "bad",
    [(0, 600, 7200), (86401, 600, 90000), (3600, 0, 7200), (3600, 7201, 9000), (3600, 600, 599)],
)
def test_intervals_outside_section_6_ranges_are_refused(bad):
    with pytest.raises(ValueError, match="interval"):
        Intervals(*bad)


def test_expire_must_exceed_refresh_and_retry():
    with pytest.raises(ValueError, match="larger"):
        Intervals(3600, 600, 3600)


def test_from_end_of_data_v0_has_no_timers_so_defaults():
    assert Intervals.from_end_of_data(EndOfData(0, 1, 1)) == Intervals()
    assert Intervals.from_end_of_data(EndOfData(2, 1, 1, 100, 200, 900)) == Intervals(100, 200, 900)


def test_refresh_counts_from_end_of_data():
    t = PollTimer(started_at=0)
    t.on_end_of_data(1000, Intervals(100, 50, 900))
    assert t.next_query_at() == 1100
    assert not t.query_due(1099)
    assert t.query_due(1100)


def test_serial_notify_overrides_refresh_but_not_retry():
    t = PollTimer(started_at=0)
    t.on_end_of_data(1000, Intervals(100, 50, 900))
    assert t.query_due(1001, notified=True)
    t.on_query_failed(1200)
    assert not t.query_due(1201, notified=True)


def test_retry_restarts_at_each_failure_and_downgrade_overrides_it():
    t = PollTimer(started_at=0)
    t.on_end_of_data(0, Intervals(100, 50, 900))
    t.on_query_failed(200)
    assert t.next_query_at() == 250
    t.on_query_failed(250)
    assert t.next_query_at() == 300
    assert t.query_due(251, downgraded=True)
    t.on_end_of_data(300, Intervals(100, 50, 900))
    assert t.next_query_at() == 400  # a success stops the retry countdown


def test_expire_counts_from_end_of_data_not_from_failures():
    t = PollTimer(started_at=0)
    t.on_end_of_data(1000, Intervals(100, 50, 900))
    t.on_query_failed(1500)
    assert not t.expired(1899)
    assert t.expired(1900)


def test_never_succeeded_retries_on_the_default_retry_interval():
    t = PollTimer(started_at=10)
    assert t.next_query_at() == 10 + DEFAULT_RETRY
    assert not t.expired(10**9)  # nothing held, nothing to expire


def test_cache_restart_keeps_intervals_and_shutdown_uses_the_default_retry():
    t = PollTimer(started_at=0)
    t.on_end_of_data(0, Intervals(100, 50, 900))
    t.on_cache_restart(10)
    assert t.next_query_at() == 60
    t.on_cache_shutdown(20)
    assert t.next_query_at() == 20 + DEFAULT_RETRY


def test_end_of_data_timers_out_of_range_are_kept_flagged_then_clamped_by_the_session():
    from rtrkit.serialize import decode_pdu

    # version 1, type 7, session 0, length 24, serial 7, then refresh 0, retry 9000, expire 100
    wire = struct.pack(">BBHIIIII", 1, 7, 0, 24, 7, 0, 9000, 100)
    pdu, used = decode_pdu(wire)
    assert used == 24
    # the decoder keeps them as sent and flags them
    assert (pdu.refresh, pdu.retry, pdu.expire) == (0, 9000, 100)
    assert pdu.timer_defects == ("refresh", "retry", "expire", "expire-order")
    with pytest.raises(ValueError, match="interval"):
        Intervals.from_end_of_data(pdu)
    # the session clamps them and records that it did
    timer = PollTimer(started_at=0.0)
    timer.on_end_of_data_pdu(10.0, pdu)
    assert timer.clamped == ("refresh", "retry", "expire", "expire-order")
    assert timer.intervals == Intervals(1, 7200, 7201)
    assert timer.next_query_at() == 11.0
    # a conforming one is used as sent and records nothing
    good = EndOfData(2, 1, 1, 100, 200, 900)
    assert good.timer_defects == ()
    timer.on_end_of_data_pdu(20.0, good)
    assert timer.intervals == Intervals(100, 200, 900)
    assert timer.clamped == ()
