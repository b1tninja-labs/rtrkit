"""Router-side polling timers as pure functions of a clock (RFC 8210 section 6).

Sans-IO: every method takes ``now``, a number of seconds from any monotonic clock, and no
method reads one. Intervals are in seconds. The version 2 draft (``rtrkit.pdu.DRAFT_8210BIS``
section 6) repeats the RFC 8210 section 6 ranges and defaults unchanged.

Rules implemented, from section 6:

* Refresh: poll no sooner than ``refresh`` after the End of Data that carried it; a Serial
  Notify overrides it and allows an immediate query.
* Retry: after a failed query, retry no sooner than ``retry`` after the failure, restarting at
  each further failure; a version downgrade overrides it and allows an immediate query.
* Expire: the data MUST NOT be kept past ``expire`` after the End of Data; the router flushes.
* A router that has never had a successful query retries periodically using the default Retry
  Interval, counted from when it started.
* Cache Restart (section 8.7) keeps the cache's own intervals; Cache Shutdown (section 8.8)
  falls back to the default Retry Interval.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .pdu import EXPIRE_RANGE, REFRESH_RANGE, RETRY_RANGE, EndOfData
from .serialize import _check_timers

__all__ = [
    "DEFAULT_EXPIRE",
    "DEFAULT_REFRESH",
    "DEFAULT_RETRY",
    "Intervals",
    "PollTimer",
]

DEFAULT_REFRESH = 3600
DEFAULT_RETRY = 600
DEFAULT_EXPIRE = 7200


@dataclass(frozen=True, slots=True)
class Intervals:
    """The three section 6 intervals; construction refuses values outside the allowed ranges
    and an Expire Interval not larger than both Refresh and Retry."""

    refresh: int = DEFAULT_REFRESH
    retry: int = DEFAULT_RETRY
    expire: int = DEFAULT_EXPIRE

    def __post_init__(self) -> None:
        _check_timers(self.refresh, self.retry, self.expire)

    @classmethod
    def from_end_of_data(cls, pdu: EndOfData) -> Intervals:
        """The intervals an End of Data carries; a version 0 one carries none, so defaults.

        ``ValueError`` if the cache sent values outside the section 6 ranges: this method never
        guesses. A session that wants to carry on uses :meth:`clamp_end_of_data`.
        """
        if pdu.refresh is None or pdu.retry is None or pdu.expire is None:
            return cls()
        return cls(pdu.refresh, pdu.retry, pdu.expire)

    @classmethod
    def clamp_end_of_data(cls, pdu: EndOfData) -> tuple[Intervals, tuple[str, ...]]:
        """The intervals a session uses for an End of Data, and what it had to change.

        Timers inside the section 6 ranges are used as sent. One outside its range is clamped to
        the nearest end of it, and an Expire not larger than Refresh and Retry is raised to one
        more than the larger of them. The second item is ``pdu.timer_defects``: the names of
        what was clamped, empty when nothing was. The PDU itself is never altered.
        """
        defects = pdu.timer_defects
        if not defects or pdu.refresh is None or pdu.retry is None or pdu.expire is None:
            return cls.from_end_of_data(pdu), ()
        refresh = min(max(pdu.refresh, REFRESH_RANGE[0]), REFRESH_RANGE[1])
        retry = min(max(pdu.retry, RETRY_RANGE[0]), RETRY_RANGE[1])
        expire = min(max(pdu.expire, EXPIRE_RANGE[0]), EXPIRE_RANGE[1])
        if expire <= max(refresh, retry):
            expire = max(refresh, retry) + 1  # at most 86401, inside the Expire range
        return cls(refresh, retry, expire), defects


@dataclass(slots=True)
class PollTimer:
    """When to query next and when held data expires, for one cache session."""

    started_at: float
    intervals: Intervals = Intervals()
    data_at: float | None = None  # when the last End of Data arrived
    failed_at: float | None = None  # when the most recent failed query failed
    clamped: tuple[str, ...] = ()  # which timers of the last End of Data were clamped

    def on_end_of_data(self, now: float, intervals: Intervals) -> None:
        """A query succeeded: refresh and expire count from ``now``; the retry count stops."""
        self.intervals, self.data_at, self.failed_at = intervals, now, None

    def on_end_of_data_pdu(self, now: float, pdu: EndOfData) -> None:
        """As :meth:`on_end_of_data` for a decoded End of Data: out-of-range timers are clamped
        (:meth:`Intervals.clamp_end_of_data`) and ``clamped`` records which ones."""
        intervals, self.clamped = Intervals.clamp_end_of_data(pdu)
        self.on_end_of_data(now, intervals)

    def on_query_failed(self, now: float) -> None:
        """A query failed: the retry countdown (re)starts at ``now``."""
        self.failed_at = now

    def on_cache_restart(self, now: float) -> None:
        """Cache Restart (error 12): retry periodically on the intervals the cache gave."""
        self.on_query_failed(now)

    def on_cache_shutdown(self, now: float) -> None:
        """Cache Shutdown (error 13): retry using the *default* Retry Interval, and the
        data are to be flushed by the caller (fatal)."""
        self.intervals = replace(self.intervals, retry=DEFAULT_RETRY)
        self.on_query_failed(now)

    def next_query_at(self) -> float:
        """Earliest time a Serial or Reset Query is allowed, ignoring overrides."""
        if self.failed_at is not None:
            return self.failed_at + self.intervals.retry
        if self.data_at is not None:
            return self.data_at + self.intervals.refresh
        return self.started_at + DEFAULT_RETRY

    def query_due(self, now: float, *, notified: bool = False, downgraded: bool = False) -> bool:
        """True when a query may be sent now. A Serial Notify (``notified``) overrides Refresh,
        and a protocol version downgrade (``downgraded``) overrides Retry."""
        if downgraded and self.failed_at is not None:
            return True
        if notified and self.failed_at is None and self.data_at is not None:
            return True
        return now >= self.next_query_at()

    def expired(self, now: float) -> bool:
        """True when the held data must be flushed: ``expire`` has elapsed since End of Data."""
        return self.data_at is not None and now >= self.data_at + self.intervals.expire
