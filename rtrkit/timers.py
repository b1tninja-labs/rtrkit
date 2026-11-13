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

from .pdu import EndOfData
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

        ``ValueError`` if the cache sent values outside the section 6 ranges: what a router
        does with them is not specified (see ROADMAP open questions), so it is not guessed.
        """
        if pdu.refresh is None or pdu.retry is None or pdu.expire is None:
            return cls()
        return cls(pdu.refresh, pdu.retry, pdu.expire)


@dataclass(slots=True)
class PollTimer:
    """When to query next and when held data expires, for one cache session."""

    started_at: float
    intervals: Intervals = Intervals()
    data_at: float | None = None  # when the last End of Data arrived
    failed_at: float | None = None  # when the most recent failed query failed

    def on_end_of_data(self, now: float, intervals: Intervals) -> None:
        """A query succeeded: refresh and expire count from ``now``; the retry count stops."""
        self.intervals, self.data_at, self.failed_at = intervals, now, None

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
