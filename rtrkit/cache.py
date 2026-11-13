"""The cache end of RTR sessions as sans-IO state machines (RFC 8210 sections 4 to 8 and 12).

:class:`CacheStore` is the cache's database with its Session ID, Serial Number and the history
needed to answer a Serial Query. :class:`CacheSession` is one connected router: it consumes the
router's bytes and queues the answer. Nothing here reads a socket or a clock.

Behaviour, each from the section named (draft-ietf-sidrops-8210bis-29, ``pdu.DRAFT_8210BIS``,
for version 2):

* Version negotiation is :func:`rtrkit.session.negotiate` (RFC 8210 section 7); afterwards a PDU
  of another version is Error 8 and the end of the session.
* Reset Query (section 5.4): Cache Response, every record as an announcement, End of Data. A
  store with no data answers Error 2 (section 8.4), a non-fatal error: the session goes on.
* Serial Query (section 5.3): a Session ID that is not the store's is Error 0 and the end of the
  session (section 5.1). The router's own Serial Number gets a Cache Response and an End of Data
  with nothing between. A Serial Number the store still remembers gets the minimum set of
  changes since it, which is the symmetric difference of the two states, so a change that
  cancels out is never mentioned and no record is both withdrawn and announced (section 5.3).
  Any other Serial Number gets Cache Reset (section 5.9). Matching is by identity, not order, so
  wrap-around of the 32-bit serial (section 4, RFC 1982) cannot confuse it.
* An ASPA record for a customer already held is a replacement, announced alone (draft section
  5.12), and ASPA and Router Key records are left out of sessions of versions that lack them.
* Version 2 sessions get payload PDUs in the mandatory order of draft section 11.2
  (:func:`rtrkit.payload.ordering_key`); older ones get the same order, which RFC 8210 does not
  require.
* The Session ID sent is the store's offset by the session version, so two versions never share
  one (RFC 8210 section 5.1: cache servers SHOULD NOT).
* :meth:`CacheSession.notify` queues a Serial Notify when the Serial Number has moved, at most
  once a minute (section 8.2: MUST rate-limit).
* A PDU a router must not send (anything but a query or an Error Report) is Error 3 (draft
  section 8.5); an undecodable one is reported with the code the decoder names.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from dataclasses import dataclass, replace

from .payload import ordering_key
from .pdu import (
    VERSIONS,
    Aspa,
    ErrorCode,
    ErrorReport,
    Ipv4Prefix,
    Ipv6Prefix,
    NeedMore,
    Pdu,
    PduType,
    ResetQuery,
    RouterKey,
    RtrError,
    SerialQuery,
    pdu_type,
)
from .serialize import (
    MAX_PDU_LENGTH,
    decode_pdu,
    encode_cache_reset,
    encode_cache_response,
    encode_end_of_data,
    encode_error_report,
    encode_pdu,
    encode_serial_notify,
)
from .session import Role, check_established, negotiate
from .timers import Intervals

__all__ = ["NOTIFY_INTERVAL", "CacheClosed", "CacheSession", "CacheStore", "Served"]

#: RFC 8210 section 8.2: the cache MUST NOT send Serial Notify more often than once a minute.
NOTIFY_INTERVAL = 60.0
_REPORT_BYTES = 256

Record = Ipv4Prefix | Ipv6Prefix | RouterKey | Aspa


def _canonical(pdu: Pdu) -> Record:
    """A record with the version and flag normalised, so the store holds one form."""
    if not isinstance(pdu, Ipv4Prefix | Ipv6Prefix | RouterKey | Aspa):
        raise TypeError(f"not a payload record: {pdu!r}")
    return replace(pdu, version=0, announce=True)


class CacheStore:
    """The cache's data: records, a Session ID, a Serial Number and recent history.

    ``update`` replaces the record set; the Serial Number moves (mod 2**32) only when the set
    changed, as section 5.1 ties it to a completed update. ``max_history`` states are kept, so a
    Serial Query older than that gets Cache Reset. A store is ``available`` after its first
    ``update``: until then every query is Error 2.
    """

    def __init__(
        self,
        session_id: int,
        serial: int = 0,
        *,
        intervals: Intervals = Intervals(),  # noqa: B008 - frozen, shared by design
        max_history: int = 32,
    ) -> None:
        if not 0 <= session_id <= 0xFFFF or not 0 <= serial <= 0xFFFFFFFF:
            raise ValueError("session_id is 16 bits and serial 32 bits")
        if max_history < 1:
            raise ValueError("max_history must be at least 1")
        self.session_id = session_id
        self.serial = serial
        self.intervals = intervals
        self.max_history = max_history
        self.records: frozenset[Record] = frozenset()
        self.available = False
        self._history: dict[int, frozenset[Record]] = {}

    def update(self, records: Iterable[Pdu]) -> int:
        """Install ``records`` (any payload PDUs; version and flag are ignored) as the current
        state and return the Serial Number. Duplicates collapse; two ASPA records for one
        customer are refused, since only the union may be served (draft section 5.12)."""
        new = frozenset(_canonical(pdu) for pdu in records)
        customers = [r.customer_asn for r in new if isinstance(r, Aspa)]
        if len(customers) != len(set(customers)):
            raise ValueError("two ASPA records for one customer: serve their union")
        if not self.available:
            self.available = True
        elif new == self.records:
            return self.serial
        else:
            self.serial = (self.serial + 1) & 0xFFFFFFFF
        self.records = new
        self._history[self.serial] = new
        while len(self._history) > self.max_history:
            del self._history[next(iter(self._history))]
        return self.serial

    def session_id_for(self, version: int) -> int:
        """The Session ID used in sessions of ``version``: distinct for each version."""
        return (self.session_id + version) & 0xFFFF

    def changes_since(self, serial: int) -> tuple[list[Pdu], list[Pdu]] | None:
        """(withdrawals, announcements) taking a router from ``serial`` to now, or None when the
        store no longer remembers that state (Cache Reset)."""
        old = self._history.get(serial)
        if old is None:
            return None
        replaced = {r.customer_asn for r in self.records if isinstance(r, Aspa)}
        withdrawn: list[Pdu] = [
            replace(r, announce=False)
            for r in old - self.records
            if not (isinstance(r, Aspa) and r.customer_asn in replaced)
        ]
        announced: list[Pdu] = list(self.records - old)
        return withdrawn, announced


@dataclass(frozen=True, slots=True)
class Served:
    """A query was answered: ``kind`` is ``reset``, ``serial``, ``current`` (nothing new),
    ``cache-reset`` or ``no-data``; ``announced`` and ``withdrawn`` count the records sent."""

    kind: str
    announced: int = 0
    withdrawn: int = 0


@dataclass(frozen=True, slots=True)
class CacheClosed:
    """The session ended; ``error_code`` is the code sent or received and ``sent`` whether an
    Error Report went out."""

    reason: str
    error_code: int | None = None
    sent: bool = False


CacheEvent = Served | CacheClosed


class CacheSession:
    """One router connected to a :class:`CacheStore`."""

    def __init__(self, store: CacheStore, *, supported: frozenset[int] = frozenset({0, 1, 2})):
        if not supported or not supported <= VERSIONS:
            raise ValueError("supported must be a non-empty subset of {0, 1, 2}")
        self.store = store
        self.supported = supported
        self.version: int | None = None
        self.closed = False
        self._buffer = bytearray()
        self._out = bytearray()
        self._router_serial: int | None = None
        self._notified_at: float | None = None

    def data_to_send(self) -> bytes:
        """The bytes queued for the router since the last call; the queue is emptied."""
        data = bytes(self._out)
        self._out.clear()
        return data

    def notify(self, now: float) -> bool:
        """Queue a Serial Notify if the session is established, the store has data, its Serial
        Number is not the one this router last received or was told, and a minute has passed since the last one
        (RFC 8210 section 8.2). Returns whether one was queued."""
        if self.closed or self.version is None or not self.store.available:
            return False
        if self._router_serial == self.store.serial:
            return False
        if self._notified_at is not None and now - self._notified_at < NOTIFY_INTERVAL:
            return False
        self._out += encode_serial_notify(
            self.version, self.store.session_id_for(self.version), self.store.serial
        )
        self._router_serial, self._notified_at = self.store.serial, now
        return True

    def going_away(self, *, restart: bool, text: str = "") -> bool:
        """The cache is about to become unavailable: queue Cache Restart (error 12) when it will
        be back before the routers' Expire Interval, else Cache Shutdown (error 13, which makes
        routers flush), and close the session (draft-ietf-sidrops-8210bis-29 sections 8.7 and 8.8).

        Both codes exist only in version 2 (section 12): in an older session nothing can be said,
        so nothing is queued and False is returned; the session still closes and the caller
        drops the transport. Deciding that the conditions of the sections hold is the operator's.
        """
        sent = False
        if not self.closed and self.version == 2:
            code = ErrorCode.CACHE_RESTART if restart else ErrorCode.CACHE_SHUTDOWN
            self._out += encode_error_report(2, code, b"", text)
            sent = True
        self.closed = True
        return sent

    def receive_data(self, data: bytes) -> list[CacheEvent]:
        """Take bytes from the router; return what they caused. Never raises on router input."""
        events: list[CacheEvent] = []
        if self.closed:
            return events
        self._buffer += data
        while not self.closed and len(self._buffer) >= 8:
            length = struct.unpack_from(">I", self._buffer, 4)[0]
            chunk = bytes(self._buffer[: length if 8 <= length <= MAX_PDU_LENGTH else 8])
            try:
                pdu, used = decode_pdu(chunk)
            except NeedMore:
                break
            except RtrError as error:
                is_report = self._buffer[1] == PduType.ERROR_REPORT
                self._close(
                    events,
                    str(error),
                    error.code,
                    report=None if is_report else bytes(self._buffer),
                )
                break
            raw = bytes(self._buffer[:used])
            del self._buffer[:used]
            self._handle(pdu, raw, events)
        return events

    # ---- internals --------------------------------------------------------------------------

    def _close(
        self, events: list[CacheEvent], reason: str, code: int | None, *, report: bytes | None
    ) -> None:
        sent = False
        if code is not None and report is not None:
            version = self.version if self.version is not None else max(self.supported)
            self._out += encode_error_report(version, code, report[:_REPORT_BYTES], reason)
            sent = True
        self.closed = True
        events.append(CacheClosed(reason, code, sent))

    def _handle(self, pdu: Pdu, raw: bytes, events: list[CacheEvent]) -> None:
        kind = pdu_type(pdu)
        if self.version is None:
            decision = negotiate(Role.CACHE, self.supported, pdu.version, int(kind))
            if decision.action == "terminate":
                self._close(
                    events,
                    f"version negotiation failed (error {decision.error_code})",
                    decision.error_code,
                    report=raw if decision.send_error_report else None,
                )
                return
            self.version = decision.version
        else:
            established = check_established(self.version, pdu.version, int(kind))
            if established.action == "terminate":
                self._close(
                    events,
                    f"protocol version {pdu.version} differs from the negotiated {self.version}",
                    established.error_code,
                    report=None if kind == PduType.ERROR_REPORT else raw,
                )
                return
        if isinstance(pdu, ErrorReport):
            self._close(
                events, pdu.text or f"router reported error {pdu.code}", pdu.code, report=None
            )
        elif isinstance(pdu, ResetQuery):
            self._answer_reset(events)
        elif isinstance(pdu, SerialQuery):
            self._answer_serial(pdu, raw, events)
        else:
            self._close(
                events,
                f"a router must not send {kind.name}",
                ErrorCode.INVALID_REQUEST,
                report=raw,
            )

    def _respond(self, announced: list[Pdu], withdrawn: list[Pdu]) -> tuple[int, int]:
        """Queue Cache Response, the payload in section 11.2 order, and End of Data."""
        version = self.version
        assert version is not None  # noqa: S101 - set by negotiation before any answer
        session_id = self.store.session_id_for(version)
        payload = [
            replace(pdu, version=version)
            for pdu in (*announced, *withdrawn)
            if not (isinstance(pdu, Aspa) and version < 2)
            and not (isinstance(pdu, RouterKey) and version < 1)
        ]
        payload.sort(key=ordering_key)
        self._out += encode_cache_response(version, session_id)
        for pdu in payload:
            self._out += encode_pdu(pdu)
        self._router_serial = self.store.serial  # the router now holds this state
        timers = self.store.intervals
        if version == 0:
            self._out += encode_end_of_data(0, session_id, self.store.serial)
        else:
            self._out += encode_end_of_data(
                version, session_id, self.store.serial, timers.refresh, timers.retry, timers.expire
            )
        return (
            sum(1 for pdu in payload if getattr(pdu, "announce", False)),
            sum(1 for pdu in payload if not getattr(pdu, "announce", True)),
        )

    def _no_data(self, events: list[CacheEvent]) -> bool:
        """Error 2 (section 8.4) when the store has nothing yet; the session goes on."""
        if self.store.available:
            return False
        assert self.version is not None  # noqa: S101
        self._out += encode_error_report(
            self.version, ErrorCode.NO_DATA_AVAILABLE, b"", "no data available yet"
        )
        events.append(Served("no-data"))
        return True

    def _answer_reset(self, events: list[CacheEvent]) -> None:
        if self._no_data(events):
            return
        announced, _ = self._respond(list(self.store.records), [])
        events.append(Served("reset", announced))

    def _answer_serial(self, pdu: SerialQuery, raw: bytes, events: list[CacheEvent]) -> None:
        if self._no_data(events):
            return
        assert self.version is not None  # noqa: S101
        if pdu.session_id != self.store.session_id_for(self.version):
            self._close(
                events,
                "Serial Query carries another Session ID",
                ErrorCode.CORRUPT_DATA,
                report=raw,
            )
            return
        if pdu.serial == self.store.serial:
            self._respond([], [])
            events.append(Served("current"))
            return
        changes = self.store.changes_since(pdu.serial)
        if changes is None:
            self._out += encode_cache_reset(self.version)
            events.append(Served("cache-reset"))
            return
        announced, withdrawn = self._respond(changes[1], changes[0])
        events.append(Served("serial", announced, withdrawn))
