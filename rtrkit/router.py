"""The router end of one RTR session as a sans-IO state machine (RFC 8210 sections 4 to 8 and 12).

Nothing here reads a socket or a clock. The caller feeds received bytes to :meth:`receive_data`
with the current time, reads what to send from :meth:`data_to_send`, and calls :meth:`poll` when
time passes. Each call returns events describing what happened.

Behaviour, each from the section named (draft-ietf-sidrops-8210bis-29, ``pdu.DRAFT_8210BIS``,
for version 2 and for the flush rules it repeats):

* Start (RFC 8210 section 8.1): a Serial Query when the router holds a Session ID and Serial
  Number from an earlier session with this cache, otherwise a Reset Query.
* Version negotiation (section 7) is :func:`rtrkit.session.negotiate` and
  :func:`rtrkit.session.check_established`; a Serial Notify during it is ignored (section 5.2).
* Payload PDUs of a response are held and applied only on End of Data (draft section 11.3, the
  recommended transaction), all or nothing, with :func:`rtrkit.payload.apply_payload`. A Reset
  Query response replaces the whole database; a Serial Query response changes it.
* The Session ID must stay the one the Cache Response gave, and End of Data must carry the Cache
  Response's (section 5.1 and 5.8); a mismatch is Error Report 0 and a flush.
* Cache Reset answers a Serial Query (section 5.9); a Reset Query is queued at once (section 8.3
  says SHOULD first try more-preferred caches, which is the caller's decision, and the event says
  so).
* Error Report from the cache: a fatal code flushes the data and closes (draft section 12); No
  Data Available (2) keeps the data and makes the next queries Reset Queries (section 8.4);
  Cache Restart (12) keeps the data and retries on the cache's own intervals; Unsupported
  Protocol Version (4) closes without a flush and offers a retry at a lower version (section 7).
* Timers are :class:`rtrkit.timers.PollTimer`: a query goes out when it is due, a Serial Notify
  may make it due early, and held data are flushed when the Expire Interval has run out.

Library decisions where the text is silent, each listed in ROADMAP.md: a PDU the router should
never receive (a query), or a payload PDU outside a response, is Error Report 0 (corrupt data
"not specified by another error code"); more pending PDUs than ``max_pending`` is Error Report 1
(Internal Error, the section 12 example being memory).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .payload import PayloadDb, apply_payload, check_order
from .pdu import (
    FATAL_ERRORS,
    VERSIONS,
    Aspa,
    CacheReset,
    CacheResponse,
    EndOfData,
    ErrorCode,
    ErrorReport,
    Ipv4Prefix,
    Ipv6Prefix,
    NeedMore,
    Pdu,
    PduType,
    RouterKey,
    RtrError,
    SerialNotify,
    pdu_type,
)
from .serialize import (
    MAX_PDU_LENGTH,
    decode_pdu,
    encode_error_report,
    encode_reset_query,
    encode_serial_query,
)
from .session import Role, check_established, negotiate
from .timers import PollTimer

__all__ = [
    "CacheResetReceived",
    "CacheRestarting",
    "Closed",
    "Event",
    "Expired",
    "NoData",
    "Notified",
    "RouterSession",
    "Synced",
]

#: Error codes valid in a session of each version: draft section 12 sends only codes the
#: version defines, and treats an Error Report with any other code as invalid.
_CODES = {0: range(0, 9), 1: range(0, 9), 2: range(0, 14)}
_REPORT_BYTES = 256  # section 5.11 lets the Erroneous PDU be truncated


@dataclass(frozen=True, slots=True)
class Synced:
    """End of Data was applied: the database now matches ``serial`` of ``session_id``.

    ``reset`` says the whole database was replaced (a Reset Query response). ``ignored`` holds
    what a ``lenient`` session skipped (see :func:`rtrkit.payload.apply_payload`) and
    ``clamped`` the timers it had to clamp (see :class:`rtrkit.timers.PollTimer`).
    """

    session_id: int
    serial: int
    version: int
    reset: bool
    announced: int
    ignored: tuple[RtrError, ...] = ()
    clamped: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Notified:
    """A Serial Notify for this session: a hint that a query would find new data."""

    serial: int


@dataclass(frozen=True, slots=True)
class CacheResetReceived:
    """The cache cannot give an incremental update; a Reset Query is already queued.

    Section 8.3: the router SHOULD first try any more-preferred cache. A caller that does so
    abandons this session and need not send the queued bytes.
    """


@dataclass(frozen=True, slots=True)
class NoData:
    """Error 2: the cache has nothing to give yet. Data are kept; Reset Queries follow on the
    retry timer (section 8.4). The caller SHOULD try other caches meanwhile."""

    text: str


@dataclass(frozen=True, slots=True)
class CacheRestarting:
    """Error 12 (version 2): retry on the cache's own Retry Interval; the data are flushed only
    when the Expire Interval runs out (draft section 8.7)."""

    text: str


@dataclass(frozen=True, slots=True)
class Expired:
    """The Expire Interval ran out since the last End of Data: the data were flushed."""


@dataclass(frozen=True, slots=True)
class Closed:
    """The session ended. ``error_code`` is the code sent or received, ``sent`` whether an Error
    Report went out, ``flushed`` whether the database was cleared, ``retry_version`` the lower
    version a router may reconnect with (section 7)."""

    reason: str
    error_code: int | None = None
    sent: bool = False
    flushed: bool = False
    retry_version: int | None = None


Event = Synced | Notified | CacheResetReceived | NoData | CacheRestarting | Expired | Closed


@dataclass(slots=True)
class _Response:
    session_id: int
    reset: bool
    pdus: list[Pdu] = field(default_factory=list)


class RouterSession:
    """One router-to-cache session. See the module docstring for the rules it applies."""

    def __init__(
        self,
        now: float,
        *,
        supported: frozenset[int] = frozenset({0, 1, 2}),
        version: int | None = None,
        db: PayloadDb | None = None,
        session_id: int | None = None,
        serial: int | None = None,
        lenient: bool = False,
        max_pending: int = 4_000_000,
    ) -> None:
        if not supported or not supported <= VERSIONS:
            raise ValueError("supported must be a non-empty subset of {0, 1, 2}")
        self.supported = supported
        self.version = max(supported) if version is None else version
        if self.version not in supported:
            raise ValueError("version must be one of the supported versions")
        if (session_id is None) != (serial is None):
            raise ValueError("session_id and serial are given together or not at all")
        self.db = PayloadDb() if db is None else db
        self.session_id = session_id
        self.serial = serial
        self.lenient = lenient
        self.max_pending = max_pending
        self.timers = PollTimer(started_at=now)
        self.negotiated = False
        self.closed = False
        self._awaiting: str | None = None
        self._force_reset = False
        self._notified = False
        self._response: _Response | None = None
        self._buffer = bytearray()
        self._out = bytearray()

    # ---- what the caller drives -------------------------------------------------------------

    def data_to_send(self) -> bytes:
        """The bytes queued for the cache since the last call; the queue is emptied."""
        data = bytes(self._out)
        self._out.clear()
        return data

    def start(self) -> None:
        """Queue the first query (section 8.1): Serial Query when a Session ID and Serial Number
        are held, else Reset Query. Call once, right after the transport connects."""
        if self._awaiting is not None or self.closed:
            raise RuntimeError("the session has already started or is closed")
        self._send_query()

    def poll(self, now: float) -> list[Event]:
        """Time has passed: flush expired data, and send the next query if one is due."""
        events: list[Event] = []
        if self.closed:
            return events
        if self.timers.expired(now) and (self.db or self.session_id is not None):
            self._flush()
            events.append(Expired())
        if self._awaiting is None and self.timers.query_due(now, notified=self._notified):
            self._send_query()
        return events

    def receive_data(self, data: bytes, now: float) -> list[Event]:
        """Take bytes from the cache; return what they caused. Never raises on cache input."""
        events: list[Event] = []
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
                skipped = self._skip_ignorable(error)
                if skipped:
                    continue
                if skipped is None:  # an ignorable Serial Notify whose tail has not arrived
                    break
                self._on_undecodable(error, events)
                break
            raw = bytes(self._buffer[:used])
            del self._buffer[:used]
            self._handle(pdu, raw, now, events)
        return events

    # ---- internals --------------------------------------------------------------------------

    def _flush(self) -> None:
        self.db.clear()
        self.session_id = self.serial = None

    def _send_query(self) -> None:
        if self.session_id is not None and self.serial is not None and not self._force_reset:
            self._out += encode_serial_query(self.version, self.session_id, self.serial)
            self._awaiting = "serial"
        else:
            self._out += encode_reset_query(self.version)
            self._awaiting = "reset"
        self._notified = False

    def _close(
        self,
        events: list[Event],
        reason: str,
        code: int | None = None,
        *,
        report: bytes | None = None,
        flush: bool = False,
        retry_version: int | None = None,
    ) -> None:
        """End the session; ``report`` is the offending PDU when an Error Report is to be sent."""
        sent = False
        if code is not None and report is not None:
            version = self.version if self.negotiated else max(self.supported)
            self._out += encode_error_report(version, code, report[:_REPORT_BYTES], reason)
            sent = True
        if flush:
            self._flush()
        self.closed = True
        self._response = None
        events.append(Closed(reason, code, sent, flush, retry_version))

    def _skip_ignorable(self, error: RtrError) -> bool | None:
        """True when the undecodable PDU at the head of the buffer was a Serial Notify seen during
        version negotiation and has been dropped: section 5.2 says to ignore it "even if the
        Serial Notify PDU is for an unexpected protocol version". Dropped by its Length, when
        that is believable; None while the whole PDU has not arrived yet."""
        head = bytes(self._buffer[:8])
        if (
            self.negotiated
            or head[1] != PduType.SERIAL_NOTIFY
            or error.code != ErrorCode.UNSUPPORTED_PROTOCOL_VERSION
        ):
            return False
        length = int.from_bytes(head[4:8], "big")
        if not 8 <= length <= MAX_PDU_LENGTH:
            return False
        if len(self._buffer) < length:
            return None
        del self._buffer[:length]
        return True

    def _on_undecodable(self, error: RtrError, events: list[Event]) -> None:
        head = bytes(self._buffer[:8])
        is_report = head[1] == PduType.ERROR_REPORT
        code = error.code
        self._close(
            events,
            str(error),
            code,
            report=None if is_report else bytes(self._buffer),
            flush=code in FATAL_ERRORS or is_report,
        )

    def _handle(self, pdu: Pdu, raw: bytes, now: float, events: list[Event]) -> None:
        kind = pdu_type(pdu)
        if isinstance(pdu, ErrorReport):
            self._on_error_report(pdu, now, events)
            return
        if not self.negotiated:
            decision = negotiate(Role.ROUTER, self.supported, pdu.version, int(kind), self.version)
            if decision.action == "ignore":
                if isinstance(pdu, SerialNotify):
                    events.append(Notified(pdu.serial))
                return
            if decision.action == "terminate":
                self._close(
                    events,
                    f"version negotiation failed (error {decision.error_code})",
                    decision.error_code,
                    report=raw if decision.send_error_report else None,
                    flush=decision.error_code in FATAL_ERRORS,
                )
                return
            if decision.version is not None:
                self.version = decision.version
            self.negotiated = True
        else:
            established = check_established(self.version, pdu.version, int(kind))
            if established.action == "terminate":
                self._close(
                    events,
                    f"protocol version {pdu.version} differs from the negotiated {self.version}",
                    established.error_code,
                    report=raw,
                    flush=True,
                )
                return
        if isinstance(pdu, SerialNotify):
            self._on_notify(pdu, raw, events)
        elif isinstance(pdu, CacheResponse):
            self._on_cache_response(pdu, raw, events)
        elif isinstance(pdu, Ipv4Prefix | Ipv6Prefix | RouterKey | Aspa):
            self._on_payload(pdu, raw, events)
        elif isinstance(pdu, EndOfData):
            self._on_end_of_data(pdu, raw, now, events)
        elif isinstance(pdu, CacheReset):
            self._on_cache_reset(raw, events)
        else:  # a query: only a cache receives those
            self._close(
                events,
                f"unexpected {kind.name} PDU from a cache",
                ErrorCode.CORRUPT_DATA,
                report=raw,
                flush=True,
            )

    def _corrupt(self, events: list[Event], raw: bytes, reason: str) -> None:
        self._close(events, reason, ErrorCode.CORRUPT_DATA, report=raw, flush=True)

    def _on_notify(self, pdu: SerialNotify, raw: bytes, events: list[Event]) -> None:
        if self.session_id is not None and pdu.session_id != self.session_id:
            self._corrupt(events, raw, "Serial Notify carries another Session ID")
            return
        if self._awaiting is None:
            self._notified = True
        events.append(Notified(pdu.serial))

    def _on_cache_response(self, pdu: CacheResponse, raw: bytes, events: list[Event]) -> None:
        if self._awaiting is None or self._response is not None:
            self._corrupt(events, raw, "Cache Response that no query asked for")
            return
        if self._awaiting == "serial" and pdu.session_id != self.session_id:
            self._corrupt(events, raw, "Cache Response carries another Session ID")
            return
        self._response = _Response(pdu.session_id, self._awaiting == "reset")

    def _on_payload(self, pdu: Pdu, raw: bytes, events: list[Event]) -> None:
        if self._response is None:
            self._corrupt(events, raw, "payload PDU outside a Cache Response")
            return
        if len(self._response.pdus) >= self.max_pending:
            self._close(
                events,
                f"more than {self.max_pending} payload PDUs in one response",
                ErrorCode.INTERNAL_ERROR,
                report=raw,
                flush=True,
            )
            return
        self._response.pdus.append(pdu)

    def _on_end_of_data(self, pdu: EndOfData, raw: bytes, now: float, events: list[Event]) -> None:
        response = self._response
        if response is None:
            self._corrupt(events, raw, "End of Data outside a Cache Response")
            return
        if pdu.session_id != response.session_id:
            self._corrupt(events, raw, "End of Data carries another Session ID than its response")
            return
        target = PayloadDb() if response.reset else self.db
        try:
            if self.version == 2:
                check_order(response.pdus)
            ignored = apply_payload(target, response.pdus, lenient=self.lenient)
        except RtrError as error:
            self._close(events, str(error), error.code, report=raw, flush=True)
            return
        if response.reset:
            self.db.prefixes, self.db.router_keys = target.prefixes, target.router_keys
            self.db.aspas = target.aspas
        self.session_id, self.serial = response.session_id, pdu.serial
        self.timers.on_end_of_data_pdu(now, pdu)
        announced = len(response.pdus)
        self._response, self._awaiting, self._force_reset = None, None, False
        events.append(
            Synced(
                response.session_id,
                pdu.serial,
                self.version,
                response.reset,
                announced,
                ignored,
                self.timers.clamped,
            )
        )

    def _on_cache_reset(self, raw: bytes, events: list[Event]) -> None:
        if self._awaiting != "serial" or self._response is not None:
            self._corrupt(events, raw, "Cache Reset that is not the answer to a Serial Query")
            return
        self._force_reset = True
        self._awaiting = None
        self._send_query()
        events.append(CacheResetReceived())

    def _on_error_report(self, pdu: ErrorReport, now: float, events: list[Event]) -> None:
        code = pdu.code
        valid = code in _CODES.get(pdu.version, ())
        lower = (
            pdu.version
            if not self.negotiated and pdu.version in self.supported and pdu.version < self.version
            else None
        )
        if not valid:
            # Draft section 12: an invalid Error Report drops the session and flushes, unanswered.
            self._close(events, f"Error Report with invalid code {code}", flush=True)
        elif code == ErrorCode.UNSUPPORTED_PROTOCOL_VERSION:
            self._close(
                events, pdu.text or "unsupported protocol version", code, retry_version=lower
            )
        elif code == ErrorCode.NO_DATA_AVAILABLE:
            if (
                not self.negotiated
                and pdu.version in self.supported
                and pdu.version <= self.version
            ):
                self.version, self.negotiated = pdu.version, True
            self._response, self._awaiting, self._force_reset = None, None, True
            self.timers.on_query_failed(now)
            events.append(NoData(pdu.text))
        elif code == ErrorCode.CACHE_RESTART:
            self._response, self._awaiting = None, None
            self.timers.on_cache_restart(now)
            events.append(CacheRestarting(pdu.text))
        else:
            if code == ErrorCode.CACHE_SHUTDOWN:
                self.timers.on_cache_shutdown(now)
            self._close(events, pdu.text or f"cache reported error {code}", code, flush=True)
