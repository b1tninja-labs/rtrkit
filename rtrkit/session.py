"""client and server state machine: version negotiation, serials, timers (RFC 8210; version 2
per draft-ietf-sidrops-8210bis, section 7 unchanged in substance).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Literal

from .pdu import VERSIONS, ErrorCode, PduType

if TYPE_CHECKING:
    from typing import Any

    AssertionStore = Any  # placeholder: give it a real type in the milestone that needs it
    RouterClient = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "Decision",
    "Role",
    "check_established",
    "connect",
    "negotiate",
    "serve",
]


class Role(Enum):
    """Which end of the connection is deciding."""

    ROUTER = "router"
    CACHE = "cache"


@dataclass(frozen=True, slots=True)
class Decision:
    """What to do about the PDU just received during or after version negotiation.

    ``action``: ``use`` (the version is agreed as is), ``downgrade`` (agree on a lower
    ``version``), ``ignore`` (drop this PDU, carry on) or ``terminate``. When
    ``send_error_report`` is true the caller sends an Error Report with ``error_code``,
    encoded at ``report_version``. ``retry_version`` is set when a router MAY reconnect with
    a lower version (RFC 8210 section 7, first case).
    """

    action: Literal["use", "downgrade", "ignore", "terminate"]
    version: int | None = None
    error_code: int | None = None
    send_error_report: bool = False
    report_version: int | None = None
    retry_version: int | None = None


_QUERIES = (int(PduType.SERIAL_QUERY), int(PduType.RESET_QUERY))
_ERROR_REPORT = int(PduType.ERROR_REPORT)


def _terminate(
    code: ErrorCode, pdu_type: int, supported: frozenset[int], retry: int | None = None
) -> Decision:
    # RFC 8210 section 5.11: never an Error Report for an Error Report.
    return Decision(
        "terminate",
        error_code=int(code),
        send_error_report=pdu_type != _ERROR_REPORT,
        # Section 7 does not say which version the report carries; the highest this end
        # supports is the one a peer that speaks it will read (convention, not RFC text).
        report_version=max(supported),
        retry_version=retry,
    )


def negotiate(
    role: Role,
    supported: frozenset[int],
    pdu_version: int,
    pdu_type: int,
    proposed: int | None = None,
) -> Decision:
    """Decide what the first PDU received on a connection means (RFC 8210 section 7).

    A cache receives the router's first query: a version it supports is used (a lower one
    than the cache's best is a downgrade, section 7), anything else, or a first PDU that is
    not a query, ends the session with Error Code 4 or 3 (the latter is our reading of
    "A router MUST start each transport connection by issuing either a Reset Query or a
    Serial Query"; the RFC names no code for it). A router (``proposed`` is the version
    its query carried) ignores Serial Notify whatever its version, downgrades to a lower
    supported version the cache answers with, and terminates on an Error Report, offering a
    retry at the Error Report's version when that is lower and supported. An unrecognized
    version terminates with Error Code 4 and an Error Report unless the PDU is one.
    """
    if not supported or not supported <= VERSIONS:
        raise ValueError("supported must be a non-empty subset of {0, 1, 2}")
    if role is Role.ROUTER:
        if proposed not in supported:
            raise ValueError("a router must propose a version it supports")
        if pdu_type == int(PduType.SERIAL_NOTIFY):
            return Decision("ignore")
        if pdu_version not in supported:
            return _terminate(ErrorCode.UNSUPPORTED_PROTOCOL_VERSION, pdu_type, supported)
        if pdu_type == _ERROR_REPORT:
            lower = pdu_version if pdu_version < proposed else None
            return Decision("terminate", retry_version=lower)
        if pdu_version == proposed:
            return Decision("use", version=pdu_version)
        if pdu_version < proposed:
            return Decision("downgrade", version=pdu_version)
        # Not covered by section 7: a cache answered with a higher version than we asked for.
        return _terminate(ErrorCode.UNEXPECTED_PROTOCOL_VERSION, pdu_type, supported)
    if pdu_type == _ERROR_REPORT:
        return Decision("terminate")
    if pdu_version not in supported:
        return _terminate(ErrorCode.UNSUPPORTED_PROTOCOL_VERSION, pdu_type, supported)
    if pdu_type not in _QUERIES:
        return _terminate(ErrorCode.INVALID_REQUEST, pdu_type, supported)
    if pdu_version < max(supported):
        return Decision("downgrade", version=pdu_version)
    return Decision("use", version=pdu_version)


def check_established(version: int, pdu_version: int, pdu_type: int) -> Decision:
    """Apply the rule for a PDU received after negotiation (RFC 8210 section 7).

    A different Protocol Version MUST drop the session, and the party SHOULD send Error
    Code 8 unless the offending PDU was itself an Error Report.
    """
    if pdu_version == version:
        return Decision("use", version=version)
    return Decision(
        "terminate",
        error_code=int(ErrorCode.UNEXPECTED_PROTOCOL_VERSION),
        send_error_report=pdu_type != _ERROR_REPORT,
        report_version=version,
    )


def serve(store: AssertionStore, host: str, port: int) -> None:
    """Pending behaviour defined by RFC 8210.

    Not implemented yet. See the ``session.serve()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("serve() is not implemented: RFC 8210")


async def connect(host: str, port: int) -> RouterClient:
    """Pending behaviour defined by RFC 8210.

    Not implemented yet. See the ``session.connect()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("connect() is not implemented: RFC 8210")
