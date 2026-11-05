"""client and server state machine: version negotiation, serials, timers (RFC 8210).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    AssertionStore = Any  # placeholder: give it a real type in the milestone that needs it
    RouterClient = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "connect",
    "serve",
]


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
