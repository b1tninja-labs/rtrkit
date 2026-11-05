"""fault injection helpers for conformance testing.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

__all__ = [
    "truncated_record",
]


def truncated_record(payload: bytes, keep: int) -> bytes:
    """Pending behaviour defined by design.

    Not implemented yet. See the ``inject.truncated_record()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("truncated_record() is not implemented: design")
