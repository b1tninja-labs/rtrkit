# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation rtrkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `serialize.decode_pdu()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::test_decode_pdu` (to be written) | M1 |
| `serialize.encode_reset_query()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::test_encode_reset_query` (to be written) | M1 |
| `serialize.encode_ipv4_prefix_record()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::test_encode_ipv4_prefix_record` (to be written) | M1 |
| `serialize.encode_router_key_record()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::test_encode_router_key_record` (to be written) | M1 |
| `session.serve()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::test_serve` (to be written) | M3 |
| `session.connect()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::test_connect` (to be written) | M2 |
| `inject.truncated_record()` | design | `[ ]` | `tests/test_obligations.py::test_truncated_record` (to be written) | M4 |

## 2. Milestones

- M1 PDU codec, byte-exact, with fuzzed-input refusal
- M2 client session: reset query, serial notify, record application
- M3 server session: timers, cache notify, error PDUs, concurrent routers
- M4 fault injection suite and a loopback conformance test against itself
- M5 drive it from an rpkit assertion stream end to end
- M6 publication: 0.1.0 with the conformance trace in the docs

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 6810 is updated by RFC 8210. Implement 8210 and negotiate down to 0 rather than writing two stacks.
- RFC 8210 reports no errata as of 2026-10-29. Re-check before the M1 freeze.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| repository access or validation, which is rpkit | `[no]` | a named document requires it |
| BGP itself, which is pathattr | `[no]` | a named document requires it |
| MRT files | `[no]` | a named document requires it |

## 5. Open questions

- does the server hold a full assertion set or stream from rpkit incrementally
- M5 (drive it from an rpkit assertion stream) has no row: add one once the question above is settled, or drop the rung

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
