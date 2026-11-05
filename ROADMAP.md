# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation rtrkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `serialize.decode_pdu()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::decode_pdu` |
| `serialize.encode_reset_query()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::encode_reset_query` |
| `serialize.encode_ipv4_prefix_record()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::encode_ipv4_prefix_record` |
| `serialize.encode_router_key_record()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::encode_router_key_record` |
| `session.serve()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::serve` |
| `session.connect()` | RFC 8210 | `[ ]` | `tests/test_obligations.py::connect` |
| `inject.truncated_record()` | design | `[ ]` | `tests/test_obligations.py::truncated_record` |

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
| BGP itself, which is asnkit | `[no]` | a named document requires it |
| MRT files | `[no]` | a named document requires it |

## 5. Open questions

- does the server hold a full assertion set or stream from rpkit incrementally

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
