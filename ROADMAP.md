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
| `serialize.decode_pdu()` | RFC 8210 sections 5.1 to 5.11, RFC 6810 section 5 | `[ok]` | `tests/test_pdu.py::test_decode_ipv4_prefix_roundtrip`, `tests/test_pdu.py::test_decode_short_buffer_needs_more_not_corrupt`, `tests/test_pdu.py::test_decode_length_huge_does_not_ask_for_gigabytes` | M1 |
| `serialize.encode_reset_query()` | RFC 8210 section 5.4; takes a protocol version, not a session id (the stub's signature was wrong) | `[ok]` | `tests/test_pdu.py::test_decode_reset_query_v1_bytes`, `tests/test_pdu.py::test_reset_query_takes_a_version_and_no_session` | M1 |
| `serialize.encode_ipv4_prefix_record()` | RFC 8210 section 5.6 | `[ok]` | `tests/test_pdu.py::test_decode_ipv4_prefix_roundtrip`, `tests/test_pdu.py::test_encode_emits_zero_reserved` | M1 |
| `serialize.encode_ipv6_prefix_record()` | RFC 8210 section 5.7 | `[ok]` | `tests/test_pdu.py::test_decode_ipv6_prefix_roundtrip` | M1 |
| `serialize.encode_router_key_record()` | RFC 8210 section 5.10; SPKI format per RFC 8608 | `[ok]` | `tests/test_pdu.py::test_decode_router_key_roundtrip`, `tests/test_pdu.py::test_decode_router_key_v0_refused` | M1 |
| `serialize.encode_serial_query()` | RFC 8210 section 5.3 | `[ok]` | `tests/test_pdu.py::test_decode_serial_pdus` | M1 |
| `serialize.encode_serial_notify()` | RFC 8210 section 5.2 | `[ok]` | `tests/test_pdu.py::test_decode_serial_pdus` | M1 |
| `serialize.encode_cache_response()` | RFC 8210 section 5.5 | `[ok]` | `tests/test_pdu.py::test_decode_cache_response_and_reset` | M1 |
| `serialize.encode_cache_reset()` | RFC 8210 section 5.9 | `[ok]` | `tests/test_pdu.py::test_decode_cache_response_and_reset` | M1 |
| `serialize.encode_end_of_data()` | RFC 8210 section 5.8 (v1, 24 octets), RFC 6810 section 5.8 (v0, 12 octets), timer ranges RFC 8210 section 6 | `[ok]` | `tests/test_pdu.py::test_decode_end_of_data_v0_length_12_and_v1_length_24`, `tests/test_pdu.py::test_encode_end_of_data_enforces_section_6_timers` | M1 |
| `serialize.encode_error_report()` | RFC 8210 section 5.11, codes in section 12 | `[ok]` | `tests/test_pdu.py::test_decode_error_report_roundtrip`, `tests/test_pdu.py::test_error_report_within_error_report_flagged` | M1 |
| `serialize.encode_pdu()` | RFC 8210 section 5 | `[ok]` | `tests/test_pdu.py::test_roundtrip_property_over_random_valid_pdus` | M1 |
| `session.negotiate()` | RFC 8210 section 7 | `[ok]` | `tests/test_negotiate.py::test_cache_v1_receives_v0_downgrades`, `tests/test_negotiate.py::test_router_ignores_serial_notify_before_negotiation` | M2 |
| `session.check_established()` | RFC 8210 section 7, last paragraph | `[ok]` | `tests/test_negotiate.py::test_established_version_mismatch_drops_with_error_8` | M2 |
| `session.serve()` | RFC 8210 | `[ ]` | tests/test_obligations.py::test_serve (to be written) | M3 |
| `session.connect()` | RFC 8210 | `[ ]` | tests/test_obligations.py::test_connect (to be written) | M2 |
| `inject.truncated_record()` | design; belongs with M1 as fuzz-input generation rather than after the server | `[ ]` | tests/test_obligations.py::test_truncated_record (to be written) | M1 |
| `rtr.apply-payload` | RFC 8210 sections 5.1, 5.6, 5.10 and error codes 6 and 7: announce, withdraw, Duplicate Announcement, Withdrawal of Unknown Record; a Router Key duplicate compares SKI and SPKI | `[ ]` | tests/test_obligations.py::test_apply_payload (to be written) | M2 |
| `rtr.timers` | RFC 8210 section 6: refresh, retry and expire bounds and countdown starts, as sans-IO functions of a clock | `[ ]` | tests/test_obligations.py::test_timers (to be written) | M2 |
| `serialize.decode_pdu()` interop capture | a capture from a non-Python cache (Routinator, rpki-client) committed under tests/data with source and date; until then every vector in tests/test_pdu.py is hand-built from the RFC figures and so self-referential | `[ ]` | tests/test_obligations.py::test_decode_real_cache_capture (to be written) | M4 |
| `serialize.decode_pdu()` host bits | whether a prefix PDU with bits set past Prefix Length is refused: RFC 8210 section 5.6 is silent, so the decoder accepts and preserves them; decide against a real cache | `[ ]` | tests/test_obligations.py::test_prefix_host_bits (to be written) | M1 |
| RTR version 2 and the ASPA PDU | not an RFC: rfclib has no document (searched 2026-11-13); owner decision on which drafts to follow (section 5) | `[ ]` | tests/test_obligations.py::test_version_2_aspa (to be written) | - |
| transports: SSH, TLS, TCP-MD5, TCP-AO | RFC 8210 sections 9.1 to 9.4; the stdlib covers TCP and TLS only | `[ ]` | tests/test_obligations.py::test_transports (to be written) | M3 |

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
- RFC 8210 reports no errata as of 2026-11-13 (rfclib); RFC 6810 none either. Re-check before the M1 freeze.
- RFC 8210 section 5.1 cites RFC 8208 for the Router Key SPKI. RFC 8208 is OBSOLETE (obsoleted by RFC 8608): cite RFC 8608. Recorded in `docs/rfc-map.md`.
- RFC 9324 is in the spine but is about router policy without Route Refresh, not RTR wire format; it matters to `routevalid.replay`, not here.
- RFC 6945 (RTR MIB) is a deliberate non-goal.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| repository access or validation, which is rpkit | `[no]` | a named document requires it |
| BGP itself, which is pathattr | `[no]` | a named document requires it |
| RTR MIB (RFC 6945) | `[no]` | an SNMP surface is wanted |
| MRT files | `[no]` | a named document requires it |

## 5. Open questions

- does the server hold a full assertion set or stream from rpkit incrementally (the review recommends a full set plus a bounded serial history, since Serial Query and Cache Reset need it; streaming is an optimisation)
- owner decision: which RTR drafts beyond RFC 8210 to follow (version 2, the ASPA PDU). They are outside rfclib, so no claim about their wire format can be checked here
- the codec's own caps (MAX_PDU_LENGTH 65535, SPKI must be one complete DER SEQUENCE) are not RFC text; confirm against real caches
- negotiation choices the RFC leaves open: an Error Report is written at the highest supported version, a first PDU that is not a query gets code 3, a cache answering with a higher version than proposed gets code 8
- M5 (drive it from an rpkit assertion stream) has no row: add one once the question above is settled, or drop the rung

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
