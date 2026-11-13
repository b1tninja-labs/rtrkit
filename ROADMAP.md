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
| `session.negotiate()` | RFC 8210 section 7; version 2 per draft-ietf-sidrops-8210bis-29 section 7 (same rules, versions `{0, 1, 2}`) | `[ok]` | `tests/test_negotiate.py::test_cache_v1_receives_v0_downgrades`, `tests/test_negotiate.py::test_router_ignores_serial_notify_before_negotiation`, `tests/test_negotiate.py::test_version_2_cache_negotiates_all_three_versions`, `tests/test_negotiate.py::test_version_2_router_downgrade_and_retry_at_the_cache_version` | M2 |
| `session.check_established()` | RFC 8210 section 7, last paragraph | `[ok]` | `tests/test_negotiate.py::test_established_version_mismatch_drops_with_error_8` | M2 |
| `session.serve()` | RFC 8210 | `[ ]` | tests/test_obligations.py::test_serve (to be written) | M3 |
| `session.connect()` | RFC 8210 | `[ ]` | tests/test_obligations.py::test_connect (to be written) | M2 |
| `inject.truncated_record()` | design; belongs with M1 as fuzz-input generation rather than after the server | `[ ]` | tests/test_obligations.py::test_truncated_record (to be written) | M1 |
| `payload.apply_payload()` | RFC 8210 sections 5.1, 5.6, 5.7, 5.10 and error codes 6 and 7; ASPA replacement and withdrawal per draft-ietf-sidrops-8210bis-29 section 5.12; all-or-nothing batches per section 11.3. A Router Key duplicate compares SKI, ASN and SPKI. Strict: a duplicate or unknown withdrawal raises, although the draft lets an implementor ignore it (section 12) | `[ok]` | `tests/test_payload.py::test_duplicate_announcement_is_code_7_and_leaves_the_database_unchanged`, `tests/test_payload.py::test_withdrawal_of_unknown_is_code_6`, `tests/test_payload.py::test_router_key_duplicate_compares_ski_spki_and_asn`, `tests/test_payload.py::test_aspa_announce_replaces_and_withdraw_removes_the_whole_record` | M2 |
| `payload.check_order()` | draft-ietf-sidrops-8210bis-29 section 11.2 (total order, MUST for version 2 caches) and error code 11; `ordering_key` is the sort key a cache sends in | `[ok]` | `tests/test_payload.py::test_ordering_prefix_announcements_high_to_low_and_as0_last`, `tests/test_payload.py::test_ordering_withdrawal_as0_first_and_type_order`, `tests/test_payload.py::test_ordering_router_keys_and_aspa` | M3 |
| `timers.poll-timer` | `timers.PollTimer` and `Intervals`: RFC 8210 section 6 and draft section 6 (same ranges and defaults): refresh and expire count from End of Data, retry restarts at each failure, Serial Notify overrides refresh, a downgrade overrides retry, never-succeeded retries on the default; a function of a clock, no clock read | `[ok]` | `tests/test_timers.py::test_refresh_counts_from_end_of_data`, `tests/test_timers.py::test_retry_restarts_at_each_failure_and_downgrade_overrides_it`, `tests/test_timers.py::test_expire_counts_from_end_of_data_not_from_failures`, `tests/test_timers.py::test_serial_notify_overrides_refresh_but_not_retry`, `tests/test_timers.py::test_intervals_outside_section_6_ranges_are_refused` | M2 |
| `timers.cache-restart-shutdown` | draft sections 8.7 and 8.8: after Cache Restart (error 12, non-fatal) retry on the cache's own Retry Interval and flush only at its Expire Interval; after Cache Shutdown (error 13, fatal) retry on the default Retry Interval and flush now. The timer side is done; sending these errors is a `session.serve()` matter | `[part]` | `tests/test_timers.py::test_cache_restart_keeps_intervals_and_shutdown_uses_the_default_retry` | M3 |
| `serialize.decode_pdu()` interop capture | a capture from a non-Python cache (Routinator, rpki-client) committed under tests/data with source and date; until then every vector in tests/test_pdu.py is hand-built from the RFC figures and so self-referential | `[ ]` | tests/test_obligations.py::test_decode_real_cache_capture (to be written) | M4 |
| `serialize.decode_pdu()` host bits | whether a prefix PDU with bits set past Prefix Length is refused: RFC 8210 section 5.6 is silent, so the decoder accepts and preserves them; decide against a real cache | `[ ]` | tests/test_obligations.py::test_prefix_host_bits (to be written) | M1 |
| `serialize.encode_aspa()` | RTR version 2 and the ASPA PDU: draft-ietf-sidrops-8210bis-29 section 5.12 (a draft, not an RFC; pinned as `pdu.DRAFT_8210BIS`) with the provider-list rules of draft-ietf-sidrops-aspa-profile-31 section 3.3. Announce needs at least one provider, ascending, no duplicates, AS0 alone; a withdrawal is Length 12; violations are error code 9; ASPA before version 2 is code 5 | `[ok]` | `tests/test_aspa.py::test_aspa_announce_roundtrip_matches_figure_11`, `tests/test_aspa.py::test_aspa_withdrawal_is_length_12_with_no_providers`, `tests/test_aspa.py::test_aspa_bad_provider_list_is_error_code_9`, `tests/test_aspa.py::test_aspa_is_refused_before_version_2` | M1 |
| `serialize.encode_error_report()` codes 9 to 13 | draft section 12: codes 9 to 13 (ASPA Provider List Error, Transport Failure, Ordering Error, Cache Restart, Cache Shutdown) are sent only in version 2 sessions; fatal set in `pdu.FATAL_ERRORS` | `[ok]` | `tests/test_aspa.py::test_error_codes_9_to_13_are_sent_only_in_version_2_sessions`, `tests/test_aspa.py::test_error_codes_9_to_13_and_which_are_fatal` | M1 |
| `serialize.decode_pdu()` version 2 | draft sections 5.1, 5.7 and 5.11: version 2 End of Data has the version 1 shape, Router Key is valid in versions 1 and 2, prefix PDUs are unchanged | `[ok]` | `tests/test_aspa.py::test_version_2_end_of_data_has_the_version_1_shape`, `tests/test_aspa.py::test_version_2_router_key_and_queries`, `tests/test_aspa.py::test_version_2_prefix_pdus_are_unchanged_in_shape` | M1 |
| `serialize.decode_pdu()` version 2 interop | a capture of version 2 and ASPA from a non-Python cache (Routinator, rpki-client, StayRTR) under tests/data with source and date; the version 2 vectors are hand-built from Figure 11 and so self-referential. The draft is at revision 29: a later revision may move the wire | `[ ]` | tests/test_obligations.py::test_decode_v2_cache_capture (to be written) | M4 |
| `timers.Intervals()` from the wire | what a router does with an End of Data whose timers are outside the section 6 ranges is not specified (the text says what a cache sets, not what a router tolerates). `Intervals.from_end_of_data` raises `ValueError` while the decoder accepts the PDU. Decide: clamp, or refuse with code 0 | `[ ]` | tests/test_obligations.py::test_timers_out_of_range_from_cache (to be written) | M2 |
| `aspa.customer-in-providers` | draft-ietf-sidrops-aspa-profile-31 section 3.3 forbids the customer ASN among its providers; draft-ietf-sidrops-8210bis-29 section 5.12 lists no such PDU rule, so rtrkit does not check it. Revisit when the drafts agree | `[ ]` | tests/test_obligations.py::test_aspa_customer_in_providers (to be written) | - |
| `session.cache-restart-shutdown` | draft sections 8.7 and 8.8: a cache MUST send Cache Restart (12) or Cache Shutdown (13) when it is about to become unavailable on those conditions; needs `session.serve()` | `[ ]` | tests/test_obligations.py::test_serve_sends_restart_shutdown (to be written) | M3 |
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
- RFC 8210 reports no errata as of 2026-11-13 (rfclib, re-checked this round); RFC 6810 none either; RFC 8608 none. Re-check before the M1 freeze.
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
- the drafts: version 2 follows draft-ietf-sidrops-8210bis-29 and the ASPA content rules draft-ietf-sidrops-aspa-profile-31 (2026-11-13 fan-out decision). Neither is in rfclib; both were read raw from ietf.org/archive/id (the primarysource `draft` collection is the planned home). A new revision means re-reading sections 5.12, 6, 11 and 12 and moving `pdu.DRAFT_8210BIS`
- the codec's own caps (MAX_PDU_LENGTH 65535, SPKI must be one complete DER SEQUENCE) are not RFC text; confirm against real caches
- negotiation choices the RFC leaves open: an Error Report is written at the highest supported version, a first PDU that is not a query gets code 3, a cache answering with a higher version than proposed gets code 8
- M5 (drive it from an rpkit assertion stream) has no row: add one once the question above is settled, or drop the rung

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
