# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

### Added

- RTR version 2 and the ASPA PDU (type 11), implemented from `draft-ietf-sidrops-8210bis-29` with
  the provider-list rules of `draft-ietf-sidrops-aspa-profile-31`; both revisions are pinned in
  `rtrkit.pdu`. Error codes 9 to 13 and `FATAL_ERRORS`. Version negotiation accepts `{0, 1, 2}`.
- `rtrkit.payload`: `PayloadDb`, all-or-nothing `apply_payload`, and the section 11.2 ordering
  (`ordering_key`, `check_order`).
- `rtrkit.timers`: `Intervals` and `PollTimer`, router refresh, retry and expire as functions of a
  clock.
- `rtrkit.router.RouterSession` and `rtrkit.cache.CacheStore` with `CacheSession`: the two ends of an RTR
  connection as sans-IO state machines (queries and responses, minimum-change Serial Query answers,
  Cache Reset, Serial Notify with its rate limit, error handling and flushing by section 12, timers,
  Cache Restart and Shutdown), tested by running them against each other in versions 0, 1 and 2.
  `pdu.pdu_type` names the type of a decoded PDU. `connect()` and `serve()` (the socket loops) still raise.

### Changed

- Version 3 is now the first unknown protocol version (it was 2); End of Data and Router Key
  accept version 2.

Nothing yet. This repository is a shell: the public surface exists as typed stubs that raise
`NotImplementedError`, and [ROADMAP.md](ROADMAP.md) lists what has to happen first.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for rtrkit.
- `rtrkit.apps` namespace reserved for composition that is not protocol behaviour.
