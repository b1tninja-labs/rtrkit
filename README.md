# rtrkit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
No protocol behaviour is implemented: every public function raises `NotImplementedError`,
and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

rtrkit -- RPKI-to-Router protocol, both ends

RTR is the only protocol between an RPKI cache and a router, and Python cannot speak it. On PyPI there is nothing at all: rtr, rtrkit, rpki-rtr and rtr-client were all absent when checked on 2026-11-05. rtrkit is deliberately the small half of the problem. It validates nothing; it moves already validated assertions over a socket with the right serial discipline, which is exactly what makes it testable against a real router without needing a repository, and what lets rpkit stay a validator instead of growing a server.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| rov | 0.6.0 | 2025-07-09 | batch validator, no RTR |
| FRR and BIRD RTR clients | - | - | C daemons, not importable code |
| rtr, rpki-rtr, rtr-client | - | - | absent from PyPI (2026-11-05) |

What this project intends to add:

- cache server: serial discipline, reset query, cache notify, refresh and retry timers
- router client: IPv4 and IPv6 prefix records plus router-key records with the error PDU contract
- incremental and diff-only update modes that a validator like rpkit can drive directly
- a fault injector for truncated records, serial wrap and reset-query storms, the bugs routers actually ship with

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 8210 | Proposed Standard | 2017-09 | RTR version 1: PDU set, record types, error handling |
| RFC 6810 | Proposed Standard | 2013-01 | version 0, still what most routers speak |
| RFC 6480 | Informational | 2012-02 | where a cache server sits and what it must deliver |
| RFC 9324 | Proposed Standard | 2022-12 | why fresh RPKI data must not trigger a BGP route refresh |

### Errata watch

- RFC 6810 is updated by RFC 8210. Implement 8210 and negotiate down to 0 rather than writing two stacks.
- RFC 8210 reports no errata as of 2026-10-29. Re-check before the M1 freeze.

## Module layout

| Module | Responsibility |
|---|---|
| `pdu` | RTR PDU framing and every record type (RFC 8210) |
| `serialize` | endian-exact encode and decode, hostile input refusal (RFC 8210, RFC 6810) |
| `session` | client and server state machine: version negotiation, serials, timers (RFC 8210) |
| `inject` | fault injection helpers for conformance testing |

## What it does not do

- repository access or validation, which is rpkit
- BGP itself, which is pathattr
- MRT files


## Install

```bash
git clone https://github.com/b1tninja/rtrkit.git
cd rtrkit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy rtrkit
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
