# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 8210 | Proposed Standard | 2017-09 | 2026-11-05 |
| RFC 6810 | Proposed Standard | 2013-01 | 2026-11-05 |
| RFC 6480 | Informational | 2012-02 | 2026-11-05 |
| RFC 9324 | Proposed Standard | 2022-12 | 2026-11-05 |
| RFC 8608 | Proposed Standard, obsoletes RFC 8208 | 2019-06 | 2026-11-13 |
| RFC 8208 | OBSOLETE (by RFC 8608); RFC 8210 section 5.1 still cites it for the SPKI; do not cite it | 2017-09 | 2026-11-13 |
| RFC 6487 | SKI of a router key (RFC 8210 section 5.1); status not yet read | - | not verified |
| RFC 6945 | RTR MIB; deliberate non-goal; status not yet read | - | not verified |
| RTR version 2, ASPA PDU | no RFC in rfclib as of 2026-11-13; drafts, owner decision on whether to follow | - | rfclib search found nothing |

RFC 8210 and RFC 6810 carry no errata in rfclib (2026-11-13). RFC 9324 is background for
`routevalid.replay`, not an RTR wire document. Neither RFC publishes test vectors: the byte
strings in `tests/test_pdu.py` are hand-built from the section 5 figures.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
