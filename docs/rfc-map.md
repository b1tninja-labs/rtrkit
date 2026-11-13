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
| draft-ietf-sidrops-8210bis-29 | Internet-Draft (RTR version 2), 2026-11-12, expires 2027-05-16; obsoletes nothing yet but RFC 6810 and RFC 8210 are compatible with it; pinned in `rtrkit.pdu.DRAFT_8210BIS` | 2026-11 | read raw from ietf.org/archive/id on 2026-11-13: sections 1.2, 5.1, 5.7, 5.8, 5.11, 5.12, 6, 7, 8.7, 8.8, 11.2, 11.3, 12, 15 |
| draft-ietf-sidrops-aspa-profile-31 | Internet-Draft, 2026-11, expires 2027-05-14; section 3.3 gives the provider-list rules | 2026-11 | read raw 2026-11-13: sections 3.1 to 3.3 |
| draft-ietf-sidrops-aspa-verification-29 | not used here (routevalid) | 2026-10 | - |

RFC 8210 and RFC 6810 carry no errata in rfclib (2026-11-13). RFC 8608 is current with no errata.

Draft findings (2026-11-13). Every claim in the version 2 code is from the pinned draft revision
and may move: the pin is `DRAFT_8210BIS`. Re-read before each release.

- Section 5.12 requires at least one provider, ascending order, no duplicates and no AS0 beside
  others, and error code 9 for a violation. The ASPA profile (section 3.3) adds that the customer
  ASN must not appear among its own providers; that is a rule for the signed object, and the PDU
  section does not repeat it, so rtrkit does not enforce it in the PDU.
- Section 5.12: a withdrawal has Length 12 and no provider list. rtrkit reports a withdrawal that
  carries providers as code 9 (the section gives no code for it).
- Section 12 codes 9 to 13; fatal are 0, 1, 3, 5 to 11 and 13, non-fatal 2, 4 and 12.
- Section 6 repeats the RFC 8210 ranges and defaults unchanged; section 11.2 gives a total order for
  version 2 caches (SHOULD for earlier versions); section 11.3 recommends applying on End of Data.
- The draft's own numbering differs from RFC 8210 (IPv4 Prefix is 5.9 there, 5.6 in RFC 8210).
  Code comments cite the RFC numbering for RFC 8210 behaviour and say "draft" for the others.

RFC 9324 is background for `routevalid.replay`, not an RTR wire document. Neither RFC publishes
test vectors, and the draft publishes none: the byte strings in `tests/test_pdu.py` and
`tests/test_aspa.py` are hand-built from the figures.

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.
