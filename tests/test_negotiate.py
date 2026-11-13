"""Version negotiation decisions (RFC 8210 section 7).

No vectors exist for this: each case below is one sentence of section 7, quoted by paragraph
in its comment, expressed as inputs and the decision the sentence demands.
"""

from __future__ import annotations

import pytest

from rtrkit.session import Role, check_established, negotiate

BOTH = frozenset({0, 1})
ONLY0 = frozenset({0})
SERIAL_NOTIFY, SERIAL_QUERY, RESET_QUERY, CACHE_RESPONSE, ERROR_REPORT = 0, 1, 2, 3, 10


def test_cache_v1_receives_v0_downgrades():
    # section 7 para 2: a v1 cache receiving a v0 query MUST downgrade (or error 4 and close).
    decision = negotiate(Role.CACHE, BOTH, 0, RESET_QUERY)
    assert (decision.action, decision.version) == ("downgrade", 0)
    assert negotiate(Role.CACHE, BOTH, 1, SERIAL_QUERY).action == "use"


def test_cache_v0only_receives_v1_sends_error_4_v0_formatted():
    # section 7 paras 4 and 7: a v0-only cache may terminate "perhaps with a version 0 Error
    # Report"; the report is written at the highest version this end speaks.
    decision = negotiate(Role.CACHE, ONLY0, 1, RESET_QUERY)
    assert decision.action == "terminate"
    assert (decision.error_code, decision.send_error_report, decision.report_version) == (
        4,
        True,
        0,
    )


def test_unknown_version_2_terminates_with_error_4():
    # section 7 para 7: a cache that supports only 0 and 1 meets a version 2 query
    decision = negotiate(Role.CACHE, BOTH, 2, RESET_QUERY)
    assert (decision.action, decision.error_code, decision.send_error_report) == (
        "terminate",
        4,
        True,
    )
    assert decision.report_version == 1
    router = negotiate(Role.ROUTER, BOTH, 2, CACHE_RESPONSE, proposed=1)
    assert (router.action, router.error_code) == ("terminate", 4)


def test_unknown_version_in_error_report_terminates_without_reply():
    # section 7 para 7 ("unless the received PDU is itself an Error Report") and 5.11 para 5
    for role, kwargs in ((Role.CACHE, {}), (Role.ROUTER, {"proposed": 1})):
        decision = negotiate(role, BOTH, 2, ERROR_REPORT, **kwargs)
        assert decision.action == "terminate"
        assert decision.send_error_report is False


def test_router_ignores_serial_notify_before_negotiation():
    # section 7 para 8: ignored "regardless of the Protocol Version field"
    for version in (0, 1, 2, 255):
        assert negotiate(Role.ROUTER, BOTH, version, SERIAL_NOTIFY, proposed=1).action == "ignore"


def test_router_downgrades_when_cache_answers_in_v0():
    # section 7 para 5: the router MUST downgrade or terminate; we downgrade
    decision = negotiate(Role.ROUTER, BOTH, 0, CACHE_RESPONSE, proposed=1)
    assert (decision.action, decision.version) == ("downgrade", 0)
    assert negotiate(Role.ROUTER, BOTH, 1, CACHE_RESPONSE, proposed=1).action == "use"


def test_router_v0_error_report_offers_a_retry_at_v0():
    # section 7 para 4: after a v0 Error Report "the router MAY retry the connection" with v0
    decision = negotiate(Role.ROUTER, BOTH, 0, ERROR_REPORT, proposed=1)
    assert (decision.action, decision.retry_version, decision.send_error_report) == (
        "terminate",
        0,
        False,
    )
    same = negotiate(Role.ROUTER, BOTH, 1, ERROR_REPORT, proposed=1)
    assert same.retry_version is None


def test_cache_first_pdu_that_is_not_a_query_is_invalid_request():
    # section 7 para 1: a router MUST start with a query; the code (3) is our reading
    decision = negotiate(Role.CACHE, BOTH, 1, CACHE_RESPONSE)
    assert (decision.action, decision.error_code) == ("terminate", 3)


ALL = frozenset({0, 1, 2})


def test_version_2_cache_negotiates_all_three_versions():
    # draft-ietf-sidrops-8210bis section 7: a cache of version C answers Q < C at Q
    assert negotiate(Role.CACHE, ALL, 2, RESET_QUERY).action == "use"
    for version in (0, 1):
        decision = negotiate(Role.CACHE, ALL, version, SERIAL_QUERY)
        assert (decision.action, decision.version) == ("downgrade", version)
    unknown = negotiate(Role.CACHE, ALL, 3, RESET_QUERY)
    assert (unknown.error_code, unknown.report_version) == (4, 2)


def test_version_2_router_downgrade_and_retry_at_the_cache_version():
    # section 7: Error Code 4 carries the cache's version C; the router retries at C
    decision = negotiate(Role.ROUTER, ALL, 1, ERROR_REPORT, proposed=2)
    assert (decision.action, decision.retry_version) == ("terminate", 1)
    assert negotiate(Role.ROUTER, ALL, 1, CACHE_RESPONSE, proposed=2).action == "downgrade"
    assert negotiate(Role.ROUTER, ALL, 2, CACHE_RESPONSE, proposed=2).action == "use"
    assert check_established(2, 1, SERIAL_QUERY).error_code == 8


def test_established_version_mismatch_drops_with_error_8():
    # section 7 para 11
    decision = check_established(1, 0, SERIAL_QUERY)
    assert (decision.action, decision.error_code, decision.send_error_report) == (
        "terminate",
        8,
        True,
    )
    assert check_established(1, 1, SERIAL_QUERY).action == "use"


def test_established_mismatch_in_error_report_drops_silently():
    decision = check_established(1, 0, ERROR_REPORT)
    assert (decision.action, decision.send_error_report) == ("terminate", False)


@pytest.mark.parametrize("version", [255, 3, 128])
def test_version_255_and_friends_are_unknown(version):
    assert negotiate(Role.CACHE, BOTH, version, RESET_QUERY).error_code == 4


def test_unsupported_sets_and_missing_proposal_are_programming_errors():
    with pytest.raises(ValueError, match="supported"):
        negotiate(Role.CACHE, frozenset({3}), 1, RESET_QUERY)
    with pytest.raises(ValueError, match="supported"):
        negotiate(Role.CACHE, frozenset(), 1, RESET_QUERY)
    with pytest.raises(ValueError, match="propose"):
        negotiate(Role.ROUTER, BOTH, 1, CACHE_RESPONSE)
