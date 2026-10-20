import json

import pytest

from odnas.classify import (R_AUTH, R_CRITICAL, R_ERROR, R_OK, R_RETRY, R_TIMEOUT, classify, parse_json_log)
from odnas.entra import AUTH_CA, AUTH_OK, AUTH_REAUTH, AUTH_TRANSIENT, TokenResult, classify_auth_error

pytestmark = pytest.mark.smoke


def jl(*objs):
    return "\n".join(json.dumps(o) for o in objs)


@pytest.mark.parametrize("code,expected", [(0, R_OK), (1, R_RETRY), (3, R_RETRY), (4, R_RETRY), (5, R_RETRY),
                                           (6, R_RETRY), (2, R_ERROR), (7, R_CRITICAL), (9, R_ERROR)])
def test_exit_codes(code, expected):
    assert classify(code, "").result == expected


@pytest.mark.parametrize("err,desc,expected", [
    ("invalid_grant", "AADSTS700082: The refresh token has expired due to inactivity", AUTH_REAUTH),
    ("invalid_grant", "AADSTS50173: The provided grant has expired due to it being revoked", AUTH_REAUTH),
    ("invalid_grant", "AADSTS50076: Due to a configuration change made by your administrator", AUTH_REAUTH),
    ("interaction_required", "AADSTS50078: Presented multi-factor authentication has expired", AUTH_REAUTH),
    ("interaction_required", "", AUTH_REAUTH),
    ("invalid_grant", "", AUTH_REAUTH),
    ("invalid_grant", "AADSTS53003: Access has been blocked by Conditional Access policies.", AUTH_CA),
    ("interaction_required", "AADSTS53000: Device is not in required device state", AUTH_CA),
    ("temporarily_unavailable", "AADSTS90033", AUTH_TRANSIENT),
    ("", "", AUTH_OK),
])
def test_aadsts_classifier(err, desc, expected):
    assert classify_auth_error(err, desc) == expected


def test_error_codes_list_used():
    assert TokenResult(error="invalid_grant", error_codes=[53003]).classification == AUTH_CA


def test_broker_auth_wins():
    oc = classify(1, "", broker_auth=AUTH_REAUTH)
    assert oc.result == R_AUTH and oc.auth == AUTH_REAUTH
    assert classify(1, "", broker_auth=AUTH_CA).auth == AUTH_CA


def test_auth_detected_in_rclone_log():
    log = jl({"level": "error", "msg": 'Failed to refresh token: oauth2: "invalid_grant" "AADSTS700082: expired"'})
    oc = classify(1, log)
    assert oc.result == R_AUTH and oc.auth == AUTH_REAUTH


def test_max_delete_abort_is_critical_even_with_exit_1():
    # verified against real rclone v1.75.2: with --resilient this exits 1, not 7
    log = jl({"level": "error", "msg": 'too many deletes (>10%, 3 of 21) on Path2 "p2/". Run with --force if desired.',
              "object": "Safety abort"})
    oc = classify(1, log)
    assert oc.result == R_CRITICAL and "max-delete" in oc.detail


def test_check_access_failure_is_critical():
    log = jl({"level": "error", "msg": "Access test failed: Path1 count 1, Path2 count 0 - .springsync-check"},
             {"level": "error", "msg": "Bisync critical error: check file check failed"})
    oc = classify(7, log)
    assert oc.result == R_CRITICAL and "check-access" in oc.detail


def test_timeout():
    assert classify(None, "", timed_out=True).result == R_TIMEOUT


def test_parse_stats_and_throttle():
    log = jl({"level": "info", "msg": "x", "stats": {"transfers": 3, "deletes": 1, "bytes": 99, "errors": 0}},
             {"level": "notice", "msg": "y", "stats": {"transfers": 20, "deletes": 2, "bytes": 51, "errors": 1}},
             {"level": "error", "msg": "Too Many Requests: 429 retry after 30s"},
             {"level": "notice", "msg": "- Path1    Renaming conflict loser file.txt -> file.sync-conflict-2026-10-20-1.txt"},
             {"level": "error", "msg": "Failed to copy: path too long"})
    st = parse_json_log(log + "\nnot json\n")
    assert (st.files_copied, st.files_deleted, st.bytes, st.errors_count) == (20, 2, 51, 1)
    assert st.throttled and st.conflicts == 1 and st.unsyncable == 1
