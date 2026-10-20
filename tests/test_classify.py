import json

import pytest

from odnas.classify import (R_AUTH, R_CRIT_RETRY, R_CRITICAL, R_OK, R_RETRY, R_SAFETY, R_TIMEOUT, R_USAGE,
                            classify, delta_summary, parse_deltas, parse_json_log)
from odnas.entra import AUTH_CA, AUTH_OK, AUTH_REAUTH, AUTH_TRANSIENT, TokenResult, classify_auth_error

pytestmark = pytest.mark.smoke


def jl(*objs):
    return "\n".join(json.dumps(o) for o in objs)


OK_LOG = jl({"level": "info", "msg": "Bisync successful", "source": "bisync/operations.go:218"})
# exact v1.75.2 lines (captured from the real binary; SPEC v0.2 §9.4 table)
MAXDEL = {"level": "error", "msg": 'too many deletes (>10%, 4 of 21) on Path1 "od-x:". Run with --force if desired.',
          "object": "Safety abort", "objectType": "string", "source": "bisync/deltas.go:557"}
ABORTED_TRY_AGAIN = {"level": "notice", "msg": "Bisync aborted. Please try again.", "source": "bisync/operations.go:215"}
FAILED_MAXDEL = {"level": "notice", "msg": "Failed to bisync: too many deletes", "source": "cmd/cmd.go:334"}
CRIT_ACCESS = {"level": "error", "msg": "Bisync critical error: check file check failed"}
RETRYABLE = {"level": "error", "msg": "Bisync aborted. Error is retryable without --resync due to --resilient mode."}
LOCKOUT = {"level": "error", "msg": "Bisync aborted. Must run --resync to recover."}


@pytest.mark.parametrize("code,expected", [(1, R_RETRY), (3, R_RETRY), (4, R_RETRY), (5, R_RETRY), (6, R_RETRY),
                                           (8, R_RETRY), (10, R_RETRY), (2, R_USAGE), (7, R_CRITICAL),
                                           (9, R_CRITICAL), (-9, R_RETRY)])
def test_exit_codes_rule5_and_6(code, expected):
    assert classify(code, "").result == expected


def test_rule1_ok_needs_success_line():
    assert classify(0, OK_LOG).result == R_OK
    oc = classify(0, "")                     # exit 0 but no "Bisync successful": mismatch -> fail safe
    assert oc.result == R_CRITICAL and oc.warning


def test_rule2_safety_abort_max_delete_exit_1():
    oc = classify(1, jl(MAXDEL, ABORTED_TRY_AGAIN, FAILED_MAXDEL))
    assert oc.result == R_SAFETY and not oc.warning
    sa = oc.safety
    assert (sa.check, sa.side, sa.pct, sa.deletes, sa.total, sa.path) == ("max_delete", "Path1", 10, 4, 21, "od-x:")
    assert "4 of 21" in oc.detail and "OneDrive" in oc.detail


def test_rule2_safety_abort_any_exit_code_but_warns():
    oc = classify(7, jl(MAXDEL))
    assert oc.result == R_SAFETY and "unexpected exit 7" in oc.warning


def test_rule2_requires_object_safety_abort():
    m = dict(MAXDEL); m.pop("object"); m.pop("objectType")
    assert classify(1, jl(m)).result == R_RETRY      # same text without object="Safety abort" is not a match


def test_rule2_all_files_changed():
    oc = classify(1, jl({"level": "error", "msg": 'Safety abort: all files were changed on Path2 "/srv/x/mnt/u/". '
                                                  'Run with --force if desired.'}))
    assert oc.result == R_SAFETY and oc.safety.check == "all_files_changed" and oc.safety.side == "Path2"


def test_rule2_text_mode_golden_line():
    line = ('2026/10/20 07:00:00 ERROR : Safety abort: too many deletes (>50%, 5 of 9) on Path1 "{path1/}". '
            'Run with --force if desired.')
    oc = classify(1, line)
    assert oc.result == R_SAFETY and (oc.safety.deletes, oc.safety.total) == (5, 9)


def test_ansi_codes_stripped():
    m = dict(MAXDEL, msg="\x1b[31m" + MAXDEL["msg"] + "\x1b[0m")
    assert classify(1, jl(m)).result == R_SAFETY


def test_rule3_exit7_must_resync_is_lockout():
    oc = classify(7, jl(CRIT_ACCESS, LOCKOUT))
    assert oc.result == R_CRITICAL and "locked out" in oc.detail and not oc.warning


def test_rule4_exit7_retryable_under_resilient():
    oc = classify(7, jl({"level": "error", "msg": "Access test failed: Path1 count 1, Path2 count 0 - .springsync-check"},
                        CRIT_ACCESS, RETRYABLE))
    assert oc.result == R_CRIT_RETRY and "check file check failed" in oc.detail


def test_rule6_exit7_without_either_string_is_critical_with_warning():
    oc = classify(7, jl(CRIT_ACCESS))
    assert oc.result == R_CRITICAL and oc.warning


def test_rule6_mismatch_code_vs_text():
    assert classify(1, jl(CRIT_ACCESS, LOCKOUT)).result == R_CRITICAL       # lockout text with exit 1
    assert classify(1, jl(CRIT_ACCESS, RETRYABLE)).result == R_CRITICAL     # retryable text needs exit 7
    assert classify(0, jl({"level": "info", "msg": "Bisync successful"}, LOCKOUT)).result == R_CRITICAL


def test_delta_list_parsing_counts_only_in_summary():
    log = jl({"level": "notice", "msg": "- Path1             File was deleted                            - a/f1.txt"},
             {"level": "notice", "msg": "- Path1             File was deleted                            - f2.txt"},
             {"level": "notice", "msg": "- Path2             File is new                                 - new.txt"},
             {"level": "notice", "msg": "- Path2             Queue delete                                - p2/f1.txt"})
    d = parse_deltas(log)
    assert d["counts"]["Path1"] == {"deleted": 2} and d["counts"]["Path2"] == {"new": 1}
    assert [i["name"] for i in d["items"]] == ["a/f1.txt", "f2.txt", "new.txt"]
    s = delta_summary(d)
    assert s == "OneDrive: 2 deleted; NAS: 1 new" and "f1" not in s


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


def test_auth_and_timeout_precede_safety_abort():
    assert classify(1, jl(MAXDEL), broker_auth=AUTH_REAUTH).result == R_AUTH
    assert classify(None, jl(MAXDEL), timed_out=True).result == R_TIMEOUT


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
