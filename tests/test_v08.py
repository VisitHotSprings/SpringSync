"""SPEC v0.8 §9.5 Service mode, and the NAS health-check alert after 2 consecutive failures."""
import json
from datetime import timedelta

import pytest

from odnas import db as D
from odnas import service_mode as SM
from odnas.notify import Alerter
from tests.conftest import G_ADMINS, G_AUDIT, FakeProc, seed_user
from tests.test_runner_broker import make_worker
from tests.test_safety_abort import DELTA, MAXDEL
from tests.test_safety_v03 import actions, approve_accept, approve_restore
from tests.test_web import csrf, login, wc  # noqa: F401  (wc is a fixture)

DEL2 = [{"level": "notice", "msg": "- Path1             File was deleted                            - a.txt"},
        {"level": "notice", "msg": "- Path2             File was deleted                            - b.txt"},
        {"level": "notice", "msg": "- Path2             File was deleted                            - c.txt"}]


def flag(cmd, name):
    return cmd[cmd.index(name) + 1]


def bisync_cmds(proc):
    return [c for c, _ in proc.calls if len(c) > 1 and c[1] == "bisync"]


@pytest.fixture
def web(cfg, db, kr, entra, wc):
    from odnas.web.app import create_app
    a = create_app(cfg, db, kr, entra, wc)
    mark = login(a, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    walter = login(a, entra, oid="w", upn="walter@hotsprings.org", groups=(G_AUDIT,))
    return mark, csrf(mark, "/admin"), walter


# ---- effect on runs -------------------------------------------------------------------------------

def test_user_scope_bisync_gets_max_delete_100_never_force(cfg, db, kr, entra):
    proc = FakeProc(log_lines=DEL2)
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 4, "folder cleanup")
    assert w.runner.run(uid, "bisync").result == "ok"
    cmd = bisync_cmds(proc)[-1]
    assert flag(cmd, "--max-delete") == "100" and "--force" not in cmd
    assert "--check-access" in cmd and "--backup-dir1" in cmd and "--backup-dir2" in cmd
    r = db.one("SELECT * FROM sync_runs WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,))
    assert (r["service_mode"], r["deletes_path1"], r["deletes_path2"]) == ("user", 1, 2)
    det = json.loads(db.audit_rows(action="run_bisync")[0]["details_json"])
    assert det["service_mode"] == "user"


def test_normal_run_keeps_user_max_delete(cfg, db, kr, entra):
    proc = FakeProc()
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    assert flag(bisync_cmds(proc)[-1], "--max-delete") == "10"
    assert db.one("SELECT service_mode FROM sync_runs WHERE user_id=?", (uid,))["service_mode"] is None


def test_all_scope_and_combination(cfg, db, kr, entra):
    proc = FakeProc()
    w, _ = make_worker(cfg, db, kr, entra, proc)
    a, b = seed_user(db, kr, upn="a@hotsprings.org"), seed_user(db, kr, upn="b@hotsprings.org")
    SM.enable_all(db, Alerter(db), "m", "mark@hotsprings.org", 2, "NAS move")
    SM.enable_user(db, Alerter(db), b, "m", "mark@hotsprings.org", 6, "cleanup")
    for uid in (a, b):
        w.runner.run(uid, "bisync")
        assert flag(bisync_cmds(proc)[-1], "--max-delete") == "100"
    tags = [r["service_mode"] for r in db.all("SELECT service_mode FROM sync_runs ORDER BY id")]
    assert tags == ["all", "all"]                                   # all-users takes precedence as the tag
    SM.disable_all(db, Alerter(db), "m", "mark@hotsprings.org")
    w.runner.run(a, "bisync"); w.runner.run(b, "bisync")
    assert [flag(c, "--max-delete") for c in bisync_cmds(proc)[-2:]] == ["10", "100"]   # b still selected


def test_skips_onboarding_users(cfg, db, kr, entra):
    proc = FakeProc()
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr, onboarding_completed_at=None)
    SM.enable_all(db, Alerter(db), "m", "mark@hotsprings.org", 4, "cleanup")
    w.runner.run(uid, "bisync")
    assert flag(bisync_cmds(proc)[-1], "--max-delete") == "10"


def test_not_applied_to_restore_accept_or_delta_and_keeps_safety_abort(cfg, db, kr, entra):
    proc = FakeProc(exit_codes=[1], log_lines=MAXDEL)
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    assert db.user(uid)["state"] == D.SAFETY_ABORT
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 4, "cleanup")
    SM.enable_all(db, Alerter(db), "m", "mark@hotsprings.org", 4, "cleanup")
    assert db.user(uid)["state"] == D.SAFETY_ABORT                  # existing pause not cleared
    w.runner.proc = proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    w.runner.run(uid, "delta")
    approve_accept(db, uid, 0, 2, at=D.utcnow() - timedelta(hours=1))
    w.runner.run(uid, "force")
    cmds = bisync_cmds(proc)
    assert len(cmds) == 3 and all(flag(c, "--max-delete") == "10" for c in cmds)
    assert all(r["service_mode"] is None for r in db.all("SELECT service_mode FROM sync_runs"))


def test_restore_run_not_in_service_mode(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1], log_lines=MAXDEL))
    uid = seed_user(db, kr)
    w.runner.run(uid, "bisync")
    w.runner.proc = FakeProc(exit_codes=[0], log_lines=DELTA)
    w.runner.run(uid, "delta")
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 4, "cleanup")
    approve_restore(db, uid)
    w.runner.proc = proc = FakeProc()
    w.runner.run(uid, "resync")
    assert flag(bisync_cmds(proc)[-1], "--max-delete") == "10"
    with pytest.raises(ValueError):
        from odnas.bisync import JobPaths, build_bisync
        build_bisync(cfg, JobPaths(uid, 1, "/dev/null", "/m", ""), max_delete_pct=10, resync=True, service_mode=True)


def test_safety_abort_during_service_mode_is_still_safety_abort(cfg, db, kr, entra):
    allchanged = [{"level": "error", "msg": 'Safety abort: all files were changed on Path2 "/m/". Run with --force if desired.'}]
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1], log_lines=allchanged))
    uid = seed_user(db, kr)
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 4, "cleanup")
    assert w.runner.run(uid, "bisync").result == "safety_abort"
    assert db.user(uid)["state"] == D.SAFETY_ABORT


def test_global_nas_pause_blocks_service_mode_runs(cfg, db, kr, entra):
    proc = FakeProc()
    w, _ = make_worker(cfg, db, kr, entra, proc)
    seed_user(db, kr)
    SM.enable_all(db, Alerter(db), "m", "mark@hotsprings.org", 4, "cleanup")
    from odnas import settings_store
    settings_store.update(db, cfg, kr, {"nas_option": "B", "nas_svc_password": "x"}, "t")
    db.set_flag(D.NAS_GLOBAL_PAUSE, "svc-sync NAS login rejected", pw_version=db.setting_version("nas_svc_password"))
    assert w.tick(wait=True) == [] and bisync_cmds(proc) == []


# ---- window, expiry, restart ---------------------------------------------------------------------

def test_hours_limits_and_reason_required():
    assert SM.parse_hours("") == 4 and SM.parse_hours("24") == 24
    for bad in ("0", "25", "72", "x"):
        with pytest.raises(ValueError):
            SM.parse_hours(bad)
    with pytest.raises(ValueError):
        SM.parse_reason("  ")


def test_expires_at_end_time_including_after_restart(cfg, db, kr, entra, monkeypatch):
    proc = FakeProc()
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    t0 = D.utcnow()
    SM.enable_all(db, Alerter(db), "m", "mark@hotsprings.org", 1, "cleanup")
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 2, "cleanup")
    # a "restart": a brand-new worker object over the same DB, 3 h later
    w2, _ = make_worker(cfg, db, kr, entra, proc)
    later = t0 + timedelta(hours=3)
    monkeypatch.setattr(D, "utcnow", lambda: later)
    w2.tick(later, wait=True)
    assert db.flag(D.SERVICE_MODE_GLOBAL) is None and db.user_full(uid)["service_mode_until"] is None
    exp = db.audit_rows(action="service_mode_expired")
    assert len(exp) == 2 and all(r["actor"] == "system" for r in exp)
    w2.runner.run(uid, "bisync")
    assert flag(bisync_cmds(proc)[-1], "--max-delete") == "10"


def test_expired_window_is_never_applied_even_before_the_tick(cfg, db, kr, entra, monkeypatch):
    proc = FakeProc()
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 1, "cleanup")
    later = D.utcnow() + timedelta(hours=2)
    monkeypatch.setattr(D, "utcnow", lambda: later)
    w.runner.run(uid, "bisync")                               # no tick in between
    assert flag(bisync_cmds(proc)[-1], "--max-delete") == "10"


def test_run_started_inside_window_keeps_its_flags(cfg, db, kr, entra):
    w, _ = make_worker(cfg, db, kr, entra, None)
    uid = seed_user(db, kr)
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 1, "cleanup")

    class EndsMidRun(FakeProc):
        def run(self, cmd, env, timeout_s, capture=False, stderr_path=None):
            SM.disable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org")   # admin turns it off mid-run
            return super().run(cmd, env, timeout_s, capture, stderr_path)
    w.runner.proc = proc = EndsMidRun()
    w.runner.run(uid, "bisync")
    assert flag(bisync_cmds(proc)[-1], "--max-delete") == "100"
    assert db.one("SELECT service_mode FROM sync_runs WHERE user_id=?", (uid,))["service_mode"] == "user"


def test_audit_alerts_extend_and_end_summary(cfg, db, kr, entra):
    proc = FakeProc(log_lines=DEL2)
    w, _ = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    al = Alerter(db)
    SM.enable_user(db, al, uid, "m", "mark@hotsprings.org", 2, "cleanup")
    on = [i for i in db.open_issues(uid) if i["type"] == "service_mode"]
    assert len(on) == 1 and on[0]["severity"] == "low"
    SM.enable_user(db, al, uid, "m", "mark@hotsprings.org", 6, "cleanup, more time")
    ext = json.loads(db.audit_rows(action="service_mode_extended")[0]["details_json"])
    assert ext["hours"] == 6 and ext["previous_ends_at"] and ext["reason"] == "cleanup, more time"
    w.runner.run(uid, "bisync"); w.runner.run(uid, "bisync")
    rows = SM.disable_user(db, al, uid, "m", "mark@hotsprings.org")
    assert rows == [{"user_id": uid, "upn": "jsmith@hotsprings.org", "runs": 2, "deleted_onedrive": 2,
                     "deleted_nas": 4}]
    assert not [i for i in db.open_issues(uid) if i["type"] == "service_mode"]
    summ = [i for i in db.open_issues(uid) if i["type"] == "service_mode_summary"]
    assert len(summ) == 1 and "OneDrive 2, NAS 4" in summ[0]["summary"]
    assert ".txt" not in summ[0]["summary"]                         # counts only, no file names
    off = json.loads(db.audit_rows(action="service_mode_disabled")[0]["details_json"])
    assert off["scope"] == "user" and off["deletes"][0]["deleted_nas"] == 4 and off["by_upn"] == "mark@hotsprings.org"
    en = json.loads(db.audit_rows(action="service_mode_enabled")[0]["details_json"])
    assert {"scope", "hours", "ends_at", "reason", "by_upn"} <= set(en)


# ---- web: admins change, auditors see --------------------------------------------------------------

def test_admin_all_users_switch_needs_typed_confirmation_reason_and_max_24h(db, kr, web):
    mark, tok, _ = web
    url = "/admin/service-mode"
    base = {"csrf": tok, "scope": "all", "op": "on", "reason": "NAS move", "hours": "4"}
    assert mark.post(url, data=base).status_code == 400                       # no typed confirmation
    assert mark.post(url, data={**base, "confirm": "ALL USERS", "hours": "25"}).status_code == 400
    assert mark.post(url, data={**base, "confirm": "ALL USERS", "reason": ""}).status_code == 400
    assert db.flag(D.SERVICE_MODE_GLOBAL) is None
    assert mark.post(url, data={**base, "confirm": "ALL USERS"}).status_code == 303
    f = db.flag(D.SERVICE_MODE_GLOBAL)
    assert f["reason"] == "NAS move" and f["set_by_upn"] == "mark@hotsprings.org"
    page = mark.get("/admin").text
    assert "Service mode is ON" in page and "All users" in page and "Turn off now (all users)" in page
    assert mark.post(url, data={"csrf": tok, "scope": "all", "op": "off"}).status_code == 303
    assert db.flag(D.SERVICE_MODE_GLOBAL) is None and "service_mode_disabled" in actions(db)


def test_admin_selected_accounts_picker(db, kr, web):
    mark, tok, _ = web
    a = seed_user(db, kr, upn="a@hotsprings.org")
    b = seed_user(db, kr, upn="b@hotsprings.org")
    onb = seed_user(db, kr, upn="new@hotsprings.org", onboarding_completed_at=None)
    page = mark.get("/admin").text
    assert f'value="{a}"' in page and f'value="{onb}"' not in page            # onboarding users not offered
    url = "/admin/service-mode"
    assert mark.post(url, data={"csrf": tok, "scope": "selected", "op": "on", "reason": "cleanup", "hours": "4",
                                "user_id": [a, onb]}).status_code == 409      # nothing changed
    assert db.user_full(a)["service_mode_until"] is None
    assert mark.post(url, data={"csrf": tok, "scope": "selected", "op": "on", "reason": "cleanup", "hours": "4",
                                "user_id": [a, b]}).status_code == 303
    assert db.user_full(a)["service_mode_until"] and db.user_full(b)["service_mode_until"]
    assert mark.post(url, data={"csrf": tok, "scope": "selected", "op": "off", "user_id": [a]}).status_code == 303
    assert db.user_full(a)["service_mode_until"] is None and db.user_full(b)["service_mode_until"]


def test_per_user_page_toggle(db, kr, web):
    mark, tok, _ = web
    uid = seed_user(db, kr)
    assert "Turn on service mode" in mark.get(f"/admin/users/{uid}").text
    assert mark.post(f"/admin/users/{uid}/service-mode-on", data={"csrf": tok, "hours": "3"}).status_code == 400
    assert mark.post(f"/admin/users/{uid}/service-mode-on",
                     data={"csrf": tok, "hours": "3", "reason": "reorg"}).status_code == 303
    page = mark.get(f"/admin/users/{uid}").text
    assert "Extend service mode" in page and "Turn off service mode now" in page and "reorg" in page
    assert mark.post(f"/admin/users/{uid}/service-mode-off", data={"csrf": tok}).status_code == 303
    assert db.user_full(uid)["service_mode_until"] is None


def test_auditor_sees_banner_read_only_and_cannot_change(db, kr, web):
    mark, tok, walter = web
    uid = seed_user(db, kr)
    SM.enable_all(db, Alerter(db), "m", "mark@hotsprings.org", 4, "NAS move")
    page = walter.get("/audit").text
    assert "Service mode is ON" in page and "NAS move" in page and "mark@hotsprings.org" in page
    assert "/admin/service-mode" not in page and "Turn off" not in page
    upage = walter.get(f"/audit/users/{uid}").text
    assert "ON (all users)" in upage and "service-mode-on" not in upage
    wt = csrf(walter, "/audit")
    assert walter.post("/admin/service-mode", data={"csrf": wt, "scope": "all", "op": "off"}).status_code == 403
    assert walter.post(f"/admin/users/{uid}/service-mode-on",
                       data={"csrf": wt, "hours": "2", "reason": "x y z"}).status_code == 403
    assert db.flag(D.SERVICE_MODE_GLOBAL) is not None


def test_migration_7(db):
    assert db.schema_version() == 7
    cols = {r["name"] for r in db.all("PRAGMA table_info(sync_profiles)")}
    assert {"service_mode_until", "service_mode_by", "service_mode_at", "service_mode_reason"} <= cols
    rcols = {r["name"] for r in db.all("PRAGMA table_info(sync_runs)")}
    assert {"service_mode", "deletes_path1", "deletes_path2"} <= rcols


# ---- NAS health check: medium after 2 consecutive failures ----------------------------------------

def test_health_check_ok_between_failures_resets(cfg, db, kr, entra):
    from odnas import settings_store
    settings_store.update(db, cfg, kr, {"nas_option": "B", "nas_svc_password": "x"}, "t")
    w, hr = make_worker(cfg, db, kr, entra, FakeProc(), {"verify": 4})
    t0 = D.utcnow()
    w.tick(t0, wait=True)                                    # fail 1
    hr.codes["verify"] = 0
    w.tick(t0 + timedelta(minutes=16), wait=True)            # ok -> reset
    hr.codes["verify"] = 4
    w.tick(t0 + timedelta(minutes=32), wait=True)            # fail 1 again
    assert not any(i["type"] == "nas_health" for i in db.open_issues())
    w.tick(t0 + timedelta(minutes=48), wait=True)            # fail 2 in a row
    assert [i["severity"] for i in db.open_issues() if i["type"] == "nas_health"] == ["medium"]
