"""SPEC v0.9: Google Drive as a per-user connected drive, one-way pull (Copy only / Mirror), safe direction
switching, backup target, Windows file-name rules. No network: FakeGoogle / FakeEntra / FakeProc only."""
import json
import os
import re
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from odnas import cloud, settings_store
from odnas import db as D
from odnas import preflight
from odnas.google import AUTH_APP, ClaimsError, GoogleTokenResult, check_claims
from odnas.notify import Alerter
from odnas.tokens import render_drive_config
from tests.conftest import CANARY_PW, CANARY_RT, G_ADMINS, G_AUDIT, G_USERS, FakeHelperRunner, claims, seed_user
from tests.test_web import csrf, login, wc  # noqa: F401  (wc is a fixture)

ROOT = Path(__file__).resolve().parent.parent
GOOGLE_RT = "CANARY-GOOGLE-REFRESH-do-not-leak-55e1"
GCLIENT = "1234567890-test.apps.googleusercontent.com"


class FakeGoogle:
    def __init__(self):
        self.claims = {}
        self.drive_email = None
        self.scope = "openid email https://www.googleapis.com/auth/drive"
        self.next_refresh = None
        self.begun = []
        self.refresh_calls = []

    def begin_auth(self, redirect_uri, hd="", login_hint=""):
        self.begun.append((redirect_uri, hd, login_hint))
        return {"state": "gst-" + os.urandom(4).hex(), "auth_uri": "https://accounts.example.invalid/auth",
                "redirect_uri": redirect_uri}

    def complete_auth(self, flow, query):
        if query.get("error"):
            return GoogleTokenResult(error=query["error"])
        return GoogleTokenResult(access_token="g-at", refresh_token=GOOGLE_RT, expires_in=3600,
                                 id_claims=dict(self.claims), scope=self.scope)

    def refresh(self, rt):
        self.refresh_calls.append(rt)
        return self.next_refresh or GoogleTokenResult(access_token="g-at-2", expires_in=3600)

    def get_drive(self, at):
        return {"id": "0Aroot", "email": self.drive_email or self.claims.get("email", "")}


def gclaims(email="jsmith@hotsprings.org", sub="g-sub-1", hd="hotsprings.org", verified=True):
    return {"sub": sub, "email": email, "hd": hd, "email_verified": verified}


# ---- migration / settings -------------------------------------------------------------------------

@pytest.mark.smoke
def test_migration_is_additive_with_safe_defaults(db, kr):
    uid = seed_user(db, kr)
    u = db.user_full(uid)
    assert (u["provider"], u["direction"], u["gdocs_mode"]) == ("onedrive", "two_way", "skip")
    cols = {r["name"] for r in db.all("PRAGMA table_info(google_credentials)")}
    assert {"refresh_token_ct", "key_id", "google_sub", "google_email", "granted_scope"} <= cols
    run_cols = {r["name"] for r in db.all("PRAGMA table_info(sync_runs)")}
    assert {"direction", "provider", "op"} <= run_cols
    # old kinds kept (no table rebuild, additive only)
    sql = db.one("SELECT sql FROM sqlite_master WHERE name='sync_runs'")["sql"]
    for k in ("bisync", "resync", "dryrun", "delta", "force", "check", "preflight"):
        assert f"'{k}'" in sql


def test_new_settings_defaults_and_validation(cfg, db, kr):
    s = settings_store.load(db, cfg, kr)
    assert s.providers() == ["onedrive", "gdrive"] or set(s.providers()) == {"onedrive", "gdrive"}
    assert s.default_direction == "two_way" and s.google_gdocs_default == "skip"
    assert s.pull_backup_target == "backup_nas" and s.backup_nas_share == "Sync-Archive"
    assert s.google_allowed_domain == "hotsprings.org"
    settings_store.update(db, cfg, kr, {"gdrive_users": "AnnA@hotsprings.org\nbob@hotsprings.org",
                                        "google_email_aliases": "anna@hotsprings.org = anna.b@hotsprings.org"}, "t")
    s = settings_store.load(db, cfg, kr)
    assert "anna@hotsprings.org" in s.gdrive_user_set()
    assert s.google_aliases()["anna@hotsprings.org"] == {"anna.b@hotsprings.org"}
    with pytest.raises(ValueError):
        settings_store.update(db, cfg, kr, {"default_direction": "push"}, "t")
    with pytest.raises(ValueError):
        settings_store.update(db, cfg, kr, {"providers_enabled": "dropbox"}, "t")


# ---- Google claims / rclone config ----------------------------------------------------------------

@pytest.mark.parametrize("c,reason", [
    (gclaims(hd=""), "not_workspace"),
    (gclaims(hd="gmail.com"), "domain_not_allowed"),
    (gclaims(verified=False), "email_not_verified"),
    (gclaims(email="someone.else@hotsprings.org"), "email_mismatch"),
    ({"email": "x@hotsprings.org", "hd": "hotsprings.org"}, "no_identity"),
])
def test_check_claims_rejects(c, reason):
    with pytest.raises(ClaimsError) as e:
        check_claims(c, "hotsprings.org", {"jsmith@hotsprings.org"})
    assert e.value.reason == reason


def test_check_claims_accepts_upn_and_alias():
    assert check_claims(gclaims(), "hotsprings.org", {"jsmith@hotsprings.org"}) == ("g-sub-1", "jsmith@hotsprings.org")
    al = gclaims(email="John.Smith@hotsprings.org")
    assert check_claims(al, "hotsprings.org", {"jsmith@hotsprings.org", "john.smith@hotsprings.org"})[1] == \
        "john.smith@hotsprings.org"


@pytest.mark.smoke
def test_drive_config_has_exactly_the_spec_keys(cfg):
    uid = "0b6c3a52-6d43-4c55-9d2b-6a1c9e1f0a11"
    tok = {"access_token": "h", "token_type": "Bearer", "expiry": "2000-01-01T00:00:00Z"}
    text = render_drive_config(replace(cfg, google_client_id=GCLIENT), uid, tok, "http://127.0.0.1:9/t")
    keys = {ln.split("=", 1)[0].strip() for ln in text.splitlines() if "=" in ln}
    assert f"[gd-{uid}]" in text
    assert keys == {"type", "client_id", "client_secret", "scope", "token_url", "token", "root_folder_id",
                    "skip_gdocs", "skip_shortcuts", "skip_dangling_shortcuts", "stop_on_upload_limit"}
    assert "skip_gdocs = true" in text
    ex = render_drive_config(cfg, uid, tok, "http://127.0.0.1:9/t", export_formats="docx,xlsx")
    assert "export_formats = docx,xlsx" in ex and "skip_gdocs = false" in ex


# ---- web: app sign-in stays Microsoft; Google is a connected drive ---------------------------------

@pytest.fixture
def gapp(cfg, db, kr, entra, wc):
    from odnas.web.app import create_app
    g = FakeGoogle()
    c2 = replace(cfg, google_client_id=GCLIENT)
    settings_store.update(db, c2, kr, {"pilot_list": "jsmith@hotsprings.org, mark@hotsprings.org, "
                                                     "bob@hotsprings.org",
                                       "gdrive_users": "jsmith@hotsprings.org"}, "test")
    return create_app(c2, db, kr, entra, wc, google=g), g


def connect(c, g, **kw):
    g.claims = gclaims(**kw)
    r = c.post("/me/google/connect", data={"csrf": csrf(c, "/me")})
    assert r.status_code == 303 and r.headers["location"].startswith("https://accounts.example.invalid"), r.text
    st = c.cookies.get("springsync_flow")
    return c.get(f"/auth/google/callback?code=x&state={st}")


@pytest.mark.smoke
def test_no_google_app_login(gapp):
    a, _ = gapp
    c = TestClient(a, follow_redirects=False)
    page = c.get("/").text
    assert "Sign in with Google" not in page and "/login/google" not in page
    assert c.get("/login/google").status_code == 404


def test_gdrive_user_signs_in_with_microsoft_then_connects_google(gapp, entra, db, kr):
    a, g = gapp
    c = login(a, entra)
    u = db.users()[0]
    assert u["provider"] == "gdrive" and u["direction"] == "two_way"
    assert db.ms_credential(u["id"]) is None           # the Microsoft token is not kept for Google users
    page = c.get("/me").text
    assert "Connect Google Drive" in page
    r = connect(c, g)
    assert r.status_code == 303 and "google_connected" in r.headers["location"], r.text
    assert g.begun[-1][1:] == ("hotsprings.org", "jsmith@hotsprings.org")   # hd + login_hint
    gc = db.google_credential(u["id"])
    assert gc["google_email"] == "jsmith@hotsprings.org" and gc["google_sub"] == "g-sub-1"
    assert db.google_refresh_token(kr, u["id"]) == GOOGLE_RT
    raw = Path(db.path).read_bytes() if hasattr(db, "path") else b""
    assert GOOGLE_RT.encode() not in raw
    assert GOOGLE_RT not in c.get("/me").text
    assert db.audit_rows(action="google_connected")
    assert db.user_full(u["id"])["preflight_requested"] in (0, 1)


def test_onedrive_user_is_unchanged(gapp, entra, db):
    a, _ = gapp
    login(a, entra, oid="b", upn="bob@hotsprings.org")
    u = db.users()[0]
    assert u["provider"] == "onedrive" and db.ms_credential(u["id"]) is not None


@pytest.mark.parametrize("kw,reason", [({"email": "other@hotsprings.org"}, "email_mismatch"),
                                       ({"hd": "evil.example"}, "domain_not_allowed")])
def test_google_connect_rejects_wrong_account(gapp, entra, db, kw, reason):
    a, g = gapp
    c = login(a, entra)
    r = connect(c, g, **kw)
    assert r.status_code == 403
    uid = db.users()[0]["id"]
    assert db.google_credential(uid) is None
    assert json.loads(db.audit_rows(action="google_connect_denied")[0]["details_json"])["reason"] == reason


def test_google_callback_needs_the_same_microsoft_session(gapp, entra, db):
    a, g = gapp
    c = login(a, entra)
    g.claims = gclaims()
    c.post("/me/google/connect", data={"csrf": csrf(c, "/me")})
    st = c.cookies.get("springsync_flow")
    other = TestClient(a, follow_redirects=False)
    other.cookies.set("springsync_flow", st)
    r = other.get(f"/auth/google/callback?code=x&state={st}")
    assert r.status_code == 303 and r.headers["location"] == "/"          # 401 -> back to the sign-in page
    assert db.google_credential(db.users()[0]["id"]) is None
    # the Microsoft callback refuses a Google flow state
    assert c.get(f"/auth/callback?code=x&state={st}").status_code in (400, 403)


def test_google_account_cannot_be_linked_to_two_users(gapp, entra, db, kr):
    a, g = gapp
    other = seed_user(db, kr, upn="z@hotsprings.org", ms=False, provider="gdrive")
    db.put_google_credential(kr, other, "x", "g-sub-1", "z@hotsprings.org", "drive")
    c = login(a, entra)
    assert connect(c, g).status_code == 409


def test_drive_account_must_match_sign_in(gapp, entra, db):
    a, g = gapp
    c = login(a, entra)
    g.drive_email = "someone@hotsprings.org"
    assert connect(c, g).status_code == 403


def test_google_disabled_provider_hides_connect(gapp, entra, db, kr, cfg):
    a, g = gapp
    settings_store.update(db, cfg, kr, {"providers_enabled": "onedrive"}, "t")
    c = login(a, entra)
    assert "Connect Google Drive" not in c.get("/me").text
    assert c.post("/me/google/connect", data={"csrf": csrf(c, "/me")}).status_code == 409


# ---- web: admin direction / provider actions; Walter read-only -------------------------------------

@pytest.fixture
def admin(gapp, entra):
    a, g = gapp
    mark = login(a, entra, oid="m", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    walter = login(a, entra, oid="w", upn="walter@hotsprings.org", groups=(G_AUDIT,))
    return a, mark, csrf(mark, "/admin"), walter


def test_admin_switch_direction_needs_a_reason_and_is_audited(admin, db, kr):
    a, mark, tok, walter = admin
    uid = seed_user(db, kr)
    r = mark.post(f"/admin/users/{uid}/set-direction", data={"csrf": tok, "direction": "pull_copy", "reason": ""})
    assert r.status_code == 400
    r = mark.post(f"/admin/users/{uid}/set-direction",
                  data={"csrf": tok, "direction": "pull_copy", "reason": "Dec 2026 move"})
    assert r.status_code == 303
    u = db.user_full(uid)
    assert u["direction_req"] == "pull_copy" and u["direction"] == "two_way"   # applied between runs
    assert db.audit_rows(action="direction_switch_requested")
    page = mark.get(f"/admin/users/{uid}").text
    assert "switch to One-way pull: Copy only" in page


def test_auditor_sees_direction_but_cannot_change_it(admin, db, kr):
    a, mark, tok, walter = admin
    uid = seed_user(db, kr, direction="pull_mirror")
    page = walter.get(f"/audit/users/{uid}")
    assert page.status_code == 200 and "One-way pull: Mirror" in page.text and "moved" in page.text
    assert "set-direction" not in page.text and "set-provider" not in page.text
    for act in ("set-direction", "set-provider", "approve-mirror-baseline", "safety-retry"):
        assert walter.post(f"/admin/users/{uid}/{act}", data={"csrf": tok}).status_code in (401, 403)


def test_set_provider_needs_upn_and_erases_credentials(admin, db, kr):
    a, mark, tok, _ = admin
    uid = seed_user(db, kr)
    r = mark.post(f"/admin/users/{uid}/set-provider",
                  data={"csrf": tok, "provider": "gdrive", "reason": "moving to Google", "confirm": "nope"})
    assert r.status_code == 400 and db.ms_credential(uid) is not None
    r = mark.post(f"/admin/users/{uid}/set-provider", data={"csrf": tok, "provider": "gdrive",
                                                            "reason": "moving to Google",
                                                            "confirm": "jsmith@hotsprings.org"})
    assert r.status_code == 303
    u = db.user_full(uid)
    assert u["provider"] == "gdrive" and u["state"] == D.ONBOARDING and db.ms_credential(uid) is None
    assert db.nas_credential(kr, uid)       # the NAS login is kept
    assert db.audit_rows(action="admin_set_provider")


def test_restore_is_refused_for_one_way_users(admin, db, kr):
    a, mark, tok, _ = admin
    uid = seed_user(db, kr, direction="pull_mirror", mirror_baseline_ok_at="2026-10-01T00:00:00+00:00",
                    state=D.SAFETY_ABORT)
    db.update_profile(uid, safety_abort_at=D.iso(D.utcnow()), safety_abort_json=json.dumps({"check": "max_delete"}),
                      safety_delta_at=D.iso(D.utcnow()))
    assert mark.post(f"/admin/users/{uid}/safety-restore", data={"csrf": tok}).status_code == 409
    r = mark.post(f"/admin/users/{uid}/safety-switch-copy", data={"csrf": tok, "reason": "keep NAS files"})
    assert r.status_code == 303 and db.user_full(uid)["direction_req"] == "pull_copy"


def test_gdocs_export_refused_for_two_way(admin, db, kr):
    a, mark, tok, _ = admin
    uid = seed_user(db, kr, ms=False, provider="gdrive")
    r = mark.post(f"/admin/users/{uid}/set-gdocs-mode", data={"csrf": tok, "gdocs_mode": "export"})
    assert r.status_code == 400 and db.user_full(uid)["gdocs_mode"] == "skip"


def test_backup_test_button_sets_worker_flag(admin, db):
    a, mark, tok, _ = admin
    tok = csrf(mark, "/admin/settings")
    assert mark.post("/admin/settings/backup-test", data={"csrf": tok}).status_code == 303
    assert db.flag("backup_test_requested") is not None
    assert "Test backup target" in mark.get("/admin/settings").text


# ---- runner: one-way pull ---------------------------------------------------------------------------

@dataclass
class PullProc:
    """FakeProc for one-way runs: lsf answers with the check file, the counting dry-run writes a
    --combined report, real runs write a JSON log."""
    combined: str = ""
    exit_codes: dict = field(default_factory=dict)       # op -> exit code
    log_lines: list = field(default_factory=list)
    cloud_has_check: bool = True
    calls: list = field(default_factory=list)

    def run(self, cmd, env, timeout_s, capture=False, stderr_path=None):
        from odnas.runner import ProcResult
        self.calls.append(cmd)
        op = cmd[1]
        if op == "lsf":
            names = ".springsync-check\n" if (self.cloud_has_check or not cmd[2].endswith(":")) else ""
            return ProcResult(0, False, names)
        if op in ("lsjson", "about"):
            return ProcResult(0, False, "[]")
        if "--combined" in cmd:
            Path(cmd[cmd.index("--combined") + 1]).write_text(self.combined)
        code = self.exit_codes.get("dry" if "--dry-run" in cmd else op, 0)
        if "--log-file" in cmd:
            p = Path(cmd[cmd.index("--log-file") + 1])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("\n".join(json.dumps(x) for x in self.log_lines) + "\n")
        return ProcResult(code, False, "")


def pulls(proc, op=None):
    return [c for c in proc.calls if c[1] in ("copy", "sync") and (op is None or c[1] == op)]


def flag(cmd, name):
    return cmd[cmd.index(name) + 1]


def combined(same=0, changed=0, nas_only=0, new=0):
    return "\n".join([f"= s{i}" for i in range(same)] + [f"* c{i}" for i in range(changed)]
                     + [f"- n{i}" for i in range(nas_only)] + [f"+ w{i}" for i in range(new)]) + "\n"


@pytest.fixture
def pw(cfg, db, kr, entra):
    from odnas.nas import MountHelperClient
    from odnas.worker import Worker

    def make(proc, target="same_share"):
        settings_store.update(db, cfg, kr, {"pull_backup_target": target}, "t")
        hr = FakeHelperRunner(None, mnt_root=cfg.p_mnt)
        return Worker(cfg, db, kr, entra, proc=proc, helper=MountHelperClient(cfg, hr), google=FakeGoogle())
    return make


@pytest.mark.smoke
def test_copy_only_uses_rclone_copy_and_never_deletes(pw, db, kr):
    proc = PullProc()
    w = pw(proc)
    uid = seed_user(db, kr, direction="pull_copy")
    assert w.runner.run(uid, "bisync").result == "ok"
    (cmd,) = pulls(proc)
    assert cmd[1] == "copy" and "--max-delete" not in cmd and "--delete-after" not in cmd
    assert re.search(r"/\.springsync-archive/\d{4}-\d\d-\d\d_\d{6}$", flag(cmd, "--backup-dir"))
    assert not any("--dry-run" in c for c in proc.calls if c[1] in ("copy", "sync"))   # no pre-count for Copy
    assert "--local-encoding" in cmd and cmd[2].startswith("od-") and cmd[3].startswith("/")
    r = db.one("SELECT * FROM sync_runs WHERE user_id=? ORDER BY id DESC", (uid,))
    assert (r["direction"], r["provider"], r["op"]) == ("pull_copy", "onedrive", "pull_copy")


def test_google_pull_uses_gd_remote(pw, db, kr):
    proc = PullProc()
    w = pw(proc)
    uid = seed_user(db, kr, ms=False, provider="gdrive", direction="pull_copy")
    db.put_google_credential(kr, uid, GOOGLE_RT, "s1", "jsmith@hotsprings.org", "drive")
    assert w.runner.run(uid, "bisync").result == "ok"
    assert pulls(proc)[0][2] == f"gd-{uid}:"


def test_mirror_waiting_for_baseline_runs_copy_only(pw, db, kr):
    proc = PullProc()
    w = pw(proc)
    uid = seed_user(db, kr, direction="pull_mirror")
    assert w.runner.run(uid, "bisync").result == "ok"
    assert [c[1] for c in pulls(proc)] == ["copy"]


def test_mirror_baseline_count_approve_and_run(pw, db, kr):
    proc = PullProc(combined=combined(same=90, nas_only=30))
    w = pw(proc)
    uid = seed_user(db, kr, direction="pull_mirror")
    assert w.runner.run(uid, "delta").result == "ok"
    u = db.user_full(uid)
    assert (u["mirror_baseline_count"], u["mirror_baseline_total"]) == (30, 120)
    assert not pulls(proc, "sync") or all("--dry-run" in c for c in pulls(proc, "sync"))
    with pytest.raises(ValueError):
        cloud.approve_baseline(db, uid, 29, "m", "mark@hotsprings.org")
    cloud.approve_baseline(db, uid, 30, "m", "mark@hotsprings.org")
    assert w.runner.run(uid, "force").result == "ok"
    real = [c for c in pulls(proc, "sync") if "--dry-run" not in c][-1]
    assert flag(real, "--max-delete") == "30" and "--delete-after" in real
    u = db.user_full(uid)
    assert u["mirror_baseline_ok_at"] and not cloud.baseline_needed(u)


def test_mirror_baseline_cancelled_if_count_changes(pw, db, kr):
    proc = PullProc(combined=combined(same=90, nas_only=30))
    w = pw(proc)
    uid = seed_user(db, kr, direction="pull_mirror")
    w.runner.run(uid, "delta")
    cloud.approve_baseline(db, uid, 30, "m", "mark@hotsprings.org")
    proc.combined = combined(same=90, nas_only=31)
    w.runner.run(uid, "force")
    assert not [c for c in pulls(proc, "sync") if "--dry-run" not in c]
    assert cloud.baseline_needed(db.user_full(uid))


def ok_mirror(db, kr, **kw):
    return seed_user(db, kr, direction="pull_mirror", mirror_baseline_ok_at="2026-10-01T00:00:00+00:00", **kw)


@pytest.mark.smoke
def test_mirror_over_the_delete_limit_stops_before_moving_anything(pw, db, kr):
    proc = PullProc(combined=combined(same=80, nas_only=20))   # 20% > 10%
    w = pw(proc)
    uid = ok_mirror(db, kr)
    oc = w.runner.run(uid, "bisync")
    assert oc.result == "safety_abort"
    assert not [c for c in pulls(proc, "sync") if "--dry-run" not in c]
    u = db.user_full(uid)
    assert u["state"] == D.SAFETY_ABORT and u["safety_delta_at"]
    assert json.loads(u["safety_abort_json"])["mode"] == "pull_mirror"


def test_mirror_under_the_limit_runs_with_the_backstop(pw, db, kr):
    proc = PullProc(combined=combined(same=95, nas_only=5))
    w = pw(proc)
    uid = ok_mirror(db, kr)
    assert w.runner.run(uid, "bisync").result == "ok"
    real = [c for c in pulls(proc, "sync") if "--dry-run" not in c][-1]
    assert flag(real, "--max-delete") == "10"          # floor(100 * 10%)
    dry = [c for c in pulls(proc, "sync") if "--dry-run" in c][-1]
    assert flag(dry, "--max-delete") == "-1" and "--combined" in dry
    # the combined report (file names) is shredded after use
    assert not list(Path(dry[dry.index("--combined") + 1]).parent.glob("*.combined"))


def test_backstop_trip_is_a_safety_abort(pw, db, kr):
    proc = PullProc(combined=combined(same=95, nas_only=5), exit_codes={"sync": 7},
                    log_lines=[{"level": "error", "msg": "--max-delete threshold reached"}])
    w = pw(proc)
    uid = ok_mirror(db, kr)
    assert w.runner.run(uid, "bisync").result == "safety_abort"


def test_empty_cloud_listing_stops_mirror_even_in_service_mode(pw, db, kr):
    from odnas import service_mode as SM
    proc = PullProc(combined=combined(nas_only=50))
    w = pw(proc)
    uid = ok_mirror(db, kr)
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 4, "cleanup")
    assert w.runner.run(uid, "bisync").result == "safety_abort"
    assert json.loads(db.user_full(uid)["safety_abort_json"])["check"] == "empty_source"


def test_service_mode_mirror_omits_max_delete(pw, db, kr):
    from odnas import service_mode as SM
    proc = PullProc(combined=combined(same=50, nas_only=50))
    w = pw(proc)
    uid = ok_mirror(db, kr)
    SM.enable_user(db, Alerter(db), uid, "m", "mark@hotsprings.org", 4, "cleanup")
    assert w.runner.run(uid, "bisync").result == "ok"
    real = [c for c in pulls(proc, "sync") if "--dry-run" not in c][-1]
    assert "--max-delete" not in real


def test_missing_cloud_check_file_is_critical(pw, db, kr):
    proc = PullProc(cloud_has_check=False)
    w = pw(proc)
    uid = seed_user(db, kr, direction="pull_copy")
    w.runner.run(uid, "bisync")
    assert db.user_full(uid)["state"] == D.CRITICAL and not pulls(proc)


def test_backup_target_unavailable_skips_the_run(pw, db, kr):
    proc = PullProc()
    w = pw(proc, target="backup_nas")      # not configured
    uid = seed_user(db, kr, direction="pull_copy")
    w.runner.run(uid, "bisync")
    u = db.user_full(uid)
    assert not pulls(proc) and u["state"] == D.ACTIVE and u["consecutive_failures"] == 0
    assert any(i["type"] == "backup_target_unavailable" for i in db.open_issues(uid))


def test_one_way_restore_run_is_refused(pw, db, kr):
    w = pw(PullProc())
    uid = ok_mirror(db, kr, state=D.SAFETY_ABORT)
    db.update_profile(uid, safety_action=D.SAFETY_RESTORE, resync_approved_by="m")
    with pytest.raises(RuntimeError):
        w.runner.run(uid, "resync")


# ---- direction switching (worker, between runs) ----------------------------------------------------

def test_two_way_to_copy_sets_listings_aside(cfg, db, kr):
    uid = seed_user(db, kr)
    wd = Path(cfg.p_state) / "bisync" / uid
    wd.mkdir(parents=True, exist_ok=True)
    (wd / "a.path1.lst").write_text("x")
    cloud.request_direction(db, uid, "pull_copy", "Dec 2026 move", "m", "mark@hotsprings.org")
    s = settings_store.load(db, cfg, kr)
    cloud.apply_direction_changes(db, Alerter(db), s, cfg, running=set())
    u = db.user_full(uid)
    assert u["direction"] == "pull_copy" and u["direction_req"] is None
    assert db.audit_rows(action="direction_switched")


def test_back_to_two_way_goes_through_onboarding(cfg, db, kr):
    uid = seed_user(db, kr, direction="pull_mirror", mirror_baseline_ok_at="2026-10-01T00:00:00+00:00")
    cloud.request_direction(db, uid, "two_way", "pilot over", "m", "mark@hotsprings.org")
    cloud.apply_direction_changes(db, Alerter(db), settings_store.load(db, cfg, kr), cfg, running=set())
    u = db.user_full(uid)
    assert u["direction"] == "two_way" and u["state"] == D.ONBOARDING and u["needs_resync"]
    assert u["two_way_baseline_at"] is None and u["gdocs_mode"] == "skip"


def test_copy_to_two_way_defaults_to_a_mirror_pass_first(cfg, db, kr):
    uid = seed_user(db, kr, direction="pull_copy")
    cloud.request_direction(db, uid, "two_way", "pilot over", "m", "mark@hotsprings.org")
    cloud.apply_direction_changes(db, Alerter(db), settings_store.load(db, cfg, kr), cfg, running=set())
    u = db.user_full(uid)
    assert u["direction"] == "pull_mirror" and u["direction_then"] == "two_way"


def test_switch_waits_while_a_job_runs_or_user_paused(cfg, db, kr):
    uid = seed_user(db, kr)
    cloud.request_direction(db, uid, "pull_copy", "move", "m", "mark@hotsprings.org")
    s = settings_store.load(db, cfg, kr)
    cloud.apply_direction_changes(db, Alerter(db), s, cfg, running={uid})
    assert db.user_full(uid)["direction"] == "two_way"


# ---- preflight: Windows names, Google rules --------------------------------------------------------

def test_windows_file_name_rules_from_day_one():
    rep = preflight.scan({"onedrive": [], "nas": [{"Path": "CON.txt", "Size": 1}, {"Path": "a:b.txt", "Size": 1},
                                                  {"Path": "trail. ", "Size": 1}]}, provider="onedrive")
    codes = {f.rule for f in rep.findings}
    assert {"win_reserved_name", "win_reserved_char", "win_trailing_space_or_dot"} <= codes


def test_google_duplicates_and_native_files_are_reported():
    rep = preflight.scan({"google_drive": [{"Path": "x.txt", "Size": 1}, {"Path": "x.txt", "Size": 2},
                                           {"Path": "Doc", "Size": -1, "MimeType": "application/vnd.google-apps.document"}],
                          "nas": []}, provider="gdrive")
    assert rep.gdocs == 1 and "google_duplicate_name" in rep.summary()


# ---- hygiene ------------------------------------------------------------------------------------------

@pytest.mark.smoke
def test_no_google_secrets_in_the_repo():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    pat = re.compile(r"GOCSPX-[A-Za-z0-9_-]{10,}|1//0[A-Za-z0-9_-]{20,}|ya29\.[A-Za-z0-9_-]{20,}")
    for f in out + ["odnas/google.py", "odnas/cloud.py", "odnas/pull.py"]:
        p = ROOT / f
        if p.is_file() and p.suffix not in (".png", ".ico"):
            assert not pat.search(p.read_text(errors="ignore")), f


# ---- app-wide Google client failure, backup test, Mirror onboarding approval ----------------------

def test_google_invalid_client_is_app_wide_not_per_user():
    from odnas.tokens import log_auth_classification
    from odnas.pull import classify_pull
    txt = json.dumps({"level": "error", "msg": "oauth2: cannot fetch token: 401 {\"error\": \"invalid_client\"}"})
    assert log_auth_classification(txt, "gdrive") == AUTH_APP
    assert classify_pull(1, txt, provider="gdrive", cloud="Google Drive").result == "auth"


def test_worker_skips_google_users_while_app_flag_set(pw, db, kr):
    from odnas.runner import GOOGLE_APP_FLAG
    w = pw(PullProc())
    g = seed_user(db, kr, ms=False, provider="gdrive", upn="g@hotsprings.org", direction="pull_copy")
    db.put_google_credential(kr, g, GOOGLE_RT, "s9", "g@hotsprings.org", "drive")
    db.set_flag(GOOGLE_APP_FLAG, "invalid_client")
    s = settings_store.load(db, w.cfg, kr)
    assert w.choose_job(db.user_full(g), s, D.utcnow()) is None


def test_worker_runs_the_backup_target_test(pw, db, kr):
    w = pw(PullProc(), target="backup_nas")
    db.set_flag("backup_test_requested", "admin test", by="mark@hotsprings.org")
    w._backup_test(settings_store.load(db, w.cfg, kr), D.utcnow())
    assert db.flag("backup_test_requested") is None
    hb = json.loads(db.heartbeat("backup_test")["detail"])
    assert hb["result"] != "ok" and "not configured" in hb["message"]
    assert db.audit_rows(action="backup_target_tested")


def test_mirror_onboarding_approval_carries_the_count(admin, db, kr):
    a, mark, tok, _ = admin
    uid = seed_user(db, kr, state=D.ONBOARDING, direction="pull_mirror", dryrun_ok_at=D.iso(D.utcnow()),
                    mirror_baseline_count=12, mirror_baseline_total=100, needs_resync=1)
    page = mark.get(f"/admin/users/{uid}").text
    assert "moves 12 of 100 NAS file(s)" in page
    assert mark.post(f"/admin/users/{uid}/approve-resync", data={"csrf": tok, "baseline_count": "11"}).status_code == 409
    assert mark.post(f"/admin/users/{uid}/approve-resync", data={"csrf": tok, "baseline_count": "12"}).status_code == 303
    u = db.user_full(uid)
    assert u["mirror_baseline_approved_count"] == 12 and u["resync_approved_by"]


def test_admin_and_auditor_banners_for_google_flag_and_disabled_provider(admin, db, kr, cfg):
    a, mark, tok, walter = admin
    seed_user(db, kr, ms=False, provider="gdrive")
    db.set_flag("google_app_credential", "invalid_client")
    settings_store.update(db, cfg, kr, {"providers_enabled": "onedrive"}, "t")
    for c, path in ((mark, "/admin"), (walter, "/audit")):
        page = c.get(path).text
        assert 'id="google-app"' in page and 'id="provider-off"' in page
