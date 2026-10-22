"""v0.11: opt-in nightly auto-update (SPEC §11.4.1). One test (or more) per rule.

The Python half (odnas/autoupdate.py) decides; deploy/auto-update.sh (root) verifies the tag, runs update.sh
and turns itself off after a failure. The shell script is run here against a fake /opt + /etc tree
(SPRINGSYNC_TEST_PREFIX) with a stub `odnas` and a stub update.sh, so nothing real is touched.
"""
import json
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from odnas import autoupdate as AU
from odnas import cli
from odnas import db as D
from odnas.config import ConfigError, load_config
from tests.conftest import seed_user
from tests.test_web import wc  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 23, 7, 45, tzinfo=timezone.utc)     # 02:45 Central
OLD = NOW - timedelta(hours=30)


def rel(tag, *, draft=False, pre=False, at=OLD, created=None):
    return AU.Release(tag, draft, pre, None if draft else at, created or at)


@pytest.fixture
def on(cfg):
    """The shared test config with [auto_update] enabled = true."""
    from dataclasses import replace
    return replace(cfg, auto_update_enabled=True)


# ---- tags and semver ------------------------------------------------------------------------------------
@pytest.mark.parametrize("tag,ok", [
    ("v0.11.0", True), ("v1.2.3", True), ("v10.0.12", True),
    ("v0.11.1-rc1", False), ("v0.11.1-beta", False), ("v0.11.1+build", False), ("0.11.1", False),
    ("main", False), ("master", False), ("refs/heads/main", False), ("v0.11", False), ("v01.1.1", False),
    ("v0.11.1\n", False), ("", False), ("v0.11.1 ", False),
])
def test_parse_tag_only_plain_release_tags(tag, ok):
    assert (AU.parse_tag(tag) is not None) is ok


@pytest.mark.parametrize("a,b,newer", [
    ("v0.11.1", "v0.11.0", True), ("v0.11.10", "v0.11.9", True), ("v0.12.0", "v0.11.99", True),
    ("v1.0.0", "v0.99.99", True), ("v0.11.0", "v0.11.0", False), ("v0.10.9", "v0.11.0", False),
    ("v0.11.1-rc1", "v0.11.0", False), ("main", "v0.11.0", False), ("v0.11.1", "garbage", False),
])
def test_semver_compare_is_numeric_and_strict(a, b, newer):
    assert AU.is_newer(a, b) is newer


# ---- rule 3: what it picks ------------------------------------------------------------------------------
def test_newer_patch_is_installed():
    d = AU.choose("v0.11.0", [rel("v0.11.1"), rel("v0.11.2"), rel("v0.10.9")], NOW)
    assert (d.action, d.tag, d.reason) == ("install", "v0.11.2", "newer_patch")


@pytest.mark.parametrize("releases", [[rel("v0.11.0")], [rel("v0.10.5")], []])
def test_same_or_older_is_a_noop(releases):
    d = AU.choose("v0.11.0", releases, NOW)
    assert (d.action, d.reason) == ("none", "up_to_date")


def test_drafts_prereleases_and_suffix_tags_are_ignored():
    rs = [rel("v0.11.5", draft=True), rel("v0.11.4", pre=True), rel("v0.11.3-rc1"), rel("v0.11.2-beta"),
          rel("main"), rel("release/v0.11.9")]
    d = AU.choose("v0.11.0", rs, NOW)
    assert (d.action, d.reason) == ("none", "up_to_date")
    # a normal release next to them is still taken, and only that one
    assert AU.choose("v0.11.0", rs + [rel("v0.11.1")], NOW).tag == "v0.11.1"


def test_api_payload_parsing_defaults_to_not_eligible():
    rs = AU.releases_from_api([
        {"tag_name": "v0.11.1", "draft": False, "prerelease": False, "published_at": "2026-10-22T01:00:00Z",
         "created_at": "2026-10-22T00:50:00Z"},
        {"tag_name": "v0.11.2"},                       # fields missing: treated as draft + pre-release
        {"tag_name": "v0.11.3", "draft": False, "prerelease": True, "published_at": "2026-10-22T01:00:00Z"},
        {"name": "no tag"}, "junk"])
    assert [r.tag for r in rs if AU.eligible(r)] == ["v0.11.1"]
    with pytest.raises(AU.FetchError):
        AU.releases_from_api({"message": "API rate limit exceeded"})


def test_current_prereleases_alone_never_trigger_an_update():
    """Pilot note: every release so far is a GitHub pre-release, so auto-update waits for a normal one."""
    rs = [rel(f"v0.10.{i}", pre=True) for i in range(4)] + [rel("v0.11.1", pre=True)]
    assert AU.choose("v0.11.0", rs, NOW).action == "none"


# ---- rule 4: 24 h waiting period ----------------------------------------------------------------------
def test_release_younger_than_24h_waits():
    d = AU.choose("v0.11.0", [rel("v0.11.1", at=NOW - timedelta(hours=23, minutes=59))], NOW)
    assert (d.action, d.reason, d.tag) == ("none", "waiting_period", "v0.11.1")
    assert AU.choose("v0.11.0", [rel("v0.11.1", at=NOW - timedelta(hours=24))], NOW).action == "install"


def test_waiting_period_counts_from_publication_not_tag_creation():
    r = rel("v0.11.1", at=NOW - timedelta(hours=2), created=NOW - timedelta(days=10))
    assert AU.choose("v0.11.0", [r], NOW).reason == "waiting_period"


def test_older_aged_patch_still_installs_while_a_newer_one_waits():
    d = AU.choose("v0.11.0", [rel("v0.11.1"), rel("v0.11.2", at=NOW - timedelta(hours=1))], NOW)
    assert (d.action, d.tag) == ("install", "v0.11.1")


# ---- rule 5: patch only; minor/major waits for a manual update ------------------------------------------
@pytest.mark.parametrize("tag", ["v0.12.0", "v1.0.0"])
def test_new_minor_or_major_is_not_installed(tag):
    d = AU.choose("v0.11.0", [rel(tag)], NOW)
    assert (d.action, d.reason, d.newer_minor) == ("none", "newer_minor_needs_manual_update", tag)


def test_new_minor_is_reported_alongside_a_patch():
    d = AU.choose("v0.11.0", [rel("v0.11.1"), rel("v0.12.0")], NOW)
    assert (d.action, d.tag, d.newer_minor) == ("install", "v0.11.1", "v0.12.0")


def test_new_minor_is_audited_and_alerted_once(on, db):
    for _ in range(2):
        d = AU.check(on, db, "v0.11.0", fetch=lambda: [rel("v0.12.0")], now=NOW)
    assert d.action == "none"
    issues = [i for i in db.open_issues() if i["type"] == AU.ISSUE_MANUAL]
    assert len(issues) == 1 and "v0.12.0" in issues[0]["summary"]
    rows = db.audit_rows(action="auto_update_skipped")
    assert len(rows) == 2 and json.loads(rows[0]["details_json"])["newer_minor"] == "v0.12.0"


# ---- rule 1: off by default -----------------------------------------------------------------------------
def test_off_by_default_and_example_config_ships_off(cfg, db):
    assert cfg.auto_update_enabled is False
    called = []
    d = AU.check(cfg, db, "v0.11.0", fetch=lambda: called.append(1) or [rel("v0.11.1")], now=NOW)
    assert (d.action, d.reason) == ("none", "disabled") and not called
    assert db.audit_rows(action="auto_update_checked") == [] and db.heartbeat(AU.HEARTBEAT) is None
    ex = load_config(str(ROOT / "deploy/config/springsync.toml.example"), env={})
    assert ex.auto_update_enabled is False and ex.auto_update_require_signed_tags is False


def test_config_section_and_validation(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[auto_update]\nenabled = true\nrequire_signed_tags = true\n'
                 'allowed_signers = "/etc/springsync/deploy/allowed_signers"\n')
    c = load_config(str(p), env={})
    assert c.auto_update_enabled and c.auto_update_require_signed_tags
    assert c.auto_update_allowed_signers.endswith("allowed_signers")
    for bad in ('repo = "not a repo"', 'allowed_signers = "relative/path"', 'surprise = 1'):
        p.write_text(f"[auto_update]\n{bad}\n")
        with pytest.raises(ConfigError):
            load_config(str(p), env={})


def test_self_disabled_flag_blocks_until_reenabled(on, db):
    AU.disabled_flag(on).parent.mkdir(parents=True, exist_ok=True)
    AU.disabled_flag(on).write_text("failed")
    called = []
    d = AU.check(on, db, "v0.11.0", fetch=lambda: called.append(1) or [rel("v0.11.1")], now=NOW)
    assert d.reason == "disabled_after_failure" and not called
    AU.disabled_flag(on).unlink()
    AU.report(on, db, "reenabled", "v0.11.0", "v0.11.0", now=NOW)
    assert AU.check(on, db, "v0.11.0", fetch=lambda: [rel("v0.11.1")], now=NOW).action == "install"


# ---- rule 2: never while a Mirror run or an approval is pending ----------------------------------------
def test_blocked_by_running_mirror_run(on, db, kr):
    uid = seed_user(db, kr, direction="pull_mirror")
    rid = db.start_run(uid, "bisync", "")
    db.q("UPDATE sync_runs SET direction='pull_mirror', op='pull_mirror' WHERE id=?", (rid,))
    d = AU.check(on, db, "v0.11.0", fetch=lambda: [rel("v0.11.1")], now=NOW)
    assert (d.action, d.reason) == ("none", "mirror_run_in_progress")
    db.q("UPDATE sync_runs SET ended_at=? WHERE id=?", (D.iso(NOW), rid))
    assert AU.check(on, db, "v0.11.0", fetch=lambda: [rel("v0.11.1")], now=NOW).action == "install"


def test_a_running_two_way_run_does_not_block(on, db, kr):
    uid = seed_user(db, kr)
    db.start_run(uid, "bisync", "")       # update.sh drains it
    assert AU.blockers(db) == []


@pytest.mark.parametrize("field,value", [("safety_accept_state", D.ACCEPT_PENDING),
                                         ("mirror_baseline_state", "pending"), ("direction_req", "pull_mirror")])
def test_blocked_by_pending_approval(on, db, kr, field, value):
    uid = seed_user(db, kr)
    db.update_profile(uid, **{field: value})
    d = AU.check(on, db, "v0.11.0", fetch=lambda: [rel("v0.11.1")], now=NOW)
    assert (d.action, d.reason) == ("none", "approval_pending")
    assert json.loads(db.audit_rows(action="auto_update_skipped")[0]["details_json"])["reason"] == "approval_pending"


# ---- network failure ---------------------------------------------------------------------------------------
def test_network_failure_is_a_logged_noop(on, db, caplog):
    def boom():
        raise AU.FetchError("ConnectError: no route to host")
    d = AU.check(on, db, "v0.11.0", fetch=boom, now=NOW)
    assert (d.action, d.reason) == ("none", "fetch_failed")
    assert any("could not read releases" in r.message and r.levelname == "WARNING" for r in caplog.records)
    assert json.loads(db.audit_rows(action="auto_update_skipped")[0]["details_json"])["reason"] == "fetch_failed"


def test_fetch_releases_wraps_http_errors(monkeypatch):
    import httpx

    def fail(*a, **k):
        raise httpx.ConnectError("offline")
    monkeypatch.setattr(httpx, "get", fail)
    with pytest.raises(AU.FetchError):
        AU.fetch_releases("VisitHotSprings/SpringSync", "ua")


# ---- rule 8: every check audited; installs/rollbacks alerted ---------------------------------------------
def test_check_and_reports_are_audited_and_alerted(on, db):
    assert AU.check(on, db, "v0.11.0", fetch=lambda: [], now=NOW).reason == "up_to_date"
    assert db.audit_rows(action="auto_update_checked")
    AU.report(on, db, "installed", "v0.11.1", "v0.11.0", now=NOW)
    AU.report(on, db, "failed", "v0.11.2", "v0.11.1", now=NOW)
    AU.report(on, db, "refused_unsigned", "v0.11.3", "v0.11.1", now=NOW)
    types = {i["type"]: i["severity"] for i in db.open_issues()}
    assert types[AU.ISSUE_INSTALLED] == "low" and types[AU.ISSUE_FAILED] == "high" and types[AU.ISSUE_REFUSED] == "high"
    for a in ("auto_update_installed", "auto_update_rolled_back", "auto_update_refused"):
        assert db.audit_rows(action=a), a
    assert db.verify_audit_chain()[0]
    assert AU.state(on, db)["last"]["result"] == "refused"
    with pytest.raises(ValueError):
        AU.report(on, db, "bogus", "v0.11.1", "v0.11.0")


def test_cli_check_when_disabled_prints_json_and_needs_no_network(cfg, monkeypatch, capsys):
    env = {"ODNAS_DB_PATH": cfg.db_path, "ODNAS_ETC_DIR": cfg.etc_dir, "ODNAS_TENANT_ID": cfg.tenant_id,
           "ODNAS_CLIENT_ID": cfg.client_id, "ODNAS_HOST_OS": "linux"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("ODNAS_CONFIG", raising=False)
    import httpx
    monkeypatch.setattr(httpx, "get", lambda *a, **k: pytest.fail("network used while disabled"))
    assert cli.main(["auto-update", "check", "--current", "v0.11.0"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["action"] == "none" and out["reason"] == "disabled" and out["require_signed_tags"] is False
    assert cli.main(["auto-update", "report", "--event", "installed", "--tag", "main"]) == 2


# ---- GUI: read-only -----------------------------------------------------------------------------------------
def test_settings_page_shows_state_but_has_no_update_control(cfg, db, kr, entra, wc):
    from tests.conftest import G_ADMINS
    from tests.test_web import login
    from odnas.web.app import create_app
    app = create_app(cfg, db, kr, entra, wc)
    mark = login(app, entra, oid="oid-mark", upn="mark@hotsprings.org", groups=(G_ADMINS,))
    page = mark.get("/admin/settings").text
    i = page.index('id="auto-update"')
    block = page[i:page.index("</fieldset>", i)]
    assert "Automatic updates: <strong>Off</strong>" in block and "No check recorded yet" in block
    assert "<form" not in block and "<button" not in block and "<input" not in block
    db.beat(AU.HEARTBEAT, json.dumps({"at": D.iso(NOW), "result": "skipped", "reason": "waiting_period",
                                      "tag": "v0.11.1"}))
    block = mark.get("/admin/settings").text
    assert "waiting_period" in block and "v0.11.1" in block
    paths = {getattr(r, "path", "") for r in app.routes}
    assert not any("update" in p for p in paths), paths


# ---- deploy assets ----------------------------------------------------------------------------------------
def test_units_timer_and_installer():
    t = (ROOT / "deploy/systemd/springsync-autoupdate.timer").read_text()
    assert "OnCalendar=*-*-* 02:45:00 America/Chicago" in t and "RandomizedDelaySec=30min" in t
    assert "Persistent=false" in t and "WantedBy=timers.target" in t
    s = (ROOT / "deploy/systemd/springsync-autoupdate.service").read_text()
    assert "ExecStart=/opt/@SLUG@/current/deploy/auto-update.sh --slug @SLUG@" in s
    assert "OnFailure=@SLUG@-alert@%n.service" in s and "Type=oneshot" in s
    assert '"$SLUG-autoupdate.timer"' in (ROOT / "deploy/install.sh").read_text()


def test_shell_scripts_syntax_and_shellcheck():
    for s in ("auto-update.sh", "update.sh"):
        assert subprocess.run(["bash", "-n", str(ROOT / "deploy" / s)]).returncode == 0
    if shutil.which("shellcheck"):
        r = subprocess.run(["shellcheck", "-S", "warning", str(ROOT / "deploy/auto-update.sh")],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stdout


def test_update_sh_verifies_signature_even_for_a_leftover_release_dir():
    t = (ROOT / "deploy/update.sh").read_text()
    i, j = t.index('if [[ ! -d "$REL" ]]'), t.index('verify-tag "$TAG"')
    assert t.index("\nfi\n", i) < j   # the check is outside the "fresh clone" block


# ---- auto-update.sh against a fake tree -------------------------------------------------------------------
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "tag.gpgSign=false",
       "-c", "commit.gpgSign=false", "-c", "init.defaultBranch=main"]


@pytest.fixture
def tree(tmp_path):
    """$PFX/opt/springsync/{releases/v0.11.0,current}, a stub odnas and a stub update.sh."""
    if not shutil.which("jq") or not shutil.which("flock"):
        pytest.skip("jq/flock not installed")
    pfx = tmp_path / "pfx"
    origin = tmp_path / "origin"
    subprocess.run(GIT + ["init", "-q", str(origin)], check=True)
    (origin / "f").write_text("x")
    subprocess.run(GIT + ["-C", str(origin), "add", "f"], check=True)
    subprocess.run(GIT + ["-C", str(origin), "commit", "-qm", "c"], check=True)
    subprocess.run(GIT + ["-C", str(origin), "tag", "-a", "v0.11.1", "-m", "unsigned"], check=True)
    opt = pfx / "opt/springsync"
    cur = opt / "releases/v0.11.0"
    subprocess.run(GIT + ["clone", "-q", str(origin), str(cur)], check=True)
    (pfx / "etc/springsync").mkdir(parents=True)
    (cur / "venv/bin").mkdir(parents=True)
    (cur / "deploy").mkdir()
    shutil.copy(ROOT / "deploy/auto-update.sh", cur / "deploy/auto-update.sh")
    stub = cur / "venv/bin/odnas"
    stub.write_text('#!/bin/bash\nshift\ncase "$1" in check) cat "$FAKE_CHECK";; '
                    'status) echo "{\\"enabled\\": ${FAKE_ENABLED:-true}}";; '
                    '*) echo "$*" >> "$FAKE_LOG";; esac\n')
    up = cur / "deploy/update.sh"
    up.write_text('#!/bin/bash\necho "update.sh $* signed=${REQUIRE_SIGNED_TAGS:-0}" >> "$FAKE_LOG"\n'
                  'if [[ "$FAKE_UPDATE_RC" == 0 ]]; then mkdir -p "$OPT_DIR/releases/$1"; '
                  'cp -r "$OPT_DIR/current/." "$OPT_DIR/releases/$1/"; ln -sfn "$OPT_DIR/releases/$1" "$OPT_DIR/current"; fi\n'
                  'exit "$FAKE_UPDATE_RC"\n')
    for f in (stub, up, cur / "deploy/auto-update.sh"):
        f.chmod(0o755)
    os.symlink(cur, opt / "current")

    def run(check: dict, *args, rc=0, extra_env=None):
        (tmp_path / "check.json").write_text(json.dumps(
            {"action": "none", "reason": "up_to_date", "tag": "", "newer_minor": "",
             "require_signed_tags": False, "allowed_signers": "", **check}))
        env = {**os.environ, "SPRINGSYNC_TEST_PREFIX": str(pfx), "FAKE_CHECK": str(tmp_path / "check.json"),
               "FAKE_LOG": str(tmp_path / "log"), "FAKE_UPDATE_RC": str(rc), "OPT_DIR": str(opt)}
        env.pop("REQUIRE_SIGNED_TAGS", None)
        env.update(extra_env or {})
        p = subprocess.run(["bash", str(opt / "current/deploy/auto-update.sh"), *args], env=env,
                           capture_output=True, text=True)
        log = (tmp_path / "log").read_text() if (tmp_path / "log").exists() else ""
        return p, log
    run.flag = pfx / "etc/springsync/auto-update.disabled"
    run.pfx = pfx
    run.tmp = tmp_path
    run.current = lambda: os.path.basename(os.path.realpath(opt / "current"))
    return run


def test_script_noop_when_nothing_to_do(tree):
    p, log = tree({"reason": "up_to_date"})
    assert p.returncode == 0 and "no update (up_to_date)" in p.stdout and "update.sh" not in log


def test_script_disabled_stops_before_waiting_or_checking(tree):
    busy = tree.tmp / "systemctl"
    busy.write_text("#!/bin/bash\necho called >> \"$FAKE_LOG\"; exit 0\n")   # 'backup active' forever
    busy.chmod(0o755)
    p, log = tree({"action": "install", "tag": "v0.11.1"},
                  extra_env={"FAKE_ENABLED": "false", "FAKE_SYSTEMCTL": str(busy), "FAKE_BACKUP_WAIT_S": "60"})
    assert p.returncode == 0 and "no update (disabled)" in p.stdout and log == ""


def test_script_installs_newer_tag_via_update_sh(tree):
    p, log = tree({"action": "install", "reason": "newer_patch", "tag": "v0.11.1"})
    assert p.returncode == 0, p.stderr
    assert "update.sh v0.11.1 --slug springsync signed=0" in log
    assert "report --event installed --tag v0.11.1 --from v0.11.0" in log
    assert tree.current() == "v0.11.1" and not tree.flag.exists()


def test_script_check_only_installs_nothing(tree):
    p, log = tree({"action": "install", "reason": "newer_patch", "tag": "v0.11.1"}, "--check-only")
    assert p.returncode == 0 and "would install v0.11.1" in p.stdout and "update.sh" not in log


def test_script_refuses_a_branch_or_suffix_tag_even_if_asked(tree):
    for bad in ("main", "v0.11.1-rc1"):
        p, log = tree({"action": "install", "tag": bad})
        assert p.returncode == 1 and "refusing" in p.stderr and "update.sh" not in log


def test_script_failure_turns_auto_update_off_until_reenabled(tree):
    p, log = tree({"action": "install", "reason": "newer_patch", "tag": "v0.11.1"}, rc=1)
    assert p.returncode == 0 and "FAILED" in p.stderr
    assert tree.flag.exists() and "report --event failed --tag v0.11.1 --from v0.11.0" in log
    assert tree.current() == "v0.11.0"
    p, log = tree({}, "--reenable")
    assert p.returncode == 0 and not tree.flag.exists() and "report --event reenabled" in log


def test_script_refuses_unsigned_tag_when_signing_required(tree):
    p, log = tree({"action": "install", "reason": "newer_patch", "tag": "v0.11.1", "require_signed_tags": True})
    assert p.returncode == 0 and "refused v0.11.1" in p.stderr
    assert "report --event refused_unsigned --tag v0.11.1" in log and "update.sh" not in log
    assert tree.current() == "v0.11.0" and not tree.flag.exists()


# ---- SPEC v0.10 revisions ----------------------------------------------------------------------------------
def _fake_systemctl(tree, active_for_s):
    """systemctl stub: `is-active <slug>-backup.service` is true until `active_for_s` seconds have passed."""
    f = tree.tmp / "systemctl"
    start = tree.tmp / "start"
    f.write_text("#!/bin/bash\n[[ -f %s ]] || date +%%s > %s\n"
                 "(( $(date +%%s) - $(cat %s) < %d ))\n" % (start, start, start, active_for_s))
    f.chmod(0o755)
    return str(f)


def test_script_skips_tonight_when_backup_still_running(tree):
    p, log = tree({"action": "install", "reason": "newer_patch", "tag": "v0.11.1"},
                  extra_env={"FAKE_SYSTEMCTL": _fake_systemctl(tree, 3600), "FAKE_BACKUP_WAIT_S": "2"})
    assert p.returncode == 0 and "backup_running" in p.stdout
    assert "report --event backup_running --tag v0.11.0" in log and "update.sh" not in log
    assert tree.current() == "v0.11.0"


def test_script_waits_for_backup_then_proceeds(tree):
    p, log = tree({"action": "install", "reason": "newer_patch", "tag": "v0.11.1"},
                  extra_env={"FAKE_SYSTEMCTL": _fake_systemctl(tree, 1), "FAKE_BACKUP_WAIT_S": "10"})
    assert p.returncode == 0, p.stderr
    assert "backup_running" not in log and "update.sh v0.11.1" in log and tree.current() == "v0.11.1"


def test_backup_wait_defaults_to_15_min_and_checks_the_unit():
    t = (ROOT / "deploy/auto-update.sh").read_text()
    assert "BACKUP_WAIT_S=900" in t and 'is-active --quiet "$SLUG-backup.service"' in t
    # SPEC: After= alone is not relied on
    assert "@SLUG@-backup.service" not in (ROOT / "deploy/systemd/springsync-autoupdate.service").read_text() \
        .split("[Service]")[0].replace("# The script itself waits for <slug>-backup.service", "")


@pytest.mark.parametrize("mode", ["--exclusive", "--shared"])
def test_script_skips_when_update_or_maintenance_holds_the_lock(tree, mode):
    lock = tree.pfx / "springsync-update.lock"
    holder = subprocess.Popen(["flock", mode, str(lock), "sleep", "30"])
    try:
        for _ in range(50):
            if subprocess.run(["flock", "-n", str(lock), "true"]).returncode != 0:
                break
            import time
            time.sleep(0.05)
        p, log = tree({"action": "install", "reason": "newer_patch", "tag": "v0.11.1"})
    finally:
        holder.kill()
        holder.wait()
    assert p.returncode == 0 and "update or maintenance running" in p.stdout
    assert "report --event busy" in log and "update.sh" not in log and not tree.flag.exists()


def test_update_sh_lock_busy_is_a_skip_not_a_failure(tree):
    p, log = tree({"action": "install", "reason": "newer_patch", "tag": "v0.11.1"}, rc=75)
    assert p.returncode == 0 and "report --event busy" in log
    assert not tree.flag.exists() and "report --event failed" not in log


def test_update_lock_wiring_update_sh_maint_and_tmpfiles():
    u = (ROOT / "deploy/update.sh").read_text()
    assert 'UPDATE_LOCK="/run/lock/$SLUG-update.lock"' in u and "flock -w 900 8" in u and "exit 75" in u
    assert u.index("flock -w 900 8") < u.index('say "1. fetch')     # held for the whole update
    m = (ROOT / "deploy/systemd/springsync-maint.service").read_text()
    assert ("ExecStart=/usr/bin/flock --shared --wait 5400 /run/lock/@SLUG@-update.lock "
            "/opt/@SLUG@/current/venv/bin/odnas maint") in m
    tf = (ROOT / "deploy/tmpfiles/springsync.conf").read_text()
    assert "f /run/lock/@SLUG@-update.lock 0644 root root -" in tf
    i = (ROOT / "deploy/install.sh").read_text()
    assert '/etc/tmpfiles.d/$SLUG.conf' in i and "systemd-tmpfiles --create" in i
    assert not list((ROOT / "deploy/systemd").glob("*tmpfiles*"))   # step 12 renders every file there as a unit


def test_maint_waits_for_an_update_in_progress(tmp_path):
    """The maint ExecStart's shared flock blocks while update.sh holds the lock exclusively, then runs."""
    if not shutil.which("flock"):
        pytest.skip("flock not installed")
    lock = tmp_path / "u.lock"
    lock.touch()
    holder = subprocess.Popen(["flock", "--exclusive", str(lock), "sleep", "2"])
    try:
        import time
        time.sleep(0.3)
        quick = subprocess.run(["flock", "--shared", "--wait", "0.5", str(lock), "true"])
        assert quick.returncode == 1                           # still locked: maint is waiting
        later = subprocess.run(["flock", "--shared", "--wait", "10", str(lock), "true"])
        assert later.returncode == 0                           # update finished: maint runs
    finally:
        holder.kill()
        holder.wait()


@pytest.mark.parametrize("during", ["bisync", "pull_mirror"])
def test_blocked_by_open_safety_hold(on, db, kr, during):
    """Percentage stop (bisync / Mirror counting dry-run) and the Mirror --max-delete backstop both leave the
    user in state safety_abort until Restore / Accept deletes."""
    uid = seed_user(db, kr, direction="pull_mirror" if during == "pull_mirror" else "two_way")
    db.set_state(uid, D.SAFETY_ABORT, "max_delete_backstop" if during == "pull_mirror" else "percentage stop")
    d = AU.check(on, db, "v0.11.0", fetch=lambda: [rel("v0.11.1")], now=NOW)
    assert (d.action, d.reason) == ("none", "safety_hold")
    db.set_state(uid, D.ACTIVE, "")
    assert AU.check(on, db, "v0.11.0", fetch=lambda: [rel("v0.11.1")], now=NOW).action == "install"


def test_initial_sync_waiting_user_does_not_block(on, db, kr):
    seed_user(db, kr, state=D.ONBOARDING, upn="new@example.invalid")
    assert AU.blockers(db) == []


def test_only_published_non_draft_non_prerelease_releases_count():
    assert AU.eligible(rel("v0.11.1"))
    assert not AU.eligible(rel("v0.11.1", draft=True))
    assert not AU.eligible(rel("v0.11.1", pre=True))
    assert not AU.eligible(AU.Release("v0.11.1", False, False, None, OLD))   # never published
    assert not AU.eligible(rel("v0.11.1-rc1"))


def test_24h_wait_runs_from_published_at_boundary():
    created = NOW - timedelta(days=30)
    just_under = rel("v0.11.1", at=NOW - timedelta(hours=24) + timedelta(seconds=1), created=created)
    exactly = rel("v0.11.1", at=NOW - timedelta(hours=24), created=created)
    assert AU.choose("v0.11.0", [just_under], NOW).reason == "waiting_period"
    assert AU.choose("v0.11.0", [exactly], NOW).action == "install"
    assert exactly.visible_since == exactly.published_at


def test_skip_and_self_disable_events_are_audited(on, db):
    AU.report(on, db, "backup_running", "v0.11.0", "v0.11.0", now=NOW)
    AU.report(on, db, "busy", "v0.11.0", "v0.11.0", now=NOW)
    reasons = [json.loads(r["details_json"])["reason"] for r in db.audit_rows(action="auto_update_skipped")]
    assert set(reasons) == {"backup_running", "update_or_maintenance_running"}
    AU.report(on, db, "failed", "v0.11.1", "v0.11.0", now=NOW)
    assert db.audit_rows(action="auto_update_self_disabled") and db.audit_rows(action="auto_update_rolled_back")
