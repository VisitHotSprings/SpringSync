import sqlite3
import tarfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from odnas import db as D
from odnas import settings_store
from odnas.maint import expiry_reminders, prune_logs, run_backup, run_maint, stale_refresh_tokens
from odnas.notify import Alerter, StubEmailNotifier, Alert
from odnas.preflight import blocked_name, scan
from odnas.status import credential_expiry
from tests.conftest import CANARY_PW, CANARY_RT, seed_user


# ---- audit log -----------------------------------------------------------

def test_audit_chain_and_redaction(db):
    for i in range(5):
        db.audit("mark", "setting_changed", f"k{i}", {"old": i, "new": i + 1, "smtp_password": "leak?"})
    ok, n, _ = db.verify_audit_chain()
    assert ok and n == 5
    assert all("leak?" not in r["details_json"] for r in db.audit_rows())


def test_audit_is_append_only(db):
    db.audit("system", "x")
    with pytest.raises(sqlite3.IntegrityError):
        db.q("UPDATE audit_log SET actor='evil'")
    with pytest.raises(sqlite3.IntegrityError):
        db.q("DELETE FROM audit_log")


def test_audit_tamper_detected(db):
    for i in range(3):
        db.audit("system", f"a{i}")
    db.q("DROP TRIGGER audit_no_update")  # attacker with raw DB access
    db.q("UPDATE audit_log SET action='forged' WHERE seq=2")
    ok, _, msg = db.verify_audit_chain()
    assert not ok and "seq 2" in msg


def test_migrations_idempotent(cfg):
    a = D.DB(cfg.p_db)
    v = a.schema_version()
    assert D.DB(cfg.p_db).migrate() == v == len(D.MIGRATIONS)


# ---- preflight -----------------------------------------------------------

@pytest.mark.parametrize("name,blocked", [("CON", True), ("con.txt", True), ("LPT1", True), ("COM0.log", True),
                                          ("desktop.ini", True), ("~$report.docx", True), (".lock", True),
                                          ("a_vti_b", True), ("report.docx", False), ("console.txt", False),
                                          ("#notes.txt", False)])
def test_blocked_names(name, blocked):
    assert blocked_name(name) is blocked


def test_hash_percent_optional():
    assert blocked_name("50%.txt", block_hash_percent=True) and not blocked_name("50%.txt")


def test_scan_rules():
    long = "a/" * 200 + "f.txt"
    entries = [{"Path": "Docs/CON.txt", "Size": 1}, {"Path": long, "Size": 1},
               {"Path": "big.iso", "Size": 250 * 1024 ** 3}, {"Path": "X/Report.docx", "Size": 2},
               {"Path": "X/report.docx", "Size": 3}, {"Path": "trail. /x", "Size": 1}]
    many = [{"Path": f"huge/{i}", "Size": 0} for i in range(100_001)]
    rep = scan({"nas": entries + many, "onedrive": []}, quota_remaining=10)
    c = rep.counts()
    assert c["blocked_name"] == 1 and c["path_too_long"] == 1 and c["file_too_large"] == 1
    assert c["case_collision"] == 2 and c["folder_over_100k_items"] == 1 and c["onedrive_quota"] == 1
    assert c["leading_trailing_space_or_dot"] == 1


# ---- expiry / maint -------------------------------------------------------

def _cert(tmp_path, days):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-app")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=days))
            .sign(key, hashes.SHA256()))
    p = tmp_path / "entra-app.crt"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return p


def test_expiry_from_certificate(cfg, db, tmp_path):
    from dataclasses import replace
    c2 = replace(cfg, credential_type="certificate", cert_path=str(_cert(tmp_path, 20)))
    e = credential_expiry(c2, settings_store.load(db, c2))
    assert e.source == "certificate" and e.days_left in (19, 20) and e.level == "warning"


@pytest.mark.parametrize("days,itype,sev", [(55, "credential_expiry_60d", "medium"), (25, "credential_expiry_30d", "medium"),
                                            (10, "credential_expiry_14d", "high"), (5, "credential_expiry_7d", "critical"),
                                            (1, "credential_expiry_1d", "critical"), (-1, "credential_expired", "critical")])
def test_expiry_reminders(cfg, db, kr, days, itype, sev):
    today = date(2026, 10, 20)
    settings_store.update(db, cfg, kr, {"entra_credential_expires_on": str(today + timedelta(days=days))}, "t")
    s = settings_store.load(db, cfg)
    stub = StubEmailNotifier()
    expiry_reminders(cfg, db, Alerter(db, stub), s, today)
    iss = db.open_issues()
    assert iss[0]["type"] == itype and iss[0]["severity"] == sev
    assert len(stub.outbox) == 1  # stub records, never sends


def test_expiry_unknown_raises_issue(cfg, db):
    expiry_reminders(cfg, db, Alerter(db), settings_store.load(db, cfg))
    assert db.open_issues()[0]["type"] == "credential_expiry_unknown"


def test_stale_refresh_token_80_days(db, kr):
    uid = seed_user(db, kr)
    db.q("UPDATE ms_credentials SET last_refresh_at=?", (D.iso(D.utcnow() - timedelta(days=81)),))
    assert stale_refresh_tokens(db, Alerter(db)) == 1
    assert db.user(uid)["state"] == D.NEEDS_REAUTH


def test_issue_dedup(db):
    a = Alerter(db)
    assert a.raise_(Alert("stale", "medium", "x", None)) and not a.raise_(Alert("stale", "medium", "x", None))


def test_run_maint(cfg, db, kr):
    out = run_maint(cfg, db, Alerter(db), probe_tls=False)
    assert out["audit_chain"] is True and db.heartbeat("audit_chain")["detail"].startswith("ok")


def test_prune_logs(cfg):
    import os
    d = Path(cfg.p_log) / "runs" / "u"
    d.mkdir(parents=True)
    old, new = d / "1.json", d / "2.json"
    old.write_text("x"); new.write_text("y")
    t = old.stat().st_mtime - 31 * 86400
    os.utime(old, (t, t))
    assert prune_logs(cfg) == 1 and new.exists() and not old.exists()


def test_backup_excludes_keys(cfg, db, kr, tmp_path):
    seed_user(db, kr)
    etc = Path(cfg.p_etc)
    (etc / "springsync.toml").write_text("ok=1")
    (etc / "deploy").mkdir()
    (etc / "deploy" / "id_ed25519").write_text("PRIVATE")
    (etc / "creds").mkdir()
    (etc / "creds" / "data.key.cred").write_text("ENC")
    caddy = tmp_path / "caddy"
    caddy.mkdir()
    (caddy / "Caddyfile").write_text("x")
    (caddy / "gcp-acme-sa.json").write_text("SA-KEY")
    files = run_backup(cfg, db, extra_dirs=(str(caddy),))
    names = tarfile.open(files[1]).getnames()
    assert any(n.endswith("springsync.toml") or n.endswith("etc/springsync.toml") for n in names)
    assert any(n.endswith("Caddyfile") for n in names)
    assert not any(("keys" in n) or ("id_ed25519" in n) or ("gcp-acme-sa" in n) or n.endswith(".cred")
                   for n in names)
    restored = sqlite3.connect(files[0])
    assert restored.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    restored.close()
    # DB backup holds only ciphertext: the canaries must not appear in plaintext
    raw = files[0].read_bytes()
    assert CANARY_RT.encode() not in raw and CANARY_PW.encode() not in raw
    for _ in range(16):
        run_backup(cfg, db, extra_dirs=())
    assert len(list(Path(cfg.p_state, "backups").glob("db-*.sqlite"))) == 14


# ---- offboarding -----------------------------------------------------------

def test_offboarding_crypto_erase(cfg, db, kr, entra):
    from tests.test_runner_broker import make_worker
    from tests.conftest import FakeProc
    proc = FakeProc()
    w, hr = make_worker(cfg, db, kr, entra, proc)
    uid = seed_user(db, kr)
    wd = Path(cfg.p_state) / "bisync" / uid
    wd.mkdir(parents=True)
    (wd / "x.lst").write_text("listing")
    db.update_profile(uid, final_sync_requested=1)
    db.set_state(uid, D.OFFBOARDING)
    assert w.choose_job(db.user_full(uid), w.settings(), D.utcnow()) == "offboard"
    w.offboard(uid)
    assert db.ms_credential(uid) is None and db.nas_credential_meta(uid) is None
    assert db.user(uid)["state"] == D.REMOVED and not wd.exists()
    assert len(proc.calls) == 1  # the one final bisync
    assert db.audit_rows(action="user_offboarded")
    raw = Path(cfg.p_db).read_bytes()
    assert CANARY_PW.encode() not in raw
