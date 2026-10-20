"""SQLite store (SPEC §5). WAL mode; stdlib sqlite3 with a tiny expand-only
migration list instead of SQLAlchemy/Alembic (see CHANGELOG: deviation).

Secrets are stored as nonce(12 bytes) || AES-GCM ciphertext, with the row's
key_id column naming the data key. The audit_log is append-only (triggers) and
hash-chained.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from odnas.crypto import Keyring, Sealed

# ---- user states (SPEC §5) ----------------------------------------------
INVITED, ONBOARDING, ACTIVE, PAUSED = "invited", "onboarding", "active", "paused"
NEEDS_REAUTH, NAS_AUTH_FAILED, BLOCKED_BY_CA, CRITICAL = "needs_reauth", "nas_auth_failed", "blocked_by_ca", "critical"
OFFBOARDING, REMOVED = "offboarding", "removed"
SAFETY_ABORT = "safety_abort"          # SPEC v0.2 §9.4: paused until an admin chooses Restore or Accept deletes
STATES = (INVITED, ONBOARDING, ACTIVE, PAUSED, NEEDS_REAUTH, NAS_AUTH_FAILED, BLOCKED_BY_CA, CRITICAL,
          SAFETY_ABORT, OFFBOARDING, REMOVED)
SAFETY_RESTORE, SAFETY_ACCEPT = "restore", "accept_deletes"
# SPEC v0.3 §9.4.1 Accept-deletes approval states (shown on the admin page)
ACCEPT_PENDING, ACCEPT_EXPIRED, ACCEPT_CANCELLED = "pending", "expired", "cancelled_count_changed"
ACCEPT_PRECHECK_FAILED, ACCEPT_TIMEOUT, ACCEPT_FAILED, ACCEPT_DONE = "precheck_failed", "timeout", "failed", "done"
ACCEPT_TTL_HOURS = 24
RESTORE_NEXT_SLOT, RESTORE_TONIGHT = "next_slot", "tonight"
STATE_LABELS = {
    INVITED: "Invited: sign in to connect",
    ONBOARDING: "Setting up",
    ACTIVE: "Syncing normally",
    PAUSED: "Paused by IT",
    NEEDS_REAUTH: "Microsoft sign-in expired: please reconnect",
    NAS_AUTH_FAILED: "NAS login failed: please re-enter your NAS password",
    BLOCKED_BY_CA: "Blocked by a Microsoft sign-in policy: IT has been alerted",
    CRITICAL: "Stopped safely: IT must review before syncing resumes",
    SAFETY_ABORT: "Paused: an unusually large number of deletions was blocked; IT is reviewing",
    OFFBOARDING: "Being disconnected",
    REMOVED: "Disconnected",
}

MIGRATIONS: list[str] = [
    # 1: initial schema
    """
    CREATE TABLE users (
        id TEXT PRIMARY KEY,
        entra_oid TEXT UNIQUE NOT NULL,
        upn TEXT NOT NULL,
        display_name TEXT,
        local_name TEXT NOT NULL,
        state TEXT NOT NULL,
        pause_reason TEXT,
        is_pilot INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE ms_credentials (
        user_id TEXT PRIMARY KEY REFERENCES users(id),
        refresh_token_ct BLOB NOT NULL,
        key_id TEXT NOT NULL,
        drive_id TEXT,
        drive_type TEXT,
        token_obtained_at TEXT,
        last_refresh_at TEXT,
        last_refresh_error TEXT
    );
    CREATE TABLE nas_credentials (
        user_id TEXT PRIMARY KEY REFERENCES users(id),
        provider TEXT NOT NULL,
        username_ct BLOB NOT NULL,
        password_ct BLOB NOT NULL,
        key_id TEXT NOT NULL,
        verified_at TEXT,
        last_failure_at TEXT,
        failure_count INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE sync_profiles (
        user_id TEXT PRIMARY KEY REFERENCES users(id),
        path1 TEXT NOT NULL,
        path2_subdir TEXT NOT NULL DEFAULT '',
        interval_min INTEGER,
        slot_offset_min INTEGER NOT NULL DEFAULT 0,
        max_delete_pct INTEGER,
        enabled INTEGER NOT NULL DEFAULT 1,
        needs_resync INTEGER NOT NULL DEFAULT 1,
        resync_approved_by TEXT,
        resync_approved_at TEXT,
        dryrun_ok_at TEXT,
        dryrun_summary TEXT,
        last_success_at TEXT,
        last_run_at TEXT,
        last_result TEXT,
        next_run_at TEXT,
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        consecutive_timeouts INTEGER NOT NULL DEFAULT 0,
        backoff_factor INTEGER NOT NULL DEFAULT 1,
        last_check_at TEXT,
        unsyncable_count INTEGER NOT NULL DEFAULT 0,
        preflight_requested INTEGER NOT NULL DEFAULT 0,
        preflight_at TEXT,
        preflight_summary TEXT,
        final_sync_requested INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE sync_runs (
        id INTEGER PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        started_at TEXT NOT NULL,
        ended_at TEXT,
        kind TEXT NOT NULL CHECK (kind IN ('dryrun','resync','bisync','check','preflight')),
        exit_code INTEGER,
        result TEXT,
        files_copied INTEGER DEFAULT 0,
        files_deleted INTEGER DEFAULT 0,
        bytes INTEGER DEFAULT 0,
        conflicts INTEGER DEFAULT 0,
        errors_count INTEGER DEFAULT 0,
        throttled INTEGER DEFAULT 0,
        detail TEXT,
        log_path TEXT
    );
    CREATE INDEX sync_runs_user ON sync_runs(user_id, id DESC);
    CREATE TABLE issues (
        id INTEGER PRIMARY KEY,
        user_id TEXT REFERENCES users(id),
        type TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
        opened_at TEXT NOT NULL,
        closed_at TEXT,
        summary TEXT NOT NULL
    );
    CREATE INDEX issues_open ON issues(closed_at, user_id, type);
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        is_secret INTEGER NOT NULL DEFAULT 0,
        key_id TEXT,
        updated_by TEXT,
        updated_at TEXT
    );
    CREATE TABLE audit_log (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        details_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
    );
    CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        data_json TEXT NOT NULL,
        csrf TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE TABLE auth_flows (
        state TEXT PRIMARY KEY,
        flow_ct BLOB NOT NULL,
        key_id TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE rate_events (bucket TEXT NOT NULL, ts TEXT NOT NULL);
    CREATE INDEX rate_events_b ON rate_events(bucket, ts);
    CREATE TABLE heartbeat (component TEXT PRIMARY KEY, ts TEXT NOT NULL, detail TEXT);
    """,
    # 2: SPEC v0.2 §9.4 safety_abort handling. Expand-only: new nullable/defaulted columns, and
    #    sync_runs.kind gains 'delta' (dry-run --force delta list) and 'force' (one Accept-deletes run).
    #    The v0.1 code never writes the new kinds/columns, so it still runs against this schema.
    """
    ALTER TABLE sync_profiles ADD COLUMN consecutive_crit_retry INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sync_profiles ADD COLUMN safety_abort_at TEXT;
    ALTER TABLE sync_profiles ADD COLUMN safety_abort_json TEXT;
    ALTER TABLE sync_profiles ADD COLUMN safety_delta_requested INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sync_profiles ADD COLUMN safety_delta_at TEXT;
    ALTER TABLE sync_profiles ADD COLUMN safety_delta_summary TEXT;
    ALTER TABLE sync_profiles ADD COLUMN safety_action TEXT CHECK (safety_action IN ('restore','accept_deletes'));
    ALTER TABLE sync_profiles ADD COLUMN safety_action_by TEXT;
    ALTER TABLE sync_profiles ADD COLUMN safety_action_at TEXT;
    CREATE TABLE sync_runs_v2 (
        id INTEGER PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id),
        started_at TEXT NOT NULL,
        ended_at TEXT,
        kind TEXT NOT NULL CHECK (kind IN ('dryrun','resync','bisync','check','preflight','delta','force')),
        exit_code INTEGER,
        result TEXT,
        files_copied INTEGER DEFAULT 0,
        files_deleted INTEGER DEFAULT 0,
        bytes INTEGER DEFAULT 0,
        conflicts INTEGER DEFAULT 0,
        errors_count INTEGER DEFAULT 0,
        throttled INTEGER DEFAULT 0,
        detail TEXT,
        log_path TEXT
    );
    INSERT INTO sync_runs_v2 SELECT id, user_id, started_at, ended_at, kind, exit_code, result, files_copied,
        files_deleted, bytes, conflicts, errors_count, throttled, detail, log_path FROM sync_runs;
    DROP TABLE sync_runs;
    ALTER TABLE sync_runs_v2 RENAME TO sync_runs;
    CREATE INDEX sync_runs_user ON sync_runs(user_id, id DESC);
    """,
    # 3: SPEC v0.3 §9.4 / §9.4.1. Expand-only (new nullable/defaulted columns).
    """
    ALTER TABLE sync_profiles ADD COLUMN last_crit_error TEXT;
    ALTER TABLE sync_profiles ADD COLUMN safety_restore_when TEXT
        CHECK (safety_restore_when IN ('next_slot','tonight'));
    ALTER TABLE sync_profiles ADD COLUMN safety_approved_deletes INTEGER;
    ALTER TABLE sync_profiles ADD COLUMN safety_accept_state TEXT;
    ALTER TABLE sync_profiles ADD COLUMN safety_accept_state_at TEXT;
    ALTER TABLE sync_profiles ADD COLUMN restore_timeouts INTEGER NOT NULL DEFAULT 0;
    """,
    # 4: SPEC v0.4 (Reid's answers 2026-10-20). Expand-only.
    #    Per-side approved delete counts (rclone applies --max-delete per side), the one-time automatic
    #    re-queue of a timed-out next-slot Restore as a tonight run, and a separate mount-failure counter.
    """
    ALTER TABLE sync_profiles ADD COLUMN safety_approved_del_p1 INTEGER;
    ALTER TABLE sync_profiles ADD COLUMN safety_approved_del_p2 INTEGER;
    ALTER TABLE sync_profiles ADD COLUMN safety_restore_requeued INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE sync_profiles ADD COLUMN consecutive_mount_failures INTEGER NOT NULL DEFAULT 0;
    """,
    # 5: SPEC v0.5. Expand-only.
    #    onboarding_completed_at: NULL = onboarding incomplete; set by the first successful normal bisync
    #    after the onboarding --resync (§6.1 step 8). Backfilled for users that already had one.
    #    tonight_held_at: last audited "<30 min left, held for the next night" deferral (§9.4.1), so the
    #    60 s tick logs it once per night, not every minute.
    """
    ALTER TABLE sync_profiles ADD COLUMN onboarding_completed_at TEXT;
    ALTER TABLE sync_profiles ADD COLUMN tonight_held_at TEXT;
    UPDATE sync_profiles SET onboarding_completed_at = COALESCE(last_success_at, '1970-01-01T00:00:00+00:00')
     WHERE user_id IN (SELECT user_id FROM sync_runs WHERE kind = 'bisync' AND result = 'ok');
    """,
    # 6: SPEC v0.6. Expand-only.
    #    tonight_hold_nights: nights the CURRENT Restore has been held by the 30-min cutoff (1 -> low alert,
    #    2+ -> medium). Reset when an admin chooses a new Restore.
    #    worker_state: server-wide flags. Row key 'nas_global_pause' = Option B svc-sync login rejected.
    """
    ALTER TABLE sync_profiles ADD COLUMN tonight_hold_nights INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE worker_state (
        key TEXT PRIMARY KEY,
        set_at TEXT NOT NULL,
        reason TEXT NOT NULL,
        detail_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
]

NAS_GLOBAL_PAUSE = "nas_global_pause"   # worker_state key (SPEC v0.6 §9.4, Option B only)

TONIGHT_MIN_REMAINING_S = 30 * 60   # SPEC v0.5 §9.4.1: a tonight run starts only with >= 30 min left

SECRET_DETAIL_KEYS = {"password", "secret", "token", "refresh_token", "access_token", "smtp_password",
                      "client_secret", "nas_password", "credential"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def parse_iso(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def pack(s: Sealed) -> bytes:
    return s.nonce + s.ciphertext


def unpack(blob: bytes, key_id: str) -> Sealed:
    return Sealed(bytes(blob[12:]), bytes(blob[:12]), key_id)


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("***" if any(s in k.lower() for s in SECRET_DETAIL_KEYS) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _audit_hash(prev: str, seq: int, ts: str, actor: str, action: str, target: str, details: str) -> str:
    payload = json.dumps([prev, seq, ts, actor, action, target, details], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


class DB:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._shared = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None) \
            if path == ":memory:" else None
        self._wlock = threading.RLock()
        self.migrate()

    @property
    def conn(self) -> sqlite3.Connection:
        c = self._shared or getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            c.execute("PRAGMA journal_mode=WAL")
            self._local.c = c
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def q(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self._wlock:
            return self.conn.execute(sql, params)

    def one(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        return self.q(sql, params).fetchone()

    def all(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        return self.q(sql, params).fetchall()

    @contextlib.contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._wlock:
            c = self.conn
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise

    def schema_version(self) -> int:
        return int(self.conn.execute("PRAGMA user_version").fetchone()[0])

    def migrate(self) -> int:
        with self._wlock:
            v = self.schema_version()
            for i, script in enumerate(MIGRATIONS[v:], start=v + 1):
                self.conn.executescript("BEGIN;" + script + f";PRAGMA user_version={i};COMMIT;")
            return self.schema_version()

    # ---- users ---------------------------------------------------------
    def create_user(self, entra_oid: str, upn: str, display_name: str, local_name: str, state: str,
                    is_pilot: bool = True) -> str:
        uid, now = str(uuid.uuid4()), iso(utcnow())
        with self.tx() as c:
            c.execute("INSERT INTO users(id, entra_oid, upn, display_name, local_name, state, is_pilot, created_at,"
                      " updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                      (uid, entra_oid, upn, display_name, local_name, state, int(is_pilot), now, now))
            c.execute("INSERT INTO sync_profiles(user_id, path1) VALUES (?, ?)", (uid, f"od-{uid}:"))
        return uid

    def user(self, uid: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM users WHERE id=?", (uid,))

    def user_by_oid(self, oid: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM users WHERE entra_oid=?", (oid,))

    def users(self, include_removed: bool = False) -> list[sqlite3.Row]:
        where = "" if include_removed else "WHERE u.state != 'removed'"
        return self.all(f"SELECT u.*, p.* FROM users u JOIN sync_profiles p ON p.user_id=u.id {where} "
                        "ORDER BY u.created_at, u.id")

    def user_full(self, uid: str) -> sqlite3.Row | None:
        return self.one("SELECT u.*, p.* FROM users u JOIN sync_profiles p ON p.user_id=u.id WHERE u.id=?", (uid,))

    def set_state(self, uid: str, state: str, reason: str | None = None) -> None:
        assert state in STATES, state
        self.q("UPDATE users SET state=?, pause_reason=?, updated_at=? WHERE id=?", (state, reason, iso(utcnow()), uid))

    def update_profile(self, uid: str, **f: Any) -> None:
        if f:
            self.q(f"UPDATE sync_profiles SET {','.join(k + '=?' for k in f)} WHERE user_id=?", (*f.values(), uid))

    # ---- credentials ----------------------------------------------------
    def put_ms_credential(self, kr: Keyring, uid: str, refresh_token: str, drive_id: str | None = None,
                          drive_type: str | None = None) -> None:
        s = kr.seal(refresh_token, Keyring.aad("ms_credentials", uid, "refresh_token"))
        now = iso(utcnow())
        self.q("INSERT INTO ms_credentials(user_id, refresh_token_ct, key_id, drive_id, drive_type, token_obtained_at,"
               " last_refresh_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
               "refresh_token_ct=excluded.refresh_token_ct, key_id=excluded.key_id, "
               "drive_id=COALESCE(excluded.drive_id, drive_id), drive_type=COALESCE(excluded.drive_type, drive_type), "
               "token_obtained_at=excluded.token_obtained_at, last_refresh_at=excluded.last_refresh_at, "
               "last_refresh_error=NULL", (uid, pack(s), s.key_id, drive_id, drive_type, now, now))

    def rotate_refresh_token(self, kr: Keyring, uid: str, refresh_token: str) -> None:
        s = kr.seal(refresh_token, Keyring.aad("ms_credentials", uid, "refresh_token"))
        self.q("UPDATE ms_credentials SET refresh_token_ct=?, key_id=?, last_refresh_at=?, last_refresh_error=NULL "
               "WHERE user_id=?", (pack(s), s.key_id, iso(utcnow()), uid))

    def ms_credential(self, uid: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM ms_credentials WHERE user_id=?", (uid,))

    def refresh_token(self, kr: Keyring, uid: str) -> str | None:
        r = self.ms_credential(uid)
        if not r:
            return None
        return kr.open(unpack(r["refresh_token_ct"], r["key_id"]), Keyring.aad("ms_credentials", uid, "refresh_token"))

    def put_nas_credential(self, kr: Keyring, uid: str, provider: str, username: str, password: str) -> None:
        su = kr.seal(username, Keyring.aad("nas_credentials", uid, "username"))
        sp = kr.seal(password, Keyring.aad("nas_credentials", uid, "password"))
        self.q("INSERT INTO nas_credentials(user_id, provider, username_ct, password_ct, key_id, verified_at, "
               "failure_count) VALUES (?,?,?,?,?,?,0) ON CONFLICT(user_id) DO UPDATE SET provider=excluded.provider, "
               "username_ct=excluded.username_ct, password_ct=excluded.password_ct, key_id=excluded.key_id, "
               "verified_at=excluded.verified_at, failure_count=0, last_failure_at=NULL",
               (uid, provider, pack(su), pack(sp), su.key_id, iso(utcnow())))

    def nas_credential_meta(self, uid: str) -> sqlite3.Row | None:
        return self.one("SELECT user_id, provider, key_id, verified_at, last_failure_at, failure_count "
                        "FROM nas_credentials WHERE user_id=?", (uid,))

    def nas_credential(self, kr: Keyring, uid: str) -> tuple[str, str] | None:
        r = self.one("SELECT * FROM nas_credentials WHERE user_id=?", (uid,))
        if not r:
            return None
        return (kr.open(unpack(r["username_ct"], r["key_id"]), Keyring.aad("nas_credentials", uid, "username")),
                kr.open(unpack(r["password_ct"], r["key_id"]), Keyring.aad("nas_credentials", uid, "password")))

    def crypto_erase(self, uid: str) -> None:
        """SPEC §6.3: delete credential rows with secure_delete on, then VACUUM."""
        with self._wlock:
            c = self.conn
            c.execute("PRAGMA secure_delete=ON")
            with self.tx() as t:
                t.execute("DELETE FROM ms_credentials WHERE user_id=?", (uid,))
                t.execute("DELETE FROM nas_credentials WHERE user_id=?", (uid,))
            c.execute("VACUUM")

    # ---- runs / issues ---------------------------------------------------
    def start_run(self, uid: str, kind: str, log_path: str) -> int:
        return int(self.q("INSERT INTO sync_runs(user_id, started_at, kind, log_path) VALUES (?,?,?,?)",
                          (uid, iso(utcnow()), kind, log_path)).lastrowid)

    def finish_run(self, run_id: int, **f: Any) -> None:
        f["ended_at"] = iso(utcnow())
        self.q(f"UPDATE sync_runs SET {','.join(k + '=?' for k in f)} WHERE id=?", (*f.values(), run_id))

    def runs(self, uid: str, limit: int = 20) -> list[sqlite3.Row]:
        return self.all("SELECT id, started_at, ended_at, kind, exit_code, result, files_copied, files_deleted, bytes,"
                        " conflicts, errors_count, throttled, detail FROM sync_runs WHERE user_id=? "
                        "ORDER BY id DESC LIMIT ?", (uid, limit))

    def open_issue(self, uid: str | None, type_: str, severity: str, summary: str) -> bool:
        """Open an issue unless the same (user, type) is already open. Returns True if newly opened."""
        if self.one("SELECT 1 FROM issues WHERE closed_at IS NULL AND type=? AND user_id IS ?", (type_, uid)):
            return False
        self.q("INSERT INTO issues(user_id, type, severity, opened_at, summary) VALUES (?,?,?,?,?)",
               (uid, type_, severity, iso(utcnow()), summary))
        return True

    def close_issues(self, uid: str | None, *types: str) -> None:
        for t in types:
            self.q("UPDATE issues SET closed_at=? WHERE closed_at IS NULL AND type=? AND user_id IS ?",
                   (iso(utcnow()), t, uid))

    def open_issues(self, uid: str | None = None) -> list[sqlite3.Row]:
        if uid:
            return self.all("SELECT * FROM issues WHERE closed_at IS NULL AND user_id=? ORDER BY id DESC", (uid,))
        return self.all("SELECT i.*, u.upn FROM issues i LEFT JOIN users u ON u.id=i.user_id "
                        "WHERE i.closed_at IS NULL ORDER BY i.id DESC")

    # ---- audit -----------------------------------------------------------
    def audit(self, actor: str, action: str, target: str = "", details: dict | None = None) -> int:
        d = json.dumps(redact(details or {}), sort_keys=True, separators=(",", ":"))
        with self.tx() as c:
            last = c.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev, seq = (last["hash"], last["seq"] + 1) if last else ("0" * 64, 1)
            ts = iso(utcnow())
            h = _audit_hash(prev, seq, ts, actor, action, target, d)
            c.execute("INSERT INTO audit_log(seq, ts, actor, action, target, details_json, prev_hash, hash) "
                      "VALUES (?,?,?,?,?,?,?,?)", (seq, ts, actor, action, target, d, prev, h))
        return seq

    def verify_audit_chain(self) -> tuple[bool, int, str]:
        prev, n = "0" * 64, 0
        for r in self.all("SELECT * FROM audit_log ORDER BY seq"):
            n += 1
            expect = _audit_hash(prev, r["seq"], r["ts"], r["actor"], r["action"], r["target"] or "", r["details_json"])
            if r["prev_hash"] != prev or r["hash"] != expect:
                return False, n, f"chain broken at seq {r['seq']}"
            prev = r["hash"]
        return True, n, "ok"

    def audit_rows(self, actor: str = "", action: str = "", since: str = "", limit: int = 500) -> list[sqlite3.Row]:
        sql, p = "SELECT * FROM audit_log WHERE 1=1", []
        if actor:
            sql += " AND actor LIKE ?"; p.append(f"%{actor}%")
        if action:
            sql += " AND action LIKE ?"; p.append(f"%{action}%")
        if since:
            sql += " AND ts >= ?"; p.append(since)
        return self.all(sql + " ORDER BY seq DESC LIMIT ?", (*p, limit))

    # ---- heartbeat -------------------------------------------------------
    # ---- server-wide flags (worker_state) ------------------------------------
    def flag(self, key: str) -> dict | None:
        r = self.one("SELECT * FROM worker_state WHERE key=?", (key,))
        if r is None:
            return None
        return {"key": r["key"], "set_at": r["set_at"], "reason": r["reason"], **json.loads(r["detail_json"])}

    def set_flag(self, key: str, reason: str, **detail) -> bool:
        """Set a flag unless already set. Returns True if newly set."""
        with self.tx() as c:
            if c.execute("SELECT 1 FROM worker_state WHERE key=?", (key,)).fetchone():
                return False
            c.execute("INSERT INTO worker_state(key, set_at, reason, detail_json) VALUES (?,?,?,?)",
                      (key, iso(utcnow()), reason, json.dumps(detail)))
            return True

    def update_flag(self, key: str, **detail) -> None:
        f = self.flag(key)
        if f is None:
            return
        cur = {k: v for k, v in f.items() if k not in ("key", "set_at", "reason")}
        cur.update(detail)
        self.q("UPDATE worker_state SET detail_json=? WHERE key=?", (json.dumps(cur), key))

    def clear_flag(self, key: str) -> bool:
        with self.tx() as c:
            return c.execute("DELETE FROM worker_state WHERE key=?", (key,)).rowcount > 0

    def setting_version(self, key: str) -> str | None:
        """An opaque version of a stored setting: a hash of the stored (for secrets: encrypted, freshly
        nonced) value, so every save is a new version. Never the secret itself."""
        r = self.one("SELECT value_json FROM settings WHERE key=?", (key,))
        if r is None:
            return None
        import hashlib
        return hashlib.sha256(str(r["value_json"]).encode()).hexdigest()[:16]

    def beat(self, component: str, detail: str = "") -> None:
        self.q("INSERT INTO heartbeat(component, ts, detail) VALUES (?,?,?) ON CONFLICT(component) DO UPDATE SET "
               "ts=excluded.ts, detail=excluded.detail", (component, iso(utcnow()), detail))

    def heartbeat(self, component: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM heartbeat WHERE component=?", (component,))

    # ---- rate limiting (SPEC §7.6: 5 per 15 min) --------------------------
    def rate_limited(self, bucket: str, limit: int = 5, window_s: int = 900) -> bool:
        now = utcnow()
        cutoff = iso(datetime.fromtimestamp(now.timestamp() - window_s, timezone.utc))
        with self.tx() as c:
            c.execute("DELETE FROM rate_events WHERE ts < ?", (cutoff,))
            n = c.execute("SELECT COUNT(*) FROM rate_events WHERE bucket=?", (bucket,)).fetchone()[0]
            if n >= limit:
                return True
            c.execute("INSERT INTO rate_events(bucket, ts) VALUES (?,?)", (bucket, iso(now)))
        return False
