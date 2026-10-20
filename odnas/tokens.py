"""How rclone gets Microsoft access (SPEC §2, §9.2), behind one interface.

BrokerTokenStrategy (default, SPEC design, PENDING LAB TEST T-A3):
    rclone's config has token_url -> http://127.0.0.1:8081/broker/<id>/token and a
    per-run random *handle* in place of the refresh token. No client credential and no
    real refresh token ever reach disk. The broker exchanges the real refresh token with
    MSAL (certificate credential), stores the rotated refresh token re-encrypted, and
    returns a short-lived access token plus the same handle.

TmpfsConfigStrategy (fallback if T-A3 fails):
    the real refresh token and the client secret go into a per-run 0600 rclone config
    on tmpfs; after the run the (possibly rotated) token is read back, re-encrypted into
    the DB, and the file is shredded. Requires credential_type=secret.
"""
from __future__ import annotations

import configparser
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from odnas.config import RCLONE_ACCESS_SCOPES, Config
from odnas.crypto import Keyring
from odnas.db import DB, iso, utcnow
from odnas.entra import AUTH_CA, AUTH_OK, AUTH_REAUTH, EntraClient, classify_auth_error

EXPIRED = "2000-01-01T00:00:00Z"


def remote_name(uid: str) -> str:
    return f"od-{uid}"


def render_rclone_config(cfg: Config, uid: str, drive_id: str, drive_type: str, token: dict,
                         token_url: str, client_secret: str = "") -> str:
    """One remote per user per run file (avoids token write races between users)."""
    for v in (uid, drive_id, drive_type, token_url):
        if any(c in str(v) for c in "\r\n[]"):
            raise ValueError("illegal character in rclone config value")
    lines = [
        f"[{remote_name(uid)}]",
        "type = onedrive",
        f"drive_type = {drive_type or 'business'}",
        f"drive_id = {drive_id}",
        f"client_id = {cfg.client_id}",
        f"client_secret = {client_secret}",
        f"token_url = {token_url}",
        f"auth_url = {cfg.auth_url}",
        "token = " + json.dumps(token, separators=(",", ":")),
        f"access_scopes = {RCLONE_ACCESS_SCOPES}",
        "disable_site_permission = true",
        "",
    ]
    return "\n".join(lines)


def write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def shred(path: Path) -> None:
    """Best effort: overwrite then unlink. tmpfs never hits a disk, so this is belt-and-braces."""
    try:
        n = path.stat().st_size
        with open(path, "r+b") as f:
            f.write(b"\0" * n)
            f.flush()
            os.fsync(f.fileno())
    except FileNotFoundError:
        return
    except OSError:
        pass
    path.unlink(missing_ok=True)


@dataclass
class RunAuth:
    config_path: Path
    handle: str = field(default="", repr=False)


class TokenStrategy(Protocol):
    name: str
    def prepare(self, uid: str, run_id: int) -> RunAuth: ...
    def finish(self, uid: str, auth: RunAuth) -> str: ...   # returns an auth classification or AUTH_OK


@dataclass
class _Handle:
    uid: str
    run_id: int
    expires: float
    outcome: str = AUTH_OK
    refreshes: int = 0


class TokenBroker:
    """Lives inside the worker process. Thread-safe; one refresh per user at a time."""

    HANDLE_TTL_S = 48 * 3600  # upper bound; revoked as soon as the run finishes

    def __init__(self, db: DB, kr: Keyring, entra: EntraClient, cfg: Config):
        self.db, self.kr, self.entra, self.cfg = db, kr, entra, cfg
        self._handles: dict[str, _Handle] = {}
        self._lock = threading.Lock()
        self._user_locks: dict[str, threading.Lock] = {}

    def issue(self, uid: str, run_id: int) -> str:
        h = secrets.token_urlsafe(32)
        with self._lock:
            self._handles[h] = _Handle(uid, run_id, time.time() + self.HANDLE_TTL_S)
        return h

    def revoke(self, handle: str) -> _Handle | None:
        with self._lock:
            return self._handles.pop(handle, None)

    def active_handles(self) -> int:
        return len(self._handles)

    def token(self, uid: str, form: dict[str, str]) -> tuple[int, dict]:
        """Implements the OAuth2 token endpoint shape rclone expects (refresh_token grant only)."""
        if form.get("grant_type") != "refresh_token":
            return 400, {"error": "unsupported_grant_type"}
        if form.get("client_id") and form["client_id"] != self.cfg.client_id:
            return 401, {"error": "invalid_client"}
        handle = form.get("refresh_token", "")
        with self._lock:
            h = self._handles.get(handle)
        if not h or h.uid != uid or h.expires < time.time():
            return 400, {"error": "invalid_grant", "error_description": "unknown or expired run handle"}
        with self._lock:
            ul = self._user_locks.setdefault(uid, threading.Lock())
        with ul:
            rt = self.db.refresh_token(self.kr, uid)
            if not rt:
                h.outcome = AUTH_REAUTH
                return 400, {"error": "invalid_grant", "error_description": "no stored credential"}
            res = self.entra.refresh(rt)
            if not res.ok:
                cls = res.classification
                h.outcome = cls
                # store only the error code family, never the token or full response
                codes = ",".join(f"AADSTS{c}" for c in res.error_codes) or res.error
                self.db.q("UPDATE ms_credentials SET last_refresh_error=? WHERE user_id=?", (f"{cls}:{codes}"[:200], uid))
                return 400, {"error": res.error or "invalid_grant", "error_description": f"refresh failed ({cls})"}
            if res.refresh_token and res.refresh_token != rt:
                self.db.rotate_refresh_token(self.kr, uid, res.refresh_token)
            else:
                self.db.q("UPDATE ms_credentials SET last_refresh_at=?, last_refresh_error=NULL WHERE user_id=?",
                          (iso(utcnow()), uid))
            h.refreshes += 1
        return 200, {"access_token": res.access_token, "token_type": "Bearer",
                     "expires_in": res.expires_in or 3600, "refresh_token": handle}


class BrokerTokenStrategy:
    name = "broker"

    def __init__(self, cfg: Config, db: DB, broker: TokenBroker):
        self.cfg, self.db, self.broker = cfg, db, broker

    def prepare(self, uid: str, run_id: int) -> RunAuth:
        cred = self.db.ms_credential(uid)
        handle = self.broker.issue(uid, run_id)
        token = {"access_token": "", "token_type": "Bearer", "refresh_token": handle, "expiry": EXPIRED}
        text = render_rclone_config(self.cfg, uid, cred["drive_id"], cred["drive_type"], token,
                                    f"{self.cfg.broker_base}/broker/{uid}/token")
        path = Path(self.cfg.p_run) / "rclone" / f"{uid}.conf"
        write_private(path, text)
        return RunAuth(path, handle)

    def finish(self, uid: str, auth: RunAuth) -> str:
        h = self.broker.revoke(auth.handle)
        shred(auth.config_path)
        return h.outcome if h else AUTH_OK


class TmpfsConfigStrategy:
    name = "tmpfs_config"

    def __init__(self, cfg: Config, db: DB, kr: Keyring):
        self.cfg, self.db, self.kr = cfg, db, kr

    def prepare(self, uid: str, run_id: int) -> RunAuth:
        cred = self.db.ms_credential(uid)
        rt = self.db.refresh_token(self.kr, uid)
        secret = self.cfg.read_secret("entra-client-secret").decode().strip()
        token = {"access_token": "", "token_type": "Bearer", "refresh_token": rt, "expiry": EXPIRED}
        text = render_rclone_config(self.cfg, uid, cred["drive_id"], cred["drive_type"], token,
                                    self.cfg.token_url, client_secret=secret)
        path = Path(self.cfg.p_run) / "rclone" / f"{uid}.conf"
        write_private(path, text)
        return RunAuth(path)

    def finish(self, uid: str, auth: RunAuth) -> str:
        try:
            cp = configparser.ConfigParser(interpolation=None)
            cp.read(auth.config_path)
            raw = cp.get(remote_name(uid), "token", fallback="")
            new_rt = json.loads(raw).get("refresh_token", "") if raw else ""
            if new_rt and new_rt != self.db.refresh_token(self.kr, uid):
                self.db.rotate_refresh_token(self.kr, uid, new_rt)
        finally:
            shred(auth.config_path)
        return AUTH_OK  # auth failures are detected from the rclone log in this mode


def log_auth_classification(log_text: str) -> str:
    """Used in both modes: rclone surfaces token-endpoint errors in its log."""
    if "oauth2" not in log_text and "AADSTS" not in log_text and "invalid_grant" not in log_text:
        return AUTH_OK
    c = classify_auth_error("", log_text)
    return c if c in (AUTH_REAUTH, AUTH_CA) else AUTH_OK
