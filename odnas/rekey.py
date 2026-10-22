"""Re-encrypt every sealed value under the current primary key (SPEC §7.2 key_id rotation)."""
from __future__ import annotations

import json

from odnas.crypto import Keyring
from odnas.db import DB, pack, unpack


def rekey_all(db: DB, kr: Keyring) -> dict[str, int]:
    n = {"ms_credentials": 0, "google_credentials": 0, "nas_credentials": 0, "settings": 0}
    for r in db.all("SELECT * FROM google_credentials WHERE key_id != ?", (kr.primary_id,)):   # v0.9
        s = kr.reseal(unpack(r["refresh_token_ct"], r["key_id"]),
                      Keyring.aad("google_credentials", r["user_id"], "refresh_token"))
        db.q("UPDATE google_credentials SET refresh_token_ct=?, key_id=? WHERE user_id=?",
             (pack(s), s.key_id, r["user_id"]))
        n["google_credentials"] += 1
    for r in db.all("SELECT * FROM ms_credentials WHERE key_id != ?", (kr.primary_id,)):
        aad = Keyring.aad("ms_credentials", r["user_id"], "refresh_token")
        s = kr.reseal(unpack(r["refresh_token_ct"], r["key_id"]), aad)
        db.q("UPDATE ms_credentials SET refresh_token_ct=?, key_id=? WHERE user_id=?", (pack(s), s.key_id, r["user_id"]))
        n["ms_credentials"] += 1
    for r in db.all("SELECT * FROM nas_credentials WHERE key_id != ?", (kr.primary_id,)):
        su = kr.reseal(unpack(r["username_ct"], r["key_id"]), Keyring.aad("nas_credentials", r["user_id"], "username"))
        sp = kr.reseal(unpack(r["password_ct"], r["key_id"]), Keyring.aad("nas_credentials", r["user_id"], "password"))
        db.q("UPDATE nas_credentials SET username_ct=?, password_ct=?, key_id=? WHERE user_id=?",
             (pack(su), pack(sp), su.key_id, r["user_id"]))
        n["nas_credentials"] += 1
    for r in db.all("SELECT * FROM settings WHERE is_secret=1 AND key_id != ?", (kr.primary_id,)):
        blob = bytes.fromhex(json.loads(r["value_json"]))
        s = kr.reseal(unpack(blob, r["key_id"]), Keyring.aad("settings", r["key"], "value"))
        db.q("UPDATE settings SET value_json=?, key_id=? WHERE key=?", (json.dumps(pack(s).hex()), s.key_id, r["key"]))
        n["settings"] += 1
    db.audit("system", "rekey", "", n)
    return n
