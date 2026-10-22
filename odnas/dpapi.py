r"""Windows secret storage with DPAPI (SPEC v0.9 §11.5.4).

On Windows the secrets that systemd credentials hold on Ubuntu (data.key, entra-app.key,
google-client.secret, optional entra-client-secret, data.key.old) live as
    %ProgramData%\SpringSync\keys\<name>.dpapi
encrypted with CryptProtectData in the *service account's user scope* (not machine scope: another
local account or process cannot unprotect them). Only the account svc-springsync can read them back.

Getting a secret in: the installer runs as an Administrator, not as svc-springsync, so it cannot DPAPI-
protect for that account directly. It writes the plain file to keys\incoming\<name> (ACL: SYSTEM,
Administrators, svc-springsync only; inheritance off). The first web/worker start (running as svc-springsync)
calls `ingest_incoming`, which protects each file into <name>.dpapi, verifies the round trip, and overwrites
and deletes the plain file. `odnas secrets ingest` does the same on demand.

CAVEAT (SPEC §11.5.4): an administrator *reset* of the svc-springsync password (rather than a change by the
account itself) loses the DPAPI master key, and every *.dpapi file becomes unreadable. Recovery = put the
escrowed data.key (and the other secrets) back into keys\incoming. Escrow is mandatory before go-live.

The Windows API is reached through ctypes; tests inject a fake (`set_backend`).
"""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from odnas import hostos

log = logging.getLogger("odnas.dpapi")
SUFFIX = ".dpapi"
INCOMING = "incoming"
KNOWN_SECRETS = ("data.key", "data.key.old", "entra-app.key", "entra-client-secret", "google-client.secret")
_ENTROPY = b"SpringSync/v1/"   # optional entropy + secret name: a .dpapi file renamed to another name fails
CRYPTPROTECT_UI_FORBIDDEN = 0x1


class DpapiError(RuntimeError):
    pass


class _WinDpapi:
    """CryptProtectData / CryptUnprotectData via ctypes (crypt32.dll)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        self._c, self._BLOB = ctypes, BLOB
        self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def _blob(self, data: bytes):
        buf = self._c.create_string_buffer(data, len(data))
        return self._BLOB(len(data), self._c.cast(buf, self._c.POINTER(self._c.c_char))), buf

    def _call(self, fn, data: bytes, entropy: bytes) -> bytes:
        c = self._c
        din, _k1 = self._blob(data)
        ent, _k2 = self._blob(entropy)
        out = self._BLOB()
        # (pDataIn, description in/out = NULL, pOptionalEntropy, reserved, prompt, flags, pDataOut)
        if not fn(c.byref(din), None, c.byref(ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, c.byref(out)):
            raise DpapiError(f"DPAPI call failed (Windows error {c.get_last_error()})")
        try:
            return c.string_at(out.pbData, out.cbData)
        finally:
            self._kernel32.LocalFree(out.pbData)

    def protect(self, data: bytes, entropy: bytes) -> bytes:
        return self._call(self._crypt32.CryptProtectData, data, entropy)

    def unprotect(self, data: bytes, entropy: bytes) -> bytes:
        return self._call(self._crypt32.CryptUnprotectData, data, entropy)


_backend = None


def set_backend(b) -> None:
    """Tests: inject an object with protect(data, entropy) / unprotect(data, entropy)."""
    global _backend
    _backend = b


def backend():
    global _backend
    if _backend is None:
        if os.name != "nt":
            raise DpapiError("DPAPI is only available on Windows")
        _backend = _WinDpapi()
    return _backend


def _entropy(name: str) -> bytes:
    return _ENTROPY + name.encode()


def dpapi_path(cfg, name: str) -> Path:
    return Path(hostos.join(cfg, cfg.p_keys, name + SUFFIX))


def incoming_dir(cfg) -> Path:
    return Path(hostos.join(cfg, cfg.p_keys, INCOMING))


def read_secret(cfg, name: str) -> bytes:
    from odnas.config import ConfigError
    if "/" in name or "\\" in name or name.startswith("."):
        raise ConfigError("bad secret name")
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")   # dev/tests only
    if cred_dir and (Path(cred_dir) / name).is_file():
        return (Path(cred_dir) / name).read_bytes()
    p = dpapi_path(cfg, name)
    if p.is_file():
        try:
            return backend().unprotect(p.read_bytes(), _entropy(name))
        except DpapiError as e:
            raise ConfigError(f"secret '{name}' could not be decrypted with DPAPI (was the service account "
                              f"password reset? see INSTALL-WINDOWS.md 'Lost keys'): {e}") from None
    if (incoming_dir(cfg) / name).is_file():
        raise ConfigError(f"secret '{name}' is waiting in keys\\incoming; start the services or run "
                          f"'odnas secrets ingest' as the service account")
    raise ConfigError(f"secret '{name}' not found ({p})")


def _overwrite_delete(p: Path) -> None:
    try:
        n = p.stat().st_size
        with open(p, "r+b") as fh:
            fh.write(os.urandom(max(n, 1)))
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    p.unlink(missing_ok=True)


def ingest_incoming(cfg) -> list[str]:
    """Protect every keys\\incoming\\<known name> into keys\\<name>.dpapi, then shred the plain file.
    Never overwrites an existing .dpapi with different content unless the incoming file is newer (that is how
    a secret is rotated or a lost key restored). Serialised across web and worker with a file lock.
    Returns the names ingested. Names are listed, values never."""
    inc = incoming_dir(cfg)
    if not inc.is_dir():
        return []
    done: list[str] = []
    with hostos.locked(Path(hostos.join(cfg, cfg.p_keys, ".ingest.lock"))):   # the real OS decides the lock API
        for name in KNOWN_SECRETS:
            src = inc / name
            if not src.is_file():
                continue
            plain = src.read_bytes()
            if not plain:
                log.warning("ignoring empty incoming secret %s", name)
                continue
            if name.startswith("data.key") and len(plain) != 32:
                raise DpapiError(f"{name} must be exactly 32 bytes (got {len(plain)})")
            blob = backend().protect(plain, _entropy(name))
            if backend().unprotect(blob, _entropy(name)) != plain:
                raise DpapiError(f"DPAPI round trip failed for {name}")
            dst = dpapi_path(cfg, name)
            tmp = dst.with_name(dst.name + ".tmp")
            tmp.write_bytes(blob)
            os.replace(tmp, dst)
            _overwrite_delete(src)
            done.append(name)
            log.info("secret %s protected with DPAPI (sha256 prefix %s)", name,
                     hashlib.sha256(plain).hexdigest()[:8])
    return done


def status(cfg) -> dict[str, str]:
    """name -> 'protected' | 'incoming' | 'missing' (no decryption, no values)."""
    out = {}
    for name in KNOWN_SECRETS:
        if dpapi_path(cfg, name).is_file():
            out[name] = "protected"
        elif (incoming_dir(cfg) / name).is_file():
            out[name] = "incoming"
        else:
            out[name] = "missing"
    return out
