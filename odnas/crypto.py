"""Encryption at rest (SPEC §7.2): AES-256-GCM, random 96-bit nonce per value,
associated data = "<table>:<row id>:<field>" so a ciphertext can't be moved to
another row or column. The 32-byte data key lives outside the DB (systemd
credential `data.key`); `key_id` (first 8 hex chars of SHA-256(key)) lets the
key be rotated: load the old key as `data.key.old`, run `odnas rekey`.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

__all__ = ["Keyring", "Sealed", "InvalidTag", "key_id_for", "new_data_key"]


def key_id_for(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:8]


def new_data_key() -> bytes:
    return os.urandom(32)


@dataclass(frozen=True)
class Sealed:
    ciphertext: bytes
    nonce: bytes
    key_id: str


class Keyring:
    def __init__(self, primary: bytes, *older: bytes):
        for k in (primary, *older):
            if len(k) != 32:
                raise ValueError("data keys must be exactly 32 bytes")
        self._primary_id = key_id_for(primary)
        self._keys = {key_id_for(k): AESGCM(k) for k in (primary, *older)}
        # derived, purpose-bound sub-key for internal web->worker auth (not used for data)
        self._internal = hmac.new(primary, b"odnas-internal-api-v1", hashlib.sha256).digest()

    @classmethod
    def from_config(cls, cfg) -> "Keyring":
        primary = cfg.read_secret("data.key")
        try:
            old = cfg.read_secret("data.key.old")
            return cls(primary, old)
        except Exception:
            return cls(primary)

    @property
    def primary_id(self) -> str:
        return self._primary_id

    @staticmethod
    def aad(table: str, row_id: str, field: str) -> bytes:
        return f"{table}:{row_id}:{field}".encode()

    def seal(self, plaintext: str, aad: bytes) -> Sealed:
        nonce = os.urandom(12)
        ct = self._keys[self._primary_id].encrypt(nonce, plaintext.encode("utf-8"), aad)
        return Sealed(ct, nonce, self._primary_id)

    def open(self, sealed: Sealed, aad: bytes) -> str:
        k = self._keys.get(sealed.key_id)
        if k is None:
            raise InvalidTag(f"unknown key_id {sealed.key_id}")
        return k.decrypt(sealed.nonce, sealed.ciphertext, aad).decode("utf-8")

    def reseal(self, sealed: Sealed, aad: bytes) -> Sealed:
        return sealed if sealed.key_id == self._primary_id else self.seal(self.open(sealed, aad), aad)

    def internal_token(self) -> str:
        return self._internal.hex()

    def __repr__(self) -> str:
        return f"Keyring(primary={self._primary_id}, keys={len(self._keys)})"
