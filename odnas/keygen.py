r"""First-install key material for the Windows host (Linux uses openssl in deploy/install.sh; same result).

    data.key        32 random bytes (AES-GCM data key, SPEC §7.3)
    entra-app.key   RSA-2048 private key, PKCS#8 PEM, no passphrase (it is DPAPI-protected right after)
    entra-app.crt   self-signed X.509, CN=<slug>-entra-app, 730 days: the PUBLIC part Mark uploads to Entra

The installer (Administrator) runs `odnas keygen`; the private files go to keys\incoming (ACL'd) and are
DPAPI-protected by the services' first start (odnas/dpapi.py). An escrow copy of data.key and entra-app.key
goes to <data>\escrow\ for Mark to move into the IT password manager / safe and then delete; doctor warns
until he does. Existing keys are never replaced.
"""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from odnas import dpapi, hostos


def _have(cfg, name: str) -> bool:
    return dpapi.dpapi_path(cfg, name).is_file() or (dpapi.incoming_dir(cfg) / name).is_file()


def _write_new(p: Path, data: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def make_entra_cert(slug: str, now: dt.datetime | None = None) -> tuple[bytes, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = now or dt.datetime.now(dt.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{slug}-entra-app")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=730))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    pem_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return pem_key, cert.public_bytes(serialization.Encoding.PEM)


def keygen(cfg, escrow: bool = True) -> list[str]:
    """Returns human-readable lines of what was created (never values)."""
    inc = dpapi.incoming_dir(cfg)
    esc = Path(hostos.join(cfg, cfg.p_etc, "escrow"))
    out = []
    if not _have(cfg, "data.key"):
        k = os.urandom(32)
        _write_new(inc / "data.key", k)
        if escrow:
            _write_new(esc / "data.key", k)
        out.append("NEW data.key created; escrow copy in " + str(esc))
    else:
        out.append("data.key exists (kept)")
    crt = Path(hostos.join(cfg, cfg.p_keys, "entra-app.crt"))
    if not _have(cfg, "entra-app.key"):
        pem_key, pem_crt = make_entra_cert(cfg.slug)
        _write_new(inc / "entra-app.key", pem_key)
        if escrow:
            _write_new(esc / "entra-app.key", pem_key)
        crt.parent.mkdir(parents=True, exist_ok=True)
        crt.write_bytes(pem_crt)
        out.append(f"NEW Entra certificate: upload {crt} to the app registration (Certificates & secrets)")
    else:
        out.append("entra-app.key exists (kept)")
    return out
