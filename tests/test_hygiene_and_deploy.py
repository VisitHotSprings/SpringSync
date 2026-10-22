"""Security hygiene (no secrets in repo/logs) and deploy-asset sanity checks."""
import logging
import re
import subprocess
from pathlib import Path

import pytest

from tests.conftest import CANARY_PW, CANARY_RT, FakeProc, seed_user

ROOT = Path(__file__).resolve().parent.parent
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9_\-]{43}=(?![=A-Za-z0-9])"),            # Fernet-style key
    re.compile(r"\b[0-9a-zA-Z~_.\-]{3}8Q~[0-9a-zA-Z~_.\-]{31,34}\b"),  # Entra client-secret shape
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\"private_key\":\s*\"-----BEGIN"),
]


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    files = out or [str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and ".venv" not in p.parts]
    return [ROOT / f for f in files if (ROOT / f).is_file()]


def test_no_secrets_in_repo():
    hits = []
    for f in tracked_files():
        if f.suffix in (".lock",) or f.name == "test_hygiene_and_deploy.py":
            continue
        text = f.read_text(errors="ignore")
        for p in SECRET_PATTERNS:
            if p.search(text):
                hits.append(f"{f.relative_to(ROOT)}: {p.pattern}")
    assert hits == []


def test_gitignore_blocks_secret_files():
    gi = (ROOT / ".gitignore").read_text()
    for pat in ("*.key", "*.cred", "*.pem", "id_ed25519*", "gcp-acme-sa.json", ".env", "*.db"):
        assert pat in gi


def test_no_canary_secrets_in_logs(cfg, db, kr, entra, caplog):
    from tests.test_runner_broker import make_worker
    caplog.set_level(logging.DEBUG)
    w, _ = make_worker(cfg, db, kr, entra, FakeProc(exit_codes=[1]))
    uid = seed_user(db, kr)
    for _ in range(3):
        w.runner.run(uid, "bisync")
    from odnas.maint import run_maint
    from odnas.notify import Alerter
    run_maint(cfg, db, Alerter(db), probe_tls=False)
    blob = caplog.text + "".join(p.read_text(errors="ignore") for p in Path(cfg.p_log).rglob("*") if p.is_file())
    blob += "".join(r["details_json"] for r in db.audit_rows())
    assert CANARY_RT not in blob and CANARY_PW not in blob


UNITS = sorted((ROOT / "deploy/systemd").glob("*.service"))


@pytest.mark.parametrize("unit", [u for u in UNITS if u.name in ("springsync-web.service", "springsync-worker.service")],
                         ids=lambda p: p.name)
def test_long_running_units_restart(unit):
    t = unit.read_text()
    for need in ("Restart=on-failure", "RestartSec=5s", "StartLimitIntervalSec=300", "StartLimitBurst=5",
                 "OnFailure=@SLUG@-alert@%n.service", "WantedBy=multi-user.target", "User=@SLUG@",
                 "LoadCredentialEncrypted=data.key:", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes"):
        assert need in t, (unit.name, need)


def test_web_unit_hardening():
    t = (ROOT / "deploy/systemd/springsync-web.service").read_text()
    assert "NoNewPrivileges=yes" in t and re.search(r"^CapabilityBoundingSet=$", t, re.M)
    assert "--bind 127.0.0.1:8080" in t


def test_worker_unit():
    t = (ROOT / "deploy/systemd/springsync-worker.service").read_text()
    for need in ("RuntimeDirectory=@SLUG@", "RuntimeDirectoryMode=0700", "KillMode=mixed", "TimeoutStopSec=120",
                 "UMask=0027"):
        assert need in t


def test_timers():
    assert "02:30:00 America/Chicago" in (ROOT / "deploy/systemd/springsync-backup.timer").read_text()
    assert "03:30:00 America/Chicago" in (ROOT / "deploy/systemd/springsync-maint.timer").read_text()


def test_caddyfile_template():
    t = (ROOT / "deploy/caddy/Caddyfile.tmpl").read_text()
    for need in ("dns googleclouddns", "gcp_project {$GCP_ACME_PROJECT}", "gcp_application_default /etc/caddy/gcp-acme-sa.json",
                 "dns_challenge_override_domain sync.{$ACME_ZONE}", "resolvers 8.8.8.8 1.1.1.1",
                 'Strict-Transport-Security "max-age=31536000"', "reverse_proxy 127.0.0.1:8080"):
        assert need in t


def test_sudoers_single_command():
    lines = [l for l in (ROOT / "deploy/sudoers/springsync").read_text().splitlines() if l and not l.startswith("#")]
    rules = [l for l in lines if "NOPASSWD" in l]
    assert rules == ["@SLUG@ ALL=(root) NOPASSWD: /usr/local/lib/@SLUG@/mount-helper"]


def test_install_script_pins_and_syntax():
    t = (ROOT / "deploy/install.sh").read_text()
    assert 'RCLONE_VERSION="1.75.2"' in t
    assert "349ac8fba6ff65d6247043f1750cdcb518ec5d500ef91463a10d37c0ccdf3702" in t
    assert 'CADDY_VERSION="v2.11.7"' in t and 'XCADDY_VERSION="v0.4.7"' in t and 'GO_VERSION="1.27.3"' in t
    # SPEC v0.2: pin the tag; record the commit; verify the built module version + go.sum hash
    assert 'CADDY_DNS_MODULE="github.com/caddy-dns/googleclouddns"' in t and 'CADDY_DNS_VERSION="v1.1.0"' in t
    assert "6fcdbd98a8565df50ff40ff53411dc6c8d97dcd9" in t
    assert 'CADDY_DNS_H1="h1:SDxKxFh7d5Jq2/JPnu9Jv8ErOIdfXmK+Oad0qVzQi80="' in t
    assert 'plugin_pinned "$T/caddy" ||' in t and "GOSUMDB=sum.golang.org" in t
    assert 'GO_SHA256="65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40"' in t
    assert "REPLACE_WITH" not in t and "GO_SHA256 is not pinned" not in t   # v0.1 refusal removed
    assert 'sha256sum -c -' in t and "Go checksum mismatch: ABORT" in t
    assert '"$OS_VERSION_ID" == "24.04"' in t and "--require-hashes" in t and "visudo -cf" in t
    for s in ("install.sh", "update.sh", "rollback.sh"):
        assert subprocess.run(["bash", "-n", str(ROOT / "deploy" / s)]).returncode == 0


def test_update_refuses_branches():
    p = subprocess.run(["bash", str(ROOT / "deploy/update.sh"), "main"], capture_output=True, text=True)
    assert p.returncode == 2 and "refused" in p.stderr


def test_requirements_lock_is_hashed():
    t = (ROOT / "requirements.lock").read_text()
    pkgs = [l for l in t.splitlines() if re.match(r"^[a-z0-9]", l)]
    assert pkgs and all("==" in l for l in pkgs)
    assert t.count("--hash=sha256:") >= len(pkgs)


def test_install_plugin_pin_check_logic(tmp_path):
    """Run install.sh's plugin_pinned() against fake `caddy build-info` output (tab-separated Go build info)."""
    t = (ROOT / "deploy/install.sh").read_text()
    fn = t[t.index("plugin_pinned() {"):t.index("caddy_ok()")]
    head = "\n".join(l for l in t.splitlines() if l.startswith(("CADDY_DNS_MODULE=", "CADDY_DNS_VERSION=", "CADDY_DNS_H1=")))
    for ver, h1, ok in (("v1.1.0", "h1:SDxKxFh7d5Jq2/JPnu9Jv8ErOIdfXmK+Oad0qVzQi80=", 0), ("v1.0.4", "h1:SDxKxFh7d5Jq2/JPnu9Jv8ErOIdfXmK+Oad0qVzQi80=", 1),
                        ("v1.1.0", "h1:AAAA=", 1)):
        fake = tmp_path / "caddy"
        fake.write_text("#!/bin/bash\nprintf 'go\\tgo1.27.3\\npath\\tcaddy\\n"
                        f"dep\\tgithub.com/caddy-dns/googleclouddns\\t{ver}\\t{h1}\\n'\n")
        fake.chmod(0o755)
        r = subprocess.run(["bash", "-c", head + "\n" + fn + f'\nplugin_pinned "{fake}"'])
        assert r.returncode == ok, (ver, h1)


def test_install_sh_does_not_source_os_release_into_its_own_scope():
    """v0.10.3: `. /etc/os-release` at top level overwrote --version with the OS VERSION string."""
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "deploy" / "install.sh").read_text()
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not re.match(r"^(\.|source)\s+/etc/os-release", stripped), line
