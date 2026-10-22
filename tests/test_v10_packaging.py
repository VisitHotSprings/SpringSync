"""v0.10: Windows deploy assets (scripts, templates, pins, lock) checked on Linux."""
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WIN = ROOT / "deploy" / "windows"
SCRIPTS = sorted(WIN.glob("*.ps1")) + sorted(WIN.glob("*.psm1")) + sorted(WIN.glob("*.psd1"))


def _checker():
    spec = importlib.util.spec_from_file_location("ps_static_check", WIN / "ps_static_check.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_expected_windows_assets_exist():
    names = {p.name for p in WIN.iterdir()}
    for n in ("install.ps1", "update.ps1", "rollback.ps1", "uninstall.ps1", "set-secret.ps1", "SpringSync.psm1",
              "pins.psd1", "svc.py", "Caddyfile.tmpl", "springsync.toml.tmpl", "build-release.sh",
              "build-caddy-windows.sh", "make-windows-lock.py"):
        assert n in names, n


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: p.name)
def test_powershell_static_check(path):
    assert _checker().check(path) == []


@pytest.mark.parametrize("bad,what", [
    ("<#\n#>\n[CmdletBinding(SupportsShouldProcess)] param()\nInvoke-Expression $x\n", "Invoke-Expression"),
    ("<#\n#>\n[CmdletBinding(SupportsShouldProcess)] param()\npowershell -EncodedCommand AAA\n", "EncodedCommand"),
    ("<#\n#>\n[CmdletBinding(SupportsShouldProcess)] param()\nAdd-MpPreference -ExclusionPath C:\\\n", "Defender"),
    ("<#\n#>\n[CmdletBinding(SupportsShouldProcess)] param()\nInvoke-WebRequest https://x.example\n", "loopback"),
    ("<#\n#>\n[CmdletBinding(SupportsShouldProcess)] param()\nif ($a) { 'x'\n", "unclosed"),
    ("<#\n#>\n[CmdletBinding(SupportsShouldProcess)] param()\n$s = \"$(Get-Date\"\n", "unterminated"),
    ("param()\n", "comment-based help"),
])
def test_static_check_catches(tmp_path, bad, what):
    f = tmp_path / "x.ps1"
    f.write_text(bad)
    assert any(what in p for p in _checker().check(f)), _checker().check(f)


def test_static_check_handles_strings_and_subexpressions(tmp_path):
    f = tmp_path / "ok.ps1"
    f.write_text("<#\n.SYNOPSIS x\n#>\n[CmdletBinding(SupportsShouldProcess)]\nparam()\n"
                 "$a = 'it''s { not code'\n$b = \"x $(if ($a) { 'y' }) `\" }\"\n# comment {\n"
                 "$h = @'\n{ ( [\n'@\n")
    assert _checker().check(f) == []


def test_toml_template_renders_to_a_valid_windows_config(tmp_path):
    t = (WIN / "springsync.toml.tmpl").read_text()
    vals = {"DATA": r"C:\ProgramData\SpringSync", "BASE_URL": "https://sync.hotsprings.org",
            "TENANT_ID": "11111111-2222-3333-4444-555555555555", "CLIENT_ID": "66666666-7777-8888-9999-000000000000",
            "UPN_DOMAIN": "hotsprings.org", "GOOGLE_CLIENT_ID": "", "NAS_HOST": "unas.hotsprings.local",
            "NAS_SHARE": "Personal-Drive", "GROUP_USERS": "", "GROUP_ADMINS": "aaaaaaaa-0000-0000-0000-000000000002",
            "GROUP_AUDITORS": ""}
    for k, v in vals.items():
        t = t.replace(f"@{k}@", v)
    assert not re.search(r"@[A-Z_]+@", t)
    p = tmp_path / "s.toml"
    p.write_text(t)
    from odnas.config import load_config
    c = load_config(str(p), env={})
    assert c.is_windows and c.cert_path == r"C:\ProgramData\SpringSync\keys\entra-app.crt"
    assert c.cookie_secure and c.base_url.startswith("https://")
    assert c.group_admins == "aaaaaaaa-0000-0000-0000-000000000002"


def test_caddyfile_template_is_https_only_and_same_dns01_as_linux():
    win = (WIN / "Caddyfile.tmpl").read_text()
    lin = (ROOT / "deploy" / "caddy" / "Caddyfile.tmpl").read_text()
    assert set(re.findall(r"@([A-Z_]+)@", win)) == {"DATA", "SYNC_HOST", "ACME_EMAIL"}
    for line in ("dns googleclouddns", "gcp_project {$GCP_ACME_PROJECT}", "dns_challenge_override_domain sync.{$ACME_ZONE}",
                 "reverse_proxy 127.0.0.1:8080", 'header Strict-Transport-Security "max-age=31536000"'):
        assert line in win and line in lin
    assert "http://" not in win.replace("acme-staging-v02", "")


def test_pins_match_linux_install_and_spec():
    psd = (WIN / "pins.psd1").read_text()
    sh = (ROOT / "deploy" / "install.sh").read_text()
    for var in ("CADDY_VERSION", "CADDY_DNS_VERSION", "CADDY_DNS_H1", "GO_VERSION", "XCADDY_VERSION"):
        val = re.search(rf'^{var}="([^"]+)"', sh, re.M).group(1)
        assert f"'{val}'" in psd, var
    assert "'v1.75.2'" in psd and "8a9db2bad1dc79a65b3348fd857069598e2aab7cf4d118b77b1df23055aff818" in psd
    from odnas.doctor import RCLONE_VERSION
    assert RCLONE_VERSION == "v1.75.2"
    for h in re.findall(r"Sha256\s*=\s*'([^']*)'", psd):
        assert re.fullmatch(r"[0-9a-f]{64}", h)


def _lock(p):
    out = {}
    for m in re.finditer(r"^([a-z0-9-]+)==(\S+)", p.read_text(), re.M):
        out[m.group(1)] = m.group(2)
    return out


def test_windows_lock_is_the_linux_lock_plus_windows_extras():
    lin, win = _lock(ROOT / "requirements.lock"), _lock(ROOT / "requirements-windows.lock")
    for k, v in lin.items():
        assert win.get(k) == v, k
    assert set(win) - set(lin) == {"pywin32", "tzdata", "colorama"}
    text = (ROOT / "requirements-windows.lock").read_text()
    assert text.count("--hash=sha256:") == len(win)


@pytest.mark.skipif(__import__("shutil").which("bash") is None, reason="no bash")
def test_build_scripts_are_valid_bash():
    for f in ("build-release.sh", "build-caddy-windows.sh"):
        subprocess.run(["bash", "-n", str(WIN / f)], check=True)


def test_svc_bootstrap_compiles():
    import py_compile
    py_compile.compile(str(WIN / "svc.py"), doraise=True)
