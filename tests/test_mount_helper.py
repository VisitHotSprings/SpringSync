"""The root-owned mount helper: argument validation, fixed mount options, file checks."""
import importlib.machinery
import importlib.util
import os
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def helper(tmp_path, monkeypatch):
    src = (ROOT / "deploy" / "mount-helper").read_text().replace("@SLUG@", "springsync")
    p = tmp_path / "mount_helper.py"
    p.write_text(src)
    spec = importlib.util.spec_from_file_location("mount_helper", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.RUN = str(tmp_path / "creds")
    os.makedirs(m.RUN)
    return m


UUID = "0b6c3a52-6d43-4c55-9d2b-6a1c9e1f0a11"


@pytest.mark.parametrize("argv", [["h"], ["h", "mount"], ["h", "mount", "../../etc"], ["h", "rm", UUID],
                                  ["h", "mount", UUID, "extra"], ["h", "mount", UUID.upper()],
                                  ["h", "mount", "-o", "rw"]])
def test_rejects_bad_arguments(helper, monkeypatch, argv):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit) as e:
        helper.main(argv)
    assert e.value.code == helper.USAGE


def test_requires_root(helper, monkeypatch):
    monkeypatch.setattr(helper.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as e:
        helper.main(["h", "mount", UUID])
    assert e.value.code == helper.USAGE


def test_fixed_mount_options(helper):
    svc = types.SimpleNamespace(pw_uid=990, pw_gid=990)
    o = helper.mount_options(svc, "/run/springsync/creds/x", read_only=False).split(",")
    for need in ("vers=3.1.1", "seal", "uid=990", "gid=990", "file_mode=0600", "dir_mode=0700", "nosuid", "nodev",
                 "noexec", "credentials=/run/springsync/creds/x", "rw"):
        assert need in o
    assert "ro" in helper.mount_options(svc, "c", read_only=True).split(",")


@pytest.mark.parametrize("err,code", [("mount error(13): Permission denied", 13),
                                      ("STATUS_LOGON_FAILURE", 13),
                                      ("mount error(112): Host is down", 4),
                                      ("mount error(2): No such file or directory", 3)])
def test_classify_mount_errors(helper, err, code):
    assert helper.classify(32, err) == code


def test_read_owned_rejects_symlink_and_bad_mode(helper, tmp_path):
    uid = os.getuid()
    good = Path(helper.RUN) / "good"
    good.write_text("username=a\npassword=b\n")
    os.chmod(good, 0o600)
    assert "username=a" in helper.read_owned(str(good), uid)
    os.chmod(good, 0o644)
    with pytest.raises(SystemExit):
        helper.read_owned(str(good), uid)
    os.chmod(good, 0o600)
    link = Path(helper.RUN) / "link"
    link.symlink_to(good)
    with pytest.raises(SystemExit):
        helper.read_owned(str(link), uid)
    with pytest.raises(SystemExit):
        helper.read_owned(str(good), uid + 1)  # wrong owner


def test_unc_validation(helper):
    assert helper.UNC_RE.match("//unas.hotsprings.local/Personal-Drive")
    assert helper.UNC_RE.match("//unas/Home-jsmith")
    for bad in ("//unas/share,uid=0", "//unas/share/../x", "//unas/", "\\\\unas\\share", "//un as/x", "//unas/x\n"):
        assert not helper.UNC_RE.match(bad), bad
