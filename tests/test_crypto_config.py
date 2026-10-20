import pytest

from odnas.config import ConfigError, load_config
from odnas.crypto import InvalidTag, Keyring, new_data_key
from odnas.rekey import rekey_all
from tests.conftest import CANARY_PW, CANARY_RT, CLIENT, TENANT, seed_user

pytestmark = pytest.mark.smoke


def test_roundtrip_and_aad_binding():
    kr = Keyring(new_data_key())
    aad = Keyring.aad("ms_credentials", "u1", "refresh_token")
    s = kr.seal("secret-value", aad)
    assert s.ciphertext != b"secret-value" and len(s.nonce) == 12
    assert kr.open(s, aad) == "secret-value"
    with pytest.raises(InvalidTag):
        kr.open(s, Keyring.aad("ms_credentials", "u2", "refresh_token"))  # can't move ciphertext to another row


def test_nonce_unique_per_value():
    kr = Keyring(new_data_key())
    aad = b"x"
    assert len({kr.seal("same", aad).nonce for _ in range(50)}) == 50


def test_key_rotation_with_key_id(db, kr, cfg):
    uid = seed_user(db, kr)
    db.q("INSERT INTO settings(key, value_json, is_secret) VALUES ('x', '1', 0)")
    old_id = db.ms_credential(uid)["key_id"]
    new = Keyring(new_data_key(), cfg.read_secret("data.key"))  # new primary, old still loadable
    assert new.primary_id != old_id
    assert db.refresh_token(new, uid) == CANARY_RT
    n = rekey_all(db, new)
    assert n["ms_credentials"] == 1 and n["nas_credentials"] == 1
    assert db.ms_credential(uid)["key_id"] == new.primary_id
    only_new = Keyring(new_data_key())  # unrelated key
    with pytest.raises(Exception):
        db.refresh_token(only_new, uid)
    assert db.nas_credential(new, uid) == ("jsmith", CANARY_PW)


def test_data_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        Keyring(b"short")


def test_config_validation():
    base = {"ODNAS_TENANT_ID": TENANT, "ODNAS_CLIENT_ID": CLIENT}
    assert load_config(env=base).slug == "springsync"
    for bad in ({"ODNAS_TENANT_ID": "common"}, {"ODNAS_WEB_HOST": "0.0.0.0"}, {"ODNAS_SLUG": "Bad Slug"},
                {"ODNAS_TOKEN_MODE": "tmpfs_config"}):  # needs credential_type=secret
        with pytest.raises(ConfigError):
            load_config(env={**base, **bad})
    c = load_config(env={**base, "ODNAS_TOKEN_MODE": "tmpfs_config", "ODNAS_CREDENTIAL_TYPE": "secret",
                         "ODNAS_SLUG": "homesync", "ODNAS_PRODUCT_NAME": "HomeSync"})
    assert c.check_filename == ".homesync-check" and c.p_db == "/var/lib/homesync/db/homesync.db"
    assert c.user_agent == "NONISV|VisitHotSprings|HomeSync/0.3"


def test_config_toml(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(f'[app]\nproduct_name = "SpringSync"\n[entra]\ntenant_id = "{TENANT}"\nclient_id = "{CLIENT}"\n'
                 '[nas]\nnas_host = "unas.lan"\n')
    c = load_config(str(p), env={})
    assert c.nas_host == "unas.lan" and c.tenant_id == TENANT
    p.write_text('[app]\nno_such_key = 1\n')
    with pytest.raises(ConfigError):
        load_config(str(p), env={})


def test_repr_never_shows_keys():
    kr = Keyring(new_data_key())
    assert "Keyring(primary=" in repr(kr) and len(repr(kr)) < 60
