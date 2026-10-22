"""v0.12.0: Sign in with Microsoft / Sign in with Google (SPEC v0.10.1 §4.5; lab test T-I1 §12.2).

Real RS256 keys and real PyJWT verification (odnas/oidc.py) for the token checks; a fake provider for the web
flows (linking, roles, step-up, kill switch). No network: JWKS fetches and token endpoints are injected."""
import json
import re
import sqlite3
import time
from dataclasses import replace
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from tests.conftest import CLIENT, G_ADMINS, G_AUDIT, G_USERS, TENANT, claims, seed_user
from tests.test_web import FakeWorkerClient
from odnas import db as D
from odnas import oidc, settings_store
from odnas.entra import MsalEntraClient
from odnas.google import ClaimsError, GoogleTokenResult, HttpGoogleClient, check_signin_claims
from odnas.web.app import create_app

GCLIENT = "1234567890-abcdefghij0123.apps.googleusercontent.com"
GISS = "https://accounts.google.com"
MSISS = f"https://login.microsoftonline.com/{TENANT}/v2.0"
FOREIGN = "99999999-8888-7777-6666-555555555555"


# ---- keys / tokens -------------------------------------------------------------------------------

def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


KEY, OTHER_KEY = _key(), _key()


def jwk(key, kid):
    d = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    d.update(kid=kid, use="sig", alg="RS256")
    return d


class Jwks:
    """Injected JWKS fetch: records calls; the key set can change (rotation)."""
    def __init__(self, keys=None):
        self.keys = keys if keys is not None else [jwk(KEY, "k1")]
        self.calls = []

    def __call__(self, uri):
        self.calls.append(uri)
        return {"keys": list(self.keys)}


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


def tok(claims_, key=KEY, kid="k1", alg="RS256", headers=None):
    h = {"kid": kid, **(headers or {})}
    return jwt.encode(claims_, key, algorithm=alg, headers=h)


def gtoken_claims(nonce="n1", **kw):
    now = int(time.time())
    c = {"iss": GISS, "aud": GCLIENT, "sub": "g-sub-1", "email": "jsmith@hotsprings.org", "email_verified": True,
         "hd": "hotsprings.org", "iat": now, "exp": now + 3600, "nonce": nonce, "azp": GCLIENT}
    c.update(kw)
    return {k: v for k, v in c.items() if v is not None}


def mstoken_claims(nonce_raw="raw-nonce", **kw):
    now = int(time.time())
    c = {"iss": MSISS, "aud": CLIENT, "tid": TENANT, "oid": "oid-1", "sub": "ms-sub", "iat": now, "nbf": now,
         "exp": now + 3600, "nonce": oidc.msal_nonce(nonce_raw), "preferred_username": "jsmith@hotsprings.org"}
    c.update(kw)
    return {k: v for k, v in c.items() if v is not None}


def gverify(t, nonce="n1", jwks=None, now=None):
    return oidc.verify(t, oidc.google_expect(GCLIENT, nonce), jwks or oidc.JwksCache(Jwks()), now=now)


def msverify(t, nonce_raw="raw-nonce", jwks=None):
    return oidc.verify(t, oidc.ms_expect(CLIENT, TENANT, oidc.msal_nonce(nonce_raw)), jwks or oidc.JwksCache(Jwks()))


def reason(fn, *a, **kw):
    with pytest.raises(oidc.TokenError) as e:
        fn(*a, **kw)
    return e.value.reason


# ---- §4.5.2 Google token checks --------------------------------------------------------------------

@pytest.mark.smoke
@pytest.mark.parametrize("iss", ["https://accounts.google.com", "accounts.google.com"])
def test_google_valid_token_both_documented_issuers(iss):
    c = gverify(tok(gtoken_claims(iss=iss)))
    assert c["sub"] == "g-sub-1" and c["hd"] == "hotsprings.org"


@pytest.mark.smoke
def test_forged_signature_refused():
    # signed by an attacker key but claiming Google's kid
    assert reason(gverify, tok(gtoken_claims(), key=OTHER_KEY)) == "bad_signature"


def test_tampered_payload_refused():
    good = tok(gtoken_claims())
    h, p, s = good.split(".")
    body = json.loads(jwt.utils.base64url_decode(p))
    body["hd"] = "evil.example.org"
    p2 = jwt.utils.base64url_encode(json.dumps(body).encode()).decode()
    assert reason(gverify, f"{h}.{p2}.{s}") == "bad_signature"


@pytest.mark.parametrize("alg", ["none", "HS256"])
def test_non_rs256_algorithms_refused(alg):
    if alg == "none":
        t = jwt.encode(gtoken_claims(), None, algorithm="none", headers={"kid": "k1"})
    else:
        t = jwt.encode(gtoken_claims(), "a-shared-secret-of-sufficient-length-1234567890", algorithm="HS256",
                       headers={"kid": "k1"})
    assert reason(gverify, t) == "bad_algorithm"


def test_unknown_kid_refused():
    assert reason(gverify, tok(gtoken_claims(), kid="nope")) == "unknown_signing_key"


@pytest.mark.smoke
@pytest.mark.parametrize("aud", ["someone-else.apps.googleusercontent.com", [GCLIENT, "other-client"]])
def test_wrong_audience_refused(aud):
    assert reason(gverify, tok(gtoken_claims(aud=aud))) == "wrong_audience"


@pytest.mark.smoke
@pytest.mark.parametrize("iss", ["https://evil.example.org", "https://accounts.google.com.evil.example.org",
                                 "http://accounts.google.com", MSISS])
def test_wrong_issuer_refused(iss):
    assert reason(gverify, tok(gtoken_claims(iss=iss))) == "wrong_issuer"


@pytest.mark.smoke
def test_expired_token_refused():
    now = int(time.time())
    assert reason(gverify, tok(gtoken_claims(iat=now - 7200, exp=now - 3600))) == "expired"


def test_skew_is_60_seconds():
    now = int(time.time())
    assert oidc.SKEW_S == 60
    gverify(tok(gtoken_claims(iat=now + 30)))                      # within skew: ok
    assert reason(gverify, tok(gtoken_claims(iat=now + 300))) == "not_yet_valid"
    gverify(tok(gtoken_claims(iat=now - 600, exp=now - 30)))       # expired 30 s ago: within skew
    assert reason(gverify, tok(gtoken_claims(iat=now - 900))) == "too_old"   # used > 10 min after iat


@pytest.mark.parametrize("missing", ["exp", "iat", "sub", "aud", "iss"])
def test_required_claims(missing):
    c = gtoken_claims()
    c.pop(missing)
    assert reason(gverify, tok(c)) in ("missing_claim", "wrong_audience", "wrong_issuer")


@pytest.mark.smoke
def test_nonce_mismatch_and_missing_refused():
    assert reason(gverify, tok(gtoken_claims(nonce="n1")), nonce="n2") == "nonce_mismatch"
    assert reason(gverify, tok(gtoken_claims(nonce=None)), nonce="n1") == "nonce_mismatch"
    assert reason(gverify, tok(gtoken_claims(nonce="")), nonce="") == "nonce_mismatch"


def test_jwks_cached_and_refetched_on_new_kid_at_most_every_5_min():
    fetch, clock = Jwks(), Clock()
    cache = oidc.JwksCache(fetch, clock)
    gverify(tok(gtoken_claims()), jwks=cache)
    gverify(tok(gtoken_claims()), jwks=cache)
    assert len(fetch.calls) == 1 and fetch.calls[0] == oidc.GOOGLE_JWKS
    fetch.keys.append(jwk(OTHER_KEY, "k2"))                       # Google rotates in a new key
    assert reason(gverify, tok(gtoken_claims(), key=OTHER_KEY, kid="k2"), jwks=cache) == "unknown_signing_key"
    assert len(fetch.calls) == 1                                  # no refetch storm
    clock.t += oidc.JWKS_MIN_REFETCH_S + 1
    gverify(tok(gtoken_claims(), key=OTHER_KEY, kid="k2"), jwks=cache)
    assert len(fetch.calls) == 2


def test_jwks_must_be_https():
    with pytest.raises(oidc.TokenError) as e:
        oidc._http_fetch("http://www.googleapis.com/oauth2/v3/certs")
    assert e.value.reason == "jwks_not_https"


def _gc(**kw):
    c = {"sub": "g-sub-1", "email": "jsmith@hotsprings.org", "hd": "hotsprings.org", "email_verified": True}
    c.update(kw)
    return {k: v for k, v in c.items() if v is not None}


@pytest.mark.smoke
@pytest.mark.parametrize("c,why", [
    (_gc(hd="evil.example.org"), "domain_not_allowed"),     # wrong hd
    (_gc(hd=None), "not_workspace"),                        # missing hd = consumer account
    (_gc(hd=None, email="someone@gmail.com"), "not_workspace"),   # gmail.com
    (_gc(email_verified=False), "email_not_verified"),
    (_gc(email_verified="true"), "email_not_verified"),     # must be the JSON boolean
    (_gc(email_verified=None), "email_not_verified"),
    (_gc(sub=None), "no_identity"),
])
def test_google_signin_claims_refused(c, why):
    with pytest.raises(ClaimsError) as e:
        check_signin_claims(c, "hotsprings.org")
    assert e.value.reason == why


def test_hd_never_inferred_from_email():
    with pytest.raises(ClaimsError):
        check_signin_claims(_gc(hd=None, email="jsmith@hotsprings.org"), "hotsprings.org")
    assert check_signin_claims(_gc(hd="HotSprings.org"), "hotsprings.org")[1] == "hotsprings.org"


# ---- §4.5.2 Microsoft token checks ------------------------------------------------------------------

@pytest.mark.smoke
def test_ms_valid_token():
    assert msverify(tok(mstoken_claims()))["oid"] == "oid-1"


@pytest.mark.smoke
def test_ms_foreign_tid_refused():
    t = tok(mstoken_claims(tid=FOREIGN, iss=f"https://login.microsoftonline.com/{FOREIGN}/v2.0"))
    assert reason(msverify, t) == "wrong_tenant"


@pytest.mark.smoke
def test_ms_iss_tid_mismatch_refused():
    assert reason(msverify, tok(mstoken_claims(iss=f"https://login.microsoftonline.com/{FOREIGN}/v2.0"))) == "wrong_issuer"
    assert reason(msverify, tok(mstoken_claims(iss="https://login.microsoftonline.com/common/v2.0"))) == "wrong_issuer"


def test_ms_wrong_aud_expired_forged_nonce():
    now = int(time.time())
    assert reason(msverify, tok(mstoken_claims(aud="another-app"))) == "wrong_audience"
    assert reason(msverify, tok(mstoken_claims(iat=now - 7200, nbf=now - 7200, exp=now - 3600))) == "expired"
    assert reason(msverify, tok(mstoken_claims(nbf=now + 600))) == "not_yet_valid"
    assert reason(msverify, tok(mstoken_claims(), key=OTHER_KEY)) == "bad_signature"
    assert reason(msverify, tok(mstoken_claims(nonce_raw="other"))) == "nonce_mismatch"


def test_ms_jwks_uri_is_the_tenant_discovery_keys():
    fetch = Jwks()
    msverify(tok(mstoken_claims()), jwks=oidc.JwksCache(fetch))
    assert fetch.calls == [f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"]


class _FakeMsalApp:
    def __init__(self, result):
        self.result = result
        self.flows = []

    def acquire_token_by_auth_code_flow(self, flow, query):
        return self.result

    def initiate_auth_code_flow(self, scopes, redirect_uri, prompt):
        self.flows.append(prompt)
        return {"state": "s", "nonce": "raw-nonce", "auth_uri": "https://login.example.invalid/a"}


def _msal_client(cfg, result, monkeypatch):
    c = MsalEntraClient(cfg, jwks=oidc.JwksCache(Jwks()))
    app = _FakeMsalApp(result)
    monkeypatch.setattr(c, "_msal", lambda cache=None: app)
    monkeypatch.setattr(c, "_rt_from_cache", staticmethod(lambda cache: ""))
    return c, app


@pytest.mark.smoke
def test_msal_client_verifies_id_token(cfg, monkeypatch):
    good = {"access_token": "at", "refresh_token": "rt", "id_token": tok(mstoken_claims()),
            "id_token_claims": {"oid": "UNTRUSTED"}}
    c, app = _msal_client(cfg, good, monkeypatch)
    r = c.complete_auth({"nonce": "raw-nonce"}, {})
    assert r.ok and r.id_claims["oid"] == "oid-1"          # from OUR verification, not MSAL's decode
    bad = dict(good, id_token=tok(mstoken_claims(), key=OTHER_KEY))
    c, _ = _msal_client(cfg, bad, monkeypatch)
    r = c.complete_auth({"nonce": "raw-nonce"}, {})
    assert (r.ok, r.error, r.error_description) == (False, "invalid_id_token", "bad_signature")
    c, _ = _msal_client(cfg, dict(good, id_token=tok(mstoken_claims(oid=None))), monkeypatch)
    assert c.complete_auth({"nonce": "raw-nonce"}, {}).error_description == "missing_oid"
    c, _ = _msal_client(cfg, {k: v for k, v in good.items() if k != "id_token"}, monkeypatch)
    assert c.complete_auth({"nonce": "raw-nonce"}, {}).error_description == "no_id_token"


def test_msal_prompt_passthrough(cfg, monkeypatch):
    c, app = _msal_client(cfg, {}, monkeypatch)
    c.begin_auth("https://sync.example.org/auth/callback")
    c.begin_auth("https://sync.example.org/auth/callback", prompt="login")
    assert app.flows == ["select_account", "login"]
    with pytest.raises(ValueError):
        c.begin_auth("https://sync.example.org/auth/callback", prompt="none")


# ---- HttpGoogleClient sign-in (MockTransport) --------------------------------------------------------

def _http_google(cfg, id_token_for):
    keys = Path(cfg.keys_dir)
    (keys / "google-client.secret").write_text("placeholder-google-secret-for-tests")
    seen = []

    def handler(req: httpx.Request):
        form = dict(x.split("=", 1) for x in req.content.decode().split("&"))
        seen.append(form)
        return httpx.Response(200, json={"access_token": "g-at", "id_token": id_token_for(form), "expires_in": 3600})
    c = HttpGoogleClient(replace(cfg, google_client_id=GCLIENT), transport=httpx.MockTransport(handler),
                         jwks=oidc.JwksCache(Jwks()))
    return c, seen


def test_http_google_signin_scopes_and_hint_only(cfg):
    c, _ = _http_google(cfg, lambda f: "")
    flow = c.begin_signin("https://sync.example.org/auth/google/signin/callback", "hotsprings.org")
    q = dict(x.split("=", 1) for x in flow["auth_uri"].split("?", 1)[1].split("&"))
    assert q["scope"] == "openid+email+profile" and q["prompt"] == "select_account" and q["hd"] == "hotsprings.org"
    assert "access_type" not in q and q["code_challenge_method"] == "S256" and flow["nonce"]


@pytest.mark.smoke
def test_http_google_signin_verifies_and_nonce_replay_fails(cfg):
    tokens = {}
    c, seen = _http_google(cfg, lambda f: tokens["t"])
    flow = c.begin_signin("https://sync.example.org/auth/google/signin/callback", "hotsprings.org")
    tokens["t"] = tok(gtoken_claims(nonce=flow["nonce"]))
    r = c.complete_signin(flow, {"code": "c1", "state": flow["state"]})
    assert r.ok and r.id_claims["sub"] == "g-sub-1" and r.refresh_token == ""
    assert seen[0]["code_verifier"] == flow["code_verifier"]
    # the same token replayed into a new sign-in (new nonce) fails
    flow2 = c.begin_signin("https://sync.example.org/auth/google/signin/callback", "hotsprings.org")
    r2 = c.complete_signin(flow2, {"code": "c2", "state": flow2["state"]})
    assert (r2.ok, r2.error, r2.error_description) == (False, "invalid_id_token", "nonce_mismatch")
    assert c.complete_signin(flow2, {"code": "c", "state": "other"}).error == "state_mismatch"


def test_http_google_drive_connect_also_verified(cfg):
    c, _ = _http_google(cfg, lambda f: tok(gtoken_claims(nonce="whatever"), key=OTHER_KEY))
    flow = c.begin_auth("https://sync.example.org/auth/google/callback", "hotsprings.org")
    r = c.complete_auth(flow, {"code": "c", "state": flow["state"]})
    assert not r.ok and r.error == "invalid_id_token"


# ---- DB model (§4.5.7) ----------------------------------------------------------------------------------

def test_identities_unique_constraints(db, kr):

    a = seed_user(db, kr, upn="a@hotsprings.org")
    b = seed_user(db, kr, upn="b@hotsprings.org")
    db.link_identity("google", GISS, "sub-a", a, "self", hd="hotsprings.org")
    with pytest.raises(sqlite3.IntegrityError):          # one identity -> one user
        db.link_identity("google", GISS, "sub-a", b, "self", hd="hotsprings.org")
    with pytest.raises(sqlite3.IntegrityError):          # one identity per provider per user
        db.link_identity("google", GISS, "sub-a2", a, "self", hd="hotsprings.org")
    with pytest.raises(sqlite3.IntegrityError):
        db.link_identity("gmail", GISS, "x", b, "self")
    cols = {r["name"] for r in db.all("PRAGMA table_info(identities)")}
    assert {"provider", "issuer", "subject", "user_id", "linked_at", "linked_by", "tid", "hd"} <= cols


def test_backfill_entra_identities_idempotent(cfg, db, kr):

    uid = seed_user(db, kr, oid="oid-x")
    assert db.backfill_entra_identities(TENANT) == 1
    assert db.backfill_entra_identities(TENANT) == 0
    (i,) = db.identities_for_user(uid)
    assert (i["provider"], i["issuer"], i["subject"], i["linked_by"]) == ("entra", MSISS, "oid-x", "migration")


# ---- web flows ------------------------------------------------------------------------------------------

class FakeGoogleSignin:
    """Sign-in half of a Google client: the test sets `claims` (already 'verified')."""
    def __init__(self):
        self.claims = {}
        self.begun = []
        self.fail = None

    def begin_signin(self, redirect_uri, hd=""):
        import os
        self.begun.append((redirect_uri, hd))
        return {"state": "gs-" + os.urandom(4).hex(), "nonce": "n", "auth_uri": "https://accounts.example.invalid/s",
                "redirect_uri": redirect_uri}

    def complete_signin(self, flow, query):
        if self.fail:
            return GoogleTokenResult(error="invalid_id_token", error_description=self.fail)
        return GoogleTokenResult(access_token="signin", id_claims=dict(self.claims))

    def begin_auth(self, *a, **k):
        raise AssertionError("Drive connect not used here")


def gc(sub="g-sub-1", email="jsmith@hotsprings.org", hd="hotsprings.org", verified=True, **kw):
    return {"sub": sub, "email": email, "hd": hd, "email_verified": verified, "iss": GISS, **kw}


@pytest.fixture
def g():
    return FakeGoogleSignin()


@pytest.fixture
def scfg(cfg):
    return replace(cfg, google_client_id=GCLIENT, signin_google=True)


@pytest.fixture
def sapp(scfg, db, kr, entra, g):
    settings_store.update(db, scfg, kr, {"pilot_list": "jsmith@hotsprings.org\nit-admin@hotsprings.org"}, "test")
    return create_app(scfg, db, kr, entra, FakeWorkerClient(), google=g)


def ms(c, entra, **kw):
    extra = kw.pop("extra", {})
    entra.claims = {**claims(**kw), **extra}
    r = c.get("/login")
    assert r.status_code == 303, r.text
    r = c.get(f"/auth/callback?code=abc&state={c.cookies.get('springsync_flow')}")
    assert r.status_code == 303, r.text
    return c


def google_login(c, g, claims_=None):
    g.claims = claims_ or gc()
    r = c.get("/login/google")
    assert r.status_code == 303, r.text
    return c.get(f"/auth/google/signin/callback?code=x&state={c.cookies.get('springsync_flow')}")


def csrf(c, path):
    m = re.search(r'name="csrf" value="([^"]+)"', c.get(path).text)
    return m.group(1)


def link_google(c, g, claims_=None):
    r = c.post("/me/signin-methods/link/google", data={"csrf": csrf(c, "/me/signin-methods")})
    assert r.status_code == 303 and r.headers["location"].startswith("https://accounts.example.invalid"), r.text
    g.claims = claims_ or gc()
    return c.get(f"/auth/google/signin/callback?code=x&state={c.cookies.get('springsync_flow')}")


def client(app):
    return TestClient(app, follow_redirects=False)


def actions(db):
    return [r["action"] for r in db.all("SELECT action FROM audit_log ORDER BY seq")]


@pytest.mark.smoke
def test_login_page_shows_both_buttons(sapp, scfg, db, kr, entra):
    t = client(sapp).get("/").text
    assert "Sign in with Microsoft" in t and 'href="/login/google"' in t
    off = create_app(replace(scfg, signin_google=False), db, kr, entra, FakeWorkerClient(), google=FakeGoogleSignin())
    t = client(off).get("/").text
    assert "Sign in with Microsoft" in t and "/login/google" not in t
    assert client(off).get("/login/google").status_code == 404


def test_google_signin_uses_its_own_redirect_and_hd_hint(sapp, g):
    c = client(sapp)
    c.get("/login/google")
    assert g.begun[0][0].endswith("/auth/google/signin/callback") and g.begun[0][1] == "hotsprings.org"


@pytest.mark.smoke
def test_unlinked_google_identity_denied_and_audited(sapp, g, db):
    r = google_login(client(sapp), g)
    assert r.status_code == 403
    assert "linked to SpringSync yet" in r.text
    assert db.users() == []
    row = db.one("SELECT * FROM audit_log WHERE action='signin_refused'")
    d = json.loads(row["details_json"]) if "details_json" in row.keys() else json.loads(row["detail_json"])
    assert d["reason"] == "not_linked" and d["provider"] == "google" and "g-sub-1" not in json.dumps(d)


def test_email_match_only_suggests_never_links(sapp, g, entra, db):
    ms(client(sapp), entra)                                    # jsmith exists with an entra identity
    r = google_login(client(sapp), g)                          # same verified email, not linked
    assert r.status_code == 403 and "sign in with Microsoft, then use Link Google" in r.text
    assert not [i for i in db.identities_for_user(db.users()[0]["id"]) if i["provider"] == "google"]
    r = google_login(client(sapp), g, gc(verified=False))     # unverified: refused before any suggestion
    assert r.status_code == 403 and "Link Google" not in r.text


@pytest.mark.smoke
@pytest.mark.parametrize("bad,why", [
    (gc(hd="evil.example.org"), "domain_not_allowed"), (gc(hd=None), "not_workspace"),
    (gc(hd=None, email="x@gmail.com"), "not_workspace"), (gc(verified=False), "email_not_verified"),
])
def test_google_claim_refusals_in_web(sapp, g, db, bad, why):
    bad = {k: v for k, v in bad.items() if v is not None}
    assert google_login(client(sapp), g, bad).status_code == 403
    assert why in json.dumps([dict(r) for r in db.all("SELECT * FROM audit_log WHERE action='signin_refused'")])


def test_invalid_token_refused_and_audited(sapp, g, db):
    g.fail = "bad_signature"
    assert google_login(client(sapp), g).status_code == 403
    assert "bad_signature" in json.dumps([dict(r) for r in db.all("SELECT * FROM audit_log WHERE action='signin_refused'")])


@pytest.mark.smoke
def test_callback_replay_refused(sapp, g, entra):
    c = ms(client(sapp), entra)
    r = c.post("/me/signin-methods/link/google", data={"csrf": csrf(c, "/me/signin-methods")})
    state = c.cookies.get("springsync_flow")
    g.claims = gc()
    assert c.get(f"/auth/google/signin/callback?code=x&state={state}").status_code == 303
    r = c.get(f"/auth/google/signin/callback?code=x&state={state}")   # the state row (and nonce) is gone
    assert r.status_code == 400


@pytest.mark.smoke
def test_link_google_then_sign_in_with_google(sapp, g, entra, db):
    c = ms(client(sapp), entra)
    uid = db.users()[0]["id"]
    r = link_google(c, g)
    assert r.headers["location"] == "/me/signin-methods?msg=linked"
    provs = sorted(i["provider"] for i in db.identities_for_user(uid))
    assert provs == ["entra", "google"]
    gi = [i for i in db.identities_for_user(uid) if i["provider"] == "google"][0]
    assert (gi["issuer"], gi["subject"], gi["hd"], gi["linked_by"]) == (GISS, "g-sub-1", "hotsprings.org", "self")
    assert "identity_linked" in actions(db)
    g2 = client(sapp)
    r = google_login(g2, g)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert g2.get("/me").status_code == 200                   # User role from the stored roles
    assert "My sign-in methods" in g2.get("/me").text
    logins = [json.loads(dict(x).get("details_json") or dict(x).get("detail_json") or "{}")
              for x in db.all("SELECT * FROM audit_log WHERE action='login'")]
    assert any(d.get("provider") == "google" for d in logins)


def test_link_cross_flow_and_session_binding(sapp, g, entra, db):
    c = ms(client(sapp), entra)
    c.post("/me/signin-methods/link/google", data={"csrf": csrf(c, "/me/signin-methods")})
    state = c.cookies.get("springsync_flow")
    other = ms(client(sapp), entra, oid="oid-m", upn="it-admin@hotsprings.org")
    other.cookies.set("springsync_flow", state, path="/auth")
    g.claims = gc()
    r = other.get(f"/auth/google/signin/callback?code=x&state={state}")   # finished in another session
    assert r.status_code == 403
    assert not [i for i in db.all("SELECT * FROM identities WHERE provider='google'")]


def test_link_request_expires_after_10_minutes(sapp, g, entra, db):
    c = ms(client(sapp), entra)
    c.post("/me/signin-methods/link/google", data={"csrf": csrf(c, "/me/signin-methods")})
    db.q("UPDATE auth_flows SET created_at=?", (D.iso(D.utcnow() - __import__("datetime").timedelta(minutes=11)),))
    g.claims = gc()
    r = c.get(f"/auth/google/signin/callback?code=x&state={c.cookies.get('springsync_flow')}")
    assert r.status_code == 400 and "expired" in r.text


def test_link_refuses_stale_auth_time(sapp, g, entra, db):
    c = ms(client(sapp), entra)
    r = link_google(c, g, gc(auth_time=int(time.time()) - 3600))
    assert r.status_code == 403 and "identity_link_refused" in actions(db)


def test_identity_linked_to_another_user_refused(sapp, g, entra, db):
    a = ms(client(sapp), entra)
    link_google(a, g)
    b = ms(client(sapp), entra, oid="oid-m", upn="it-admin@hotsprings.org")
    r = link_google(b, g)
    assert r.status_code == 409
    assert len(db.all("SELECT * FROM identities WHERE provider='google'")) == 1


def test_link_microsoft_from_google_session_uses_prompt_login_and_iat(sapp, g, entra, db, kr):

    # a user whose Entra identity was unlinked earlier, who still has Google
    c = ms(client(sapp), entra)
    uid = db.users()[0]["id"]
    link_google(c, g)
    ent = [i for i in db.identities_for_user(uid) if i["provider"] == "entra"][0]
    db.unlink_identity(ent["id"])
    gs = client(sapp)
    assert google_login(gs, g).status_code == 303
    r = gs.post("/me/signin-methods/link/microsoft", data={"csrf": csrf(gs, "/me/signin-methods")})
    assert r.status_code == 303 and entra.prompts[-1] == "login"
    entra.claims = {**claims(), "iat": int(time.time()) - 3600}          # stale
    r = gs.get(f"/auth/callback?code=a&state={gs.cookies.get('springsync_flow')}")
    assert r.status_code == 403
    gs.post("/me/signin-methods/link/microsoft", data={"csrf": csrf(gs, "/me/signin-methods")})
    entra.claims = {**claims(), "iat": int(time.time())}
    r = gs.get(f"/auth/callback?code=a&state={gs.cookies.get('springsync_flow')}")
    assert r.headers["location"] == "/me/signin-methods?msg=linked"
    assert {i["provider"] for i in db.identities_for_user(uid)} == {"entra", "google"}
    assert db.user(uid)["entra_oid"] == "oid-1"


def test_self_unlink_needs_another_method(sapp, g, entra, db):
    c = ms(client(sapp), entra)
    uid = db.users()[0]["id"]
    (only,) = db.identities_for_user(uid)
    assert c.post(f"/me/signin-methods/{only['id']}/unlink", data={"csrf": csrf(c, "/me/signin-methods")}).status_code == 409
    link_google(c, g)
    gi = [i for i in db.identities_for_user(uid) if i["provider"] == "google"][0]
    gs = client(sapp)
    google_login(gs, g)
    r = c.post(f"/me/signin-methods/{gi['id']}/unlink", data={"csrf": csrf(c, "/me/signin-methods")})
    assert r.status_code == 303
    assert [i["provider"] for i in db.identities_for_user(uid)] == ["entra"]
    assert gs.get("/me").status_code == 303                   # that Google session ended (401 -> back to /)
    assert "identity_unlinked" in actions(db)
    assert google_login(client(sapp), g).status_code == 403   # unlinked again: default deny


def test_cannot_unlink_someone_elses_identity(sapp, g, entra, db):
    a = ms(client(sapp), entra)
    link_google(a, g)
    b = ms(client(sapp), entra, oid="oid-m", upn="it-admin@hotsprings.org")
    link_google(b, g, gc(sub="g-sub-m", email="it-admin@hotsprings.org"))
    ga = [i for i in db.all("SELECT * FROM identities WHERE subject='g-sub-1'")][0]
    assert b.post(f"/me/signin-methods/{ga['id']}/unlink", data={"csrf": csrf(b, "/me/signin-methods")}).status_code == 404


# ---- §4.5.6 roles on Google sessions ---------------------------------------------------------------------

def _admin_with_google(sapp, g, entra, db):
    c = ms(client(sapp), entra, oid="oid-m", upn="it-admin@hotsprings.org", groups=(G_USERS, G_ADMINS))
    uid = db.user_by_oid("oid-m")["id"]
    link_google(c, g, gc(sub="g-sub-m", email="it-admin@hotsprings.org"))
    return c, uid


@pytest.mark.smoke
def test_roles_stored_and_refreshed_at_ms_signin(sapp, g, entra, db):
    c, uid = _admin_with_google(sapp, g, entra, db)
    assert db.user_roles(uid) == {"user", "admin"} and db.user(uid)["roles_synced_at"]
    ms(client(sapp), entra, oid="oid-m", upn="it-admin@hotsprings.org", groups=(G_USERS,))   # admin removed in Entra
    assert db.user_roles(uid) == {"user"} and "roles_changed" in actions(db)


@pytest.mark.smoke
def test_google_admin_within_24h_then_user_only_with_banner(sapp, g, entra, db):
    _, uid = _admin_with_google(sapp, g, entra, db)
    gs = client(sapp)
    google_login(gs, g, gc(sub="g-sub-m", email="it-admin@hotsprings.org"))
    assert gs.get("/admin").status_code == 200
    db.q("UPDATE users SET roles_synced_at=? WHERE id=?",
         (D.iso(D.utcnow() - __import__("datetime").timedelta(hours=25)), uid))
    r = gs.get("/admin")
    assert r.status_code == 403 and "Sign in with Microsoft" in r.text and "/login?stepup=1" in r.text
    me = gs.get("/me")
    assert me.status_code == 200 and "Sign in with Microsoft to use admin tools" in me.text


def test_google_session_no_access_after_n_days_without_ms(sapp, g, entra, db, scfg, kr):
    _, uid = _admin_with_google(sapp, g, entra, db)
    settings_store.update(db, scfg, kr, {"google_signin_ms_max_age_days": "3"}, "test")
    db.q("UPDATE users SET roles_synced_at=? WHERE id=?",
         (D.iso(D.utcnow() - __import__("datetime").timedelta(days=4)), uid))
    gs = client(sapp)
    google_login(gs, g, gc(sub="g-sub-m", email="it-admin@hotsprings.org"))
    assert gs.get("/me").status_code == 403
    assert "too long since you last signed in with Microsoft" in gs.get("/").text


def test_google_session_never_admin_without_stored_role(sapp, g, entra, db):
    c = ms(client(sapp), entra)
    link_google(c, g)
    gs = client(sapp)
    google_login(gs, g)
    assert gs.get("/admin").status_code == 403 and gs.get("/audit").status_code == 403


@pytest.mark.smoke
def test_destructive_admin_actions_need_microsoft_session(sapp, g, entra, db, kr):

    target = seed_user(db, kr, upn="other@hotsprings.org", oid="oid-o")
    _, uid = _admin_with_google(sapp, g, entra, db)
    gs = client(sapp)
    google_login(gs, g, gc(sub="g-sub-m", email="it-admin@hotsprings.org"))
    tok_ = csrf(gs, "/admin/settings")
    for path, data in [(f"/admin/users/{target}/offboard", {"confirm": "other@hotsprings.org"}),
                       (f"/admin/users/{target}/set-direction", {"direction": "pull_copy"}),
                       (f"/admin/users/{target}/approve-mirror-baseline", {}),
                       (f"/admin/users/{target}/set-provider", {}),
                       (f"/admin/users/{target}/safety-accept-deletes", {}),
                       ("/admin/settings", {"pilot_list": "x@hotsprings.org"}),
                       ("/admin/service-mode", {"scope": "all", "op": "on", "hours": "4", "reason": "test",
                                                "confirm": "ALL USERS"}),
                       ("/admin/settings/google-signin-off", {})]:
        r = gs.post(path, data={"csrf": tok_, **data})
        assert r.status_code == 403 and "needs a Microsoft sign-in" in r.text, path
    assert db.user(target)["state"] == D.ACTIVE
    assert "x@hotsprings.org" not in settings_store.load(db, replace(sapp.state.cfg)).pilot_list
    # non-destructive admin action still works on a fresh Google session
    assert gs.post(f"/admin/users/{target}/pause", data={"csrf": tok_}).status_code == 303
    assert "stepup_required" in actions(db)


def test_stepup_login_uses_prompt_login_when_ms_signin_is_old(sapp, g, entra, db):
    _, uid = _admin_with_google(sapp, g, entra, db)
    gs = client(sapp)
    google_login(gs, g, gc(sub="g-sub-m", email="it-admin@hotsprings.org"))
    gs.get("/login?stepup=1")
    assert entra.prompts[-1] == "select_account"          # Microsoft sign-in minutes ago
    db.q("UPDATE users SET roles_synced_at=? WHERE id=?",
         (D.iso(D.utcnow() - __import__("datetime").timedelta(hours=2)), uid))
    gs.get("/login?stepup=1")
    assert entra.prompts[-1] == "login"


def test_guest_gets_no_roles(sapp, entra, db):
    c = ms(client(sapp), entra, extra={"acct": 1})
    assert db.users() == [] and c.get("/me").status_code == 403


def test_ms_callback_refuses_google_flow_and_foreign_tenant(sapp, entra, db, g):
    c = client(sapp)
    c.get("/login/google")
    entra.claims = claims()
    assert c.get(f"/auth/callback?code=a&state={c.cookies.get('springsync_flow')}").status_code == 400
    c = client(sapp)
    entra.claims = claims(tid=FOREIGN)
    c.get("/login")
    assert c.get(f"/auth/callback?code=a&state={c.cookies.get('springsync_flow')}").status_code == 403
    entra.claims = {**claims(), "oid": ""}
    c.get("/login")
    assert c.get(f"/auth/callback?code=a&state={c.cookies.get('springsync_flow')}").status_code == 403


# ---- admin unlink / kill switch ----------------------------------------------------------------------------

def test_admin_sees_and_unlinks_identities_last_one_disables(sapp, g, entra, db):
    u = ms(client(sapp), entra)
    uid = db.user_by_oid("oid-1")["id"]
    link_google(u, g)
    adm = ms(client(sapp), entra, oid="oid-m", upn="it-admin@hotsprings.org", groups=(G_USERS, G_ADMINS))
    page = adm.get(f"/admin/users/{uid}").text
    assert "Google (Workspace)" in page and "Microsoft (work)" in page
    gi, ei = sorted(db.identities_for_user(uid), key=lambda i: i["provider"] != "google")
    tok_ = csrf(adm, f"/admin/users/{uid}")
    assert adm.post(f"/admin/users/{uid}/identities/{gi['id']}/unlink", data={"csrf": tok_}).status_code == 303
    assert db.user(uid)["state"] != D.OFFBOARDING
    r = adm.post(f"/admin/users/{uid}/identities/{ei['id']}/unlink", data={"csrf": tok_})
    assert r.status_code == 400                               # last method: UPN confirmation required
    r = adm.post(f"/admin/users/{uid}/identities/{ei['id']}/unlink", data={"csrf": tok_, "confirm": "jsmith@hotsprings.org"})
    assert r.status_code == 303 and db.user(uid)["state"] == D.OFFBOARDING
    assert db.identities_for_user(uid) == [] and "user_disabled_no_signin_method" in actions(db)
    assert u.get("/me").status_code == 303                    # their Microsoft session ended
    # the same Microsoft account can't silently get a new user row
    c = client(sapp)
    entra.claims = claims()
    c.get("/login")
    r = c.get(f"/auth/callback?code=abc&state={c.cookies.get('springsync_flow')}")
    assert r.status_code == 403 and "removed from SpringSync" in r.text
    assert len(db.users(include_removed=True)) == 2


def test_auditor_view_shows_identities_without_unlink(sapp, g, entra, db):

    ms(client(sapp), entra)
    uid = db.users()[0]["id"]
    a = ms(client(sapp), entra, oid="oid-a", upn="aud@hotsprings.org", groups=(G_AUDIT,))
    t = a.get(f"/audit/users/{uid}").text
    assert "Microsoft (work)" in t and "/identities/" not in t


@pytest.mark.smoke
def test_kill_switch_ends_google_sessions_and_only_cli_reenables(sapp, g, entra, db, scfg):
    c = ms(client(sapp), entra)
    link_google(c, g)
    gs = client(sapp)
    google_login(gs, g)
    assert gs.get("/me").status_code == 200
    adm = ms(client(sapp), entra, oid="oid-m", upn="it-admin@hotsprings.org", groups=(G_USERS, G_ADMINS))
    assert "Turn off Google sign-in now" in adm.get("/admin/settings").text
    r = adm.post("/admin/settings/google-signin-off", data={"csrf": csrf(adm, "/admin/settings")})
    assert r.status_code == 303 and "signin_google_disabled" in actions(db)
    assert gs.get("/me").status_code == 303                   # Google session ended
    assert client(sapp).get("/login/google").status_code == 404
    assert "/login/google" not in client(sapp).get("/").text
    assert "springsync signin enable-google" in adm.get("/admin/settings").text
    assert any(i["type"] == "signin_google_disabled" for i in db.open_issues())
    # no GUI route turns it back on
    assert adm.post("/admin/settings/google-signin-on", data={"csrf": csrf(adm, "/admin/settings")}).status_code in (404, 405)
    db.clear_flag("signin_google_off")      # what `odnas signin enable-google` does (tested below)
    assert google_login(client(sapp), g).status_code == 303


def test_cli_signin_status_and_enable(monkeypatch, scfg, db, capsys):
    from odnas import cli
    monkeypatch.setattr(cli, "_cfg_db", lambda: (scfg, db))
    assert cli.main(["signin", "status"]) == 0
    st = json.loads(capsys.readouterr().out)
    assert st["google_available"] is True and st["google_redirect_uri"].endswith("/auth/google/signin/callback")
    assert cli.main(["signin", "enable-google"]) == 0 and "nothing to do" in capsys.readouterr().out
    db.set_flag("signin_google_off", "gui", by="it-admin@hotsprings.org")
    assert cli.main(["signin", "enable-google"]) == 0 and db.flag("signin_google_off") is None
    assert "signin_google_enabled" in actions(db)
    monkeypatch.setattr(cli, "_cfg_db", lambda: (replace(scfg, signin_google=False), db))
    assert cli.main(["signin", "enable-google"]) == 2


# ---- config (§4.5.9) ----------------------------------------------------------------------------------------

def test_signin_config_switches(tmp_path):
    from odnas.config import ConfigError, load_config
    p = tmp_path / "c.toml"

    def write(google_extra="", signin="google = true\n", client_id=GCLIENT):
        p.write_text(f'[entra]\ntenant_id = "{TENANT}"\nclient_id = "{CLIENT}"\n'
                     f'[google]\nclient_id = "{client_id}"\nallowed_domain = "hotsprings.org"\n{google_extra}'
                     f'[signin]\n{signin}')
        return load_config(path=str(p), env={})
    c = write()
    assert c.signin_google and c.google_signin_available and c.signin_microsoft_work
    assert c.google_signin_redirect_path == "/auth/google/signin/callback"
    assert write(signin="").signin_google is False                  # code default: off
    for kw in ({"signin": "personal_microsoft = true\n"}, {"signin": "microsoft_work = false\n"},
               {"google_extra": 'signin_redirect_path = "/auth/google/callback"\n'},
               {"google_extra": 'signin_redirect_path = "/elsewhere"\n'}):
        with pytest.raises(ConfigError):
            write(**kw)
    assert write(client_id="").google_signin_available is False      # no client: no button


def test_no_gmail_setting_anywhere():
    from odnas.config import Config
    names = {f for f in Config.__dataclass_fields__}
    assert not [n for n in names if "gmail" in n or "google_personal" in n]
    ex = (Path(__file__).resolve().parent.parent / "deploy" / "config" / "springsync.toml.example").read_text()
    assert "[signin]" in ex and "google = false" in ex and "personal_microsoft = false" in ex
