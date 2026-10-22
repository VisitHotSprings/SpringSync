"""Connect Google Drive (SPEC v0.9 §4.3, §4.4). Google is a DATA connection only: app sign-in and roles stay
Microsoft Entra for everyone. A signed-in user whose admin-set provider is `gdrive` clicks Connect Google
Drive; we store the Google refresh token (google_credentials) for rclone's `drive` remote via the broker.
Mirrors odnas/entra.py: the HTTP client sits behind the GoogleClient protocol so tests (FakeGoogle) and the
lab can substitute it. Nothing here runs at import time and no network call is made until a method of
HttpGoogleClient is invoked.

- OAuth 2.0 web client (confidential), authorization-code flow with PKCE (S256), `state` and `nonce`.
- Delegated, offline: access_type=offline + prompt=consent, so Google returns a refresh token.
- Scopes: openid email + https://www.googleapis.com/auth/drive (full Drive: bisync must create, update,
  move and delete files anywhere in My Drive, and one-way runs create the cloud .springsync-check once;
  drive.file would only see files the app created; drive.readonly is §14.19).
  Google lets a user untick the Drive scope on the consent screen: complete_auth refuses a grant
  without it.
- v0.12: every ID token (Drive connect and Sign in with Google) is fully validated by odnas/oidc.py:
  RS256 signature against Google's JWKS, iss, aud/azp, exp/nbf/iat with 2 min skew, and the flow's nonce.
- v0.12 Sign in with Google (SPEC v0.10 §4.5): identity only (`openid email profile`, no offline access, no
  refresh token kept), its own redirect path, and check_signin_claims: hd == google_allowed_domain from the
  verified token (the `hd` request parameter is only a hint) and email_verified. The email never links or
  authorizes anything; the identity is (issuer, sub).
- check_claims: `hd` == google_allowed_domain, email_verified, and the email equal to the signed-in user's
  UPN (case-insensitive) or an admin-approved alias (§14.24). Consumer Gmail accounts have no `hd`.
- Error mapping (§4.3): invalid_grant -> needs_reauth; admin_policy_enforced -> blocked_by_ca ("blocked by
  admin policy"); invalid_client / unauthorized_client -> AUTH_APP: the app's own Google credential is
  wrong, one high alert and no Google user runs until it is fixed.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

from odnas.config import GOOGLE_SECRET_FILE, Config
from odnas.entra import AUTH_CA, AUTH_OK, AUTH_REAUTH, AUTH_TRANSIENT, TokenResult

AUTH_APP = "app_credential"   # invalid_client / unauthorized_client: the client id/secret, not the user

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
SCOPES = ("openid", "email", DRIVE_SCOPE)
SIGNIN_SCOPES = ("openid", "email", "profile")   # v0.12 sign-in: identity only, never file scopes
# Google token-endpoint errors: revoked/expired grant -> reconnect; a Workspace admin policy -> like an
# Entra Conditional Access block (the user can't fix it, IT must look at the Google admin console).
REAUTH_ERRORS = {"invalid_grant", "invalid_rapt", "interaction_required"}
POLICY_ERRORS = {"admin_policy_enforced", "org_internal"}
APP_ERRORS = {"invalid_client", "unauthorized_client"}


def classify_google_error(error: str | None, description: str | None = "") -> str:
    e, d = (error or "").strip(), (description or "")
    if e in APP_ERRORS:
        return AUTH_APP
    if e in POLICY_ERRORS or "admin_policy_enforced" in d:
        return AUTH_CA
    if e in REAUTH_ERRORS or "invalid_rapt" in d:
        return AUTH_REAUTH
    return AUTH_TRANSIENT if e else AUTH_OK


@dataclass
class GoogleTokenResult(TokenResult):
    scope: str = ""

    @property
    def classification(self) -> str:
        return AUTH_OK if self.ok else classify_google_error(self.error, self.error_description)


class GoogleClient(Protocol):
    def begin_auth(self, redirect_uri: str, hd: str = "", login_hint: str = "") -> dict: ...
    def begin_signin(self, redirect_uri: str, hd: str = "") -> dict: ...
    def complete_signin(self, flow: dict, query: dict[str, str]) -> "GoogleTokenResult": ...
    def complete_auth(self, flow: dict, query: dict[str, str]) -> GoogleTokenResult: ...
    def refresh(self, refresh_token: str) -> GoogleTokenResult: ...
    def get_drive(self, access_token: str) -> dict: ...   # {"id": My Drive root folder id, "email": account}


class ClaimsError(ValueError):
    """A Google identity that may not sign in. `reason` is a short code for the audit log."""
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def check_claims(c: dict, allowed_domain: str, expected_emails: set[str]) -> tuple[str, str]:
    """-> (sub, email). §4.3/§4.4: hd == allowed domain, verified email, email == UPN or approved alias."""
    sub = str(c.get("sub") or "")
    email = str(c.get("email") or "").strip().lower()
    hd = str(c.get("hd") or "").strip().lower()
    if not sub or not email:
        raise ClaimsError("no_identity", "Google did not return an account identity.")
    if not hd:
        raise ClaimsError("not_workspace", "Only Visit Hot Springs Google Workspace accounts can be connected.")
    if hd != (allowed_domain or "").strip().lower():
        raise ClaimsError("domain_not_allowed", "This Google Workspace organisation is not allowed.")
    if c.get("email_verified") not in (True, "true"):
        raise ClaimsError("email_not_verified", "This Google account's email address is not verified.")
    if email not in {e.strip().lower() for e in expected_emails}:
        raise ClaimsError("email_mismatch", "This Google account does not match your Microsoft account. Sign in to "
                                            "Google with your work address, or ask IT to approve an alias.")
    return sub, email


def check_signin_claims(c: dict, allowed_domain: str) -> tuple[str, str, str]:
    """-> (sub, hd, email). Sign in with Google (v0.12): a Workspace account of the allowed domain (`hd` from the
    VERIFIED ID token) with a verified email. No email matching here: the identity is (issuer, sub), and only a
    link made by the signed-in owner (or an admin) maps it to a SpringSync user."""
    sub = str(c.get("sub") or "")
    hd = str(c.get("hd") or "").strip().lower()
    email = str(c.get("email") or "").strip().lower()
    if not sub:
        raise ClaimsError("no_identity", "Google did not return an account identity.")
    if not hd:
        raise ClaimsError("not_workspace", "Only Visit Hot Springs Google Workspace accounts can sign in with Google.")
    if hd != (allowed_domain or "").strip().lower():
        raise ClaimsError("domain_not_allowed", "This Google Workspace organisation is not allowed.")
    if c.get("email_verified") is not True:
        raise ClaimsError("email_not_verified", "This Google account's email address is not verified.")
    return sub, hd, email


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class HttpGoogleClient:
    """Real client (httpx). Only used in production; tests use FakeGoogle or an httpx MockTransport."""

    def __init__(self, cfg: Config, transport: Any = None, jwks: Any = None):
        from odnas import oidc
        self.cfg, self._transport = cfg, transport
        self._jwks = jwks or oidc.default_jwks()

    def _secret(self) -> str:
        return self.cfg.read_secret(GOOGLE_SECRET_FILE).decode().strip()

    def _http(self):
        import httpx
        return httpx.Client(timeout=30, transport=self._transport, headers={"User-Agent": self.cfg.user_agent})

    def begin_auth(self, redirect_uri: str, hd: str = "", login_hint: str = "") -> dict:
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        q = {"client_id": self.cfg.google_client_id, "redirect_uri": redirect_uri, "response_type": "code",
             "scope": " ".join(SCOPES), "access_type": "offline", "prompt": "consent",
             "include_granted_scopes": "false", "state": state, "nonce": nonce, "code_challenge": challenge,
             "code_challenge_method": "S256"}
        if hd:
            q["hd"] = hd   # a hint for the account chooser only; check_claims is the real check
        if login_hint:
            q["login_hint"] = login_hint
        return {"provider": "google", "state": state, "nonce": nonce, "code_verifier": verifier,
                "redirect_uri": redirect_uri, "auth_uri": GOOGLE_AUTH_URL + "?" + urlencode(q)}

    def _token(self, form: dict) -> GoogleTokenResult:
        try:
            with self._http() as h:
                r = h.post(GOOGLE_TOKEN_URL, data={**form, "client_id": self.cfg.google_client_id,
                                                   "client_secret": self._secret()})
            j = r.json()
        except Exception as e:   # network / JSON: transient, never echo anything back
            return GoogleTokenResult(error="network_error", error_description=type(e).__name__)
        if "error" in j:
            return GoogleTokenResult(error=str(j.get("error")), error_description=str(j.get("error_description", "")))
        return GoogleTokenResult(access_token=j.get("access_token", ""), refresh_token=j.get("refresh_token", ""),
                                 expires_in=int(j.get("expires_in") or 0), scope=j.get("scope", ""),
                                 id_claims={"_id_token": j.get("id_token", "")})

    def complete_auth(self, flow: dict, query: dict[str, str]) -> GoogleTokenResult:
        if query.get("error"):
            return GoogleTokenResult(error=query["error"], error_description=query.get("error_description", ""))
        if not secrets.compare_digest(str(query.get("state", "")), str(flow.get("state", ""))):
            return GoogleTokenResult(error="state_mismatch")
        res = self._token({"grant_type": "authorization_code", "code": query.get("code", ""),
                           "redirect_uri": flow["redirect_uri"], "code_verifier": flow["code_verifier"]})
        if not res.ok:
            return res
        try:
            res.id_claims = self._verify(res.id_claims.get("_id_token", ""), flow)
        except ValueError as e:
            return GoogleTokenResult(error="invalid_id_token", error_description=str(e))
        if DRIVE_SCOPE not in res.scope.split():
            return GoogleTokenResult(error="drive_scope_not_granted",
                                     error_description="Google Drive access was not granted on the consent screen")
        return res

    def _verify(self, id_token: str, flow: dict) -> dict:
        from odnas import oidc
        return oidc.verify(id_token, oidc.google_expect(self.cfg.google_client_id, flow.get("nonce", "")), self._jwks)

    # ---- v0.12 Sign in with Google (identity only) ----------------------------------------------------
    def begin_signin(self, redirect_uri: str, hd: str = "") -> dict:
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        q = {"client_id": self.cfg.google_client_id, "redirect_uri": redirect_uri, "response_type": "code",
             "scope": " ".join(SIGNIN_SCOPES), "prompt": "select_account", "state": state, "nonce": nonce,
             "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
        if hd:
            q["hd"] = hd   # account-chooser hint only; check_signin_claims checks hd in the verified token
        return {"provider": "google", "state": state, "nonce": nonce, "code_verifier": verifier,
                "redirect_uri": redirect_uri, "auth_uri": GOOGLE_AUTH_URL + "?" + urlencode(q)}

    def complete_signin(self, flow: dict, query: dict[str, str]) -> GoogleTokenResult:
        if query.get("error"):
            return GoogleTokenResult(error=query["error"], error_description=query.get("error_description", ""))
        if not secrets.compare_digest(str(query.get("state", "")), str(flow.get("state", ""))):
            return GoogleTokenResult(error="state_mismatch")
        res = self._token({"grant_type": "authorization_code", "code": query.get("code", ""),
                           "redirect_uri": flow["redirect_uri"], "code_verifier": flow["code_verifier"]})
        if not res.ok:
            return res
        try:
            claims = self._verify(res.id_claims.get("_id_token", ""), flow)
        except ValueError as e:
            return GoogleTokenResult(error="invalid_id_token", error_description=str(e))
        # identity only: nothing from this exchange is kept except the verified claims
        return GoogleTokenResult(access_token="signin", id_claims=claims)

    def refresh(self, refresh_token: str) -> GoogleTokenResult:
        res = self._token({"grant_type": "refresh_token", "refresh_token": refresh_token})
        if res.ok and not res.refresh_token:
            res.refresh_token = refresh_token   # Google normally does not rotate refresh tokens
        return res

    def get_drive(self, access_token: str) -> dict:
        with self._http() as h:
            hdr = {"Authorization": f"Bearer {access_token}"}
            root = h.get("https://www.googleapis.com/drive/v3/files/root", params={"fields": "id"}, headers=hdr)
            about = h.get("https://www.googleapis.com/drive/v3/about", params={"fields": "user(emailAddress)"},
                          headers=hdr)
            root.raise_for_status()
            about.raise_for_status()
        return {"id": root.json()["id"], "email": about.json().get("user", {}).get("emailAddress", "")}
