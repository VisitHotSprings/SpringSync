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
- The ID token arrives directly from Google's token endpoint over TLS, so per OIDC Core 3.1.3.7 the TLS
  server check stands in for a signature check; iss, aud, exp and nonce are still validated. It is never
  accepted from any other channel.
- check_claims: `hd` == google_allowed_domain, email_verified, and the email equal to the signed-in user's
  UPN (case-insensitive) or an admin-approved alias (§14.24). Consumer Gmail accounts have no `hd`.
- Error mapping (§4.3): invalid_grant -> needs_reauth; admin_policy_enforced -> blocked_by_ca ("blocked by
  admin policy"); invalid_client / unauthorized_client -> AUTH_APP: the app's own Google credential is
  wrong, one high alert and no Google user runs until it is fixed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlencode

from odnas.config import GOOGLE_SECRET_FILE, Config
from odnas.entra import AUTH_CA, AUTH_OK, AUTH_REAUTH, AUTH_TRANSIENT, TokenResult

AUTH_APP = "app_credential"   # invalid_client / unauthorized_client: the client id/secret, not the user

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
SCOPES = ("openid", "email", DRIVE_SCOPE)
ISSUERS = ("https://accounts.google.com", "accounts.google.com")
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


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_id_token(id_token: str) -> dict:
    """Payload of a JWT received directly from Google's token endpoint (see module docstring)."""
    try:
        payload = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as e:
        raise ValueError("malformed id_token") from e


def validate_id_claims(c: dict, *, client_id: str, nonce: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    if c.get("iss") not in ISSUERS:
        raise ValueError("id_token issuer is not Google")
    aud = c.get("aud")
    if (aud if isinstance(aud, str) else (aud or [None])[0]) != client_id:
        raise ValueError("id_token audience mismatch")
    if float(c.get("exp", 0)) < now - 60:
        raise ValueError("id_token expired")
    if not nonce or not secrets.compare_digest(str(c.get("nonce", "")), nonce):
        raise ValueError("id_token nonce mismatch")


class HttpGoogleClient:
    """Real client (httpx). Only used in production; tests use FakeGoogle or an httpx MockTransport."""

    def __init__(self, cfg: Config, transport: Any = None):
        self.cfg, self._transport = cfg, transport

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
            claims = decode_id_token(res.id_claims.get("_id_token", ""))
            validate_id_claims(claims, client_id=self.cfg.google_client_id, nonce=flow.get("nonce", ""))
        except ValueError as e:
            return GoogleTokenResult(error="invalid_id_token", error_description=str(e))
        res.id_claims = claims
        if DRIVE_SCOPE not in res.scope.split():
            return GoogleTokenResult(error="drive_scope_not_granted",
                                     error_description="Google Drive access was not granted on the consent screen")
        return res

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
