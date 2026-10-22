"""ID-token validation for both sign-in providers (v0.12, SPEC v0.10 §4.5.2, §4.5.4).

MSAL Python 1.39 no longer validates ID tokens ("validation is the application's responsibility"), and
Google's OIDC docs allow skipping the signature check only for a token taken straight off the token
endpoint. SpringSync validates every ID token itself, for both Microsoft and Google:
  * signature: RS256 only, key picked by `kid` from the provider's JWKS (cached; one forced refetch when an
    unknown `kid` appears, so key rotation works, but at most every 5 min, so a forged `kid` can't make us
    hammer the JWKS endpoint);
  * `iss` exact match (Microsoft: https://login.microsoftonline.com/<tid>/v2.0 for the token's own `tid`,
    and that `tid` must be the configured VHS tenant);
  * `aud` == our client ID (and `azp` too when there are several audiences);
  * `exp`, `nbf`, `iat` with a small clock skew (2 min), plus `iat` no older than 10 min (the token is used
    straight after the code exchange, never later);
  * `nonce` == the nonce of this one sign-in flow (flows are single use, so a replayed callback fails).
Nothing in here is ever logged with a token in it.
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

SKEW_S = 60                 # SPEC v0.10.1 §4.5.2: 60 s clock skew
MAX_TOKEN_AGE_S = 600
JWKS_TTL_S = 3600
JWKS_MIN_REFETCH_S = 300
ALGORITHMS = ("RS256",)

GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
GOOGLE_ISSUER = "https://accounts.google.com"   # the form identities are stored under
MS_LOGIN = "https://login.microsoftonline.com"


def ms_jwks_uri(tenant_id: str) -> str:
    return f"{MS_LOGIN}/{tenant_id}/discovery/v2.0/keys"


def ms_issuer(tid: str) -> str:
    return f"{MS_LOGIN}/{tid}/v2.0"


def msal_nonce(raw: str) -> str:
    """MSAL sends sha256(nonce) in the request, so that's what comes back in the token."""
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


class TokenError(ValueError):
    """An ID token we refuse. `reason` is a short code for the audit log (never the token)."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _http_fetch(uri: str) -> dict:
    import httpx
    if not uri.startswith("https://"):
        raise TokenError("jwks_not_https")
    r = httpx.get(uri, timeout=10, follow_redirects=False)
    r.raise_for_status()
    return r.json()


class JwksCache:
    """Per-URI JWKS cache. `fetch` is injectable for tests."""

    def __init__(self, fetch: Callable[[str], dict] | None = None, clock: Callable[[], float] = time.time):
        self._fetch, self._clock = fetch or _http_fetch, clock
        self._keys: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _load(self, uri: str) -> dict[str, Any]:
        import jwt
        try:
            data = self._fetch(uri)
        except TokenError:
            raise
        except Exception as e:
            raise TokenError("jwks_unavailable") from e
        keys = {}
        for k in (data or {}).get("keys", []):
            if k.get("kty") == "RSA" and k.get("kid") and k.get("use", "sig") == "sig":
                try:
                    keys[k["kid"]] = jwt.PyJWK(k, algorithm="RS256").key
                except Exception:
                    continue
        self._keys[uri] = (self._clock(), keys)
        return keys

    def key(self, uri: str, kid: str):
        with self._lock:
            fetched, keys = self._keys.get(uri, (0.0, {}))
            age = self._clock() - fetched
            if not keys or age > JWKS_TTL_S:
                fetched, keys = self._clock(), self._load(uri)
                age = 0.0
            if kid not in keys and age >= JWKS_MIN_REFETCH_S:
                keys = self._load(uri)
            if kid not in keys:
                raise TokenError("unknown_signing_key")
            return keys[kid]


@dataclass(frozen=True)
class Expect:
    jwks_uri: str
    audience: str
    nonce: str
    issuers: tuple[str, ...] = ()                      # exact issuers (Google)
    issuer_for: Callable[[dict], str] | None = None    # issuer computed from the claims (Microsoft: per tid)


def verify(id_token: str, expect: Expect, jwks: JwksCache, now: float | None = None) -> dict:
    """-> verified claims, or raises TokenError."""
    import jwt
    if not id_token or not isinstance(id_token, str):
        raise TokenError("no_id_token")
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError:
        raise TokenError("malformed") from None
    if header.get("alg") not in ALGORITHMS:          # no "none", no HS256 with a public key as secret
        raise TokenError("bad_algorithm")
    kid = header.get("kid")
    if not kid:
        raise TokenError("no_kid")
    key = jwks.key(expect.jwks_uri, kid)
    now = time.time() if now is None else now
    try:
        # times are checked by _check_times (with a pinnable clock); everything else by PyJWT
        c = jwt.decode(id_token, key, algorithms=list(ALGORITHMS), audience=expect.audience,
                       options={"require": ["exp", "iat", "iss", "aud", "sub"], "verify_iss": False,
                                "verify_exp": False, "verify_nbf": False, "verify_iat": False})
    except jwt.InvalidSignatureError:
        raise TokenError("bad_signature") from None
    except jwt.ExpiredSignatureError:
        raise TokenError("expired") from None
    except jwt.ImmatureSignatureError:
        raise TokenError("not_yet_valid") from None
    except jwt.InvalidAudienceError:
        raise TokenError("wrong_audience") from None
    except jwt.MissingRequiredClaimError:
        raise TokenError("missing_claim") from None
    except jwt.PyJWTError:
        raise TokenError("invalid") from None
    _check_times(c, now)
    want = expect.issuer_for(c) if expect.issuer_for else ""
    if not (c.get("iss") == want if expect.issuer_for else c.get("iss") in expect.issuers):
        raise TokenError("wrong_issuer")
    aud = c.get("aud")
    if isinstance(aud, list) and aud != [expect.audience]:   # §4.5.2: a list must contain only our client ID
        raise TokenError("wrong_audience")
    if not expect.nonce or not secrets.compare_digest(str(c.get("nonce", "")), expect.nonce):
        raise TokenError("nonce_mismatch")
    return c


def _check_times(c: dict, now: float) -> None:
    """exp / nbf / iat with SKEW_S of clock skew, and iat no older than MAX_TOKEN_AGE_S."""
    try:
        exp, iat = float(c["exp"]), float(c["iat"])
        nbf = float(c.get("nbf", iat))
    except (KeyError, TypeError, ValueError):
        raise TokenError("missing_claim") from None
    if now > exp + SKEW_S:
        raise TokenError("expired")
    if now + SKEW_S < nbf or now + SKEW_S < iat:
        raise TokenError("not_yet_valid")
    if now - iat > MAX_TOKEN_AGE_S + SKEW_S:
        raise TokenError("too_old")


def google_expect(client_id: str, nonce: str) -> Expect:
    return Expect(GOOGLE_JWKS, client_id, nonce, issuers=GOOGLE_ISSUERS)


def ms_expect(client_id: str, tenant_id: str, nonce_hash: str) -> Expect:
    """Microsoft, single-tenant org app: the token's own tid must be the VHS tenant, and iss must be exactly
    the issuer for that tid (no wildcard, no prefix match)."""
    tenant = tenant_id.lower()

    def issuer_for(c: dict) -> str:
        tid = str(c.get("tid", "")).lower()
        if tid != tenant:
            raise TokenError("wrong_tenant")
        return ms_issuer(c.get("tid", ""))
    return Expect(ms_jwks_uri(tenant_id), client_id, nonce_hash, issuer_for=issuer_for)


_DEFAULT = JwksCache()


def default_jwks() -> JwksCache:
    return _DEFAULT
