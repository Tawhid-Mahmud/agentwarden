"""OpenID Connect: verify ID tokens from an external identity provider (IdP).

Used by the token-exchange endpoint (RFC 8693): a user signs in with the organization's IdP
(Google, Okta, Microsoft Entra, Keycloak…) and exchanges the resulting ID token for a scoped,
short-lived AgentWarden token for one of their agents. AgentWarden never sees a password.

Verification is deliberately strict:

* only asymmetric algorithms (RS/PS/ES/EdDSA), so ``alg=none`` and HMAC confusion are impossible;
* the key is chosen by ``kid`` from the IdP's JWKS (refetched once, rate-limited, when an unknown
  ``kid`` appears, which handles IdP key rotation);
* ``iss`` must equal the configured issuer exactly, ``aud`` must contain the configured client id,
  and ``azp`` (when present) must equal it too;
* ``exp``, ``iat`` and ``nbf`` are checked with the configured clock skew;
* when users are matched by email, ``email_verified`` must be ``true``;
* issuers must use HTTPS (plain HTTP is accepted only for ``localhost`` during development).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt

from agentwarden.errors import AuthenticationError, ConfigurationError

ASYMMETRIC_ALGORITHMS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "EdDSA",
)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def require_secure_url(url: str, what: str) -> str:
    parts = urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in _LOCAL_HOSTS):
        return url
    raise ConfigurationError(f"{what} must use https (http is allowed only for localhost): {url}")


@dataclass(frozen=True)
class IdentityClaims:
    """The verified identity asserted by the IdP."""

    issuer: str
    subject: str
    email: str | None
    email_verified: bool
    claims: dict[str, Any]


class OidcVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str | None = None,
        algorithms: tuple[str, ...] = ASYMMETRIC_ALGORITHMS,
        clock_skew: int = 30,
        http: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
        min_refresh_interval: float = 30.0,
    ) -> None:
        unsafe = [a for a in algorithms if a not in ASYMMETRIC_ALGORITHMS]
        if unsafe:
            raise ConfigurationError(f"only asymmetric algorithms are allowed, not {unsafe}")
        self.issuer = require_secure_url(issuer.rstrip("/"), "OIDC issuer")
        self.audience = audience
        self._jwks_url = require_secure_url(jwks_url, "JWKS URL") if jwks_url else None
        self._algorithms = list(algorithms)
        self._skew = clock_skew
        self._http = http or httpx.Client(timeout=5.0)
        self._clock = clock
        self._min_refresh = min_refresh_interval
        self._keys: dict[str, jwt.PyJWK] = {}
        self._last_fetch = -1e18
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ key discovery
    def _discover_jwks_url(self) -> str:
        url = f"{self.issuer}/.well-known/openid-configuration"
        document = self._get_json(url)
        if document.get("issuer", "").rstrip("/") != self.issuer:
            raise AuthenticationError("IdP discovery document names a different issuer")
        jwks_uri = document.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            raise AuthenticationError("IdP discovery document has no jwks_uri")
        return require_secure_url(jwks_uri, "JWKS URL")

    def _get_json(self, url: str) -> dict[str, Any]:
        try:
            response = self._http.get(url)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
            raise AuthenticationError(
                f"could not reach the identity provider ({url}): {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise AuthenticationError(f"unexpected response from the identity provider ({url})")
        return data

    def _refresh_keys(self, force: bool) -> None:
        with self._lock:
            now = self._clock()
            if not force and self._keys:
                return
            if now - self._last_fetch < self._min_refresh:
                return  # rate limit: an attacker can't make us hammer the IdP with random kids
            if self._jwks_url is None:
                self._jwks_url = self._discover_jwks_url()
            document = self._get_json(self._jwks_url)
            keys: dict[str, jwt.PyJWK] = {}
            for entry in document.get("keys", []):
                if (
                    not isinstance(entry, dict)
                    or entry.get("use", "sig") != "sig"
                    or "kid" not in entry
                ):
                    continue
                try:
                    keys[str(entry["kid"])] = jwt.PyJWK(entry)
                except (jwt.PyJWKError, jwt.InvalidKeyError):
                    continue  # skip keys we can't use (e.g. symmetric "oct" keys)
            self._keys = keys
            self._last_fetch = now

    def _key_for(self, kid: str) -> jwt.PyJWK:
        self._refresh_keys(force=False)
        if kid not in self._keys:
            self._refresh_keys(force=True)  # the IdP may have rotated its keys
        key = self._keys.get(kid)
        if key is None:
            raise AuthenticationError(
                "ID token signed with a key the identity provider doesn't publish"
            )
        return key

    # ------------------------------------------------------------------ verification
    def verify(self, token: str, *, require_verified_email: bool = True) -> IdentityClaims:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthenticationError("malformed ID token") from exc
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in self._algorithms:
            raise AuthenticationError(f"ID token algorithm {alg!r} is not accepted")
        if not isinstance(kid, str):
            raise AuthenticationError("ID token has no key id (kid)")
        key = self._key_for(kid)
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=[alg],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "require": ["iss", "aud", "sub", "exp", "iat"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"invalid ID token: {exc}") from exc

        now = self._clock()
        if float(claims["exp"]) <= now - self._skew:
            raise AuthenticationError("ID token expired")
        if float(claims["iat"]) > now + self._skew:
            raise AuthenticationError("ID token issued in the future")
        if "nbf" in claims and float(claims["nbf"]) > now + self._skew:
            raise AuthenticationError("ID token not valid yet")
        if "azp" in claims and claims["azp"] != self.audience:
            raise AuthenticationError("ID token was issued to a different client (azp)")

        email = claims.get("email")
        verified = claims.get("email_verified") is True
        if require_verified_email and (not isinstance(email, str) or not verified):
            raise AuthenticationError("ID token has no verified email address")
        return IdentityClaims(
            issuer=self.issuer,
            subject=str(claims["sub"]),
            email=email.lower() if isinstance(email, str) else None,
            email_verified=verified,
            claims=claims,
        )
