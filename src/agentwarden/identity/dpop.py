"""DPoP: sender-constrained agent tokens (RFC 9449).

A DPoP-bound token carries ``cnf.jkt``, the RFC 7638 thumbprint of a public key the agent holds.
Every use of the token must come with a fresh **proof**: a JWT the agent signs with that key,
covering the HTTP method and URL of *this* request and a hash of the token (``ath``). Stolen
tokens are useless without the private key, and proofs can't be replayed (each ``jti`` is
remembered in the database, so this holds across AgentWarden instances).

Server nonces (``use_dpop_nonce``) are not implemented; proofs are accepted for ``max_age``
seconds around the server clock instead.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt

from agentwarden.errors import AuthenticationError
from agentwarden.identity.keys import b64url, jwk_thumbprint
from agentwarden.storage import Database

PROOF_TYPE = "dpop+jwt"
ALLOWED_ALGORITHMS = ("ES256", "EdDSA")
_PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})
_DEFAULT_PORTS = {"http": 80, "https": 443}


class DpopError(AuthenticationError):
    """The DPoP proof is missing, malformed, or doesn't match the request or token."""


@dataclass(frozen=True)
class DpopPresentation:
    """What arrived with a request: the ``DPoP`` header, the auth scheme, and the request target."""

    proof: str | None
    method: str
    url: str
    scheme: str = "DPoP"


def normalize_htu(url: str) -> str:
    """Lowercase scheme and host, drop the default port, query and fragment (RFC 9449 4.3)."""
    parts = urlsplit(url)
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    netloc = host if parts.port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{parts.port}"
    return urlunsplit((scheme, netloc, parts.path or "/", "", ""))


def access_token_hash(token: str) -> str:
    return b64url(hashlib.sha256(token.encode("ascii")).digest())


class DpopVerifier:
    def __init__(
        self,
        db: Database,
        *,
        clock: Callable[[], float] = time.time,
        max_age: int = 60,
        skew: int = 30,
    ) -> None:
        self._db = db
        self._clock = clock
        self._max_age = max_age
        self._skew = skew
        self._checks = 0

    def verify(self, proof: str, *, method: str, url: str, access_token: str | None = None) -> str:
        """Validate ``proof`` for this request and return the key's thumbprint (``jkt``)."""
        try:
            header = jwt.get_unverified_header(proof)
        except jwt.PyJWTError as exc:
            raise DpopError("malformed DPoP proof") from exc
        if header.get("typ") != PROOF_TYPE:
            raise DpopError("DPoP proof must have typ dpop+jwt")
        alg = header.get("alg")
        if alg not in ALLOWED_ALGORITHMS:
            raise DpopError(f"DPoP proof algorithm {alg!r} is not accepted")
        jwk = header.get("jwk")
        if not isinstance(jwk, Mapping) or _PRIVATE_MEMBERS & set(jwk):
            raise DpopError("DPoP proof must carry a public jwk (and no private key material)")
        try:
            key = jwt.PyJWK(dict(jwk), algorithm=alg).key
            claims: dict[str, Any] = jwt.decode(
                proof,
                key,
                algorithms=[alg],
                options={
                    "require": ["jti", "htm", "htu", "iat"],
                    "verify_iat": False,
                    "verify_aud": False,
                },
            )
            thumbprint = jwk_thumbprint(dict(jwk))
        except (jwt.PyJWTError, ValueError, TypeError) as exc:
            raise DpopError(f"invalid DPoP proof: {exc}") from exc

        if str(claims["htm"]).upper() != method.upper():
            raise DpopError("DPoP proof is for a different HTTP method")
        if normalize_htu(str(claims["htu"])) != normalize_htu(url):
            raise DpopError("DPoP proof is for a different URL")
        now, iat = self._clock(), float(claims["iat"])
        if iat > now + self._skew or iat < now - self._max_age - self._skew:
            raise DpopError("DPoP proof is too old or from the future")
        if access_token is not None and claims.get("ath") != access_token_hash(access_token):
            raise DpopError("DPoP proof doesn't match the presented token (ath)")
        self._remember(str(claims["jti"]), thumbprint, iat)
        return thumbprint

    def _remember(self, jti: str, thumbprint: str, iat: float) -> None:
        self._checks += 1
        now = self._clock()
        if self._checks % 100 == 1:  # keep the table small
            self._db.execute("DELETE FROM used_dpop_proofs WHERE expires_at < ?", (now,))
        key = hashlib.sha256(f"{thumbprint}:{jti}".encode()).hexdigest()
        first_use = self._db.execute(
            "INSERT INTO used_dpop_proofs (proof_hash, expires_at) VALUES (?, ?)"
            " ON CONFLICT (proof_hash) DO NOTHING",
            (key, iat + self._max_age + 2 * self._skew),
        )
        if not first_use:
            raise DpopError("DPoP proof has already been used (replay)")
