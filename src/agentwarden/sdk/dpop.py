"""Client side of DPoP: the agent's key pair and the proofs it signs (RFC 9449)."""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from agentwarden.identity.dpop import PROOF_TYPE, access_token_hash
from agentwarden.identity.keys import jwk_thumbprint


class DpopKey:
    """An agent's DPoP key (ECDSA P-256 / ES256). Keep the private key with the agent only."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._private_key = private_key or ec.generate_private_key(ec.SECP256R1())
        if not isinstance(self._private_key.curve, ec.SECP256R1):
            raise ValueError("DPoP keys must be on the P-256 curve (ES256)")
        public = json.loads(ECAlgorithm.to_jwk(self._private_key.public_key()))
        self.public_jwk: dict[str, Any] = {k: public[k] for k in ("kty", "crv", "x", "y")}
        self.thumbprint = jwk_thumbprint(self.public_jwk)

    @classmethod
    def load(cls, path: str | Path) -> DpopKey:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("expected an EC private key")
        return cls(key)

    def save(self, path: str | Path) -> Path:
        """Write the private key as PEM with 0600 permissions. Never overwrites."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return path

    def proof(self, method: str, url: str, access_token: str | None = None) -> str:
        """A one-time proof for ``method url`` (and ``access_token``, when presenting one)."""
        claims: dict[str, Any] = {
            "jti": uuid.uuid4().hex,
            "htm": method.upper(),
            "htu": url,
            "iat": int(time.time()),
        }
        if access_token is not None:
            claims["ath"] = access_token_hash(access_token)
        return jwt.encode(
            claims,
            self._private_key,
            algorithm="ES256",
            headers={"typ": PROOF_TYPE, "jwk": self.public_jwk},
        )

    def headers(self, method: str, url: str, access_token: str | None = None) -> dict[str, str]:
        """Headers for a request: the proof, plus ``Authorization: DPoP`` when given a token."""
        headers = {"DPoP": self.proof(method, url, access_token)}
        if access_token is not None:
            headers["Authorization"] = f"DPoP {access_token}"
        return headers
