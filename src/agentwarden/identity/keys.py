"""Ed25519 signing keys and the JWKS document used to verify AgentWarden tokens."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import warnings
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agentwarden.errors import ConfigurationError


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


#: RFC 7638 required members per key type.
_THUMBPRINT_MEMBERS = {
    "OKP": ("crv", "kty", "x"),
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
}


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint of a public JWK (OKP, EC or RSA). Used as ``kid`` and DPoP ``jkt``."""
    members = _THUMBPRINT_MEMBERS.get(str(jwk.get("kty")))
    if members is None or not all(isinstance(jwk.get(m), str) for m in members):
        raise ValueError("unsupported or incomplete JWK")
    required = {k: jwk[k] for k in members}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode("ascii")).digest())


class SigningKeys(Protocol):
    """What token issuance and audit checkpoints need: one signing key, many verification keys."""

    @property
    def kid(self) -> str: ...

    @property
    def private_key(self) -> Ed25519PrivateKey: ...

    def sign(self, data: bytes) -> bytes: ...

    def jwks(self) -> dict[str, Any]: ...

    def verification_key(self, kid: str) -> Ed25519PublicKey | None:
        """Key that may still verify *tokens* with this kid (None if unknown or expired)."""
        ...

    def any_public_key(self, kid: str) -> Ed25519PublicKey | None:
        """Any public key ever used with this kid (for old audit checkpoints)."""
        ...


def public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
        raise ConfigurationError("expected an Ed25519 OKP public JWK")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


class KeyManager:
    """Holds the gateway's Ed25519 key pair.

    A single key. For rotation with several published keys, use ``KeyRing``.
    The ``kid`` is derived from the public key, so a rotated key always gets a new id.
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self.public_key: Ed25519PublicKey = private_key.public_key()
        raw = self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}
        self.kid = jwk_thumbprint(self._jwk)

    @classmethod
    def generate(cls) -> KeyManager:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem_file(cls, path: str | Path) -> KeyManager:
        path = Path(path)
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise ConfigurationError(f"signing key not found: {path}") from exc
        if os.name == "posix" and path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            warnings.warn(
                f"signing key {path} is readable by group/others; run: chmod 600 {path}",
                stacklevel=2,
            )
        try:
            key = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError) as exc:
            raise ConfigurationError(f"could not parse signing key {path}: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ConfigurationError("signing key must be an Ed25519 private key")
        return cls(key)

    @classmethod
    def load_or_generate(cls, path: str | Path | None) -> KeyManager:
        """Load the key at ``path``, or create an ephemeral key when ``path`` is ``None``."""
        if path is None:
            return cls.generate()
        return cls.from_pem_file(path)

    def save_pem(self, path: str | Path) -> Path:
        """Write the private key as PKCS#8 PEM with 0600 permissions. Never overwrites."""
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

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._private_key

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        try:
            self.public_key.verify(signature, data)
        except InvalidSignature:
            return False
        return True

    def public_jwk(self) -> dict[str, Any]:
        return {**self._jwk, "kid": self.kid, "alg": "EdDSA", "use": "sig"}

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.public_jwk()]}

    def verification_key(self, kid: str) -> Ed25519PublicKey | None:
        return self.public_key if kid == self.kid else None

    def any_public_key(self, kid: str) -> Ed25519PublicKey | None:
        return self.verification_key(kid)
