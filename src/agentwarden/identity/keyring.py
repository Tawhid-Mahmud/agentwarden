"""Signing-key rotation.

A key ring is a directory of Ed25519 keys plus a ``keyring.json`` manifest::

    keys/
      keyring.json         # kid, status, timestamps and public JWK of every key ever used
      <kid>.pem            # private keys of the active and retired keys (mode 0600)

Lifecycle of a key:

* **active**: signs new tokens and audit checkpoints. Exactly one key is active.
* **retired**: after a rotation. Still verifies tokens it signed until ``retired_at + grace``
  (grace = the longest token lifetime plus clock skew), so rotation never breaks live tokens.
* **pruned**: the private key file is deleted. The public key stays in the manifest so old audit
  checkpoints remain verifiable, but tokens signed with it are no longer accepted.

Rotations and prunes are written atomically under a lock file. Every process using the ring
re-reads the manifest when it changes (checked at most every ``reload_interval`` seconds), so a
rotation done with ``agentwarden keys rotate`` reaches running servers without a restart.
"""

from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agentwarden.errors import ConfigurationError
from agentwarden.identity.keys import KeyManager, public_key_from_jwk

MANIFEST = "keyring.json"
Status = Literal["active", "retired", "pruned"]

try:  # POSIX advisory locking; on other platforms a single writer is assumed
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


@dataclass
class KeyEntry:
    kid: str
    status: Status
    created_at: float
    retired_at: float | None
    public_jwk: dict[str, Any]
    manager: KeyManager | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "kid": self.kid,
            "status": self.status,
            "created_at": self.created_at,
            "retired_at": self.retired_at,
            "public_jwk": self.public_jwk,
        }


class KeyRing:
    """A rotating set of signing keys (implements ``SigningKeys``)."""

    def __init__(
        self,
        directory: str | Path,
        *,
        grace_seconds: int,
        clock: Callable[[], float] = time.time,
        reload_interval: float = 5.0,
    ) -> None:
        self.directory = Path(directory)
        self.grace_seconds = grace_seconds
        self._clock = clock
        self._reload_interval = reload_interval
        self._entries: dict[str, KeyEntry] = {}
        self._active: KeyEntry | None = None
        self._mtime: float | None = None
        self._last_check = -1e18
        self._lock = threading.RLock()

    @classmethod
    def open(
        cls,
        directory: str | Path,
        *,
        grace_seconds: int,
        clock: Callable[[], float] = time.time,
        create: bool = True,
        reload_interval: float = 5.0,
    ) -> KeyRing:
        """Load the ring, creating it with a first key if the directory has none."""
        ring = cls(
            directory, grace_seconds=grace_seconds, clock=clock, reload_interval=reload_interval
        )
        if not (ring.directory / MANIFEST).exists():
            if not create:
                raise ConfigurationError(f"no key ring in {ring.directory}")
            ring.rotate()
        ring._load()
        return ring

    # ------------------------------------------------------------------ persistence
    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(self.directory / ".lock", "a+") as fh:
            if fcntl is not None:
                fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fh, fcntl.LOCK_UN)

    def _read_manifest(self) -> list[dict[str, Any]]:
        path = self.directory / MANIFEST
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"corrupt key ring manifest {path}: {exc}") from exc
        keys = data.get("keys") if isinstance(data, dict) else None
        if not isinstance(keys, list):
            raise ConfigurationError(f"corrupt key ring manifest {path}")
        return keys

    def _write_manifest(self, entries: list[KeyEntry]) -> None:
        path = self.directory / MANIFEST
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, "keys": [e.to_json() for e in entries]}, indent=2))
        os.replace(tmp, path)

    def _load(self) -> None:
        with self._lock:
            entries: dict[str, KeyEntry] = {}
            active: KeyEntry | None = None
            for raw in self._read_manifest():
                entry = KeyEntry(
                    kid=str(raw["kid"]),
                    status=raw["status"],
                    created_at=float(raw["created_at"]),
                    retired_at=float(raw["retired_at"])
                    if raw.get("retired_at") is not None
                    else None,
                    public_jwk=dict(raw["public_jwk"]),
                )
                if entry.status in ("active", "retired"):
                    entry.manager = KeyManager.from_pem_file(self.directory / f"{entry.kid}.pem")
                    if entry.manager.kid != entry.kid:
                        raise ConfigurationError(f"key file for {entry.kid} holds a different key")
                if entry.status == "active":
                    if active is not None:
                        raise ConfigurationError("key ring has more than one active key")
                    active = entry
                entries[entry.kid] = entry
            if active is None:
                raise ConfigurationError(f"key ring in {self.directory} has no active key")
            self._entries, self._active = entries, active
            self._mtime = (self.directory / MANIFEST).stat().st_mtime
            self._last_check = self._clock()

    def _maybe_reload(self) -> None:
        now = self._clock()
        if now - self._last_check < self._reload_interval:
            return
        self._last_check = now
        try:
            mtime = (self.directory / MANIFEST).stat().st_mtime
        except FileNotFoundError:
            return
        if mtime != self._mtime:
            self._load()

    # ------------------------------------------------------------------ lifecycle
    def rotate(self) -> KeyEntry:
        """Create a new active key and retire the current one."""
        with self._lock, self._file_lock():
            now = self._clock()
            entries = [self._entry_from_json(raw) for raw in self._read_manifest()]
            manager = KeyManager(Ed25519PrivateKey.generate())
            manager.save_pem(self.directory / f"{manager.kid}.pem")
            for entry in entries:
                if entry.status == "active":
                    entry.status, entry.retired_at = "retired", now
            new = KeyEntry(manager.kid, "active", now, None, manager.public_jwk(), manager)
            entries.append(new)
            self._write_manifest(entries)
        self._load()
        return new

    def prune(self) -> list[str]:
        """Delete private keys whose grace period is over. Returns the pruned kids."""
        pruned: list[str] = []
        with self._lock, self._file_lock():
            now = self._clock()
            entries = [self._entry_from_json(raw) for raw in self._read_manifest()]
            for entry in entries:
                if (
                    entry.status == "retired"
                    and entry.retired_at is not None
                    and now >= entry.retired_at + self.grace_seconds
                ):
                    (self.directory / f"{entry.kid}.pem").unlink(missing_ok=True)
                    entry.status = "pruned"
                    pruned.append(entry.kid)
            if pruned:
                self._write_manifest(entries)
        if pruned:
            self._load()
        return pruned

    @staticmethod
    def _entry_from_json(raw: dict[str, Any]) -> KeyEntry:
        return KeyEntry(
            kid=str(raw["kid"]),
            status=raw["status"],
            created_at=float(raw["created_at"]),
            retired_at=raw.get("retired_at"),
            public_jwk=dict(raw["public_jwk"]),
        )

    def entries(self) -> list[KeyEntry]:
        self._maybe_reload()
        return sorted(self._entries.values(), key=lambda e: e.created_at)

    # ------------------------------------------------------------------ SigningKeys
    @property
    def _current(self) -> KeyManager:
        self._maybe_reload()
        if (
            self._active is None or self._active.manager is None
        ):  # pragma: no cover - guarded by _load
            raise ConfigurationError("key ring has no active key")
        return self._active.manager

    @property
    def kid(self) -> str:
        return self._current.kid

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._current.private_key

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._current.public_key

    def sign(self, data: bytes) -> bytes:
        return self._current.sign(data)

    def _accepts_tokens(self, entry: KeyEntry) -> bool:
        if entry.status == "active":
            return True
        return (
            entry.status == "retired"
            and entry.retired_at is not None
            and self._clock() < entry.retired_at + self.grace_seconds
        )

    def verification_key(self, kid: str) -> Ed25519PublicKey | None:
        self._maybe_reload()
        entry = self._entries.get(kid)
        if entry is None and kid not in self._entries:
            self._last_check = -1e18  # unknown kid: maybe another process just rotated
            self._maybe_reload()
            entry = self._entries.get(kid)
        if entry is None or entry.manager is None or not self._accepts_tokens(entry):
            return None
        return entry.manager.public_key

    def any_public_key(self, kid: str) -> Ed25519PublicKey | None:
        self._maybe_reload()
        entry = self._entries.get(kid)
        return public_key_from_jwk(entry.public_jwk) if entry else None

    def jwks(self) -> dict[str, Any]:
        self._maybe_reload()
        return {
            "keys": [e.public_jwk for e in self.entries() if e.manager and self._accepts_tokens(e)]
        }
