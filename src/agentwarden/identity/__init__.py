"""Agent identity: keys, scopes, delegated tokens, registry and revocation."""

from agentwarden.identity.keyring import KeyRing
from agentwarden.identity.keys import KeyManager, SigningKeys
from agentwarden.identity.registry import AgentRegistry, RevocationList
from agentwarden.identity.scopes import attenuate, scope_covers, validate_scope
from agentwarden.identity.tokens import TokenClaims, TokenService

__all__ = [
    "AgentRegistry",
    "KeyManager",
    "KeyRing",
    "RevocationList",
    "SigningKeys",
    "TokenClaims",
    "TokenService",
    "attenuate",
    "scope_covers",
    "validate_scope",
]
