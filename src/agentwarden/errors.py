"""Exception hierarchy for AgentWarden.

Every error raised on purpose by the library derives from :class:`AgentWardenError`. The API
layer maps each subclass to one HTTP status code, so callers can rely on stable error semantics.
"""

from __future__ import annotations


class AgentWardenError(Exception):
    """Base class for all AgentWarden errors."""


class ConfigurationError(AgentWardenError):
    """The service is misconfigured (bad YAML, missing key file, invalid settings)."""


class AuthenticationError(AgentWardenError):
    """A credential is missing, malformed, expired, revoked or otherwise invalid."""


class PermissionDeniedError(AgentWardenError):
    """The caller is authenticated but not allowed to perform a management operation."""


class NotFoundError(AgentWardenError):
    """A referenced object (agent, user, tool, approval) does not exist."""


class InvalidRequestError(AgentWardenError):
    """The request is well-formed but semantically invalid."""


class PolicyError(ConfigurationError):
    """A policy document failed validation."""


class DelegationError(InvalidRequestError):
    """A token delegation request would escalate privilege or exceed limits."""


class ApprovalError(InvalidRequestError):
    """An approval operation is not allowed (wrong state, self-approval, expired...)."""
