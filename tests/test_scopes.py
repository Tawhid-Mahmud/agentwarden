import pytest

from agentwarden.errors import InvalidRequestError
from agentwarden.identity.scopes import (
    attenuate,
    covered_by_any,
    is_wildcard,
    scope_covers,
    validate_scope,
)


@pytest.mark.parametrize(
    ("pattern", "scope", "expected"),
    [
        ("email:send", "email:send", True),
        ("email:send", "email:read", False),
        ("email:*", "email:send", True),
        ("files:*", "files:read:reports", True),
        ("files:*:reports", "files:read:reports", True),
        ("files:*:reports", "files:read:secrets", False),
        ("files:read", "files:read:reports", False),
        ("files:*", "files", False),
        ("email:send", "email:send:bulk", False),
    ],
)
def test_scope_covers(pattern: str, scope: str, expected: bool) -> None:
    assert scope_covers(pattern, scope) is expected


@pytest.mark.parametrize("bad", ["", "email", "Email:send", "email:se*nd", "email: send", "*:send"])
def test_validate_scope_rejects_malformed(bad: str) -> None:
    with pytest.raises(InvalidRequestError):
        validate_scope(bad)


def test_wildcards_cannot_be_requested() -> None:
    assert validate_scope("files:*") == "files:*"
    with pytest.raises(InvalidRequestError, match="cannot be requested"):
        validate_scope("files:*", allow_wildcards=False)
    assert is_wildcard("files:*") and not is_wildcard("files:read")


def test_attenuate_is_intersection_of_all_ceilings() -> None:
    granted, denied = attenuate(
        ["email:send", "email:read", "payments:write", "email:send"],
        ["email:*", "payments:write"],  # user entitlements
        ["email:read", "email:send"],  # agent ceiling
    )
    assert granted == ["email:send", "email:read"]
    assert denied == ["payments:write"]


def test_covered_by_any() -> None:
    assert covered_by_any("docs:read", ["email:*", "docs:read"])
    assert not covered_by_any("docs:write", ["email:*", "docs:read"])
