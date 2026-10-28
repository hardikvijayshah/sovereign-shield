"""Tests for API role authorization independent of API Gateway."""

from __future__ import annotations

import pytest

from sovereign_shield.services.authorization import (
    ApiAction,
    AuthorizationError,
    RequestPrincipal,
    authorize,
    principal_from_claims,
)


def test_administrator_can_execute_mutating_and_read_operations():
    principal = RequestPrincipal("admin-123", frozenset({"SovereignShieldAdministrators"}))

    authorize(principal, ApiAction.START_SCAN)
    authorize(principal, ApiAction.MANAGE_SCHEDULE)
    authorize(principal, ApiAction.VIEW_REPORT)


def test_auditor_can_read_but_cannot_mutate():
    principal = principal_from_claims(
        {"sub": "auditor-123", "cognito:groups": "SovereignShieldAuditors"}
    )

    authorize(principal, ApiAction.VIEW_FINDINGS)
    with pytest.raises(AuthorizationError):
        authorize(principal, ApiAction.START_SCAN)


def test_missing_identity_or_unrecognized_group_is_not_authorized():
    with pytest.raises(AuthorizationError):
        authorize(RequestPrincipal("", frozenset({"SovereignShieldAdministrators"})), ApiAction.VIEW_SCAN)
    with pytest.raises(AuthorizationError):
        authorize(RequestPrincipal("user-123", frozenset({"other-group"})), ApiAction.VIEW_SCAN)


def test_http_api_flattened_group_claim_is_split_into_groups():
    principal = principal_from_claims(
        {"sub": "user-123", "cognito:groups": "[SovereignShieldAuditors SovereignShieldAdministrators]"}
    )

    assert principal.groups == frozenset({"SovereignShieldAuditors", "SovereignShieldAdministrators"})
    authorize(principal, ApiAction.START_SCAN)
