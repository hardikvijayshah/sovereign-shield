"""Application-layer authorization for authenticated Sovereign Shield APIs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class ApiAction(str, Enum):
    """Operations whose authorization remains enforced beyond API Gateway JWT checks."""

    START_SCAN = "start_scan"
    CANCEL_SCAN = "cancel_scan"
    VIEW_SCAN = "view_scan"
    VIEW_FINDINGS = "view_findings"
    VIEW_REPORT = "view_report"
    VIEW_SCHEDULES = "view_schedules"
    VIEW_CONFIGURATION = "view_configuration"
    MANAGE_SCHEDULE = "manage_schedule"
    VIEW_AUDIT_LOG = "view_audit_log"
    VIEW_ACCOUNTS = "view_accounts"
    MANAGE_ACCOUNTS = "manage_accounts"


class AuthorizationError(PermissionError):
    """Raised when an authenticated caller lacks the required product role."""


@dataclass(frozen=True)
class RequestPrincipal:
    """Minimal identity extracted from a verified JWT claim set."""

    subject: str
    groups: frozenset[str]


_ADMINISTRATOR_GROUP = "SovereignShieldAdministrators"
_AUDITOR_GROUP = "SovereignShieldAuditors"
_AUDITOR_ACTIONS = {
    ApiAction.VIEW_SCAN,
    ApiAction.VIEW_FINDINGS,
    ApiAction.VIEW_REPORT,
    ApiAction.VIEW_SCHEDULES,
    ApiAction.VIEW_CONFIGURATION,
    ApiAction.VIEW_ACCOUNTS,
}
_ADMINISTRATOR_ACTIONS = _AUDITOR_ACTIONS | {
    ApiAction.START_SCAN,
    ApiAction.CANCEL_SCAN,
    ApiAction.MANAGE_SCHEDULE,
    ApiAction.VIEW_AUDIT_LOG,
    ApiAction.MANAGE_ACCOUNTS,
}


def roles_for(principal: RequestPrincipal) -> list[str]:
    """Return the product roles held by a principal, for display only."""

    roles = []
    if _ADMINISTRATOR_GROUP in principal.groups:
        roles.append("administrator")
    if _AUDITOR_GROUP in principal.groups:
        roles.append("auditor")
    return roles


def allowed_actions(principal: RequestPrincipal) -> list[str]:
    """Return the actions a principal may perform, so a console can hide others.

    The API still enforces every action; this list only drives presentation.
    """

    actions: set[ApiAction] = set()
    if not principal.subject:
        return []
    if _ADMINISTRATOR_GROUP in principal.groups:
        actions |= _ADMINISTRATOR_ACTIONS
    if _AUDITOR_GROUP in principal.groups:
        actions |= _AUDITOR_ACTIONS
    return sorted(action.value for action in actions)


def authorize(principal: RequestPrincipal, action: ApiAction) -> None:
    """Enforce the documented administrator/auditor permissions."""

    if not principal.subject:
        raise AuthorizationError("An authenticated user is required.")
    if _ADMINISTRATOR_GROUP in principal.groups and action in _ADMINISTRATOR_ACTIONS:
        return
    if _AUDITOR_GROUP in principal.groups and action in _AUDITOR_ACTIONS:
        return
    raise AuthorizationError("The authenticated user is not authorized for this operation.")


def principal_from_claims(claims: dict[str, object]) -> RequestPrincipal:
    """Normalize the Cognito group claim without trusting caller-provided fields."""

    raw_groups = claims.get("cognito:groups", [])
    if isinstance(raw_groups, str):
        # API Gateway HTTP API JWT authorizers flatten array claims to "[a b]".
        groups = re.split(r"[\s,]+", raw_groups.strip().strip("[]"))
    elif isinstance(raw_groups, list):
        groups = [str(group).strip() for group in raw_groups]
    else:
        groups = []
    return RequestPrincipal(
        subject=str(claims.get("sub", "")),
        groups=frozenset(group for group in groups if group),
    )
