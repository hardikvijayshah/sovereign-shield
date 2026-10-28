"""AWS Organizations onboarding: member-account registry, eligibility, and sync (plan.md section 7.2).

In AWS Organizations mode the central stack deploys a read-only member role
into the selected OUs through a service-managed StackSet. This module keeps a
per-account onboarding record and decides which accounts a scan may target:

- **Eligibility precedence:** denylist > exclusion tag > allowlist >
  administrator exclusion > onboarding state. Only ``onboarded`` member
  accounts and the deployment account itself are scannable.
- **Sync** reconciles Organizations membership (recursive under the selected
  OUs), StackSet instance status, account tags, and a live role-assumption
  probe, then saves one record per account. It never changes member accounts.

In single-account mode only the deployment account exists.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

ORGANIZATIONS_MODE = "AWS_ORGANIZATIONS"
SINGLE_ACCOUNT_MODE = "SINGLE_ACCOUNT"


class AccountStatus(str, Enum):
    DEPLOYMENT_ACCOUNT = "deployment_account"
    ONBOARDED = "onboarded"
    PENDING = "pending"
    FAILED = "failed"
    ROLE_UNREACHABLE = "role_unreachable"
    EXCLUDED = "excluded"
    SUSPENDED = "suspended"
    OUT_OF_SCOPE = "out_of_scope"


SCANNABLE_STATUSES = frozenset({AccountStatus.DEPLOYMENT_ACCOUNT, AccountStatus.ONBOARDED})


class ExclusionReason(str, Enum):
    DENYLIST = "denylist"
    EXCLUSION_TAG = "exclusion_tag"
    NOT_ALLOWLISTED = "not_allowlisted"
    ADMINISTRATOR = "administrator"


class MemberAccount(BaseModel):
    """Onboarding record for one account. Holds identifiers only, never scan evidence."""

    account_id: str = Field(pattern=r"^\d{12}$")
    name: str = ""
    organizational_unit_id: str = ""
    status: AccountStatus
    exclusion_reason: ExclusionReason | None = None
    administrator_excluded: bool = False
    administrator_exclusion_note: str = Field(default="", max_length=256)
    stack_instance_status: str = ""
    detail: str = Field(default="", max_length=256)
    last_synced_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def scannable(self) -> bool:
        return self.status in SCANNABLE_STATUSES


@dataclass(frozen=True)
class OrganizationSettings:
    """Deployment-time organization configuration (CloudFormation parameters)."""

    mode: str = SINGLE_ACCOUNT_MODE
    deployment_account_id: str = ""
    organization_id: str = ""
    target_ou_ids: tuple[str, ...] = ()
    allowlist: frozenset[str] = field(default_factory=frozenset)
    denylist: frozenset[str] = field(default_factory=frozenset)
    exclusion_tag_key: str = "sovereign-shield:exclude"
    max_accounts_per_scan: int = 25
    stack_set_name: str = ""
    stack_set_call_as: str = "SELF"
    member_role_name: str = "SovereignShieldScanRole"

    @property
    def organizations(self) -> bool:
        return self.mode == ORGANIZATIONS_MODE

    @classmethod
    def from_environment(cls, environment: dict[str, str]) -> OrganizationSettings:
        def account_set(name: str) -> frozenset[str]:
            return frozenset(value.strip() for value in environment.get(name, "").split(",") if value.strip())

        return cls(
            mode=environment.get("ORGANIZATION_MODE", SINGLE_ACCOUNT_MODE),
            deployment_account_id=environment.get("DEPLOYMENT_ACCOUNT_ID", ""),
            organization_id=environment.get("ORGANIZATION_ID", ""),
            target_ou_ids=tuple(
                value.strip() for value in environment.get("TARGET_OU_IDS", "").split(",") if value.strip()
            ),
            allowlist=account_set("ACCOUNT_ALLOWLIST"),
            denylist=account_set("ACCOUNT_DENYLIST"),
            exclusion_tag_key=environment.get("EXCLUSION_TAG_KEY", "sovereign-shield:exclude"),
            max_accounts_per_scan=int(environment.get("MAX_ACCOUNTS_PER_SCAN", "25")),
            stack_set_name=environment.get("STACK_SET_NAME", ""),
            stack_set_call_as=environment.get("STACK_SET_CALL_AS", "SELF"),
            member_role_name=environment.get("SCAN_ROLE_NAME", "SovereignShieldScanRole"),
        )


def exclusion_for(
    settings: OrganizationSettings, account_id: str, tags: dict[str, str], administrator_excluded: bool
) -> ExclusionReason | None:
    """Apply the documented precedence. Administrators cannot override the denylist or tags."""

    if account_id in settings.denylist:
        return ExclusionReason.DENYLIST
    if tags.get(settings.exclusion_tag_key, "").strip().lower() in {"true", "yes", "1"}:
        return ExclusionReason.EXCLUSION_TAG
    if settings.allowlist and account_id not in settings.allowlist and account_id != settings.deployment_account_id:
        return ExclusionReason.NOT_ALLOWLISTED
    if administrator_excluded:
        return ExclusionReason.ADMINISTRATOR
    return None


class AccountRegistry(Protocol):
    def get(self, account_id: str) -> MemberAccount | None: ...

    def save(self, account: MemberAccount) -> None: ...

    def list_all(self) -> list[MemberAccount]: ...


class InMemoryAccountRegistry:
    def __init__(self) -> None:
        self._accounts: dict[str, MemberAccount] = {}

    def get(self, account_id: str) -> MemberAccount | None:
        account = self._accounts.get(account_id)
        return account.model_copy(deep=True) if account else None

    def save(self, account: MemberAccount) -> None:
        self._accounts[account.account_id] = account.model_copy(deep=True)

    def list_all(self) -> list[MemberAccount]:
        return sorted((a.model_copy(deep=True) for a in self._accounts.values()), key=lambda a: a.account_id)


class DynamoDBAccountRegistry:
    """Runs-table adapter: ``pk=ACCOUNT#<id>``, ``sk=ACCOUNT``, listed through the sparse entity index."""

    _ENTITY = "member_account"

    def __init__(self, *, runs_table: Any) -> None:
        self._table = runs_table

    def get(self, account_id: str) -> MemberAccount | None:
        item = self._table.get_item(Key={"pk": f"ACCOUNT#{account_id}", "sk": "ACCOUNT"}).get("Item")
        return MemberAccount.model_validate(item) if item else None

    def save(self, account: MemberAccount) -> None:
        self._table.put_item(
            Item={"pk": f"ACCOUNT#{account.account_id}", "sk": "ACCOUNT", "entity_type": self._ENTITY,
                  **account.model_dump(mode="json")}
        )

    def list_all(self) -> list[MemberAccount]:
        from sovereign_shield.services.scan_lifecycle import query_entities

        accounts: list[MemberAccount] = []
        cursor = None
        while True:
            items, cursor = query_entities(self._table, self._ENTITY, limit=100, cursor=cursor)
            accounts.extend(MemberAccount.model_validate(item) for item in items)
            if not cursor:
                return sorted(accounts, key=lambda account: account.account_id)


def deployment_account_record(settings: OrganizationSettings) -> MemberAccount:
    return MemberAccount(
        account_id=settings.deployment_account_id,
        name="Deployment account",
        status=AccountStatus.DEPLOYMENT_ACCOUNT,
        detail="Scanned with the stack's own role; no member role is needed.",
    )


class AccountDirectory:
    """Read model used by the API, the scan resolver, and workers."""

    def __init__(self, *, settings: OrganizationSettings, registry: AccountRegistry | None) -> None:
        self._settings = settings
        self._registry = registry

    @property
    def settings(self) -> OrganizationSettings:
        return self._settings

    def list_accounts(self) -> list[MemberAccount]:
        # Local runs without a real deployment account ID list no deployment record.
        has_deployment_account = bool(re.fullmatch(r"\d{12}", self._settings.deployment_account_id))
        if not self._settings.organizations or self._registry is None:
            return [deployment_account_record(self._settings)] if has_deployment_account else []
        accounts = {account.account_id: account for account in self._registry.list_all()}
        if has_deployment_account:
            accounts.setdefault(self._settings.deployment_account_id, deployment_account_record(self._settings))
        return sorted(accounts.values(), key=lambda account: account.account_id)

    def is_scannable(self, account_id: str) -> bool:
        if account_id == self._settings.deployment_account_id:
            return exclusion_for(self._settings, account_id, {}, False) is None
        if not self._settings.organizations or self._registry is None:
            return False
        account = self._registry.get(account_id)
        return bool(account and account.scannable)

    def resolve_targets(self, requested: list[str]) -> list[str]:
        """Turn a request's account selection into the exact accounts to scan, or raise ValueError."""

        if not self._settings.organizations:
            if requested and requested != [self._settings.deployment_account_id]:
                raise ValueError("This deployment scans only its own account (OrganizationMode=SINGLE_ACCOUNT).")
            return [self._settings.deployment_account_id]
        if requested:
            not_scannable = [account_id for account_id in requested if not self.is_scannable(account_id)]
            if not_scannable:
                raise ValueError(
                    f"Accounts not onboarded or excluded: {', '.join(sorted(not_scannable)[:10])}."
                )
            targets = list(requested)
        else:
            targets = [account.account_id for account in self.list_accounts() if account.scannable]
        if not targets:
            raise ValueError("No onboarded accounts are available to scan.")
        if len(targets) > self._settings.max_accounts_per_scan:
            raise ValueError(
                f"A scan may target at most {self._settings.max_accounts_per_scan} accounts "
                f"(MaxAccountsPerScan); {len(targets)} were selected."
            )
        return targets

    def set_administrator_exclusion(self, account_id: str, *, excluded: bool, note: str) -> MemberAccount:
        if not self._settings.organizations or self._registry is None:
            raise ValueError("Account exclusions apply only in AWS Organizations mode.")
        if account_id == self._settings.deployment_account_id:
            raise ValueError("The deployment account cannot be excluded; use AccountDenylist instead.")
        account = self._registry.get(account_id)
        if account is None:
            raise KeyError(account_id)
        if not excluded and account.exclusion_reason in {ExclusionReason.DENYLIST, ExclusionReason.EXCLUSION_TAG}:
            raise PermissionError("Accounts excluded by the denylist or exclusion tag cannot be re-included here.")
        updated = account.model_copy(update={
            "administrator_excluded": excluded,
            "administrator_exclusion_note": note[:256] if excluded else "",
            "updated_at": datetime.now(timezone.utc),
        })
        reason = exclusion_for(self._settings, account_id, {}, excluded) or (
            account.exclusion_reason if account.exclusion_reason not in {ExclusionReason.ADMINISTRATOR, None} else None
        )
        if reason is not None:
            updated = updated.model_copy(update={"status": AccountStatus.EXCLUDED, "exclusion_reason": reason})
        elif account.status == AccountStatus.EXCLUDED:
            # Re-included: the next sync re-checks the member role; until then it is pending.
            updated = updated.model_copy(update={"status": AccountStatus.PENDING, "exclusion_reason": None,
                                                 "detail": "Re-included; awaiting the next onboarding sync."})
        self._registry.save(updated)
        return updated


@dataclass
class SyncSummary:
    counts: dict[str, int]
    accounts: int

    def as_dict(self) -> dict[str, Any]:
        return {"accounts": self.accounts, "byStatus": dict(sorted(self.counts.items()))}


class OnboardingSync:
    """Reconcile Organizations membership, StackSet instances, tags, and role reachability."""

    def __init__(
        self,
        *,
        settings: OrganizationSettings,
        registry: AccountRegistry,
        organizations: Any,
        cloudformation: Any,
        probe_role: Callable[[str], None],
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._settings = settings
        self._registry = registry
        self._organizations = organizations
        self._cloudformation = cloudformation
        self._probe_role = probe_role
        self._now = now

    def run(self) -> SyncSummary:
        if not self._settings.organizations:
            record = deployment_account_record(self._settings).model_copy(update={"last_synced_at": self._now()})
            self._registry.save(record)
            return SyncSummary(counts={record.status.value: 1}, accounts=1)

        members = self._member_accounts()
        instances = self._stack_instances()
        previous = {account.account_id: account for account in self._registry.list_all()}
        counts: dict[str, int] = {}
        seen: set[str] = set()
        for member in members:
            account_id = member["Id"]
            seen.add(account_id)
            record = self._evaluate(member, instances.get(account_id), previous.get(account_id))
            self._registry.save(record)
            counts[record.status.value] = counts.get(record.status.value, 0) + 1
        for account_id, account in previous.items():
            if account_id in seen or account_id == self._settings.deployment_account_id:
                continue
            if account.status != AccountStatus.OUT_OF_SCOPE:
                self._registry.save(account.model_copy(update={
                    "status": AccountStatus.OUT_OF_SCOPE,
                    "detail": "No longer in the selected organizational units.",
                    "last_synced_at": self._now(),
                    "updated_at": self._now(),
                }))
            counts[AccountStatus.OUT_OF_SCOPE.value] = counts.get(AccountStatus.OUT_OF_SCOPE.value, 0) + 1
        return SyncSummary(counts=counts, accounts=len(seen))

    def _evaluate(self, member: dict[str, Any], instance: dict[str, Any] | None, previous: MemberAccount | None):
        account_id = member["Id"]
        administrator_excluded = bool(previous and previous.administrator_excluded)
        base = {
            "account_id": account_id,
            "name": str(member.get("Name", ""))[:128],
            "organizational_unit_id": member.get("_ParentId", ""),
            "administrator_excluded": administrator_excluded,
            "administrator_exclusion_note": previous.administrator_exclusion_note if previous else "",
            "stack_instance_status": _instance_status(instance),
            "last_synced_at": self._now(),
            "created_at": previous.created_at if previous else self._now(),
            "updated_at": self._now(),
        }
        if account_id == self._settings.deployment_account_id:
            reason = exclusion_for(self._settings, account_id, {}, False)
            if reason is None:
                return MemberAccount(**{**base, "status": AccountStatus.DEPLOYMENT_ACCOUNT,
                                        "detail": "Scanned with the stack's own role."})
        if member.get("Status") not in {None, "ACTIVE"}:
            return MemberAccount(
                **base, status=AccountStatus.SUSPENDED, detail=f"Account status {member.get('Status')}."
            )
        reason = exclusion_for(self._settings, account_id, self._tags(account_id), administrator_excluded)
        if reason is not None:
            return MemberAccount(**base, status=AccountStatus.EXCLUDED, exclusion_reason=reason,
                                 detail=_EXCLUSION_DETAIL[reason])
        if instance is None:
            return MemberAccount(**base, status=AccountStatus.PENDING,
                                 detail="The member role has not been deployed to this account yet.")
        detailed = _instance_status(instance)
        if detailed in {"FAILED", "INOPERABLE", "CANCELLED"}:
            reason_text = str(instance.get("StatusReason") or instance.get("StackInstanceStatus", {}).get(
                "DetailedStatus", ""))
            return MemberAccount(**base, status=AccountStatus.FAILED,
                                 detail=f"Member role deployment {detailed}: {reason_text}"[:256])
        if detailed not in {"SUCCEEDED", "CURRENT"}:
            return MemberAccount(**base, status=AccountStatus.PENDING, detail=f"Member role deployment {detailed}.")
        try:
            self._probe_role(account_id)
        except Exception as exc:  # noqa: BLE001 - reachability is reported, not raised
            return MemberAccount(**base, status=AccountStatus.ROLE_UNREACHABLE,
                                 detail=f"Member role could not be assumed ({_error_code(exc)}).")
        return MemberAccount(**base, status=AccountStatus.ONBOARDED, detail="Member role verified.")

    def _member_accounts(self) -> list[dict[str, Any]]:
        accounts: dict[str, dict[str, Any]] = {}
        for ou_id in self._settings.target_ou_ids:
            for parent_id, account in self._walk(ou_id):
                accounts.setdefault(account["Id"], {**account, "_ParentId": parent_id})
        return list(accounts.values())

    def _walk(self, parent_id: str) -> Iterable[tuple[str, dict[str, Any]]]:
        for page in self._organizations.get_paginator("list_accounts_for_parent").paginate(ParentId=parent_id):
            for account in page.get("Accounts", []):
                yield parent_id, account
        for page in self._organizations.get_paginator("list_organizational_units_for_parent").paginate(
            ParentId=parent_id
        ):
            for child in page.get("OrganizationalUnits", []):
                yield from self._walk(child["Id"])

    def _stack_instances(self) -> dict[str, dict[str, Any]]:
        if not self._settings.stack_set_name:
            return {}
        instances: dict[str, dict[str, Any]] = {}
        paginator = self._cloudformation.get_paginator("list_stack_instances")
        for page in paginator.paginate(StackSetName=self._settings.stack_set_name,
                                       CallAs=self._settings.stack_set_call_as):
            for summary in page.get("Summaries", []):
                instances[summary["Account"]] = summary
        return instances

    def _tags(self, account_id: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        try:
            for page in self._organizations.get_paginator("list_tags_for_resource").paginate(ResourceId=account_id):
                tags.update({tag["Key"]: tag["Value"] for tag in page.get("Tags", [])})
        except Exception as exc:  # noqa: BLE001 - missing tag access must not hide the account
            logger.warning("Could not read tags for %s: %s", account_id, _error_code(exc))
        return tags


_EXCLUSION_DETAIL = {
    ExclusionReason.DENYLIST: "Listed in AccountDenylist.",
    ExclusionReason.EXCLUSION_TAG: "Excluded by the account's exclusion tag.",
    ExclusionReason.NOT_ALLOWLISTED: "Not in AccountAllowlist.",
    ExclusionReason.ADMINISTRATOR: "Excluded by an administrator.",
}


def account_response(account: MemberAccount) -> dict[str, Any]:
    return {
        "accountId": account.account_id,
        "name": account.name,
        "organizationalUnitId": account.organizational_unit_id,
        "status": account.status.value,
        "scannable": account.scannable,
        "exclusionReason": account.exclusion_reason.value if account.exclusion_reason else None,
        "administratorExcluded": account.administrator_excluded,
        "administratorExclusionNote": account.administrator_exclusion_note,
        "stackInstanceStatus": account.stack_instance_status,
        "detail": account.detail,
        "lastSyncedAt": account.last_synced_at.isoformat() if account.last_synced_at else None,
    }


def _instance_status(instance: dict[str, Any] | None) -> str:
    if not instance:
        return ""
    detailed = (instance.get("StackInstanceStatus") or {}).get("DetailedStatus")
    return str(detailed or instance.get("Status", ""))


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", {})
    if isinstance(response, dict) and response.get("Error", {}).get("Code"):
        return str(response["Error"]["Code"])
    return type(exc).__name__
