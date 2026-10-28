"""Tests for AWS Organizations onboarding: eligibility, registry, resolver, and sync."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sovereign_shield.services.accounts import (
    AccountDirectory,
    AccountStatus,
    DynamoDBAccountRegistry,
    ExclusionReason,
    InMemoryAccountRegistry,
    MemberAccount,
    OnboardingSync,
    OrganizationSettings,
    account_response,
    exclusion_for,
)

CENTRAL = "111111111111"
A, B, C, D, E = "222222222222", "333333333333", "444444444444", "555555555555", "666666666666"


def _settings(**changes) -> OrganizationSettings:
    values = {
        "mode": "AWS_ORGANIZATIONS",
        "deployment_account_id": CENTRAL,
        "organization_id": "o-abcdef1234",
        "target_ou_ids": ("ou-root-workloads",),
        "stack_set_name": "ss-member-role",
        "max_accounts_per_scan": 3,
    }
    values.update(changes)
    return OrganizationSettings(**values)


class _Paginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages(kwargs)


class _Organizations:
    """OU tree: ou-root-workloads -> [A, B (suspended)] + child ou-child -> [C, D, E]."""

    def __init__(self, tags=None):
        self.tags = tags or {}

    def get_paginator(self, name):
        if name == "list_accounts_for_parent":
            tree = {
                "ou-root-workloads": [{"Id": A, "Name": "payments", "Status": "ACTIVE"},
                                      {"Id": B, "Name": "legacy", "Status": "SUSPENDED"}],
                "ou-child": [{"Id": C, "Name": "analytics", "Status": "ACTIVE"},
                             {"Id": D, "Name": "sandbox", "Status": "ACTIVE"},
                             {"Id": E, "Name": "new", "Status": "ACTIVE"}],
            }
            return _Paginator(lambda kw: [{"Accounts": tree.get(kw["ParentId"], [])}])
        if name == "list_organizational_units_for_parent":
            children = {"ou-root-workloads": [{"Id": "ou-child"}]}
            return _Paginator(lambda kw: [{"OrganizationalUnits": children.get(kw["ParentId"], [])}])
        if name == "list_tags_for_resource":
            return _Paginator(lambda kw: [{"Tags": [{"Key": k, "Value": v} for k, v in self.tags.get(
                kw["ResourceId"], {}).items()]}])
        raise AssertionError(name)


class _CloudFormation:
    def __init__(self, instances):
        self.instances = instances
        self.calls = []

    def get_paginator(self, name):
        assert name == "list_stack_instances"

        def pages(kwargs):
            self.calls.append(kwargs)
            return [{"Summaries": self.instances}]

        return _Paginator(pages)


def _instance(account, detailed="SUCCEEDED", reason=""):
    return {"Account": account, "Status": "CURRENT", "StatusReason": reason,
            "StackInstanceStatus": {"DetailedStatus": detailed}}


def _sync(settings=None, registry=None, tags=None, instances=None, unreachable=()):
    registry = registry or InMemoryAccountRegistry()
    probes = []

    def probe(account_id):
        probes.append(account_id)
        if account_id in unreachable:
            error = Exception("denied")
            error.response = {"Error": {"Code": "AccessDenied"}}
            raise error

    sync = OnboardingSync(
        settings=settings or _settings(),
        registry=registry,
        organizations=_Organizations(tags),
        cloudformation=_CloudFormation(instances if instances is not None else [
            _instance(A), _instance(C), _instance(D, "FAILED", "Role already exists"),
        ]),
        probe_role=probe,
        now=lambda: datetime(2026, 10, 26, tzinfo=timezone.utc),
    )
    return sync, registry, probes


def test_sync_walks_nested_ous_and_reports_each_onboarding_state():
    sync, registry, probes = _sync(unreachable={C})

    summary = sync.run()
    status = {account.account_id: account.status for account in registry.list_all()}

    assert status == {
        A: AccountStatus.ONBOARDED,
        B: AccountStatus.SUSPENDED,
        C: AccountStatus.ROLE_UNREACHABLE,
        D: AccountStatus.FAILED,
        E: AccountStatus.PENDING,
    }
    assert set(probes) == {A, C}
    assert summary.accounts == 5
    assert registry.get(C).organizational_unit_id == "ou-child"
    assert "Role already exists" in registry.get(D).detail


def test_sync_uses_the_configured_stack_set_caller():
    sync, _, _ = _sync(settings=_settings(stack_set_call_as="DELEGATED_ADMIN"))
    sync.run()

    assert sync._cloudformation.calls[0] == {"StackSetName": "ss-member-role", "CallAs": "DELEGATED_ADMIN"}


def test_denylist_and_exclusion_tag_override_everything_and_are_never_probed():
    sync, registry, probes = _sync(
        settings=_settings(denylist=frozenset({A})), tags={C: {"sovereign-shield:exclude": "true"}}
    )
    sync.run()

    assert registry.get(A).exclusion_reason == ExclusionReason.DENYLIST
    assert registry.get(C).exclusion_reason == ExclusionReason.EXCLUSION_TAG
    assert registry.get(A).status == AccountStatus.EXCLUDED
    assert A not in probes and C not in probes


def test_allowlist_limits_scope_but_never_excludes_the_deployment_account():
    settings = _settings(allowlist=frozenset({A}))

    assert exclusion_for(settings, C, {}, False) == ExclusionReason.NOT_ALLOWLISTED
    assert exclusion_for(settings, A, {}, False) is None
    assert exclusion_for(settings, CENTRAL, {}, False) is None


def test_administrator_exclusion_survives_sync_and_can_be_reversed():
    sync, registry, _ = _sync()
    sync.run()
    directory = AccountDirectory(settings=_settings(), registry=registry)

    excluded = directory.set_administrator_exclusion(A, excluded=True, note="Acquired company, pending review")
    sync.run()

    assert excluded.status == AccountStatus.EXCLUDED
    assert registry.get(A).exclusion_reason == ExclusionReason.ADMINISTRATOR
    assert registry.get(A).administrator_exclusion_note == "Acquired company, pending review"

    reincluded = directory.set_administrator_exclusion(A, excluded=False, note="")
    assert reincluded.status == AccountStatus.PENDING
    sync.run()
    assert registry.get(A).status == AccountStatus.ONBOARDED


def test_administrators_cannot_reinclude_denylisted_or_tagged_accounts():
    sync, registry, _ = _sync(settings=_settings(denylist=frozenset({A})))
    sync.run()
    directory = AccountDirectory(settings=_settings(denylist=frozenset({A})), registry=registry)

    with pytest.raises(PermissionError):
        directory.set_administrator_exclusion(A, excluded=False, note="")
    with pytest.raises(ValueError):
        directory.set_administrator_exclusion(CENTRAL, excluded=True, note="")


def test_accounts_that_leave_the_selected_ous_become_out_of_scope():
    registry = InMemoryAccountRegistry()
    registry.save(MemberAccount(account_id="999999999999", status=AccountStatus.ONBOARDED))
    sync, _, _ = _sync(registry=registry)

    summary = sync.run()

    assert registry.get("999999999999").status == AccountStatus.OUT_OF_SCOPE
    assert summary.counts["out_of_scope"] == 1


def test_resolver_scans_only_onboarded_accounts_and_enforces_the_account_limit():
    sync, registry, _ = _sync(instances=[_instance(A), _instance(C), _instance(D), _instance(E)])
    sync.run()
    directory = AccountDirectory(settings=_settings(), registry=registry)

    assert directory.resolve_targets([A, C]) == [A, C]
    with pytest.raises(ValueError, match="not onboarded"):
        directory.resolve_targets([A, B])
    with pytest.raises(ValueError, match="at most 3"):
        directory.resolve_targets([])  # central + A, C, D, E are all scannable


def test_resolver_defaults_to_every_scannable_account_within_the_limit():
    sync, registry, _ = _sync(settings=_settings(max_accounts_per_scan=10))
    sync.run()
    directory = AccountDirectory(settings=_settings(max_accounts_per_scan=10), registry=registry)

    assert directory.resolve_targets([]) == [CENTRAL, A, C]  # D failed, E pending, B suspended


def test_single_account_mode_scans_only_the_deployment_account():
    settings = OrganizationSettings(deployment_account_id=CENTRAL)
    directory = AccountDirectory(settings=settings, registry=None)

    assert directory.resolve_targets([]) == [CENTRAL]
    assert [account.status for account in directory.list_accounts()] == [AccountStatus.DEPLOYMENT_ACCOUNT]
    with pytest.raises(ValueError, match="SINGLE_ACCOUNT"):
        directory.resolve_targets([A])
    assert directory.is_scannable(A) is False


def test_single_account_sync_records_only_the_deployment_account():
    settings = OrganizationSettings(deployment_account_id=CENTRAL)
    registry = InMemoryAccountRegistry()
    OnboardingSync(settings=settings, registry=registry, organizations=None, cloudformation=None,
                   probe_role=lambda _: None).run()

    assert [account.account_id for account in registry.list_all()] == [CENTRAL]


def test_settings_are_read_from_the_stack_environment():
    settings = OrganizationSettings.from_environment({
        "ORGANIZATION_MODE": "AWS_ORGANIZATIONS", "TARGET_OU_IDS": "ou-a-11111111, r-ab12",
        "ACCOUNT_DENYLIST": "222222222222,", "MAX_ACCOUNTS_PER_SCAN": "40",
    })

    assert settings.organizations
    assert settings.target_ou_ids == ("ou-a-11111111", "r-ab12")
    assert settings.denylist == frozenset({"222222222222"})
    assert settings.max_accounts_per_scan == 40


def test_dynamodb_registry_round_trips_records():
    class Table:
        def __init__(self):
            self.items = {}

        def put_item(self, *, Item):
            self.items[(Item["pk"], Item["sk"])] = Item

        def get_item(self, *, Key):
            item = self.items.get((Key["pk"], Key["sk"]))
            return {"Item": item} if item else {}

    table = Table()
    registry = DynamoDBAccountRegistry(runs_table=table)
    registry.save(MemberAccount(account_id=A, status=AccountStatus.ONBOARDED, name="payments"))

    assert table.items[(f"ACCOUNT#{A}", "ACCOUNT")]["entity_type"] == "member_account"
    assert registry.get(A).name == "payments"
    assert account_response(registry.get(A))["scannable"] is True
