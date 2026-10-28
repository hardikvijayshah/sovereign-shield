"""Lambda entry point for the AWS Organizations onboarding sync.

Runs on a schedule and on demand (``POST /v1/accounts/sync``). It reads
Organizations membership under the selected OUs, the member-role StackSet's
instance status, and account tags; probes each deployed member role with
``sts:GetCallerIdentity``; and records one onboarding status per account. It
never changes member accounts.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import boto3

from sovereign_shield.services.accounts import DynamoDBAccountRegistry, OnboardingSync, OrganizationSettings
from sovereign_shield.tools import aws_scanner

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    settings = OrganizationSettings.from_environment(dict(os.environ))
    sync = OnboardingSync(
        settings=settings,
        registry=DynamoDBAccountRegistry(
            runs_table=boto3.resource("dynamodb").Table(os.environ["SCAN_RUNS_TABLE"])
        ),
        organizations=boto3.client("organizations") if settings.organizations else None,
        cloudformation=boto3.client("cloudformation") if settings.organizations else None,
        probe_role=probe_member_role,
    )
    summary = sync.run().as_dict()
    logger.info("Onboarding sync complete: %s", summary)
    return summary


def probe_member_role(account_id: str) -> None:
    """Prove the member role is assumable with this installation's trust (fresh credentials)."""

    aws_scanner._assumed_credentials.pop(account_id, None)
    credentials = aws_scanner.member_role_credentials(account_id)
    boto3.client(
        "sts",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    ).get_caller_identity()
