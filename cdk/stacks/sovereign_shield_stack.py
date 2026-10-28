"""CDK source for the Sovereign Shield customer CloudFormation template.

One stack serves two purposes:

- **Internal development** (``cdk deploy``): code and the console bundle are
  CDK assets, and launch values are passed with ``--parameters``.
- **Customer release** (``scripts/build_release.py``): synthesized with
  ``ReleaseArtifacts`` and a bootstrapless synthesizer, so the template reads
  versioned code from the vendor artifact bucket in each region and needs no
  CDK bootstrap, source checkout, or Docker.

Customer choices are CloudFormation parameters (plan.md section 4.1). Data
removal cannot be a parameter, because CloudFormation does not accept
parameter-driven ``DeletionPolicy``; it is a choice between the production
template (retain) and the non-production template (delete, with an explicit
acknowledgement parameter). Development-only context keys:

- ``dataRemovalPolicy``: ``RETAIN`` (default) or ``DESTROY``.
- ``allowedOrigins`` / ``consoleDevOrigins``: extra CORS / sign-in callback
  origins for local console development (for example ``http://localhost:5173``).
- ``releaseVersion``: version label shown in the console (default ``development``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from aws_cdk import (
    Annotations,
    Aws,
    CfnCondition,
    CfnOutput,
    CfnParameter,
    CfnRule,
    CfnRuleAssertion,
    CustomResource,
    Duration,
    Fn,
    RemovalPolicy,
    Stack,
    Tags,
    Token,
)
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_authorizers as apigwv2_authorizers
from aws_cdk import aws_apigatewayv2_integrations as apigwv2_integrations
from aws_cdk import aws_budgets as budgets
from aws_cdk import aws_cloudformation as cloudformation
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as cloudfront_origins
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_cloudwatch_actions as cloudwatch_actions
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_assets as s3_assets
from aws_cdk import aws_scheduler as scheduler
from aws_cdk import aws_sns as sns
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as sfn_tasks
from constructs import Construct

from .member_role import SCANNER_READ_ACTIONS, member_role_template

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LAMBDA_PACKAGE = PROJECT_ROOT / "dist" / "lambda_package.zip"
CONSOLE_BUILD = PROJECT_ROOT / "console" / "dist"

ADMINISTRATORS_GROUP = "SovereignShieldAdministrators"
AUDITORS_GROUP = "SovereignShieldAuditors"
METRICS_NAMESPACE = "SovereignShield/Scans"
OPERATIONS_NAMESPACE = "SovereignShield/Operations"

# Regions in which this release is tested and its artifacts are published.
SUPPORTED_REGIONS = ("eu-central-1", "eu-west-1", "us-east-1", "us-west-2")
DATA_DELETION_ACKNOWLEDGEMENT = "DELETE_ALL_SOVEREIGN_SHIELD_DATA_WITH_THE_STACK"
ORGANIZATION_ACKNOWLEDGEMENT = "I_ACKNOWLEDGE_ORGANIZATION_WIDE_READ_ONLY_ACCESS"
_OU_LIST_PATTERN = (
    r"^$|^(r-[a-z0-9]{4,32}|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32})"
    r"(,(r-[a-z0-9]{4,32}|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32})){0,49}$"
)
_ACCOUNT_LIST_PATTERN = r"^$|^\d{12}(,\d{12}){0,499}$"

_ORIGIN_PATTERN = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?$")
_RELEASE_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_REGION_LIST_PATTERN = r"^$|^[a-z]{2}-[a-z]+-\d(,[a-z]{2}-[a-z]+-\d){0,24}$"
_EMAIL_PATTERN = r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$"
_TAG_PATTERN = r"^[\w .:/=+@-]{1,128}$"

# Lambda transient errors that are safe to retry: the invocation did not run
# the handler, so the run has not left its current lifecycle state.
_TRANSIENT_LAMBDA_ERRORS = [
    "Lambda.ServiceException",
    "Lambda.AWSLambdaException",
    "Lambda.SdkClientException",
    "Lambda.TooManyRequestsException",
]

# Read-only discovery actions, shared with every member-account role.
_SCANNER_READ_ACTIONS = SCANNER_READ_ACTIONS


@dataclass(frozen=True)
class ReleaseArtifacts:
    """Where a customer release template reads its versioned code from."""

    version: str
    bucket_prefix: str

    def __post_init__(self) -> None:
        if not _RELEASE_VERSION_PATTERN.fullmatch(self.version):
            raise ValueError("Release version must be 1-32 letters, numbers, dots, hyphens, or underscores.")
        if not re.fullmatch(r"^[a-z0-9][a-z0-9-]{2,40}$", self.bucket_prefix):
            raise ValueError("Artifact bucket prefix must be 3-41 lowercase letters, numbers, or hyphens.")

    def key(self, name: str) -> str:
        return f"releases/{self.version}/{name}"


class SovereignShieldStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        artifacts: ReleaseArtifacts | None = None,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        dev = _DevelopmentOptions.from_context(self)
        release_version = artifacts.version if artifacts else dev.release_version
        destroy_data = dev.data_removal_policy == "DESTROY"
        data_removal_policy = RemovalPolicy.DESTROY if destroy_data else RemovalPolicy.RETAIN
        params = _Parameters(self, non_production=destroy_data)
        # Unique per installation: names account-global resources and serves as the
        # member-role external ID (external IDs prevent confused-deputy use; they are not secrets).
        stack_unique_id = Fn.select(2, Fn.split("/", Aws.STACK_ID))
        member_role_external_id = stack_unique_id
        # The StackSet itself exists only in organization mode, so it takes the literal
        # name; functions get an empty name in single-account mode.
        stack_set_name = f"sovereign-shield-member-{stack_unique_id}"
        stack_set_name_setting = Fn.condition_if(
            params.organization_mode_enabled.logical_id, stack_set_name, ""
        ).to_string()
        organization_environment = {
            "ORGANIZATION_MODE": params.organization_mode,
            "ORGANIZATION_ID": params.organization_id,
            "TARGET_OU_IDS": params.target_ou_ids,
            "ACCOUNT_ALLOWLIST": params.account_allowlist,
            "ACCOUNT_DENYLIST": params.account_denylist,
            "EXCLUSION_TAG_KEY": params.exclusion_tag_key,
            "MAX_ACCOUNTS_PER_SCAN": params.max_accounts_per_scan_text,
            "SCAN_ROLE_NAME": params.member_role_name,
            "SCAN_ROLE_EXTERNAL_ID": member_role_external_id,
            "STACK_SET_NAME": stack_set_name_setting,
            "STACK_SET_CALL_AS": params.stack_set_call_as,
        }
        # Cross-account access is limited to the member role inside the selected OUs of
        # this organization. In single-account mode OrganizationId is empty and the
        # conditions can never match, so no member role is assumable.
        organization_paths = Fn.split(",", Fn.join("", [
            "*/", Fn.join("/*,*/", Fn.split(",", params.target_ou_ids)), "/*",
        ]))
        assume_member_role = iam.PolicyStatement(
            sid="AssumeMemberScanRoleInSelectedOUs",
            actions=["sts:AssumeRole"],
            resources=[f"arn:{Aws.PARTITION}:iam::*:role/{params.member_role_name}"],
            conditions={
                "StringEquals": {"aws:ResourceOrgID": params.organization_id},
                "ForAnyValue:StringLike": {"aws:ResourceOrgPaths": organization_paths},
            },
        )

        Tags.of(self).add("Application", "SovereignShield")
        Tags.of(self).add("ReleaseVersion", release_version)
        # Parameter-valued tags apply to resources; CloudFormation stack tags must be literal.
        for tag, value in (
            ("DeploymentPrefix", params.prefix),
            ("Environment", params.environment),
            ("Owner", params.owner),
            ("CostCenter", params.cost_center),
        ):
            Tags.of(self).add(tag, value, exclude_resource_types=["aws:cdk:stack"])

        # ══════════════════════════════════════════════════════════
        #  ENCRYPTION
        # ══════════════════════════════════════════════════════════

        created_key = kms.Key(
            self, "DataKey",
            alias=f"alias/{params.prefix}-data",
            description="Encrypts Sovereign Shield findings, evidence, reports, logs, and notifications.",
            enable_key_rotation=True,
            removal_policy=data_removal_policy,
        )
        created_key.add_to_resource_policy(iam.PolicyStatement(
            sid="AllowCloudWatchLogsEncryption",
            principals=[iam.ServicePrincipal(f"logs.{Aws.REGION}.amazonaws.com")],
            actions=["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"],
            resources=["*"],
            conditions={
                "ArnLike": {
                    "kms:EncryptionContext:aws:logs:arn": f"arn:{Aws.PARTITION}:logs:{Aws.REGION}:{Aws.ACCOUNT_ID}:*"
                }
            },
        ))
        created_key.add_to_resource_policy(iam.PolicyStatement(
            sid="AllowCloudWatchAlarmNotifications",
            principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
            actions=["kms:Decrypt", "kms:GenerateDataKey*"],
            resources=["*"],
            conditions={"StringEquals": {"aws:SourceAccount": Aws.ACCOUNT_ID}},
        ))
        # The key and its alias exist only when the customer did not supply a key.
        _set_condition(created_key, params.create_key)
        _set_condition(created_key.node.find_child("Alias"), params.create_key)
        data_key_arn = Fn.condition_if(
            params.create_key.logical_id, created_key.key_arn, params.existing_key_arn
        ).to_string()
        data_key = kms.Key.from_key_arn(self, "DataKeyReference", data_key_arn)

        # ══════════════════════════════════════════════════════════
        #  CUSTOMER-OWNED STORAGE
        # ══════════════════════════════════════════════════════════

        # Versioned tables implementing docs/DATA_PERSISTENCE_CONTRACT.md.
        runs_table = self._table("ScanRunsTableV1", data_key, data_removal_policy, ttl=True)
        # Sparse newest-first listing index: only scan runs and schedules carry
        # both attributes, so evidence and coverage-gap records never enter it.
        runs_table.add_global_secondary_index(
            index_name="by-entity-created",
            partition_key=dynamodb.Attribute(name="entity_type", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="created_at", type=dynamodb.AttributeType.STRING),
            projection_type=dynamodb.ProjectionType.ALL,
        )
        audit_table = self._table("AuditTableV1", data_key, data_removal_policy, ttl=False)
        findings_table = self._table("FindingsTableV1", data_key, data_removal_policy, ttl=True)

        reports_bucket = s3.Bucket(
            self, "ReportsBucketV1",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=data_key,
            bucket_key_enabled=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            enforce_ssl=True,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ReportRetention",
                    prefix="reports/",
                    expiration=Duration.days(params.report_retention_days),
                    noncurrent_version_expiration=Duration.days(30),
                ),
                s3.LifecycleRule(
                    id="TransientWorkItemResults",
                    prefix="work/",
                    expiration=Duration.days(7),
                    noncurrent_version_expiration=Duration.days(1),
                ),
                s3.LifecycleRule(id="AbortIncompleteUploads", abort_incomplete_multipart_upload_after=Duration.days(1)),
            ],
            removal_policy=data_removal_policy,
        )

        # ══════════════════════════════════════════════════════════
        #  NOTIFICATIONS
        # ══════════════════════════════════════════════════════════

        notification_topic = sns.Topic(
            self, "NotificationTopic",
            display_name="Sovereign Shield scan alerts",
            master_key=data_key,
            enforce_ssl=True,
        )
        email_subscription = sns.Subscription(
            self, "NotificationEmailSubscription",
            topic=notification_topic,
            protocol=sns.SubscriptionProtocol.EMAIL,
            endpoint=params.notification_email,
        )
        _set_condition(email_subscription, params.has_notification_email)

        # ══════════════════════════════════════════════════════════
        #  RUNTIME CODE
        # ══════════════════════════════════════════════════════════

        if artifacts:
            artifact_bucket = s3.Bucket.from_bucket_name(
                self, "ReleaseArtifactBucket", f"{artifacts.bucket_prefix}-{Aws.REGION}"
            )
            Annotations.of(self).acknowledge_warning(
                "@aws-cdk/aws-lambda:codeFromBucketObjectVersionNotSpecified",
                "Release keys include the version and are never overwritten; each release uses new keys.",
            )
            code = lambda_.Code.from_bucket(artifact_bucket, artifacts.key("lambda_package.zip"))
            console_source: tuple[s3.IBucket, str] | None = (artifact_bucket, artifacts.key("console.zip"))
        else:
            if LAMBDA_PACKAGE.exists():
                code = lambda_.Code.from_asset(str(LAMBDA_PACKAGE))
            else:
                Annotations.of(self).add_warning(
                    "dist/lambda_package.zip was not found; the Lambda functions are packaged from src/ without "
                    "third-party dependencies and will fail at runtime. Run `python scripts/build_lambda.py` first."
                )
                code = lambda_.Code.from_asset(str(PROJECT_ROOT / "src"))
            if (CONSOLE_BUILD / "index.html").exists():
                bundle = s3_assets.Asset(self, "ConsoleBundle", path=str(CONSOLE_BUILD))
                console_source = (bundle.bucket, bundle.s3_object_key)
            else:
                Annotations.of(self).add_warning(
                    "console/dist was not found; the console is not published. "
                    "Run `npm ci && npm run build` in console/ first."
                )
                console_source = None

        # ══════════════════════════════════════════════════════════
        #  SCAN WORKER
        # ══════════════════════════════════════════════════════════

        workflow_log_group = self._log_group("WorkflowFunctionLogs", data_key, params, data_removal_policy)
        workflow_role = iam.Role(
            self, "WorkflowFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Sovereign Shield scan worker: read-only discovery plus run/finding/report writes.",
        )
        workflow_function = lambda_.Function(
            self, "WorkflowFunction",
            description="Executes accepted Sovereign Shield scan runs deterministically.",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="sovereign_shield.workflow_handler.handler",
            code=code,
            role=workflow_role,
            memory_size=1024,
            timeout=Duration.minutes(15),
            log_group=workflow_log_group,
            tracing=lambda_.Tracing.ACTIVE,
            environment={
                "SCAN_RUNS_TABLE": runs_table.table_name,
                "FINDINGS_TABLE": findings_table.table_name,
                "REPORTS_BUCKET": reports_bucket.bucket_name,
                "REPORTS_KMS_KEY_ID": data_key_arn,
                "NOTIFICATION_TOPIC_ARN": notification_topic.topic_arn,
                "DEPLOYMENT_ACCOUNT_ID": Aws.ACCOUNT_ID,
                "FINDINGS_RETENTION_DAYS": params.findings_retention_days_text,
                "SCAN_CONCURRENCY": params.scan_concurrency_text,
                "SCHEDULED_SCANS_ENABLED": params.scheduled_scans_enabled,
                **organization_environment,
            },
        )
        workflow_role.add_to_policy(assume_member_role)
        workflow_role.add_to_policy(iam.PolicyStatement(
            sid="ReadAccountRegistry",
            actions=["dynamodb:Query"],
            resources=[f"{runs_table.table_arn}/index/by-entity-created"],
        ))

        workflow_role.add_to_policy(iam.PolicyStatement(
            sid="ReadOnlyDiscovery",
            actions=_SCANNER_READ_ACTIONS,
            resources=["*"],
        ))
        workflow_role.add_to_policy(iam.PolicyStatement(
            sid="ScanRunState",
            # UpdateItem is used only for atomic per-unit progress counters.
            actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
            resources=[runs_table.table_arn],
        ))
        workflow_role.add_to_policy(iam.PolicyStatement(
            sid="FindingWrites",
            actions=["dynamodb:PutItem"],
            resources=[findings_table.table_arn],
        ))
        workflow_role.add_to_policy(iam.PolicyStatement(
            sid="ReportWrites",
            actions=["s3:PutObject"],
            resources=[reports_bucket.arn_for_objects("reports/*")],
        ))
        workflow_role.add_to_policy(iam.PolicyStatement(
            sid="WorkItemResults",
            actions=["s3:PutObject", "s3:GetObject"],
            resources=[reports_bucket.arn_for_objects("work/*")],
        ))
        workflow_role.add_to_policy(iam.PolicyStatement(
            sid="WorkItemResultLookups",
            # Without ListBucket, S3 reports a missing work-item result as 403, not 404.
            actions=["s3:ListBucket"],
            resources=[reports_bucket.bucket_arn],
            conditions={"StringLike": {"s3:prefix": ["work/*"]}},
        ))
        workflow_role.add_to_policy(iam.PolicyStatement(
            sid="ScanMetrics",
            actions=["cloudwatch:PutMetricData"],
            resources=["*"],
            conditions={"StringEquals": {"cloudwatch:namespace": METRICS_NAMESPACE}},
        ))
        notification_topic.grant_publish(workflow_role)
        workflow_log_group.grant_write(workflow_role)
        data_key.grant_encrypt_decrypt(workflow_role)
        data_key.grant(workflow_role, "kms:DescribeKey")

        # ══════════════════════════════════════════════════════════
        #  SCAN STATE MACHINE
        # ══════════════════════════════════════════════════════════

        admit_scheduled_run = sfn_tasks.LambdaInvoke(
            self, "AdmitScheduledRun",
            lambda_function=workflow_function,
            payload=sfn.TaskInput.from_object({
                "action": "admit_scheduled_run",
                "scheduleId": sfn.JsonPath.string_at("$.scheduleId"),
                "executionArn": sfn.JsonPath.string_at("$$.Execution.Id"),
            }),
            payload_response_only=True,
            retry_on_service_exceptions=False,
            task_timeout=sfn.Timeout.duration(Duration.minutes(1)),
        )
        admit_scheduled_run.add_retry(
            errors=_TRANSIENT_LAMBDA_ERRORS, interval=Duration.seconds(5), max_attempts=3, backoff_rate=2,
        )

        prepare_run = self._workflow_task(
            "PrepareRun", workflow_function,
            {"action": "prepare", "scanRunId": sfn.JsonPath.string_at("$.scanRunId")},
            result_path="$.prepared", timeout=Duration.minutes(1),
        )
        execute_work_item = self._workflow_task(
            "ExecuteWorkItem", workflow_function,
            {"action": "execute_work_item", "workItem": sfn.JsonPath.string_at("$.workItem")},
            result_path=sfn.JsonPath.DISCARD, timeout=Duration.minutes(15),
        )
        record_work_item_failure = self._workflow_task(
            "RecordWorkItemFailure", workflow_function,
            {
                "action": "record_work_item_failure",
                "workItem": sfn.JsonPath.string_at("$.workItem"),
                "error": sfn.JsonPath.string_at("$.error.Error"),
            },
            result_path=sfn.JsonPath.DISCARD, timeout=Duration.minutes(1),
            # Recording is idempotent, so handler errors are also safe to retry.
            extra_retry_errors=["States.TaskFailed"],
        )
        # A crashed or timed-out unit becomes a coverage gap; the scan continues.
        execute_work_item.add_catch(record_work_item_failure, errors=["States.ALL"], result_path="$.error")

        scan_work_items = sfn.Map(
            self, "ScanWorkItems",
            items_path=sfn.JsonPath.string_at("$.prepared.workItems"),
            item_selector={"workItem": sfn.JsonPath.string_at("$$.Map.Item.Value")},
            # Concurrency is a launch parameter, returned by PrepareRun at runtime.
            max_concurrency_path=sfn.JsonPath.string_at("$.prepared.maxConcurrency"),
            result_path=sfn.JsonPath.DISCARD,
        )
        scan_work_items.item_processor(execute_work_item)

        finalize_run = self._workflow_task(
            "FinalizeRun", workflow_function,
            {"action": "finalize", "scanRunId": sfn.JsonPath.string_at("$.scanRunId")},
            result_path="$.result", timeout=Duration.minutes(15),
        )

        mark_run_failed = sfn_tasks.LambdaInvoke(
            self, "MarkRunFailed",
            lambda_function=workflow_function,
            payload=sfn.TaskInput.from_object({
                "action": "mark_failed",
                "scanRunId": sfn.JsonPath.string_at("$.scanRunId"),
                "error": sfn.JsonPath.string_at("$.error.Error"),
            }),
            payload_response_only=True,
            result_path=sfn.JsonPath.DISCARD,
            retry_on_service_exceptions=False,
            task_timeout=sfn.Timeout.duration(Duration.minutes(1)),
        )
        mark_run_failed.add_retry(
            errors=_TRANSIENT_LAMBDA_ERRORS + ["States.TaskFailed"],
            interval=Duration.seconds(5),
            max_attempts=3,
            backoff_rate=2,
        )

        scan_failed = sfn.Fail(self, "ScanFailed", error="ScanFailed", cause="The scan run ended in the failed state.")
        admission_rejected = sfn.Fail(
            self, "ScheduledRunRejected",
            error="ScheduledRunRejected",
            cause="The schedule was missing, disabled, or did not match its stored request.",
        )
        for step in (prepare_run, scan_work_items, finalize_run):
            step.add_catch(mark_run_failed, errors=["States.ALL"], result_path="$.error")
        mark_run_failed.add_catch(scan_failed, errors=["States.ALL"], result_path=sfn.JsonPath.DISCARD)
        mark_run_failed.next(scan_failed)
        admit_scheduled_run.add_catch(admission_rejected, errors=["States.ALL"], result_path=sfn.JsonPath.DISCARD)

        scan_finished = sfn.Succeed(self, "ScanFinished")
        check_outcome = (
            sfn.Choice(self, "CheckRunOutcome")
            .when(sfn.Condition.string_equals("$.result.status", "failed"), scan_failed)
            .otherwise(scan_finished)
        )
        has_work = (
            sfn.Choice(self, "HasWorkItems")
            .when(sfn.Condition.string_equals("$.prepared.status", "cancelled"), scan_finished)
            .otherwise(scan_work_items)
        )
        prepare_run.next(has_work)
        scan_work_items.next(finalize_run)
        finalize_run.next(check_outcome)
        admit_scheduled_run.next(prepare_run)

        definition = (
            sfn.Choice(self, "IsScheduledExecution")
            .when(sfn.Condition.is_present("$.scheduleId"), admit_scheduled_run)
            .otherwise(prepare_run)
        )

        state_machine_log_group = self._log_group("StateMachineLogs", data_key, params, data_removal_policy)
        state_machine = sfn.StateMachine(
            self, "ScanStateMachine",
            state_machine_type=sfn.StateMachineType.STANDARD,
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.hours(2),
            tracing_enabled=True,
            logs=sfn.LogOptions(
                destination=state_machine_log_group,
                level=sfn.LogLevel.ERROR,
                include_execution_data=False,
            ),
        )

        # ══════════════════════════════════════════════════════════
        #  SCHEDULING
        # ══════════════════════════════════════════════════════════

        schedule_group = scheduler.CfnScheduleGroup(self, "ScheduleGroup", name=f"{params.prefix}-scans")
        schedule_group_arn = (
            f"arn:{Aws.PARTITION}:scheduler:{Aws.REGION}:{Aws.ACCOUNT_ID}:schedule-group/{schedule_group.name}"
        )
        scheduler_role = iam.Role(
            self, "SchedulerRole",
            assumed_by=iam.ServicePrincipal(
                "scheduler.amazonaws.com",
                conditions={
                    "StringEquals": {"aws:SourceAccount": Aws.ACCOUNT_ID},
                    "ArnEquals": {"aws:SourceArn": schedule_group_arn},
                },
            ),
            description="Allows the Sovereign Shield schedule group to start only the scan state machine.",
        )
        state_machine.grant_start_execution(scheduler_role)

        # ══════════════════════════════════════════════════════════
        #  AWS ORGANIZATIONS ONBOARDING
        # ══════════════════════════════════════════════════════════

        onboarding_log_group = self._log_group("OnboardingFunctionLogs", data_key, params, data_removal_policy)
        onboarding_role = iam.Role(
            self, "OnboardingFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Sovereign Shield onboarding sync: read organization membership and probe member roles.",
        )
        onboarding_function = lambda_.Function(
            self, "OnboardingFunction",
            description="Reconciles AWS Organizations membership with Sovereign Shield member-role status.",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="sovereign_shield.onboarding_handler.handler",
            code=code,
            role=onboarding_role,
            memory_size=512,
            timeout=Duration.minutes(10),
            log_group=onboarding_log_group,
            environment={
                "SCAN_RUNS_TABLE": runs_table.table_name,
                "DEPLOYMENT_ACCOUNT_ID": Aws.ACCOUNT_ID,
                **organization_environment,
            },
        )
        onboarding_log_group.grant_write(onboarding_role)
        onboarding_role.add_to_policy(assume_member_role)
        onboarding_role.add_to_policy(iam.PolicyStatement(
            sid="ReadOrganizationMembership",
            # Organizations read APIs do not support resource-level scoping for these calls.
            actions=[
                "organizations:ListAccountsForParent",
                "organizations:ListOrganizationalUnitsForParent",
                "organizations:ListTagsForResource",
                "organizations:DescribeOrganization",
            ],
            resources=["*"],
        ))
        onboarding_role.add_to_policy(iam.PolicyStatement(
            sid="ReadMemberRoleStackSet",
            actions=["cloudformation:ListStackInstances", "cloudformation:DescribeStackSet"],
            resources=[f"arn:{Aws.PARTITION}:cloudformation:{Aws.REGION}:{Aws.ACCOUNT_ID}:stackset/sovereign-shield-member-*"],
        ))
        onboarding_role.add_to_policy(iam.PolicyStatement(
            sid="WriteAccountRegistry",
            actions=["dynamodb:GetItem", "dynamodb:PutItem"],
            resources=[runs_table.table_arn],
        ))
        onboarding_role.add_to_policy(iam.PolicyStatement(
            sid="ListAccountRegistry",
            actions=["dynamodb:Query"],
            resources=[f"{runs_table.table_arn}/index/by-entity-created"],
        ))
        data_key.grant_encrypt_decrypt(onboarding_role)
        data_key.grant(onboarding_role, "kms:DescribeKey")

        # Deploys the read-only member role into every account under the selected OUs
        # (minus the denylist), including accounts that join later. Failures in
        # individual accounts are reported per account rather than failing this stack.
        member_stack_set = cloudformation.CfnStackSet(
            self, "MemberRoleStackSet",
            stack_set_name=stack_set_name,
            description="Sovereign Shield read-only member scan role",
            permission_model="SERVICE_MANAGED",
            call_as=params.stack_set_call_as,
            auto_deployment=cloudformation.CfnStackSet.AutoDeploymentProperty(
                enabled=True, retain_stacks_on_account_removal=False,
            ),
            managed_execution={"Active": True},
            capabilities=["CAPABILITY_NAMED_IAM"],
            operation_preferences=cloudformation.CfnStackSet.OperationPreferencesProperty(
                failure_tolerance_percentage=100,
                max_concurrent_percentage=25,
                region_concurrency_type="PARALLEL",
            ),
            parameters=[
                cloudformation.CfnStackSet.ParameterProperty(
                    parameter_key="CentralPrincipalArns",
                    parameter_value=Fn.join(",", [workflow_role.role_arn, onboarding_role.role_arn]),
                ),
                cloudformation.CfnStackSet.ParameterProperty(
                    parameter_key="ExternalId", parameter_value=member_role_external_id,
                ),
                cloudformation.CfnStackSet.ParameterProperty(
                    parameter_key="OrganizationId", parameter_value=params.organization_id,
                ),
                cloudformation.CfnStackSet.ParameterProperty(
                    parameter_key="RoleName", parameter_value=params.member_role_name,
                ),
            ],
            stack_instances_group=[cloudformation.CfnStackSet.StackInstancesProperty(
                regions=[Aws.REGION],
                deployment_targets=cloudformation.CfnStackSet.DeploymentTargetsProperty(
                    organizational_unit_ids=Fn.split(",", params.target_ou_ids),
                    accounts=Token.as_list(Fn.condition_if(
                        params.has_denylist.logical_id, Fn.split(",", params.account_denylist), Aws.NO_VALUE,
                    )),
                    account_filter_type=Fn.condition_if(
                        params.has_denylist.logical_id, "DIFFERENCE", Aws.NO_VALUE,
                    ).to_string(),
                ),
            )],
            template_body=self.to_json_string(member_role_template()),
        )
        member_stack_set.cfn_options.condition = params.organization_mode_enabled

        onboarding_schedule = events.CfnRule(
            self, "OnboardingSyncSchedule",
            description="Refresh Sovereign Shield member-account onboarding status.",
            schedule_expression="rate(6 hours)",
            state="ENABLED",
            targets=[events.CfnRule.TargetProperty(arn=onboarding_function.function_arn, id="OnboardingSync")],
        )
        onboarding_schedule.cfn_options.condition = params.organization_mode_enabled
        onboarding_schedule_permission = lambda_.CfnPermission(
            self, "OnboardingSyncSchedulePermission",
            action="lambda:InvokeFunction",
            function_name=onboarding_function.function_name,
            principal="events.amazonaws.com",
            source_arn=onboarding_schedule.attr_arn,
        )
        onboarding_schedule_permission.cfn_options.condition = params.organization_mode_enabled

        # ══════════════════════════════════════════════════════════
        #  CONSOLE HOSTING
        # ══════════════════════════════════════════════════════════

        cognito_domain_prefix = f"{params.prefix}-{Aws.ACCOUNT_ID}"
        cognito_origin = f"https://{cognito_domain_prefix}.auth.{Aws.REGION}.amazoncognito.com"
        # The API origin is matched by its AWS-owned domain pattern: naming the
        # exact API here would create a dependency cycle with the API's CORS
        # policy, which names this distribution. Every API call needs a token.
        api_origin_pattern = f"https://*.execute-api.{Aws.REGION}.amazonaws.com"
        content_security_policy = "; ".join([
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self' data:",
            "font-src 'self'",
            f"connect-src 'self' {api_origin_pattern} {cognito_origin}",
            f"form-action 'self' {cognito_origin}",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "object-src 'none'",
        ])

        console_bucket = s3.Bucket(
            self, "ConsoleBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            enforce_ssl=True,
            # Holds only the prebuilt console bundle, never customer data. The
            # ConsolePublication resource empties it before deletion.
            removal_policy=RemovalPolicy.DESTROY,
        )
        # CloudFront names are unique per account across all regions, so they are
        # derived from this stack's own ID: two installations never collide.
        security_headers = cloudfront.ResponseHeadersPolicy(
            self, "ConsoleSecurityHeaders",
            response_headers_policy_name=f"sovereign-shield-{stack_unique_id}",
            comment="Sovereign Shield console security headers",
            security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(
                    content_security_policy=content_security_policy, override=True,
                ),
                strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                    access_control_max_age=Duration.days(730), include_subdomains=True, override=True,
                ),
                content_type_options=cloudfront.ResponseHeadersContentTypeOptions(override=True),
                frame_options=cloudfront.ResponseHeadersFrameOptions(
                    frame_option=cloudfront.HeadersFrameOption.DENY, override=True,
                ),
                referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                    referrer_policy=cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN, override=True,
                ),
            ),
        )
        distribution = cloudfront.Distribution(
            self, "ConsoleDistribution",
            comment="Sovereign Shield console",
            default_root_object="index.html",
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            default_behavior=cloudfront.BehaviorOptions(
                origin=cloudfront_origins.S3BucketOrigin.with_origin_access_control(
                    console_bucket,
                    origin_access_control=cloudfront.S3OriginAccessControl(
                        self, "ConsoleOriginAccessControl",
                        origin_access_control_name=f"ss-console-{stack_unique_id}",
                    ),
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                response_headers_policy=security_headers,
            ),
            # Client-side routes (for example /scans/<id>) resolve to the app shell.
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=status, response_http_status=200, response_page_path="/index.html",
                    ttl=Duration.seconds(0),
                )
                for status in (403, 404)
            ],
        )
        console_origin = f"https://{distribution.distribution_domain_name}"

        # ══════════════════════════════════════════════════════════
        #  IDENTITY
        # ══════════════════════════════════════════════════════════

        user_pool = cognito.UserPool(
            self, "UserPool",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            mfa=cognito.Mfa.OPTIONAL,
            mfa_second_factor=cognito.MfaSecondFactor(sms=False, otp=True),
            password_policy=cognito.PasswordPolicy(
                min_length=12,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            account_recovery=cognito.AccountRecovery.EMAIL_ONLY,
            user_invitation=cognito.UserInvitationConfig(
                email_subject="Your Sovereign Shield console access",
                email_body=(
                    f"You have been given access to the Sovereign Shield console at {console_origin} . "
                    "Sign in with username {username} and temporary password {####} ; "
                    "you will be asked to choose a new password."
                ),
            ),
            removal_policy=data_removal_policy,
        )
        administrators_group = cognito.CfnUserPoolGroup(
            self, "AdministratorsGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name=ADMINISTRATORS_GROUP,
            description="Start and cancel scans, manage schedules, and view all results.",
        )
        cognito.CfnUserPoolGroup(
            self, "AuditorsGroup",
            user_pool_id=user_pool.user_pool_id,
            group_name=AUDITORS_GROUP,
            description="View scans, findings, and reports.",
        )
        # Operator client: SRP sign-in and IAM-authorized admin sign-in for API validation.
        user_pool_client = user_pool.add_client(
            "ApiClient",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(user_srp=True, admin_user_password=True),
            disable_o_auth=True,
            prevent_user_existence_errors=True,
            access_token_validity=Duration.hours(1),
            id_token_validity=Duration.hours(1),
            refresh_token_validity=Duration.hours(12),
        )
        user_pool_domain = user_pool.add_domain(
            "HostedSignInDomain",
            cognito_domain=cognito.CognitoDomainOptions(domain_prefix=cognito_domain_prefix),
        )
        console_callback_origins = [console_origin, *dev.console_dev_origins]
        # Public browser client: authorization code grant with PKCE, no secret,
        # no implicit grant. Tokens are short-lived; refresh is bounded.
        console_client = user_pool.add_client(
            "ConsoleClient",
            generate_secret=False,
            auth_flows=cognito.AuthFlow(user_srp=True),
            o_auth=cognito.OAuthSettings(
                flows=cognito.OAuthFlows(authorization_code_grant=True),
                scopes=[cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
                callback_urls=[f"{origin}/callback" for origin in console_callback_origins],
                logout_urls=[f"{origin}/" for origin in console_callback_origins],
            ),
            supported_identity_providers=[cognito.UserPoolClientIdentityProvider.COGNITO],
            prevent_user_existence_errors=True,
            enable_token_revocation=True,
            access_token_validity=Duration.hours(1),
            id_token_validity=Duration.hours(1),
            refresh_token_validity=Duration.hours(12),
        )
        admin_user = cognito.CfnUserPoolUser(
            self, "BootstrapAdministrator",
            user_pool_id=user_pool.user_pool_id,
            username=params.administrator_email,
            desired_delivery_mediums=["EMAIL"],
            user_attributes=[
                cognito.CfnUserPoolUser.AttributeTypeProperty(name="email", value=params.administrator_email),
                cognito.CfnUserPoolUser.AttributeTypeProperty(name="email_verified", value="true"),
            ],
        )
        admin_membership = cognito.CfnUserPoolUserToGroupAttachment(
            self, "BootstrapAdministratorMembership",
            user_pool_id=user_pool.user_pool_id,
            group_name=ADMINISTRATORS_GROUP,
            username=params.administrator_email,
        )
        admin_membership.add_dependency(admin_user)
        admin_membership.add_dependency(administrators_group)
        admin_user.cfn_options.condition = params.has_administrator
        admin_membership.cfn_options.condition = params.has_administrator

        # ══════════════════════════════════════════════════════════
        #  V1 API
        # ══════════════════════════════════════════════════════════

        dashboard_name = f"{params.prefix}-{Aws.REGION}-operations"
        operations_dashboard_url = (
            f"https://{Aws.REGION}.console.aws.amazon.com/cloudwatch/home?region={Aws.REGION}"
            f"#dashboards:name={dashboard_name}"
        )
        api_log_group = self._log_group("ApiFunctionLogs", data_key, params, data_removal_policy)
        api_role = iam.Role(
            self, "ApiFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Sovereign Shield v1 API: run/schedule records, workflow start, and schedule management.",
        )
        api_function = lambda_.Function(
            self, "ApiFunction",
            description="Sovereign Shield v1 scan, findings, report, and schedule API.",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="sovereign_shield.lambda_handler.handler",
            code=code,
            role=api_role,
            memory_size=512,
            timeout=Duration.seconds(29),
            log_group=api_log_group,
            tracing=lambda_.Tracing.ACTIVE,
            environment={
                "SCAN_RUNS_TABLE": runs_table.table_name,
                "FINDINGS_TABLE": findings_table.table_name,
                "SCAN_STATE_MACHINE_ARN": state_machine.state_machine_arn,
                "SCHEDULE_GROUP_NAME": schedule_group.name,
                "SCHEDULER_ROLE_ARN": scheduler_role.role_arn,
                "DEPLOYMENT_ACCOUNT_ID": Aws.ACCOUNT_ID,
                "AUDIT_TABLE": audit_table.table_name,
                "REPORTS_BUCKET": reports_bucket.bucket_name,
                "RELEASE_VERSION": release_version,
                "OPERATIONS_DASHBOARD_URL": operations_dashboard_url,
                "FINDINGS_RETENTION_DAYS": params.findings_retention_days_text,
                "SCHEDULED_SCANS_ENABLED": params.scheduled_scans_enabled,
                "DEFAULT_SCAN_REGIONS": params.default_scan_regions,
                "ONBOARDING_FUNCTION_NAME": onboarding_function.function_name,
                **organization_environment,
                "ADMINISTRATOR_SETTINGS": self.to_json_string({
                    "reportRetentionDays": params.report_retention_days_text,
                    "findingsRetentionDays": params.findings_retention_days_text,
                    "logRetentionDays": params.log_retention_days_text,
                    "scanConcurrency": params.scan_concurrency_text,
                    "scheduledScansEnabled": params.scheduled_scans_enabled,
                    "notificationsEnabled": Fn.condition_if(
                        params.has_notification_email.logical_id, "true", "false"
                    ).to_string(),
                    "dataRemovalPolicy": "DESTROY" if destroy_data else "RETAIN",
                    "dataDeletionAcknowledgement": params.data_deletion_acknowledgement,
                    "kmsKeyMode": params.kms_key_mode,
                    "organizationMode": params.organization_mode,
                    "organizationId": params.organization_id,
                    "targetOrganizationalUnitIds": params.target_ou_ids,
                    "accountAllowlist": params.account_allowlist,
                    "accountDenylist": params.account_denylist,
                    "exclusionTagKey": params.exclusion_tag_key,
                    "memberRoleName": params.member_role_name,
                    "maxAccountsPerScan": params.max_accounts_per_scan_text,
                    "identityProviderMode": params.identity_mode,
                }),
            },
        )

        api_role.add_to_policy(iam.PolicyStatement(
            sid="ListRunsAndSchedules",
            actions=["dynamodb:Query"],
            resources=[f"{runs_table.table_arn}/index/by-entity-created"],
        ))
        api_role.add_to_policy(iam.PolicyStatement(
            sid="AppendAndReadAuditEvents",
            # No UpdateItem or DeleteItem: audit records are append-only via the product.
            actions=["dynamodb:PutItem", "dynamodb:Query"],
            resources=[audit_table.table_arn],
        ))
        api_role.add_to_policy(iam.PolicyStatement(
            sid="SignReportDownloads",
            # Pre-signed URLs carry this role's authority, limited to reports/*.
            actions=["s3:GetObject"],
            resources=[reports_bucket.arn_for_objects("reports/*")],
        ))
        api_role.add_to_policy(iam.PolicyStatement(
            sid="RunAndScheduleRecords",
            actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"],
            resources=[runs_table.table_arn],
        ))
        api_role.add_to_policy(iam.PolicyStatement(
            sid="FindingReads",
            actions=["dynamodb:Query"],
            resources=[findings_table.table_arn],
        ))
        api_role.add_to_policy(iam.PolicyStatement(
            sid="ManageScanSchedules",
            actions=["scheduler:CreateSchedule", "scheduler:UpdateSchedule", "scheduler:DeleteSchedule"],
            resources=[
                f"arn:{Aws.PARTITION}:scheduler:{Aws.REGION}:{Aws.ACCOUNT_ID}"
                f":schedule/{schedule_group.name}/sovereign-shield-*"
            ],
        ))
        api_role.add_to_policy(iam.PolicyStatement(
            sid="PassSchedulerRole",
            actions=["iam:PassRole"],
            resources=[scheduler_role.role_arn],
            conditions={"StringEquals": {"iam:PassedToService": "scheduler.amazonaws.com"}},
        ))
        state_machine.grant_start_execution(api_role)
        api_role.add_to_policy(iam.PolicyStatement(
            sid="RequestOnboardingSync",
            actions=["lambda:InvokeFunction"],
            resources=[onboarding_function.function_arn],
        ))
        api_log_group.grant_write(api_role)
        data_key.grant_encrypt_decrypt(api_role)
        data_key.grant(api_role, "kms:DescribeKey")

        http_api = apigwv2.HttpApi(
            self, "HttpApi",
            description="Sovereign Shield v1 API",
            create_default_stage=False,
            cors_preflight=apigwv2.CorsPreflightOptions(
                allow_origins=[console_origin, *dev.console_dev_origins, *dev.allowed_origins],
                allow_methods=[
                    apigwv2.CorsHttpMethod.GET,
                    apigwv2.CorsHttpMethod.POST,
                    apigwv2.CorsHttpMethod.PATCH,
                    apigwv2.CorsHttpMethod.DELETE,
                ],
                allow_headers=["Authorization", "Content-Type", "X-Correlation-Id"],
                max_age=Duration.hours(1),
            ),
        )
        api_stage = apigwv2.HttpStage(
            self, "HttpApiDefaultStage",
            http_api=http_api,
            stage_name="$default",
            auto_deploy=True,
            throttle=apigwv2.ThrottleSettings(rate_limit=20, burst_limit=40),
        )
        api_access_log_group = self._log_group("ApiAccessLogs", data_key, params, data_removal_policy)
        cfn_stage: apigwv2.CfnStage = api_stage.node.default_child  # type: ignore[assignment]
        # Redacted access-log format: no source IP, user agent, or JWT claims.
        cfn_stage.access_log_settings = apigwv2.CfnStage.AccessLogSettingsProperty(
            destination_arn=api_access_log_group.log_group_arn,
            format=(
                '{"requestId":"$context.requestId","requestTime":"$context.requestTime",'
                '"routeKey":"$context.routeKey","status":"$context.status",'
                '"responseLatency":"$context.responseLatency",'
                '"integrationError":"$context.integrationErrorMessage"}'
            ),
        )

        authorizer = apigwv2_authorizers.HttpUserPoolAuthorizer(
            "CognitoAuthorizer", user_pool, user_pool_clients=[user_pool_client, console_client],
        )
        integration = apigwv2_integrations.HttpLambdaIntegration("ApiIntegration", api_function)
        # The shared integration's logical ID comes from the first route, so
        # POST /v1/scans stays first to keep the deployed integration in place.
        for path, method in (
            ("/v1/scans", apigwv2.HttpMethod.POST),
            ("/v1/configuration", apigwv2.HttpMethod.GET),
            ("/v1/scans", apigwv2.HttpMethod.GET),
            ("/v1/scans/{scanRunId}", apigwv2.HttpMethod.GET),
            ("/v1/scans/{scanRunId}/cancel", apigwv2.HttpMethod.POST),
            ("/v1/scans/{scanRunId}/findings", apigwv2.HttpMethod.GET),
            ("/v1/scans/{scanRunId}/report", apigwv2.HttpMethod.GET),
            ("/v1/schedules", apigwv2.HttpMethod.GET),
            ("/v1/schedules", apigwv2.HttpMethod.POST),
            ("/v1/schedules/{scheduleId}", apigwv2.HttpMethod.PATCH),
            ("/v1/schedules/{scheduleId}", apigwv2.HttpMethod.DELETE),
            ("/v1/audit-events", apigwv2.HttpMethod.GET),
            ("/v1/accounts", apigwv2.HttpMethod.GET),
            ("/v1/accounts/sync", apigwv2.HttpMethod.POST),
            ("/v1/accounts/{accountId}", apigwv2.HttpMethod.PATCH),
        ):
            http_api.add_routes(path=path, methods=[method], integration=integration, authorizer=authorizer)

        # ══════════════════════════════════════════════════════════
        #  DEPLOYMENT TASKS (product-owned custom resources)
        # ══════════════════════════════════════════════════════════

        deployment_log_group = self._log_group("DeploymentFunctionLogs", data_key, params, data_removal_policy)
        deployment_role = iam.Role(
            self, "DeploymentFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Sovereign Shield deploy-time tasks: publish the console bundle and empty stack buckets.",
        )
        deployment_function = lambda_.Function(
            self, "DeploymentFunction",
            description="Publishes the Sovereign Shield console and prepares stack buckets for deletion.",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="sovereign_shield.deployment_handler.handler",
            code=code,
            role=deployment_role,
            memory_size=512,
            timeout=Duration.minutes(5),
            log_group=deployment_log_group,
        )
        deployment_log_group.grant_write(deployment_role)
        deployment_role.add_to_policy(iam.PolicyStatement(
            sid="ManageConsoleBundle",
            actions=["s3:PutObject", "s3:DeleteObject"],
            resources=[console_bucket.arn_for_objects("*")],
        ))
        deployment_role.add_to_policy(iam.PolicyStatement(
            sid="ListAndEmptyConsoleBucket",
            actions=["s3:ListBucket", "s3:ListBucketVersions", "s3:DeleteObjectVersion"],
            resources=[console_bucket.bucket_arn, console_bucket.arn_for_objects("*")],
        ))
        deployment_role.add_to_policy(iam.PolicyStatement(
            sid="InvalidateConsoleCache",
            actions=["cloudfront:CreateInvalidation"],
            resources=[
                f"arn:{Aws.PARTITION}:cloudfront::{Aws.ACCOUNT_ID}:distribution/{distribution.distribution_id}"
            ],
        ))

        if console_source is not None:
            source_bucket, source_key = console_source
            deployment_role.add_to_policy(iam.PolicyStatement(
                sid="ReadConsoleBundle",
                actions=["s3:GetObject"],
                resources=[source_bucket.arn_for_objects(source_key)],
            ))
            publication = CustomResource(
                self, "ConsolePublication",
                service_token=deployment_function.function_arn,
                resource_type="Custom::ConsolePublication",
                properties={
                    "SourceBucket": source_bucket.bucket_name,
                    "SourceKey": source_key,
                    "TargetBucket": console_bucket.bucket_name,
                    "DistributionId": distribution.distribution_id,
                    "Config": self.to_json_string({
                        "apiUrl": http_api.api_endpoint,
                        "region": Aws.REGION,
                        "cognitoDomain": cognito_origin,
                        "clientId": console_client.user_pool_client_id,
                    }),
                },
            )
            publication.node.add_dependency(deployment_role)
            publication.node.add_dependency(deployment_log_group)

        if destroy_data:
            deployment_role.add_to_policy(iam.PolicyStatement(
                sid="EmptyReportsBucketOnDelete",
                actions=["s3:ListBucket", "s3:ListBucketVersions", "s3:DeleteObject", "s3:DeleteObjectVersion"],
                resources=[reports_bucket.bucket_arn, reports_bucket.arn_for_objects("*")],
            ))
            emptier = CustomResource(
                self, "ReportsBucketEmptier",
                service_token=deployment_function.function_arn,
                resource_type="Custom::BucketEmptier",
                properties={"BucketName": reports_bucket.bucket_name},
            )
            emptier.node.add_dependency(deployment_role)
            emptier.node.add_dependency(deployment_log_group)

        # ══════════════════════════════════════════════════════════
        #  READINESS CHECK
        # ══════════════════════════════════════════════════════════

        readiness_log_group = self._log_group("ReadinessFunctionLogs", data_key, params, data_removal_policy)
        readiness_role = iam.Role(
            self, "ReadinessFunctionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Sovereign Shield post-deploy readiness check: describe-only access.",
        )
        readiness_function = lambda_.Function(
            self, "ReadinessFunction",
            description="Non-mutating Sovereign Shield post-deployment readiness check.",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="sovereign_shield.readiness_handler.handler",
            code=code,
            role=readiness_role,
            memory_size=256,
            timeout=Duration.minutes(2),
            log_group=readiness_log_group,
            environment={
                "SCAN_RUNS_TABLE": runs_table.table_name,
                "FINDINGS_TABLE": findings_table.table_name,
                "AUDIT_TABLE": audit_table.table_name,
                "REPORTS_BUCKET": reports_bucket.bucket_name,
                "DATA_KEY_ARN": data_key_arn,
                "SCAN_STATE_MACHINE_ARN": state_machine.state_machine_arn,
                "USER_POOL_ID": user_pool.user_pool_id,
                "CONSOLE_CLIENT_ID": console_client.user_pool_client_id,
                "DEFAULT_SCAN_REGIONS": params.default_scan_regions,
                "RELEASE_VERSION": release_version,
                **organization_environment,
            },
        )
        readiness_log_group.grant_write(readiness_role)
        readiness_role.add_to_policy(iam.PolicyStatement(
            sid="DescribeOrganizationSetup",
            actions=["organizations:DescribeOrganization", "cloudformation:DescribeStackSet"],
            resources=["*"],
        ))
        readiness_role.add_to_policy(iam.PolicyStatement(
            sid="ScannerPermissionDryRun",
            actions=_SCANNER_READ_ACTIONS,
            resources=["*"],
        ))
        readiness_role.add_to_policy(iam.PolicyStatement(
            sid="DescribeStackResources",
            actions=["states:DescribeStateMachine"],
            resources=[state_machine.state_machine_arn],
        ))
        readiness_role.add_to_policy(iam.PolicyStatement(
            sid="DescribeConsoleClient",
            actions=["cognito-idp:DescribeUserPoolClient"],
            resources=[user_pool.user_pool_arn],
        ))

        # ══════════════════════════════════════════════════════════
        #  OPERATIONS
        # ══════════════════════════════════════════════════════════

        alarm_action = cloudwatch_actions.SnsAction(notification_topic)
        five_minutes = Duration.minutes(5)

        def alarm(alarm_id: str, metric: cloudwatch.IMetric, description: str, threshold: float = 1) -> None:
            created = cloudwatch.Alarm(
                self, alarm_id,
                metric=metric,
                threshold=threshold,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
                alarm_description=description,
            )
            created.add_alarm_action(alarm_action)

        failed_runs = cloudwatch.Metric(
            namespace=METRICS_NAMESPACE,
            metric_name="CompletedRuns",
            dimensions_map={"Status": "failed"},
            statistic="Sum",
            period=five_minutes,
        )
        scheduler_errors = cloudwatch.MathExpression(
            expression="errors + dropped",
            using_metrics={
                "errors": cloudwatch.Metric(
                    namespace="AWS/Scheduler", metric_name="TargetErrorCount",
                    dimensions_map={"ScheduleGroup": schedule_group.name}, statistic="Sum", period=five_minutes,
                ),
                "dropped": cloudwatch.Metric(
                    namespace="AWS/Scheduler", metric_name="InvocationDroppedCount",
                    dimensions_map={"ScheduleGroup": schedule_group.name}, statistic="Sum", period=five_minutes,
                ),
            },
            period=five_minutes,
        )
        dynamodb_throttles = cloudwatch.MathExpression(
            expression="runs + findings",
            using_metrics={
                "runs": runs_table.metric("ThrottledRequests", statistic="Sum", period=five_minutes),
                "findings": findings_table.metric("ThrottledRequests", statistic="Sum", period=five_minutes),
            },
            period=five_minutes,
        )

        alarm("StateMachineFailedAlarm", state_machine.metric_failed(period=five_minutes),
              "A scan workflow execution failed.")
        alarm("StateMachineTimedOutAlarm", state_machine.metric_timed_out(period=five_minutes),
              "A scan workflow execution timed out.")
        alarm("FailedScanRunsAlarm", failed_runs, "A scan run reached the failed state.")
        alarm("WorkflowErrorsAlarm", workflow_function.metric_errors(period=five_minutes),
              "The scan workflow function returned errors.")
        alarm("WorkflowThrottlesAlarm", workflow_function.metric_throttles(period=five_minutes),
              "The scan workflow function was throttled.")
        alarm("ApiFunctionErrorsAlarm", api_function.metric_errors(period=five_minutes),
              "The v1 API function returned errors.")
        alarm("Api5xxAlarm", http_api.metric_server_error(period=five_minutes),
              "The v1 API returned server errors.", threshold=5)
        alarm("SchedulerDeliveryAlarm", scheduler_errors,
              "EventBridge Scheduler could not start a scheduled scan.")
        alarm("DynamoDBThrottlesAlarm", dynamodb_throttles, "Scan data tables throttled requests.")

        # Failures that are logged rather than raised get metric filters, so they alarm.
        def log_metric(construct_id: str, log_group: logs.LogGroup, term: str, metric_name: str) -> cloudwatch.Metric:
            logs.MetricFilter(
                self, construct_id,
                log_group=log_group,
                filter_pattern=logs.FilterPattern.literal(f'"{term}"'),
                metric_namespace=OPERATIONS_NAMESPACE,
                metric_name=metric_name,
                metric_value="1",
                default_value=0,
            )
            return cloudwatch.Metric(
                namespace=OPERATIONS_NAMESPACE, metric_name=metric_name, statistic="Sum", period=five_minutes,
            )

        audit_write_failures = log_metric("AuditWriteFailureFilter", api_log_group, "AUDIT_WRITE_FAILED",
                                          "AuditWriteFailures")
        authorization_denials = log_metric("AuthorizationDenialFilter", api_log_group, "AUTHORIZATION_DENIED",
                                           "AuthorizationDenials")
        alarm("AuditWriteFailuresAlarm", audit_write_failures,
              "An audit record could not be written; the audited action itself succeeded.")
        alarm("AuthorizationDenialsAlarm", authorization_denials,
              "Many requests were denied by role checks (possible probing or a misconfigured group).", threshold=25)
        alarm("OnboardingErrorsAlarm", onboarding_function.metric_errors(period=five_minutes),
              "The organization onboarding sync failed.")

        cloudwatch.Dashboard(
            self, "OperationsDashboard",
            dashboard_name=dashboard_name,
            widgets=[
                [
                    cloudwatch.GraphWidget(
                        title="Scan workflow executions",
                        left=[
                            state_machine.metric_started(period=five_minutes),
                            state_machine.metric_succeeded(period=five_minutes),
                            state_machine.metric_failed(period=five_minutes),
                            state_machine.metric_timed_out(period=five_minutes),
                        ],
                    ),
                    cloudwatch.GraphWidget(
                        title="Scan run outcomes",
                        left=[
                            cloudwatch.Metric(
                                namespace=METRICS_NAMESPACE, metric_name="CompletedRuns",
                                dimensions_map={"Status": status}, statistic="Sum", period=five_minutes,
                                label=status,
                            )
                            for status in ("complete", "partial", "failed", "cancelled")
                        ],
                    ),
                ],
                [
                    cloudwatch.GraphWidget(
                        title="Workflow function",
                        left=[
                            workflow_function.metric_invocations(period=five_minutes),
                            workflow_function.metric_errors(period=five_minutes),
                            workflow_function.metric_throttles(period=five_minutes),
                        ],
                        right=[workflow_function.metric_duration(period=five_minutes, statistic="Maximum")],
                    ),
                    cloudwatch.GraphWidget(
                        title="v1 API",
                        left=[
                            http_api.metric_count(period=five_minutes),
                            http_api.metric_client_error(period=five_minutes),
                            http_api.metric_server_error(period=five_minutes),
                        ],
                        right=[http_api.metric_latency(period=five_minutes)],
                    ),
                ],
                [
                    cloudwatch.GraphWidget(title="Scheduler delivery failures", left=[scheduler_errors]),
                    cloudwatch.GraphWidget(title="DynamoDB throttles", left=[dynamodb_throttles]),
                ],
                [
                    cloudwatch.GraphWidget(
                        title="Security and audit",
                        left=[authorization_denials, audit_write_failures],
                    ),
                    cloudwatch.GraphWidget(
                        title="Report storage",
                        left=[cloudwatch.Metric(
                            namespace="AWS/S3", metric_name="BucketSizeBytes", statistic="Average",
                            period=Duration.days(1),
                            dimensions_map={"BucketName": reports_bucket.bucket_name, "StorageType": "StandardStorage"},
                        )],
                    ),
                ],
            ],
        )

        budget = budgets.CfnBudget(
            self, "MonthlyBudget",
            budget=budgets.CfnBudget.BudgetDataProperty(
                # Budget names are unique per account, so they come from the stack's own ID.
                budget_name=f"sovereign-shield-{stack_unique_id}",
                budget_type="COST",
                time_unit="MONTHLY",
                budget_limit=budgets.CfnBudget.SpendProperty(amount=params.monthly_budget, unit="USD"),
                cost_filters={"TagKeyValue": ["user:Application$SovereignShield"]},
            ),
            notifications_with_subscribers=[
                budgets.CfnBudget.NotificationWithSubscribersProperty(
                    notification=budgets.CfnBudget.NotificationProperty(
                        notification_type=notification_type, comparison_operator="GREATER_THAN",
                        threshold=threshold, threshold_type="PERCENTAGE",
                    ),
                    subscribers=[budgets.CfnBudget.SubscriberProperty(
                        subscription_type="EMAIL", address=params.notification_email,
                    )],
                )
                for notification_type, threshold in (("ACTUAL", 80), ("FORECASTED", 100))
            ],
        )
        budget.cfn_options.condition = params.has_budget

        # ══════════════════════════════════════════════════════════
        #  OUTPUTS (plan.md section 4.2)
        # ══════════════════════════════════════════════════════════

        def output(output_id: str, value: str, description: str) -> None:
            CfnOutput(self, output_id, value=value, description=description)

        output("ConsoleUrl", console_origin, "Sovereign Shield console")
        output("ApiUrl", http_api.api_endpoint, "Sovereign Shield v1 API endpoint")
        output("ScanRunTableName", runs_table.table_name, "Scan runs table")
        output("FindingsTableName", findings_table.table_name, "Findings table")
        output("ReportsBucketName", reports_bucket.bucket_name, "Private reports bucket")
        output("KmsKeyArn", data_key_arn, "Data encryption key")
        output("ScannerRoleArn", workflow_role.role_arn, "Read-only discovery role used by scan workers")
        output(
            "OrganizationOnboardingStatus",
            Fn.condition_if(
                params.organization_mode_enabled.logical_id,
                f"MEMBER_ROLES_VIA_STACKSET {stack_set_name}: per-account status on the console Accounts page",
                "NOT_APPLICABLE_SINGLE_ACCOUNT",
            ).to_string(),
            "AWS Organizations onboarding status",
        )
        output("MemberRoleExternalId", member_role_external_id,
               "External ID member roles require; use it when deploying the member role outside the StackSet")
        output("OnboardingFunctionName", onboarding_function.function_name, "Onboarding sync function")
        output("OperationsDashboardUrl", operations_dashboard_url, "CloudWatch operations dashboard")
        output(
            "PostDeployValidationCommand",
            f"aws lambda invoke --region {Aws.REGION} --function-name {readiness_function.function_name} "
            "--cli-binary-format raw-in-base64-out --payload '{}' readiness.json && cat readiness.json",
            "Non-mutating readiness check; run it after deployment",
        )
        output("ReleaseVersion", release_version, "Sovereign Shield release")
        output("CognitoDomain", user_pool_domain.base_url(), "Hosted sign-in domain")
        output("ConsoleClientId", console_client.user_pool_client_id, "Cognito app client used by the console")
        output("AuditTableName", audit_table.table_name, "Append-only audit table")
        output("UserPoolId", user_pool.user_pool_id, "Cognito user pool ID")
        output("UserPoolClientId", user_pool_client.user_pool_client_id, "Cognito app client ID for API sign-in")
        output("ScanStateMachineArn", state_machine.state_machine_arn, "Scan workflow state machine")
        output("ScheduleGroupName", schedule_group.name, "EventBridge Scheduler group")
        output("NotificationTopicArn", notification_topic.topic_arn, "Scan failure and critical-finding alerts")
        output("ReadinessFunctionName", readiness_function.function_name, "Readiness check function")

    def _table(self, construct_id: str, key: kms.IKey, removal_policy: RemovalPolicy, *, ttl: bool) -> dynamodb.Table:
        return dynamodb.Table(
            self, construct_id,
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=key,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True,
            ),
            time_to_live_attribute="expires_at" if ttl else None,
            removal_policy=removal_policy,
        )

    def _workflow_task(
        self,
        construct_id: str,
        function: lambda_.IFunction,
        payload: dict,
        *,
        result_path: str,
        timeout: Duration,
        extra_retry_errors: list[str] | None = None,
    ) -> sfn_tasks.LambdaInvoke:
        """Invoke the workflow function, retrying only errors raised before the handler ran."""

        task = sfn_tasks.LambdaInvoke(
            self, construct_id,
            lambda_function=function,
            payload=sfn.TaskInput.from_object(payload),
            payload_response_only=True,
            result_path=result_path,
            retry_on_service_exceptions=False,
            task_timeout=sfn.Timeout.duration(timeout),
        )
        task.add_retry(
            errors=_TRANSIENT_LAMBDA_ERRORS + (extra_retry_errors or []),
            interval=Duration.seconds(5),
            max_attempts=3,
            backoff_rate=2,
        )
        return task

    def _log_group(
        self,
        construct_id: str,
        key: kms.IKey,
        params: _Parameters,
        removal_policy: RemovalPolicy,
    ) -> logs.LogGroup:
        log_group = logs.LogGroup(self, construct_id, encryption_key=key, removal_policy=removal_policy)
        cfn_log_group: logs.CfnLogGroup = log_group.node.default_child  # type: ignore[assignment]
        cfn_log_group.retention_in_days = params.log_retention_days
        return log_group


def _set_condition(construct: Construct, condition: CfnCondition) -> None:
    resource = construct.node.default_child
    resource.cfn_options.condition = condition  # type: ignore[union-attr]


class _Parameters:
    """Customer launch parameters, conditions, rules, and console grouping (plan.md section 4.1)."""

    def __init__(self, stack: Stack, *, non_production: bool) -> None:
        def parameter(name: str, **options) -> CfnParameter:
            return CfnParameter(stack, name, **options)

        prefix = parameter(
            "DeploymentPrefix", type="String", default="sovereign-shield",
            allowed_pattern=r"^[a-z][a-z0-9-]{2,23}$",
            constraint_description="3-24 lowercase letters, numbers, and hyphens, starting with a letter. "
            "Must not contain 'aws', 'amazon', or 'cognito' (used in the sign-in domain).",
            description="Names the sign-in domain, encryption key alias, schedule group, and dashboard.",
        )
        administrator = parameter(
            "AdministratorEmail", type="String", default="", allowed_pattern=_EMAIL_PATTERN,
            constraint_description="An email address, or empty.",
            description="Optional bootstrap administrator. Cognito emails a temporary password and the console link.",
        )
        notification = parameter(
            "NotificationEmail", type="String", default="", allowed_pattern=_EMAIL_PATTERN,
            constraint_description="An email address, or empty.",
            description="Optional recipient for scan-failure, critical-finding, and operations alerts.",
        )
        scan_regions = parameter(
            "DefaultScanRegions", type="String", default="", allowed_pattern=_REGION_LIST_PATTERN,
            constraint_description="Comma-separated region codes without spaces, for example eu-central-1,eu-west-1.",
            description="Regions preselected for new scans and used by the readiness check. Empty means this region.",
        )
        schedules = parameter(
            "EnableScheduledScans", type="String", default="false", allowed_values=["false", "true"],
            description="Allow administrators to create recurring scans. No schedule is created by installation.",
        )
        kms_mode = parameter(
            "KmsKeyMode", type="String", default="CREATE_CUSTOMER_MANAGED",
            allowed_values=["CREATE_CUSTOMER_MANAGED", "EXISTING_KEY_ARN"],
            description="Create a dedicated customer-managed key, or use an existing key in this region.",
        )
        existing_key = parameter(
            "ExistingKmsKeyArn", type="String", default="",
            allowed_pattern=r"^$|^arn:aws:kms:[a-z0-9-]+:\d{12}:key/[0-9a-f-]{36}$",
            constraint_description="A KMS key ARN in this account, or empty.",
            description="Required for EXISTING_KEY_ARN. Its key policy must allow CloudWatch Logs and CloudWatch "
            "alarms in this region (see the deployment guide).",
        )
        findings_retention = parameter(
            "FindingsRetentionDays", type="Number", default=0, min_value=0, max_value=3650,
            description="Days to keep completed scan evidence and findings. 0 keeps them indefinitely.",
        )
        report_retention = parameter(
            "ReportRetentionDays", type="Number", default=365, min_value=30, max_value=3650,
            description="Days to keep generated reports.",
        )
        log_retention = parameter(
            "LogRetentionDays", type="Number", default="90", allowed_values=["30", "90", "180", "365"],
            description="Days to keep function and workflow logs.",
        )
        monthly_budget = parameter(
            "MonthlyBudgetUsd", type="Number", default=0, min_value=0, max_value=1000000,
            description="Optional monthly cost budget in USD for resources tagged Application=SovereignShield. "
            "0 disables it. Requires NotificationEmail and the Application cost allocation tag to be activated.",
        )
        concurrency = parameter(
            "ScanConcurrency", type="Number", default=10, min_value=1, max_value=40,
            description="Account/region/service units scanned in parallel per scan.",
        )
        organization_mode = parameter(
            "OrganizationMode", type="String", default="SINGLE_ACCOUNT",
            allowed_values=["SINGLE_ACCOUNT", "AWS_ORGANIZATIONS"],
            description="SINGLE_ACCOUNT scans this account. AWS_ORGANIZATIONS deploys a read-only member role "
            "to the selected OUs and scans onboarded accounts. Deploy in the management or a delegated "
            "administrator account with StackSets trusted access enabled.",
        )
        organization_id = parameter(
            "OrganizationId", type="String", default="", allowed_pattern=r"^$|^o-[a-z0-9]{10,32}$",
            constraint_description="An organization ID such as o-a1b2c3d4e5, or empty.",
            description="Required for AWS_ORGANIZATIONS.",
        )
        target_ous = parameter(
            "TargetOrganizationalUnitIds", type="String", default="", allowed_pattern=_OU_LIST_PATTERN,
            constraint_description="Comma-separated OU or root IDs without spaces (ou-xxxx-xxxxxxxx or r-xxxx).",
            description="OUs (and their child OUs) whose accounts receive the member role. Required for "
            "AWS_ORGANIZATIONS.",
        )
        allowlist = parameter(
            "AccountAllowlist", type="String", default="", allowed_pattern=_ACCOUNT_LIST_PATTERN,
            constraint_description="Comma-separated 12-digit account IDs, or empty.",
            description="If set, only these member accounts are scanned.",
        )
        denylist = parameter(
            "AccountDenylist", type="String", default="", allowed_pattern=_ACCOUNT_LIST_PATTERN,
            constraint_description="Comma-separated 12-digit account IDs, or empty.",
            description="Accounts that never receive the member role and are never scanned.",
        )
        exclusion_tag = parameter(
            "ExclusionTagKey", type="String", default="sovereign-shield:exclude",
            allowed_pattern=r"^[\w.:/=+@-]{1,128}$",
            description="Accounts tagged with this key and value 'true' in AWS Organizations are never scanned.",
        )
        member_role_name = parameter(
            "MemberRoleName", type="String", default="SovereignShieldScanRole",
            allowed_pattern=r"^[\w+=,.@-]{1,64}$",
            description="Name of the read-only role created in each member account.",
        )
        call_as = parameter(
            "StackSetCallAs", type="String", default="SELF", allowed_values=["SELF", "DELEGATED_ADMIN"],
            description="SELF in the management account; DELEGATED_ADMIN in a StackSets delegated administrator.",
        )
        max_accounts = parameter(
            "MaxAccountsPerScan", type="Number", default=25, min_value=1, max_value=200,
            description="Upper bound on accounts per scan (scans are also limited to 1,000 work units).",
        )
        organization_acknowledgement = parameter(
            "AcknowledgeOrganizationPermissions", type="String", default="",
            allowed_values=["", ORGANIZATION_ACKNOWLEDGEMENT],
            description="Required for AWS_ORGANIZATIONS: this stack reads organization membership and deploys a "
            f"read-only role to member accounts. Enter {ORGANIZATION_ACKNOWLEDGEMENT} to confirm.",
        )
        identity_mode = parameter(
            "IdentityProviderMode", type="String", default="COGNITO_LOCAL", allowed_values=["COGNITO_LOCAL"],
            description="Console users are managed in the stack's Cognito user pool.",
        )
        tags = {
            name: parameter(
                name, type="String", default="unspecified", allowed_pattern=_TAG_PATTERN,
                description=f"{name} tag applied to every taggable resource.",
            )
            for name in ("Environment", "Owner", "CostCenter")
        }
        groups = [
            ("Deployment", [prefix]),
            ("Organization", [
                organization_mode, organization_id, target_ous, organization_acknowledgement, call_as,
                allowlist, denylist, exclusion_tag, member_role_name, max_accounts,
            ]),
            ("Access", [identity_mode, administrator, notification]),
            ("Scanning", [scan_regions, concurrency, schedules]),
            ("Data protection", [kms_mode, existing_key, findings_retention, report_retention, log_retention]),
            ("Cost", [monthly_budget]),
            ("Tags", list(tags.values())),
        ]
        acknowledgement = None
        if non_production:
            acknowledgement = parameter(
                "AcknowledgeDataDeletion", type="String", allowed_values=[DATA_DELETION_ACKNOWLEDGEMENT],
                description="This non-production template deletes all findings, reports, audit records, users, "
                f"and the encryption key with the stack. Enter {DATA_DELETION_ACKNOWLEDGEMENT} to confirm.",
            )
            groups.insert(0, ("Non-production data deletion", [acknowledgement]))

        stack.template_options.metadata = {
            "AWS::CloudFormation::Interface": {
                "ParameterGroups": [
                    {"Label": {"default": label}, "Parameters": [item.logical_id for item in items]}
                    for label, items in groups
                ],
            }
        }

        self.create_key = CfnCondition(
            stack, "CreateDataKey", expression=Fn.condition_equals(kms_mode.value_as_string, "CREATE_CUSTOMER_MANAGED")
        )
        self.has_administrator = CfnCondition(
            stack, "HasAdministratorEmail",
            expression=Fn.condition_not(Fn.condition_equals(administrator.value_as_string, "")),
        )
        self.has_notification_email = CfnCondition(
            stack, "HasNotificationEmail",
            expression=Fn.condition_not(Fn.condition_equals(notification.value_as_string, "")),
        )
        CfnRule(
            stack, "SupportedRegion",
            assertions=[CfnRuleAssertion(
                assert_=Fn.condition_contains(list(SUPPORTED_REGIONS), Aws.REGION),
                assert_description=f"This release supports only: {', '.join(SUPPORTED_REGIONS)}.",
            )],
        )
        CfnRule(
            stack, "OrganizationModeRequirements",
            rule_condition=Fn.condition_equals(organization_mode.value_as_string, "AWS_ORGANIZATIONS"),
            assertions=[
                CfnRuleAssertion(
                    assert_=Fn.condition_not(Fn.condition_equals(organization_id.value_as_string, "")),
                    assert_description="OrganizationId is required for AWS_ORGANIZATIONS.",
                ),
                CfnRuleAssertion(
                    assert_=Fn.condition_not(Fn.condition_equals(target_ous.value_as_string, "")),
                    assert_description="TargetOrganizationalUnitIds is required for AWS_ORGANIZATIONS.",
                ),
                CfnRuleAssertion(
                    assert_=Fn.condition_equals(
                        organization_acknowledgement.value_as_string, ORGANIZATION_ACKNOWLEDGEMENT
                    ),
                    assert_description="AcknowledgeOrganizationPermissions must be confirmed for AWS_ORGANIZATIONS.",
                ),
            ],
        )
        CfnRule(
            stack, "ExistingKeyRequiresArn",
            rule_condition=Fn.condition_equals(kms_mode.value_as_string, "EXISTING_KEY_ARN"),
            assertions=[CfnRuleAssertion(
                assert_=Fn.condition_not(Fn.condition_equals(existing_key.value_as_string, "")),
                assert_description="ExistingKmsKeyArn is required when KmsKeyMode is EXISTING_KEY_ARN.",
            )],
        )

        self.prefix = prefix.value_as_string
        self.administrator_email = administrator.value_as_string
        self.notification_email = notification.value_as_string
        self.default_scan_regions = scan_regions.value_as_string
        self.scheduled_scans_enabled = schedules.value_as_string
        self.kms_key_mode = kms_mode.value_as_string
        self.existing_key_arn = existing_key.value_as_string
        self.report_retention_days = report_retention.value_as_number
        self.log_retention_days = log_retention.value_as_number
        self.findings_retention_days_text = findings_retention.value_as_string
        self.report_retention_days_text = report_retention.value_as_string
        self.log_retention_days_text = log_retention.value_as_string
        self.scan_concurrency_text = concurrency.value_as_string
        self.environment = tags["Environment"].value_as_string
        self.owner = tags["Owner"].value_as_string
        self.cost_center = tags["CostCenter"].value_as_string
        self.organization_mode = organization_mode.value_as_string
        self.organization_id = organization_id.value_as_string
        self.target_ou_ids = target_ous.value_as_string
        self.account_allowlist = allowlist.value_as_string
        self.account_denylist = denylist.value_as_string
        self.exclusion_tag_key = exclusion_tag.value_as_string
        self.member_role_name = member_role_name.value_as_string
        self.stack_set_call_as = call_as.value_as_string
        self.max_accounts_per_scan_text = max_accounts.value_as_string
        self.organization_mode_enabled = CfnCondition(
            stack, "IsOrganizationMode",
            expression=Fn.condition_equals(organization_mode.value_as_string, "AWS_ORGANIZATIONS"),
        )
        self.monthly_budget = monthly_budget.value_as_number
        self.has_budget = CfnCondition(
            stack, "HasMonthlyBudget",
            expression=Fn.condition_and(
                Fn.condition_not(Fn.condition_equals(monthly_budget.value_as_string, "0")),
                Fn.condition_not(Fn.condition_equals(notification.value_as_string, "")),
            ),
        )
        self.has_denylist = CfnCondition(
            stack, "HasAccountDenylist",
            expression=Fn.condition_not(Fn.condition_equals(denylist.value_as_string, "")),
        )
        self.identity_mode = identity_mode.value_as_string
        self.data_deletion_acknowledgement = acknowledgement.value_as_string if acknowledgement else ""


class _DevelopmentOptions:
    """Internal-only CDK context options. Customer choices are template parameters."""

    def __init__(self, scope: Construct) -> None:
        self._scope = scope

    @classmethod
    def from_context(cls, scope: Construct) -> _DevelopmentOptions:
        options = cls(scope)
        options.allowed_origins = options._origins("allowedOrigins")
        options.console_dev_origins = options._origins("consoleDevOrigins")
        options.release_version = options._string("releaseVersion", "development")
        if not _RELEASE_VERSION_PATTERN.fullmatch(options.release_version):
            raise ValueError("releaseVersion must be 1-32 letters, numbers, dots, hyphens, or underscores.")
        options.data_removal_policy = options._string("dataRemovalPolicy", "RETAIN").upper()
        if options.data_removal_policy not in {"RETAIN", "DESTROY"}:
            raise ValueError("dataRemovalPolicy must be RETAIN or DESTROY.")
        return options

    def _origins(self, key: str) -> list[str]:
        origins = [origin.strip() for origin in self._string(key, "").split(",") if origin.strip()]
        for origin in origins:
            if origin == "*" or not _ORIGIN_PATTERN.fullmatch(origin):
                raise ValueError(f"{key} entries must be explicit http(s) origins: {origin!r}")
        return origins

    def _string(self, key: str, default: str) -> str:
        value = self._scope.node.try_get_context(key)
        return default if value is None else str(value).strip()
