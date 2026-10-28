"""Synthesis assertions for the Phase 2 asynchronous backend stack."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

cdk = pytest.importorskip("aws_cdk")
from aws_cdk.assertions import Match, Template  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cdk"))
from stacks.sovereign_shield_stack import (  # noqa: E402
    DATA_DELETION_ACKNOWLEDGEMENT,
    SUPPORTED_REGIONS,
    ReleaseArtifacts,
    SovereignShieldStack,
)


def _template(artifacts: ReleaseArtifacts | None = None, **context: str) -> Template:
    app = cdk.App(context=context)
    stack = SovereignShieldStack(
        app,
        "TestStack",
        artifacts=artifacts,
        synthesizer=cdk.BootstraplessSynthesizer() if artifacts else None,
        env=cdk.Environment(account="111111111111", region="eu-central-1"),
    )
    return Template.from_stack(stack)


@pytest.fixture(scope="module")
def template() -> Template:
    return _template(allowedOrigins="https://console.example.com")


@pytest.fixture(scope="module")
def release_template() -> Template:
    return _template(ReleaseArtifacts(version="1.0.0", bucket_prefix="vendor-releases"))


@pytest.fixture(scope="module")
def nonprod_release_template() -> Template:
    return _template(ReleaseArtifacts(version="1.0.0", bucket_prefix="vendor-releases"), dataRemovalPolicy="DESTROY")


def _statements(template: Template) -> list[dict]:
    statements: list[dict] = []
    for policy in template.find_resources("AWS::IAM::Policy").values():
        statements.extend(policy["Properties"]["PolicyDocument"]["Statement"])
    return statements


def _actions(statement: dict) -> list[str]:
    actions = statement["Action"]
    return [actions] if isinstance(actions, str) else actions


def test_prototype_resources_are_not_deployed(template):
    for resource_type in ("AWS::AppRunner::Service", "AWS::ApiGateway::RestApi"):
        assert template.find_resources(resource_type) == {}
    # The prototype's fixed daily scan rule is gone: installation never schedules scans.
    # The only rule allowed refreshes onboarding status, and only in AWS Organizations mode.
    for rule in template.find_resources("AWS::Events::Rule").values():
        assert rule["Condition"] == "IsOrganizationMode"
        targets = json.dumps(rule["Properties"]["Targets"])
        assert "OnboardingFunction" in targets
        assert "ScanStateMachine" not in targets and "WorkflowFunction" not in targets
    product_functions = [
        function
        for function in template.find_resources("AWS::Lambda::Function").values()
        if str(function["Properties"].get("Handler", "")).startswith("sovereign_shield.")
    ]
    assert len(product_functions) == 5  # api, workflow, deployment, readiness, onboarding
    for function in product_functions:
        assert "Layers" not in function["Properties"]
        assert "FunctionName" not in function["Properties"]


def test_every_api_route_requires_jwt_authorization(template):
    routes = template.find_resources("AWS::ApiGatewayV2::Route")
    assert len(routes) == 15
    for route in routes.values():
        assert route["Properties"]["AuthorizationType"] == "JWT"
        assert route["Properties"]["RouteKey"].split(" ")[1].startswith("/v1/")


def test_cors_allows_only_the_console_and_configured_origins(template):
    api = next(iter(template.find_resources("AWS::ApiGatewayV2::Api").values()))
    origins = api["Properties"]["CorsConfiguration"]["AllowOrigins"]

    assert "*" not in origins
    assert "https://console.example.com" in origins
    console_origin = next(origin for origin in origins if isinstance(origin, dict))
    assert "ConsoleDistribution" in json.dumps(console_origin)


def test_wildcard_cors_origin_is_rejected():
    with pytest.raises(ValueError, match="allowedOrigins"):
        _template(allowedOrigins="*")


def test_deployment_prefix_is_validated_by_the_template(template):
    parameter = template.to_json()["Parameters"]["DeploymentPrefix"]
    assert parameter["AllowedPattern"] == r"^[a-z][a-z0-9-]{2,23}$"
    assert parameter["Default"] == "sovereign-shield"

def test_customer_data_is_encrypted_retained_and_recoverable(template):
    tables = template.find_resources("AWS::DynamoDB::Table")
    assert len(tables) == 3  # runs, findings, audit
    for table in tables.values():
        assert table["DeletionPolicy"] == "Retain"
        properties = table["Properties"]
        assert properties["SSESpecification"]["SSEEnabled"] is True
        assert properties["SSESpecification"]["SSEType"] == "KMS"
        assert properties["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"] is True
        assert [key["AttributeName"] for key in properties["KeySchema"]] == ["pk", "sk"]

    template.has_resource(
        "AWS::S3::Bucket",
        {
            "DeletionPolicy": "Retain",
            "Properties": Match.object_like({
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                },
                "BucketEncryption": Match.object_like({
                    "ServerSideEncryptionConfiguration": [
                        Match.object_like({
                            "ServerSideEncryptionByDefault": Match.object_like({"SSEAlgorithm": "aws:kms"})
                        })
                    ]
                }),
            }),
        },
    )
    for log_group in template.find_resources("AWS::Logs::LogGroup").values():
        assert "KmsKeyId" in log_group["Properties"]
        assert "RetentionInDays" in log_group["Properties"]


# Actions AWS documents as requiring `Resource: *`: X-Ray tracing, Step Functions
# vended log delivery, and namespace-conditioned custom metrics.
_UNSCOPED_ACTION_ALLOWLIST = {
    "cloudwatch:PutMetricData",
    "logs:CreateLogDelivery",
    "logs:GetLogDelivery",
    "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery",
    "logs:ListLogDeliveries",
    "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies",
    "logs:DescribeLogGroups",
    # CDK's deploy-time console upload function (BucketDeployment) invalidates
    # the CDN cache; it has no access to customer data. Phase 4 replaces it
    # with published release artifacts.
    "cloudfront:CreateInvalidation",
    "cloudfront:GetInvalidation",
}


def test_runtime_roles_cannot_assume_member_roles_or_use_unscoped_writes(template):
    for statement in _statements(template):
        actions = _actions(statement)
        if "sts:AssumeRole" in actions:
            # Only the organization-scoped member-role statement may assume roles.
            assert statement["Sid"] == "AssumeMemberScanRoleInSelectedOUs"
            continue
        assert not any(action.endswith(":*") or action == "*" for action in actions)
        if statement.get("Resource") == "*":
            assert all(
                action.split(":")[1].startswith(("List", "Describe", "Get"))
                or action.startswith("xray:")
                or action in _UNSCOPED_ACTION_ALLOWLIST
                for action in actions
            ), actions


def test_scheduler_role_trust_is_scoped_to_the_schedule_group(template):
    roles = template.find_resources("AWS::IAM::Role")
    scheduler_trusts = [
        statement
        for role in roles.values()
        for statement in role["Properties"]["AssumeRolePolicyDocument"]["Statement"]
        if statement["Principal"].get("Service") == "scheduler.amazonaws.com"
    ]
    assert len(scheduler_trusts) == 1
    assert scheduler_trusts[0]["Condition"]["StringEquals"]["aws:SourceAccount"] == {"Ref": "AWS::AccountId"}
    assert "aws:SourceArn" in scheduler_trusts[0]["Condition"]["ArnEquals"]


def test_state_machine_records_failures_and_admits_scheduled_runs(template):
    state_machine = next(iter(template.find_resources("AWS::StepFunctions::StateMachine").values()))
    parts = state_machine["Properties"]["DefinitionString"]["Fn::Join"][1]
    # Token parts (Lambda ARNs) are spliced in between quotes; replace them with a placeholder.
    definition = json.loads("".join(part if isinstance(part, str) else "ref" for part in parts))
    states = definition["States"]

    assert definition["StartAt"] == "IsScheduledExecution"
    assert states["AdmitScheduledRun"]["Next"] == "PrepareRun"
    assert states["PrepareRun"]["Next"] == "HasWorkItems"
    assert states["ScanWorkItems"]["Next"] == "FinalizeRun"
    assert states["FinalizeRun"]["Next"] == "CheckRunOutcome"
    for name in ("PrepareRun", "ScanWorkItems", "FinalizeRun"):
        assert states[name]["Catch"][0]["Next"] == "MarkRunFailed", name
    for name in ("PrepareRun", "FinalizeRun"):
        assert "States.ALL" not in json.dumps(states[name]["Retry"]), name
    assert states["MarkRunFailed"]["Parameters"]["action"] == "mark_failed"
    assert state_machine["Properties"]["StateMachineType"] == "STANDARD"
    assert state_machine["Properties"]["LoggingConfiguration"]["IncludeExecutionData"] is False


def test_work_items_fan_out_with_bounded_concurrency_and_per_unit_failure_capture(template):
    state_machine = next(iter(template.find_resources("AWS::StepFunctions::StateMachine").values()))
    parts = state_machine["Properties"]["DefinitionString"]["Fn::Join"][1]
    states = json.loads("".join(part if isinstance(part, str) else "ref" for part in parts))["States"]
    fan_out = states["ScanWorkItems"]
    worker_states = fan_out["ItemProcessor"]["States"]

    assert fan_out["Type"] == "Map"
    assert fan_out["MaxConcurrencyPath"] == "$.prepared.maxConcurrency"
    assert fan_out["ItemsPath"] == "$.prepared.workItems"
    assert fan_out["ResultPath"] is None
    assert worker_states["ExecuteWorkItem"]["Catch"][0]["Next"] == "RecordWorkItemFailure"
    assert "States.ALL" not in json.dumps(worker_states["ExecuteWorkItem"]["Retry"])
    assert worker_states["RecordWorkItemFailure"]["Parameters"]["action"] == "record_work_item_failure"


def test_scan_concurrency_is_a_bounded_launch_parameter(template):
    parameter = template.to_json()["Parameters"]["ScanConcurrency"]
    assert (parameter["MinValue"], parameter["MaxValue"], parameter["Default"]) == (1, 40, 10)

def test_work_item_results_are_transient_and_scoped(template):
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {"LifecycleConfiguration": {"Rules": Match.array_with([
            Match.object_like({"Id": "TransientWorkItemResults", "Prefix": "work/", "ExpirationInDays": 7}),
        ])}},
    )
    statements = {statement.get("Sid"): statement for statement in _statements(template)}
    assert set(_actions(statements["WorkItemResults"])) == {"s3:PutObject", "s3:GetObject"}
    assert statements["WorkItemResultLookups"]["Condition"] == {"StringLike": {"s3:prefix": ["work/*"]}}


def test_operations_alarms_notify_the_alert_topic(template):
    alarms = template.find_resources("AWS::CloudWatch::Alarm")
    assert len(alarms) >= 9
    for alarm in alarms.values():
        assert alarm["Properties"]["AlarmActions"]
    template.resource_count_is("AWS::CloudWatch::Dashboard", 1)
    template.has_resource("AWS::SNS::Subscription", {
        "Condition": "HasNotificationEmail",
        "Properties": Match.object_like({"Protocol": "email", "Endpoint": {"Ref": "NotificationEmail"}}),
    })


def _api_role_statements(template: Template) -> dict[str, dict]:
    policies = template.find_resources("AWS::IAM::Policy")
    api_policy = next(
        policy for policy in policies.values()
        if "ApiFunctionRole" in json.dumps(policy["Properties"]["Roles"])
    )
    return {statement.get("Sid"): statement for statement in api_policy["Properties"]["PolicyDocument"]["Statement"]}


def test_audit_table_is_append_only_for_the_api(template):
    statements = _api_role_statements(template)

    assert set(_actions(statements["AppendAndReadAuditEvents"])) == {"dynamodb:PutItem", "dynamodb:Query"}
    audit_resources = json.dumps(statements["AppendAndReadAuditEvents"]["Resource"])
    for statement in statements.values():
        if "AuditTableV1" in json.dumps(statement.get("Resource")):
            assert not {"dynamodb:UpdateItem", "dynamodb:DeleteItem"} & set(_actions(statement))
    assert "AuditTableV1" in audit_resources


def test_api_can_sign_only_report_downloads_and_list_through_the_index(template):
    statements = _api_role_statements(template)

    assert _actions(statements["SignReportDownloads"]) == ["s3:GetObject"]
    assert "/reports/*" in json.dumps(statements["SignReportDownloads"]["Resource"])
    assert "/index/by-entity-created" in json.dumps(statements["ListRunsAndSchedules"]["Resource"])
    template.has_resource_properties("AWS::DynamoDB::Table", {
        "GlobalSecondaryIndexes": [Match.object_like({
            "IndexName": "by-entity-created",
            "KeySchema": [
                {"AttributeName": "entity_type", "KeyType": "HASH"},
                {"AttributeName": "created_at", "KeyType": "RANGE"},
            ],
        })],
    })


def test_console_is_private_behind_cloudfront_with_security_headers(template):
    distribution = next(iter(template.find_resources("AWS::CloudFront::Distribution").values()))
    config = distribution["Properties"]["DistributionConfig"]
    assert config["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "redirect-to-https"
    assert config["Origins"][0]["OriginAccessControlId"]
    template.resource_count_is("AWS::CloudFront::OriginAccessControl", 1)

    headers = next(iter(template.find_resources("AWS::CloudFront::ResponseHeadersPolicy").values()))
    security = headers["Properties"]["ResponseHeadersPolicyConfig"]["SecurityHeadersConfig"]
    csp = json.dumps(security["ContentSecurityPolicy"]["ContentSecurityPolicy"])
    assert "frame-ancestors 'none'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert security["FrameOptions"]["FrameOption"] == "DENY"
    assert security["StrictTransportSecurity"]["AccessControlMaxAgeSec"] >= 31536000

    buckets = template.find_resources("AWS::S3::Bucket")
    for bucket in buckets.values():
        assert all(bucket["Properties"]["PublicAccessBlockConfiguration"].values())


def test_console_client_uses_code_grant_with_console_callbacks_only(template):
    clients = template.find_resources("AWS::Cognito::UserPoolClient")
    console = next(
        client for client in clients.values() if client["Properties"].get("AllowedOAuthFlows")
    )["Properties"]

    assert console["AllowedOAuthFlows"] == ["code"]
    assert console["GenerateSecret"] is False
    assert console["AllowedOAuthFlowsUserPoolClient"] is True
    assert all("ConsoleDistribution" in json.dumps(url) for url in console["CallbackURLs"])
    assert all(json.dumps(url).count("/callback") == 1 for url in console["CallbackURLs"])
    template.resource_count_is("AWS::Cognito::UserPoolDomain", 1)


def test_console_dev_origins_are_validated_and_added_to_callbacks():
    with pytest.raises(ValueError, match="consoleDevOrigins"):
        _template(consoleDevOrigins="localhost:5173")

    template = _template(consoleDevOrigins="http://localhost:5173")
    clients = template.find_resources("AWS::Cognito::UserPoolClient")
    callbacks = json.dumps([client["Properties"].get("CallbackURLs") for client in clients.values()])
    assert "http://localhost:5173/callback" in callbacks


def test_release_template_needs_no_bootstrap_assets_or_cdk_helpers(release_template):
    text = json.dumps(release_template.to_json())
    resources = release_template.to_json()["Resources"]

    assert "cdk-hnb659fds" not in text
    assert "BootstrapVersion" not in text
    assert {r["Type"] for r in resources.values() if r["Type"].startswith("Custom::")} == {"Custom::ConsolePublication"}
    for function in release_template.find_resources("AWS::Lambda::Function").values():
        code = function["Properties"]["Code"]
        assert code["S3Key"] == "releases/1.0.0/lambda_package.zip"
        assert "vendor-releases-" in json.dumps(code["S3Bucket"])


def test_release_template_offers_the_documented_parameters_grouped_for_the_console(release_template):
    template_json = release_template.to_json()
    expected = {
        "DeploymentPrefix", "AdministratorEmail", "NotificationEmail", "DefaultScanRegions", "EnableScheduledScans",
        "KmsKeyMode", "ExistingKmsKeyArn", "FindingsRetentionDays", "ReportRetentionDays", "LogRetentionDays",
        "ScanConcurrency", "OrganizationMode", "IdentityProviderMode", "Environment", "Owner", "CostCenter",
        "OrganizationId", "TargetOrganizationalUnitIds", "AccountAllowlist", "AccountDenylist", "ExclusionTagKey",
        "MemberRoleName", "StackSetCallAs", "MaxAccountsPerScan", "AcknowledgeOrganizationPermissions",
        "MonthlyBudgetUsd",
    }
    assert set(template_json["Parameters"]) == expected
    assert template_json["Parameters"]["EnableScheduledScans"]["Default"] == "false"
    grouped = {
        name
        for group in template_json["Metadata"]["AWS::CloudFormation::Interface"]["ParameterGroups"]
        for name in group["Parameters"]
    }
    assert grouped == expected


def test_release_template_fails_early_outside_supported_regions(release_template):
    rule = release_template.to_json()["Rules"]["SupportedRegion"]["Assertions"][0]["Assert"]
    assert rule == {"Fn::Contains": [list(SUPPORTED_REGIONS), {"Ref": "AWS::Region"}]}


def test_existing_kms_key_replaces_the_created_key(release_template):
    resources = release_template.to_json()["Resources"]
    key = next(r for r in resources.values() if r["Type"] == "AWS::KMS::Key")
    alias = next(r for r in resources.values() if r["Type"] == "AWS::KMS::Alias")

    assert key["Condition"] == "CreateDataKey"
    assert alias["Condition"] == "CreateDataKey"
    tables = release_template.find_resources("AWS::DynamoDB::Table")
    for table in tables.values():
        assert "Fn::If" in json.dumps(table["Properties"]["SSESpecification"]["KMSMasterKeyId"])
    rule = release_template.to_json()["Rules"]["ExistingKeyRequiresArn"]
    assert rule["RuleCondition"] == {"Fn::Equals": [{"Ref": "KmsKeyMode"}, "EXISTING_KEY_ARN"]}


def test_production_release_retains_data_and_has_no_deletion_helpers(release_template):
    for resource_type in ("AWS::DynamoDB::Table", "AWS::KMS::Key", "AWS::Cognito::UserPool"):
        for resource in release_template.find_resources(resource_type).values():
            assert resource["DeletionPolicy"] == "Retain", resource_type
    reports = [
        bucket for logical_id, bucket in release_template.find_resources("AWS::S3::Bucket").items()
        if logical_id.startswith("ReportsBucket")
    ]
    assert reports[0]["DeletionPolicy"] == "Retain"
    assert "AcknowledgeDataDeletion" not in release_template.to_json()["Parameters"]
    assert release_template.find_resources("Custom::BucketEmptier") == {}


def test_nonprod_release_deletes_data_only_with_explicit_acknowledgement(nonprod_release_template):
    template_json = nonprod_release_template.to_json()
    acknowledgement = template_json["Parameters"]["AcknowledgeDataDeletion"]

    assert acknowledgement["AllowedValues"] == [DATA_DELETION_ACKNOWLEDGEMENT]
    assert "Default" not in acknowledgement
    for resource in nonprod_release_template.find_resources("AWS::DynamoDB::Table").values():
        assert resource["DeletionPolicy"] == "Delete"
    assert len(nonprod_release_template.find_resources("Custom::BucketEmptier")) == 1


def test_optional_bootstrap_administrator_is_conditional(release_template):
    for resource_type in ("AWS::Cognito::UserPoolUser", "AWS::Cognito::UserPoolUserToGroupAttachment"):
        resource = next(iter(release_template.find_resources(resource_type).values()))
        assert resource["Condition"] == "HasAdministratorEmail"


def test_release_outputs_include_the_documented_operator_values(release_template):
    outputs = release_template.to_json()["Outputs"]
    for name in (
        "ConsoleUrl", "ApiUrl", "ScanRunTableName", "FindingsTableName", "ReportsBucketName", "KmsKeyArn",
        "ScannerRoleArn", "OrganizationOnboardingStatus", "OperationsDashboardUrl", "PostDeployValidationCommand",
        "ReleaseVersion",
    ):
        assert name in outputs, name
    assert outputs["ReleaseVersion"]["Value"] == "1.0.0"
    assert "readiness.json" in json.dumps(outputs["PostDeployValidationCommand"])


def test_readiness_function_is_describe_only(release_template):
    policies = release_template.find_resources("AWS::IAM::Policy")
    readiness = next(
        policy for policy in policies.values() if "ReadinessFunctionRole" in json.dumps(policy["Properties"]["Roles"])
    )
    actions = {
        action
        for statement in readiness["Properties"]["PolicyDocument"]["Statement"]
        for action in _actions(statement)
    }
    mutating = {action for action in actions if action.split(":")[1].startswith(("Put", "Delete", "Update", "Create"))}
    assert mutating <= {"logs:CreateLogStream", "logs:PutLogEvents"}


def test_release_artifacts_are_validated():
    with pytest.raises(ValueError):
        ReleaseArtifacts(version="1.0.0/../x", bucket_prefix="vendor")
    with pytest.raises(ValueError):
        ReleaseArtifacts(version="1.0.0", bucket_prefix="Vendor_Bucket")


def test_account_global_cloudfront_names_are_unique_per_stack(release_template):
    """CloudFront names are account-wide; a second installation must not collide (found in release testing)."""

    oac = next(iter(release_template.find_resources("AWS::CloudFront::OriginAccessControl").values()))
    headers = next(iter(release_template.find_resources("AWS::CloudFront::ResponseHeadersPolicy").values()))
    oac_name = json.dumps(oac["Properties"]["OriginAccessControlConfig"]["Name"])
    headers_name = json.dumps(headers["Properties"]["ResponseHeadersPolicyConfig"]["Name"])

    for name in (oac_name, headers_name):
        assert "AWS::StackId" in name
        assert "SovereignShieldStack" not in name


def _policy_for_role(template: Template, role_fragment: str) -> list[dict]:
    policies = template.find_resources("AWS::IAM::Policy")
    return [
        statement
        for policy in policies.values()
        if role_fragment in json.dumps(policy["Properties"]["Roles"])
        for statement in policy["Properties"]["PolicyDocument"]["Statement"]
    ]


def test_only_workers_and_onboarding_assume_member_roles_and_only_inside_the_organization(release_template):
    for role in ("WorkflowFunctionRole", "OnboardingFunctionRole"):
        statement = next(s for s in _policy_for_role(release_template, role) if s.get("Sid", "").startswith("Assume"))
        assert statement["Action"] == "sts:AssumeRole"
        assert "MemberRoleName" in json.dumps(statement["Resource"])
        assert ":root" not in json.dumps(statement["Resource"])
        assert statement["Condition"]["StringEquals"] == {"aws:ResourceOrgID": {"Ref": "OrganizationId"}}
        paths = json.dumps(statement["Condition"]["ForAnyValue:StringLike"]["aws:ResourceOrgPaths"])
        assert "TargetOrganizationalUnitIds" in paths and "/*" in paths
    for role in ("ApiFunctionRole", "ReadinessFunctionRole", "DeploymentFunctionRole"):
        assert not any("sts:AssumeRole" in _actions(s) for s in _policy_for_role(release_template, role)), role


def test_member_role_stack_set_is_service_managed_and_only_in_organization_mode(release_template):
    stack_set = next(iter(release_template.find_resources("AWS::CloudFormation::StackSet").values()))
    properties = stack_set["Properties"]

    assert stack_set["Condition"] == "IsOrganizationMode"
    assert properties["PermissionModel"] == "SERVICE_MANAGED"
    assert properties["AutoDeployment"] == {"Enabled": True, "RetainStacksOnAccountRemoval": False}
    assert properties["CallAs"] == {"Ref": "StackSetCallAs"}
    assert properties["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
    # Per-account failures are reported by the onboarding sync instead of failing the central stack.
    assert properties["OperationPreferences"]["FailureTolerancePercentage"] == 100
    targets = properties["StackInstancesGroup"][0]["DeploymentTargets"]
    assert "TargetOrganizationalUnitIds" in json.dumps(targets["OrganizationalUnitIds"])
    assert targets["AccountFilterType"] == {"Fn::If": ["HasAccountDenylist", "DIFFERENCE", {"Ref": "AWS::NoValue"}]}
    parameters = {p["ParameterKey"]: json.dumps(p["ParameterValue"]) for p in properties["Parameters"]}
    assert "WorkflowFunctionRole" in parameters["CentralPrincipalArns"]
    assert "OnboardingFunctionRole" in parameters["CentralPrincipalArns"]
    assert "AWS::StackId" in parameters["ExternalId"]


def test_member_role_template_is_read_only_and_trusts_only_the_central_roles():
    from stacks.member_role import SCANNER_READ_ACTIONS, member_role_template

    template = member_role_template()
    role = template["Resources"]["SovereignShieldScanRole"]["Properties"]
    trust = role["AssumeRolePolicyDocument"]["Statement"][0]
    actions = role["Policies"][0]["PolicyDocument"]["Statement"][0]["Action"]

    assert trust["Principal"] == {"AWS": {"Ref": "CentralPrincipalArns"}}
    assert trust["Condition"]["StringEquals"] == {
        "sts:ExternalId": {"Ref": "ExternalId"},
        "aws:PrincipalOrgID": {"Ref": "OrganizationId"},
    }
    assert actions == SCANNER_READ_ACTIONS
    assert all(action.split(":")[1].startswith(("List", "Describe", "Get")) for action in actions)
    assert role["MaxSessionDuration"] == 3600


def test_central_scanner_and_member_roles_share_one_action_list(release_template):
    from stacks.member_role import SCANNER_READ_ACTIONS

    discovery = next(s for s in _policy_for_role(release_template, "WorkflowFunctionRole")
                     if s.get("Sid") == "ReadOnlyDiscovery")
    assert _actions(discovery) == SCANNER_READ_ACTIONS


def test_organization_mode_requires_id_ous_and_acknowledgement(release_template):
    template_json = release_template.to_json()
    rule = template_json["Rules"]["OrganizationModeRequirements"]

    assert rule["RuleCondition"] == {"Fn::Equals": [{"Ref": "OrganizationMode"}, "AWS_ORGANIZATIONS"]}
    assert len(rule["Assertions"]) == 3
    assert template_json["Parameters"]["OrganizationMode"]["AllowedValues"] == ["SINGLE_ACCOUNT", "AWS_ORGANIZATIONS"]
    assert template_json["Parameters"]["OrganizationMode"]["Default"] == "SINGLE_ACCOUNT"
    assert template_json["Parameters"]["AcknowledgeOrganizationPermissions"]["Default"] == ""


def test_onboarding_sync_runs_on_a_schedule_only_in_organization_mode(release_template):
    rule = next(iter(release_template.find_resources("AWS::Events::Rule").values()))
    permission = next(
        p for p in release_template.find_resources("AWS::Lambda::Permission").values()
        if p["Properties"]["Principal"] == "events.amazonaws.com"
    )

    assert rule["Condition"] == permission["Condition"] == "IsOrganizationMode"
    assert rule["Properties"]["ScheduleExpression"] == "rate(6 hours)"


def test_api_can_request_an_onboarding_sync_but_not_assume_roles(release_template):
    statements = {s.get("Sid"): s for s in _policy_for_role(release_template, "ApiFunctionRole")}

    assert _actions(statements["RequestOnboardingSync"]) == ["lambda:InvokeFunction"]
    assert "OnboardingFunction" in json.dumps(statements["RequestOnboardingSync"]["Resource"])


def test_organization_settings_reach_every_function_that_needs_them(release_template):
    functions = release_template.find_resources("AWS::Lambda::Function")
    for name in ("Workflow", "Api", "Onboarding", "Readiness"):
        function = next(f for logical_id, f in functions.items() if logical_id.startswith(f"{name}Function"))
        variables = function["Properties"]["Environment"]["Variables"]
        for key in ("ORGANIZATION_MODE", "ORGANIZATION_ID", "TARGET_OU_IDS", "SCAN_ROLE_EXTERNAL_ID",
                    "ACCOUNT_DENYLIST", "EXCLUSION_TAG_KEY", "MAX_ACCOUNTS_PER_SCAN"):
            assert key in variables, (name, key)


def test_every_router_route_is_registered_on_the_http_api(template):
    """The Lambda router and API Gateway must expose the same routes (a gap here is a silent 404)."""

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from sovereign_shield.lambda_handler import _ROUTES

    deployed = {
        route["Properties"]["RouteKey"].replace("{scanRunId}", "{id}").replace("{scheduleId}", "{id}")
        .replace("{accountId}", "{id}")
        for route in template.find_resources("AWS::ApiGatewayV2::Route").values()
    }
    routed = {f"{method} {pattern}" for _, method, pattern, _ in _ROUTES}
    assert deployed == routed


def test_logged_failures_have_metric_filters_and_alarms(release_template):
    filters = {
        f["Properties"]["MetricTransformations"][0]["MetricName"]: f["Properties"]["FilterPattern"]
        for f in release_template.find_resources("AWS::Logs::MetricFilter").values()
    }
    assert filters == {"AuditWriteFailures": '"AUDIT_WRITE_FAILED"', "AuthorizationDenials": '"AUTHORIZATION_DENIED"'}
    alarms = release_template.find_resources("AWS::CloudWatch::Alarm")
    for logical_prefix in ("AuditWriteFailuresAlarm", "AuthorizationDenialsAlarm", "OnboardingErrorsAlarm"):
        assert any(logical_id.startswith(logical_prefix) for logical_id in alarms), logical_prefix
    assert len(alarms) == 12


def test_optional_budget_is_off_by_default_and_uniquely_named(release_template):
    template_json = release_template.to_json()
    budget = next(iter(release_template.find_resources("AWS::Budgets::Budget").values()))

    assert template_json["Parameters"]["MonthlyBudgetUsd"]["Default"] == 0
    assert budget["Condition"] == "HasMonthlyBudget"
    assert "AWS::StackId" in json.dumps(budget["Properties"]["Budget"]["BudgetName"])
    assert budget["Properties"]["Budget"]["CostFilters"] == {"TagKeyValue": ["user:Application$SovereignShield"]}
