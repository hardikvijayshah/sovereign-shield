"""Tests for typed deterministic policy evaluation."""

from __future__ import annotations

import json

import pytest

from sovereign_shield.models.contracts import ScanRequest, ScanService
from sovereign_shield.services import evaluate_scan, execute_scan


def _eu_to_us_scanner(region: str, account_id: str) -> str:
    return json.dumps(
        {
            "resources": [
                {
                    "service": "S3",
                    "resource_name": "customer-pii",
                    "resource_arn": "arn:aws:s3:::customer-pii",
                    "region": region,
                    "encryption_at_rest": True,
                }
            ],
            "flows": [
                {
                    "service": "S3",
                    "resource_name": "customer-pii",
                    "resource_arn": "arn:aws:s3:::customer-pii",
                    "source_region": region,
                    "destination_regions": ["us-east-1"],
                    "flow_type": "replication",
                    "encryption_enabled": True,
                }
            ],
        }
    )


def test_evaluate_scan_returns_stable_evidence_linked_findings():
    request = ScanRequest(
        scan_regions=["eu-central-1"],
        services=[ScanService.S3],
        regulations=["gdpr"],
    )
    scan = execute_scan(
        request,
        account_id="123456789012",
        scan_run_id="scan-001",
        scanners={ScanService.S3: _eu_to_us_scanner},
    )

    result = evaluate_scan(scan, rule_pack_version="test-rule-pack")
    retry_result = evaluate_scan(scan, rule_pack_version="test-rule-pack")

    assert result.total_findings == 1
    finding = result.findings[0]
    assert finding.scan_run_id == "scan-001"
    assert finding.account_id == "123456789012"
    assert finding.service is ScanService.S3
    assert finding.rule_pack_version == "test-rule-pack"
    assert finding.finding_state == "potential"
    assert set(finding.evidence_ids) == {scan.flows[0].evidence_id, scan.resources[0].evidence_id}
    assert retry_result.findings[0].finding_id == finding.finding_id


def test_evaluate_scan_applies_only_customer_selected_data_categories():
    personal_data_request = ScanRequest(
        scan_regions=["eu-central-1"],
        services=[ScanService.S3],
        regulations=["gdpr"],
        data_categories=["personal_data"],
    )
    sensitive_data_request = personal_data_request.model_copy(
        update={"data_categories": ["sensitive_personal_data"]}
    )
    personal_scan = execute_scan(
        personal_data_request,
        scan_run_id="personal-data",
        scanners={ScanService.S3: _eu_to_us_scanner},
    )
    sensitive_scan = execute_scan(
        sensitive_data_request,
        scan_run_id="sensitive-data",
        scanners={ScanService.S3: _eu_to_us_scanner},
    )

    personal_finding = evaluate_scan(personal_scan).findings[0]
    sensitive_finding = evaluate_scan(sensitive_scan).findings[0]

    assert personal_finding.severity == "high"
    assert sensitive_finding.severity == "critical"
    assert personal_finding.rule_id.endswith(":0")
    assert sensitive_finding.rule_id.endswith(":1")


@pytest.mark.parametrize(
    ("regulation", "data_category", "source_region", "destination_region", "severity"),
    [
        ("gdpr", "personal_data", "eu-central-1", "us-east-1", "high"),
        ("gdpr", "sensitive_personal_data", "eu-central-1", "us-east-1", "critical"),
        ("eu-data-act", "iot_data", "eu-central-1", "us-east-1", "high"),
        ("dpdp", "personal_data", "ap-south-1", "cn-north-1", "critical"),
        ("dpdp", "critical_personal_data", "ap-south-1", "us-east-1", "critical"),
        ("pipl", "personal_data", "cn-north-1", "ap-south-1", "critical"),
        ("lgpd", "personal_data", "sa-east-1", "ap-south-1", "high"),
        ("dora", "financial_data", "eu-central-1", "us-east-1", "high"),
        ("nis2", "network_security_data", "eu-central-1", "us-east-1", "high"),
    ],
)
def test_evaluate_scan_covers_each_supported_regulation_constraint(
    regulation: str,
    data_category: str,
    source_region: str,
    destination_region: str,
    severity: str,
):
    def scanner(region: str, account_id: str) -> dict:
        return {
            "resources": [],
            "flows": [
                {
                    "resource_name": "regulated-data",
                    "resource_arn": "arn:aws:s3:::regulated-data",
                    "source_region": region,
                    "destination_regions": [destination_region],
                    "flow_type": "replication",
                    "encryption_enabled": True,
                }
            ],
        }

    request = ScanRequest(
        scan_regions=[source_region],
        services=[ScanService.S3],
        regulations=[regulation],
        data_categories=[data_category],
    )
    scan = execute_scan(request, scanners={ScanService.S3: scanner})
    findings = evaluate_scan(scan).findings

    assert len(findings) == 1
    assert findings[0].severity == severity
    assert findings[0].rule_id.startswith(f"{regulation}:")
    assert findings[0].data_categories == [data_category]


def test_evaluate_scan_covers_encryption_at_rest_and_in_transit_rules():
    def unprotected_scanner(region: str, account_id: str) -> dict:
        return {
            "resources": [
                {
                    "resource_name": "regulated-data",
                    "resource_arn": "arn:aws:s3:::regulated-data",
                    "region": region,
                    "encryption_at_rest": False,
                }
            ],
            "flows": [
                {
                    "resource_name": "regulated-data",
                    "resource_arn": "arn:aws:s3:::regulated-data",
                    "source_region": region,
                    "destination_regions": ["eu-west-1"],
                    "flow_type": "replication",
                    "encryption_enabled": False,
                }
            ],
        }

    request = ScanRequest(
        scan_regions=["eu-central-1"],
        services=[ScanService.S3],
        regulations=["gdpr"],
        data_categories=["personal_data"],
    )
    scan = execute_scan(request, scanners={ScanService.S3: unprotected_scanner})
    findings = evaluate_scan(scan).findings

    assert {finding.severity for finding in findings} == {"high", "medium"}


def test_evaluate_scan_does_not_flag_adequacy_region_for_matching_constraint():
    request = ScanRequest(
        scan_regions=["eu-central-1"],
        services=[ScanService.S3],
        regulations=["gdpr"],
        data_categories=["personal_data"],
    )

    scan = execute_scan(
        request,
        scanners={
            ScanService.S3: lambda region, account_id: {
                "resources": [],
                "flows": [
                    {
                        "resource_name": "regulated-data",
                        "resource_arn": "arn:aws:s3:::regulated-data",
                        "source_region": region,
                        "destination_regions": ["ca-central-1"],
                        "flow_type": "replication",
                        "encryption_enabled": True,
                    }
                ],
            }
        },
    )

    assert evaluate_scan(scan).findings == []


def _single_finding(destination_region: str, *, encrypted_at_rest: bool = True, encrypted_in_transit: bool = True):
    def scanner(region: str, account_id: str) -> str:
        payload = json.loads(_eu_to_us_scanner(region, account_id))
        payload["resources"][0]["encryption_at_rest"] = encrypted_at_rest
        payload["flows"][0]["destination_regions"] = [destination_region] if destination_region else []
        payload["flows"][0]["encryption_enabled"] = encrypted_in_transit
        if not destination_region:
            payload["flows"] = []
        return json.dumps(payload)

    request = ScanRequest(scan_regions=["eu-central-1"], services=[ScanService.S3], regulations=["gdpr"])
    scan = execute_scan(request, account_id="123456789012", scan_run_id="scan-001", scanners={ScanService.S3: scanner})
    return evaluate_scan(scan, rule_pack_version="test-rule-pack").findings


def test_findings_are_categorized_for_guidance():
    assert {f.category for f in _single_finding("us-east-1")} == {"non_allowed_destination"}
    assert {f.category for f in _single_finding("", encrypted_at_rest=False)} == {"encryption_at_rest_missing"}
    assert {f.category for f in _single_finding("global-edge-locations")} == {"global_edge_distribution"}


def test_category_does_not_change_finding_identifiers():
    from sovereign_shield.services.policy_evaluator import _stable_id

    finding = _single_finding("us-east-1")[0]
    expected = _stable_id(
        "scan-001",
        "123456789012",
        finding.rule_id,
        finding.resource_arn,
        "eu-central-1",
        "us-east-1",
        finding.description,
    )
    assert finding.finding_id == expected


def test_guidance_is_category_and_service_specific_and_read_only():
    from sovereign_shield.services.guidance import GUIDANCE_NOTICE, guidance_for

    guidance = guidance_for({"category": "prohibited_transfer", "service": "s3"})
    fallback = guidance_for({"category": "unknown", "service": "iam"})

    assert guidance["notice"] == GUIDANCE_NOTICE
    assert "does not make changes" in GUIDANCE_NOTICE
    assert any("replication" in step for step in guidance["steps"])
    assert guidance["steps"][-1].startswith("For S3")
    assert fallback["steps"] == ["Review the finding's evidence and confirm whether in-scope data is affected."]


def test_findings_are_attributed_to_the_evidence_account_not_the_deployment_account():
    from sovereign_shield.models.contracts import DeterministicScanResult, FlowEvidence, ResourceEvidence

    request = ScanRequest(scan_regions=["eu-central-1"], services=[ScanService.S3], regulations=["gdpr"])
    common = {"region": "eu-central-1", "service": ScanService.S3, "resource_type": "bucket"}
    scan = DeterministicScanResult(
        scan_run_id="scan-002",
        account_id="111111111111",
        request=request,
        resources=[
            ResourceEvidence(evidence_id=f"r-{account}", account_id=account, resource_arn="arn:aws:s3:::shared",
                             resource_name="shared", encryption_at_rest=True, **common)
            for account in ("222222222222", "333333333333")
        ],
        flows=[
            FlowEvidence(evidence_id=f"f-{account}", account_id=account, resource_arn="arn:aws:s3:::shared",
                         resource_name="shared", source_region="eu-central-1", destination_regions=["us-east-1"],
                         flow_type="replication", encryption_enabled=True, service=ScanService.S3)
            for account in ("222222222222", "333333333333")
        ],
    )

    findings = evaluate_scan(scan, rule_pack_version="test").findings

    assert sorted(finding.account_id for finding in findings) == ["222222222222", "333333333333"]
    assert len({finding.finding_id for finding in findings}) == 2
