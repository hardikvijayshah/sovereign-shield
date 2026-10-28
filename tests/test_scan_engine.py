"""Tests for deterministic direct scanner execution."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from sovereign_shield.models.contracts import ScanRequest, ScanService, ScanStatus
from sovereign_shield.services.scan_engine import execute_scan


def _scanner_response(region: str, account_id: str) -> str:
    return json.dumps(
        {
            "resources": [
                {
                    "service": "S3",
                    "resource_name": f"bucket-{region}",
                    "resource_arn": f"arn:aws:s3:::{account_id}-{region}",
                    "region": region,
                    "encryption_at_rest": True,
                }
            ],
            "flows": [
                {
                    "service": "S3",
                    "resource_name": f"bucket-{region}",
                    "resource_arn": f"arn:aws:s3:::{account_id}-{region}",
                    "source_region": region,
                    "destination_regions": ["eu-west-1"],
                    "flow_type": "replication",
                    "encryption_enabled": True,
                }
            ],
        }
    )


def test_execute_scan_invokes_requested_scanners_without_an_agent():
    calls: list[tuple[str, str]] = []

    def scanner(region: str, account_id: str) -> str:
        calls.append((region, account_id))
        return _scanner_response(region, account_id)

    request = ScanRequest(
        scan_regions=["eu-central-1", "eu-west-1"],
        services=[ScanService.S3],
        regulations=["gdpr"],
    )

    result = execute_scan(
        request,
        account_id="123456789012",
        scan_run_id="test-run",
        scanners={ScanService.S3: scanner},
    )

    assert calls == [("eu-central-1", "123456789012"), ("eu-west-1", "123456789012")]
    assert result.status is ScanStatus.COMPLETE
    assert len(result.resources) == 2
    assert len(result.flows) == 2
    assert result.resources[0].evidence_id
    assert result.resources[0].account_id == "123456789012"


def test_execute_scan_runs_global_services_once():
    calls: list[str] = []

    def scanner(region: str, account_id: str) -> str:
        calls.append(region)
        return json.dumps({"resources": [], "flows": []})

    request = ScanRequest(
        scan_regions=["eu-central-1", "eu-west-1"],
        services=[ScanService.CLOUDFRONT],
    )

    result = execute_scan(request, scanners={ScanService.CLOUDFRONT: scanner})

    assert calls == ["eu-central-1"]
    assert result.status is ScanStatus.COMPLETE


def test_execute_scan_records_scanner_failures_as_coverage_gaps():
    def failing_scanner(region: str, account_id: str) -> str:
        raise PermissionError("Access denied")

    request = ScanRequest(scan_regions=["eu-central-1"], services=[ScanService.S3])
    result = execute_scan(request, scanners={ScanService.S3: failing_scanner})

    assert result.status is ScanStatus.PARTIAL
    assert result.coverage_gaps[0].code == "scanner_exception"
    # Raw exception text is withheld from stored gaps (plan.md section 5.3).
    assert result.coverage_gaps[0].message == "PermissionError (details withheld)."


def test_execute_scan_records_invalid_scanner_responses_as_coverage_gaps():
    request = ScanRequest(scan_regions=["eu-central-1"], services=[ScanService.S3])
    result = execute_scan(request, scanners={ScanService.S3: lambda **_: "not-json"})

    assert result.status is ScanStatus.PARTIAL
    assert result.coverage_gaps[0].code == "invalid_scanner_response"


def test_execute_scan_normalizes_valid_evidence_when_other_records_are_malformed():
    def mixed_scanner(region: str, account_id: str) -> dict:
        return {
            "resources": [
                {
                    "resource_name": "valid-bucket",
                    "resource_arn": "arn:aws:s3:::valid-bucket",
                    "encryption_at_rest": True,
                },
                "not-an-object",
            ],
            "flows": [
                {
                    "resource_name": "valid-bucket",
                    "resource_arn": "arn:aws:s3:::valid-bucket",
                    "source_region": region,
                    "destination_regions": ["eu-west-1"],
                    "flow_type": "replication",
                },
                {
                    "resource_name": "invalid-flow",
                    "resource_arn": "arn:aws:s3:::invalid-flow",
                    "source_region": region,
                    "destination_regions": "eu-west-1",
                    "flow_type": "replication",
                },
            ],
        }

    request = ScanRequest(scan_regions=["eu-central-1"], services=[ScanService.S3])
    result = execute_scan(request, scanners={ScanService.S3: mixed_scanner})

    assert result.status is ScanStatus.PARTIAL
    assert [resource.resource_name for resource in result.resources] == ["valid-bucket"]
    assert [flow.resource_name for flow in result.flows] == ["valid-bucket"]
    assert {gap.code for gap in result.coverage_gaps} == {
        "invalid_resource_evidence",
        "invalid_flow_evidence",
    }


def test_execute_scan_deduplicates_repeated_normalized_evidence():
    repeated = json.loads(_scanner_response("eu-west-1", "123456789012"))
    repeated["resources"].append(repeated["resources"][0])
    repeated["flows"].append(repeated["flows"][0])
    request = ScanRequest(scan_regions=["eu-west-1"], services=[ScanService.S3])

    result = execute_scan(request, scan_run_id="test-run", scanners={ScanService.S3: lambda **_: repeated})

    assert len(result.resources) == 1
    assert len(result.flows) == 1
    assert result.status is ScanStatus.COMPLETE


def test_scan_request_rejects_duplicate_regions_and_services():
    with pytest.raises(ValidationError):
        ScanRequest(scan_regions=["eu-west-1", "eu-west-1"], services=[ScanService.S3])

    with pytest.raises(ValidationError):
        ScanRequest(scan_regions=["eu-west-1"], services=[ScanService.S3, ScanService.S3])


def test_execute_scan_rejects_unknown_regulations():
    request = ScanRequest(
        scan_regions=["eu-west-1"],
        services=[ScanService.S3],
        regulations=["not-a-regulation"],
    )

    with pytest.raises(ValueError, match="Unknown regulations"):
        execute_scan(request, scanners={ScanService.S3: _scanner_response})



def test_scanner_errors_keep_only_the_aws_error_code_and_operation():
    from sovereign_shield.services.scan_engine import redact_error_text

    raw = (
        "An error occurred (AccessDenied) when calling the AssumeRole operation: User: "
        "arn:aws:sts::111111111111:assumed-role/worker/x is not authorized to perform: sts:AssumeRole on "
        "resource: arn:aws:iam::222222222222:role/SovereignShieldScanRole"
    )

    assert redact_error_text(raw) == "AccessDenied calling AssumeRole"
    assert "222222222222" not in redact_error_text(raw)
    assert redact_error_text("bucket customer-pii-eu not found").startswith("Scanner error (details withheld")


def test_validation_gaps_never_echo_scanned_input_values():
    from pydantic import BaseModel, ValidationError

    from sovereign_shield.services.scan_engine import redact_exception

    class Record(BaseModel):
        region: int

    try:
        Record(region="secret-bucket-name-in-eu")
    except ValidationError as exc:
        message = redact_exception(exc)

    assert message == "Invalid fields: region: int_parsing"
    assert "secret-bucket-name" not in message


def test_scanner_error_payloads_are_redacted_before_they_become_gaps():
    def erroring_scanner(region: str, account_id: str) -> str:
        return json.dumps({"error": "An error occurred (ThrottlingException) when calling the ListKeys operation: "
                                    "Rate exceeded for account 111111111111"})

    request = ScanRequest(scan_regions=["eu-central-1"], services=[ScanService.KMS], regulations=["gdpr"])
    result = execute_scan(request, scanners={ScanService.KMS: erroring_scanner})

    assert result.coverage_gaps[0].message == "ThrottlingException calling ListKeys"
