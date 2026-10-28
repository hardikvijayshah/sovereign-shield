"""Tests for the violation detection logic."""

import json

from sovereign_shield.tools.invocation import invoke_tool
from sovereign_shield.tools.violation_detector import check_violations


def _call_check_violations(scan_results: dict, regulations: str = "") -> dict:
    """Helper to call the tool function directly (bypassing Strands decorator)."""
    result_str = invoke_tool(
        check_violations,
        scan_results_json=json.dumps(scan_results),
        applicable_regulations=regulations,
    )
    return json.loads(result_str)


def test_s3_replication_to_us_violates_gdpr():
    scan = {
        "flows": [{
            "service": "S3",
            "resource_name": "customer-pii-prod",
            "resource_arn": "arn:aws:s3:::customer-pii-prod",
            "source_region": "eu-central-1",
            "destination_regions": ["us-east-1"],
            "flow_type": "replication",
            "encryption_enabled": True,
        }],
        "resources": [],
    }
    result = _call_check_violations(scan, "gdpr")
    assert result["total"] > 0
    violations = result["violations"]
    gdpr_violations = [v for v in violations if v["regulation_id"] == "gdpr"]
    assert len(gdpr_violations) > 0
    assert any("us-east-1" in v["description"] for v in gdpr_violations)


def test_s3_replication_within_eu_is_compliant():
    scan = {
        "flows": [{
            "service": "S3",
            "resource_name": "eu-data-bucket",
            "resource_arn": "arn:aws:s3:::eu-data-bucket",
            "source_region": "eu-central-1",
            "destination_regions": ["eu-west-1"],
            "flow_type": "replication",
            "encryption_enabled": True,
        }],
        "resources": [],
    }
    result = _call_check_violations(scan, "gdpr")
    assert result["total"] == 0


def test_unencrypted_resource_flagged():
    scan = {
        "flows": [],
        "resources": [{
            "service": "S3",
            "resource_name": "unencrypted-bucket",
            "resource_arn": "arn:aws:s3:::unencrypted-bucket",
            "region": "eu-central-1",
            "encryption_at_rest": False,
        }],
    }
    result = _call_check_violations(scan, "gdpr")
    encryption_violations = [v for v in result["violations"] if "encryption" in v["description"].lower()]
    assert len(encryption_violations) > 0


def test_pipl_blocks_all_cross_border():
    scan = {
        "flows": [{
            "service": "RDS",
            "resource_name": "china-db",
            "resource_arn": "arn:aws:rds:cn-north-1:123:db:china-db",
            "source_region": "cn-north-1",
            "destination_regions": ["ap-southeast-1"],
            "flow_type": "replication",
            "encryption_enabled": True,
        }],
        "resources": [],
    }
    result = _call_check_violations(scan, "pipl")
    assert result["total"] > 0
    assert any(v["severity"] in ("critical", "high") for v in result["violations"])


def test_dpdp_prohibited_region():
    scan = {
        "flows": [{
            "service": "DynamoDB",
            "resource_name": "india-users",
            "resource_arn": "arn:aws:dynamodb:ap-south-1:123:table/india-users",
            "source_region": "ap-south-1",
            "destination_regions": ["cn-north-1"],
            "flow_type": "replication",
            "encryption_enabled": True,
        }],
        "resources": [],
    }
    result = _call_check_violations(scan, "dpdp")
    critical = [v for v in result["violations"] if v["severity"] == "critical"]
    assert len(critical) > 0


def test_empty_scan_no_violations():
    scan = {"flows": [], "resources": []}
    result = _call_check_violations(scan)
    assert result["total"] == 0


def test_invalid_json_returns_error():
    result_str = invoke_tool(
        check_violations,
        scan_results_json="not valid json",
        applicable_regulations="",
    )
    result = json.loads(result_str)
    assert "error" in result
