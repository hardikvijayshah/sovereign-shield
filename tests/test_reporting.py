"""Tests for deterministic report generation and private object writes."""

from __future__ import annotations

import json

from sovereign_shield.models.contracts import ScanRequest, ScanService
from sovereign_shield.services import (
    DeterministicReportGenerator,
    InMemoryReportStore,
    evaluate_scan,
    execute_scan,
)
from sovereign_shield.services.reporting import S3ReportStore


def _scan() -> tuple:
    request = ScanRequest(
        scan_regions=["eu-central-1"],
        services=[ScanService.S3],
        regulations=["gdpr"],
        data_categories=["personal_data"],
    )
    scan = execute_scan(
        request,
        scan_run_id="report-test",
        scanners={
            ScanService.S3: lambda region, account_id: json.dumps(
                {
                    "resources": [],
                    "flows": [
                        {
                            "resource_name": "customer-data",
                            "resource_arn": "arn:aws:s3:::customer-data",
                            "source_region": region,
                            "destination_regions": ["us-east-1"],
                            "flow_type": "replication",
                            "encryption_enabled": True,
                        }
                    ],
                }
            )
        },
    )
    return scan, evaluate_scan(scan, rule_pack_version="test-rule-pack")


def test_deterministic_report_is_reproducible_and_has_finding_evidence():
    scan, evaluation = _scan()
    generator = DeterministicReportGenerator()

    first_record, first_content = generator.generate(scan=scan, evaluation=evaluation)
    second_record, second_content = generator.generate(scan=scan, evaluation=evaluation)

    assert first_record.report_id == second_record.report_id
    assert first_record.sha256 == second_record.sha256
    assert first_content == second_content
    assert b"Sovereign Shield Scan Report" in first_content
    assert evaluation.findings[0].evidence_ids[0].encode() in first_content


def test_report_stores_keep_report_metadata_and_use_kms_when_configured():
    scan, evaluation = _scan()
    record, content = DeterministicReportGenerator().generate(scan=scan, evaluation=evaluation)
    in_memory = InMemoryReportStore()

    saved = in_memory.write(record, content)

    class S3Client:
        def __init__(self) -> None:
            self.request = {}

        def put_object(self, **kwargs):
            self.request = kwargs

    client = S3Client()
    s3_store = S3ReportStore(client=client, bucket_name="customer-reports", kms_key_id="key-arn")
    s3_store.write(record, content)

    assert in_memory.get(scan.scan_run_id) == saved
    assert client.request["Bucket"] == "customer-reports"
    assert client.request["Key"] == record.object_key
    assert client.request["ServerSideEncryption"] == "aws:kms"
    assert client.request["Metadata"]["sha256"] == record.sha256
