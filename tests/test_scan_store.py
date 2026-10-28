"""Tests for deterministic scan persistence adapters."""

from __future__ import annotations

import json

from sovereign_shield.models.contracts import ScanRequest, ScanService
from sovereign_shield.services import InMemoryScanStore, evaluate_scan, execute_scan
from sovereign_shield.services.scan_store import DynamoDBScanStore


def _scanner(region: str, account_id: str) -> str:
    return json.dumps(
        {
            "resources": [
                {
                    "resource_name": "customer-pii",
                    "resource_arn": "arn:aws:s3:::customer-pii",
                    "region": region,
                    "encryption_at_rest": True,
                }
            ],
            "flows": [
                {
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


def _scan_with_finding(store=None):
    scan = execute_scan(
        ScanRequest(
            scan_regions=["eu-central-1"],
            services=[ScanService.S3],
            regulations=["gdpr"],
        ),
        account_id="123456789012",
        scan_run_id="scan-store-test",
        scanners={ScanService.S3: _scanner},
        store=store,
    )
    evaluation = evaluate_scan(scan, rule_pack_version="test-rule-pack", store=store)
    return scan, evaluation


def test_in_memory_store_persists_run_evidence_and_findings():
    store = InMemoryScanStore()
    scan, evaluation = _scan_with_finding(store)

    run = store.get_run(scan.scan_run_id)
    assert run["pk"] == "RUN#scan-store-test"
    assert run["status"] == "complete"
    assert len(store.evidence[scan.scan_run_id]) == 2
    assert len(store.get_findings(scan.scan_run_id)) == evaluation.total_findings
    assert store.get_findings(scan.scan_run_id)[0]["rule_pack_version"] == "test-rule-pack"


class _FakeTable:
    def __init__(self) -> None:
        self.items = []

    def put_item(self, *, Item):
        self.items.append(Item)


def test_dynamodb_store_writes_the_documented_item_shapes():
    runs_table = _FakeTable()
    findings_table = _FakeTable()
    store = DynamoDBScanStore(runs_table=runs_table, findings_table=findings_table)

    _, evaluation = _scan_with_finding(store)

    assert runs_table.items[0]["sk"] == "SUMMARY"
    assert all(item["sk"] != "RUN" for item in runs_table.items)
    assert {item["entity_type"] for item in runs_table.items} == {
        "scan_result_summary",
        "resource_evidence",
        "flow_evidence",
    }
    assert findings_table.items[0]["sk"].startswith("FINDING#")
    assert findings_table.items[0]["rule_pack_version"] == evaluation.rule_pack_version
