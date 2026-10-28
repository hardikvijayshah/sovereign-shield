"""Tests for safe scan notifications and operational metrics."""

from __future__ import annotations

from sovereign_shield.models.contracts import (
    EvaluationResult,
    FindingRecord,
    ScanRequest,
    ScanRun,
    ScanService,
    ScanStatus,
)
from sovereign_shield.services.operations import (
    CloudWatchScanMetricsPublisher,
    ScanOutcomeNotifier,
    SnsNotificationPublisher,
)


def _run(status: ScanStatus) -> ScanRun:
    return ScanRun(
        scan_run_id="run-123",
        request=ScanRequest(scan_regions=["eu-central-1"], services=[ScanService.S3]),
        request_fingerprint="fingerprint",
        status=status,
    )


def _evaluation(severity: str) -> EvaluationResult:
    return EvaluationResult(
        scan_run_id="run-123",
        rule_pack_version="test",
        findings=[
            FindingRecord(
                finding_id="finding-123",
                scan_run_id="run-123",
                region="eu-central-1",
                service=ScanService.S3,
                resource_arn="arn:aws:s3:::customer-data",
                resource_name="customer-data",
                rule_id="gdpr:test",
                rule_pack_version="test",
                severity=severity,
                description="test",
                evidence_ids=["evidence-123"],
            )
        ],
    )


def test_notifications_are_limited_to_failed_or_critical_outcomes():
    class Publisher:
        def __init__(self) -> None:
            self.messages = []

        def publish(self, *, subject, message):
            self.messages.append((subject, message))

    publisher = Publisher()
    notifier = ScanOutcomeNotifier(publisher=publisher)

    notifier.notify(run=_run(ScanStatus.COMPLETE), evaluation=_evaluation("high"))
    notifier.notify(run=_run(ScanStatus.COMPLETE), evaluation=_evaluation("critical"))

    assert len(publisher.messages) == 1
    assert "Critical findings: 1" in publisher.messages[0][1]
    assert "arn:aws" not in publisher.messages[0][1]


def test_sns_and_cloudwatch_adapters_emit_only_expected_operational_data():
    class SnsClient:
        def __init__(self) -> None:
            self.request = {}

        def publish(self, **kwargs):
            self.request = kwargs

    class CloudWatchClient:
        def __init__(self) -> None:
            self.request = {}

        def put_metric_data(self, **kwargs):
            self.request = kwargs

    sns_client = SnsClient()
    cloudwatch_client = CloudWatchClient()
    SnsNotificationPublisher(client=sns_client, topic_arn="arn:aws:sns:eu-central-1:123:alerts").publish(
        subject="Scan complete",
        message="Review the console.",
    )
    CloudWatchScanMetricsPublisher(client=cloudwatch_client).publish(
        run=_run(ScanStatus.PARTIAL),
        evaluation=_evaluation("high"),
    )

    assert sns_client.request["TopicArn"].endswith(":alerts")
    assert cloudwatch_client.request["Namespace"] == "SovereignShield/Scans"
    assert {entry["MetricName"] for entry in cloudwatch_client.request["MetricData"]} == {
        "CompletedRuns",
        "CoverageGaps",
        "Findings",
    }
