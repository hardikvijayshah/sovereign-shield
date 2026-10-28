"""Customer-safe notification and metrics adapters for completed scan runs."""

from __future__ import annotations

from typing import Any, Protocol

from sovereign_shield.models.contracts import EvaluationResult, ScanRun, ScanStatus


class ScanNotificationPublisher(Protocol):
    """Publishes concise opt-in scan outcome notifications."""

    def publish(self, *, subject: str, message: str) -> None:
        """Deliver a notification without exposing report or evidence content."""


class ScanMetricsPublisher(Protocol):
    """Publishes non-sensitive completion counters for CloudWatch alarms."""

    def publish(self, *, run: ScanRun, evaluation: EvaluationResult | None) -> None:
        """Emit terminal scan metrics."""


class ScanOutcomeNotifier:
    """Publishes only failed runs and runs containing critical findings."""

    def __init__(self, *, publisher: ScanNotificationPublisher) -> None:
        self._publisher = publisher

    def notify(self, *, run: ScanRun, evaluation: EvaluationResult | None) -> None:
        critical_findings = sum(
            1
            for finding in (evaluation.findings if evaluation else [])
            if finding.severity.lower() == "critical"
        )
        if run.status is not ScanStatus.FAILED and not critical_findings:
            return
        self._publisher.publish(
            subject=f"Sovereign Shield scan {run.status.value}: {run.scan_run_id}",
            message=(
                f"Scan run {run.scan_run_id} completed with status {run.status.value}. "
                f"Critical findings: {critical_findings}. "
                f"Coverage gaps: {run.progress.coverage_gap_count}. "
                "Review details in the authenticated Sovereign Shield console."
            ),
        )


class SnsNotificationPublisher:
    """SNS-compatible publisher for a customer-managed notification topic."""

    def __init__(self, *, client: Any, topic_arn: str) -> None:
        self._client = client
        self._topic_arn = topic_arn

    def publish(self, *, subject: str, message: str) -> None:
        self._client.publish(TopicArn=self._topic_arn, Subject=subject[:100], Message=message)


class CloudWatchScanMetricsPublisher:
    """CloudWatch-compatible publisher with no resource names or evidence data."""

    NAMESPACE = "SovereignShield/Scans"

    def __init__(self, *, client: Any) -> None:
        self._client = client

    def publish(self, *, run: ScanRun, evaluation: EvaluationResult | None) -> None:
        dimensions = [{"Name": "Status", "Value": run.status.value}]
        metric_data = [
            {"MetricName": "CompletedRuns", "Value": 1, "Unit": "Count", "Dimensions": dimensions},
            {
                "MetricName": "CoverageGaps",
                "Value": run.progress.coverage_gap_count,
                "Unit": "Count",
                "Dimensions": dimensions,
            },
            {
                "MetricName": "Findings",
                "Value": evaluation.total_findings if evaluation else 0,
                "Unit": "Count",
                "Dimensions": dimensions,
            },
        ]
        self._client.put_metric_data(Namespace=self.NAMESPACE, MetricData=metric_data)
