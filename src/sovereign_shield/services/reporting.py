"""Deterministic report generation and customer-owned report storage adapters."""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any, Protocol

from sovereign_shield.models.contracts import (
    DeterministicScanResult,
    EvaluationResult,
    ReportGenerationMode,
    ReportRecord,
)


class ReportStore(Protocol):
    """Persistence boundary for report objects; implementations keep data customer-owned."""

    def write(self, report: ReportRecord, content: bytes) -> ReportRecord:
        """Persist report bytes and return the durable report metadata."""


class DeterministicReportGenerator:
    """Build a reproducible report from typed findings without Bedrock."""

    TEMPLATE_VERSION = "deterministic-markdown-v1"

    def generate(
        self,
        *,
        scan: DeterministicScanResult,
        evaluation: EvaluationResult,
        requested_mode: ReportGenerationMode = ReportGenerationMode.DETERMINISTIC_ONLY,
    ) -> tuple[ReportRecord, bytes]:
        """Create a stable Markdown report from persisted scan evidence."""

        report_id = hashlib.sha256(
            f"{scan.scan_run_id}|{evaluation.rule_pack_version}|{self.TEMPLATE_VERSION}".encode("utf-8")
        ).hexdigest()[:32]
        content = _render_markdown(scan, evaluation).encode("utf-8")
        report = ReportRecord(
            report_id=report_id,
            scan_run_id=scan.scan_run_id,
            generation_mode=ReportGenerationMode.DETERMINISTIC_ONLY,
            object_key=f"reports/{scan.scan_run_id}/{report_id}.md",
            sha256=hashlib.sha256(content).hexdigest(),
            byte_size=len(content),
            enrichment_status=(
                "not_requested"
                if requested_mode is ReportGenerationMode.DETERMINISTIC_ONLY
                else "not_available_fallback"
            ),
        )
        return report, content


class InMemoryReportStore:
    """Test/local report store. Never use this implementation in a deployed Lambda."""

    def __init__(self) -> None:
        self.records: dict[str, ReportRecord] = {}
        self.contents: dict[str, bytes] = {}

    def write(self, report: ReportRecord, content: bytes) -> ReportRecord:
        self.records[report.scan_run_id] = report.model_copy(deep=True)
        self.contents[report.scan_run_id] = bytes(content)
        return report.model_copy(deep=True)

    def get(self, scan_run_id: str) -> ReportRecord | None:
        report = self.records.get(scan_run_id)
        return report.model_copy(deep=True) if report else None


class S3ReportStore:
    """S3-compatible adapter for private customer-owned reports."""

    def __init__(
        self,
        *,
        client: Any,
        bucket_name: str,
        kms_key_id: str | None = None,
    ) -> None:
        self._client = client
        self._bucket_name = bucket_name
        self._kms_key_id = kms_key_id

    def write(self, report: ReportRecord, content: bytes) -> ReportRecord:
        request: dict[str, Any] = {
            "Bucket": self._bucket_name,
            "Key": report.object_key,
            "Body": content,
            "ContentType": report.content_type,
            "Metadata": {
                "scan-run-id": report.scan_run_id,
                "report-id": report.report_id,
                "sha256": report.sha256,
                "generation-mode": report.generation_mode.value,
            },
        }
        if self._kms_key_id:
            request.update(
                {
                    "ServerSideEncryption": "aws:kms",
                    "SSEKMSKeyId": self._kms_key_id,
                }
            )
        self._client.put_object(**request)
        return report


def _render_markdown(scan: DeterministicScanResult, evaluation: EvaluationResult) -> str:
    severity_counts = Counter(finding.severity.upper() for finding in evaluation.findings)
    lines = [
        "# Sovereign Shield Scan Report",
        "",
        f"- Scan run: `{scan.scan_run_id}`",
        f"- Rule pack: `{evaluation.rule_pack_version}`",
        f"- Scan status: `{scan.status.value}`",
        f"- Resources observed: {len(scan.resources)}",
        f"- Cross-region flows observed: {len(scan.flows)}",
        f"- Findings: {evaluation.total_findings}",
        f"- Coverage gaps: {len(scan.coverage_gaps)}",
        "",
        "## Finding summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| {severity} | {severity_counts.get(severity, 0)} |"
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    lines.extend(["", "## Findings", ""])
    if not evaluation.findings:
        lines.append("No findings were generated from the completed deterministic evaluation.")
    else:
        for finding in sorted(evaluation.findings, key=lambda item: (item.severity, item.finding_id)):
            lines.extend(
                [
                    f"### {finding.severity.upper()} — {finding.rule_id}",
                    "",
                    f"- Resource: `{finding.resource_arn}`",
                    f"- Region: `{finding.region}`",
                    f"- Evidence: {', '.join(finding.evidence_ids)}",
                    f"- Assessment: {finding.finding_state}",
                    f"- Uncertainty: {finding.uncertainty}",
                    "",
                    finding.description,
                    "",
                ]
            )

    lines.extend(["## Coverage", ""])
    if not scan.coverage_gaps:
        lines.append("No coverage gaps were reported by the selected deterministic scanners.")
    else:
        for gap in scan.coverage_gaps:
            lines.append(f"- `{gap.service.value}` in `{gap.region}`: {gap.code} — {gap.message}")
    lines.extend(["", f"_Template: {DeterministicReportGenerator.TEMPLATE_VERSION}_", ""])
    return "\n".join(lines)
