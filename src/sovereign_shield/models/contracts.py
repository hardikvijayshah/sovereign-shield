"""Versioned domain contracts for deterministic sovereignty scans.

These contracts are deliberately independent of Strands and Bedrock. They are
used by the scan workers, evaluator, persistence adapters, and later API layer.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"
AWS_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$")
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")


class ScanService(str, Enum):
    """Services supported by the deterministic discovery engine."""

    S3 = "s3"
    RDS = "rds"
    DYNAMODB = "dynamodb"
    CLOUDFRONT = "cloudfront"
    KMS = "kms"
    SNS_SQS = "sns_sqs"
    TRANSIT_GATEWAY = "transit_gateway"
    LAMBDA_AT_EDGE = "lambda_at_edge"


class ScanStatus(str, Enum):
    """Lifecycle states for a durable scan run."""

    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    EVALUATING = "evaluating"
    REPORTING = "reporting"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"


class ReportGenerationMode(str, Enum):
    """Whether a scan may use Bedrock for report enrichment."""

    DETERMINISTIC_ONLY = "deterministic_only"
    BEDROCK_ENHANCED = "bedrock_enhanced"


class ScanRequest(BaseModel):
    """Validated scan intent accepted by the deterministic scan engine."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    scan_regions: list[str] = Field(min_length=1, max_length=25)
    services: list[ScanService] = Field(default_factory=lambda: list(ScanService))
    regulations: list[str] = Field(default_factory=list, max_length=20)
    data_categories: list[str] = Field(default_factory=list, max_length=30)
    report_generation_mode: ReportGenerationMode = ReportGenerationMode.DETERMINISTIC_ONLY
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)
    # Member accounts to scan. Empty means the deployment account (single-account
    # mode) or every eligible onboarded account (AWS Organizations mode).
    account_ids: list[str] = Field(default_factory=list, max_length=200)

    @field_validator("account_ids")
    @classmethod
    def validate_account_ids(cls, account_ids: list[str]) -> list[str]:
        normalized = [account_id.strip() for account_id in account_ids]
        if any(not ACCOUNT_ID_PATTERN.fullmatch(account_id) for account_id in normalized):
            raise ValueError("account_ids must contain 12-digit AWS account IDs")
        if len(set(normalized)) != len(normalized):
            raise ValueError("account_ids must not contain duplicates")
        return normalized

    @field_validator("scan_regions")
    @classmethod
    def normalize_regions(cls, regions: list[str]) -> list[str]:
        normalized = [region.strip().lower() for region in regions]
        if any(not AWS_REGION_PATTERN.fullmatch(region) for region in normalized):
            raise ValueError("scan_regions must contain valid AWS region codes")
        if len(set(normalized)) != len(normalized):
            raise ValueError("scan_regions must not contain duplicates")
        return normalized

    @field_validator("services")
    @classmethod
    def unique_services(cls, services: list[ScanService]) -> list[ScanService]:
        if not services:
            raise ValueError("at least one service must be selected")
        if len(set(services)) != len(services):
            raise ValueError("services must not contain duplicates")
        return services

    @field_validator("regulations")
    @classmethod
    def normalize_regulations(cls, regulations: list[str]) -> list[str]:
        normalized = [regulation.strip().lower() for regulation in regulations]
        if any(not regulation for regulation in normalized):
            raise ValueError("regulations must not contain empty values")
        if len(set(normalized)) != len(normalized):
            raise ValueError("regulations must not contain duplicates")
        return normalized

    @field_validator("data_categories")
    @classmethod
    def normalize_data_categories(cls, data_categories: list[str]) -> list[str]:
        normalized = [category.strip().lower() for category in data_categories]
        if any(not category for category in normalized):
            raise ValueError("data_categories must not contain empty values")
        if len(set(normalized)) != len(normalized):
            raise ValueError("data_categories must not contain duplicates")
        return normalized


class ScanCoverageGap(BaseModel):
    """A scope element that could not be assessed completely."""

    account_id: str = ""
    region: str
    service: ScanService
    code: str
    message: str
    retryable: bool = False
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ResourceEvidence(BaseModel):
    """Normalized resource evidence collected by one deterministic scanner."""

    evidence_id: str
    account_id: str = ""
    region: str
    service: ScanService
    resource_arn: str
    resource_name: str
    resource_type: str
    encryption_at_rest: bool = False
    encryption_in_transit: bool = False
    details: dict = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FlowEvidence(BaseModel):
    """Normalized cross-region flow evidence collected by one scanner."""

    evidence_id: str
    account_id: str = ""
    service: ScanService
    resource_arn: str
    resource_name: str
    source_region: str
    destination_regions: list[str] = Field(min_length=1)
    flow_type: str
    encryption_enabled: bool = False
    details: dict = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DeterministicScanResult(BaseModel):
    """Complete typed result of direct scanner execution before rule evaluation."""

    schema_version: str = SCHEMA_VERSION
    scan_run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    account_id: str = ""
    request: ScanRequest
    status: ScanStatus = ScanStatus.COMPLETE
    resources: list[ResourceEvidence] = Field(default_factory=list)
    flows: list[FlowEvidence] = Field(default_factory=list)
    coverage_gaps: list[ScanCoverageGap] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanProgress(BaseModel):
    """Bounded progress counters safe to return from the scan-status API."""

    planned_units: int = Field(default=0, ge=0)
    completed_units: int = Field(default=0, ge=0)
    failed_units: int = Field(default=0, ge=0)
    resource_count: int = Field(default=0, ge=0)
    flow_count: int = Field(default=0, ge=0)
    finding_count: int = Field(default=0, ge=0)
    coverage_gap_count: int = Field(default=0, ge=0)


class ScanRun(BaseModel):
    """Durable control-plane record for one accepted scan request."""

    schema_version: str = SCHEMA_VERSION
    scan_run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    account_id: str = ""
    request: ScanRequest
    request_fingerprint: str
    requester_subject: str = ""
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    # Accounts resolved when the run was accepted. Empty means only account_id
    # (runs accepted before multi-account support).
    target_account_ids: list[str] = Field(default_factory=list)
    status: ScanStatus = ScanStatus.QUEUED
    progress: ScanProgress = Field(default_factory=ScanProgress)
    execution_arn: str | None = None
    error_summary: str | None = None
    report: dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None


class ReportRecord(BaseModel):
    """Metadata for a customer-owned generated report object."""

    schema_version: str = SCHEMA_VERSION
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_run_id: str
    generation_mode: ReportGenerationMode
    object_key: str
    content_type: str = "text/markdown"
    sha256: str
    byte_size: int = Field(ge=0)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    enrichment_status: str = "not_requested"


class ScanSchedule(BaseModel):
    """Durable definition for an explicitly enabled scheduled scan."""

    schema_version: str = SCHEMA_VERSION
    schedule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(min_length=1, max_length=64)
    schedule_expression: str = Field(min_length=8, max_length=256)
    request: ScanRequest
    request_fingerprint: str
    requester_subject: str = ""
    enabled: bool = True
    scheduler_arn: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FindingRecord(BaseModel):
    """Evidence-backed deterministic policy-evaluation result."""

    finding_id: str
    scan_run_id: str
    account_id: str = ""
    region: str
    service: ScanService
    resource_arn: str
    resource_name: str
    rule_id: str
    rule_pack_version: str
    severity: str
    # Deterministic finding kind, used to select remediation guidance. Not part
    # of the finding ID, so adding it does not change existing identifiers.
    category: str = "residency"
    description: str
    evidence_ids: list[str] = Field(min_length=1)
    data_categories: list[str] = Field(default_factory=list)
    finding_state: str = "potential"
    data_classification: str = "not_assessed"
    uncertainty: str = "data classification and legal basis require customer validation"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvaluationResult(BaseModel):
    """Typed outcome of deterministic rule evaluation for a completed scan."""

    schema_version: str = SCHEMA_VERSION
    scan_run_id: str
    rule_pack_version: str
    findings: list[FindingRecord] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)
