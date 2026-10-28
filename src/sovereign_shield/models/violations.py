"""Data models for violations, remediation, and sovereignty reports."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RemediationType(str, Enum):
    SCP_POLICY = "scp_policy"
    RESOURCE_CONFIG = "resource_config"
    ARCHITECTURE_CHANGE = "architecture_change"
    ENCRYPTION_ENABLEMENT = "encryption_enablement"
    DELETION = "deletion"


class Violation(BaseModel):
    """A detected sovereignty violation."""

    violation_id: str
    regulation_id: str
    regulation_name: str
    article_reference: str
    severity: Severity
    service: str
    resource_arn: str
    resource_name: str
    source_region: str
    destination_region: str
    description: str
    data_category: str = ""
    account_id: str = ""


class Remediation(BaseModel):
    """A proposed fix for a violation."""

    violation_id: str
    remediation_type: RemediationType
    title: str
    description: str
    steps: list[str]
    policy_document: str = ""
    estimated_effort: str = ""
    risk_if_not_remediated: str = ""


class JurisdictionScore(BaseModel):
    """Risk score for a single jurisdiction."""

    jurisdiction: str
    regulation_id: str
    regulation_name: str
    total_resources_scanned: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    risk_score: float = 0.0
    critical_violations: int = 0
    high_violations: int = 0


class SovereigntyReport(BaseModel):
    """Executive-ready sovereignty posture report."""

    report_id: str
    generated_at: str
    accounts_scanned: list[str]
    regions_scanned: list[str]
    jurisdiction_scores: list[JurisdictionScore] = []
    total_violations: int = 0
    critical_violations: int = 0
    violations: list[Violation] = []
    remediations: list[Remediation] = []
    summary: str = ""
    recommendations: list[str] = []
