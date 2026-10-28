"""Specialist agents wrapped as Strands tools for the orchestrator (agent-as-tool pattern)."""

from __future__ import annotations

from strands import Agent, tool
from strands.models import BedrockModel

from sovereign_shield.tools.aws_scanner import (
    scan_cloudfront_distributions,
    scan_dynamodb_tables,
    scan_kms_keys,
    scan_lambda_at_edge,
    scan_rds_instances,
    scan_s3_buckets,
    scan_sns_sqs,
    scan_transit_gateways,
)
from sovereign_shield.tools.remediation import generate_remediation_plan, generate_scp_policy
from sovereign_shield.tools.violation_detector import check_violations


def _get_model(model_id: str | None = None, region: str | None = None) -> BedrockModel:
    return BedrockModel(
        model_id=model_id or "us.anthropic.claude-sonnet-4-20250514-v1:0",
        region_name=region or "us-east-1",
    )


@tool
def jurisdiction_profiler(query: str) -> str:
    """Specialist agent that analyzes which data sovereignty regulations apply to a given
    AWS environment based on regions, data categories, and business context.

    Use this to understand which regulations are relevant before scanning.

    Args:
        query: Description of the environment to profile (regions, data types, industry, countries of operation)
    """
    agent = Agent(
        model=_get_model(),
        system_prompt="""You are a data sovereignty jurisdiction specialist. Your role is to:

1. Analyze the user's AWS environment (regions, data types, industry) and determine which
   data sovereignty regulations apply.
2. Map each applicable regulation to concrete AWS region constraints.
3. Identify data categories (personal_data, financial_data, health_data, etc.) and their
   specific residency requirements.

You have deep knowledge of these regulations:
- GDPR (EU) - Art. 44-49 transfer restrictions
- EU Data Act - connected product data sovereignty
- India DPDP - Sec. 16-17 transfer restrictions, critical personal data localization
- China PIPL - Art. 38-40 cross-border assessment, CII local storage
- Brazil LGPD - Art. 33-34 international transfer conditions
- DORA (EU) - Financial sector ICT risk and data location
- NIS2 (EU) - Critical infrastructure cybersecurity

Output a structured analysis with:
- List of applicable regulations with IDs (gdpr, dpdp, pipl, lgpd, dora, nis2)
- Per-regulation: allowed AWS regions, prohibited regions, data categories affected
- Risk assessment for the current setup""",
        callback_handler=None,
    )
    return str(agent(query))


@tool
def data_flow_scanner(scan_request: str) -> str:
    """Specialist agent that discovers all cross-border data movements in an AWS environment.

    Scans S3, RDS, DynamoDB, CloudFront, KMS, SNS/SQS, Transit Gateway, and Lambda@Edge
    to find replication rules, edge caches, backups, streams, and peering connections
    that move data across AWS regions.

    Args:
        scan_request: JSON or description specifying which accounts and regions to scan
    """
    agent = Agent(
        model=_get_model(),
        system_prompt="""You are an AWS data flow scanning specialist. Your role is to systematically
discover every cross-border data movement in the target AWS environment.

SCANNING PROCEDURE:
1. Parse the scan request to identify target accounts and regions.
2. For each region, call the scanning tools in this order:
   - scan_s3_buckets: Find S3 replication rules
   - scan_rds_instances: Find cross-region read replicas
   - scan_dynamodb_tables: Find global table replicas
   - scan_cloudfront_distributions: Find edge cache distributions
   - scan_kms_keys: Find multi-region keys
   - scan_sns_sqs: Find cross-region message routing
   - scan_transit_gateways: Find cross-region network peering
   - scan_lambda_at_edge: Find edge-executing Lambda functions
3. Aggregate all results into a unified report.

IMPORTANT:
- Scan ALL specified regions — do not skip any.
- Report both resources (inventory) and cross-border flows separately.
- Include encryption status for every resource and flow.
- Note any scanning errors per region/service.

Return a comprehensive JSON with all scan results combined.""",
        tools=[
            scan_s3_buckets, scan_rds_instances, scan_dynamodb_tables,
            scan_cloudfront_distributions, scan_kms_keys, scan_sns_sqs,
            scan_transit_gateways, scan_lambda_at_edge,
        ],
        callback_handler=None,
    )
    return str(agent(scan_request))


@tool
def violation_detector(analysis_request: str) -> str:
    """Specialist agent that analyzes scan results against sovereignty regulations to find violations.

    Takes scan results and applicable regulations, then flags every breach with severity ranking,
    regulation reference, and precise description of the violation.

    Args:
        analysis_request: JSON containing scan results and optionally the applicable regulation IDs
    """
    agent = Agent(
        model=_get_model(),
        system_prompt="""You are a data sovereignty violation detection specialist. Your role is to
analyze AWS scan results and identify every data residency violation.

ANALYSIS PROCEDURE:
1. Parse the scan results (resources and cross-border flows).
2. Use the check_violations tool to systematically check all flows against regulations.
3. For each violation found, assess the severity:
   - CRITICAL: Data in explicitly prohibited regions, or transfers without any legal basis
   - HIGH: Data outside allowed regions without adequacy decision
   - MEDIUM: Missing encryption on cross-border transfers
   - LOW: Configuration that could lead to future violations
4. Provide a summary with total violations by severity and regulation.

Return the full violations list as JSON with severity ranking.""",
        tools=[check_violations],
        callback_handler=None,
    )
    return str(agent(analysis_request))


@tool
def remediation_generator(remediation_request: str) -> str:
    """Specialist agent that produces remediation plans, SCP policies, and architecture fixes
    for detected sovereignty violations.

    Args:
        remediation_request: JSON containing violations to remediate
    """
    agent = Agent(
        model=_get_model(),
        system_prompt="""You are a data sovereignty remediation specialist. Your role is to produce
actionable, deployable fixes for every detected violation.

REMEDIATION PROCEDURE:
1. Parse the violations list.
2. Use generate_remediation_plan to create step-by-step fix instructions for each violation.
3. For region-restriction violations, use generate_scp_policy to produce ready-to-deploy SCPs.
4. Prioritize remediations by violation severity (critical first).
5. For each remediation, include:
   - Exact CLI commands or console steps
   - Estimated effort and risk assessment
   - Compliant architecture alternatives where applicable

PRINCIPLES:
- Prefer preventive controls (SCPs) over reactive fixes.
- Always suggest deploying an SCP alongside the resource-level fix.
- For architecture changes, provide both immediate fix and long-term recommendation.
- Include rollback steps for risky changes.

Return the full remediation plan as structured JSON.""",
        tools=[generate_remediation_plan, generate_scp_policy],
        callback_handler=None,
    )
    return str(agent(remediation_request))


@tool
def report_generator(report_request: str) -> str:
    """Specialist agent that produces an executive-ready sovereignty posture report.

    Synthesizes jurisdiction analysis, scan results, violations, and remediation plans
    into a comprehensive, severity-ranked report with risk scores per jurisdiction.

    Args:
        report_request: JSON containing all prior analysis: jurisdiction profile, scan results, violations, remediations
    """
    agent = Agent(
        model=_get_model(),
        system_prompt="""You are a sovereignty reporting specialist. Your role is to produce an
executive-ready Sovereignty Posture Report.

REPORT STRUCTURE:
1. **Executive Summary** — 2-3 sentence overview of sovereignty posture and key risks.
2. **Risk Score by Jurisdiction** — For each regulation:
   - Compliance percentage
   - Number of violations by severity
   - Overall risk score (0-100, where 100 is fully compliant)
3. **Violation Summary** — Table of all violations sorted by severity:
   - Regulation | Service | Resource | Violation | Severity
4. **Cross-Border Data Flow Map** — Summary of all detected flows:
   - Source region → Destination region | Service | Flow type | Compliant (Y/N)
5. **Remediation Timeline** — Prioritized fix plan:
   - Immediate (< 24h): Critical violations
   - Short-term (< 1 week): High violations
   - Medium-term (< 1 month): Medium/Low violations
6. **SCP Policies** — Ready-to-deploy policy documents.
7. **Recommendations** — Strategic recommendations for long-term compliance.

FORMAT: Output the report in clean Markdown format suitable for executive review.
Include concrete numbers, not vague statements. Every claim must trace to a specific finding.""",
        callback_handler=None,
    )
    return str(agent(report_request))
