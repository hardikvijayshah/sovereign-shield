# Sovereign Shield

**AI-powered continuous data sovereignty compliance scanner for AWS environments.**

Sovereign Shield is a multi-agent system built with the [Strands Agents SDK](https://strandsagents.com) that scans AWS infrastructure, detects cross-border data flows, evaluates them against global data residency regulations, and produces executive-ready compliance reports with actionable remediation plans.

---

## Table of Contents

- [Problem](#problem)
- [Solution](#solution)
- [Supported Regulations](#supported-regulations)
- [Architecture](#architecture)
  - [Multi-Agent Design](#multi-agent-design)
  - [Agent Pipeline](#agent-pipeline)
  - [AWS Deployment Architecture](#aws-deployment-architecture)
- [Components](#components)
  - [Orchestrator Agent](#1-orchestrator-agent)
  - [Jurisdiction Profiler Agent](#2-jurisdiction-profiler-agent)
  - [Data Flow Scanner Agent](#3-data-flow-scanner-agent)
  - [Violation Detector Agent](#4-violation-detector-agent)
  - [Remediation Generator Agent](#5-remediation-generator-agent)
  - [Report Generator Agent](#6-report-generator-agent)
- [AWS Services Scanned](#aws-services-scanned)
- [Data Models](#data-models)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [CLI Usage](#cli-usage)
  - [Lambda Invocation](#lambda-invocation)
  - [Python SDK Usage](#python-sdk-usage)
- [End-to-End Demo](#end-to-end-demo)
  - [Demo 1: Full Compliance Scan](#demo-1-full-compliance-scan)
  - [Demo 2: Targeted GDPR Audit](#demo-2-targeted-gdpr-audit)
  - [Demo 3: Interactive Investigation](#demo-3-interactive-investigation)
  - [Demo 4: Violation Detection (Offline)](#demo-4-violation-detection-offline)
  - [Demo 5: SCP Policy Generation](#demo-5-scp-policy-generation)
  - [Demo 6: Lambda Invocation via AWS CLI](#demo-6-lambda-invocation-via-aws-cli)
- [AWS Deployment](#aws-deployment)
  - [CDK Stack Resources](#cdk-stack-resources)
  - [Cross-Account Scanning Setup](#cross-account-scanning-setup)
  - [Deploy Steps](#deploy-steps)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Regulation Coverage](#regulation-coverage)

---

## Problem

Data sovereignty laws are exploding globally — GDPR, EU Data Act, India's DPDP, China's PIPL, Brazil's LGPD, DORA, NIS2 — each enforcing strict rules on where data lives and moves. Enterprise customers routinely ask: *"Are we compliant with data residency laws in every country we operate?"*

Nobody has a fast answer. Verifying compliance means manually auditing S3 replication rules, RDS replica regions, DynamoDB global tables, CloudFront edge caches, KMS key regions, and cross-region VPC configs — across hundreds of accounts. One misconfigured replication rule silently creates a GDPR violation overnight.

## Solution

An AI agent system that continuously scans AWS environments and evaluates them against applicable residency requirements through a five-stage pipeline:

1. **Jurisdiction Profiler** — maps each regulation to concrete residency constraints per account and region
2. **Data Flow Scanner** — discovers every cross-border data movement across 8 AWS services
3. **Violation Detector** — flags breaches with precision (e.g., *"S3 bucket customer-pii-prod replicating to us-east-1 — violates GDPR Art. 44"*), severity-ranked by data sensitivity
4. **Remediation Generator** — produces exact fixes, ready-to-deploy SCP templates, and compliant architecture alternatives
5. **Sovereignty Posture Report** — executive-ready document with risk score per jurisdiction, compliant vs. non-compliant flows, and remediation timeline

---

## Supported Regulations

| ID | Regulation | Jurisdiction | Effective Date | Key Requirement |
|----|-----------|-------------|----------------|-----------------|
| `gdpr` | EU General Data Protection Regulation | EU | 2018-05-25 | Personal data must stay in EU/EEA; transfers require adequacy decision (Art. 44-49) |
| `eu-data-act` | EU Data Act | EU | 2025-09-12 | IoT/connected product data must prevent unlawful international access (Art. 27) |
| `dpdp` | India Digital Personal Data Protection Act | India | 2023-08-11 | Critical personal data must stay in India; general data restricted to notified countries (Sec. 16-17) |
| `pipl` | China Personal Information Protection Law | China | 2021-11-01 | Cross-border transfers require CAC security assessment; CII operators must store locally (Art. 38-40) |
| `lgpd` | Brazil General Data Protection Law | Brazil | 2020-09-18 | International transfers only to countries with adequate protection (Art. 33-34) |
| `dora` | EU Digital Operational Resilience Act | EU | 2025-01-17 | Financial sector must control data location and ICT provider oversight (Art. 28, 31) |
| `nis2` | EU Network and Information Security Directive 2 | EU | 2024-10-18 | Critical infrastructure data security and supply chain controls (Art. 21, 23) |

---

## Architecture

### Multi-Agent Design

Sovereign Shield uses the Strands Agents **"agent-as-tool" pattern** — each specialist agent is wrapped as a `@tool`-decorated function and called by a central orchestrator. This gives the orchestrator full control over execution order while allowing each specialist to operate autonomously with its own tools and system prompt.

```
                        ┌─────────────────────────────┐
                        │      ORCHESTRATOR AGENT      │
                        │  (Pipeline Coordination)     │
                        │  Model: Claude Sonnet 4      │
                        └──────────┬──────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
    ┌─────────▼──────────┐ ┌──────▼───────────┐ ┌──────▼──────────┐
    │  1. JURISDICTION   │ │ 2. DATA FLOW     │ │ 3. VIOLATION    │
    │     PROFILER       │ │    SCANNER       │ │    DETECTOR     │
    │                    │ │                  │ │                 │
    │  Regulation KB     │ │  8 AWS Scanning  │ │ check_violations│
    │  (no AWS tools)    │ │  Tools (boto3)   │ │ (regulation     │
    │                    │ │                  │ │  cross-ref)     │
    └────────────────────┘ └──────────────────┘ └─────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                                         │
    ┌─────────▼──────────┐                   ┌──────────▼─────────┐
    │ 4. REMEDIATION     │                   │ 5. REPORT          │
    │    GENERATOR       │                   │    GENERATOR       │
    │                    │                   │                    │
    │ generate_plan()    │                   │  LLM synthesis     │
    │ generate_scp()     │                   │  (no tools)        │
    └────────────────────┘                   └────────────────────┘
```

### Agent Pipeline

The orchestrator executes agents in strict sequence — each stage depends on the output of the previous:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Jurisdiction │───▶│  Data Flow   │───▶│  Violation   │───▶│ Remediation  │───▶│   Report     │
│  Profiler    │    │   Scanner    │    │  Detector    │    │  Generator   │    │  Generator   │
│              │    │              │    │              │    │              │    │              │
│ Which regs   │    │ What flows   │    │ What's       │    │ How to fix   │    │ Executive    │
│ apply?       │    │ exist?       │    │ violated?    │    │ it?          │    │ summary      │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
     Input:              Input:              Input:              Input:              Input:
  Regions, data      Accounts,           Scan results +     Violations         All prior
  types, industry    regions             regulation IDs     list               results
```

### AWS Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AWS Account                                  │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  EventBridge │───▶│    Step      │───▶│   Lambda Function    │  │
│  │  (Daily 6AM) │    │  Functions   │    │  (sovereign-shield)  │  │
│  └──────────────┘    │  (Pipeline)  │    │                      │  │
│                      └──────────────┘    │  Strands Agents SDK  │  │
│                                          │  + Agent Tools       │  │
│                                          └───────┬──────────────┘  │
│                                                  │                  │
│                    ┌─────────────────┬────────────┼────────┐       │
│                    │                 │            │        │       │
│              ┌─────▼─────┐    ┌─────▼─────┐ ┌───▼────┐ ┌─▼──┐   │
│              │  DynamoDB  │    │  DynamoDB  │ │   S3   │ │ BR │   │
│              │ Violations │    │   Scan     │ │Reports │ │ ed │   │
│              │   Table    │    │  Results   │ │ Bucket │ │ ro │   │
│              │  (GSI by   │    │  (w/ TTL)  │ │        │ │ ck │   │
│              │ regulation)│    │            │ │        │ │    │   │
│              └────────────┘    └────────────┘ └────────┘ └────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                   Cross-Account Scanning                      │  │
│  │    STS AssumeRole → SovereignShieldScanRole in each account  │  │
│  │    Scans: S3, RDS, DynamoDB, CloudFront, KMS, SNS/SQS,      │  │
│  │           Transit Gateway, Lambda@Edge                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. Orchestrator Agent

**File**: `src/sovereign_shield/agents/orchestrator.py`

The central coordinator that manages the full compliance scan pipeline. It receives a user request (accounts, regions, regulations) and delegates to specialist agents in sequence, passing each agent's output as context to the next.

- **Model**: Amazon Bedrock Claude Sonnet 4 (configurable)
- **Tools**: The 5 specialist agents (as Strands tools)
- **Entry point**: `create_orchestrator(model_id, region) -> Agent`

### 2. Jurisdiction Profiler Agent

**File**: `src/sovereign_shield/agents/specialists.py` → `jurisdiction_profiler()`

Analyzes the target AWS environment and determines which data sovereignty regulations apply based on:
- AWS regions in use
- Data categories stored (personal data, financial data, health data, etc.)
- Industry sector (financial services triggers DORA, critical infrastructure triggers NIS2)
- Countries of operation

**Output**: List of applicable regulation IDs with per-regulation region constraints and risk assessment.

### 3. Data Flow Scanner Agent

**File**: `src/sovereign_shield/agents/specialists.py` → `data_flow_scanner()`

Systematically discovers every cross-border data movement by calling 8 AWS scanning tools. For each region specified, it scans all supported services and aggregates results into a unified report of resources and cross-border flows.

**Tools available**: `scan_s3_buckets`, `scan_rds_instances`, `scan_dynamodb_tables`, `scan_cloudfront_distributions`, `scan_kms_keys`, `scan_sns_sqs`, `scan_transit_gateways`, `scan_lambda_at_edge`

### 4. Violation Detector Agent

**File**: `src/sovereign_shield/agents/specialists.py` → `violation_detector()`

Cross-references every detected data flow against regulation constraints. Assigns severity:

| Severity | Condition |
|----------|-----------|
| **CRITICAL** | Data in explicitly prohibited region, or transfer with no legal basis |
| **HIGH** | Data outside allowed regions without adequacy decision |
| **MEDIUM** | Missing encryption on regulated cross-border transfer |
| **LOW** | Configuration that could lead to future violations |

### 5. Remediation Generator Agent

**File**: `src/sovereign_shield/agents/specialists.py` → `remediation_generator()`

Produces actionable fixes for every violation:
- **AWS CLI commands** for immediate resource-level fixes
- **SCP policy documents** (JSON) ready to deploy via AWS Organizations
- **Architecture alternatives** for systemic issues
- **Effort estimates** and risk-if-not-remediated assessments

### 6. Report Generator Agent

**File**: `src/sovereign_shield/agents/specialists.py` → `report_generator()`

Synthesizes all prior results into an executive-ready Sovereignty Posture Report containing:
- Executive summary
- Risk scores per jurisdiction (0-100 scale)
- Violation summary table (regulation, service, resource, severity)
- Cross-border data flow map
- Prioritized remediation timeline (immediate / short-term / medium-term)
- Ready-to-deploy SCP policies
- Strategic recommendations

---

## AWS Services Scanned

| Service | What's Detected | Flow Type |
|---------|----------------|-----------|
| **S3** | Cross-region replication rules, server-side encryption config | `replication` |
| **RDS** | Cross-region read replicas (instances + clusters), encryption status | `replication` |
| **DynamoDB** | Global table replicas, SSE configuration | `replication` |
| **CloudFront** | Edge cache distributions, origin regions, price class restrictions | `edge_cache` |
| **KMS** | Multi-region key replicas | `replication` |
| **SNS/SQS** | Cross-region topic subscriptions (to SQS/Lambda in other regions) | `stream` |
| **Transit Gateway** | Cross-region peering attachments | `peering` |
| **Lambda@Edge** | Functions executing at CloudFront edge locations globally | `edge_cache` |

All scanners support **cross-account scanning** via STS AssumeRole to `SovereignShieldScanRole`.

---

## Data Models

All models are defined as [Pydantic v2](https://docs.pydantic.dev/) BaseModels in `src/sovereign_shield/models/`.

### Regulation Models

- **`Regulation`** — A sovereignty regulation with ID, jurisdiction, description, effective date, key articles, and constraints
- **`DataResidencyConstraint`** — Concrete residency rule: allowed/prohibited AWS regions, data categories, encryption requirements, adequacy decision support
- **`RegulationRegistry`** — Collection with lookup methods: `get_by_id()`, `get_by_jurisdiction()`, `get_all_constraints()`

### Scan Models

- **`CrossBorderFlow`** — A detected cross-border data movement: service, source/destination regions, flow type, encryption status
- **`ResourceInventory`** — AWS resource with residency implications: service, region, encryption settings, tags
- **`ScanResult`** — Aggregated scan output per account: resources, flows, errors

### Violation & Report Models

- **`Violation`** — A detected breach: regulation reference, severity, resource details, description
- **`Remediation`** — A proposed fix: type (SCP/config/architecture/encryption), steps, effort estimate
- **`JurisdictionScore`** — Risk score per regulation: compliant/non-compliant counts, critical/high violation counts
- **`SovereigntyReport`** — Full report: jurisdiction scores, violations, remediations, summary, recommendations

---

## Features

- **Multi-agent AI pipeline** — Five specialized agents coordinated by an orchestrator using Strands SDK
- **8 AWS service scanners** — S3, RDS, DynamoDB, CloudFront, KMS, SNS/SQS, Transit Gateway, Lambda@Edge
- **7 global regulations** — GDPR, EU Data Act, India DPDP, China PIPL, Brazil LGPD, DORA, NIS2
- **Cross-account scanning** — Scan hundreds of AWS accounts via STS AssumeRole
- **Severity-ranked violations** — Critical, High, Medium, Low with regulation article references
- **Auto-generated SCP policies** — Ready-to-deploy Service Control Policies for AWS Organizations
- **Step-by-step remediation** — AWS CLI commands, effort estimates, and risk assessments
- **Executive reporting** — Risk scores per jurisdiction, violation tables, remediation timelines
- **Scheduled scanning** — EventBridge-triggered daily scans (configurable)
- **Interactive mode** — Chat with the agent for follow-up questions after a scan
- **Serverless deployment** — Lambda + Step Functions + EventBridge via AWS CDK
- **Encryption validation** — Checks both at-rest and in-transit encryption per regulation requirements

---

## Prerequisites

- **Python 3.10+**
- **AWS credentials** configured (`aws configure` or environment variables)
- **Amazon Bedrock access** — model access enabled for Claude Sonnet 4 in your region
- **IAM permissions** — `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, plus read-only access to services being scanned
- **AWS CDK** (for deployment only) — `npm install -g aws-cdk`

---

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd sovereign-shield

# Install core dependencies
pip install -e .

# Install with development tools (pytest, ruff, moto)
pip install -e ".[dev]"

# Install with CDK deployment support
pip install -e ".[cdk]"

# Install everything
pip install -e ".[dev,cdk]"
```

---

## Configuration

Copy the environment template and configure:

```bash
cp .env.example .env
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_DEFAULT_REGION` | `us-east-1` | Default AWS region |
| `AWS_PROFILE` | `default` | AWS CLI profile to use |
| `BEDROCK_MODEL_ID` | `us.anthropic.claude-sonnet-4-20250514-v1:0` | Bedrock model for agents |
| `BEDROCK_REGION` | `us-east-1` | Region for Bedrock API calls |
| `SCAN_ACCOUNTS` | (empty) | Comma-separated account IDs for cross-account scanning |
| `SCAN_REGIONS` | `us-east-1,us-west-2,eu-west-1,eu-central-1,ap-south-1,ap-southeast-1` | Regions to scan |
| `VIOLATIONS_TABLE` | `sovereign-shield-violations` | DynamoDB violations table (set by CDK) |
| `SCAN_RESULTS_TABLE` | `sovereign-shield-scan-results` | DynamoDB scan results table (set by CDK) |
| `REPORTS_BUCKET` | `sovereign-shield-reports` | S3 bucket for reports (set by CDK) |

---

## Usage

### CLI Usage

```bash
# Full scan against all regulations in specified regions
sovereign-shield --regions us-east-1,eu-west-1,eu-central-1,ap-south-1

# Scan specific regulations only
sovereign-shield --regions eu-west-1,eu-central-1 --regulations gdpr,dora,nis2

# Cross-account scan
sovereign-shield --accounts 111111111111,222222222222 --regions eu-west-1,eu-central-1

# Interactive mode (chat after scan)
sovereign-shield --regions eu-central-1 --regulations gdpr --interactive

# Custom model and region
sovereign-shield --model-id us.anthropic.claude-sonnet-4-20250514-v1:0 --model-region us-west-2 --regions eu-west-1
```

### Lambda Invocation

```bash
# Invoke via AWS CLI
aws lambda invoke \
  --function-name sovereign-shield-scan \
  --payload '{"action":"scan","regions":"eu-west-1,eu-central-1","regulations":"gdpr"}' \
  --cli-binary-format raw-in-base64-out \
  output.json

# Chat mode via Lambda
aws lambda invoke \
  --function-name sovereign-shield-scan \
  --payload '{"action":"chat","prompt":"Which S3 buckets in eu-central-1 have replication to non-EU regions?"}' \
  --cli-binary-format raw-in-base64-out \
  output.json
```

### Python SDK Usage

```python
from sovereign_shield.agents import create_orchestrator

# Create the agent
orchestrator = create_orchestrator(
    model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
    region="us-east-1",
)

# Run a full scan
response = orchestrator(
    "Run a complete sovereignty compliance scan. "
    "Regions: eu-west-1, eu-central-1. "
    "Regulations: gdpr, dora. "
    "Execute the full pipeline."
)
print(response)

# Follow-up question (maintains conversation context)
response = orchestrator("Which violations are critical and need immediate remediation?")
print(response)
```

---

## End-to-End Demo

### Demo 1: Full Compliance Scan

Save as `demos/demo_full_scan.py`:

```python
"""Full sovereignty compliance scan across multiple regions and regulations."""

from sovereign_shield.agents import create_orchestrator


def main():
    orchestrator = create_orchestrator()

    print("=" * 70)
    print("  SOVEREIGN SHIELD — Full Compliance Scan Demo")
    print("=" * 70)

    response = orchestrator("""
    Run a complete sovereignty compliance scan on the following environment:

    AWS Regions: eu-west-1, eu-central-1, us-east-1, ap-south-1
    Regulations: GDPR, DPDP, DORA

    Our organization operates in Europe and India. We store:
    - Customer personal data (PII) in eu-central-1
    - Financial transaction data in eu-west-1
    - Application backups in us-east-1
    - Indian customer data in ap-south-1

    Execute the full pipeline:
    1) Profile applicable jurisdictions
    2) Scan all resources for cross-border data flows
    3) Detect violations
    4) Generate remediation plans with SCP policies
    5) Produce the executive Sovereignty Posture Report
    """)

    print(response)

    # Save report to file
    with open("sovereignty_report.md", "w") as f:
        f.write(str(response))
    print("\nReport saved to sovereignty_report.md")


if __name__ == "__main__":
    main()
```

**Run:**
```bash
python demos/demo_full_scan.py
```

---

### Demo 2: Targeted GDPR Audit

Save as `demos/demo_gdpr_audit.py`:

```python
"""Targeted GDPR compliance audit for EU regions only."""

from sovereign_shield.agents import create_orchestrator


def main():
    orchestrator = create_orchestrator()

    response = orchestrator("""
    Perform a targeted GDPR compliance audit.

    Scan only EU regions: eu-west-1, eu-central-1, eu-west-2, eu-north-1
    Regulation: GDPR only

    Focus on:
    - S3 buckets with cross-region replication rules going outside EU
    - RDS instances with read replicas in non-EU regions
    - DynamoDB global tables replicating to non-EU regions
    - CloudFront distributions serving EU-origin data to global edge locations
    - Any unencrypted resources storing personal data

    For every violation found, generate:
    1. The specific GDPR article being violated
    2. The exact AWS CLI command to fix it
    3. An SCP policy to prevent recurrence
    """)

    print(response)


if __name__ == "__main__":
    main()
```

**Run:**
```bash
python demos/demo_gdpr_audit.py
```

---

### Demo 3: Interactive Investigation

Save as `demos/demo_interactive.py`:

```python
"""Interactive session — scan first, then ask follow-up questions."""

from sovereign_shield.agents import create_orchestrator


def main():
    orchestrator = create_orchestrator()

    # Initial scan
    print("Running initial scan...\n")
    response = orchestrator(
        "Scan eu-central-1 and us-east-1 for GDPR violations. "
        "Focus on S3 and RDS cross-border data flows."
    )
    print(response)

    # Follow-up questions
    questions = [
        "Which of these violations are critical severity?",
        "Generate an SCP policy that blocks all S3 replication to regions outside the EU.",
        "What would a compliant architecture look like if we need read replicas for low-latency access in Asia?",
        "Summarize the top 3 actions we should take this week.",
    ]

    for q in questions:
        print(f"\n{'─' * 60}")
        print(f"Question: {q}\n")
        response = orchestrator(q)
        print(response)


if __name__ == "__main__":
    main()
```

**Run:**
```bash
python demos/demo_interactive.py
```

---

### Demo 4: Violation Detection (Offline)

Save as `demos/demo_offline_detection.py`:

This demo runs the violation detection logic against sample data **without requiring AWS credentials** — useful for testing and development.

```python
"""Offline violation detection against sample scan data — no AWS credentials needed."""

import json

from sovereign_shield.tools.violation_detector import check_violations


def main():
    # Simulated scan results representing common misconfigurations
    sample_scan = {
        "flows": [
            {
                "service": "S3",
                "resource_name": "customer-pii-prod",
                "resource_arn": "arn:aws:s3:::customer-pii-prod",
                "source_region": "eu-central-1",
                "destination_regions": ["us-east-1"],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
            {
                "service": "RDS",
                "resource_name": "orders-primary",
                "resource_arn": "arn:aws:rds:eu-west-1:123456789012:db:orders-primary",
                "source_region": "eu-west-1",
                "destination_regions": ["ap-southeast-1"],
                "flow_type": "replication",
                "encryption_enabled": False,
            },
            {
                "service": "DynamoDB",
                "resource_name": "user-sessions",
                "resource_arn": "arn:aws:dynamodb:ap-south-1:123456789012:table/user-sessions",
                "source_region": "ap-south-1",
                "destination_regions": ["cn-north-1"],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
            {
                "service": "S3",
                "resource_name": "eu-analytics",
                "resource_arn": "arn:aws:s3:::eu-analytics",
                "source_region": "eu-central-1",
                "destination_regions": ["eu-west-1"],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
            {
                "service": "CloudFront",
                "resource_name": "E1A2B3C4D5E6F7",
                "resource_arn": "arn:aws:cloudfront::123456789012:distribution/E1A2B3C4D5E6F7",
                "source_region": "eu-central-1",
                "destination_regions": ["global-edge-locations"],
                "flow_type": "edge_cache",
                "encryption_enabled": True,
            },
        ],
        "resources": [
            {
                "service": "S3",
                "resource_name": "sensitive-data-bucket",
                "resource_arn": "arn:aws:s3:::sensitive-data-bucket",
                "region": "eu-central-1",
                "encryption_at_rest": False,
            },
            {
                "service": "RDS",
                "resource_name": "finance-db",
                "resource_arn": "arn:aws:rds:eu-west-1:123456789012:db:finance-db",
                "region": "eu-west-1",
                "encryption_at_rest": True,
            },
        ],
    }

    print("=" * 70)
    print("  SOVEREIGN SHIELD — Offline Violation Detection Demo")
    print("=" * 70)
    print()

    # Check against all regulations
    print("Checking against ALL regulations...")
    result = json.loads(check_violations.tool_func(
        scan_results_json=json.dumps(sample_scan),
        applicable_regulations="",
    ))

    print(f"\nTotal violations found: {result['total']}\n")

    for v in result["violations"]:
        severity_icon = {
            "critical": "[CRITICAL]",
            "high": "[HIGH]    ",
            "medium": "[MEDIUM]  ",
            "low": "[LOW]     ",
        }.get(v["severity"], "[INFO]    ")

        print(f"  {severity_icon} {v['regulation_name']}")
        print(f"             {v['service']} '{v['resource_name']}': {v['source_region']} -> {v['destination_region']}")
        print(f"             {v['description'][:120]}...")
        print()

    # Now check only GDPR
    print("-" * 70)
    print("\nChecking against GDPR only...")
    gdpr_result = json.loads(check_violations.tool_func(
        scan_results_json=json.dumps(sample_scan),
        applicable_regulations="gdpr",
    ))
    print(f"GDPR violations: {gdpr_result['total']}\n")

    # Check DPDP (India)
    print("Checking against India DPDP only...")
    dpdp_result = json.loads(check_violations.tool_func(
        scan_results_json=json.dumps(sample_scan),
        applicable_regulations="dpdp",
    ))
    print(f"DPDP violations: {dpdp_result['total']}\n")

    for v in dpdp_result["violations"]:
        print(f"  [{v['severity'].upper()}] {v['description']}")


if __name__ == "__main__":
    main()
```

**Run:**
```bash
python demos/demo_offline_detection.py
```

**Expected output:**
```
======================================================================
  SOVEREIGN SHIELD — Offline Violation Detection Demo
======================================================================

Checking against ALL regulations...

Total violations found: <N>

  [CRITICAL] India Digital Personal Data Protection Act
             DynamoDB 'user-sessions': ap-south-1 -> cn-north-1
             DynamoDB 'user-sessions' replicates data from ap-south-1 to cn-north-1, which is explicitly prohibited...

  [HIGH]     EU General Data Protection Regulation
             S3 'customer-pii-prod': eu-central-1 -> us-east-1
             S3 'customer-pii-prod' transfers data from eu-central-1 to us-east-1...

  [HIGH]     EU General Data Protection Regulation
             CloudFront 'E1A2B3C4D5E6F7': eu-central-1 -> global-edge-locations
             CloudFront 'E1A2B3C4D5E6F7' executes at global edge locations...

  [HIGH]     EU General Data Protection Regulation
             S3 'sensitive-data-bucket': eu-central-1 -> eu-central-1
             S3 resource 'sensitive-data-bucket' in eu-central-1 lacks required encryption at rest...
```

---

### Demo 5: SCP Policy Generation

Save as `demos/demo_scp_generation.py`:

```python
"""Generate SCP policies for region restriction and replication prevention."""

import json

from sovereign_shield.tools.remediation import generate_remediation_plan, generate_scp_policy


def main():
    print("=" * 70)
    print("  SOVEREIGN SHIELD — SCP Policy Generation Demo")
    print("=" * 70)

    # Generate an SCP that blocks EU data services in non-EU regions
    print("\n1. Region Restriction SCP (EU data services blocked outside EU)\n")
    scp_result = json.loads(generate_scp_policy.tool_func(
        prohibited_regions="us-east-1,us-west-2,ap-south-1,ap-southeast-1,sa-east-1",
        allowed_services="s3,rds,dynamodb,kms",
        policy_name="EUDataResidencyEnforcement",
    ))

    print("Region Restriction Policy:")
    print(json.dumps(scp_result["region_restriction_policy"], indent=2))
    print("\nReplication Deny Policy:")
    print(json.dumps(scp_result["replication_deny_policy"], indent=2))
    print("\nDeployment Instructions:")
    for step in scp_result["instructions"]:
        print(f"  {step}")

    # Generate remediation plan for sample violations
    print(f"\n{'─' * 70}")
    print("\n2. Remediation Plan for Sample Violations\n")

    violations = {
        "violations": [
            {
                "violation_id": "v001",
                "regulation_id": "gdpr",
                "regulation_name": "GDPR",
                "article_reference": "Art. 44",
                "severity": "critical",
                "service": "S3",
                "resource_arn": "arn:aws:s3:::customer-pii-prod",
                "resource_name": "customer-pii-prod",
                "source_region": "eu-central-1",
                "destination_region": "us-east-1",
                "description": "S3 bucket 'customer-pii-prod' replicating from eu-central-1 to us-east-1",
            },
            {
                "violation_id": "v002",
                "regulation_id": "gdpr",
                "regulation_name": "GDPR",
                "severity": "high",
                "service": "RDS",
                "resource_arn": "arn:aws:rds:eu-west-1:123:db:orders-primary",
                "resource_name": "orders-primary",
                "source_region": "eu-west-1",
                "destination_region": "ap-southeast-1",
                "description": "RDS instance 'orders-primary' has read replica in ap-southeast-1",
            },
            {
                "violation_id": "v003",
                "regulation_id": "gdpr",
                "regulation_name": "GDPR",
                "severity": "high",
                "service": "S3",
                "resource_arn": "arn:aws:s3:::sensitive-data",
                "resource_name": "sensitive-data",
                "source_region": "eu-central-1",
                "destination_region": "eu-central-1",
                "description": "S3 resource 'sensitive-data' lacks required encryption at rest under GDPR",
            },
        ],
    }

    plan_result = json.loads(generate_remediation_plan.tool_func(
        violations_json=json.dumps(violations),
    ))

    for rem in plan_result["remediations"]:
        print(f"  Violation: {rem['violation_id']}")
        print(f"  Title:     {rem['title']}")
        print(f"  Type:      {rem['remediation_type']}")
        print(f"  Effort:    {rem['estimated_effort']}")
        print(f"  Steps:")
        for i, step in enumerate(rem["steps"], 1):
            print(f"    {i}. {step}")
        print(f"  Risk:      {rem['risk_if_not_remediated']}")
        print()


if __name__ == "__main__":
    main()
```

**Run:**
```bash
python demos/demo_scp_generation.py
```

---

### Demo 6: Lambda Invocation via AWS CLI

After deploying with CDK:

```bash
# Full scan
aws lambda invoke \
  --function-name sovereign-shield-scan \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "action": "scan",
    "accounts": "",
    "regions": "eu-west-1,eu-central-1,us-east-1",
    "regulations": "gdpr,dora"
  }' \
  /tmp/scan-result.json

cat /tmp/scan-result.json | python -m json.tool

# Ask a follow-up question
aws lambda invoke \
  --function-name sovereign-shield-scan \
  --cli-binary-format raw-in-base64-out \
  --payload '{
    "action": "chat",
    "prompt": "List all S3 buckets with cross-region replication to non-EU regions and generate SCP policies to block them"
  }' \
  /tmp/chat-result.json

cat /tmp/chat-result.json | python -m json.tool

# Trigger via Step Functions
aws stepfunctions start-execution \
  --state-machine-arn arn:aws:states:<region>:<account>:stateMachine:sovereign-shield-scan-pipeline \
  --input '{
    "accounts": "",
    "regions": "eu-west-1,eu-central-1",
    "regulations": "gdpr"
  }'
```

---

## AWS Deployment

### CDK Stack Resources

The `cdk/stacks/sovereign_shield_stack.py` stack provisions the Phase 2
asynchronous, deterministic backend. Deployed scans do not call Bedrock.
See [DEPLOYMENT.md](DEPLOYMENT.md) for configuration and verification.

| Resource | Configuration |
|----------|---------------|
| **KMS key** | Customer-managed, rotation enabled; encrypts tables, reports, logs, and alerts |
| **DynamoDB** `ScanRunsTableV1` / `FindingsTableV1` | `pk`/`sk` per `docs/DATA_PERSISTENCE_CONTRACT.md`, PITR, KMS, RETAIN |
| **S3 reports bucket** | Private, versioned, KMS, TLS-only, lifecycle expiration, RETAIN |
| **HTTP API** | Eight `/v1/*` routes, Cognito JWT authorizer on every route, explicit CORS origins, throttled, redacted access logs |
| **Cognito** | User pool with `SovereignShieldAdministrators` / `SovereignShieldAuditors` groups |
| **Lambda** `ApiFunction` / `WorkflowFunction` | Python 3.12, ARM64, separate least-privilege roles |
| **Step Functions (Standard)** | Scheduled-run admission, then prepare -> Map fan-out (one Lambda per account/region/service, bounded concurrency) -> finalize; crashed units become coverage gaps |
| **EventBridge Scheduler group** | Holds API-managed schedules; none are created by default |
| **SNS, CloudWatch alarms, dashboard** | Workflow, Lambda, API, scheduler, and DynamoDB health |

### Cross-Account Scanning Setup

> The deployed Phase 2 stack scans only its own account. Cross-account scanning
> applies to the local CLI until Organizations onboarding (Phase 5).

To scan resources in other AWS accounts, create a `SovereignShieldScanRole` IAM role in each target account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<sovereign-shield-account>:role/ScanLambdaRole"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Attach read-only policies for the services being scanned (S3, RDS, DynamoDB, CloudFront, KMS, SNS, SQS, EC2, Lambda).

### Deploy Steps

```bash
# Install CDK dependencies
pip install -e ".[cdk]"

# Bootstrap CDK (first time only)
cd cdk
cdk bootstrap

# Preview changes
cdk diff

# Deploy
cdk deploy

# Verify
aws lambda invoke \
  --function-name sovereign-shield-scan \
  --cli-binary-format raw-in-base64-out \
  --payload '{"action":"scan","regions":"eu-central-1","regulations":"gdpr"}' \
  /tmp/test-result.json
```

---

## Testing

```bash
# Run all tests
pytest

# Verbose output
pytest -v

# Run specific test file
pytest tests/test_regulations.py
pytest tests/test_violation_detector.py
pytest tests/test_remediation.py

# Run by test name pattern
pytest -k "test_gdpr"
pytest -k "test_pipl"

# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/
```

### Test Coverage

| Test File | Tests | What's Covered |
|-----------|-------|----------------|
| `test_regulations.py` | 9 | Registry loading, lookup by ID/jurisdiction, region constraints, adequacy rules |
| `test_violation_detector.py` | 7 | GDPR EU→US violation, EU→EU compliance, encryption checks, PIPL/DPDP rules, edge cases |
| `test_remediation.py` | 3 | SCP policy generation, S3 remediation plans, encryption remediation |

---

## Project Structure

```
sovereign-shield/
├── src/sovereign_shield/
│   ├── __init__.py
│   ├── cli.py                         # CLI entry point (sovereign-shield command)
│   ├── lambda_handler.py              # AWS Lambda handler (scan/chat actions)
│   ├── regulations.py                 # Built-in regulation knowledge base (7 regulations)
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── orchestrator.py            # Main orchestrator agent (coordinates pipeline)
│   │   └── specialists.py            # 5 specialist agents as @tool functions
│   ├── models/
│   │   ├── __init__.py
│   │   ├── regulations.py            # Regulation, DataResidencyConstraint, RegulationRegistry
│   │   ├── scan.py                   # CrossBorderFlow, ResourceInventory, ScanResult
│   │   └── violations.py            # Violation, Remediation, SovereigntyReport, enums
│   └── tools/
│       ├── __init__.py
│       ├── aws_scanner.py            # 8 boto3 scanning tools (@tool decorated)
│       ├── violation_detector.py     # check_violations tool (regulation cross-reference)
│       └── remediation.py            # generate_scp_policy + generate_remediation_plan tools
├── cdk/
│   ├── app.py                         # CDK app entry point
│   ├── cdk.json                       # CDK configuration
│   └── stacks/
│       └── sovereign_shield_stack.py  # Full AWS infrastructure stack
├── tests/
│   ├── test_regulations.py
│   ├── test_violation_detector.py
│   └── test_remediation.py
├── demos/                             # Demo scripts (see End-to-End Demo section)
├── pyproject.toml                     # Project config, dependencies, scripts
├── .env.example                       # Environment variable template
├── CLAUDE.md                          # Claude Code guidance
└── plan.md                            # Original problem/solution statement
```

---

## Regulation Coverage

### Region Mapping

| Region Set | AWS Regions |
|-----------|------------|
| **EU** | eu-west-1 (Ireland), eu-west-2 (London), eu-west-3 (Paris), eu-central-1 (Frankfurt), eu-central-2 (Zurich), eu-south-1 (Milan), eu-south-2 (Spain), eu-north-1 (Stockholm) |
| **EU Adequacy** | EU regions + ca-central-1 (Canada), ap-northeast-1 (Tokyo), il-central-1 (Israel) |
| **India** | ap-south-1 (Mumbai), ap-south-2 (Hyderabad) |
| **China** | cn-north-1 (Beijing), cn-northwest-1 (Ningxia) |
| **Brazil** | sa-east-1 (Sao Paulo) |

### Data Categories

Each regulation constrains specific data categories:

| Category | Applicable Regulations |
|----------|----------------------|
| `personal_data` | GDPR, DPDP, PIPL, LGPD |
| `pii` | GDPR, DPDP, PIPL, LGPD |
| `sensitive_personal_data` | GDPR (strict — no adequacy) |
| `health_data`, `biometric_data` | GDPR (strict) |
| `critical_personal_data` | DPDP (India-only, no cross-border) |
| `government_data` | DPDP (India-only, no cross-border) |
| `financial_data`, `transaction_data` | DORA |
| `critical_infrastructure_data` | NIS2 |
| `iot_data`, `connected_product_data` | EU Data Act |
| `customer_data` | GDPR, DPDP, PIPL, LGPD |
