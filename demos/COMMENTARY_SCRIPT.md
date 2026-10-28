# Sovereign Shield — 5-Minute Video Commentary Script

**Format:** Read aloud while screen-recording the actual app (navigate sidebar pages)  
**Navigation order:** Settings → Dashboard → Run Scan → Results → Remediation → SCP Policies → Schedule → Dashboard (wrap-up)  
**Pace:** ~130 words per minute (conversational, not rushed)  
**Total words:** ~650  
**Total time:** 5:00 (300 seconds)  
**Tip:** Pause at `[PAUSE]` markers (2-3 seconds silence) for visual breathing room.

---

## [0:00 – 0:30] Opening — Settings Page (Load Demo Data)

> *Navigate to: ⚙️ Settings*

Hey everyone. Today I want to show you Sovereign Shield — an AI-powered data sovereignty compliance platform for AWS.

I'm starting in Settings because this is where you configure your data source. You can either connect live AWS credentials and point to your real environment, or load Demo Mode with synthetic data. I'll load demo data so you can see the full experience without needing an AWS account.

Watch the progress bar — it's scanning eight services. Done. You can see the sidebar now shows "Demo Connected" in green.

There's also the Bedrock configuration here — model selection, API region. And below that, AWS accounts management for cross-account scanning.

[PAUSE]

---

## [0:30 – 1:10] Dashboard — Executive Posture Overview

> *Navigate to: 📊 Dashboard*

This is the executive dashboard. Right away I can see the hero banner showing we're in Demo Mode, plus the key metrics.

The posture score is 28 percent — not great. Two critical violations, four high, three medium — nine total across four regulations.

Below that, the intelligence bar gives a quick summary: score, findings count, regulations hit, and services affected.

Now look at the compliance-by-framework section — each regulation gets a letter grade. GDPR is at a D, DPDP is at a D, DORA a C, NIS2 a C. These grades are weighted by severity — a single critical violation drops the grade significantly.

There's also the recent activity section with scan history. Everything updates in real-time as new scans complete.

[PAUSE]

---

## [1:10 – 1:50] Run Scan — Configuration & Execution

> *Navigate to: 🔍 Run Scan*

This is the scan configuration page. At the top, you'll notice the data source banner clearly telling you whether you're working with demo data or a live account — and if live, it shows the account ID and IAM identity.

For regions, there are presets — All EU, EU plus US, Global, India Only — or you can pick individual regions. I'll select EU plus US.

Below that, select which regulations to check — all seven are enabled by default: GDPR, EU Data Act, DPDP, PIPL, LGPD, DORA, NIS2.

The scan runs in the background via a daemon thread — this is important. I can navigate away to other pages and the scan keeps running. It won't fail if I switch tabs. That's the global scan runner at work.

[PAUSE]

---

## [1:50 – 2:40] Results — Violations Detail

> *Navigate to: 📋 Results*

Here are the scan results. The source badge at the top confirms this is demo data.

The metric cards show the breakdown: two critical, four high, three medium. Let me walk through the critical ones.

This first one — S3 bucket "customer-pii-prod" is replicating EU personal data from Frankfurt to US East. That violates GDPR Article 44 — transferring personal data outside the EEA without adequate safeguards.

And this — DynamoDB table "user-sessions" replicating Indian data to China North. Explicitly prohibited under India's DPDP Act Section 16.

I can filter by severity, by regulation, or by service. Let me filter to GDPR only — four violations. Now just critical — two remaining. Each violation shows the resource ARN, source and destination regions, regulation article, and encryption status.

The Data Flows tab at the bottom shows every cross-border movement with compliant or non-compliant status.

[PAUSE]

---

## [2:40 – 3:20] Remediation — Actionable Fixes

> *Navigate to: 🔧 Remediation*

This is where Sovereign Shield stands apart — it doesn't just find problems, it tells you exactly how to fix them.

At the top, remediation types are categorized: resource configuration changes, architecture changes, enable encryption, SCP policies, and resource deletions.

I can filter by priority — immediate, short-term, or medium-term.

Let me look at the first plan. For the S3 replication violation, it gives me the exact AWS CLI command: `aws s3api delete-bucket-replication --bucket customer-pii-prod`. Then instructions to create a compliant EU-to-EU rule, and clean-up steps for already-replicated objects.

Effort estimate: two hours. Priority: immediate.

And here's the risk assessment — GDPR Article 83 penalties, up to four percent of global annual turnover or twenty million euros.

Every violation gets this level of detail. Actionable, not theoretical.

[PAUSE]

---

## [3:20 – 3:55] SCP Policies — Preventive Controls

> *Navigate to: 📜 SCP Policies*

Fixing existing violations is necessary, but we need to prevent new ones. That's what this page does — generates ready-to-deploy Service Control Policies.

I'll select "EU Only" as my allowed regions preset. On the right, all data services are checked by default — S3, RDS, DynamoDB, KMS, Lambda, and more.

Click Generate — and I get two policies. The Region Restriction policy blocks all data service operations outside EU regions. The Replication Deny policy prevents creating cross-region replication to non-EU destinations.

This JSON is ready to paste directly into AWS Organizations. There's even a deployment guide section with the exact `aws organizations create-policy` CLI command.

These are preventive controls — they catch misconfigurations before they create violations.

[PAUSE]

---

## [3:55 – 4:25] Schedule — Automated Recurring Scans

> *Navigate to: 🕐 Schedule*

For production environments, you need continuous compliance monitoring, not one-time scans.

This page lets you configure recurring scans. Choose a frequency — daily, every six hours, weekly, monthly. Pick your regions and regulations. When deployed to AWS, these become EventBridge rules triggering the Lambda-based agent pipeline automatically.

Daily 6 AM UTC is the default — that means your compliance posture is checked every morning before the team starts work.

Combined with the CDK deployment — Lambda on ARM64, Step Functions for orchestration, DynamoDB for violations storage, S3 for reports — you get a fully serverless, scheduled compliance system. One `cdk deploy` command and you're running.

[PAUSE]

---

## [4:25 – 5:00] Closing — Back to Dashboard

> *Navigate to: 📊 Dashboard*

Let me wrap up on the dashboard. Here's what makes Sovereign Shield enterprise-ready:

Five AI agents powered by Amazon Bedrock and Strands SDK. Seven regulations — GDPR, EU Data Act, DPDP, PIPL, LGPD, DORA, NIS2. Eight AWS services — complete cross-border data flow discovery. Cross-account scanning — unlimited accounts via STS AssumeRole. Ready-to-deploy SCPs. Serverless deployment. Executive reports with grades and timelines.

From discovery to remediation in minutes, not weeks. That's Sovereign Shield — AI-powered data sovereignty compliance for AWS.

Thanks for watching.

---

## Recording Tips

- Navigate sidebar pages in order: Settings → Dashboard → Run Scan → Results → Remediation → SCP Policies → Schedule → Dashboard
- Click sidebar items slightly before you narrate what's on screen
- At `[PAUSE]` markers, stay silent 2-3 seconds while the viewer reads
- Let transitions settle before speaking about the new page
- If you stumble, pause and continue — trim in post
- Total speaking time is ~4:15, leaving ~45s for pauses and transitions

## Key Numbers to Mention

| Stat | Value |
|------|-------|
| AI Agents | 5 (orchestrator + 4 specialists) |
| Regulations | 7 (GDPR, EU Data Act, DPDP, PIPL, LGPD, DORA, NIS2) |
| AWS Services | 8 (S3, RDS, DynamoDB, CloudFront, KMS, SNS/SQS, TGW, Lambda@Edge) |
| Severity Levels | 4 (Critical, High, Medium, Low) |
| Demo Violations | 9 across 4 regulations |
| Max GDPR Penalty | 4% annual turnover or EUR 20M |
| Deployment | Serverless (CDK → Lambda + Step Functions + EventBridge) |
| Cross-Account | STS AssumeRole to SovereignShieldScanRole |
| Posture Score | Weighted by severity (crit=20, high=10, med=3, low=1) |
