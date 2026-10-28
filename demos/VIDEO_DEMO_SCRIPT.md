# Sovereign Shield — 5-Minute Video Demo Script

**Total runtime:** 5:00  
**Recording tool:** OBS Studio, Loom, or any screen recorder  
**Resolution:** 1920x1080 (full HD)  
**Browser:** Chrome/Edge, maximized, at 90% zoom  
**Pre-requisites:** App running at `http://localhost:8501` via `streamlit run ui/app.py`

---

## Option A: Fully Automated (Recommended)

The app has a built-in **Guided Demo** page that auto-plays through all scenes with timed narration scripts. Just:

1. Start Streamlit: `streamlit run ui/app.py`
2. Open browser to `http://localhost:8501`
3. Click **Settings** → **Load Demo Data** (loads synthetic violations)
4. Click **Guided Demo** in the sidebar
5. Select **Auto-play (timed, for recording)**
6. Start your screen recorder
7. Click **Start Auto-Play** — scenes advance automatically (~5 min total)
8. Read the narration text aloud as voiceover (or record it separately)

---

## Option B: Manual Step-Through

Use **Step-through (click to advance)** mode in Guided Demo to control pacing.

---

## Option C: Manual Recording (Full Script Below)

If you prefer to manually navigate the real pages while recording:

---

## Pre-Recording Setup

1. Kill any running Streamlit: `taskkill /F /IM streamlit.exe`
2. Start fresh: `streamlit run ui/app.py`
3. Open browser to `http://localhost:8501`
4. Go to **Settings** → Click **Load Demo Data** (animated progress loads synthetic data)
5. You're now on Dashboard with populated data — start recording here

---

## Scene 1: Opening — Dashboard & Problem Statement (0:00 – 0:45)

### What's on screen
Dashboard with the cinematic hero banner showing "9 Findings", compliance grade cards, top risks panel.

### Narration
> "Data sovereignty is one of the biggest compliance challenges in cloud today. Organizations operating across borders must comply with regulations like GDPR, India's DPDP Act, China's PIPL, and others — each dictating where data can and cannot reside.
>
> Sovereign Shield is an AI-powered multi-agent system built with Amazon Bedrock and the Strands Agents SDK. It continuously scans your AWS environment, detects cross-border data flows, and evaluates them against seven global data sovereignty regulations.
>
> Let me show you how it works."

### Actions
- Linger on the Dashboard hero banner (shows posture score, status)
- Scroll down to show compliance grade cards (GDPR: D, DPDP: D, DORA: C, NIS2: C)
- Point out the "Top Risks" panel with critical/high violations
- Click **Run Scan** in the sidebar

---

## Scene 2: Configuring a Scan (0:45 – 1:30)

### What's on screen
Run Scan page with the configuration form.

### Narration
> "The scan configuration gives you full control. I'll select the 'EU + US' region preset — this covers the most common data residency conflict: EU personal data flowing to US infrastructure.
>
> For regulations, GDPR, DPDP, DORA, and NIS2 are enabled. The scan targets all 8 AWS services: S3, RDS, DynamoDB, CloudFront, KMS, SNS/SQS, Transit Gateway, and Lambda@Edge.
>
> The background scan runner means you can navigate away without interrupting the scan."

### Actions
1. Show the region preset dropdown
2. Show the regulation checkboxes
3. Show the services section
4. Show the Advanced Settings expander (Bedrock model selection)
5. Click **Start Scan** (or just show the form since demo data is already loaded)

---

## Scene 3: Viewing Results (1:30 – 2:30)

### What's on screen
Results page with violations table, severity chart, and filters.

### Narration
> "The scan found 9 violations across 4 regulations. At the top — severity distribution. We have 2 critical, 4 high, and 3 medium findings.
>
> Here's the critical one: S3 bucket 'customer-pii-prod' replicating EU personal data from Frankfurt to US East — a direct violation of GDPR Article 44.
>
> This DynamoDB table 'user-sessions' replicates Indian data to China — explicitly prohibited under India's DPDP Act Section 16.
>
> I can filter by severity, regulation, or service. The Data Flows tab shows all cross-border movements with compliance status."

### Actions
1. Click **Results** in sidebar
2. Show the metric cards at top (Total: 9, Critical: 2, etc.)
3. Click "Charts" tab — show severity bar chart
4. Click "Table View" tab — show the sortable table
5. Click "Detail View" tab — expand a critical violation
6. Click "Data Flows" tab — show all flows with Compliant: Yes/No column
7. Show the Export buttons at bottom

---

## Scene 4: Remediation Plans (2:30 – 3:30)

### What's on screen
Remediation page with expandable fix plans.

### Narration
> "Each violation comes with a concrete remediation plan. Sovereign Shield doesn't just find problems — it tells you exactly how to fix them.
>
> For the S3 replication violation: delete the cross-region replication rule to us-east-1, create a new one targeting an EU region. Here are the exact AWS CLI commands.
>
> Effort: 2 hours. Risk if not remediated: GDPR penalties up to 4% of annual turnover.
>
> For encryption violations, it generates KMS and S3 encryption commands. Each plan is prioritized — you can filter by Immediate, Short-term, or Medium-term."

### Actions
1. Click **Remediation** in sidebar
2. Show the type summary metrics at top
3. Show the priority filter radio buttons
4. Expand the first remediation (S3 replication)
5. Show the AWS CLI commands in the steps
6. Show the risk warning at the bottom
7. Expand a second remediation (encryption)

---

## Scene 5: SCP Policy Generation (3:30 – 4:15)

### What's on screen
SCP Policies page with configuration and generated JSON.

### Narration
> "To prevent future violations, Sovereign Shield generates ready-to-deploy Service Control Policies.
>
> I'll select 'EU Only' preset — this blocks all data services outside EU regions. The system generates two policies: a region restriction policy and a replication deny policy.
>
> Copy this JSON directly into AWS Organizations. There's also a deployment guide with the exact AWS CLI commands and the EventBridge rule definition."

### Actions
1. Click **SCP Policies** in sidebar
2. Select "EU Only" preset in Allowed Regions
3. Leave "All data services" checked
4. Click **Generate SCP Policy**
5. Show the generated JSON in "Region Restriction Policy" tab
6. Click "Replication Deny Policy" tab
7. Click "Deployment Guide" tab — show the CLI command

---

## Scene 6: Settings & Demo Mode (4:15 – 4:40)

### What's on screen
Settings page with Demo Mode card, Bedrock config, AWS accounts dropdown.

### Narration
> "The Settings page offers three data sources: Demo Mode for exploring without credentials, Live Scan with AWS credentials, or API mode for Lambda deployment.
>
> You configure your Bedrock model — Claude Sonnet 4 recommended for accuracy — your API region, AWS accounts for cross-account scanning, and default scan preferences."

### Actions
1. Click **Settings** in sidebar
2. Show the two-column layout (Demo Mode / Live Scan cards)
3. Show Bedrock configuration section
4. Show the AWS Accounts multiselect dropdown
5. Show connection status at bottom

---

## Scene 7: Closing (4:40 – 5:00)

### What's on screen
Back to Dashboard with full data.

### Narration
> "Sovereign Shield: AI-powered data sovereignty compliance from scan to fix.
>
> Built on the Strands Agents SDK with Amazon Bedrock — five specialist AI agents, 8 AWS service scanners, 7 global regulations, ready-to-deploy fixes.
>
> From discovery to remediation in minutes, not weeks."

### Actions
1. Click **Dashboard**
2. Linger on the populated dashboard showing compliance grades
3. Fade out / end recording

---

## Tips for Recording

- **Hide bookmarks bar** (Ctrl+Shift+B) for clean look
- **90% browser zoom** fits Streamlit well on 1080p
- **Turn off notifications** (Windows Focus Assist)
- **Record narration separately** for cleaner audio
- **Use the Guided Demo auto-play** for hands-free recording

---

## Key Talking Points

| Point | Why It Matters |
|-------|---------------|
| Multi-agent architecture (5 agents) | Sophisticated AI design, not single prompt |
| 7 regulations | Breadth: GDPR, DPDP, PIPL, LGPD, DORA, NIS2, EU Data Act |
| 8 AWS services scanned | Depth: S3, RDS, DynamoDB, CloudFront, KMS, SNS/SQS, TGW, Lambda@Edge |
| Ready-to-deploy SCPs | Actionable output, not just reports |
| Background scan execution | Production UX — navigate freely during scan |
| Demo mode | Instant showcase without credentials |
| Strands SDK + Bedrock | AWS-native implementation |
| Cross-account support | Enterprise scale |
