"""Generate Sovereign Shield demo PowerPoint from guided demo scenes."""

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt

# Colors
BG_DARK = RGBColor(0x0B, 0x11, 0x20)
CARD_BG = RGBColor(0x1A, 0x23, 0x32)
PRIMARY = RGBColor(0x63, 0x66, 0xF1)
ACCENT_CYAN = RGBColor(0x22, 0xD3, 0xEE)
TEXT_WHITE = RGBColor(0xF1, 0xF5, 0xF9)
TEXT_MUTED = RGBColor(0x94, 0xA3, 0xB8)
GREEN = RGBColor(0x10, 0xB9, 0x81)
RED = RGBColor(0xEF, 0x44, 0x44)
ORANGE = RGBColor(0xF5, 0x9E, 0x0B)


SCENES = [
    {
        "title": "The Data Sovereignty Challenge",
        "subtitle": "Scene 1 | 0:00 - 0:35",
        "bullets": [
            "7 global data residency laws: GDPR, EU Data Act, DPDP, PIPL, LGPD, DORA, NIS2",
            "One misconfigured S3 replication rule = silent compliance violation",
            "Manual audits take weeks and are outdated before they're complete",
            "Sovereign Shield: AI-powered multi-agent system built with Amazon Bedrock + Strands Agents SDK",
            "Scans AWS environments against all 7 regulations in minutes",
        ],
    },
    {
        "title": "Multi-Agent AI Pipeline (Strands SDK)",
        "subtitle": "Scene 2 | 0:35 - 1:10",
        "bullets": [
            "Strands SDK 'agent-as-tool' pattern — 5 specialist agents + orchestrator",
            "1. Jurisdiction Profiler — maps regulations to AWS regions",
            "2. Data Flow Scanner — discovers flows across 8 services (boto3)",
            "3. Violation Detector — cross-refs against regulation constraints",
            "4. Remediation Generator — CLI commands + SCP policies",
            "5. Report Generator — executive-ready compliance reports",
            "Powered by Amazon Bedrock Claude Sonnet 4 (configurable)",
        ],
    },
    {
        "title": "8 AWS Services • Cross-Account Scanning",
        "subtitle": "Scene 3 | 1:10 - 1:40",
        "bullets": [
            "S3 (replication rules) • RDS (read replicas) • DynamoDB (global tables)",
            "CloudFront (edge cache) • KMS (multi-region keys) • SNS/SQS (cross-region)",
            "Transit Gateway (VPC peering) • Lambda@Edge (edge functions)",
            "Cross-account scanning via STS AssumeRole — hundreds of accounts, single deployment",
            "Clear data source indicator: Live AWS (account ID shown) vs Demo Mode",
        ],
    },
    {
        "title": "Severity-Ranked Violations with Article References",
        "subtitle": "Scene 4 | 1:40 - 2:20",
        "bullets": [
            "9 violations detected across 4 regulations",
            "CRITICAL: S3 'customer-pii-prod' replicating EU data to us-east-1 — GDPR Art. 44",
            "CRITICAL: DynamoDB 'user-sessions' India → cn-north-1 — DPDP Sec. 16",
            "HIGH: RDS unencrypted replica in ap-southeast-1 — GDPR Art. 32 + Art. 44",
            "Each violation: regulation article, resource ARN, flow direction, encryption status",
            "Filterable by severity, regulation, and service",
        ],
    },
    {
        "title": "Compliance Scoring & Risk Dashboard",
        "subtitle": "Scene 5 | 2:20 - 2:50",
        "bullets": [
            "Overall compliance score (0-100%) based on weighted violation severity",
            "Per-regulation grades: GDPR: D | DPDP: D | DORA: C | NIS2: C",
            "Progress bars showing compliant percentage per framework",
            "Top risks panel — critical violations requiring immediate action",
            "Real-time updates as new scans complete; track posture over time",
        ],
    },
    {
        "title": "Step-by-Step Remediation with AWS CLI Commands",
        "subtitle": "Scene 6 | 2:50 - 3:25",
        "bullets": [
            "Every violation gets an actionable fix with exact AWS CLI commands",
            "S3 fix: aws s3api delete-bucket-replication --bucket customer-pii-prod",
            "→ Create compliant EU-to-EU rule, delete already-replicated objects",
            "Effort: 2 hours | Priority: Immediate",
            "Risk if not fixed: GDPR Art. 83 — up to 4% annual turnover or EUR 20M",
            "Plans filterable: Immediate (<24h), Short-term (<1wk), Medium-term",
        ],
    },
    {
        "title": "Preventive SCP Policies — Ready to Deploy",
        "subtitle": "Scene 7 | 3:25 - 3:55",
        "bullets": [
            "Don't just fix — prevent recurrence with Service Control Policies",
            "Region Restriction: blocks S3/RDS/DynamoDB/KMS in non-EU regions",
            "Replication Deny: prevents cross-region replication to blocked regions",
            "JSON ready to paste into AWS Organizations",
            "Presets: EU Only | EU + Adequacy | India Only | China Only | Custom",
            "Deployment guide with exact CLI commands included",
        ],
    },
    {
        "title": "Serverless Deployment & Scheduled Scans",
        "subtitle": "Scene 8 | 3:55 - 4:25",
        "bullets": [
            "One-command deployment: cd cdk && cdk deploy",
            "Lambda (ARM64, 1024MB, 10min timeout) — agent pipeline",
            "Step Functions — orchestrated scan workflow with error handling",
            "EventBridge — daily 6AM UTC automated scans (configurable)",
            "DynamoDB — violations table with GSI by regulation + severity",
            "S3 — versioned report storage | API Gateway — REST endpoint",
            "Interactive chat mode — ask follow-up questions after scan",
        ],
    },
    {
        "title": "From Scan to Fix — Minutes, Not Weeks",
        "subtitle": "Scene 9 | 4:25 - 5:00",
        "bullets": [
            "✓ 5 AI agents coordinated by Strands SDK orchestrator",
            "✓ 7 regulations — GDPR, EU Data Act, DPDP, PIPL, LGPD, DORA, NIS2",
            "✓ 8 AWS services — complete cross-border data flow discovery",
            "✓ Cross-account — unlimited accounts via STS AssumeRole",
            "✓ Ready-to-deploy SCPs — preventive compliance controls",
            "✓ Serverless — Lambda + Step Functions + EventBridge",
            "✓ Executive reports — risk scores, grades, remediation timelines",
        ],
    },
]


def _set_slide_bg(slide, color):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def _add_text_box(slide, left, top, width, height, text, font_size=14,
                  bold=False, color=TEXT_WHITE, alignment=PP_ALIGN.LEFT):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.bold = bold
    p.font.color.rgb = color
    p.alignment = alignment
    return txBox


def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.33)
    prs.slide_height = Inches(7.5)

    # --- Title Slide ---
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
    _set_slide_bg(slide, BG_DARK)

    _add_text_box(slide, Inches(1.5), Inches(2.0), Inches(10), Inches(1.2),
                  "SOVEREIGN SHIELD", font_size=44, bold=True, color=PRIMARY,
                  alignment=PP_ALIGN.CENTER)
    _add_text_box(slide, Inches(1.5), Inches(3.2), Inches(10), Inches(0.8),
                  "AI-Powered Data Sovereignty Compliance for AWS", font_size=22,
                  color=ACCENT_CYAN, alignment=PP_ALIGN.CENTER)
    _add_text_box(slide, Inches(1.5), Inches(4.4), Inches(10), Inches(0.6),
                  "Built with Amazon Bedrock  •  Strands Agents SDK  •  AWS CDK",
                  font_size=14, color=TEXT_MUTED, alignment=PP_ALIGN.CENTER)
    _add_text_box(slide, Inches(1.5), Inches(5.6), Inches(10), Inches(0.5),
                  "5-Minute Demo Walkthrough  |  9 Scenes  |  300 Seconds",
                  font_size=12, color=TEXT_MUTED, alignment=PP_ALIGN.CENTER)

    # --- Scene Slides ---
    for i, scene in enumerate(SCENES):
        slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
        _set_slide_bg(slide, BG_DARK)

        # Scene number badge
        _add_text_box(slide, Inches(0.6), Inches(0.4), Inches(2), Inches(0.4),
                      scene["subtitle"], font_size=10, color=TEXT_MUTED)

        # Title
        _add_text_box(slide, Inches(0.6), Inches(0.9), Inches(11), Inches(0.8),
                      scene["title"], font_size=30, bold=True, color=TEXT_WHITE)

        # Accent line
        shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                       Inches(0.6), Inches(1.7), Inches(2.5), Pt(3))
        shape.fill.solid()
        shape.fill.fore_color.rgb = PRIMARY
        shape.line.fill.background()

        # Bullet points
        txBox = slide.shapes.add_textbox(Inches(0.8), Inches(2.1), Inches(11.5), Inches(4.8))
        tf = txBox.text_frame
        tf.word_wrap = True

        for j, bullet in enumerate(scene["bullets"]):
            if j == 0:
                p = tf.paragraphs[0]
            else:
                p = tf.add_paragraph()
            p.text = bullet
            p.font.size = Pt(16)
            p.font.color.rgb = TEXT_WHITE if not bullet.startswith("✓") else GREEN
            p.space_after = Pt(10)
            p.level = 0

            # Highlight critical/high items
            if "CRITICAL" in bullet:
                p.font.color.rgb = RED
            elif "HIGH" in bullet:
                p.font.color.rgb = ORANGE

        # Page number
        _add_text_box(slide, Inches(11.8), Inches(6.9), Inches(1), Inches(0.4),
                      f"{i + 2}/10", font_size=9, color=TEXT_MUTED,
                      alignment=PP_ALIGN.RIGHT)

    # --- Closing Slide ---
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    _set_slide_bg(slide, BG_DARK)

    _add_text_box(slide, Inches(1.5), Inches(2.5), Inches(10), Inches(1),
                  "Thank You", font_size=40, bold=True, color=PRIMARY,
                  alignment=PP_ALIGN.CENTER)
    _add_text_box(slide, Inches(1.5), Inches(3.8), Inches(10), Inches(0.6),
                  "From discovery to remediation in minutes, not weeks.",
                  font_size=18, color=ACCENT_CYAN, alignment=PP_ALIGN.CENTER)
    _add_text_box(slide, Inches(1.5), Inches(5.0), Inches(10), Inches(1.2),
                  "5 Agents  •  7 Regulations  •  8 AWS Services  •  Unlimited Accounts\n"
                  "Serverless  •  Cross-Account  •  Executive Reports  •  Preventive SCPs",
                  font_size=14, color=TEXT_MUTED, alignment=PP_ALIGN.CENTER)

    output_path = "demos/Sovereign_Shield_Demo.pptx"
    prs.save(output_path)
    return output_path


if __name__ == "__main__":
    path = create_presentation()
    print(f"Presentation saved: {path}")
