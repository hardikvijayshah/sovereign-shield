"""Shared constants, helpers, and layout functions for the Streamlit UI."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import streamlit as st

ASSETS = Path(__file__).parent / "assets"

# ── Region registry ──────────────────────────────────────────────
AWS_REGIONS = {
    "US East (N. Virginia)": "us-east-1",
    "US East (Ohio)": "us-east-2",
    "US West (Oregon)": "us-west-2",
    "US West (N. California)": "us-west-1",
    "EU (Frankfurt)": "eu-central-1",
    "EU (Ireland)": "eu-west-1",
    "EU (London)": "eu-west-2",
    "EU (Paris)": "eu-west-3",
    "EU (Stockholm)": "eu-north-1",
    "EU (Milan)": "eu-south-1",
    "EU (Spain)": "eu-south-2",
    "EU (Zurich)": "eu-central-2",
    "Asia Pacific (Mumbai)": "ap-south-1",
    "Asia Pacific (Hyderabad)": "ap-south-2",
    "Asia Pacific (Singapore)": "ap-southeast-1",
    "Asia Pacific (Sydney)": "ap-southeast-2",
    "Asia Pacific (Tokyo)": "ap-northeast-1",
    "Asia Pacific (Seoul)": "ap-northeast-2",
    "South America (São Paulo)": "sa-east-1",
    "Canada (Central)": "ca-central-1",
    "Middle East (Bahrain)": "me-south-1",
    "Africa (Cape Town)": "af-south-1",
    "Israel (Tel Aviv)": "il-central-1",
    "China (Beijing)": "cn-north-1",
    "China (Ningxia)": "cn-northwest-1",
}

REGION_GROUPS = {
    "EU Regions": [
        "EU (Frankfurt)", "EU (Ireland)", "EU (London)", "EU (Paris)",
        "EU (Stockholm)", "EU (Milan)", "EU (Spain)", "EU (Zurich)",
    ],
    "US Regions": ["US East (N. Virginia)", "US East (Ohio)", "US West (Oregon)", "US West (N. California)"],
    "Asia Pacific": [
        "Asia Pacific (Mumbai)", "Asia Pacific (Hyderabad)", "Asia Pacific (Singapore)",
        "Asia Pacific (Sydney)", "Asia Pacific (Tokyo)", "Asia Pacific (Seoul)",
    ],
    "Other": ["South America (São Paulo)", "Canada (Central)", "Middle East (Bahrain)", "Africa (Cape Town)", "Israel (Tel Aviv)"],
    "China": ["China (Beijing)", "China (Ningxia)"],
}

# ── Regulation registry ──────────────────────────────────────────
REGULATIONS = {
    "gdpr": {"name": "GDPR", "full": "EU General Data Protection Regulation", "jurisdiction": "EU", "icon": "🇪🇺", "effective": "2018-05-25"},
    "eu-data-act": {"name": "EU Data Act", "full": "EU Data Act", "jurisdiction": "EU", "icon": "🇪🇺", "effective": "2025-09-12"},
    "dpdp": {"name": "DPDP", "full": "India Digital Personal Data Protection Act", "jurisdiction": "India", "icon": "🇮🇳", "effective": "2023-08-11"},
    "pipl": {"name": "PIPL", "full": "China Personal Information Protection Law", "jurisdiction": "China", "icon": "🇨🇳", "effective": "2021-11-01"},
    "lgpd": {"name": "LGPD", "full": "Brazil General Data Protection Law", "jurisdiction": "Brazil", "icon": "🇧🇷", "effective": "2020-09-18"},
    "dora": {"name": "DORA", "full": "EU Digital Operational Resilience Act", "jurisdiction": "EU", "icon": "🏦", "effective": "2025-01-17"},
    "nis2": {"name": "NIS2", "full": "EU Network and Information Security Directive 2", "jurisdiction": "EU", "icon": "🔒", "effective": "2024-10-18"},
}

AWS_SERVICES = ["S3", "RDS", "DynamoDB", "CloudFront", "KMS", "SNS/SQS", "Transit Gateway", "Lambda@Edge"]

SEVERITY_COLORS = {
    "critical": {"bg": "#FEE2E2", "fg": "#DC2626", "label": "CRITICAL"},
    "high": {"bg": "#FFEDD5", "fg": "#EA580C", "label": "HIGH"},
    "medium": {"bg": "#FEF3C7", "fg": "#D97706", "label": "MEDIUM"},
    "low": {"bg": "#DCFCE7", "fg": "#16A34A", "label": "LOW"},
    "info": {"bg": "#EFF6FF", "fg": "#2563EB", "label": "INFO"},
}

BEDROCK_MODELS = {
    "Claude Sonnet 4 (recommended)": "us.anthropic.claude-sonnet-4-20250514-v1:0",
    "Claude Haiku 4.5 (faster, lighter)": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
}


# ── Layout helpers ───────────────────────────────────────────────

def load_css():
    css_file = ASSETS / "style.css"
    if css_file.exists():
        st.markdown(f"<style>{css_file.read_text()}</style>", unsafe_allow_html=True)


def render_logo_header():
    svg_file = ASSETS / "logo.svg"
    if svg_file.exists():
        b64 = base64.b64encode(svg_file.read_bytes()).decode()
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:12px; padding:8px 0 4px 0;">
                <img src="data:image/svg+xml;base64,{b64}" width="40" height="40" />
                <div>
                    <p style="margin:0; font-size:1.15rem; font-weight:700; color:#0F52BA; line-height:1.2; letter-spacing:-0.01em;">Sovereign Shield</p>
                    <p style="margin:0; color:#64748B; font-size:0.72rem; line-height:1.3;">Data Sovereignty Compliance</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown("**Sovereign Shield**")


def severity_badge(severity: str) -> str:
    s = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    return f'<span style="background:{s["bg"]}; color:{s["fg"]}; padding:3px 12px; border-radius:20px; font-weight:600; font-size:0.8rem;">{s["label"]}</span>'


def metric_card(label: str, value: str | int, delta: str = "", color: str = "#0F52BA"):
    delta_html = f'<p style="margin:0; font-size:0.8rem; color:{color};">{delta}</p>' if delta else ""
    st.markdown(
        f"""
        <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:12px; padding:18px 22px;
                    border-left:4px solid {color};">
            <p style="margin:0; color:#64748B; font-size:0.8rem; text-transform:uppercase; letter-spacing:0.04em; font-weight:500;">{label}</p>
            <p style="margin:4px 0 0 0; font-size:1.8rem; font-weight:700; color:#0F172A;">{value}</p>
            {delta_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(title: str, subtitle: str = "", icon: str = ""):
    icon_html = f'<span style="font-size:1.4rem; margin-right:8px;">{icon}</span>' if icon else ""
    sub_html = f'<p style="margin:0; color:#64748B; font-size:0.9rem;">{subtitle}</p>' if subtitle else ""
    st.markdown(
        f"""
        <div style="margin:28px 0 16px 0;">
            <h2 style="margin:0; color:#0F172A; font-size:1.3rem;">{icon_html}{title}</h2>
            {sub_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def divider():
    st.markdown('<hr style="border:none; border-top:1px solid #E2E8F0; margin:24px 0;" />', unsafe_allow_html=True)


def parse_json_safe(text: str) -> dict | list | None:
    """Try to extract JSON from agent response text."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    for start_char, end_char in [("{", "}"), ("[", "]")]:
        start = text.find(start_char)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == start_char:
                depth += 1
            elif text[i] == end_char:
                depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    break
    return None
