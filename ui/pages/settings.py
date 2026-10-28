"""Settings — configure Bedrock model, AWS credentials, and preferences."""

from __future__ import annotations

import os

import streamlit as st
from common import BEDROCK_MODELS, divider, section_header


def render():
    section_header("Settings", "Configure agent model, AWS credentials, and scan preferences.", icon="⚙️")

    # ── Bedrock Configuration ─────────────────────────────────────
    st.markdown("##### Amazon Bedrock Configuration")

    current_model = st.session_state.get("bedrock_model_id", list(BEDROCK_MODELS.values())[0])
    model_keys = list(BEDROCK_MODELS.keys())
    model_vals = list(BEDROCK_MODELS.values())
    default_idx = model_vals.index(current_model) if current_model in model_vals else 0

    model_label = st.selectbox(
        "Model",
        model_keys,
        index=default_idx,
        help="Claude Sonnet 4 is recommended for accuracy. Haiku 4.5 is faster and cheaper.",
    )
    st.session_state["bedrock_model_id"] = BEDROCK_MODELS[model_label]

    current_region = st.session_state.get("bedrock_region", "us-east-1")
    region_options = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-northeast-1", "ap-southeast-1"]
    default_region_idx = region_options.index(current_region) if current_region in region_options else 0

    bedrock_region = st.selectbox(
        "Bedrock API Region",
        region_options,
        index=default_region_idx,
        help="Choose the region where Bedrock API calls are made. Must have model access enabled.",
    )
    st.session_state["bedrock_region"] = bedrock_region

    st.caption(f"Model ID: `{BEDROCK_MODELS[model_label]}`")

    divider()

    # ── AWS Credentials ───────────────────────────────────────────
    st.markdown("##### AWS Credentials")
    st.info(
        "Sovereign Shield uses your local AWS credentials (`~/.aws/credentials`, environment variables, or IAM role). "
        "Ensure your credentials have Bedrock access and read-only permissions for the services being scanned."
    )

    cred_method = st.radio(
        "Credential method",
        ["Default (AWS CLI / environment)", "Named profile", "Environment variables"],
        horizontal=True,
    )

    if cred_method == "Named profile":
        profile = st.text_input("AWS Profile Name", value=os.environ.get("AWS_PROFILE", "default"))
        st.caption(f"Set via: `export AWS_PROFILE={profile}`")
        st.session_state["aws_profile"] = profile

    elif cred_method == "Environment variables":
        st.markdown("Set these environment variables before running the app:")
        st.code(
            "export AWS_ACCESS_KEY_ID=AKIA...\n"
            "export AWS_SECRET_ACCESS_KEY=...\n"
            "export AWS_DEFAULT_REGION=us-east-1",
            language="bash",
        )

    divider()

    # ── Scan Defaults ─────────────────────────────────────────────
    st.markdown("##### Default Scan Configuration")

    default_regions = st.text_input(
        "Default regions",
        value=st.session_state.get("default_regions", os.environ.get("SCAN_REGIONS", "us-east-1,eu-west-1,eu-central-1,ap-south-1")),
        help="Comma-separated region codes used when no regions are explicitly selected.",
    )
    st.session_state["default_regions"] = default_regions

    default_accounts = st.text_input(
        "Default account IDs",
        value=st.session_state.get("default_accounts", os.environ.get("SCAN_ACCOUNTS", "")),
        placeholder="Leave empty for current account",
    )
    if default_accounts:
        parts = [p.strip() for p in default_accounts.split(",") if p.strip()]
        invalid = [p for p in parts if not p.isdigit() or len(p) != 12]
        if invalid:
            st.warning(f"Invalid AWS account IDs (must be 12 digits): {', '.join(invalid)}")
    st.session_state["default_accounts"] = default_accounts

    divider()

    # ── Scan Behavior ─────────────────────────────────────────────
    st.markdown("##### Scan Behavior")

    auto_report = st.checkbox(
        "Auto-generate executive report after each scan",
        value=st.session_state.get("auto_report", True),
    )
    st.session_state["auto_report"] = auto_report

    auto_remediation = st.checkbox(
        "Auto-generate remediation plans after each scan",
        value=st.session_state.get("auto_remediation", True),
    )
    st.session_state["auto_remediation"] = auto_remediation

    divider()

    # ── Clear data ────────────────────────────────────────────────
    st.markdown("##### Data Management")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🗑️  Clear Scan Results", use_container_width=True):
            st.session_state.scan_results = None
            st.session_state.violations = None
            st.session_state.remediations = None
            st.session_state.report_markdown = None
            st.success("Scan results cleared.")
    with col2:
        if st.button("🗑️  Clear Scan History", use_container_width=True):
            st.session_state.scan_history = []
            st.success("Scan history cleared.")

    divider()

    # ── Connection status ─────────────────────────────────────────
    st.markdown("##### Connection Status")
    from api_client import API_GATEWAY_URL, LAMBDA_FUNCTION_NAME, _is_api_mode
    if _is_api_mode():
        st.success("Running in **API mode** — calls routed to Lambda")
        if API_GATEWAY_URL:
            st.caption(f"API Gateway: `{API_GATEWAY_URL}`")
        if LAMBDA_FUNCTION_NAME:
            st.caption(f"Lambda: `{LAMBDA_FUNCTION_NAME}`")
    else:
        st.info("Running in **local mode** — tools execute directly in this process")
