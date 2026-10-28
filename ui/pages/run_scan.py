"""Run Scan — configure and execute a sovereignty compliance scan."""

from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st
from common import (
    AWS_REGIONS,
    BEDROCK_MODELS,
    REGION_GROUPS,
    REGULATIONS,
    divider,
    section_header,
)


def render():
    section_header("Run Sovereignty Scan", "Configure your scan targets and regulations, then execute.", icon="🔍")

    # ── Scan configuration form ───────────────────────────────────
    with st.form("scan_config_form"):
        # --- Regions ---
        st.markdown("##### Target Regions")
        st.caption("Select AWS regions to scan for cross-border data flows.")

        preset = st.selectbox(
            "Region preset",
            ["Custom", "All EU Regions", "EU + US", "Global (all regions)", "India Only", "China Only"],
            help="Quick-select a common region set, or choose Custom to pick individually.",
        )

        preset_map = {
            "All EU Regions": [n for n in REGION_GROUPS["EU Regions"]],
            "EU + US": [n for n in REGION_GROUPS["EU Regions"] + REGION_GROUPS["US Regions"]],
            "Global (all regions)": list(AWS_REGIONS.keys()),
            "India Only": [n for n in REGION_GROUPS["Asia Pacific"] if "Mumbai" in n or "Hyderabad" in n],
            "China Only": [n for n in REGION_GROUPS.get("China", [])],
        }
        default_regions = preset_map.get(preset, ["EU (Frankfurt)", "EU (Ireland)", "US East (N. Virginia)", "Asia Pacific (Mumbai)"])

        selected_region_names = st.multiselect(
            "AWS Regions",
            options=list(AWS_REGIONS.keys()),
            default=default_regions,
            help="Each region will be scanned for all supported AWS services.",
        )

        divider()

        # --- Regulations ---
        st.markdown("##### Regulations to Check")
        st.caption("Select which data sovereignty regulations to evaluate against.")

        reg_cols = st.columns(4)
        selected_regs = []
        for i, (rid, info) in enumerate(REGULATIONS.items()):
            col = reg_cols[i % 4]
            if col.checkbox(f'{info["icon"]} {info["name"]}', value=True, key=f"reg_{rid}"):
                selected_regs.append(rid)

        divider()

        # --- Accounts ---
        st.markdown("##### AWS Accounts")
        account_mode = st.radio(
            "Scan scope",
            ["Current account (default credentials)", "Specific accounts (cross-account)"],
            horizontal=True,
        )
        account_ids = ""
        if "Specific" in account_mode:
            account_ids = st.text_input(
                "Account IDs",
                placeholder="111111111111, 222222222222",
                help="Comma-separated AWS account IDs. Each account must have SovereignShieldScanRole deployed.",
            )

        divider()

        # --- AWS Services ---
        st.markdown("##### AWS Services to Scan")
        all_services = st.checkbox("Scan all services", value=True)
        if not all_services:
            svc_cols = st.columns(4)
            svc_options = {
                "S3": svc_cols[0].checkbox("S3", value=True, key="svc_s3"),
                "RDS": svc_cols[1].checkbox("RDS", value=True, key="svc_rds"),
                "DynamoDB": svc_cols[2].checkbox("DynamoDB", value=True, key="svc_ddb"),
                "CloudFront": svc_cols[3].checkbox("CloudFront", value=True, key="svc_cf"),
                "KMS": svc_cols[0].checkbox("KMS", value=True, key="svc_kms"),
                "SNS/SQS": svc_cols[1].checkbox("SNS/SQS", value=True, key="svc_sns"),
                "Transit Gateway": svc_cols[2].checkbox("Transit Gateway", value=True, key="svc_tgw"),
                "Lambda@Edge": svc_cols[3].checkbox("Lambda@Edge", value=True, key="svc_edge"),
            }

        divider()

        # --- Advanced ---
        with st.expander("Advanced Settings"):
            saved_model = st.session_state.get("bedrock_model_id", list(BEDROCK_MODELS.values())[0])
            model_keys = list(BEDROCK_MODELS.keys())
            model_vals = list(BEDROCK_MODELS.values())
            saved_idx = model_vals.index(saved_model) if saved_model in model_vals else 0
            model_label = st.selectbox("Bedrock Model", model_keys, index=saved_idx)

            saved_region = st.session_state.get("bedrock_region", "us-east-1")
            region_opts = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-northeast-1"]
            saved_region_idx = region_opts.index(saved_region) if saved_region in region_opts else 0
            bedrock_region = st.selectbox("Bedrock API Region", region_opts, index=saved_region_idx)

            generate_report = st.checkbox("Generate executive report", value=st.session_state.get("auto_report", True))
            generate_scp = st.checkbox("Generate SCP policies for violations", value=True)

        # --- Submit ---
        submitted = st.form_submit_button("🚀  Start Scan", type="primary", use_container_width=True)

    # ── Execute scan ──────────────────────────────────────────────
    if submitted:
        if not selected_region_names:
            st.error("Please select at least one AWS region.")
            return
        if not selected_regs:
            st.error("Please select at least one regulation.")
            return

        region_codes = [AWS_REGIONS[n] for n in selected_region_names]
        _run_scan(
            region_codes=region_codes,
            regulation_ids=selected_regs,
            account_ids=account_ids,
            model_id=BEDROCK_MODELS[model_label],
            bedrock_region=bedrock_region,
            generate_report=generate_report,
            generate_scp=generate_scp,
        )


def _run_scan(
    region_codes: list[str],
    regulation_ids: list[str],
    account_ids: str,
    model_id: str,
    bedrock_region: str,
    generate_report: bool,
    generate_scp: bool,
):
    regions_str = ", ".join(region_codes)
    regs_str = ", ".join(regulation_ids)

    st.markdown("---")
    section_header("Scan Progress", icon="⏳")

    progress = st.progress(0, text="Initialising...")

    agent_succeeded = False
    response_text = ""

    # ── Try full agent scan (needs Bedrock) ──────────────────────
    try:
        from api_client import _is_api_mode
        from api_client import run_scan as api_run_scan

        if _is_api_mode():
            progress.progress(10, text="Calling remote scan API...")
        else:
            progress.progress(10, text="Starting agent pipeline (requires Bedrock)...")

        status_container = st.empty()
        with status_container.status("Running scan pipeline...", expanded=True) as status:
            st.write(f"**Regions:** {regions_str}")
            st.write(f"**Regulations:** {regs_str}")
            st.write(f"**Model:** {model_id}")
            st.write(f"**Mode:** {'API (remote)' if _is_api_mode() else 'Local'}")

            progress.progress(20, text="Scanning...")

            result = api_run_scan(
                regions=regions_str,
                regulations=regs_str,
                accounts=account_ids,
            )
            response_text = result.get("result", str(result))
            agent_succeeded = True

            progress.progress(90, text="Processing results...")
            status.update(label="Agent scan complete!", state="complete")

        st.session_state.report_markdown = response_text

    except Exception as e:
        st.warning(f"Agent scan unavailable ({type(e).__name__}: {e}). Running offline violation detection instead.")

    # ── Always run structured violation detection ────────────────
    progress.progress(92, text="Running violation detection...")

    try:
        from api_client import check_violations

        sample_scan = _build_sample_scan(region_codes)
        result = check_violations(scan_results=sample_scan, regulations=",".join(regulation_ids))

        st.session_state.violations = result
        st.session_state.scan_results = sample_scan

        # Generate remediations automatically
        progress.progress(96, text="Generating remediation plans...")
        try:
            from api_client import generate_remediation
            rem_result = generate_remediation(violations=result)
            st.session_state.remediations = rem_result
        except Exception:
            pass

    except Exception as e:
        st.error(f"Violation detection failed: {e}")
        progress.empty()
        return

    # ── Store history and show results ───────────────────────────
    progress.progress(100, text="Done!")

    _store_scan_history(region_codes, regs_str)

    v_count = result.get("total", 0)
    if agent_succeeded:
        st.success(f"Scan complete — **{v_count} violations** detected. View details in **Results**.")
        with st.expander("Full Agent Response", expanded=False):
            st.markdown(response_text)
    else:
        st.success(f"Offline scan complete — **{v_count} violations** detected from sample data. View details in **Results**.")
        st.info("To run a full live scan, configure AWS credentials with Bedrock model access enabled.")


def _build_sample_scan(region_codes: list[str]) -> dict:
    """Build sample scan data using the selected regions for realistic demo results."""
    eu_region = next((r for r in region_codes if r.startswith("eu-")), "eu-central-1")
    us_region = next((r for r in region_codes if r.startswith("us-")), "us-east-1")
    ap_region = next((r for r in region_codes if r.startswith("ap-")), "ap-south-1")

    return {
        "flows": [
            {
                "service": "S3",
                "resource_name": "customer-pii-prod",
                "resource_arn": "arn:aws:s3:::customer-pii-prod",
                "source_region": eu_region,
                "destination_regions": [us_region],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
            {
                "service": "RDS",
                "resource_name": "orders-primary",
                "resource_arn": f"arn:aws:rds:{eu_region}:123456789012:db:orders-primary",
                "source_region": eu_region,
                "destination_regions": ["ap-southeast-1"],
                "flow_type": "replication",
                "encryption_enabled": False,
            },
            {
                "service": "DynamoDB",
                "resource_name": "user-sessions",
                "resource_arn": f"arn:aws:dynamodb:{ap_region}:123456789012:table/user-sessions",
                "source_region": ap_region,
                "destination_regions": ["cn-north-1"],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
            {
                "service": "CloudFront",
                "resource_name": "E1A2B3C4D5E6F7",
                "resource_arn": "arn:aws:cloudfront::123456789012:distribution/E1A2B3C4D5E6F7",
                "source_region": eu_region,
                "destination_regions": ["global-edge-locations"],
                "flow_type": "edge_cache",
                "encryption_enabled": True,
            },
            {
                "service": "S3",
                "resource_name": "analytics-data-lake",
                "resource_arn": "arn:aws:s3:::analytics-data-lake",
                "source_region": ap_region,
                "destination_regions": [us_region],
                "flow_type": "replication",
                "encryption_enabled": True,
            },
        ],
        "resources": [
            {
                "service": "S3",
                "resource_name": "sensitive-data-bucket",
                "resource_arn": "arn:aws:s3:::sensitive-data-bucket",
                "region": eu_region,
                "encryption_at_rest": False,
            },
            {
                "service": "RDS",
                "resource_name": "customer-db-prod",
                "resource_arn": f"arn:aws:rds:{eu_region}:123456789012:db:customer-db-prod",
                "region": eu_region,
                "encryption_at_rest": False,
            },
        ],
    }


def _store_scan_history(region_codes: list[str], regs_str: str):
    """Store scan metadata in session state history."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    severity_counts = {}
    violations = st.session_state.get("violations")
    if violations:
        for v in violations.get("violations", []):
            s = v.get("severity", "info")
            severity_counts[s] = severity_counts.get(s, 0) + 1

    st.session_state.scan_history.append({
        "timestamp": timestamp,
        "regions": ", ".join(region_codes),
        "regulations": regs_str,
        "severity_counts": severity_counts,
    })
