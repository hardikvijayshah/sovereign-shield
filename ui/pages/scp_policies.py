"""SCP Policy Generator — create Service Control Policies for region restrictions."""

from __future__ import annotations

import json

import streamlit as st
from common import AWS_REGIONS, REGION_GROUPS, divider, section_header


def render():
    section_header("SCP Policy Generator", "Generate ready-to-deploy Service Control Policies for AWS Organizations.", icon="📜")

    st.markdown(
        """
        SCPs prevent resources from being created or replicated into non-compliant regions.
        Configure the parameters below and generate the policy JSON.
        """
    )

    divider()

    # ── Configuration ─────────────────────────────────────────────
    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.markdown("##### Allowed Regions")
        st.caption("Resources will ONLY be permitted in these regions. All others will be denied.")

        allowed_preset = st.selectbox(
            "Preset",
            ["EU Only", "EU + Adequacy", "India Only", "China Only", "Custom"],
            key="scp_preset",
        )

        preset_allowed = {
            "EU Only": [n for n in REGION_GROUPS["EU Regions"]],
            "EU + Adequacy": [n for n in REGION_GROUPS["EU Regions"]] + ["Canada (Central)", "Asia Pacific (Tokyo)", "Israel (Tel Aviv)"],
            "India Only": ["Asia Pacific (Mumbai)", "Asia Pacific (Hyderabad)"],
            "China Only": ["China (Beijing)", "China (Ningxia)"],
        }
        default_allowed = preset_allowed.get(allowed_preset, [])

        allowed_names = st.multiselect(
            "Allowed regions",
            options=list(AWS_REGIONS.keys()),
            default=default_allowed,
            key="scp_allowed",
        )

    with col_right:
        st.markdown("##### Services to Restrict")
        st.caption("Select which AWS services the SCP should cover.")

        all_svc = st.checkbox("All data services", value=True, key="scp_all_svc")

        service_map = {
            "S3": "s3", "RDS": "rds", "DynamoDB": "dynamodb", "KMS": "kms",
            "SNS": "sns", "SQS": "sqs", "Lambda": "lambda", "EC2": "ec2", "CloudFront": "cloudfront",
        }

        if all_svc:
            selected_services = list(service_map.values())
        else:
            svc_cols = st.columns(3)
            selected_services = []
            for i, (label, code) in enumerate(service_map.items()):
                if svc_cols[i % 3].checkbox(label, value=True, key=f"scp_svc_{code}"):
                    selected_services.append(code)

        st.markdown("")
        st.markdown("##### Policy Name")
        policy_name = st.text_input("SCP policy name", value="SovereignShieldRegionRestriction", key="scp_name")

    divider()

    # ── Generate ──────────────────────────────────────────────────
    if st.button("📜  Generate SCP Policy", type="primary", use_container_width=True):
        if not allowed_names:
            st.error("Select at least one allowed region.")
            return

        allowed_codes = set(AWS_REGIONS[n] for n in allowed_names)
        all_codes = set(AWS_REGIONS.values())
        prohibited_codes = sorted(all_codes - allowed_codes)

        if not prohibited_codes:
            st.warning("No regions to block — all regions are in the allowed list.")
            return

        try:
            from api_client import generate_scp

            with st.spinner("Generating SCP policies..."):
                result = generate_scp(
                    prohibited_regions=",".join(prohibited_codes),
                    allowed_services=",".join(selected_services),
                    policy_name=policy_name,
                )
        except Exception as e:
            st.error(f"Generation failed: {e}")
            return

        if "region_restriction_policy" not in result:
            st.error("Unexpected response format from SCP generator.")
            return

        st.success(f"SCP policy generated — blocks **{len(prohibited_codes)} regions** across **{len(selected_services)} services**.")

        divider()

        # ── Display policies ──────────────────────────────────────
        tab1, tab2, tab3 = st.tabs(["Region Restriction Policy", "Replication Deny Policy", "Deployment Guide"])

        with tab1:
            st.markdown("##### Region Restriction Policy")
            st.caption("Denies all service operations in non-allowed regions.")
            policy_json = json.dumps(result["region_restriction_policy"], indent=2)
            st.code(policy_json, language="json")
            st.download_button(
                "📥  Download Policy JSON",
                data=policy_json,
                file_name=f"{policy_name}_region_restriction.json",
                mime="application/json",
                key="dl_region",
            )

        with tab2:
            st.markdown("##### Replication Deny Policy")
            st.caption("Prevents setting up cross-region replication to blocked regions.")
            repl_json = json.dumps(result["replication_deny_policy"], indent=2)
            st.code(repl_json, language="json")
            st.download_button(
                "📥  Download Policy JSON",
                data=repl_json,
                file_name=f"{policy_name}_replication_deny.json",
                mime="application/json",
                key="dl_repl",
            )

        with tab3:
            st.markdown("##### How to Deploy")
            for step in result.get("instructions", []):
                st.markdown(f"- {step}")

            st.markdown("")
            st.markdown("##### AWS CLI Deployment")
            st.code(
                f'aws organizations create-policy \\\n'
                f'  --name "{policy_name}" \\\n'
                f'  --description "Sovereign Shield region restriction" \\\n'
                f'  --type SERVICE_CONTROL_POLICY \\\n'
                f'  --content file://{policy_name}_region_restriction.json',
                language="bash",
            )

            st.markdown("")
            st.info(
                "**Important:** SCPs apply to all accounts in the target OU. "
                "Test in a non-production OU first, and ensure the management account is not affected."
            )

        divider()
        st.markdown("##### Blocked Regions")
        blocked_display = [f"`{r}`" for r in result.get("blocked_regions", [])]
        st.markdown(", ".join(blocked_display))
