"""Remediation — view and generate remediation plans for violations."""

from __future__ import annotations

import json
import re

import streamlit as st
from common import REGULATIONS, divider, section_header, severity_badge


def render():
    section_header("Remediation Plans", "Actionable fixes for detected sovereignty violations.", icon="🔧")

    violations_data = st.session_state.get("violations")
    remediations_data = st.session_state.get("remediations")

    if not violations_data or not violations_data.get("violations"):
        st.info("No violations to remediate. Run a scan first.")
        if st.button("🔍  Go to Run Scan", type="primary"):
            st.session_state.current_page = "Run Scan"
            st.rerun()
        return

    v_list = violations_data["violations"]

    # ── Generate remediations if not already present ──────────────
    if not remediations_data:
        st.warning("Remediation plans have not been generated yet.")
        if st.button("🔧  Generate Remediation Plans", type="primary", use_container_width=True):
            with st.spinner("Generating remediation plans..."):
                _generate_remediations(violations_data)
            st.rerun()
        return

    rem_list = remediations_data.get("remediations", [])
    if not rem_list:
        st.info("No remediations generated.")
        return

    # ── Summary ───────────────────────────────────────────────────
    by_type = {}
    for r in rem_list:
        t = r.get("remediation_type", "other")
        by_type[t] = by_type.get(t, 0) + 1

    type_labels = {
        "resource_config": ("Resource Config", "🔧"),
        "architecture_change": ("Architecture Change", "🏗️"),
        "encryption_enablement": ("Enable Encryption", "🔐"),
        "scp_policy": ("SCP Policy", "📜"),
        "deletion": ("Resource Deletion", "🗑️"),
    }

    cols = st.columns(min(len(by_type), 5))
    for i, (t, count) in enumerate(by_type.items()):
        label, icon = type_labels.get(t, (t.replace("_", " ").title(), "🔧"))
        with cols[i % len(cols)]:
            st.metric(f"{icon} {label}", count)

    divider()

    # ── Priority filter ───────────────────────────────────────────
    priority = st.radio(
        "Priority filter",
        ["All", "Immediate (< 24h)", "Short-term (< 1 week)", "Medium-term"],
        horizontal=True,
    )

    def _parse_hours(effort: str) -> float:
        """Extract approximate hours from effort string like '2-4 hours' or '1 week'."""
        effort_lower = effort.lower()
        nums = [int(x) for x in re.findall(r"\d+", effort_lower)]
        if not nums:
            return 999
        avg = sum(nums) / len(nums)
        if "week" in effort_lower:
            return avg * 168
        if "day" in effort_lower:
            return avg * 24
        return avg

    def _is_priority(rem: dict, level: str) -> bool:
        hours = _parse_hours(rem.get("estimated_effort", ""))
        if level == "Immediate (< 24h)":
            return hours <= 24
        if level == "Short-term (< 1 week)":
            return hours <= 168
        return True

    filtered = rem_list if priority == "All" else [r for r in rem_list if _is_priority(r, priority)]

    st.caption(f"Showing **{len(filtered)}** of {len(rem_list)} remediation plans")
    divider()

    # ── Remediation cards ─────────────────────────────────────────
    for rem in filtered:
        vid = rem.get("violation_id", "")
        matching_v = next((v for v in v_list if v.get("violation_id") == vid), {})
        sev = matching_v.get("severity", "info")
        badge = severity_badge(sev)
        reg_name = REGULATIONS.get(matching_v.get("regulation_id", ""), {}).get("name", matching_v.get("regulation_id", ""))
        rtype_label, rtype_icon = type_labels.get(rem.get("remediation_type", ""), (rem.get("remediation_type", ""), "🔧"))

        with st.expander(f'{rtype_icon}  {rem.get("title", "Remediation")}', expanded=False):
            c1, c2, c3 = st.columns([2, 2, 1])
            with c1:
                st.markdown(f"**Severity:** {badge}", unsafe_allow_html=True)
                st.markdown(f"**Regulation:** {reg_name}")
            with c2:
                st.markdown(f"**Type:** {rtype_icon} {rtype_label}")
                st.markdown(f"**Effort:** {rem.get('estimated_effort', 'N/A')}")
            with c3:
                st.markdown(f"**Violation ID:** `{vid}`")

            st.markdown("---")
            st.markdown(f"**Description:** {rem.get('description', '')}")

            st.markdown("**Steps:**")
            for j, step in enumerate(rem.get("steps", []), 1):
                if step.strip().startswith("aws "):
                    st.code(step, language="bash")
                else:
                    st.markdown(f"**{j}.** {step}")

            if rem.get("risk_if_not_remediated"):
                st.warning(f"**Risk if not remediated:** {rem['risk_if_not_remediated']}")

    # ── Export ────────────────────────────────────────────────────
    divider()
    st.download_button(
        "📥  Download Remediation Plans (JSON)",
        data=json.dumps(remediations_data, indent=2),
        file_name="remediation_plans.json",
        mime="application/json",
    )


def _generate_remediations(violations_data: dict):
    """Generate remediation plans via API client."""
    try:
        from api_client import generate_remediation

        result = generate_remediation(violations=violations_data)
        st.session_state.remediations = result
    except Exception as e:
        st.error(f"Failed to generate remediations: {e}")
