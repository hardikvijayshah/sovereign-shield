"""Results — violation tables, charts, and filtering."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st
from common import REGULATIONS, SEVERITY_COLORS, divider, metric_card, section_header, severity_badge


def render():
    section_header("Scan Results & Violations", "Detailed view of all detected sovereignty violations.", icon="📋")

    violations_data = st.session_state.get("violations")
    if not violations_data or not violations_data.get("violations"):
        st.info("No scan results available yet. Run a scan from the **Run Scan** page first.")
        if st.button("🔍  Go to Run Scan", type="primary"):
            st.session_state.current_page = "Run Scan"
            st.rerun()
        return

    v_list = violations_data["violations"]

    # ── Summary metrics ───────────────────────────────────────────
    total = len(v_list)
    by_severity = {}
    for v in v_list:
        s = v.get("severity", "info")
        by_severity[s] = by_severity.get(s, 0) + 1

    cols = st.columns(5)
    with cols[0]:
        metric_card("Total", total, color="#0F52BA")
    with cols[1]:
        metric_card("Critical", by_severity.get("critical", 0), color="#DC2626")
    with cols[2]:
        metric_card("High", by_severity.get("high", 0), color="#EA580C")
    with cols[3]:
        metric_card("Medium", by_severity.get("medium", 0), color="#D97706")
    with cols[4]:
        metric_card("Low / Info", by_severity.get("low", 0) + by_severity.get("info", 0), color="#16A34A")

    divider()

    # ── Filters ───────────────────────────────────────────────────
    section_header("Filter Violations", icon="🔎")
    f1, f2, f3 = st.columns(3)
    with f1:
        sev_filter = st.multiselect(
            "Severity",
            options=["critical", "high", "medium", "low", "info"],
            default=["critical", "high", "medium", "low"],
            format_func=lambda x: SEVERITY_COLORS[x]["label"],
        )
    with f2:
        reg_ids_in_data = sorted(set(v.get("regulation_id", "") for v in v_list))
        reg_filter = st.multiselect(
            "Regulation",
            options=reg_ids_in_data,
            default=reg_ids_in_data,
            format_func=lambda x: REGULATIONS.get(x, {}).get("name", x),
        )
    with f3:
        services_in_data = sorted(set(v.get("service", "") for v in v_list))
        svc_filter = st.multiselect("Service", options=services_in_data, default=services_in_data)

    filtered = [
        v for v in v_list
        if v.get("severity") in sev_filter
        and v.get("regulation_id") in reg_filter
        and v.get("service") in svc_filter
    ]

    st.caption(f"Showing **{len(filtered)}** of {total} violations")
    divider()

    # ── Tabs ─────────────────────────────────────────────────────
    tab_chart, tab_table, tab_detail = st.tabs(["Charts", "Table View", "Detail View"])

    with tab_chart:
        ch1, ch2 = st.columns(2)

        with ch1:
            st.markdown("**Violations by Severity**")
            filtered_sev = {}
            for v in filtered:
                s = v.get("severity", "info")
                filtered_sev[s] = filtered_sev.get(s, 0) + 1
            sev_df = pd.DataFrame([
                {"Severity": SEVERITY_COLORS[s]["label"], "Count": filtered_sev.get(s, 0)}
                for s in ["critical", "high", "medium", "low"]
                if filtered_sev.get(s, 0) > 0
            ])
            if not sev_df.empty:
                st.bar_chart(sev_df.set_index("Severity"))
            else:
                st.info("No violations match the current filters.")

        with ch2:
            st.markdown("**Violations by Regulation**")
            by_reg = {}
            for v in filtered:
                r = REGULATIONS.get(v.get("regulation_id", ""), {}).get("name", v.get("regulation_id", ""))
                by_reg[r] = by_reg.get(r, 0) + 1
            if by_reg:
                reg_df = pd.DataFrame([{"Regulation": k, "Count": v} for k, v in by_reg.items()])
                st.bar_chart(reg_df.set_index("Regulation"))

        st.markdown("")
        st.markdown("**Violations by AWS Service**")
        by_svc = {}
        for v in filtered:
            s = v.get("service", "Unknown")
            by_svc[s] = by_svc.get(s, 0) + 1
        if by_svc:
            svc_df = pd.DataFrame([{"Service": k, "Count": v} for k, v in by_svc.items()])
            st.bar_chart(svc_df.set_index("Service"))

    with tab_table:
        rows = []
        for v in filtered:
            rows.append({
                "Severity": SEVERITY_COLORS.get(v.get("severity", ""), {}).get("label", v.get("severity", "")),
                "Regulation": REGULATIONS.get(v.get("regulation_id", ""), {}).get("name", v.get("regulation_id", "")),
                "Service": v.get("service", ""),
                "Resource": v.get("resource_name", ""),
                "Source": v.get("source_region", ""),
                "Destination": v.get("destination_region", ""),
                "Article": v.get("article_reference", ""),
            })
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)

            csv = df.to_csv(index=False)
            st.download_button("📥  Download CSV", data=csv, file_name="violations.csv", mime="text/csv")
        else:
            st.info("No violations match the current filters.")

    with tab_detail:
        if not filtered:
            st.info("No violations match the current filters.")
        for v in filtered:
            sev = v.get("severity", "info")
            badge = severity_badge(sev)
            reg_name = REGULATIONS.get(v.get("regulation_id", ""), {}).get("name", v.get("regulation_id", ""))

            with st.expander(f'{v.get("service", "")} -- {v.get("resource_name", "")} ({reg_name})'):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Severity:** {badge}", unsafe_allow_html=True)
                    st.markdown(f"**Regulation:** {reg_name} -- {v.get('article_reference', '')}")
                with c2:
                    st.markdown(f"**Resource ARN:** `{v.get('resource_arn', '')}`")
                    st.markdown(f"**Data Flow:** `{v.get('source_region', '')}` -> `{v.get('destination_region', '')}`")
                st.markdown("---")
                st.markdown(f"**Description:** {v.get('description', '')}")

    # ── Export options ────────────────────────────────────────────
    divider()
    section_header("Export", icon="📥")
    ex1, ex2, ex3 = st.columns(3)

    with ex1:
        st.download_button(
            "📥  Violations (JSON)",
            data=json.dumps(violations_data, indent=2, default=str),
            file_name="violations.json",
            mime="application/json",
            use_container_width=True,
        )

    report_md = st.session_state.get("report_markdown")
    with ex2:
        if report_md:
            st.download_button(
                "📥  Report (Markdown)",
                data=report_md,
                file_name="sovereignty_posture_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        else:
            st.button("📥  Report (N/A)", disabled=True, use_container_width=True)

    with ex3:
        rem_data = st.session_state.get("remediations")
        if rem_data:
            st.download_button(
                "📥  Remediations (JSON)",
                data=json.dumps(rem_data, indent=2, default=str),
                file_name="remediations.json",
                mime="application/json",
                use_container_width=True,
            )
        else:
            st.button("📥  Remediations (N/A)", disabled=True, use_container_width=True)

    # ── Executive report ──────────────────────────────────────────
    if report_md:
        divider()
        section_header("Executive Report", icon="📝")
        with st.expander("View Full Report", expanded=False):
            st.markdown(report_md)
