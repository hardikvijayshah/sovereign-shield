"""Dashboard — overview of sovereignty posture, recent scans, and key metrics."""

from __future__ import annotations

import streamlit as st
from common import (
    AWS_SERVICES,
    REGULATIONS,
    divider,
    metric_card,
    section_header,
    severity_badge,
)


def render():
    section_header("Dashboard", "Overview of your data sovereignty compliance posture", icon="📊")

    # ── Top metrics row ───────────────────────────────────────────
    violations = st.session_state.get("violations")
    v_list = violations.get("violations", []) if isinstance(violations, dict) else []
    total_v = len(v_list)
    crit = sum(1 for v in v_list if v.get("severity") == "critical")
    high = sum(1 for v in v_list if v.get("severity") == "high")
    med = sum(1 for v in v_list if v.get("severity") == "medium")
    low_info = total_v - crit - high - med
    history = st.session_state.get("scan_history", [])

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        metric_card("Total Violations", total_v if violations else "--", color="#0F52BA")
    with c2:
        metric_card("Critical", crit if violations else "--", color="#DC2626")
    with c3:
        metric_card("High", high if violations else "--", color="#EA580C")
    with c4:
        metric_card("Medium", med if violations else "--", color="#D97706")
    with c5:
        metric_card("Scans Run", len(history), color="#16A34A")

    divider()

    # ── Compliance score per regulation ───────────────────────────
    if violations and v_list:
        section_header("Compliance by Regulation", icon="📊")

        by_reg = {}
        for v in v_list:
            rid = v.get("regulation_id", "unknown")
            by_reg.setdefault(rid, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
            sev = v.get("severity", "info")
            by_reg[rid][sev] = by_reg[rid].get(sev, 0) + 1

        reg_cols = st.columns(min(len(by_reg), 4))
        for i, (rid, counts) in enumerate(by_reg.items()):
            reg_info = REGULATIONS.get(rid, {})
            reg_name = reg_info.get("name", rid)
            reg_icon = reg_info.get("icon", "")
            total_reg = sum(counts.values())
            crit_high = counts["critical"] + counts["high"]
            score = max(0, 100 - (crit_high * 15) - (counts["medium"] * 5) - (counts["low"] * 2))
            color = "#DC2626" if score < 40 else "#D97706" if score < 70 else "#16A34A"

            with reg_cols[i % len(reg_cols)]:
                st.markdown(
                    f"""<div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:12px;
                        padding:16px; text-align:center; border-top:3px solid {color};">
                        <p style="margin:0; font-size:1.4rem;">{reg_icon}</p>
                        <p style="margin:4px 0 0 0; font-weight:600; font-size:0.95rem; color:#0F172A;">{reg_name}</p>
                        <p style="margin:4px 0; font-size:2rem; font-weight:700; color:{color};">{score}%</p>
                        <p style="margin:0; font-size:0.78rem; color:#64748B;">{total_reg} violations</p>
                    </div>""",
                    unsafe_allow_html=True,
                )

        divider()

    # ── Two-column body ───────────────────────────────────────────
    left, right = st.columns([3, 2])

    with left:
        section_header("Recent Scan Activity", icon="🕘")
        if history:
            for entry in reversed(history[-5:]):
                sev_counts = entry.get("severity_counts", {})
                badges = " ".join(
                    severity_badge(s) + f' <span style="font-size:0.85rem;margin-right:8px;">{n}</span>'
                    for s, n in sev_counts.items() if n > 0
                )
                st.markdown(
                    f"""
                    <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:10px;
                                padding:14px 18px; margin-bottom:10px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                            <div>
                                <span style="font-weight:600; color:#0F172A;">{entry.get('timestamp', '')}</span>
                                <span style="color:#64748B; margin-left:12px; font-size:0.85rem;">
                                    {entry.get('regions', '')}
                                </span>
                            </div>
                            <div>{badges}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.info("No scans completed yet. Go to **Run Scan** to start your first sovereignty assessment.")

    with right:
        section_header("Coverage", icon="🌐")
        st.markdown("**Regulations monitored**")
        for rid, info in REGULATIONS.items():
            st.markdown(
                f'<span style="font-size:1.1rem;">{info["icon"]}</span> '
                f'**{info["name"]}** -- {info["jurisdiction"]}',
                unsafe_allow_html=True,
            )

        st.markdown("")
        st.markdown("**AWS services scanned**")
        cols = st.columns(2)
        for i, svc in enumerate(AWS_SERVICES):
            cols[i % 2].markdown(f"`{svc}`")

    divider()

    # ── Quick actions ─────────────────────────────────────────────
    section_header("Quick Actions", icon="⚡")
    qa1, qa2, qa3, qa4 = st.columns(4)
    with qa1:
        if st.button("🔍  New Scan", use_container_width=True, type="primary"):
            st.session_state.current_page = "Run Scan"
            st.rerun()
    with qa2:
        if st.button("📋  View Results", use_container_width=True):
            st.session_state.current_page = "Results"
            st.rerun()
    with qa3:
        if st.button("📜  Generate SCP", use_container_width=True):
            st.session_state.current_page = "SCP Policies"
            st.rerun()
    with qa4:
        if st.button("🕐  Schedule Scan", use_container_width=True):
            st.session_state.current_page = "Schedule"
            st.rerun()
