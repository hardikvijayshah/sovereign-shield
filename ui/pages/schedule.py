"""Schedule — configure recurring sovereignty scans."""

from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st
from common import AWS_REGIONS, REGION_GROUPS, REGULATIONS, divider, section_header


def render():
    section_header("Schedule Scans", "Set up recurring sovereignty compliance scans.", icon="🕐")

    st.markdown(
        "Configure automated scans that run on a schedule. "
        "When deployed to AWS, schedules are managed via **EventBridge rules**. "
        "In local mode, schedules are saved for reference."
    )

    divider()

    # ── Create new schedule ───────────────────────────────────────
    section_header("Create New Schedule", icon="➕")

    with st.form("schedule_form"):
        col1, col2 = st.columns(2)

        with col1:
            schedule_name = st.text_input("Schedule name", value="Daily GDPR Scan", placeholder="My scheduled scan")

            frequency = st.selectbox("Frequency", ["Daily", "Every 6 hours", "Every 12 hours", "Weekly (Monday)", "Weekly (Friday)", "Monthly (1st)"])

            time_of_day = st.time_input("Time (UTC)", value=None)

        with col2:
            region_preset = st.selectbox(
                "Region preset",
                ["All EU Regions", "EU + US", "Global", "India Only", "Custom"],
                key="sched_preset",
            )
            preset_map = {
                "All EU Regions": [n for n in REGION_GROUPS["EU Regions"]],
                "EU + US": [n for n in REGION_GROUPS["EU Regions"] + REGION_GROUPS["US Regions"]],
                "Global": list(AWS_REGIONS.keys()),
                "India Only": ["Asia Pacific (Mumbai)", "Asia Pacific (Hyderabad)"],
            }
            default_r = preset_map.get(region_preset, [])
            sched_regions = st.multiselect("Regions", options=list(AWS_REGIONS.keys()), default=default_r, key="sched_regions")

            sched_regs = st.multiselect(
                "Regulations",
                options=list(REGULATIONS.keys()),
                default=list(REGULATIONS.keys()),
                format_func=lambda x: f'{REGULATIONS[x]["icon"]} {REGULATIONS[x]["name"]}',
                key="sched_regs",
            )

        st.markdown("")
        notify = st.checkbox("Send notification on critical violations", value=True)
        sched_accounts = st.text_input("Account IDs (optional)", placeholder="111111111111, 222222222222", key="sched_accts")

        submitted = st.form_submit_button("💾  Save Schedule", type="primary", use_container_width=True)

    if submitted:
        if not schedule_name:
            st.error("Please enter a schedule name.")
            return
        if not sched_regions:
            st.error("Please select at least one region.")
            return

        freq_to_cron = {
            "Daily": "cron(0 {h} * * ? *)",
            "Every 6 hours": "rate(6 hours)",
            "Every 12 hours": "rate(12 hours)",
            "Weekly (Monday)": "cron(0 {h} ? * MON *)",
            "Weekly (Friday)": "cron(0 {h} ? * FRI *)",
            "Monthly (1st)": "cron(0 {h} 1 * ? *)",
        }
        hour = time_of_day.hour if time_of_day else 6
        cron_expr = freq_to_cron.get(frequency, "rate(1 day)").format(h=hour)

        schedule_entry = {
            "name": schedule_name,
            "frequency": frequency,
            "cron": cron_expr,
            "time_utc": f"{hour:02d}:00",
            "regions": [AWS_REGIONS[n] for n in sched_regions],
            "regulations": sched_regs,
            "accounts": sched_accounts,
            "notify_critical": notify,
            "enabled": True,
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        }

        st.session_state.schedules.append(schedule_entry)
        st.success(f"Schedule **{schedule_name}** saved!")

    divider()

    # ── Existing schedules ────────────────────────────────────────
    section_header("Active Schedules", icon="📅")

    schedules = st.session_state.get("schedules", [])

    if not schedules:
        st.info("No schedules configured. Create one above.")
        return

    for i, sched in enumerate(schedules):
        enabled = sched.get("enabled", True)
        status_icon = "🟢" if enabled else "⚪"

        with st.expander(f'{status_icon}  {sched["name"]} — {sched["frequency"]} at {sched.get("time_utc", "06:00")} UTC'):
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown(f"**Schedule:** `{sched.get('cron', '')}`")
                st.markdown(f"**Created:** {sched.get('created', '')}")
            with c2:
                st.markdown(f"**Regions:** {', '.join(sched.get('regions', []))}")
                st.markdown(f"**Accounts:** {sched.get('accounts', 'Current account')}")
            with c3:
                reg_names = [REGULATIONS.get(r, {}).get("name", r) for r in sched.get("regulations", [])]
                st.markdown(f"**Regulations:** {', '.join(reg_names)}")
                st.markdown(f"**Notify on critical:** {'Yes' if sched.get('notify_critical') else 'No'}")

            st.markdown("---")
            st.markdown("**EventBridge Rule (for AWS deployment):**")
            payload = {
                "action": "scan",
                "accounts": sched.get("accounts", ""),
                "regions": ",".join(sched.get("regions", [])),
                "regulations": ",".join(sched.get("regulations", [])),
            }
            import json
            st.code(
                f'aws events put-rule \\\n'
                f'  --name "sovereign-shield-{sched["name"].lower().replace(" ", "-")}" \\\n'
                f'  --schedule-expression "{sched.get("cron", "")}" \\\n'
                f'  --state {"ENABLED" if enabled else "DISABLED"}\n\n'
                f'aws events put-targets \\\n'
                f'  --rule "sovereign-shield-{sched["name"].lower().replace(" ", "-")}" \\\n'
                f'  --targets \'[{{"Id":"scan","Arn":"arn:aws:lambda:REGION:ACCOUNT:function:sovereign-shield-scan",'
                f'"Input":"{json.dumps(payload).replace(chr(34), chr(92)+chr(34))}"}}]\'',
                language="bash",
            )

            bc1, bc2, bc3 = st.columns(3)
            with bc1:
                new_state = not enabled
                label = "Disable" if enabled else "Enable"
                if st.button(f"{'⚪' if enabled else '🟢'}  {label}", key=f"toggle_{i}"):
                    st.session_state.schedules[i]["enabled"] = new_state
                    st.rerun()
            with bc3:
                if st.button("🗑️  Delete", key=f"delete_{i}"):
                    del st.session_state.schedules[i]
                    st.rerun()
