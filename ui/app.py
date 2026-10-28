"""Sovereign Shield — Streamlit UI entry point."""

from __future__ import annotations

import io
import sys
from pathlib import Path

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Ensure project root is on sys.path so sovereign_shield imports work
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

import streamlit as st
from common import load_css, render_logo_header

st.set_page_config(
    page_title="Sovereign Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
load_css()

# ── Session state defaults ────────────────────────────────────────
DEFAULTS = {
    "scan_running": False,
    "scan_results": None,
    "violations": None,
    "remediations": None,
    "report_markdown": None,
    "scan_history": [],
    "schedules": [],
    "current_page": "Dashboard",
}
for key, val in DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = val

# ── Sidebar ───────────────────────────────────────────────────────
PAGES = [
    "Dashboard", "Run Scan", "Results", "Remediation",
    "SCP Policies", "Schedule", "Settings", "Help",
]
PAGE_ICONS = {
    "Dashboard": "📊", "Run Scan": "🔍", "Results": "📋", "Remediation": "🔧",
    "SCP Policies": "📜", "Schedule": "🕐", "Settings": "⚙️", "Help": "❓",
}

with st.sidebar:
    render_logo_header()
    st.markdown("")

    page = st.radio(
        "Navigation",
        options=PAGES,
        index=PAGES.index(st.session_state.current_page) if st.session_state.current_page in PAGES else 0,
        format_func=lambda x: f"{PAGE_ICONS.get(x, '')}  {x}",
        label_visibility="collapsed",
    )
    st.session_state.current_page = page

    st.markdown("---")
    st.caption("v0.1.0 · Strands Agents + Bedrock")

# ── Page router ───────────────────────────────────────────────────
if page == "Dashboard":
    from pages.dashboard import render
elif page == "Run Scan":
    from pages.run_scan import render
elif page == "Results":
    from pages.results import render
elif page == "Remediation":
    from pages.remediation import render
elif page == "SCP Policies":
    from pages.scp_policies import render
elif page == "Schedule":
    from pages.schedule import render
elif page == "Settings":
    from pages.settings import render
elif page == "Help":
    from pages.help import render

render()
