import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime
import numpy as np

from frontend_design import inject_custom_css, render_header, render_footer, render_metric_card

# Page Configuration
st.set_page_config(
    page_title="LOG EXPLORER",
    page_icon="📄",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Cyber-Slate CSS
inject_custom_css()

# Data Ingestion
BASE_DIR = Path(__file__).resolve().parent.parent.parent
FILE_PATH = BASE_DIR / "Output" / "windows_logs_parsed.csv"

def humanize_event(event_id, username, ip):
    user = username if username and username != "Unknown" else "SYSTEM"
    if event_id == 4624: return f"Successful auth for {user}"
    elif event_id == 4625: return f"Auth failure on entry point for {user}"
    elif event_id == 4672: return f"Elevated privileges granted to {user}"
    return f"Security event {event_id} involving {user}"

@st.cache_data
def load_data():
    if not FILE_PATH.exists(): return None
    df = pd.read_csv(FILE_PATH)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["human_msg"] = df.apply(lambda r: humanize_event(r["event_id"], r["username"], r.get("ip","")), axis=1)
    return df

df = load_data()

if df is not None:
    render_header("LOG EXPLORER", "RECORDS DATABASE | RECOVERY MODE ACTIVE")
    st.markdown("<br>", unsafe_allow_html=True)

    # Filter Bar
    with st.expander("🔍 ADVANCED QUERY FILTERS", expanded=False):
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            u_select = st.selectbox("ENTITY", ["ALL"] + sorted(df["username"].unique().tolist()))
        with f_col2:
            e_select = st.multiselect("EVENT CLASS", sorted(df["event_id"].unique().tolist()))
        with f_col3:
            search = st.text_input("QUERY STRING", placeholder="Search in logs...")

    # Logic
    df_f = df.copy()
    if u_select != "ALL": df_f = df_f[df_f["username"] == u_select]
    if e_select: df_f = df_f[df_f["event_id"].isin(e_select)]
    if search: df_f = df_f[df_f.stack().str.contains(search, case=False).unstack().any(axis=1)]

    # Metrics
    m1, m2, m3 = st.columns(3)
    with m1:
        render_metric_card("TOTAL QUERIED", f"{len(df_f):,}", "MONITORED")
    with m2:
        render_metric_card("UNIQUE ENTITIES", f"{df_f['username'].nunique()}", "IDENTIFIED")
    with m3:
        last_rec = df_f["timestamp"].max() if len(df_f)>0 else "N/A"
        render_metric_card("LAST RECORD", f"{last_rec}", "CHRONOLOGICAL")

    # Data Display
    st.markdown('<div class="modern-card">', unsafe_allow_html=True)
    
    # Admin Unlock for Raw Data
    col_sec1, col_sec2 = st.columns([1, 2])
    with col_sec1:
        admin_code = st.text_input("🔐 ADMIN ACCESS CODE", type="password", help="Enter code to unlock raw system logs")
    
    show_raw = (admin_code == "ADMIN@LOG")
    if admin_code and not show_raw:
        st.error("Invalid Admin Code")
    elif show_raw:
        st.info("Forensic View Unlocked")
    
    df_display = df_f.sort_values("timestamp", ascending=False)
    
    if not show_raw:
        # Friendly View
        cols = ["timestamp", "event_id", "username", "ip", "human_msg"]
        # Ensure cols exist
        final_cols = [c for c in cols if c in df_display.columns]
        st.dataframe(df_display[final_cols], use_container_width=True, height=600)
    else:
        # Forensic View
        cols = ["timestamp", "event_id", "message"]
        final_cols = [c for c in cols if c in df_display.columns]
        st.dataframe(df_display[final_cols], use_container_width=True, height=600)
        
    st.markdown('</div>', unsafe_allow_html=True)

    # Footer
    render_footer()
else:
    st.error("DATABASE NOT INITIALIZED. PLEASE PARSE SYSTEM LOGS.")
