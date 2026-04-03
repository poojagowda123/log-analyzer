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
    page_title="THREAT MONITOR",
    page_icon="⚠️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Cyber-Slate CSS
inject_custom_css()

# Data Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ML_ANOMALIES = BASE_DIR / "Output" / "ml_anomalies.csv"
USB_THREATS = BASE_DIR / "Output" / "usb_context_threats.csv"
USB_SUSPICIOUS = BASE_DIR / "Output" / "usb_suspicious_events.csv"

def load_threat_data():
    dfs = []
    
    # 1. ML Anomalies
    if ML_ANOMALIES.exists():
        try:
            df = pd.read_csv(ML_ANOMALIES)
            df['source_type'] = 'ML Detection'
            # Map columns for unified view
            if 'anomaly_name' in df.columns: 
                df['description'] = df['anomaly_name']
            if 'ip' not in df.columns: df['ip'] = 'Unknown'
            dfs.append(df)
        except Exception as e: print(f"Error loading ML anomalies: {e}")

    # 2. USB Context Threats
    if USB_THREATS.exists():
        try:
            df = pd.read_csv(USB_THREATS)
            df['source_type'] = 'USB Security'
            if 'threat_type' in df.columns:
                df['description'] = df['threat_type']
            if 'details' in df.columns:
                df['message'] = df['details']
            df['ip'] = "Local Device"
            dfs.append(df)
        except: pass

    # 3. Suspicious USB Events
    if USB_SUSPICIOUS.exists():
        try:
           df = pd.read_csv(USB_SUSPICIOUS)
           df['source_type'] = 'USB Heuristic' 
           if 'reason' in df.columns:
               df['description'] = df['reason']
           df['severity'] = 'MEDIUM'
           df['ip'] = "Local Device"
           dfs.append(df)
        except: pass
        
    if not dfs: return None
    
    # Merge
    final_df = pd.concat(dfs, ignore_index=True)
    
    # Standardize Timestamp
    if 'timestamp' in final_df.columns:
        final_df['timestamp'] = pd.to_datetime(final_df['timestamp'], errors='coerce')
        final_df = final_df.sort_values('timestamp', ascending=False)
        
    # Standardize Severity
    if 'severity' not in final_df.columns:
        final_df['severity'] = 'MEDIUM'
    final_df['severity'] = final_df['severity'].fillna('MEDIUM').str.upper()
    
    # Metrics Helpers (If columns missing)
    if 'ip' not in final_df.columns: final_df['ip'] = 'Unknown'
    if 'description' not in final_df.columns: final_df['description'] = 'Unknown Event'
    
    return final_df

df_threats = load_threat_data()

render_header("THREAT MONITOR", "REAL-TIME ANOMALY DETECTION ENGINE")
st.markdown("<br>", unsafe_allow_html=True)

if df_threats is not None and len(df_threats) > 0:
    # 1. TOP METRICS STRIP
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    
    total_t = len(df_threats)
    high_t = len(df_threats[df_threats['severity'].str.upper().isin(['HIGH', 'CRITICAL'])])
    unique_ips = df_threats['ip'].nunique()
    peak_hour = df_threats['timestamp'].dt.hour.mode()[0] if 'timestamp' in df_threats.columns and not df_threats['timestamp'].isnull().all() else 0
    
    metrics = [
        ("TOTAL THREATS", f"{total_t}", "MONITORED"),
        ("CRITICAL/HIGH", f"{high_t}", "ACTION REQ"),
        ("UNIQUE SOURCES", f"{unique_ips}", "ATTACKERS"),
        ("PEAK VECTOR", f"{peak_hour}:00", "MAX ACTIVITY")
    ]
    
    for i, (label, val, sub) in enumerate(metrics):
        with [m_col1, m_col2, m_col3, m_col4][i]:
            render_metric_card(label, val, sub)

    st.markdown("<br>", unsafe_allow_html=True)

    # 2. ANALYSIS GRID
    t_col1, t_col2 = st.columns([2, 1])
    
    with t_col1:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600; margin-bottom: 15px;">INCIDENT TIMELINE</p>', unsafe_allow_html=True)
        
        # Timeline Chart
        df_threats['hour'] = df_threats['timestamp'].dt.hour
        t_counts = df_threats.groupby('hour').size().reset_index(name='count')
        
        fig = px.bar(t_counts, x='hour', y='count', color_discrete_sequence=['#ef4444'])
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#94a3b8',
            margin=dict(l=0, r=0, t=10, b=0),
            height=300,
            xaxis=dict(showgrid=False),
            yaxis=dict(gridcolor='rgba(255,255,255,0.05)')
        )
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with t_col2:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600; margin-bottom: 15px;">RECENT ALERTS</p>', unsafe_allow_html=True)
        
        # Sort by latest
        latest_threats = df_threats.sort_values(by='timestamp', ascending=False).head(5)
        
        for _, row in latest_threats.iterrows():
            severity = row.get('severity', 'MEDIUM').upper()
            color = "#ef4444" if severity in ['HIGH', 'CRITICAL'] else "#f59e0b"
            ts_str = row['timestamp'].strftime('%H:%M:%S') if pd.notnull(row.get('timestamp')) else ""
            
            st.markdown(f"""
            <div class="alert-row">
                <div style="display: flex; justify-content: space-between;">
                    <span style="color: {color}; font-size: 0.65rem; font-weight: 800;">{severity}</span>
                    <span style="color: #475569; font-size: 0.65rem;">{ts_str}</span>
                </div>
                <p style="color: #fff; font-size: 0.85rem; margin: 4px 0;">{row.get('description', 'Unknown Anomaly')}</p>
                <p style="color: #64748b; font-size: 0.7rem; margin: 0;">SRC: {row.get('ip', 'Unknown')} | USER: {row.get('username', 'N/A')}</p>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Filter by Alert Type (show a select box similar to the dashboard screenshot)
    st.markdown('<div class="modern-card">', unsafe_allow_html=True)
    st.markdown('<p style="color: #fff; font-weight: 600; margin-bottom: 15px;">ALL SECURITY INCIDENTS</p>', unsafe_allow_html=True)

    # Build alert type options from the description column (fallback to a few defaults)
    if 'description' in df_threats.columns:
        types = list(df_threats['description'].dropna().astype(str).unique())
    else:
        types = []

    # Provide a sensible ordering and include an "All" option
    types_sorted = sorted([t for t in types if t.lower() != 'unknown'])
    options = ['All'] + types_sorted

    st.markdown('<p style="color: #fff; font-weight: 600; margin-bottom: 8px;">Filter by Alert Type</p>', unsafe_allow_html=True)
    selected_type = st.selectbox('Type', options, index=0)

    # Prepare DataFrame view based on selection
    view_df = df_threats.copy()
    if selected_type != 'All':
        view_df = view_df[view_df['description'].astype(str) == selected_type]

    # Select Columns
    display_cols = ['timestamp', 'severity', 'source_type', 'description', 'ip', 'username', 'message']
    # Filter only existing columns
    final_cols = [c for c in display_cols if c in view_df.columns]

    st.dataframe(
        view_df.sort_values('timestamp', ascending=False)[final_cols], 
        use_container_width=True
    )
    st.markdown('</div>', unsafe_allow_html=True)
else:
    st.markdown("""
    <div style="text-align: center; margin-top: 100px;">
        <h2 style="color: #4ade80;">NO ACTIVE THREATS DETECTED</h2>
        <p style="color: #64748b;">System is currently operating within normal security parameters.</p>
    </div>
    """, unsafe_allow_html=True)
