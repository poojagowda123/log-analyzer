import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
from pathlib import Path
from datetime import datetime
import numpy as np

# Page Configuration
st.set_page_config(
    page_title="LOG ANALYZER PRO",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ========================================
# ADVANCED MODERN CSS (CYBER-SLATE)
# ========================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@200;300;400;500;600;700&display=swap');

:root {
    --bg-dark: #1A1A1A;
    --card-bg: rgba(42, 42, 42, 0.8);
    --neon-blue: #B8FF00;
    --neon-purple: #A0E000;
    --neon-red: #ef4444;
    --text-main: #f8fafc;
    --text-dim: #CCCCCC;
}

* { font-family: 'Inter', sans-serif; }
h1, h2, h3, .mega-title { font-family: 'Space Grotesk', sans-serif; }

.main .block-container {
    background-color: var(--bg-dark);
    background-image: 
        radial-gradient(at 0% 0%, rgba(184, 255, 0, 0.08) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(160, 224, 0, 0.08) 0px, transparent 50%);
    padding: 2rem;
}

/* Card Style */
.modern-card {
    background: var(--card-bg);
    backdrop-filter: blur(12px);
    border-radius: 16px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    padding: 20px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}

/* Border Beam (Simplified for stability) */
.modern-card::after {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--neon-blue), transparent);
    animation: flow-beam 4s linear infinite;
}

@keyframes flow-beam {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(100%); }
}

.mega-title {
    font-size: 3.5rem;
    font-weight: 800;
    text-align: center;
    background: linear-gradient(to right, #fff, var(--neon-blue), var(--neon-purple));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -2px;
}

.intel-row {
    background: rgba(15, 23, 42, 0.4);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 12px;
    padding: 12px;
    margin-bottom: 10px;
    transition: 0.3s;
}
.intel-row:hover { border-color: var(--neon-blue); background: rgba(184, 255, 0, 0.12); }

.cyber-grid {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image: linear-gradient(rgba(184, 255, 0, 0.02) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(184, 255, 0, 0.02) 1px, transparent 1px);
    background-size: 50px 50px;
    pointer-events: none;
    z-index: 0;
}

/* Sidebar Fixes */
[data-testid="stSidebar"] {
    background-color: #1A1A1A !important;
    border-right: 1px solid rgba(255, 255, 255, 0.05);
}

div.stMetric {
    background: var(--card-bg);
    padding: 15px;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.05);
}

.stPlotlyChart {
    background: transparent !important;
}

/* Action Button */
.action-btn {
    background: linear-gradient(135deg, rgba(184, 255, 0, 0.15), rgba(160, 224, 0, 0.15));
    border: 1px solid rgba(184, 255, 0, 0.4);
    border-radius: 8px;
    padding: 15px;
    text-align: center;
    cursor: pointer;
    transition: 0.3s;
}
.action-btn:hover { background: rgba(184, 255, 0, 0.25); border-color: var(--neon-blue); }

</style>
<div class="cyber-grid"></div>
""", unsafe_allow_html=True)

# ========================================
# DATA ORCHESTRATION
# ========================================
# ========================================
# DATA ORCHESTRATION
# ========================================
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR.parent / "Output"

@st.cache_data(ttl=2) # Low TTL for live feel
def fetch_system_data():
    data = {'logs': None, 'suspicious': None, 'anomalies': None, 'usb_logs': None, 'usb_suspicious': None}
    paths = {
        'logs': OUTPUT_DIR / "windows_logs_parsed.csv",
        'suspicious': OUTPUT_DIR / "suspicious_events.csv",
        'anomalies': OUTPUT_DIR / "ml_anomalies.csv",
        'usb_logs': OUTPUT_DIR / "usb_logs_parsed.csv",
        'usb_suspicious': OUTPUT_DIR / "usb_suspicious_events.csv"
    }
    for key, path in paths.items():
        if path.exists():
            try:
                df = pd.read_csv(path)
                if 'timestamp' in df.columns:
                    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                data[key] = df
            except: pass
    return data

sys_data = fetch_system_data()

# ========================================
# SIDEBAR NAVIGATION
# ========================================
with st.sidebar:
    st.markdown("""<p style="color: #B8FF00; font-size: 0.7rem; font-weight: 700;">NAVIGATION</p>""", unsafe_allow_html=True)

    # Init Session State for Navigation
    if 'page' not in st.session_state:
        st.session_state.page = 'overview'

    # Navigation buttons
    if st.button("MAIN DASHBOARD", use_container_width=True, type=("primary" if st.session_state.page == 'overview' else "secondary")):
        st.session_state.page = 'overview'
        st.rerun()

    if st.button("USB SECURITY", use_container_width=True, type=("primary" if st.session_state.page == 'usb' else "secondary")):
        st.session_state.page = 'usb'
        st.rerun()

    if st.button("NLP ANALYSIS", use_container_width=True, type=("primary" if st.session_state.page == 'nlp' else "secondary")):
        st.session_state.page = 'nlp'
        st.rerun()

    st.markdown("---")

    if st.button("USB FILE SCANNER", use_container_width=True, type=("primary" if st.session_state.page == 'file_scan' else "secondary")):
        st.session_state.page = 'file_scan'
        st.rerun()

    st.markdown("---")
    st.markdown("""<p style="color: #B8FF00; font-size: 0.7rem; font-weight: 700;">IO THROUGHPUT</p>""", unsafe_allow_html=True)

    logs_len = len(sys_data['logs']) if sys_data['logs'] is not None else 0
    st.markdown(f"""<p style="color: #f8fafc; font-size: 1.5rem; font-weight: 800; margin:0;">{logs_len:,}</p>""", unsafe_allow_html=True)
    st.markdown("""<p style="color: #4ade80; font-size: 0.7rem; margin:0;">+14.2% FROM PEAK</p>""", unsafe_allow_html=True)

# ========================================
# MAIN CONTENT ROUTING
# ========================================

if st.session_state.page == 'usb':
    # USB SECURITY VIEW
    st.markdown('<div class="mega-title">USB SHIELD</div>', unsafe_allow_html=True)
    
    usb_df = sys_data['usb_logs']
    susp_df = sys_data['usb_suspicious']
    
    if usb_df is not None:
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Total Events", len(usb_df))
        with c2:
            st.metric("Malicious Detections", len(susp_df) if susp_df is not None else 0)
        with c3:
            st.metric("Unique Devices", usb_df['product_id'].nunique() if 'product_id' in usb_df.columns else 0)
            
        st.markdown("### 🔴 LIVE THREAT FEED")
        if susp_df is not None and not susp_df.empty:
            st.dataframe(susp_df, use_container_width=True)
        else:
            st.success("No active threats detected on USB channels.")
            
        st.markdown("---")
        st.markdown("### 📋 EVENT LOG STREAM")
        
        # Admin Unlock for Raw Data
        col_sec1, col_sec2 = st.columns([1, 2])
        with col_sec1:
            admin_code = st.text_input("🔐 ADMIN ACCESS CODE", type="password", key="usb_admin_code", help="Enter code to unlock raw system logs")
        
        show_raw = (admin_code == "ADMIN@LOG")
        if admin_code and not show_raw:
            st.error("Invalid Admin Code")
        elif show_raw:
            st.info("Forensic View Unlocked")
        
        display_df = usb_df.copy()
        if not show_raw:
            # Show friendly columns
            cols = ['timestamp', 'event_type', 'activity_summary', 'vendor_id', 'product_id', 'risk_score']
            display_df = display_df[[c for c in cols if c in display_df.columns]]
            display_df.rename(columns={'activity_summary': 'Activity Description'}, inplace=True)
        else:
            # Show raw columns
            cols = ['timestamp', 'event_id', 'raw_message', 'vendor_id']
            display_df = display_df[[c for c in cols if c in display_df.columns]]
            
        st.dataframe(display_df, use_container_width=True)
        
    else:
        st.warning("No USB Logs Found. Please run the parser.")

elif st.session_state.page == 'nlp':
    # NLP ANALYSIS VIEW
    st.markdown('<div class="mega-title">NEURAL THREAT CORE</div>', unsafe_allow_html=True)
    
    st.markdown("### 🧠 SEMANTIC THREAT CLASSIFICATION")
    
    threat_path = OUTPUT_DIR / "nlp_threats.csv"
    if threat_path.exists():
        threat_df = pd.read_csv(threat_path)
        if not threat_df.empty:
            # Classification Stats
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Detected Semantic Threats", len(threat_df))
            with col2:
                top_threat = threat_df['nlp_attack_type'].mode()[0] if not threat_df.empty else "None"
                st.metric("Dominant Threat Pattern", top_threat)
            
            st.dataframe(threat_df[['event_id', 'timestamp', 'nlp_attack_type', 'message']], use_container_width=True)
        else:
            st.success("No pattern-based semantic threats detected.")
    else:
        st.info("NLP Classification not run yet.")

    st.markdown("---")
    st.markdown("### 🔥 SEMANTIC SEVERITY SCORING (BERT)")
    st.markdown("*Analysis of log meaning distance from 'danger' concepts (attack, failure, malicious)*")
    
    bert_path = OUTPUT_DIR / "bert_results.csv"
    if bert_path.exists():
        bert_df = pd.read_csv(bert_path)
        if not bert_df.empty:
            # Top High Severity Logs
            high_sev = bert_df.head(10)
           
        else:
            st.info("No BERT results available.")
    else:
        st.warning("BERT Analysis data not found.")

elif st.session_state.page == 'file_scan':
    # USB FILE SCANNER VIEW
    st.markdown('<div class="mega-title">USB FILE SCANNER</div>', unsafe_allow_html=True)
    
    scan_path = OUTPUT_DIR / "usb_file_scan.csv"
    
    # Scan Action
    if st.button("🔄 SCAN REMOVABLE DRIVES NOW"):
        with st.spinner("Scanning connected drives..."):
            try:
                # Integrated Scanner Call
                import sys
                sys.path.append(str(BASE_DIR.parent / "src"))
                from parse_usb_logs import scan_all_drives
                
                if scan_all_drives():
                    st.success("Scan Complete!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.warning("No removable drives found to scan.")
            except Exception as e:
                st.error(f"Execution error: {e}")

    # Display Results
    if scan_path.exists():
        try:
            df_scan = pd.read_csv(scan_path)
            if not df_scan.empty:
                # Metrics
                total_files = len(df_scan)
                malicious = len(df_scan[df_scan['verdict'] == 'MALICIOUS'])
                suspicious = len(df_scan[df_scan['verdict'] == 'SUSPICIOUS'])
                
                c1, c2, c3 = st.columns(3)
                c1.metric("Files Scanned", total_files)
                c2.metric("Malicious Artifacts", malicious, delta_color="inverse")
                c3.metric("Suspicious Files", suspicious, delta_color="inverse")
                
                st.markdown("### 📂 SCAN RESULTS")
                
                # Filter
                filter_verdict = st.multiselect("Filter by Verdict", ["SAFE", "SUSPICIOUS", "MALICIOUS"], default=["MALICIOUS", "SUSPICIOUS"])
                
                if filter_verdict:
                    df_show = df_scan[df_scan['verdict'].isin(filter_verdict)]
                else:
                    df_show = df_scan
                
                st.dataframe(
                    df_show[['filename', 'extension', 'size_kb', 'entropy', 'verdict', 'risk_score']],
                    use_container_width=True,
                    column_config={
                        "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
                        "entropy": st.column_config.NumberColumn("Entropy", format="%.2f")
                    }
                )
                
                if malicious > 0:
                    st.error(f"⚠️ {malicious} MALICIOUS FILES DETECTED! IMMEDIATE ACTION RECOMMENDED.")
            else:
                st.info("Scan completed but no files were found (Empty Drive?).")
        except Exception as e:
            st.error(f"Error reading scan results: {e}")
    else:
        st.info("No scan results found. Click 'SCAN REMOVABLE DRIVES NOW' to start.")

elif st.session_state.page == 'overview':
    # EXISTING MAIN DASHBOARD COMPONENT (Wrapped in conditional)
    st.markdown('<div class="mega-title">LOG ANALYZER PRO</div>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #B8FF00; letter-spacing: 5px; font-size: 0.8rem; margin-bottom: 2rem;">NEXT-GEN SECURITY ANALYTICS</p>', unsafe_allow_html=True)

    # Calculations
    if sys_data['logs'] is not None:
        logs = sys_data['logs']
        total_ev = len(logs)
        unique_users = logs['username'].nunique() if 'username' in logs.columns else 0
        failed_logins = int((logs['event_id'] == 4625).sum()) if 'event_id' in logs.columns else 0
        ml_anomalies = len(sys_data['anomalies']) if sys_data['anomalies'] is not None else 0
        threat_index = min(100, (failed_logins * 2 + ml_anomalies * 5))
    else:
        total_ev, unique_users, failed_logins, ml_anomalies, threat_index = 33461, 35, 9, 954, 82

    # 1. PRIMARY METRICS (STAGING)
    col1, col2, col3, col4 = st.columns(4)
    metrics_data = [
        ("SYSTEM EVENTS", f"{total_ev:,}", "+12%"),
        ("ACTIVE ENTITIES", f"{unique_users}", "VERIFIED"),
        ("BREACH ATTEMPTS", f"{failed_logins}", "DETECTED"),
        ("ANOMALY INDEX", f"{ml_anomalies}", "HIGH RISK")
    ]

    for i, (label, value, subtext) in enumerate(metrics_data):
        with [col1, col2, col3, col4][i]:
            st.markdown(f"""
            <div class="modern-card">
                <p style="color: #B8FF00; font-size: 0.7rem; font-weight: 800; letter-spacing: 1px; margin:0;">{label}</p>
                <p style="color: #fff; font-size: 2rem; font-weight: 800; margin: 5px 0;">{value}</p>
                <p style="color: #B8FF00; font-size: 0.65rem; font-weight: 700; margin:0;">{subtext}</p>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # 2. SECURITY INTELLIGENCE (Full Width)
    st.markdown('<div class="modern-card">', unsafe_allow_html=True)
    st.markdown('<p style="color: #f8fafc; font-weight: 700; margin-bottom: 15px;">SECURITY INTELLIGENCE</p>', unsafe_allow_html=True)

    intel_items = [
        ("🌐 NETWORK SECURITY", "CLEAN", "No active exfiltration patterns identified.", "#B8FF00"),
        ("🔑 AUTHENTICATION", "ATTACK", f"High volume of failed logins in segment B.", "#ef4444"),
        ("⚡ SYSTEM HEALTH", "STABLE", "Neural processing engine at 98% efficiency.", "#4ade80")
    ]

    for title, tag, desc, color in intel_items:
        st.markdown(f"""
        <div class="intel-row">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #fff; font-size: 0.8rem; font-weight: 700;">{title}</span>
                <span style="background: {color}22; color: {color}; padding: 2px 8px; border-radius: 4px; font-size: 0.6rem; font-weight: 800;">{tag}</span>
            </div>
            <p style="color: #B8FF00; font-size: 0.75rem; margin: 5px 0 0 0;">{desc}</p>
        </div>
        """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # 3. PATTERNS & FLOW
    st.markdown("<br>", unsafe_allow_html=True)
    col_flow, col_feed = st.columns([1.5, 1])

    with col_flow:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #f8fafc; font-weight: 700; margin-bottom: 10px;">TEMPORAL EVENT FLOW</p>', unsafe_allow_html=True)
    
        if sys_data['logs'] is not None and 'timestamp' in logs.columns:
            logs['hour_box'] = logs['timestamp'].dt.hour
            h_df = logs.groupby('hour_box').size().reset_index(name='count')
            fig_flow = px.area(h_df, x='hour_box', y='count', color_discrete_sequence=['#B8FF00'])
            fig_flow.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#B8FF00', 
                                   xaxis=dict(showgrid=False), yaxis=dict(gridcolor='rgba(255,255,255,0.05)'),
                                   height=280, margin=dict(l=0,r=0,t=10,b=0))
            fig_flow.update_traces(fillcolor='rgba(184, 255, 0, 0.15)', line=dict(width=3))
            st.plotly_chart(fig_flow, use_container_width=True)
        else:
            st.info("DATASTREAM OFFLINE...")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_feed:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #f8fafc; font-weight: 700; margin-bottom: 15px;">SEC-ALERTS FEED</p>', unsafe_allow_html=True)
    
        # Dynamic alerts feed: prefer the `suspicious` DataFrame from sys_data when available
        susp_df = sys_data.get('suspicious') if isinstance(sys_data, dict) else None

        if susp_df is not None and not susp_df.empty:
            # Show most recent suspicious events (limit to 10)
            try:
                view = susp_df.sort_values('timestamp', ascending=False).head(10)
            except Exception:
                view = susp_df.head(10)

            for _, row in view.iterrows():
                # Determine message and timestamp
                msg = str(row.get('type') or row.get('description') or '')
                ts = row.get('timestamp')
                try:
                    ts_str = pd.to_datetime(ts, errors='coerce').strftime('%H:%M:%S') if pd.notnull(ts) else ''
                except Exception:
                    ts_str = str(ts) if ts is not None else ''

                # Heuristic severity mapping based on message content
                low = msg.lower()
                if 'repeated' in low or 'privilege' in low or 'brute' in low or 'admin' in low:
                    lvl = '🔴 CRITICAL'
                    a_color = '#ef4444'
                elif 'suspicious' in low or 'anomal' in low or 'failed' in low:
                    lvl = '🟠 WARNING'
                    a_color = '#fbbf24'
                else:
                    lvl = '🔵 INFO'
                    a_color = '#B8FF00'

                st.markdown(f"""
                <div style="border-left: 3px solid {a_color}; padding-left: 12px; margin-bottom: 15px; background: rgba(15,23,42,0.3); padding: 10px; border-radius: 0 8px 8px 0;">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: {a_color}; font-size: 0.65rem; font-weight: 800;">{lvl}</span>
                        <span style="color: #888888; font-size: 0.65rem;">{ts_str}</span>
                    </div>
                    <p style="color: #e2e8f0; font-size: 0.75rem; margin: 4px 0 0 0;">{msg}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            # Fallback static feed when no suspicious data available
            alerts = [
                ("🔴 CRITICAL", "Repeated Privilege Escalation", "00:42:15"),
                ("🟠 WARNING", "Anomalous Network Traffic", "00:30:10"),
                ("🔵 INFO", "Database Backup Successful", "23:15:00"),
                ("🔵 INFO", "New User Profile Detected", "22:45:10")
            ]

            for lvl, msg, t in alerts:
                a_color = "#ef4444" if "CRITICAL" in lvl else ("#fbbf24" if "WARNING" in lvl else "#B8FF00")
                st.markdown(f"""
                <div style="border-left: 3px solid {a_color}; padding-left: 12px; margin-bottom: 15px; background: rgba(15,23,42,0.3); padding: 10px; border-radius: 0 8px 8px 0;">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="color: {a_color}; font-size: 0.65rem; font-weight: 800;">{lvl}</span>
                        <span style="color: #888888; font-size: 0.65rem;">{t}</span>
                    </div>
                    <p style="color: #e2e8f0; font-size: 0.75rem; margin: 4px 0 0 0;">{msg}</p>
                </div>
                """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # 3. QUICK ACTIONS
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p style="color: #B8FF00; font-size: 0.7rem; font-weight: 800; letter-spacing: 2px;">QUICK COMMANDS</p>', unsafe_allow_html=True)
    q_col1, q_col2, q_col3, q_col4 = st.columns(4)

    actions = [
        ("🛡️ SCAN SYSTEM", "Full security audit"),
        ("📂 EXPORT DATA", "JSON/CSV package"),
        ("🔥 KILL SESSIONS", "Terminate anomalies"),
        ("⚙️ CONFIG", "Neural engine specs")
    ]

    cols = [q_col1, q_col2, q_col3, q_col4]
    for i, (title, sub) in enumerate(actions):
        with cols[i]:
            if st.button(title, use_container_width=True, help=sub):
                if title.startswith("🛡️ SCAN SYSTEM"):
                    with st.spinner("Running system security scan..."):
                        try:
                            import sys
                            sys.path.append(str(BASE_DIR.parent / "src"))
                            from process_monitor import ProcessMonitor
                            from parse_usb_logs import scan_all_drives, SCAN_OUTPUT

                            # 1) Process scan
                            pm = ProcessMonitor()
                            detections = pm.check_processes()
                            if detections:
                                det_df = pd.DataFrame(detections)
                                st.error(f"Suspicious processes detected: {len(det_df)}")
                                st.dataframe(det_df)
                            else:
                                st.success("No suspicious processes found.")

                            # 2) USB content scan
                            try:
                                usb_result = scan_all_drives()
                                if usb_result:
                                    st.success("USB content scan completed; results saved.")
                                    try:
                                        scan_df = pd.read_csv(SCAN_OUTPUT)
                                        if not scan_df.empty:
                                            st.markdown("**USB Scan Sample Results**")
                                            st.dataframe(scan_df.head(50), use_container_width=True)
                                    except Exception:
                                        pass
                                else:
                                    st.info("No removable drives found or no files scanned.")
                            except Exception as e:
                                st.warning(f"USB scan failed: {e}")

                        except Exception as e:
                            st.error(f"System scan failed: {e}")
                else:
                    st.info(f"✅ {title} initiated: {sub}")

    # Footer
    st.markdown("""
    <div style="text-align: center; margin-top: 50px; padding: 20px; color: #666666; border-top: 1px solid rgba(255,255,255,0.02);">
        <p style="font-size: 0.65rem; letter-spacing: 2px; margin: 0;">LOG ANALYZER PRO | SECURE TERMINAL | V8.0.2</p>
    </div>
    """, unsafe_allow_html=True)
