import streamlit as st
import pandas as pd
from pathlib import Path
from frontend_design import inject_custom_css, render_header, render_footer, render_metric_card

# Page Configuration
st.set_page_config(
    page_title="USB MONITOR",
    page_icon="🔌",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Cyber-Slate CSS
# Inject Cyber-Slate CSS
inject_custom_css()

# Define BASE_DIR first
BASE_DIR = Path(__file__).resolve().parent.parent.parent

import sys
import time
from datetime import datetime

import sys
src_path = BASE_DIR / "src"
sys.path.append(str(src_path))
try:
    from parse_usb_logs import save_usb_logs, scan_all_drives
except ImportError:
    pass

# Data Paths
USB_LOG = BASE_DIR / "Output" / "usb_logs_parsed.csv"
USB_ALERTS = BASE_DIR / "Output" / "usb_suspicious_events.csv"
USB_SCAN_FILE = BASE_DIR / "Output" / "usb_file_scan.csv"
USB_THREATS = BASE_DIR / "Output" / "usb_context_threats.csv"

render_header("USB MONITOR", "PERIPHERAL ACCESS & SECURITY")

# Real-Time Refresh Control
col_refresh, col_status = st.columns([1, 4])
with col_refresh:
    if st.button("🔄 SCAN DEVICES", use_container_width=True):
        with st.spinner("Scanning System Logs & Analyzing Drive Content..."):
            try:
                # 1. Update Logs
                save_usb_logs()
                
                # 2. Scan Files
                scan_success = scan_all_drives()
                
                if not scan_success:
                    st.error("❌ NO USB DRIVE DETECTED")
                else:
                    st.toast("Scan Complete: Logs & Files Updated", icon="✅")
                    time.sleep(1) # Brief pause for file flush
                    st.rerun()
            except Exception as e:
                st.error(f"Scan Failed: {e}")

with col_status:
    if USB_LOG.exists():
        last_mod = datetime.fromtimestamp(USB_LOG.stat().st_mtime).strftime("%H:%M:%S")
        st.caption(f"Last Synced: {last_mod}")

if USB_LOG.exists():
    df_usb = pd.read_csv(USB_LOG)
    if 'timestamp' in df_usb.columns:
        df_usb['timestamp'] = pd.to_datetime(df_usb['timestamp'])
        df_usb = df_usb.sort_values(by='timestamp', ascending=False)
    
    # Metrics
    m1, m2, m3 = st.columns(3)
    with m1:
        render_metric_card("TOTAL USB EVENTS", f"{len(df_usb)}", "LOGGED")
    with m2:
        unique_devs = df_usb['product_id'].nunique() if 'product_id' in df_usb.columns else 0
        render_metric_card("UNIQUE DEVICES", f"{unique_devs}", "IDENTIFIED")
    with m3:
        alerts_count = 0
        if USB_ALERTS.exists():
            df_alerts = pd.read_csv(USB_ALERTS)
            alerts_count = len(df_alerts)
        render_metric_card("SUSPICIOUS ACTIVITY", f"{alerts_count}", "CRITICAL" if alerts_count > 0 else "NONE")

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    
    # ----------------------------------------------------
    # REMOVED: Raw Logs & Threat Intel Tables (User Request)
    # ----------------------------------------------------

    # ----------------------------------------------------
    # NEW: DRIVE CONTENT ANALYSIS
    # ----------------------------------------------------
    if USB_SCAN_FILE.exists():
        st.markdown("<br>", unsafe_allow_html=True)
        # Header with Simulation Control
        h1, h2 = st.columns([3, 1])
        with h1:
            st.markdown('<p style="color: #38bdf8; font-weight: 600; font-size: 1.2rem;">📂 DRIVE CONTENT & ANOMALY SCAN RESULTS</p>', unsafe_allow_html=True)
        with h2:
            if st.button("🧪 SIMULATE MALWARE", help="Inject a fake malicious file for demo purposes"):
                # Inject a fake malicious file into the CSV
                try:
                    current_df = pd.read_csv(USB_SCAN_FILE)
                    fake_row = pd.DataFrame([{
                        'filename': 'WannaCry_Payload.exe',
                        'path': 'E:\\WannaCry_Payload.exe',
                        'extension': '.exe',
                        'size_kb': 450.2,
                        'entropy': 7.8,
                        'is_suspicious_ext': 1,
                        'has_double_ext': 0,
                        'anomaly_score': -1,
                        'verdict': 'MALICIOUS',
                        'risk_score': 95
                    }])
                    updated_df = pd.concat([current_df, fake_row], ignore_index=True)
                    updated_df.to_csv(USB_SCAN_FILE, index=False)
                    st.rerun()
                except Exception as e:
                    st.error(f"Simulation failed: {e}")
        
        try:
            df_scan = pd.read_csv(USB_SCAN_FILE)
            if not df_scan.empty:
                # Color code verdict
                def highlight_verdict(val):
                    color = 'red' if val == 'MALICIOUS' else 'orange' if val == 'SUSPICIOUS' else 'green'
                    return f'color: {color}; font-weight: bold'
                
                st.dataframe(
                    df_scan[['filename', 'extension', 'size_kb', 'entropy', 'verdict', 'reason', 'risk_score']],
                    use_container_width=True,
                    column_config={
                        "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
                        "entropy": st.column_config.NumberColumn("Entropy", format="%.2f", help="0-8 Scale (Higher = Encrypted/Compressed)"),
                        "reason": st.column_config.TextColumn("Detection Reason", width="medium")
                    }
                )
                
                mal_count = len(df_scan[df_scan['verdict'] == 'MALICIOUS'])
                if mal_count > 0:
                    st.error(f"🚨 {mal_count} MALICIOUS FILES DETECTED ON DRIVE! IMMEDIATE ACTION REQUIRED.")
                else:
                    st.success("✅ Drive Content Analysis Passed. No threats found.")
            else:
                st.info("No files found on the scanned drive.")
        except:
            st.warning("Could not read scan results.")
            
        st.markdown('</div>', unsafe_allow_html=True)

    # ----------------------------------------------------
    # NEW: CONTEXTUAL THREATS (Heuristics)
    # ----------------------------------------------------
    st.markdown("<br>", unsafe_allow_html=True)
    
    t1, t2 = st.columns([2, 1])
    
    with t1:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #ef4444; font-weight: 600; margin-bottom: 15px;">🧠 CONTEXTUAL THREAT ANALYSIS</p>', unsafe_allow_html=True)
        
        if USB_THREATS.exists():
            try:
                df_ctxt = pd.read_csv(USB_THREATS)
                if not df_ctxt.empty:
                    df_ctxt['timestamp'] = pd.to_datetime(df_ctxt['timestamp'])
                    df_ctxt = df_ctxt.sort_values('timestamp', ascending=False)
                    st.dataframe(
                        df_ctxt[['timestamp', 'threat_type', 'severity', 'details']],
                        use_container_width=True,
                        column_config={
                            "severity": st.column_config.TextColumn("Severity", help="Criticality Level")
                        }
                    )
                else:
                    st.success("No behavioral anomalies detected (Rapid insertions, Odd hours, etc.)")
            except:
                st.info("Waiting for analysis data...")
        else:
            st.info("Analysis pending next scan...")
        st.markdown('</div>', unsafe_allow_html=True)

    with t2:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600; margin-bottom: 15px;">ℹ️ THREAT KNOWLEDGE BASE</p>', unsafe_allow_html=True)
        
        # User's Requested Reference Table
        threat_ref = pd.DataFrame([
            {"Type": "Multiple Rapid Insertions", "Risk": "Data Exfiltration"},
            {"Type": "Odd Hour Usage", "Risk": "Insider Threat"},
            {"Type": "Unknown/New Device", "Risk": "Rogue Device"},
            {"Type": "During Security Anomaly", "Risk": "Coordinated Attack"},
            {"Type": "After Failed Logins", "Risk": "Credential + Data Theft"}
        ])
        st.table(threat_ref)
        st.markdown('</div>', unsafe_allow_html=True)

else:
    # AUTO-INITIALIZATION (User Request: "Have to run everytime")
    with st.spinner("Initializing USB Database for the first time..."):
        try:
            save_usb_logs()
            st.rerun()
        except Exception as e:
            st.error(f"Failed to initialize USB logs: {e}")

render_footer()
