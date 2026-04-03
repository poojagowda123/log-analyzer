import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime
import numpy as np

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent / "src"))
from generate_demo_data import DemoInjector

from frontend_design import inject_custom_css, render_header, render_footer, render_metric_card

# Initialize Injector
injector = DemoInjector()

# Page Configuration
st.set_page_config(
    page_title="NEURAL ANALYSIS",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Cyber-Slate CSS
inject_custom_css()

# Data Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ANOMALY_PATH = BASE_DIR / "Output" / "ml_anomalies.csv"
ATTACK_PATH = BASE_DIR / "Output" / "attack_identifications.csv"

def load_data(path):
    if not path.exists(): return None
    try:
        df = pd.read_csv(path)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df
    except: return None

df_anomalies = load_data(ANOMALY_PATH)
df_attacks = load_data(ATTACK_PATH)

render_header("NEURAL ANALYSIS", "MULTI-MODEL THREAT INTELLIGENCE")

# Tabs for different ML approaches
tab1, tab2 = st.tabs(["🧬 BEHAVIORAL ANOMALIES (UNSUPERVISED)", "🎯 ATTACK CLASSIFICATION (SUPERVISED)"])

with tab1:
    if df_anomalies is not None and len(df_anomalies) > 0:
        # Metrics (Global)
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            render_metric_card("ALGORITHM", "Isolation Forest", "STABLE")
        with col2:
            render_metric_card("DETECTED", f"{len(df_anomalies)}", "OUTLIERS")
        with col3:
            render_metric_card("SENSITIVITY", "3.0%", "CONFIGURED")
        with col4:
            render_metric_card("STATUS", "CONTINUOUS", "REAL-TIME")

        # FILTERING LOGIC (Moved here as requested)
        # -----------------------------------------------------
        all_anomalies = ["ALL"] + sorted(df_anomalies['anomaly_name'].unique().tolist())
        st.write("") # Spacer
        selected_anomaly = st.selectbox("👁️ FILTER VIEW BY ANOMALY:", all_anomalies)
        
        if selected_anomaly != "ALL":
            df_anomalies = df_anomalies[df_anomalies['anomaly_name'] == selected_anomaly]
        # -----------------------------------------------------

        # 1. DATA TABLE
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600;">ANOMALY DATASTREAM</p>', unsafe_allow_html=True)
        st.dataframe(df_anomalies.sort_values('ml_score'), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

        # 2. GRAPH (Below table)
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600;">BEHAVIORAL ANOMALY TIMELINE</p>', unsafe_allow_html=True)
        
        fig = px.scatter(df_anomalies, x='timestamp', y='ml_score', 
                        color='ml_score', color_continuous_scale='Purp',
                        hover_data=['username', 'event_id'])
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#94a3b8',
            margin=dict(l=0, r=0, t=10, b=0),
            height=400,
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    else:
        st.info("NO BEHAVIORAL ANOMALIES DETECTED.")

with tab2:
    if df_attacks is not None and len(df_attacks) > 0:
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            render_metric_card("ALGORITHM", "Random Forest", "MASTERED")
        with col2:
            render_metric_card("CLASSIFIED", f"{len(df_attacks)}", "THREATS")
        with col3:
            unique_types = df_attacks['identified_attack'].nunique()
            render_metric_card("VECTORS", f"{unique_types}", "IDENTIFIED")
        with col4:
            avg_conf = f"{df_attacks['attack_confidence'].mean()*100:.1f}%"
            render_metric_card("CONFIDENCE", avg_conf, "AGGREGATE")

        c1, c2 = st.columns(2)
        
        with c1:
            st.markdown('<div class="modern-card">', unsafe_allow_html=True)
            st.markdown('<p style="color: #fff; font-weight: 600;">ATTACK DISTRIBUTION</p>', unsafe_allow_html=True)
            counts = df_attacks['identified_attack'].value_counts()
            
            # Pie Chart (Visual Only)
            fig_pie = px.pie(values=counts.values, names=counts.index, 
                            color_discrete_sequence=px.colors.sequential.RdBu)
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='#94a3b8',
                margin=dict(l=0, r=0, t=0, b=0),
                height=250,
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with c2:
             st.markdown('<div class="modern-card">', unsafe_allow_html=True)
             st.markdown('<p style="color: #fff; font-weight: 600;">RECENT ALERTS</p>', unsafe_allow_html=True)
             # Simple recent alerts list
             for i, row in df_attacks.head(3).iterrows():
                 st.markdown(f"**{row['identified_attack']}** - {row['severity']}")
                 st.caption(f"{row['timestamp']} | {row['source']}")
                 st.divider()
             st.markdown('</div>', unsafe_allow_html=True)


        # =========================================================
        # OPERATIONS CENTER (Controls Above Table)
        # =========================================================
        # =========================================================
        # CONTROLS (Above Table)
        # =========================================================
        # Layout: [Left Answer: Injection] [Right Answer: Filtering]
        # =========================================================
        # CONTROLS (Above Table)
        # =========================================================
        
        col_filter, col_clear = st.columns([3, 1])
        
        with col_filter:
            all_attacks = ["ALL"] + sorted(df_attacks['identified_attack'].unique().tolist())
            selected_attack_view = st.selectbox("🔍 FILTER VIEW BY ATTACK TYPE:", all_attacks)
            
        with col_clear:
            st.write("") # Spacer for alignment
            st.write("")
            if st.button("🧹 CLEAR ALL DATA", type="primary", use_container_width=True):
                injector.clear_data()
                st.toast("All Anomaly Data Cleared", icon="🧹")
                st.rerun()
            
        # FILTER LOGIC
        if selected_attack_view != "ALL":
            df_attacks = df_attacks[df_attacks['identified_attack'] == selected_attack_view]

        # TABLE
        st.markdown('<br>', unsafe_allow_html=True)
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600;">IDENTIFIED ATTACK LOGS</p>', unsafe_allow_html=True)
        
        # User requested specific columns: Data, Count, Timestamp
        # We ensure important columns are visible
        display_cols = ['timestamp', 'identified_attack', 'failed_count', 'severity', 'attack_confidence', 'source', 'ip', 'message']
        # Filter columns that actually exist
        final_cols = [c for c in display_cols if c in df_attacks.columns]
        
        st.dataframe(df_attacks[final_cols].sort_values('timestamp', ascending=False), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("NO SPECIFIC ATTACK PATTERNS CLASSIFIED BY RANDOM FOREST.")

render_footer()
