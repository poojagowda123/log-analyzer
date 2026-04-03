import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from frontend_design import inject_custom_css, render_header, render_footer, render_metric_card

# Page Configuration
st.set_page_config(
    page_title="NEURAL SEMANTICS",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Cyber-Slate CSS
inject_custom_css()

# Data Path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
FILE_PATH = BASE_DIR / "Output" / "bert_results.csv"

def load_bert_data():
    if not FILE_PATH.exists(): return None
    try:
        return pd.read_csv(FILE_PATH)
    except: return None

df_bert = load_bert_data()

render_header("NEURAL SEMANTICS", "BERT-BASED SEMANTIC ANOMALY DETECTION")
st.markdown("<br>", unsafe_allow_html=True)

if df_bert is not None and len(df_bert) > 0:
    # --- Metrics Section ---
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_metric_card("MODEL ARCHITECTURE", "all-MiniLM-L6-v2 + K-Means", "HYBRID-NLP")
    with col2:
        render_metric_card("LOGS PROCESSED", f"{len(df_bert)}", "CLUSTERED")
    with col3:
        high_anom = len(df_bert[df_bert['semantic_outlier_score'] > 0.8])
        render_metric_card("SEMANTIC ANOMALIES", f"{high_anom}", "CRITICAL")
    with col4:
        # Most common semantic category
        if 'semantic_category' in df_bert.columns:
            try:
                top_cat = df_bert['semantic_category'].mode()[0]
                render_metric_card("DOMINANT CONTEXT", f"{top_cat}", "OBSERVED")
            except:
                render_metric_card("INFERENCE", "COMPLETED", "DISTRIBUTED")
        else:
            render_metric_card("INFERENCE", "COMPLETED", "DISTRIBUTED")

    # --- Semantic Map & Distribution ---
    col_map, col_dist = st.columns([2, 1])
    
    with col_map:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600;">SEMANTIC CLUSTER MAP (PCA PROJECTION)</p>', unsafe_allow_html=True)
        
        if 'pca_x' in df_bert.columns and 'pca_y' in df_bert.columns:
            fig_map = px.scatter(
                df_bert, x='pca_x', y='pca_y',
                color='semantic_category', 
                size='semantic_outlier_score',
                hover_data=['message', 'semantic_outlier_score'],
                color_discrete_sequence=px.colors.qualitative.Bold,
                template='plotly_dark'
            )
            fig_map.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=0, r=0, t=10, b=0),
                height=400,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.warning("PCA data not available. Please re-run analysis.")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_dist:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600;">ANOMALY DISTRIBUTION</p>', unsafe_allow_html=True)
        
        fig_hist = px.histogram(df_bert, x='semantic_outlier_score', nbins=30,
                          color_discrete_sequence=['#ef4444'])
        fig_hist.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#94a3b8',
            margin=dict(l=0, r=0, t=10, b=0),
            height=400
        )
        st.plotly_chart(fig_hist, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # --- Interactive Log Explorer ---
    st.markdown('<div class="modern-card">', unsafe_allow_html=True)
    st.markdown('<p style="color: #fff; font-weight: 600;">INTERACTIVE LOG EXPLORER (SELECT ROW FOR DETAILS)</p>', unsafe_allow_html=True)
    
    # Sort for display
    display_df = df_bert.sort_values('semantic_outlier_score', ascending=False).reset_index(drop=True)
    
    event = st.dataframe(
        display_df[['timestamp', 'semantic_category', 'message', 'semantic_outlier_score', 'semantic_severity_score']],
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun",
        column_config={
            "semantic_outlier_score": st.column_config.ProgressColumn("Anomaly", min_value=0, max_value=1, format="%.2f"),
            "semantic_severity_score": st.column_config.NumberColumn("Severity", format="%.2f"),
            "semantic_category": st.column_config.TextColumn("Context", width="small"),
            "message": st.column_config.TextColumn("Log Message", width="large")
        }
    )
    
    # --- Neural Insight Panel (Drill-Down) ---
    if len(event.selection['rows']) > 0:
        selected_index = event.selection['rows'][0]
        selected_row = display_df.iloc[selected_index]
        
        st.markdown("---")
        st.markdown(f"### 🔍 NEURAL INSIGHT: Event Analysis")
        
        drill_c1, drill_c2 = st.columns([2, 1])
        
        with drill_c1:
            st.info(f"**Log Message:** {selected_row['message']}")
            
            # Dynamic Explanation Generation (Rule-based augmentation)
            explanation = ""
            msg = str(selected_row['message'])
            
            if "SeAssignPrimaryTokenPrivilege" in msg:
                explanation = "**Explanation:** A process requested the 'Assign Primary Token' privilege. This is often used by services to launch processes as other users. If unexpected, it could indicate privilege escalation attempts."
            elif "4624" in msg or "Logon" in msg:
                explanation = "**Explanation:** A user successfully logged on to this computer."
            elif "4625" in msg or "failed" in msg.lower():
                explanation = "**Explanation:** A logon attempt failed. Multiple failures may indicate a brute-force attack."
            elif "10016" in msg and "DCOM" in msg:
                explanation = "**Explanation:** A program tried to start a DCOM server without proper permissions. This is a very common Windows configuration noise, usually benign but can be annoying."
            else:
                explanation = f"**Explanation:** This log was categorized as **{selected_row.get('semantic_category', 'Unknown')}**. The BERT model detected it as semantically distinct from the baseline (Anomaly Score: {selected_row.get('semantic_outlier_score', 0):.2f})."
            
            st.write(explanation)
            
        with drill_c2:
            st.metric("Anomaly Confidence", f"{selected_row['semantic_outlier_score']*100:.1f}%")
            st.metric("Severity Rating", f"{selected_row['semantic_severity_score']*100:.1f}%")
            st.caption(f"Cluster Group: {selected_row.get('cluster_id', 'N/A')}")

    st.markdown('</div>', unsafe_allow_html=True)

else:
    st.info("No analysis data found. Please run the backend analysis pipeline.")
    col_run, _ = st.columns([1, 4])
    with col_run:
        if st.button("Run Semantic Analysis Now"):
            with st.spinner("Initializing BERT model and processing logs..."):
                import sys
                sys.path.append(str(BASE_DIR / "src"))
                try:
                    from semantic_analysis import SemanticAnalyzer
                    # Need to trick system path if running from pages dir
                    # But simpler to just call the script logic
                    analyzer = SemanticAnalyzer()
                    analyzer.run_analysis()
                    st.success("Analysis Complete! Please refresh the page.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to run analysis: {e}")

render_footer()
