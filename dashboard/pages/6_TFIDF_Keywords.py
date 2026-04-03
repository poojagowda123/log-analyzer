import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from frontend_design import inject_custom_css, render_header, render_footer, render_metric_card

# Page Configuration
st.set_page_config(
    page_title="KEYWORD INTELLIGENCE",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Cyber-Slate CSS
inject_custom_css()

# Data Path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
FILE_PATH = BASE_DIR / "Output" / "tfidf_results.csv"

def load_tfidf_data():
    if not FILE_PATH.exists(): return None
    try:
        return pd.read_csv(FILE_PATH)
    except: return None

df_tfidf = load_tfidf_data()

render_header("KEYWORD INTELLIGENCE", "TF-IDF SEMANTIC FEATURE EXTRACTION")
st.markdown("<br>", unsafe_allow_html=True)

if df_tfidf is not None and len(df_tfidf) > 0:
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        render_metric_card("ALGORITHM", "TF-IDF", "ACTIVE")
    with col2:
        render_metric_card("TOKENS ANALYZED", f"{len(df_tfidf)}", "IDENTIFIED")
    with col3:
        max_imp = f"{df_tfidf['importance'].max():.4f}"
        render_metric_card("PEAK SIGNIFICANCE", max_imp, "FEATURE")
    with col4:
        render_metric_card("LLM READINESS", "READY", "OPTIMIZED")

    # Main Analysis
    c1, c2 = st.columns([2, 1])
    
    with c1:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600;">TOP SIGNIFICANT SYSTEM TOKENS</p>', unsafe_allow_html=True)
        
        top_n = st.slider("Show Top Keywords", 5, 50, 20)
        df_plot = df_tfidf.head(top_n)
        
        fig = px.bar(df_plot, x='importance', y='keyword', orientation='h',
                    color='importance', color_continuous_scale='Blues')
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#94a3b8',
            margin=dict(l=0, r=0, t=10, b=0),
            height=600,
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
    with c2:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #fff; font-weight: 600;">RAW WEIGHTS</p>', unsafe_allow_html=True)
        st.dataframe(df_tfidf, use_container_width=True, height=600)
        st.markdown('</div>', unsafe_allow_html=True)

else:
    st.info("TF-IDF ANALYSIS HAS NOT BEEN RUN YET. PLEASE EXECUTE THE SEMANTIC ANALYZER.")

render_footer()
