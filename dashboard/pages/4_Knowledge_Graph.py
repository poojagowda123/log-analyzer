
import streamlit as st
import streamlit.components.v1 as components
from pathlib import Path
import os
import sys

# Add src to path just in case
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(BASE_DIR / "src"))

try:
    from graph_analysis import build_graph
except ImportError:
    build_graph = None

from frontend_design import inject_custom_css, render_header, render_footer

st.set_page_config(
    page_title="KNOWLEDGE GRAPH",
    page_icon="🕸️",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_custom_css()

# Paths
HTML_PATH = BASE_DIR / "Output" / "knowledge_graph.html"

render_header("RELATIONAL INTELLIGENCE", "USER <> IP <> EVENT RELATIONSHIPS")

c1, c2 = st.columns([3, 1])
with c1:
    st.markdown("""
    <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 8px; margin-bottom: 20px;">
        <p style="color: #94a3b8; font-size: 0.9rem; margin: 0;">
            This interactive graph visualizes connections between <b>Users</b> (Blue) and <b>IP Addresses</b> (Nodes).
            <br>Large clusters indicate shared resources or potential <b>lateral movement</b>.
            <br>Red links indicate failed login attempts.
        </p>
    </div>
    """, unsafe_allow_html=True)

with c2:
    if st.button("REGENERATE GRAPH", use_container_width=True):
        if build_graph:
            with st.spinner("Analyzing relationships..."):
                build_graph()
            st.success("Graph Updated!")
            st.rerun()
        else:
            st.error("Graph Analysis module not found.")

# Display Graph
if HTML_PATH.exists():
    with open(HTML_PATH, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Render with Streamlit Components
    components.html(html_content, height=750, scrolling=True)
else:
    st.info("No Graph Generated yet. Click 'REGENERATE GRAPH' to start.")
    # Auto-generate on first load if missing
    if build_graph:
        build_graph()
        st.rerun()

render_footer()
