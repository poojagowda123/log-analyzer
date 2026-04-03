import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import base64

# ========================================
# FRONTEND DESIGN SYSTEM
# ========================================

def setup_page_config():
    """Initializes the Streamlit page configuration."""
    st.set_page_config(
        page_title="LOG ANALYZER PRO",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

def inject_custom_css():
    """Injects the Cyber-Slate CSS styles directly into the page."""
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Inter:wght@200;300;400;500;600;700&display=swap');

    :root {
        --bg-dark: #1A1A1A;
        --card-bg: rgba(42, 42, 42, 0.8);
        --neon-blue: #B8FF00;
        --neon-purple: #A0E000;
        --neon-red: #FF6B6B;
        --text-main: #FFFFFF;
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

    /* Dataframe/Table Styling with Lime Green Borders */
    [data-testid="stDataFrame"] {
        border: 2px solid #B8FF00 !important;
        border-radius: 12px !important;
        overflow: hidden !important;
        box-shadow: 0 0 20px rgba(184, 255, 0, 0.2) !important;
    }

    [data-testid="stDataFrame"] table {
        border-collapse: collapse !important;
        width: 100% !important;
    }

    [data-testid="stDataFrame"] thead {
        background: linear-gradient(90deg, rgba(184, 255, 0, 0.25), rgba(160, 224, 0, 0.25)) !important;
        border-bottom: 3px solid #B8FF00 !important;
        border-top: 2px solid #B8FF00 !important;
    }

    [data-testid="stDataFrame"] th {
        color: #B8FF00 !important;
        font-weight: 800 !important;
        border-right: 2px solid #B8FF00 !important;
        padding: 14px 12px !important;
        text-align: left !important;
        letter-spacing: 1px !important;
        text-transform: uppercase !important;
        font-size: 0.75rem !important;
    }

    [data-testid="stDataFrame"] td {
        border-right: 1px solid rgba(184, 255, 0, 0.25) !important;
        border-bottom: 1px solid rgba(184, 255, 0, 0.2) !important;
        padding: 12px !important;
        color: #FFFFFF !important;
    }

    [data-testid="stDataFrame"] tr:hover {
        background-color: rgba(184, 255, 0, 0.12) !important;
    }

    [data-testid="stDataFrame"] tbody tr {
        border-left: 2px solid rgba(184, 255, 0, 0.2) !important;
    }

    /* Expander Styling */
    .streamlit-expanderHeader {
        background: linear-gradient(90deg, rgba(184, 255, 0, 0.1), rgba(160, 224, 0, 0.1)) !important;
        border: 1px solid rgba(184, 255, 0, 0.3) !important;
        border-radius: 8px !important;
        padding: 10px !important;
    }

    .streamlit-expanderHeader p {
        color: #B8FF00 !important;
        font-weight: 600 !important;
    }

    /* Tab Styling */
    button[data-baseweb="tab"] {
        color: #CCCCCC !important;
        border-bottom: 2px solid transparent !important;
    }

    button[data-baseweb="tab"]:hover {
        color: #B8FF00 !important;
        border-bottom-color: #B8FF00 !important;
    }

    button[aria-selected="true"][data-baseweb="tab"] {
        color: #B8FF00 !important;
        border-bottom: 3px solid #B8FF00 !important;
    }

    /* Checkbox Styling */
    [role="checkbox"] {
        border-color: rgba(184, 255, 0, 0.4) !important;
    }

    [role="checkbox"][aria-checked="true"] {
        background-color: #B8FF00 !important;
        border-color: #B8FF00 !important;
    }

    /* Input Fields */
    input, textarea {
        background-color: rgba(42, 42, 42, 0.6) !important;
        border: 1px solid rgba(184, 255, 0, 0.3) !important;
        color: #FFFFFF !important;
        border-radius: 8px !important;
    }

    input:focus, textarea:focus {
        border-color: #B8FF00 !important;
        box-shadow: 0 0 10px rgba(184, 255, 0, 0.2) !important;
    }

    input::placeholder {
        color: #888888 !important;
    }

    /* Select/Dropdown */
    [data-testid="stSelectbox"] > div {
        background-color: rgba(42, 42, 42, 0.6) !important;
        border: 1px solid rgba(184, 255, 0, 0.3) !important;
        border-radius: 8px !important;
    }

    /* Button Styling */
    .stButton > button {
        background: linear-gradient(135deg, #B8FF00, #A0E000) !important;
        color: #1A1A1A !important;
        border: none !important;
        font-weight: 700 !important;
        border-radius: 8px !important;
        padding: 10px 20px !important;
        transition: all 0.3s ease !important;
    }

    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 5px 15px rgba(184, 255, 0, 0.3) !important;
    }

    /* Scrollbar Styling */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }

    ::-webkit-scrollbar-track {
        background: rgba(42, 42, 42, 0.4);
    }

    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #B8FF00, #A0E000);
        border-radius: 5px;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #C0FF20, #B8FF00);
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
# COMPONENT RENDERERS
# ========================================

def render_header(title="LOG ANALYZER PRO", subtitle="NEXT-GEN SECURITY ANALYTICS"):
    """Renders the main page header."""
    st.markdown(f'<div class="mega-title">{title}</div>', unsafe_allow_html=True)
    st.markdown(f'<p style="text-align: center; color: #B8FF00; letter-spacing: 5px; font-size: 0.8rem; margin-bottom: 2rem;">{subtitle}</p>', unsafe_allow_html=True)

def render_sidebar_static():
    """Renders the static parts of the sidebar."""
    with st.sidebar:
        st.markdown('<h2 style="color: #fff; font-size: 1.2rem; letter-spacing: 2px;">S.O.C. CORE</h2>', unsafe_allow_html=True)
        st.markdown("""
        <div style="background: rgba(184, 255, 0, 0.1); border: 1px solid var(--neon-blue); padding: 10px; border-radius: 8px; margin-bottom: 20px;">
            <p style="color: var(--neon-blue); margin:0; font-size: 0.7rem; font-weight: 800;">🛰️ SATELLITE: STABLE</p>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('<p style="color: #B8FF00; font-size: 0.7rem; font-weight: 700;">NAVIGATION</p>', unsafe_allow_html=True)
        st.markdown("---")

def render_metric_card(label, value, subtext):
    """Renders a single metric card."""
    st.markdown(f"""
    <div class="modern-card">
        <p style="color: #B8FF00; font-size: 0.7rem; font-weight: 800; letter-spacing: 1px; margin:0;">{label}</p>
        <p style="color: #fff; font-size: 2rem; font-weight: 800; margin: 5px 0;">{value}</p>
        <p style="color: #B8FF00; font-size: 0.65rem; font-weight: 700; margin:0;">{subtext}</p>
    </div>
    """, unsafe_allow_html=True)

def render_intel_row(title, tag, desc, color):
    """Renders a single intelligence row item."""
    st.markdown(f"""
    <div class="intel-row">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="color: #fff; font-size: 0.8rem; font-weight: 700;">{title}</span>
            <span style="background: {color}22; color: {color}; padding: 2px 8px; border-radius: 4px; font-size: 0.6rem; font-weight: 800;">{tag}</span>
        </div>
        <p style="color: #B8FF00; font-size: 0.75rem; margin: 5px 0 0 0;">{desc}</p>
    </div>
    """, unsafe_allow_html=True)

def render_alert_item(level, message, time):
    """Renders a single alert item."""
    color = "#ef4444" if "CRITICAL" in level else ("#fbbf24" if "WARNING" in level else "#B8FF00")
    st.markdown(f"""
    <div style="border-left: 3px solid {color}; padding-left: 12px; margin-bottom: 15px; background: rgba(15,23,42,0.3); padding: 10px; border-radius: 0 8px 8px 0;">
        <div style="display: flex; justify-content: space-between;">
            <span style="color: {color}; font-size: 0.65rem; font-weight: 800;">{level}</span>
            <span style="color: #888888; font-size: 0.65rem;">{time}</span>
        </div>
        <p style="color: #e2e8f0; font-size: 0.75rem; margin: 4px 0 0 0;">{message}</p>
    </div>
    """, unsafe_allow_html=True)

def render_action_button(title, subtitle):
    """Renders an action button."""
    st.markdown(f"""
    <div class="action-btn">
        <p style="color: #fff; font-size: 0.85rem; font-weight: 700; margin:0;">{title}</p>
        <p style="color: #B8FF00; font-size: 0.6rem; margin:0;">{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)

def render_footer():
    """Renders the page footer."""
    st.markdown("""
    <div style="text-align: center; margin-top: 50px; padding: 20px; color: #666666; border-top: 1px solid rgba(255,255,255,0.02);">
        <p style="font-size: 0.65rem; letter-spacing: 2px; margin: 0;">LOG ANALYZER PRO | SECURE TERMINAL | DESIGN SYSTEM</p>
    </div>
    """, unsafe_allow_html=True)

# ========================================
# DEMONSTRATION LAYOUT
# ========================================

def run_design_demo():
    """Builds a dummy layout to demonstrate the design system."""
    setup_page_config()
    inject_custom_css()
    render_sidebar_static()

    render_header()

    # 1. PRIMARY METRICS ROW
    col1, col2, col3, col4 = st.columns(4)
    with col1: render_metric_card("SYSTEM EVENTS", "24,592", "+12%")
    with col2: render_metric_card("ACTIVE ENTITIES", "48", "VERIFIED")
    with col3: render_metric_card("BREACH ATTEMPTS", "12", "DETECTED")
    with col4: render_metric_card("ANOMALY INDEX", "87", "HIGH RISK")
    
    st.markdown("<br>", unsafe_allow_html=True)

    # 2. ANALYSIS CORE ROW
    col_left, col_right = st.columns([1, 1])
    
    with col_left:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #f8fafc; font-weight: 700; margin-bottom: 10px;">THREAT ASSESSMENT GAUGE (DEMO)</p>', unsafe_allow_html=True)
        # Placeholder Gauge
        fig = go.Figure(go.Indicator(
            mode = "gauge+number", value = 75,
            domain = {'x': [0, 1], 'y': [0, 1]},
            gauge = {
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#475569"},
                'bar': {'color': "#ef4444"},
                'bgcolor': "rgba(0,0,0,0)",
                'steps': [
                    {'range': [0, 40], 'color': 'rgba(184, 255, 0, 0.08)'},
                    {'range': [40, 75], 'color': 'rgba(251, 191, 36, 0.05)'},
                    {'range': [75, 100], 'color': 'rgba(239, 68, 68, 0.05)'}],
            }
        ))
        fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "#FFFFFF", 'family': "Inter"}, height=250, margin=dict(l=30,r=30,t=10,b=10))
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_right:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #f8fafc; font-weight: 700; margin-bottom: 15px;">SECURITY INTELLIGENCE</p>', unsafe_allow_html=True)
        render_intel_row("🌐 NETWORK SECURITY", "CLEAN", "No active exfiltration patterns.", "#B8FF00")
        render_intel_row("🔑 AUTHENTICATION", "ATTACK", "High volume of failed logins in segment B.", "#ef4444")
        st.markdown('</div>', unsafe_allow_html=True)

    # 3. ALERTS ROW
    st.markdown("<br>", unsafe_allow_html=True)
    col_flow, col_feed = st.columns([1.5, 1])
    
    with col_flow:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #f8fafc; font-weight: 700; margin-bottom: 10px;">TEMPORAL EVENT FLOW (DEMO)</p>', unsafe_allow_html=True)
        # Placeholder Chart
        df = pd.DataFrame({'x': range(24), 'y': [x**2 for x in range(24)]})
        fig_flow = px.area(df, x='x', y='y', color_discrete_sequence=['#B8FF00'])
        fig_flow.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#B8FF00', 
                               xaxis=dict(showgrid=False), yaxis=dict(showgrid=False),
                               height=280, margin=dict(l=0,r=0,t=10,b=0))
        st.plotly_chart(fig_flow, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col_feed:
        st.markdown('<div class="modern-card">', unsafe_allow_html=True)
        st.markdown('<p style="color: #f8fafc; font-weight: 700; margin-bottom: 15px;">SEC-ALERTS FEED</p>', unsafe_allow_html=True)
        render_alert_item("🔴 CRITICAL", "Repeated Privilege Escalation", "00:42:15")
        render_alert_item("🟠 WARNING", "Anomalous Network Traffic", "00:30:10")
        st.markdown('</div>', unsafe_allow_html=True)

    # 4. QUICK ACTIONS
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<p style="color: #B8FF00; font-size: 0.7rem; font-weight: 800; letter-spacing: 2px;">QUICK COMMANDS</p>', unsafe_allow_html=True)
    q_col1, q_col2, q_col3, q_col4 = st.columns(4)
    with q_col1: render_action_button("🛡️ SCAN SYSTEM", "Full security audit")
    with q_col2: render_action_button("📂 EXPORT DATA", "JSON/CSV package")
    with q_col3: render_action_button("🔥 KILL SESSIONS", "Terminate anomalies")
    with q_col4: render_action_button("⚙️ CONFIG", "Neural engine specs")

    render_footer()

@st.cache_data(show_spinner=False)
def get_video_html(video_path):
    """Reads and encodes video file, returning the HTML string."""
    try:
        if not video_path.exists():
            return None
        with open(video_path, "rb") as f:
            video_bytes = f.read()
            video_b64 = base64.b64encode(video_bytes).decode()
            return video_b64
    except:
        return None


if __name__ == "__main__":
    run_design_demo()
