import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from pathlib import Path
from datetime import datetime, timedelta
import numpy as np

# Page Configuration
from frontend_design import inject_custom_css, render_header, render_footer, render_metric_card

# Page Configuration
st.set_page_config(
    page_title="VISUAL INTELLIGENCE",
    page_icon="📈",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Cyber-Slate CSS
inject_custom_css()

render_header("VISUAL INTELLIGENCE", "ADVANCED RECONNAISSANCE & ANALYTICS")


# Load Data
BASE_DIR = Path(__file__).resolve().parent.parent.parent
WINDOWS_LOGS_PATH = BASE_DIR / "Output" / "windows_logs_parsed.csv"
ML_ANOMALIES_PATH = BASE_DIR / "Output" / "ml_anomalies.csv"

# Load Windows Logs
df_logs = None
if WINDOWS_LOGS_PATH.exists():
    try:
        df_logs = pd.read_csv(WINDOWS_LOGS_PATH)
        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'], errors='coerce')
    except Exception:
        pass

# Load ML Anomalies
df_ml = None
if ML_ANOMALIES_PATH.exists():
    try:
        df_ml = pd.read_csv(ML_ANOMALIES_PATH)
    except Exception:
        pass

# Generate sample data if needed
if df_logs is None or len(df_logs) == 0:
    np.random.seed(42)
    dates = pd.date_range(start=datetime.now() - timedelta(days=7), periods=500, freq='30min')
    df_logs = pd.DataFrame({
        'timestamp': dates,
        'event_id': np.random.choice([4624, 4625, 4634, 4672, 4720], 500, p=[0.4, 0.15, 0.25, 0.1, 0.1]),
        'username': [f"user_{np.random.randint(1,30)}" for _ in range(500)],
        'ip': [f"192.168.{np.random.randint(1,10)}.{np.random.randint(1,255)}" for _ in range(500)]
    })

# Add time-based columns
df_logs['hour'] = df_logs['timestamp'].dt.hour
df_logs['day'] = df_logs['timestamp'].dt.day_name()
df_logs['date'] = df_logs['timestamp'].dt.date

# Visualization Options
st.markdown('<div class="section-header">🎛️ Visualization Controls</div>', unsafe_allow_html=True)

viz_type = st.selectbox(
    "Select Visualization Type",
    ["📈 Time Series Analysis", "👥 User Activity", "🔍 Event Analysis", "🌐 Network View", "📊 Correlation Matrix"]
)

st.markdown("---")

# ==========================================
# TIME SERIES ANALYSIS
# ==========================================
if viz_type == "📈 Time Series Analysis":
    st.markdown('<div class="section-header">📈 Time Series Analysis</div>', unsafe_allow_html=True)
    
    # Events over time
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Events Over Time</h4></div>', unsafe_allow_html=True)
        
        daily_counts = df_logs.groupby('date').size().reset_index(name='count')
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=daily_counts['date'],
            y=daily_counts['count'],
            mode='lines+markers',
            line=dict(color='#3b82f6', width=3),
            fill='tonexty',
            fillcolor='rgba(59, 130, 246, 0.1)'
        ))
        fig.update_layout(
            template='plotly_dark',
            height=350,
            margin=dict(l=20, r=20, t=20, b=40),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Date"),
            yaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Events")
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Hourly Distribution</h4></div>', unsafe_allow_html=True)
        
        hourly_counts = df_logs.groupby('hour').size().reset_index(name='count')
        
        fig = px.bar(hourly_counts, x='hour', y='count',
                    color_discrete_sequence=['#8b5cf6'])
        fig.update_layout(
            template='plotly_dark',
            height=350,
            margin=dict(l=20, r=20, t=20, b=40),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Hour of Day"),
            yaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Events")
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Weekly Heatmap
    st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Weekly Activity Heatmap</h4></div>', unsafe_allow_html=True)
    
    # Create heatmap data
    heatmap_data = df_logs.groupby(['day', 'hour']).size().reset_index(name='count')
    heatmap_pivot = heatmap_data.pivot(index='day', columns='hour', values='count').fillna(0)
    
    # Ensure all 24 hours are present as columns
    all_hours = list(range(24))
    heatmap_pivot = heatmap_pivot.reindex(columns=all_hours, fill_value=0)
    
    # Reorder days
    day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    heatmap_pivot = heatmap_pivot.reindex([d for d in day_order if d in heatmap_pivot.index])
    
    fig = px.imshow(heatmap_pivot.values,
                   labels=dict(x="Hour", y="Day", color="Events"),
                   x=all_hours,
                   y=heatmap_pivot.index.tolist(),
                   color_continuous_scale='Blues')
    fig.update_layout(
        template='plotly_dark',
        height=300,
        margin=dict(l=100, r=20, t=20, b=40),
        paper_bgcolor='rgba(0,0,0,0)'
    )
    st.plotly_chart(fig, use_container_width=True)

# ==========================================
# USER ACTIVITY
# ==========================================
elif viz_type == "👥 User Activity":
    st.markdown('<div class="section-header">👥 User Activity Analysis</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Top Active Users</h4></div>', unsafe_allow_html=True)
        
        user_counts = df_logs['username'].value_counts().head(15)
        
        fig = px.bar(x=user_counts.values, y=user_counts.index, orientation='h',
                    color=user_counts.values,
                    color_continuous_scale='Blues')
        fig.update_layout(
            template='plotly_dark',
            height=400,
            margin=dict(l=100, r=20, t=20, b=40),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Events"),
            yaxis=dict(gridcolor='rgba(148,163,184,0.1)', title=""),
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">User Distribution</h4></div>', unsafe_allow_html=True)
        
        top_users = df_logs['username'].value_counts().head(8)
        
        fig = px.pie(values=top_users.values, names=top_users.index,
                    color_discrete_sequence=px.colors.sequential.Blues_r)
        fig.update_layout(
            template='plotly_dark',
            height=400,
            margin=dict(l=20, r=20, t=20, b=20),
            paper_bgcolor='rgba(0,0,0,0)'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # User Activity Timeline
    st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">User Activity Over Time</h4></div>', unsafe_allow_html=True)
    
    # Select top 5 users for timeline
    top_5_users = df_logs['username'].value_counts().head(5).index.tolist()
    user_timeline = df_logs[df_logs['username'].isin(top_5_users)].groupby(['date', 'username']).size().reset_index(name='count')
    
    fig = px.line(user_timeline, x='date', y='count', color='username',
                 color_discrete_sequence=['#3b82f6', '#8b5cf6', '#ef4444', '#4ade80', '#fbbf24'])
    fig.update_layout(
        template='plotly_dark',
        height=300,
        margin=dict(l=20, r=20, t=20, b=40),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(gridcolor='rgba(148,163,184,0.1)'),
        yaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Events")
    )
    st.plotly_chart(fig, use_container_width=True)

# ==========================================
# EVENT ANALYSIS
# ==========================================
elif viz_type == "🔍 Event Analysis":
    st.markdown('<div class="section-header">🔍 Event Type Analysis</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Event Type Distribution</h4></div>', unsafe_allow_html=True)
        
        event_counts = df_logs['event_id'].value_counts()
        event_labels = {4624: 'Login', 4625: 'Failed Login', 4634: 'Logout', 4672: 'Privilege', 4720: 'Account Created'}
        
        fig = px.pie(values=event_counts.values, 
                    names=[event_labels.get(e, f'Event {e}') for e in event_counts.index],
                    color_discrete_sequence=['#3b82f6', '#ef4444', '#4ade80', '#fbbf24', '#8b5cf6'])
        fig.update_layout(
            template='plotly_dark',
            height=350,
            margin=dict(l=20, r=20, t=20, b=20),
            paper_bgcolor='rgba(0,0,0,0)'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Events by Type</h4></div>', unsafe_allow_html=True)
        
        fig = px.bar(x=[event_labels.get(e, f'Event {e}') for e in event_counts.index],
                    y=event_counts.values,
                    color_discrete_sequence=['#3b82f6'])
        fig.update_layout(
            template='plotly_dark',
            height=350,
            margin=dict(l=20, r=20, t=20, b=80),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="", tickangle=45),
            yaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Count")
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Event Timeline by Type
    st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Event Types Over Time</h4></div>', unsafe_allow_html=True)
    
    df_logs['event_name'] = df_logs['event_id'].map(event_labels).fillna(df_logs['event_id'].astype(str))
    event_timeline = df_logs.groupby(['date', 'event_name']).size().reset_index(name='count')
    
    fig = px.area(event_timeline, x='date', y='count', color='event_name',
                 color_discrete_sequence=['#3b82f6', '#ef4444', '#4ade80', '#fbbf24', '#8b5cf6'])
    fig.update_layout(
        template='plotly_dark',
        height=350,
        margin=dict(l=20, r=20, t=20, b=40),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(gridcolor='rgba(148,163,184,0.1)'),
        yaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Events")
    )
    st.plotly_chart(fig, use_container_width=True)

# ==========================================
# NETWORK VIEW
# ==========================================
elif viz_type == "🌐 Network View":
    st.markdown('<div class="section-header">🌐 Network Activity</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Top Source IPs</h4></div>', unsafe_allow_html=True)
        
        if 'ip' in df_logs.columns:
            ip_counts = df_logs['ip'].value_counts().head(10)
            
            fig = px.bar(x=ip_counts.values, y=ip_counts.index, orientation='h',
                        color=ip_counts.values,
                        color_continuous_scale='Reds')
            fig.update_layout(
                template='plotly_dark',
                height=350,
                margin=dict(l=120, r=20, t=20, b=40),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Events"),
                yaxis=dict(gridcolor='rgba(148,163,184,0.1)', title=""),
                coloraxis_showscale=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No IP data available")
    
    with col2:
        st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">IP Distribution</h4></div>', unsafe_allow_html=True)
        
        if 'ip' in df_logs.columns:
            top_ips = df_logs['ip'].value_counts().head(8)
            
            fig = px.pie(values=top_ips.values, names=top_ips.index,
                        color_discrete_sequence=px.colors.sequential.Reds_r)
            fig.update_layout(
                template='plotly_dark',
                height=350,
                margin=dict(l=20, r=20, t=20, b=20),
                paper_bgcolor='rgba(0,0,0,0)'
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No IP data available")
    
    # Network Activity Timeline
    st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Network Activity Over Time</h4></div>', unsafe_allow_html=True)
    
    if 'ip' in df_logs.columns:
        top_ips = df_logs['ip'].value_counts().head(5).index.tolist()
        ip_timeline = df_logs[df_logs['ip'].isin(top_ips)].groupby(['date', 'ip']).size().reset_index(name='count')
        
        fig = px.line(ip_timeline, x='date', y='count', color='ip',
                     color_discrete_sequence=['#ef4444', '#fbbf24', '#4ade80', '#3b82f6', '#8b5cf6'])
        fig.update_layout(
            template='plotly_dark',
            height=300,
            margin=dict(l=20, r=20, t=20, b=40),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(gridcolor='rgba(148,163,184,0.1)'),
            yaxis=dict(gridcolor='rgba(148,163,184,0.1)', title="Events")
        )
        st.plotly_chart(fig, use_container_width=True)

# ==========================================
# CORRELATION MATRIX
# ==========================================
elif viz_type == "📊 Correlation Matrix":
    st.markdown('<div class="section-header">📊 Data Correlation Analysis</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="chart-container"><h4 style="color: #f1f5f9;">Feature Correlation Heatmap</h4></div>', unsafe_allow_html=True)
    
    # Create numeric features for correlation
    df_numeric = pd.DataFrame({
        'hour': df_logs['hour'],
        'event_4624': (df_logs['event_id'] == 4624).astype(int),
        'event_4625': (df_logs['event_id'] == 4625).astype(int),
        'event_4672': (df_logs['event_id'] == 4672).astype(int),
        'user_activity': df_logs.groupby('username')['username'].transform('count')
    })
    
    corr_matrix = df_numeric.corr()
    
    fig = px.imshow(corr_matrix,
                   labels=dict(color="Correlation"),
                   x=corr_matrix.columns,
                   y=corr_matrix.columns,
                   color_continuous_scale='RdBu_r',
                   zmin=-1, zmax=1)
    fig.update_layout(
        template='plotly_dark',
        height=400,
        margin=dict(l=100, r=20, t=20, b=100),
        paper_bgcolor='rgba(0,0,0,0)'
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Summary Statistics
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown('<div class="modern-card"><p style="color: var(--neon-blue); font-weight: 700; margin-bottom:15px;">SUMMARY STATISTICS</p>', unsafe_allow_html=True)
        
        summary_df = pd.DataFrame({
            'Metric': ['Total Events', 'Unique Users', 'Unique IPs', 'Date Range'],
            'Value': [
                f"{len(df_logs):,}",
                df_logs['username'].nunique(),
                df_logs['ip'].nunique() if 'ip' in df_logs.columns else 'N/A',
                f"{df_logs['date'].min()} to {df_logs['date'].max()}"
            ]
        })
        st.dataframe(summary_df, use_container_width=True, hide_index=True)
    
    with col2:
        st.markdown('<div class="modern-card"><p style="color: var(--neon-blue); font-weight: 700; margin-bottom:15px;">EVENT DISTRIBUTION</p>', unsafe_allow_html=True)
        
        event_stats = df_logs['event_id'].value_counts().reset_index()
        event_stats.columns = ['Event ID', 'Count']
        st.dataframe(event_stats, use_container_width=True, hide_index=True)
        st.markdown('</div>', unsafe_allow_html=True)

st.markdown("---")

# Export Options
col1, col2, col3 = st.columns(3)

with col1:
    csv_data = df_logs.to_csv(index=False).encode('utf-8')
    st.download_button("📥 Export Data", csv_data, f"visualization_data_{datetime.now().strftime('%Y%m%d')}.csv", "text/csv", use_container_width=True)

with col2:
    if st.button("🔄 Refresh", use_container_width=True):
        st.rerun()

with col3:
    if st.button("📊 Generate Report", use_container_width=True):
        st.success("Report generated successfully!")

# Footer
render_footer()
