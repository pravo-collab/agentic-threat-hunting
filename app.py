"""Streamlit UI for Agentic Threat Hunting and Incident Response System."""

import streamlit as st
import json
import uuid
from datetime import datetime
from pathlib import Path
import plotly.graph_objects as go
import plotly.express as px
from streamlit_option_menu import option_menu

from src.models.schemas import SecurityEvent, AgentState
from src.graph.workflow import ThreatHuntingWorkflow
from src.config.settings import settings

# Page configuration
st.set_page_config(
    page_title="Threat Hunting & IR System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .severity-critical {
        color: #d62728;
        font-weight: bold;
    }
    .severity-high {
        color: #ff7f0e;
        font-weight: bold;
    }
    .severity-medium {
        color: #ffbb00;
        font-weight: bold;
    }
    .severity-low {
        color: #2ca02c;
        font-weight: bold;
    }
    .stAlert {
        margin-top: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'workflow_result' not in st.session_state:
    st.session_state.workflow_result = None
if 'workflow_running' not in st.session_state:
    st.session_state.workflow_running = False


def create_severity_chart(severity):
    """Create a gauge chart for threat severity."""
    severity_map = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 3,
        "info": 1
    }
    
    value = severity_map.get(severity.lower(), 0)
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Severity"},
        gauge={
            'axis': {'range': [None, 10]},
            'bar': {'color': "darkred" if value >= 8 else "orange" if value >= 5 else "yellow"},
            'steps': [
                {'range': [0, 3], 'color': "lightgreen"},
                {'range': [3, 5], 'color': "lightyellow"},
                {'range': [5, 8], 'color': "lightsalmon"},
                {'range': [8, 10], 'color': "lightcoral"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': value
            }
        }
    ))
    
    fig.update_layout(height=300)
    return fig


def create_workflow_timeline(final_state):
    """Create a timeline visualization of the workflow stages."""
    stages = []
    colors = []
    
    if final_state.detection:
        stages.append("Detection")
        colors.append("#2ca02c")
    
    if final_state.analysis:
        stages.append("Analysis")
        colors.append("#ff7f0e")
    
    if final_state.investigation:
        stages.append("Investigation")
        colors.append("#9467bd")
    
    if final_state.response:
        stages.append("Response")
        colors.append("#8c564b")
    
    if final_state.report:
        stages.append("Reporting")
        colors.append("#1f77b4")
    
    fig = go.Figure(data=[go.Bar(
        x=stages,
        y=[1] * len(stages),
        marker_color=colors,
        text=stages,
        textposition='auto',
    )])
    
    fig.update_layout(
        title="Workflow Execution Timeline",
        xaxis_title="Stage",
        yaxis_visible=False,
        height=300,
        showlegend=False
    )
    
    return fig


def load_sample_events():
    """Load sample security events."""
    samples = {}
    data_dir = Path("data")
    
    for file in data_dir.glob("*.json"):
        with open(file, 'r') as f:
            samples[file.stem] = json.load(f)
    
    return samples


def main():
    """Main Streamlit application."""
    
    # Header
    st.markdown('<div class="main-header">🛡️ Agentic Threat Hunting & Incident Response</div>', 
                unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=100)
        
        selected = option_menu(
            menu_title="Navigation",
            options=["Dashboard", "Analyze Event", "History", "Settings"],
            icons=["speedometer2", "search", "clock-history", "gear"],
            menu_icon="cast",
            default_index=0,
        )
        
        st.markdown("---")
        st.markdown("### System Status")
        
        # Check API key
        if settings.OPENAI_API_KEY:
            st.success("✅ API Key Configured")
        else:
            st.error("❌ API Key Missing")
        
        st.info(f"Model: {settings.DEFAULT_MODEL}")
        st.info(f"Temperature: {settings.TEMPERATURE}")
    
    # Main content based on selection
    if selected == "Dashboard":
        show_dashboard()
    elif selected == "Analyze Event":
        show_analyze_event()
    elif selected == "History":
        show_history()
    elif selected == "Settings":
        show_settings()


def show_dashboard():
    """Show the main dashboard."""
    st.header("📊 Dashboard")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Events Analyzed", "0", "0")
    
    with col2:
        st.metric("Threats Detected", "0", "0")
    
    with col3:
        st.metric("Active Investigations", "0", "0")
    
    with col4:
        st.metric("Incidents Resolved", "0", "0")
    
    st.markdown("---")
    
    # Quick Start
    st.subheader("🚀 Quick Start")
    st.write("Get started by analyzing a security event:")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📁 Upload Custom Event", use_container_width=True):
            st.session_state.page = "Analyze Event"
            st.rerun()
    
    with col2:
        if st.button("📋 Use Sample Event", use_container_width=True):
            st.session_state.page = "Analyze Event"
            st.rerun()
    
    # Recent Activity (placeholder)
    st.markdown("---")
    st.subheader("📈 Recent Activity")
    st.info("No recent activity. Start by analyzing a security event!")


def show_analyze_event():
    """Show the event analysis page."""
    st.header("🔍 Analyze Security Event")
    
    # Event input method
    input_method = st.radio(
        "Choose input method:",
        ["Sample Events", "Upload JSON", "Manual Entry"],
        horizontal=True
    )
    
    security_event = None
    
    if input_method == "Sample Events":
        samples = load_sample_events()
        
        if samples:
            selected_sample = st.selectbox(
                "Select a sample event:",
                options=list(samples.keys()),
                format_func=lambda x: x.replace("_", " ").title()
            )
            
            if selected_sample:
                st.json(samples[selected_sample])
                
                if st.button("🔍 Analyze This Event", type="primary", use_container_width=True):
                    security_event = SecurityEvent(**samples[selected_sample])
        else:
            st.warning("No sample events found in the data directory.")
    
    elif input_method == "Upload JSON":
        uploaded_file = st.file_uploader("Upload security event JSON file", type=['json'])
        
        if uploaded_file:
            event_data = json.load(uploaded_file)
            st.json(event_data)
            
            if st.button("🔍 Analyze This Event", type="primary", use_container_width=True):
                security_event = SecurityEvent(**event_data)
    
    elif input_method == "Manual Entry":
        with st.form("manual_event_form"):
            st.subheader("Enter Event Details")
            
            col1, col2 = st.columns(2)
            
            with col1:
                event_id = st.text_input("Event ID", value=str(uuid.uuid4()))
                source = st.text_input("Source", value="manual_entry")
                event_type = st.text_input("Event Type", value="suspicious_activity")
                source_ip = st.text_input("Source IP", value="192.168.1.100")
            
            with col2:
                destination_ip = st.text_input("Destination IP", value="10.0.0.1")
                user = st.text_input("User", value="unknown")
                process = st.text_input("Process", value="unknown.exe")
            
            raw_data = st.text_area("Raw Data (JSON)", value='{"description": "Manual event entry"}')
            
            submitted = st.form_submit_button("🔍 Analyze Event", type="primary", use_container_width=True)
            
            if submitted:
                try:
                    security_event = SecurityEvent(
                        event_id=event_id,
                        timestamp=datetime.now(),
                        source=source,
                        event_type=event_type,
                        raw_data=json.loads(raw_data),
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        user=user,
                        process=process
                    )
                except Exception as e:
                    st.error(f"Error creating event: {str(e)}")
    
    # Run analysis
    if security_event:
        run_analysis(security_event)


def create_agent_status_display():
    """Create a visual display for agent execution status."""
    agents = [
        {"name": "Detection Agent", "icon": "🎯", "status": "pending"},
        {"name": "Analysis Agent", "icon": "🔬", "status": "pending"},
        {"name": "Investigation Agent", "icon": "🔎", "status": "pending"},
        {"name": "Response Agent", "icon": "🚨", "status": "pending"},
        {"name": "Reporting Agent", "icon": "📊", "status": "pending"}
    ]
    
    cols = st.columns(5)
    agent_containers = []
    
    for i, (col, agent) in enumerate(zip(cols, agents)):
        with col:
            container = st.empty()
            agent_containers.append(container)
            container.markdown(f"""
            <div style='text-align: center; padding: 10px; border-radius: 10px; background-color: #f0f2f6;'>
                <div style='font-size: 2rem;'>{agent['icon']}</div>
                <div style='font-size: 0.8rem; font-weight: bold;'>{agent['name']}</div>
                <div style='font-size: 0.7rem; color: #666;'>⏳ Pending</div>
            </div>
            """, unsafe_allow_html=True)
    
    return agent_containers


def update_agent_status(containers, agent_index, status, message=""):
    """Update the status of a specific agent."""
    agents = [
        {"name": "Detection Agent", "icon": "🎯"},
        {"name": "Analysis Agent", "icon": "🔬"},
        {"name": "Investigation Agent", "icon": "🔎"},
        {"name": "Response Agent", "icon": "🚨"},
        {"name": "Reporting Agent", "icon": "📊"}
    ]
    
    if agent_index >= len(agents):
        return
    
    agent = agents[agent_index]
    
    status_colors = {
        "pending": "#f0f2f6",
        "running": "#fff3cd",
        "completed": "#d4edda",
        "error": "#f8d7da"
    }
    
    status_icons = {
        "pending": "⏳",
        "running": "⚙️",
        "completed": "✅",
        "error": "❌"
    }
    
    status_text = {
        "pending": "Pending",
        "running": "Running...",
        "completed": "Completed",
        "error": "Error"
    }
    
    containers[agent_index].markdown(f"""
    <div style='text-align: center; padding: 10px; border-radius: 10px; background-color: {status_colors[status]}; border: 2px solid {"#ffc107" if status == "running" else "transparent"};'>
        <div style='font-size: 2rem;'>{agent['icon']}</div>
        <div style='font-size: 0.8rem; font-weight: bold;'>{agent['name']}</div>
        <div style='font-size: 0.7rem; color: #666;'>{status_icons[status]} {status_text[status]}</div>
        {f"<div style='font-size: 0.6rem; color: #888; margin-top: 5px;'>{message}</div>" if message else ""}
    </div>
    """, unsafe_allow_html=True)


def run_analysis(security_event):
    """Run the threat hunting workflow with real-time agent tracking."""
    st.markdown("---")
    st.subheader("🔄 Analysis in Progress")
    
    # Create agent status display
    st.markdown("### Agent Execution Pipeline")
    agent_containers = create_agent_status_display()
    
    st.markdown("---")
    
    # Create initial state
    initial_state = AgentState(
        security_event=security_event,
        current_stage="detection"
    )
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    log_container = st.expander("📋 Execution Log", expanded=True)
    
    try:
        # Initialize workflow
        with log_container:
            st.write("🔧 **Initializing workflow...**")
        status_text.text("Initializing workflow...")
        progress_bar.progress(5)
        
        import time
        time.sleep(0.5)
        
        workflow = ThreatHuntingWorkflow()
        
        with log_container:
            st.success("✅ Workflow initialized successfully")
        
        progress_bar.progress(10)
        
        # Agent 1: Detection
        update_agent_status(agent_containers, 0, "running")
        with log_container:
            st.write("🎯 **Running Detection Agent...**")
        status_text.text("🎯 Detection Agent: Analyzing security event...")
        progress_bar.progress(20)
        
        # Run workflow (we'll intercept the state changes)
        import threading
        result_container = {"state": None, "error": None}
        
        def run_workflow_thread():
            try:
                result_container["state"] = workflow.run(initial_state)
            except Exception as e:
                result_container["error"] = e
        
        thread = threading.Thread(target=run_workflow_thread)
        thread.start()
        
        # Simulate agent progression while workflow runs
        agent_stages = [
            (0, "detection", "Detection Agent", 20, 35),
            (1, "analysis", "Analysis Agent", 35, 55),
            (2, "investigation", "Investigation Agent", 55, 70),
            (3, "response", "Response Agent", 70, 85),
            (4, "reporting", "Reporting Agent", 85, 95)
        ]
        
        current_agent = 0
        last_stage = "detection"
        
        while thread.is_alive():
            time.sleep(0.5)
            
            # Check if we need to update agent status
            if result_container["state"]:
                current_stage = result_container["state"].current_stage
                
                if current_stage != last_stage:
                    # Mark previous agent as completed
                    if current_agent > 0:
                        update_agent_status(agent_containers, current_agent - 1, "completed")
                        with log_container:
                            st.success(f"✅ {agent_stages[current_agent - 1][2]} completed")
                    
                    # Update to next agent
                    for i, (idx, stage, name, start_prog, end_prog) in enumerate(agent_stages):
                        if stage == current_stage and i < len(agent_stages):
                            current_agent = i + 1
                            if i < len(agent_containers):
                                update_agent_status(agent_containers, i, "running")
                                with log_container:
                                    st.write(f"{agent_stages[i][2].split()[0]} **Running {name}...**")
                                status_text.text(f"{agent_stages[i][2].split()[0]} {name}: Processing...")
                                progress_bar.progress(start_prog)
                            break
                    
                    last_stage = current_stage
        
        thread.join()
        
        # Check for errors
        if result_container["error"]:
            raise result_container["error"]
        
        final_state = result_container["state"]
        
        # Mark all completed agents
        for i in range(5):
            if i == 0 or (i == 1 and final_state.detection) or \
               (i == 2 and final_state.analysis) or \
               (i == 3 and final_state.investigation) or \
               (i == 4 and final_state.response):
                update_agent_status(agent_containers, i, "completed")
        
        progress_bar.progress(100)
        status_text.text("✅ Analysis complete!")
        
        with log_container:
            st.success("🎉 **All agents completed successfully!**")
        
        time.sleep(1)
        
        # Store result in session state
        st.session_state.workflow_result = final_state
        
        # Display results
        display_results(final_state)
        
    except Exception as e:
        # Mark current agent as error
        if 'current_agent' in locals() and current_agent < len(agent_containers):
            update_agent_status(agent_containers, current_agent, "error", str(e)[:30])
        
        with log_container:
            st.error(f"❌ **Error:** {str(e)}")
        
        st.error(f"Error during analysis: {str(e)}")
        st.exception(e)


def display_results(final_state):
    """Display the analysis results."""
    st.markdown("---")
    st.header("📋 Analysis Results")
    
    # Check for errors
    if final_state.error:
        st.error(f"❌ Error: {final_state.error}")
        return
    
    # Workflow messages
    if final_state.messages:
        with st.expander("📝 Workflow Messages", expanded=True):
            for msg in final_state.messages:
                st.info(msg)
    
    # Detection Results
    if final_state.detection:
        st.markdown("### 🎯 Detection Results")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Detection ID", final_state.detection.detection_id[:8] + "...")
        
        with col2:
            confidence = final_state.detection.confidence_score
            st.metric("Confidence Score", f"{confidence:.2%}")
        
        with col3:
            st.metric("Detection Method", final_state.detection.detection_method)
        
        if final_state.detection.threat_indicators:
            st.write("**Threat Indicators:**")
            for indicator in final_state.detection.threat_indicators:
                st.markdown(f"- {indicator}")
    
    # Analysis Results
    if final_state.analysis:
        st.markdown("---")
        st.markdown("### 🔬 Threat Analysis")
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            # Severity gauge
            fig = create_severity_chart(final_state.analysis.severity.value)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown(f"**Severity:** <span class='severity-{final_state.analysis.severity.value}'>{final_state.analysis.severity.value.upper()}</span>", 
                       unsafe_allow_html=True)
            st.write(f"**Category:** {final_state.analysis.category.value}")
            st.write(f"**Attack Vector:** {final_state.analysis.attack_vector or 'N/A'}")
            
            if final_state.analysis.affected_assets:
                st.write("**Affected Assets:**")
                for asset in final_state.analysis.affected_assets:
                    st.markdown(f"- {asset}")
            
            if final_state.analysis.iocs:
                st.write("**Indicators of Compromise (IOCs):**")
                for ioc in final_state.analysis.iocs:
                    st.code(ioc)
        
        with st.expander("📄 Analysis Summary", expanded=True):
            st.write(final_state.analysis.analysis_summary)
    
    # Investigation Results
    if final_state.investigation:
        st.markdown("---")
        st.markdown("### 🔎 Investigation Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Root Cause:**")
            st.info(final_state.investigation.root_cause or "N/A")
        
        with col2:
            st.write("**Evidence Collected:**")
            if final_state.investigation.evidence_collected:
                for evidence in final_state.investigation.evidence_collected:
                    st.markdown(f"- {evidence}")
            else:
                st.write("No evidence items listed")
        
        if final_state.investigation.attack_chain:
            st.write("**Attack Chain:**")
            for i, step in enumerate(final_state.investigation.attack_chain, 1):
                st.markdown(f"{i}. {step}")
    
    # Response Plan
    if final_state.response:
        st.markdown("---")
        st.markdown("### 🚨 Incident Response Plan")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Planned Actions:**")
            for action in final_state.response.actions_taken:
                st.markdown(f"- {action.value}")
        
        with col2:
            st.write("**Containment Status:**")
            st.success(final_state.response.containment_status)
        
        if final_state.response.remediation_steps:
            st.write("**Remediation Steps:**")
            for i, step in enumerate(final_state.response.remediation_steps, 1):
                st.markdown(f"{i}. {step}")
        
        if settings.REQUIRE_HUMAN_APPROVAL:
            st.warning("⚠️ Human approval required before executing response actions")
    
    # Final Report
    if final_state.report:
        st.markdown("---")
        st.markdown("### 📊 Incident Report")
        
        with st.expander("📝 Executive Summary", expanded=True):
            st.write(final_state.report.executive_summary)
        
        with st.expander("🔧 Technical Details"):
            st.write(final_state.report.technical_details)
        
        if final_state.report.recommendations:
            with st.expander("💡 Recommendations"):
                for i, rec in enumerate(final_state.report.recommendations, 1):
                    st.markdown(f"{i}. {rec}")
        
        # Download button
        report_json = json.dumps(final_state.report.model_dump(), indent=2, default=str)
        st.download_button(
            label="📥 Download Full Report (JSON)",
            data=report_json,
            file_name=f"incident_report_{final_state.report.report_id}.json",
            mime="application/json",
            use_container_width=True
        )
    
    # Workflow Timeline
    st.markdown("---")
    fig = create_workflow_timeline(final_state)
    st.plotly_chart(fig, use_container_width=True)


def show_history():
    """Show analysis history."""
    st.header("🕐 Analysis History")
    st.info("History feature coming soon! This will show all previous threat analyses.")


def show_settings():
    """Show settings page."""
    st.header("⚙️ Settings")
    
    st.subheader("API Configuration")
    
    api_key_status = "Configured ✅" if settings.OPENAI_API_KEY else "Not Configured ❌"
    st.write(f"**OpenAI API Key:** {api_key_status}")
    
    st.info("To configure your API key, edit the `.env` file in the project root.")
    
    st.markdown("---")
    st.subheader("Model Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Model:** {settings.DEFAULT_MODEL}")
        st.write(f"**Temperature:** {settings.TEMPERATURE}")
    
    with col2:
        st.write(f"**Max Iterations:** {settings.MAX_ITERATIONS}")
        st.write(f"**Auto Response:** {'Enabled' if settings.AUTO_RESPONSE_ENABLED else 'Disabled'}")
    
    st.markdown("---")
    st.subheader("Alert Thresholds")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("High", settings.ALERT_THRESHOLD_HIGH)
    
    with col2:
        st.metric("Medium", settings.ALERT_THRESHOLD_MEDIUM)
    
    with col3:
        st.metric("Low", settings.ALERT_THRESHOLD_LOW)


if __name__ == "__main__":
    main()
