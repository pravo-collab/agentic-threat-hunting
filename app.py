"""Streamlit UI for Agentic Threat Hunting and Incident Response System."""

import streamlit as st
from streamlit_option_menu import option_menu
import json
import os
from pathlib import Path
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any, List

from src.config.settings import settings
from src.models.schemas import SecurityEvent, Severity

# Hugging Face Space detection
IS_HUGGINGFACE = os.getenv("SPACE_ID") is not None

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
            menu_title=None,
            options=["Dashboard", "AI Packet Analyzer", "Analyze Event", "Network Monitor", "ML Traffic Classifier", "History", "Settings"],
            icons=["speedometer2", "cpu", "shield-check", "diagram-3", "robot", "clock-history", "gear"],
            menu_icon="cast",
            default_index=0,
            orientation="vertical"
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
    elif selected == "AI Packet Analyzer":
        show_ai_packet_analyzer()
    elif selected == "Analyze Event":
        show_analyze_event()
    elif selected == "Network Monitor":
        show_network_monitor()
    elif selected == "ML Traffic Classifier":
        show_ml_classifier()
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
    should_analyze = False
    
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
                    try:
                        # Parse timestamp if it's a string
                        event_data = samples[selected_sample].copy()
                        if isinstance(event_data.get('timestamp'), str):
                            from dateutil import parser
                            event_data['timestamp'] = parser.parse(event_data['timestamp'])
                        security_event = SecurityEvent(**event_data)
                        should_analyze = True
                    except Exception as e:
                        st.error(f"Error parsing event: {str(e)}")
                        security_event = None
                        should_analyze = False
        else:
            st.warning("No sample events found in the data directory.")
    
    elif input_method == "Upload JSON":
        uploaded_file = st.file_uploader("Upload security event JSON file", type=['json'])
        
        if uploaded_file:
            try:
                event_data = json.load(uploaded_file)
                st.json(event_data)
                
                # Validate that this is actually a security event, not a report
                if 'report_id' in event_data:
                    st.error("❌ This appears to be a report file, not a security event. Please upload a security event JSON file.")
                elif 'event_id' not in event_data:
                    st.error("❌ Invalid event file: missing 'event_id' field. Please upload a valid security event JSON file.")
                else:
                    if st.button("🔍 Analyze This Event", type="primary", use_container_width=True):
                        try:
                            # Parse timestamp if it's a string
                            event_data_copy = event_data.copy()
                            if isinstance(event_data_copy.get('timestamp'), str):
                                from dateutil import parser
                                event_data_copy['timestamp'] = parser.parse(event_data_copy['timestamp'])
                            security_event = SecurityEvent(**event_data_copy)
                            should_analyze = True
                        except Exception as e:
                            st.error(f"Error parsing event: {str(e)}")
                            security_event = None
                            should_analyze = False
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON file: {str(e)}")
    
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
    
    # Run analysis only if button was clicked
    if security_event and should_analyze:
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


def show_network_monitor():
    """Show network monitoring page."""
    st.header("🌐 Network Traffic Monitor")
    
    st.markdown("""
    Monitor and analyze network traffic in real-time to detect suspicious patterns, 
    anomalies, and potential security threats.
    
    **Two Workflow Options:**
    1. **File Upload**: Upload a security event file for traditional threat detection
    2. **Network Capture**: Capture live traffic and run full analysis pipeline
    """)
    
    # Network monitoring mode selection
    mode = st.radio(
        "Select Monitoring Mode:",
        ["Analyze Network Event", "Live Traffic Simulation (Full Pipeline)", "Network Flow Analysis"],
        horizontal=True
    )
    
    if mode == "Analyze Network Event":
        analyze_network_event()
    elif mode == "Live Traffic Simulation (Full Pipeline)":
        simulate_live_traffic_full_pipeline()
    elif mode == "Network Flow Analysis":
        analyze_network_flows()


def analyze_network_event():
    """Analyze a network security event."""
    st.subheader("📁 Network Event Analysis")
    
    # Load network events
    samples = load_sample_events()
    network_events = {k: v for k, v in samples.items() if 'network' in k.lower()}
    
    if not network_events:
        st.warning("No network events found. Using all available events.")
        network_events = samples
    
    if network_events:
        selected_event = st.selectbox(
            "Select a network event:",
            options=list(network_events.keys()),
            format_func=lambda x: x.replace("_", " ").title()
        )
        
        if selected_event:
            event_data = network_events[selected_event]
            
            # Display event details
            with st.expander("📋 Event Details", expanded=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Event ID:** {event_data.get('event_id')}")
                    st.write(f"**Source:** {event_data.get('source')}")
                    st.write(f"**Type:** {event_data.get('event_type')}")
                
                with col2:
                    st.write(f"**Source IP:** {event_data.get('source_ip')}")
                    st.write(f"**Destination IP:** {event_data.get('destination_ip')}")
                    st.write(f"**Timestamp:** {event_data.get('timestamp')}")
                
                st.json(event_data.get('raw_data', {}))
            
            if st.button("🔍 Analyze Network Traffic", type="primary", use_container_width=True):
                run_network_analysis(event_data)
    else:
        st.info("No network events available. Upload a network event JSON file.")


def simulate_live_traffic_full_pipeline():
    """Simulate live network traffic capture with full analysis pipeline."""
    st.subheader("📡 Live Traffic Simulation - Full Analysis Pipeline")
    
    st.info("""
    **Full Workflow**: Network Capture → Network Analysis → Threat Detection → 
    Deep Analysis → Investigation → Response → Reporting
    
    This runs the complete threat hunting pipeline on captured network traffic.
    """)
    
    # Get available network interfaces
    try:
        from scapy.all import get_if_list
        available_interfaces = get_if_list()
        if not available_interfaces:
            available_interfaces = ["any"]
    except:
        available_interfaces = ["en0", "en1", "eth0", "wlan0", "lo0", "lo", "any"]
    
    col1, col2 = st.columns(2)
    
    with col1:
        interface = st.selectbox("Network Interface", available_interfaces, 
                                help="Select the network interface to capture from")
        duration = st.slider("Capture Duration (seconds)", 5, 180, 10)
        save_pcap = st.checkbox("💾 Save PCAP file", value=True, help="Save captured packets to a PCAP file for later analysis")
    
    with col2:
        filter_expr = st.text_input("BPF Filter (optional)", placeholder="tcp port 80")
        packet_limit = st.number_input("Packet Limit", min_value=10, max_value=1000000, value=100000)
    
    if st.button("🚀 Start Full Pipeline Analysis", type="primary", use_container_width=True):
        run_full_pipeline_capture(interface, duration, filter_expr, packet_limit, save_pcap)


def analyze_network_flows():
    """Analyze network flows."""
    st.subheader("🔀 Network Flow Analysis")
    
    st.markdown("""
    Analyze network flows to identify:
    - Suspicious connection patterns
    - Anomalous traffic volumes
    - Known malicious IPs
    - Protocol anomalies
    """)
    
    # Sample flow data input
    with st.form("flow_analysis_form"):
        st.write("**Enter Flow Details:**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            src_ip = st.text_input("Source IP", value="192.168.1.100")
            dst_ip = st.text_input("Destination IP", value="185.220.101.50")
            protocol = st.selectbox("Protocol", ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"])
        
        with col2:
            src_port = st.number_input("Source Port", min_value=0, max_value=65535, value=49152)
            dst_port = st.number_input("Destination Port", min_value=0, max_value=65535, value=4444)
            packet_count = st.number_input("Packet Count", min_value=1, max_value=100000, value=150)
        
        submitted = st.form_submit_button("🔍 Analyze Flow", type="primary", use_container_width=True)
        
        if submitted:
            run_flow_analysis(src_ip, dst_ip, protocol, src_port, dst_port, packet_count)


def run_network_analysis(event_data):
    """Run network analysis on an event."""
    from src.agents.network_capture_agent import NetworkCaptureAgent
    from src.agents.network_analysis_agent import NetworkAnalysisAgent
    
    st.markdown("---")
    st.subheader("🔄 Network Analysis in Progress")
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        # Create security event
        status_text.text("Creating security event...")
        progress_bar.progress(10)
        
        security_event = SecurityEvent(**event_data)
        
        # Initialize agents
        status_text.text("Initializing network agents...")
        progress_bar.progress(20)
        
        capture_agent = NetworkCaptureAgent()
        analysis_agent = NetworkAnalysisAgent()
        
        # Create initial state
        initial_state = AgentState(
            security_event=security_event,
            current_stage="network_capture"
        )
        
        # Capture network traffic
        status_text.text("📡 Capturing network traffic...")
        progress_bar.progress(40)
        
        state = capture_agent.capture(initial_state)
        
        if state.network_capture:
            display_network_capture_results(state.network_capture)
            
            # Analyze traffic
            status_text.text("🧠 Analyzing network traffic...")
            progress_bar.progress(70)
            
            state = analysis_agent.analyze(state)
            
            progress_bar.progress(100)
            status_text.text("✅ Analysis complete!")
            
            display_network_analysis_results(state)
        else:
            st.error("Failed to capture network traffic")
            
    except Exception as e:
        st.error(f"Error during network analysis: {str(e)}")
        st.exception(e)


def run_full_pipeline_capture(interface, duration, filter_expr, packet_limit, save_pcap=True):
    """Run full pipeline: capture → analysis → detection → investigation → response → report."""
    from src.graph.workflow import ThreatHuntingWorkflow
    from src.agents.network_capture_agent import NetworkCaptureAgent
    
    st.markdown("---")
    st.subheader("🔄 Full Pipeline Analysis in Progress")
    
    # Agent execution tracking
    st.markdown("### 🎯 Agent Execution Pipeline")
    
    agent_cols = st.columns(7)
    agent_status = {}
    
    agents = [
        ("🌐 Network Capture", "network_capture"),
        ("🔬 Network Analysis", "network_analysis"),
        ("🎯 Detection", "detection"),
        ("📊 Deep Analysis", "analysis"),
        ("🔎 Investigation", "investigation"),
        ("🚨 Response", "response"),
        ("📋 Reporting", "reporting")
    ]
    
    for idx, (name, key) in enumerate(agents):
        with agent_cols[idx]:
            agent_status[key] = st.empty()
            agent_status[key].markdown(f"**{name}**\n\n⏳ Pending")
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    log_expander = st.expander("📝 Execution Log", expanded=True)
    
    try:
        with log_expander:
            st.write(f"🚀 Initializing workflow for {duration}s capture on {interface}...")
            st.write(f"📦 Packet limit: {packet_limit:,}")
        
        # Initialize workflow
        workflow = ThreatHuntingWorkflow()
        
        # Create initial state for network capture
        initial_state = AgentState(current_stage="network_capture")
        
        # Update status
        agent_status["network_capture"].markdown(f"**🌐 Network Capture**\n\n⚙️ Running")
        status_text.text("📡 Capturing network traffic...")
        progress_bar.progress(10)
        
        with log_expander:
            st.write(f"🔍 Starting network capture for {duration} seconds...")
        
        # Run the full workflow
        import time
        time.sleep(0.5)  # Brief pause for UI
        
        final_state = workflow.run(initial_state)
        
        # Update all agents to completed
        progress_bar.progress(100)
        
        # Display results based on what was generated
        st.markdown("---")
        st.markdown("## 📊 Pipeline Results")
        
        # Network Capture Results
        if final_state.network_capture:
            agent_status["network_capture"].markdown(f"**🌐 Network Capture**\n\n✅ Done")
            with log_expander:
                st.write("✅ Network capture completed")
            display_network_capture_results(final_state.network_capture)
        
        # Network Analysis Results  
        if final_state.detection:
            agent_status["network_analysis"].markdown(f"**🔬 Network Analysis**\n\n✅ Done")
            agent_status["detection"].markdown(f"**🎯 Detection**\n\n✅ Done")
            with log_expander:
                st.write("✅ Threat detected in network traffic")
        
        # Analysis Results
        if final_state.analysis:
            agent_status["analysis"].markdown(f"**📊 Deep Analysis**\n\n✅ Done")
            with log_expander:
                st.write(f"✅ Analysis completed: {final_state.analysis.severity.value} severity")
            
            st.markdown("### 🔬 Threat Analysis")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Severity", final_state.analysis.severity.value.upper())
            with col2:
                st.metric("Category", final_state.analysis.category.value.replace("_", " ").title())
            with col3:
                st.metric("Affected Assets", len(final_state.analysis.affected_assets))
        
        # Investigation Results
        if final_state.investigation:
            agent_status["investigation"].markdown(f"**🔎 Investigation**\n\n✅ Done")
            with log_expander:
                st.write("✅ Investigation completed")
            
            st.markdown("### 🔍 Investigation Findings")
            if final_state.investigation.root_cause:
                st.write(f"**Root Cause:** {final_state.investigation.root_cause}")
            if final_state.investigation.attack_chain:
                st.write("**Attack Chain:**")
                for step in final_state.investigation.attack_chain:
                    st.write(f"  • {step}")
        
        # Response Results
        if final_state.response:
            agent_status["response"].markdown(f"**🚨 Response**\n\n✅ Done")
            with log_expander:
                st.write("✅ Response actions planned")
            
            st.markdown("### 🚨 Incident Response")
            st.write(f"**Containment Status:** {final_state.response.containment_status}")
            if final_state.response.actions_taken:
                st.write("**Actions Taken:**")
                for action in final_state.response.actions_taken:
                    st.write(f"  • {action.value.replace('_', ' ').title()}")
        
        # Report Results
        if final_state.report:
            agent_status["reporting"].markdown(f"**📋 Reporting**\n\n✅ Done")
            with log_expander:
                st.write("✅ Final report generated")
            
            st.markdown("### 📋 Incident Report")
            
            with st.expander("📄 Executive Summary", expanded=True):
                st.write(final_state.report.executive_summary)
            
            with st.expander("🔧 Technical Details"):
                st.write(final_state.report.technical_details)
            
            with st.expander("💡 Recommendations"):
                for rec in final_state.report.recommendations:
                    st.write(f"• {rec}")
            
            # Download button
            report_json = final_state.report.model_dump(mode='json')
            st.download_button(
                label="📥 Download Full Report (JSON)",
                data=json.dumps(report_json, indent=2, default=str),
                file_name=f"network_threat_report_{final_state.report.report_id[:8]}.json",
                mime="application/json",
                use_container_width=True
            )
        
        status_text.text("✅ Full pipeline analysis complete!")
        
        with log_expander:
            st.write("🎉 Workflow completed successfully!")
            
    except Exception as e:
        st.error(f"Error during pipeline execution: {str(e)}")
        st.exception(e)
        with log_expander:
            st.write(f"❌ Error: {str(e)}")


def run_flow_analysis(src_ip, dst_ip, protocol, src_port, dst_port, packet_count):
    """Analyze a single network flow."""
    from src.agents.network_capture_agent import NetworkCaptureAgent
    from src.agents.network_analysis_agent import NetworkAnalysisAgent
    
    st.markdown("---")
    st.subheader("🔍 Flow Analysis Results")
    
    try:
        # Create a synthetic event from flow data
        event_data = {
            "event_id": f"flow_{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.now().isoformat(),
            "source": "network_monitor",
            "event_type": "network_flow",
            "raw_data": {
                "protocol": protocol.lower(),
                "source_port": src_port,
                "destination_port": dst_port,
                "packet_count": packet_count
            },
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "process": "network_monitor"
        }
        
        security_event = SecurityEvent(**event_data)
        
        # Analyze
        capture_agent = NetworkCaptureAgent()
        analysis_agent = NetworkAnalysisAgent()
        
        initial_state = AgentState(
            security_event=security_event,
            current_stage="network_capture"
        )
        
        state = capture_agent.capture(initial_state)
        
        if state.network_capture:
            display_network_capture_results(state.network_capture)
            state = analysis_agent.analyze(state)
            display_network_analysis_results(state)
        
    except Exception as e:
        st.error(f"Error analyzing flow: {str(e)}")


def display_network_capture_results(capture):
    """Display network capture results."""
    st.markdown("---")
    st.markdown("### 📊 Capture Results")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Packets", capture.packets_captured)
    
    with col2:
        st.metric("Total Flows", len(capture.flows))
    
    with col3:
        st.metric("Suspicious Flows", len(capture.suspicious_flows), 
                 delta=f"{len(capture.suspicious_flows)/max(len(capture.flows), 1)*100:.1f}%")
    
    with col4:
        st.metric("Capture Status", capture.capture_status.upper())
    
    # PCAP file download
    if capture.pcap_file:
        st.markdown("---")
        col_pcap1, col_pcap2 = st.columns([3, 1])
        with col_pcap1:
            st.info(f"📦 **PCAP File Saved:** `{capture.pcap_file}`")
        with col_pcap2:
            # Check if file exists and offer download
            import os
            if os.path.exists(capture.pcap_file):
                with open(capture.pcap_file, 'rb') as f:
                    st.download_button(
                        label="📥 Download PCAP",
                        data=f.read(),
                        file_name=os.path.basename(capture.pcap_file),
                        mime="application/vnd.tcpdump.pcap",
                        use_container_width=True
                    )
            else:
                st.warning("PCAP file not found")
    
    # Flow details table
    if capture.flows:
        st.markdown("#### Network Flows")
        
        import pandas as pd
        
        flow_data = []
        for flow in capture.flows[:20]:  # Show top 20
            flow_data.append({
                "Flow ID": flow.flow_id[:8] + "...",
                "Source": f"{flow.source_ip}:{flow.source_port or 'N/A'}",
                "Destination": f"{flow.destination_ip}:{flow.destination_port or 'N/A'}",
                "Protocol": flow.protocol.value.upper(),
                "Packets": flow.packet_count,
                "Bytes": flow.byte_count,
                "Anomaly Score": f"{flow.anomaly_score:.2f}",
                "Suspicious": "🚨" if flow.is_suspicious else "✅"
            })
        
        df = pd.DataFrame(flow_data)
        st.dataframe(df, use_container_width=True)
    
    # Suspicious flows details
    if capture.suspicious_flows:
        with st.expander("⚠️ Suspicious Flow Details", expanded=True):
            for i, flow in enumerate(capture.suspicious_flows[:5], 1):
                st.markdown(f"**Flow {i}:** `{flow.flow_id}`")
                st.write(f"- **Route:** {flow.source_ip}:{flow.source_port or 'N/A'} → {flow.destination_ip}:{flow.destination_port or 'N/A'}")
                st.write(f"- **Protocol:** {flow.protocol.value.upper()}")
                st.write(f"- **Anomaly Score:** {flow.anomaly_score:.2f}")
                
                if flow.threat_indicators:
                    st.write("- **Threat Indicators:**")
                    for indicator in flow.threat_indicators:
                        st.markdown(f"  - {indicator}")
                
                st.markdown("---")


def display_network_analysis_results(state):
    """Display network analysis results."""
    st.markdown("---")
    st.markdown("### 🔬 Analysis Results")
    
    if state.detection:
        st.error("⚠️ **NETWORK THREAT DETECTED**")
        
        detection = state.detection
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Confidence", f"{detection.confidence_score:.2%}")
        
        with col2:
            st.metric("Detection Method", detection.detection_method)
        
        with col3:
            st.metric("Threat Indicators", len(detection.threat_indicators))
        
        if detection.threat_indicators:
            st.markdown("#### 🔍 Threat Indicators")
            for indicator in detection.threat_indicators:
                st.warning(f"• {indicator}")
        
        # Show created security event
        with st.expander("📋 Generated Security Event"):
            st.json(detection.event.model_dump(mode='json'))
    
    else:
        st.success("✅ **No threats detected in network traffic**")
    
    # Show messages
    if state.messages:
        with st.expander("📝 Analysis Log"):
            for msg in state.messages:
                st.info(msg)


def show_ml_classifier():
    """Show ML Traffic Classifier page."""
    st.header("🤖 ML Traffic Classifier")
    
    st.markdown("""
    ### Machine Learning-Based Network Traffic Classification
    
    This agent uses **Support Vector Machines (SVM)** for intelligent traffic analysis:
    - **Flow-based analysis** of network patterns
    - **Baseline modeling** of normal network behavior
    - **Anomaly detection** using statistical methods
    - **Multi-class classification**: Normal, Suspicious, Malicious, Anomaly
    """)
    
    tabs = st.tabs(["📊 Analyze PCAP", "🎓 Train Model", "📈 Model Info"])
    
    # Tab 1: Analyze PCAP
    with tabs[0]:
        st.subheader("Analyze PCAP File")
        
        st.info("Upload a PCAP file captured using Scapy or select from existing captures.")
        
        # Option to select from captures directory or upload
        analysis_method = st.radio(
            "Select PCAP source:",
            ["From Captures Directory", "Upload New PCAP"],
            horizontal=True
        )
        
        pcap_file = None
        
        if analysis_method == "From Captures Directory":
            # List available PCAP files
            import os
            captures_dir = Path("captures")
            if captures_dir.exists():
                pcap_files = list(captures_dir.glob("*.pcap"))
                if pcap_files:
                    selected_pcap = st.selectbox(
                        "Select PCAP file:",
                        options=[str(f) for f in pcap_files],
                        format_func=lambda x: os.path.basename(x)
                    )
                    pcap_file = selected_pcap
                else:
                    st.warning("No PCAP files found in captures directory.")
            else:
                st.warning("Captures directory not found.")
        
        else:  # Upload New PCAP
            uploaded_file = st.file_uploader("Upload PCAP file", type=['pcap', 'pcapng'])
            if uploaded_file:
                # Save uploaded file temporarily
                temp_path = Path("captures") / uploaded_file.name
                temp_path.parent.mkdir(exist_ok=True)
                with open(temp_path, 'wb') as f:
                    f.write(uploaded_file.read())
                pcap_file = str(temp_path)
                st.success(f"Uploaded: {uploaded_file.name}")
        
        if pcap_file and st.button("🔍 Analyze Traffic", type="primary", use_container_width=True):
            analyze_pcap_with_ml(pcap_file)
    
    # Tab 2: Train Model
    with tabs[1]:
        st.subheader("Train SVM Model")
        
        st.info("""
        Train the SVM classifier on labeled network traffic data.
        The model will learn to distinguish between normal, suspicious, malicious, and anomalous traffic.
        """)
        
        st.warning("⚠️ Training requires labeled data. This feature is for demonstration purposes.")
        
        if st.button("🎓 Generate Training Data & Train", type="secondary"):
            train_ml_model()
    
    # Tab 3: Model Info
    with tabs[2]:
        st.subheader("Model Information")
        
        from src.agents.ml_traffic_classifier_agent import MLTrafficClassifierAgent
        
        try:
            agent = MLTrafficClassifierAgent()
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                model_type = "Deep Learning (Neural Network)" if agent.use_deep_learning else "SVM (RBF Kernel)"
                st.metric("Model Type", model_type)
                st.metric("Feature Count", len(agent.feature_names))
                
                if agent.use_deep_learning:
                    model_status = "Trained ✅" if hasattr(agent.model, 'predict') else "Not Trained ❌"
                else:
                    model_status = "Trained ✅" if hasattr(agent.model, 'classes_') else "Not Trained ❌"
                st.metric("Model Status", model_status)
            
            with col2:
                st.metric("Traffic Classes", len(agent.traffic_classes))
                st.metric("Application Types", len(agent.application_types))
                st.metric("Baseline Status", "Loaded ✅" if agent.baseline else "Not Loaded ❌")
            
            with col3:
                if agent.use_deep_learning:
                    st.metric("Architecture", "4-Layer DNN")
                    st.metric("Hidden Layers", "128→64→32→16")
                    st.metric("Framework", "TensorFlow/Keras")
            
            st.markdown("---")
            st.markdown("### Features Used")
            
            features_df = pd.DataFrame({
                'Feature': agent.feature_names,
                'Description': [
                    'Number of packets in flow',
                    'Total bytes transferred',
                    'Average packet size',
                    'Flow duration (seconds)',
                    'Packets per second rate',
                    'Bytes per second rate',
                    'TCP protocol indicator',
                    'UDP protocol indicator',
                    'ICMP protocol indicator',
                    'Destination port range category',
                    'Flow direction indicator',
                    'Source port number',
                    'Destination port number',
                    'Variance in packet sizes',
                    'Variance in byte counts',
                    'Time between packets',
                    'Packets in forward direction',
                    'Packets in backward direction',
                    'Number of SYN flags',
                    'Number of ACK flags',
                    'Number of PSH flags'
                ]
            })
            st.dataframe(features_df, use_container_width=True)
            
            st.markdown("---")
            st.markdown("### Traffic Classes (Intrusion Detection)")
            
            col1, col2 = st.columns(2)
            
            with col1:
                for class_id in range(0, 4):
                    class_name = agent.traffic_classes.get(class_id, 'unknown')
                    st.write(f"**{class_id}:** {class_name.upper().replace('_', ' ')}")
            
            with col2:
                for class_id in range(4, len(agent.traffic_classes)):
                    class_name = agent.traffic_classes.get(class_id, 'unknown')
                    st.write(f"**{class_id}:** {class_name.upper().replace('_', ' ')}")
            
            st.markdown("---")
            st.markdown("### Application Types")
            
            app_types_df = pd.DataFrame([
                {'Application': app_type.upper(), 'Ports': ', '.join(map(str, ports)) if ports else 'Various'}
                for app_type, ports in agent.application_types.items()
            ])
            st.dataframe(app_types_df, use_container_width=True)
            
            if agent.use_deep_learning:
                st.markdown("---")
                st.markdown("### Deep Learning Architecture")
                
                st.info("""
                **Neural Network Layers:**
                - Input Layer: 21 features
                - Hidden Layer 1: 128 neurons (ReLU + BatchNorm + 30% Dropout)
                - Hidden Layer 2: 64 neurons (ReLU + BatchNorm + 30% Dropout)
                - Hidden Layer 3: 32 neurons (ReLU + BatchNorm + 20% Dropout)
                - Hidden Layer 4: 16 neurons (ReLU + 20% Dropout)
                - Output Layer: 8 neurons (Softmax)
                
                **Optimization:**
                - Optimizer: Adam (lr=0.001)
                - Loss: Sparse Categorical Crossentropy
                - Regularization: L2 (0.001) + Dropout
                - Metrics: Accuracy, Precision, Recall
                """)
            
        except Exception as e:
            st.error(f"Error loading model info: {str(e)}")


def analyze_pcap_with_ml(pcap_file: str):
    """Analyze PCAP file using ML classifier."""
    from src.agents.ml_traffic_classifier_agent import MLTrafficClassifierAgent
    
    try:
        with st.spinner("🔍 Analyzing PCAP file with ML classifier..."):
            agent = MLTrafficClassifierAgent()
            
            # Analyze PCAP
            results = agent.analyze_pcap(pcap_file)
            
            st.success("✅ Analysis Complete!")
            
            # File Information Header
            st.markdown("---")
            file_info = results['file_info']
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.info(f"📁 **Uploaded File:** {file_info['filename']}")
            with col2:
                st.info(f"📊 **File Size:** {file_info['file_size_readable']}")
            with col3:
                st.success(f"✅ **Current Status:** {file_info['status']}")
            
            # Summary Statistics
            st.markdown("---")
            st.markdown("## 📊 Sniffed, Scanned, and Summarized 🔍")
            
            packet_details = results['packet_details']
            summary = results['summary']
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### Total Packets Processed")
                st.markdown(f"<h1 style='text-align: center; color: #1f77b4;'>{results['total_packets']}</h1>", unsafe_allow_html=True)
                
                st.markdown("### Time Range")
                if packet_details['time_range']['start'] and packet_details['time_range']['end']:
                    st.write(f"**Start:** {packet_details['time_range']['start'].strftime('%d %b %Y, %I:%M:%S %p')}")
                    st.write(f"**End:** {packet_details['time_range']['end'].strftime('%d %b %Y, %I:%M:%S %p')}")
                else:
                    st.write("Time range not available")
            
            with col2:
                st.markdown("### Unique Protocols Used")
                protocol_badges = " ".join([f"`{p}`" for p in packet_details['unique_protocols']])
                st.markdown(protocol_badges)
                
                st.markdown("### Total Data Size")
                st.markdown(f"<h3 style='text-align: center; color: #2ca02c;'>{packet_details['total_data_size_readable']} ({packet_details['data_size_percentage']:.1f}% of file size)</h3>", unsafe_allow_html=True)
            
            # Detailed Analysis
            st.markdown("---")
            st.markdown("## 📋 Overview of Captured Traffic")
            
            protocol_breakdown = results['protocol_breakdown']
            total_bytes = packet_details['total_data_size']
            
            overview_text = f"The captured traffic consists of **{results['total_packets']} packets**, totaling **{packet_details['total_data_size_readable']}** of data. "
            overview_text += f"The protocols used are **{', '.join(packet_details['unique_protocols'])}**."
            
            st.write(overview_text)
            
            # Protocol Breakdown
            st.markdown("### 🔍 Protocol Breakdown")
            
            protocol_counts = protocol_breakdown['protocol_counts']
            
            if protocol_counts.get('DNS', 0) > 0:
                st.markdown(f"**DNS queries** are observed using UDP, targeting domain name servers.")
                if protocol_breakdown['dns_queries']:
                    with st.expander("View DNS Queries"):
                        for query in protocol_breakdown['dns_queries']:
                            st.write(f"- {query}")
            
            if protocol_counts.get('TCP', 0) > 0:
                st.markdown(f"**TCP connections** are established ({protocol_counts['TCP']} packets).")
                if protocol_breakdown['tcp_connections']:
                    with st.expander("View TCP Connections"):
                        for conn in protocol_breakdown['tcp_connections'][:10]:
                            st.write(f"- {conn['src']}:{conn['sport']} → {conn['dst']}:{conn['dport']} (Flags: {conn['flags']})")
            
            if protocol_counts.get('UDP', 0) > 0:
                st.markdown(f"**UDP packets** detected ({protocol_counts['UDP']} packets).")
            
            # Notable Observations
            st.markdown("### 👁️ Notable Observations")
            
            for observation in results['notable_observations']:
                st.write(f"- {observation}")
            
            # Potential Threats
            st.markdown("### ⚠️ Potential Threats")
            
            for threat in results['potential_threats']:
                if '⚠️' in threat:
                    st.warning(threat)
                else:
                    st.success(threat)
            
            # Packet Content Analysis
            st.markdown("### 📦 Packet Content Analysis")
            
            content_analysis = results['packet_content_analysis']
            st.write(content_analysis['note'])
            
            if content_analysis['packets_with_payload'] > 0:
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Packets with Payload", content_analysis['packets_with_payload'])
                with col2:
                    st.metric("Payload Percentage", f"{content_analysis['payload_percentage']:.1f}%")
            
            # Conclusion
            st.markdown("### 📝 Conclusion")
            st.markdown(results['conclusion'])
            
            # ML Classification Summary
            st.markdown("---")
            st.markdown("## 🤖 ML Classification Results")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Flows", results['total_flows'])
            with col2:
                st.metric("Anomalies", summary['anomaly_count'])
            with col3:
                st.metric("Avg Confidence", f"{summary['average_confidence']:.1%}")
            with col4:
                risk_color = {
                    'low': '🟢',
                    'medium': '🟡',
                    'high': '🟠',
                    'critical': '🔴'
                }.get(summary['risk_level'], '⚪')
                st.metric("Risk Level", f"{risk_color} {summary['risk_level'].upper()}")
            
            # Class distribution
            st.markdown("### 📈 Traffic Classification")
            
            class_dist = summary['class_distribution']
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                # Create bar chart
                import plotly.graph_objects as go
                
                fig = go.Figure(data=[
                    go.Bar(
                        x=list(class_dist.keys()),
                        y=list(class_dist.values()),
                        marker_color=['green', 'yellow', 'orange', 'red'][:len(class_dist)]
                    )
                ])
                fig.update_layout(
                    title="Traffic Classification Distribution",
                    xaxis_title="Class",
                    yaxis_title="Count",
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("#### Statistics")
                st.metric("Avg Confidence", f"{summary['average_confidence']:.2%}")
                st.metric("Avg Deviation", f"{summary['average_baseline_deviation']:.2f}σ")
                st.metric("Anomaly Rate", f"{summary['anomaly_percentage']:.1f}%")
            
            # Detailed classifications
            st.markdown("### 🔍 Detailed Flow Classifications")
            
            classifications = results['classifications']
            
            # Filter options
            filter_class = st.multiselect(
                "Filter by classification:",
                options=['normal', 'suspicious', 'malicious', 'anomaly'],
                default=['suspicious', 'malicious', 'anomaly']
            )
            
            filtered = [c for c in classifications if c['classification'] in filter_class]
            
            if filtered:
                # Create DataFrame
                df_data = []
                for c in filtered[:50]:  # Show top 50
                    df_data.append({
                        'Flow ID': c['flow_id'][:8] + '...',
                        'Classification': c['classification'].upper(),
                        'Confidence': f"{c['confidence']:.2%}",
                        'Baseline Deviation': f"{c['baseline_deviation']:.2f}σ",
                        'Anomaly': '🚨' if c['is_anomaly'] else '✅',
                        'Packets': int(c['features']['packet_count']),
                        'Bytes': int(c['features']['byte_count'])
                    })
                
                df = pd.DataFrame(df_data)
                st.dataframe(df, use_container_width=True)
                
                # Download results
                st.download_button(
                    label="📥 Download Full Results (JSON)",
                    data=json.dumps(results, indent=2, default=str),
                    file_name=f"ml_analysis_{Path(pcap_file).stem}.json",
                    mime="application/json",
                    use_container_width=True
                )
            else:
                st.info("No flows match the selected filters.")
            
    except Exception as e:
        st.error(f"Error analyzing PCAP: {str(e)}")
        st.exception(e)


def train_ml_model():
    """Train the ML model with synthetic data."""
    from src.agents.ml_traffic_classifier_agent import MLTrafficClassifierAgent
    from src.models.schemas import NetworkFlow, NetworkProtocol
    
    try:
        with st.spinner("🎓 Generating training data and training model..."):
            agent = MLTrafficClassifierAgent()
            
            # Generate synthetic training data
            flows = []
            labels = []
            
            # Normal traffic (class 0)
            for i in range(100):
                flow = NetworkFlow(
                    flow_id=str(uuid.uuid4()),
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    protocol=NetworkProtocol.TCP if i % 2 == 0 else NetworkProtocol.UDP,
                    source_ip=f"192.168.1.{i % 255}",
                    destination_ip=f"10.0.0.{i % 255}",
                    source_port=50000 + i,
                    destination_port=80 if i % 3 == 0 else 443,
                    packet_count=30 + (i % 50),
                    byte_count=45000 + (i % 30000),
                    packets=[],
                    is_suspicious=False,
                    anomaly_score=0.1
                )
                flows.append(flow)
                labels.append(0)
            
            # Suspicious traffic (class 1)
            for i in range(50):
                flow = NetworkFlow(
                    flow_id=str(uuid.uuid4()),
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    protocol=NetworkProtocol.TCP,
                    source_ip=f"192.168.1.{i % 255}",
                    destination_ip=f"185.{i % 255}.{i % 255}.{i % 255}",
                    source_port=50000 + i,
                    destination_port=4444 if i % 2 == 0 else 31337,
                    packet_count=80 + (i % 100),
                    byte_count=120000 + (i % 80000),
                    packets=[],
                    is_suspicious=True,
                    anomaly_score=0.6
                )
                flows.append(flow)
                labels.append(1)
            
            # Malicious traffic (class 2)
            for i in range(30):
                flow = NetworkFlow(
                    flow_id=str(uuid.uuid4()),
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    protocol=NetworkProtocol.TCP,
                    source_ip=f"192.168.1.{i % 255}",
                    destination_ip=f"203.0.113.{i % 255}",
                    source_port=50000 + i,
                    destination_port=1337,
                    packet_count=200 + (i % 300),
                    byte_count=300000 + (i % 200000),
                    packets=[],
                    is_suspicious=True,
                    anomaly_score=0.9
                )
                flows.append(flow)
                labels.append(2)
            
            # Anomaly traffic (class 3)
            for i in range(20):
                flow = NetworkFlow(
                    flow_id=str(uuid.uuid4()),
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    protocol=NetworkProtocol.ICMP,
                    source_ip=f"192.168.1.{i % 255}",
                    destination_ip=f"10.0.0.{i % 255}",
                    source_port=None,
                    destination_port=None,
                    packet_count=500 + (i % 1000),
                    byte_count=750000 + (i % 500000),
                    packets=[],
                    is_suspicious=True,
                    anomaly_score=0.95
                )
                flows.append(flow)
                labels.append(3)
            
            # Train model
            results = agent.train_model(flows, labels)
            
            st.success("✅ Model trained successfully!")
            
            # Display results
            st.markdown("### 📊 Training Results")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Accuracy", f"{results['accuracy']:.2%}")
            with col2:
                st.metric("Training Samples", results['train_samples'])
            with col3:
                st.metric("Test Samples", results['test_samples'])
            
            # Classification report
            st.markdown("### 📈 Classification Report")
            
            report = results['classification_report']
            report_df = pd.DataFrame(report).transpose()
            st.dataframe(report_df, use_container_width=True)
            
            # Confusion matrix
            st.markdown("### 🎯 Confusion Matrix")
            
            cm = np.array(results['confusion_matrix'])
            
            import plotly.figure_factory as ff
            
            fig = ff.create_annotated_heatmap(
                z=cm,
                x=['Normal', 'Suspicious', 'Malicious', 'Anomaly'],
                y=['Normal', 'Suspicious', 'Malicious', 'Anomaly'],
                colorscale='Blues'
            )
            fig.update_layout(title="Confusion Matrix", height=500)
            st.plotly_chart(fig, use_container_width=True)
            
    except Exception as e:
        st.error(f"Error training model: {str(e)}")
        st.exception(e)


def show_ai_packet_analyzer():
    """Show AI Packet Analyzer page."""
    st.header("🤖 AI Packet Analyzer")
    
    st.markdown("""
    ### Advanced AI-Powered Network Traffic Analysis
    
    This agent uses cutting-edge AI technologies for intelligent network analysis:
    - **Zeek Parsing**: Structured log extraction from PCAPs
    - **OpenAI Embeddings**: Vector representations of network traffic
    - **Pinecone Vector DB**: Fast similarity search
    - **RAG (Retrieval-Augmented Generation)**: Natural language querying
    - **Anomaly Detection**: Embedding-based deviation detection
    - **Threat Hunting**: Known malicious pattern matching
    """)
    
    # Check if Pinecone is configured
    if not settings.PINECONE_API_KEY:
        st.warning("⚠️ Pinecone API key not configured. Some features will be limited.")
        st.info("Add PINECONE_API_KEY to your .env file to enable vector storage and advanced querying.")
    
    tabs = st.tabs(["💬 Chat with PCAP", "📊 Analyze PCAP", "🔍 Natural Language Query", "🎯 Threat Hunt", "⚙️ Configuration"])
    
    # Tab 0: Chat with PCAP
    with tabs[0]:
        show_pcap_chat_interface()
    
    # Tab 1: Analyze PCAP
    with tabs[1]:
        st.subheader("Analyze PCAP with AI")
        
        st.info("Upload a PCAP file or select from existing captures for AI-powered analysis.")
        
        # Option to select from captures directory or upload
        analysis_method = st.radio(
            "Select PCAP source:",
            ["From Captures Directory", "Upload New PCAP"],
            horizontal=True
        )
        
        pcap_file = None
        
        if analysis_method == "From Captures Directory":
            # List available PCAP files
            import os
            captures_dir = Path("captures")
            if captures_dir.exists():
                pcap_files = list(captures_dir.glob("*.pcap"))
                if pcap_files:
                    selected_pcap = st.selectbox(
                        "Select PCAP file:",
                        options=[str(f) for f in pcap_files],
                        format_func=lambda x: os.path.basename(x)
                    )
                    pcap_file = selected_pcap
                else:
                    st.warning("No PCAP files found in captures directory.")
            else:
                st.warning("Captures directory not found.")
        
        else:  # Upload New PCAP
            uploaded_file = st.file_uploader("Upload PCAP file", type=['pcap', 'pcapng'])
            if uploaded_file:
                # Save uploaded file temporarily
                temp_path = Path("captures") / uploaded_file.name
                temp_path.parent.mkdir(exist_ok=True)
                with open(temp_path, 'wb') as f:
                    f.write(uploaded_file.read())
                pcap_file = str(temp_path)
                st.success(f"Uploaded: {uploaded_file.name}")
        
        if pcap_file and st.button("🔍 Analyze with AI", type="primary", use_container_width=True):
            analyze_pcap_with_ai(pcap_file)
    
    # Tab 2: Natural Language Query
    with tabs[2]:
        st.subheader("Query Traffic with Natural Language")
        
        st.markdown("""
        Ask questions about your network traffic in plain English. The AI will retrieve 
        relevant traffic from the vector database and provide intelligent analysis.
        """)
        
        # Example queries
        with st.expander("📝 Example Queries"):
            st.markdown("""
            - "Show me exfiltration attempts via DNS tunneling"
            - "Find all connections to port 4444"
            - "What traffic occurred between 2pm and 3pm?"
            - "Show me all HTTP POST requests"
            - "Find connections from 192.168.1.100"
            - "Detect potential C2 communications"
            - "Show me unusual DNS queries"
            - "Find large data transfers"
            """)
        
        query = st.text_area("Enter your question:", height=100, placeholder="e.g., Show me suspicious DNS queries...")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            top_k = st.slider("Number of results to retrieve:", 1, 20, 5)
        with col2:
            if st.button("🔍 Query", type="primary", use_container_width=True):
                if query:
                    query_traffic_with_rag(query, top_k)
                else:
                    st.warning("Please enter a question.")
    
    # Tab 3: Threat Hunt
    with tabs[3]:
        st.subheader("Threat Hunting")
        
        st.markdown("""
        Search for known malicious patterns using similarity matching against stored traffic.
        """)
        
        # Add malicious pattern
        with st.expander("➕ Add Malicious Pattern"):
            pattern_desc = st.text_area("Pattern Description:", 
                                       placeholder="e.g., Cobalt Strike beacon: Regular 60-second intervals to 185.x.x.x")
            pattern_type = st.selectbox("Threat Type:", ["C2", "Exfiltration", "Malware", "Scanning", "Other"])
            pattern_severity = st.selectbox("Severity:", ["Critical", "High", "Medium", "Low"])
            
            if st.button("Add Pattern"):
                if pattern_desc:
                    add_malicious_pattern(pattern_desc, pattern_type, pattern_severity)
                else:
                    st.warning("Please enter a pattern description.")
        
        # Hunt for threats
        st.markdown("### Hunt for Threats")
        
        threat_query = st.text_input("Describe the threat to hunt for:", 
                                     placeholder="e.g., C2 beaconing with regular intervals")
        hunt_top_k = st.slider("Number of matches:", 1, 20, 10)
        
        if st.button("🎯 Hunt", type="primary", use_container_width=True):
            if threat_query:
                hunt_for_threats(threat_query, hunt_top_k)
            else:
                st.warning("Please enter a threat description.")
    
    # Tab 4: Configuration
    with tabs[4]:
        st.subheader("AI Packet Analyzer Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### API Configuration")
            st.write(f"**OpenAI API Key:** {'Configured ✅' if settings.OPENAI_API_KEY else 'Not Configured ❌'}")
            st.write(f"**Pinecone API Key:** {'Configured ✅' if settings.PINECONE_API_KEY else 'Not Configured ❌'}")
            
            st.markdown("### Embedding Model")
            st.write("**Model:** text-embedding-3-small")
            st.write("**Dimensions:** 1536")
            st.write("**Cost:** $0.00002 per 1K tokens")
        
        with col2:
            st.markdown("### Vector Database")
            st.write("**Provider:** Pinecone")
            st.write("**Index:** network-traffic")
            st.write("**Metric:** Cosine Similarity")
            
            st.markdown("### LLM Configuration")
            st.write(f"**Model:** {settings.DEFAULT_MODEL}")
            st.write(f"**Temperature:** {settings.TEMPERATURE}")
        
        st.markdown("---")
        st.markdown("### Features")
        
        features = [
            "✅ Zeek PCAP parsing (with Scapy fallback)",
            "✅ OpenAI embeddings for traffic representation",
            "✅ Pinecone vector storage",
            "✅ RAG-based natural language querying",
            "✅ Anomaly detection via embedding similarity",
            "✅ Threat hunting with known patterns",
            "✅ Real-time analysis and insights"
        ]
        
        for feature in features:
            st.write(feature)


def show_pcap_chat_interface():
    """Show interactive chat interface for PCAP analysis."""
    st.subheader("💬 Chat with Your PCAP File")
    
    st.markdown("""
    Upload a PCAP file and ask questions about it in natural language. The AI will analyze 
    the traffic and answer your questions using advanced RAG (Retrieval-Augmented Generation).
    """)
    
    # Initialize session state for chat
    if 'pcap_chat_history' not in st.session_state:
        st.session_state.pcap_chat_history = []
    if 'pcap_file_loaded' not in st.session_state:
        st.session_state.pcap_file_loaded = None
    if 'pcap_analysis_results' not in st.session_state:
        st.session_state.pcap_analysis_results = None
    
    # File upload section
    st.markdown("### 📁 Step 1: Upload PCAP File")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        uploaded_file = st.file_uploader(
            "Choose a PCAP file", 
            type=['pcap', 'pcapng'],
            key="pcap_chat_uploader"
        )
    
    with col2:
        # Option to select from existing captures
        captures_dir = Path("captures")
        if captures_dir.exists():
            pcap_files = list(captures_dir.glob("*.pcap*"))
            if pcap_files:
                selected_existing = st.selectbox(
                    "Or select existing:",
                    options=["None"] + [str(f) for f in pcap_files],
                    format_func=lambda x: "Select..." if x == "None" else Path(x).name
                )
                if selected_existing != "None":
                    uploaded_file = selected_existing
    
    # Process uploaded file
    if uploaded_file:
        if isinstance(uploaded_file, str):
            # Existing file selected
            pcap_path = uploaded_file
            file_name = Path(pcap_path).name
        else:
            # New file uploaded
            pcap_path = Path("captures") / uploaded_file.name
            pcap_path.parent.mkdir(exist_ok=True)
            
            # Save if not already saved or if different
            if st.session_state.pcap_file_loaded != str(pcap_path):
                with open(pcap_path, 'wb') as f:
                    f.write(uploaded_file.read())
            
            file_name = uploaded_file.name
            pcap_path = str(pcap_path)
        
        # Check if we need to analyze this file
        if st.session_state.pcap_file_loaded != pcap_path:
            with st.spinner(f"🔍 Analyzing {file_name}..."):
                from src.agents.ai_packet_analyzer_agent import AIPacketAnalyzerAgent
                
                try:
                    agent = AIPacketAnalyzerAgent()
                    results = agent.analyze_pcap(pcap_path)
                    
                    st.session_state.pcap_file_loaded = pcap_path
                    st.session_state.pcap_analysis_results = results
                    st.session_state.pcap_chat_history = []
                    
                    # Add welcome message
                    st.session_state.pcap_chat_history.append({
                        "role": "assistant",
                        "content": f"✅ Successfully analyzed **{file_name}**!\n\n"
                                 f"📊 **Summary:**\n"
                                 f"- Total Logs: {results['total_logs']}\n"
                                 f"- Embeddings Created: {results['embeddings_created']}\n"
                                 f"- Anomalies Detected: {results['anomalies_detected']}\n\n"
                                 f"💬 Ask me anything about this network traffic!"
                    })
                    
                    st.success(f"✅ Loaded {file_name}")
                    
                except Exception as e:
                    st.error(f"Error analyzing PCAP: {str(e)}")
                    return
        else:
            st.info(f"📁 Currently analyzing: **{file_name}**")
    
    # Chat interface
    if st.session_state.pcap_file_loaded:
        st.markdown("---")
        st.markdown("### 💬 Step 2: Ask Questions")
        
        # Display chat history
        chat_container = st.container()
        with chat_container:
            for message in st.session_state.pcap_chat_history:
                if message["role"] == "user":
                    st.markdown(f"**🧑 You:** {message['content']}")
                else:
                    st.markdown(f"**🤖 AI:** {message['content']}")
                st.markdown("---")
        
        # Example questions
        with st.expander("💡 Example Questions"):
            st.markdown("""
            - "What are the most common protocols in this traffic?"
            - "Show me any suspicious DNS queries"
            - "Are there any connections to unusual ports?"
            - "What IP addresses communicated the most?"
            - "Detect any potential data exfiltration"
            - "Show me all HTTP requests"
            - "Are there signs of port scanning?"
            - "What's the total data transferred?"
            """)
        
        # Chat input
        col1, col2 = st.columns([5, 1])
        
        with col1:
            user_question = st.text_input(
                "Ask a question about the traffic:",
                placeholder="e.g., Show me suspicious DNS queries...",
                key="pcap_chat_input"
            )
        
        with col2:
            send_button = st.button("Send 📤", type="primary", use_container_width=True)
        
        # Process question
        if send_button and user_question:
            # Add user message to history
            st.session_state.pcap_chat_history.append({
                "role": "user",
                "content": user_question
            })
            
            # Get AI response
            with st.spinner("🤔 Thinking..."):
                from src.agents.ai_packet_analyzer_agent import AIPacketAnalyzerAgent
                
                try:
                    agent = AIPacketAnalyzerAgent()
                    
                    # Build context from analysis results
                    results = st.session_state.pcap_analysis_results
                    context = f"""
                    PCAP Analysis Results:
                    - Total Logs: {results['total_logs']}
                    - Log Types: {results['log_types']}
                    - Embeddings Created: {results['embeddings_created']}
                    - Anomalies Detected: {results['anomalies_detected']}
                    
                    Anomaly Details: {results.get('anomaly_details', [])}
                    """
                    
                    # Query with RAG
                    response = agent.query_with_rag(
                        f"Context: {context}\n\nQuestion: {user_question}",
                        top_k=5
                    )
                    
                    # Add AI response to history
                    st.session_state.pcap_chat_history.append({
                        "role": "assistant",
                        "content": response
                    })
                    
                    # Rerun to update chat
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Error getting response: {str(e)}")
        
        # Clear chat button
        if st.button("🗑️ Clear Chat"):
            st.session_state.pcap_chat_history = []
            st.rerun()
    
    else:
        st.info("👆 Please upload a PCAP file to start chatting!")


def analyze_pcap_with_ai(pcap_file: str):
    """Analyze PCAP file using AI Packet Analyzer."""
    from src.agents.ai_packet_analyzer_agent import AIPacketAnalyzerAgent
    
    try:
        with st.spinner("🤖 Analyzing PCAP with AI..."):
            agent = AIPacketAnalyzerAgent()
            
            # Analyze PCAP
            results = agent.analyze_pcap(pcap_file)
            
            st.success("✅ AI Analysis Complete!")
            
            # Display results
            st.markdown("---")
            st.markdown("### 📊 Analysis Summary")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Logs", results['total_logs'])
            with col2:
                st.metric("Embeddings Created", results['embeddings_created'])
            with col3:
                st.metric("Anomalies Detected", results['anomalies_detected'])
            with col4:
                stored_icon = "✅" if results['stored_in_vector_db'] else "❌"
                st.metric("Vector DB", stored_icon)
            
            # Log type breakdown
            st.markdown("### 📋 Log Types")
            
            log_types_df = pd.DataFrame([
                {'Log Type': log_type.upper(), 'Count': count}
                for log_type, count in results['log_types'].items()
                if count > 0
            ])
            
            if not log_types_df.empty:
                st.dataframe(log_types_df, use_container_width=True)
            
            # Anomalies
            if results['anomaly_details']:
                st.markdown("### 🚨 Top Anomalies")
                
                for i, anomaly in enumerate(results['anomaly_details'], 1):
                    with st.expander(f"Anomaly {i} - Score: {anomaly['anomaly_score']:.2f}"):
                        st.write(f"**Description:** {anomaly['text']}")
                        st.write(f"**Baseline Similarity:** {anomaly['baseline_similarity']:.3f}")
                        st.json(anomaly['metadata'])
            
            # Download results
            st.download_button(
                label="📥 Download Analysis Results (JSON)",
                data=json.dumps(results, indent=2, default=str),
                file_name=f"ai_analysis_{Path(pcap_file).stem}.json",
                mime="application/json",
                use_container_width=True
            )
            
    except Exception as e:
        st.error(f"Error analyzing PCAP: {str(e)}")
        st.exception(e)


def query_traffic_with_rag(query: str, top_k: int = 5):
    """Query traffic using RAG."""
    from src.agents.ai_packet_analyzer_agent import AIPacketAnalyzerAgent
    
    try:
        with st.spinner("🔍 Querying traffic with AI..."):
            agent = AIPacketAnalyzerAgent()
            
            # Query with RAG
            response = agent.query_with_rag(query, top_k=top_k)
            
            st.markdown("### 🤖 AI Response")
            st.markdown(response)
            
    except Exception as e:
        st.error(f"Error querying traffic: {str(e)}")
        st.exception(e)


def add_malicious_pattern(description: str, threat_type: str, severity: str):
    """Add malicious pattern for threat hunting."""
    from src.agents.ai_packet_analyzer_agent import AIPacketAnalyzerAgent
    
    try:
        agent = AIPacketAnalyzerAgent()
        
        agent.add_malicious_pattern(
            description=description,
            metadata={
                'threat_type': threat_type,
                'severity': severity,
                'added_at': datetime.now().isoformat()
            }
        )
        
        st.success(f"✅ Added malicious pattern: {threat_type} ({severity})")
        
    except Exception as e:
        st.error(f"Error adding pattern: {str(e)}")


def hunt_for_threats(query: str, top_k: int = 10):
    """Hunt for threats using similarity search."""
    from src.agents.ai_packet_analyzer_agent import AIPacketAnalyzerAgent
    
    try:
        with st.spinner("🎯 Hunting for threats..."):
            agent = AIPacketAnalyzerAgent()
            
            # Hunt for threats
            threats = agent.threat_hunt(query, top_k=top_k)
            
            if threats:
                st.markdown(f"### 🎯 Found {len(threats)} Potential Threats")
                
                for i, threat in enumerate(threats, 1):
                    with st.expander(f"Threat {i} - Similarity: {threat['similarity']:.3f}"):
                        st.write(f"**ID:** {threat['id']}")
                        st.write(f"**Similarity Score:** {threat['similarity']:.3f}")
                        st.json(threat['metadata'])
            else:
                st.info("No matching threats found.")
                
    except Exception as e:
        st.error(f"Error hunting threats: {str(e)}")
        st.exception(e)


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
