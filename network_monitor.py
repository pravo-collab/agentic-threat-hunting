"""Standalone Network Traffic Monitor and Analyzer.

This script demonstrates the network capture and analysis capabilities
of the threat hunting system.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime

from src.models.schemas import SecurityEvent, AgentState
from src.agents.network_capture_agent import NetworkCaptureAgent
from src.agents.network_analysis_agent import NetworkAnalysisAgent
from src.utils.logger import log
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint


console = Console()


def print_header():
    """Print application header."""
    console.print(Panel.fit(
        "[bold cyan]🌐 Network Traffic Monitor & Analyzer[/bold cyan]\n"
        "[dim]Real-time network threat detection and analysis[/dim]",
        border_style="cyan"
    ))
    console.print()


def load_network_event(file_path: str) -> SecurityEvent:
    """Load a network event from JSON file."""
    with open(file_path, 'r') as f:
        event_data = json.load(f)
    return SecurityEvent(**event_data)


def display_capture_results(capture):
    """Display network capture results."""
    console.print("\n[bold green]📡 Network Capture Results[/bold green]")
    console.print(f"Capture ID: {capture.capture_id}")
    console.print(f"Interface: {capture.interface}")
    console.print(f"Duration: {(capture.end_time - capture.start_time).total_seconds():.2f}s")
    console.print(f"Total Packets: {capture.packets_captured}")
    console.print(f"Total Flows: {len(capture.flows)}")
    console.print(f"Suspicious Flows: [bold red]{len(capture.suspicious_flows)}[/bold red]")
    
    if capture.suspicious_flows:
        console.print("\n[bold yellow]⚠️  Suspicious Flows Detected:[/bold yellow]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Flow ID", style="dim")
        table.add_column("Source")
        table.add_column("Destination")
        table.add_column("Protocol")
        table.add_column("Packets")
        table.add_column("Anomaly Score", justify="right")
        
        for flow in capture.suspicious_flows[:10]:  # Show top 10
            table.add_row(
                flow.flow_id[:8] + "...",
                f"{flow.source_ip}:{flow.source_port or 'N/A'}",
                f"{flow.destination_ip}:{flow.destination_port or 'N/A'}",
                flow.protocol.value.upper(),
                str(flow.packet_count),
                f"[red]{flow.anomaly_score:.2f}[/red]"
            )
        
        console.print(table)
        
        # Show threat indicators
        console.print("\n[bold yellow]🔍 Threat Indicators:[/bold yellow]")
        for flow in capture.suspicious_flows[:5]:
            if flow.threat_indicators:
                console.print(f"\nFlow {flow.flow_id[:8]}:")
                for indicator in flow.threat_indicators:
                    console.print(f"  • {indicator}")


def display_analysis_results(state):
    """Display network analysis results."""
    console.print("\n[bold green]🔬 Network Analysis Results[/bold green]")
    
    if state.detection:
        detection = state.detection
        console.print(f"\n[bold red]⚠️  THREAT DETECTED[/bold red]")
        console.print(f"Detection ID: {detection.detection_id}")
        console.print(f"Confidence: [bold]{detection.confidence_score:.2%}[/bold]")
        console.print(f"Method: {detection.detection_method}")
        
        console.print("\n[bold yellow]Threat Indicators:[/bold yellow]")
        for indicator in detection.threat_indicators:
            console.print(f"  • {indicator}")
    else:
        console.print("[green]✅ No threats detected in network traffic[/green]")
    
    if state.messages:
        console.print("\n[bold cyan]📋 Analysis Messages:[/bold cyan]")
        for msg in state.messages:
            console.print(f"  • {msg}")


def analyze_live_traffic(duration=10, max_packets=100000):
    """Simulate live traffic capture and analysis.
    
    Args:
        duration: Capture duration in seconds (max 180 / 3 minutes)
        max_packets: Maximum number of packets to capture (max 1,000,000)
    """
    duration = min(duration, 180)  # Enforce 180 second max
    max_packets = min(max_packets, 1000000)  # Enforce 1,000,000 max
    console.print(f"[bold cyan]Starting live traffic capture for {duration} seconds (max {max_packets} packets)...[/bold cyan]\n")
    
    # Initialize agents with specified duration and packet limit
    capture_agent = NetworkCaptureAgent(capture_duration=duration, max_packets=max_packets)
    analysis_agent = NetworkAnalysisAgent()
    
    # Create initial state (no event = live capture)
    initial_state = AgentState(current_stage="network_capture")
    
    # Capture traffic
    console.print(f"🔍 Capturing network traffic for {duration} seconds (max {max_packets} packets)...")
    state = capture_agent.capture(initial_state, duration=duration, max_packets=max_packets)
    
    if state.network_capture:
        display_capture_results(state.network_capture)
        
        # Analyze captured traffic
        console.print("\n🧠 Analyzing captured traffic...")
        state = analysis_agent.analyze(state)
        
        display_analysis_results(state)
    else:
        console.print("[red]❌ Failed to capture network traffic[/red]")


def analyze_event_file(file_path: str):
    """Analyze network traffic from event file."""
    console.print(f"[bold cyan]Loading network event from: {file_path}[/bold cyan]\n")
    
    try:
        # Load event
        event = load_network_event(file_path)
        console.print(f"Event ID: {event.event_id}")
        console.print(f"Type: {event.event_type}")
        console.print(f"Source: {event.source_ip} → {event.destination_ip}")
        
        # Initialize agents
        capture_agent = NetworkCaptureAgent()
        analysis_agent = NetworkAnalysisAgent()
        
        # Create initial state with event
        initial_state = AgentState(
            security_event=event,
            current_stage="network_capture"
        )
        
        # Capture and convert event to flows
        console.print("\n🔍 Converting event to network flows...")
        state = capture_agent.capture(initial_state)
        
        if state.network_capture:
            display_capture_results(state.network_capture)
            
            # Analyze
            console.print("\n🧠 Analyzing network traffic...")
            state = analysis_agent.analyze(state)
            
            display_analysis_results(state)
        else:
            console.print("[red]❌ Failed to process network event[/red]")
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        log.error(f"Error analyzing event: {str(e)}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Network Traffic Monitor and Analyzer"
    )
    parser.add_argument(
        "--input",
        type=str,
        help="Path to network event JSON file"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Simulate live traffic capture"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=10,
        help="Capture duration in seconds (max 180 / 3 minutes, default 10)"
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=100000,
        help="Maximum number of packets to capture (max 1,000,000, default 100,000)"
    )
    
    args = parser.parse_args()
    
    print_header()
    
    if args.input:
        analyze_event_file(args.input)
    elif args.live:
        analyze_live_traffic(duration=args.duration, max_packets=args.max_packets)
    else:
        console.print("[yellow]Please specify --input <file> or --live[/yellow]")
        console.print("\nExamples:")
        console.print("  python network_monitor.py --input data/network_traffic_event.json")
        console.print("  python network_monitor.py --live")
        console.print("  python network_monitor.py --live --duration 30")
        console.print("  python network_monitor.py --live --duration 180  # Max 3 minutes")
        console.print("  python network_monitor.py --live --duration 60 --max-packets 500000")
        console.print("  python network_monitor.py --live --duration 180 --max-packets 1000000  # Max limits")


if __name__ == "__main__":
    main()
