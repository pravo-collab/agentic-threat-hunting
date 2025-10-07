"""Main entry point for the Threat Hunting and Incident Response System."""

import argparse
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from src.models.schemas import SecurityEvent, AgentState
from src.graph.workflow import ThreatHuntingWorkflow
from src.config.settings import settings
from src.utils.logger import log


console = Console()


def load_security_event(file_path: Optional[str] = None) -> SecurityEvent:
    """Load a security event from file or create a sample event."""
    if file_path:
        log.info(f"Loading security event from: {file_path}")
        with open(file_path, 'r') as f:
            data = json.load(f)
            return SecurityEvent(**data)
    else:
        # Create a sample security event for demonstration
        log.info("Creating sample security event")
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            source="firewall_logs",
            event_type="suspicious_connection",
            raw_data={
                "protocol": "TCP",
                "port": 4444,
                "bytes_transferred": 1048576,
                "duration": 300,
                "flags": ["SYN", "ACK"],
            },
            source_ip="192.168.1.100",
            destination_ip="185.220.101.50",
            user="admin",
            process="powershell.exe",
        )


def display_results(final_state: AgentState):
    """Display the results in a formatted way."""
    console.print("\n")
    console.rule("[bold blue]Threat Hunting Results[/bold blue]")
    console.print("\n")
    
    # Display messages
    if final_state.messages:
        console.print(Panel.fit(
            "\n".join(final_state.messages),
            title="[bold green]Workflow Messages[/bold green]",
            border_style="green"
        ))
        console.print("\n")
    
    # Display error if any
    if final_state.error:
        console.print(Panel.fit(
            final_state.error,
            title="[bold red]Error[/bold red]",
            border_style="red"
        ))
        return
    
    # Display detection results
    if final_state.detection:
        detection_table = Table(title="Detection Results", show_header=True)
        detection_table.add_column("Field", style="cyan")
        detection_table.add_column("Value", style="yellow")
        
        detection_table.add_row("Detection ID", final_state.detection.detection_id)
        detection_table.add_row("Confidence Score", f"{final_state.detection.confidence_score:.2f}")
        detection_table.add_row("Method", final_state.detection.detection_method)
        detection_table.add_row("Indicators", ", ".join(final_state.detection.threat_indicators))
        
        console.print(detection_table)
        console.print("\n")
    
    # Display analysis results
    if final_state.analysis:
        analysis_table = Table(title="Threat Analysis", show_header=True)
        analysis_table.add_column("Field", style="cyan")
        analysis_table.add_column("Value", style="yellow")
        
        analysis_table.add_row("Severity", f"[bold red]{final_state.analysis.severity.value.upper()}[/bold red]")
        analysis_table.add_row("Category", final_state.analysis.category.value)
        analysis_table.add_row("Attack Vector", final_state.analysis.attack_vector or "N/A")
        analysis_table.add_row("Affected Assets", ", ".join(final_state.analysis.affected_assets))
        analysis_table.add_row("IOCs", ", ".join(final_state.analysis.iocs))
        
        console.print(analysis_table)
        console.print("\n")
        
        console.print(Panel.fit(
            final_state.analysis.analysis_summary,
            title="[bold]Analysis Summary[/bold]",
            border_style="blue"
        ))
        console.print("\n")
    
    # Display investigation results
    if final_state.investigation:
        console.print(Panel.fit(
            final_state.investigation.root_cause or "N/A",
            title="[bold]Root Cause[/bold]",
            border_style="magenta"
        ))
        console.print("\n")
        
        if final_state.investigation.attack_chain:
            console.print("[bold]Attack Chain:[/bold]")
            for i, step in enumerate(final_state.investigation.attack_chain, 1):
                console.print(f"  {i}. {step}")
            console.print("\n")
    
    # Display response results
    if final_state.response:
        response_table = Table(title="Incident Response", show_header=True)
        response_table.add_column("Field", style="cyan")
        response_table.add_column("Value", style="yellow")
        
        response_table.add_row("Actions Planned", ", ".join([a.value for a in final_state.response.actions_taken]))
        response_table.add_row("Containment Status", final_state.response.containment_status)
        
        console.print(response_table)
        console.print("\n")
    
    # Display report
    if final_state.report:
        console.print(Panel.fit(
            final_state.report.executive_summary,
            title="[bold green]Executive Summary[/bold green]",
            border_style="green"
        ))
        console.print("\n")
        
        if final_state.report.recommendations:
            console.print("[bold]Recommendations:[/bold]")
            for i, rec in enumerate(final_state.report.recommendations, 1):
                console.print(f"  {i}. {rec}")
            console.print("\n")
    
    console.rule("[bold blue]End of Report[/bold blue]")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Threat Hunting and Incident Response System")
    parser.add_argument(
        "--input",
        "-i",
        type=str,
        help="Path to input security event JSON file"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Path to save the output report"
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode"
    )
    
    args = parser.parse_args()
    
    try:
        # Validate settings
        settings.validate()
        
        # Display banner
        console.print("\n")
        console.print(Panel.fit(
            "[bold cyan]Agentic MultiStage Threat Hunting\nand Incident Response System[/bold cyan]\n"
            "[dim]Powered by LangGraph[/dim]",
            border_style="cyan"
        ))
        console.print("\n")
        
        # Load security event
        security_event = load_security_event(args.input)
        
        console.print(f"[bold]Processing Security Event:[/bold] {security_event.event_id}")
        console.print(f"[bold]Source:[/bold] {security_event.source}")
        console.print(f"[bold]Type:[/bold] {security_event.event_type}")
        console.print("\n")
        
        # Create initial state
        initial_state = AgentState(
            security_event=security_event,
            current_stage="detection"
        )
        
        # Initialize and run workflow
        with console.status("[bold green]Running threat hunting workflow...", spinner="dots"):
            workflow = ThreatHuntingWorkflow()
            final_state = workflow.run(initial_state)
        
        # Display results
        display_results(final_state)
        
        # Save output if requested
        if args.output and final_state.report:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(final_state.report.model_dump(), f, indent=2, default=str)
            
            console.print(f"\n[bold green]Report saved to:[/bold green] {output_path}")
        
    except Exception as e:
        log.error(f"Error in main: {str(e)}")
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        raise


if __name__ == "__main__":
    main()
