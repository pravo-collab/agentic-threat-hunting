"""LangGraph workflow for orchestrating threat hunting agents."""

from typing import Dict, Any, Literal
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from src.models.schemas import AgentState
from src.agents import (
    DetectionAgent,
    AnalysisAgent,
    InvestigationAgent,
    ResponseAgent,
    ReportingAgent,
)
from src.utils.logger import log


def should_continue_after_detection(state: Dict[str, Any]) -> Literal["deep_dive_agent", "completed", "error"]:
    """Determine next step after detection."""
    # Handle both dict and AgentState objects
    error = state.get("error") if isinstance(state, dict) else getattr(state, "error", None)
    detection = state.get("detection") if isinstance(state, dict) else getattr(state, "detection", None)
    
    if error:
        return "error"
    if detection:
        return "deep_dive_agent"
    return "completed"


def should_continue_after_analysis(state: Dict[str, Any]) -> Literal["investigation_agent", "error"]:
    """Determine next step after analysis."""
    error = state.get("error") if isinstance(state, dict) else getattr(state, "error", None)
    if error:
        return "error"
    return "investigation_agent"


def should_continue_after_investigation(state: Dict[str, Any]) -> Literal["response_agent", "error"]:
    """Determine next step after investigation."""
    error = state.get("error") if isinstance(state, dict) else getattr(state, "error", None)
    if error:
        return "error"
    return "response_agent"


def should_continue_after_response(state: Dict[str, Any]) -> Literal["reporting_agent", "error"]:
    """Determine next step after response."""
    error = state.get("error") if isinstance(state, dict) else getattr(state, "error", None)
    if error:
        return "error"
    return "reporting_agent"


def should_continue_after_reporting(state: Dict[str, Any]) -> Literal["completed", "error"]:
    """Determine next step after reporting."""
    error = state.get("error") if isinstance(state, dict) else getattr(state, "error", None)
    if error:
        return "error"
    return "completed"


class ThreatHuntingWorkflow:
    """LangGraph workflow for threat hunting and incident response."""
    
    def __init__(self):
        """Initialize the workflow with agents."""
        log.info("Initializing Threat Hunting Workflow")
        
        # Initialize agents
        self.detection_agent = DetectionAgent()
        self.analysis_agent = AnalysisAgent()
        self.investigation_agent = InvestigationAgent()
        self.response_agent = ResponseAgent()
        self.reporting_agent = ReportingAgent()
        
        # Build the graph
        self.graph = self._build_graph()
        
        log.info("Workflow initialized successfully")
    
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow."""
        # Create the graph
        workflow = StateGraph(AgentState)
        
        # Add nodes for each agent
        workflow.add_node("detection_agent", self.detection_agent)
        workflow.add_node("deep_dive_agent", self.analysis_agent)
        workflow.add_node("investigation_agent", self.investigation_agent)
        workflow.add_node("response_agent", self.response_agent)
        workflow.add_node("reporting_agent", self.reporting_agent)
        
        # Set entry point
        workflow.set_entry_point("detection_agent")
        
        # Add conditional edges
        workflow.add_conditional_edges(
            "detection_agent",
            should_continue_after_detection,
            {
                "deep_dive_agent": "deep_dive_agent",
                "completed": END,
                "error": END,
            }
        )
        
        workflow.add_conditional_edges(
            "deep_dive_agent",
            should_continue_after_analysis,
            {
                "investigation_agent": "investigation_agent",
                "error": END,
            }
        )
        
        workflow.add_conditional_edges(
            "investigation_agent",
            should_continue_after_investigation,
            {
                "response_agent": "response_agent",
                "error": END,
            }
        )
        
        workflow.add_conditional_edges(
            "response_agent",
            should_continue_after_response,
            {
                "reporting_agent": "reporting_agent",
                "error": END,
            }
        )
        
        workflow.add_conditional_edges(
            "reporting_agent",
            should_continue_after_reporting,
            {
                "completed": END,
                "error": END,
            }
        )
        
        # Compile the graph
        memory = MemorySaver()
        compiled_graph = workflow.compile(checkpointer=memory)
        
        return compiled_graph
    
    def run(self, initial_state: AgentState) -> AgentState:
        """Run the workflow with an initial state."""
        log.info(f"Starting workflow for event: {initial_state.security_event.event_id}")
        
        try:
            # Convert to dict for LangGraph
            state_dict = initial_state.model_dump()
            
            # Run the workflow
            config = {"configurable": {"thread_id": initial_state.security_event.event_id}}
            result = self.graph.invoke(state_dict, config)
            
            # Convert back to AgentState
            # Result is already a dict, so we can pass it directly
            if isinstance(result, dict):
                final_state = AgentState.model_validate(result)
            else:
                final_state = result
            
            log.info(f"Workflow completed: {final_state.current_stage}")
            return final_state
            
        except Exception as e:
            log.error(f"Error running workflow: {str(e)}")
            initial_state.error = str(e)
            initial_state.current_stage = "error"
            return initial_state
    
    async def arun(self, initial_state: AgentState) -> AgentState:
        """Run the workflow asynchronously."""
        log.info(f"Starting async workflow for event: {initial_state.security_event.event_id}")
        
        try:
            # Convert to dict for LangGraph
            state_dict = initial_state.model_dump()
            
            # Run the workflow asynchronously
            config = {"configurable": {"thread_id": initial_state.security_event.event_id}}
            result = await self.graph.ainvoke(state_dict, config)
            
            # Convert back to AgentState
            # Result is already a dict, so we can pass it directly
            if isinstance(result, dict):
                final_state = AgentState.model_validate(result)
            else:
                final_state = result
            
            log.info(f"Async workflow completed: {final_state.current_stage}")
            return final_state
            
        except Exception as e:
            log.error(f"Error running async workflow: {str(e)}")
            initial_state.error = str(e)
            initial_state.current_stage = "error"
            return initial_state
