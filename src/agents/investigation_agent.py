"""Investigation Agent - Performs deep forensic analysis."""

import uuid
from datetime import datetime
from typing import Dict, Any
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from src.models.schemas import Investigation, AgentState
from src.config.settings import settings
from src.utils.logger import log


class InvestigationAgent:
    """Agent responsible for forensic investigation of threats."""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=settings.DEFAULT_MODEL,
            temperature=settings.TEMPERATURE,
        )
        self.parser = JsonOutputParser()
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity forensic investigator.
            Conduct a thorough investigation of the analyzed threat.
            
            Your investigation should include:
            - Timeline of events leading to and during the incident
            - Evidence collection points
            - Root cause analysis
            - Attack chain reconstruction
            - Detailed investigation notes
            
            Respond with a JSON object containing:
            - timeline: list of events with timestamps and descriptions
            - evidence_collected: list of evidence items to collect
            - root_cause: string describing the root cause
            - attack_chain: list of steps in the attack chain
            - investigation_notes: detailed notes from the investigation
            """),
            ("human", "Threat Analysis:\n{analysis_data}")
        ])
        
        self.chain = self.prompt | self.llm | self.parser
    
    def investigate(self, state: AgentState) -> AgentState:
        """Perform forensic investigation."""
        log.info(f"Investigation Agent investigating: {state.analysis.analysis_id}")
        
        try:
            # Prepare analysis data for investigation
            analysis_data = {
                "analysis_id": state.analysis.analysis_id,
                "severity": state.analysis.severity.value,
                "category": state.analysis.category.value,
                "attack_vector": state.analysis.attack_vector,
                "affected_assets": state.analysis.affected_assets,
                "iocs": state.analysis.iocs,
                "analysis_summary": state.analysis.analysis_summary,
                "threat_indicators": state.detection.threat_indicators,
                "event_details": {
                    "timestamp": state.detection.event.timestamp.isoformat(),
                    "source": state.detection.event.source,
                    "source_ip": state.detection.event.source_ip,
                    "destination_ip": state.detection.event.destination_ip,
                    "user": state.detection.event.user,
                    "process": state.detection.event.process,
                }
            }
            
            # Run investigation
            result = self.chain.invoke({"analysis_data": str(analysis_data)})
            
            # Create Investigation object
            investigation = Investigation(
                investigation_id=str(uuid.uuid4()),
                analysis=state.analysis,
                timeline=result.get("timeline", []),
                evidence_collected=result.get("evidence_collected", []),
                root_cause=result.get("root_cause"),
                attack_chain=result.get("attack_chain", []),
                investigation_notes=result.get("investigation_notes", ""),
                investigated_at=datetime.now(),
            )
            
            state.investigation = investigation
            state.messages.append(f"Investigation completed: {len(investigation.attack_chain)} steps in attack chain")
            state.current_stage = "response"
            log.info(f"Investigation completed for {state.analysis.analysis_id}")
            
        except Exception as e:
            log.error(f"Error in investigation agent: {str(e)}")
            state.error = f"Investigation error: {str(e)}"
            state.current_stage = "error"
        
        return state
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make the agent callable for LangGraph."""
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        result_state = self.investigate(agent_state)
        return result_state.model_dump()
