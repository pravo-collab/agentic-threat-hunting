"""Analysis Agent - Analyzes detected threats and determines severity."""

import uuid
from datetime import datetime
from typing import Dict, Any
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from src.models.schemas import ThreatAnalysis, SeverityLevel, ThreatCategory, ResponseAction, AgentState
from src.config.settings import settings
from src.utils.logger import log


class AnalysisAgent:
    """Agent responsible for analyzing detected threats."""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=settings.DEFAULT_MODEL,
            temperature=settings.TEMPERATURE,
        )
        self.parser = JsonOutputParser()
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity threat analysis expert.
            Analyze the detected threat and provide detailed assessment.
            
            Determine:
            - Severity level: critical, high, medium, low, or info
            - Threat category: malware, phishing, intrusion, data_exfiltration, privilege_escalation, lateral_movement, persistence, reconnaissance, or unknown
            - Attack vector
            - Affected assets
            - Indicators of Compromise (IOCs)
            - Recommended response actions
            
            Available response actions: block_ip, quarantine_host, disable_account, alert_admin, collect_evidence, monitor, no_action
            
            Respond with a JSON object containing:
            - severity: one of the severity levels
            - category: one of the threat categories
            - attack_vector: string describing the attack vector
            - affected_assets: list of affected systems/assets
            - iocs: list of indicators of compromise
            - analysis_summary: detailed summary of the threat
            - recommended_actions: list of recommended response actions
            """),
            ("human", "Threat Detection:\n{detection_data}")
        ])
        
        self.chain = self.prompt | self.llm | self.parser
    
    def analyze(self, state: AgentState) -> AgentState:
        """Analyze the detected threat."""
        log.info(f"Analysis Agent analyzing detection: {state.detection.detection_id}")
        
        try:
            # Prepare detection data for analysis
            detection_data = {
                "detection_id": state.detection.detection_id,
                "event_id": state.detection.event.event_id,
                "threat_indicators": state.detection.threat_indicators,
                "confidence_score": state.detection.confidence_score,
                "detection_method": state.detection.detection_method,
                "event_details": {
                    "source": state.detection.event.source,
                    "event_type": state.detection.event.event_type,
                    "source_ip": state.detection.event.source_ip,
                    "destination_ip": state.detection.event.destination_ip,
                    "user": state.detection.event.user,
                    "process": state.detection.event.process,
                }
            }
            
            # Run analysis
            result = self.chain.invoke({"detection_data": str(detection_data)})
            
            # Create ThreatAnalysis object
            analysis = ThreatAnalysis(
                analysis_id=str(uuid.uuid4()),
                detection=state.detection,
                severity=SeverityLevel(result.get("severity", "medium")),
                category=ThreatCategory(result.get("category", "unknown")),
                attack_vector=result.get("attack_vector"),
                affected_assets=result.get("affected_assets", []),
                iocs=result.get("iocs", []),
                analysis_summary=result.get("analysis_summary", ""),
                recommended_actions=[ResponseAction(action) for action in result.get("recommended_actions", [])],
                analyzed_at=datetime.now(),
            )
            
            state.analysis = analysis
            state.messages.append(f"Threat analyzed: {analysis.severity.value} severity, {analysis.category.value} category")
            state.current_stage = "investigation"
            log.info(f"Analysis completed: {analysis.severity.value} severity threat")
            
        except Exception as e:
            log.error(f"Error in analysis agent: {str(e)}")
            state.error = f"Analysis error: {str(e)}"
            state.current_stage = "error"
        
        return state
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make the agent callable for LangGraph."""
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        result_state = self.analyze(agent_state)
        return result_state.model_dump()
