"""Detection Agent - Monitors and identifies potential security threats."""

import uuid
from datetime import datetime
from typing import Dict, Any
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from src.models.schemas import SecurityEvent, ThreatDetection, AgentState
from src.config.settings import settings
from src.utils.logger import log


class DetectionAgent:
    """Agent responsible for detecting potential security threats."""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=settings.DEFAULT_MODEL,
            temperature=settings.TEMPERATURE,
        )
        self.parser = JsonOutputParser()
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity threat detection expert. 
            Analyze the provided security event and determine if it represents a potential threat.
            
            Consider the following indicators:
            - Unusual network activity
            - Suspicious process execution
            - Unauthorized access attempts
            - Anomalous user behavior
            - Known malicious patterns
            
            Respond with a JSON object containing:
            - is_threat: boolean indicating if this is a threat
            - threat_indicators: list of specific indicators found
            - confidence_score: float between 0 and 1
            - detection_method: string describing the detection method used
            - reasoning: brief explanation of your analysis
            """),
            ("human", "Security Event:\n{event_data}")
        ])
        
        self.chain = self.prompt | self.llm | self.parser
    
    def detect(self, state: AgentState) -> AgentState:
        """Analyze security event and detect potential threats."""
        log.info(f"Detection Agent analyzing event: {state.security_event.event_id}")
        
        try:
            # Prepare event data for analysis
            event_data = {
                "event_id": state.security_event.event_id,
                "timestamp": state.security_event.timestamp.isoformat(),
                "source": state.security_event.source,
                "event_type": state.security_event.event_type,
                "source_ip": state.security_event.source_ip,
                "destination_ip": state.security_event.destination_ip,
                "user": state.security_event.user,
                "process": state.security_event.process,
                "raw_data": state.security_event.raw_data,
            }
            
            # Run detection analysis
            result = self.chain.invoke({"event_data": str(event_data)})
            
            # If threat detected, create ThreatDetection object
            if result.get("is_threat", False):
                detection = ThreatDetection(
                    detection_id=str(uuid.uuid4()),
                    event=state.security_event,
                    threat_indicators=result.get("threat_indicators", []),
                    confidence_score=result.get("confidence_score", 0.5),
                    detected_at=datetime.now(),
                    detection_method=result.get("detection_method", "AI-based analysis"),
                )
                
                state.detection = detection
                state.messages.append(f"Threat detected: {result.get('reasoning', '')}")
                state.current_stage = "analysis"
                log.warning(f"Threat detected in event {state.security_event.event_id}")
            else:
                state.messages.append(f"No threat detected: {result.get('reasoning', '')}")
                state.current_stage = "completed"
                log.info(f"No threat detected in event {state.security_event.event_id}")
            
        except Exception as e:
            log.error(f"Error in detection agent: {str(e)}")
            state.error = f"Detection error: {str(e)}"
            state.current_stage = "error"
        
        return state
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make the agent callable for LangGraph."""
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        result_state = self.detect(agent_state)
        return result_state.model_dump()
