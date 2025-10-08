"""Network Analysis Agent for analyzing captured network traffic."""

import uuid
from datetime import datetime
from typing import Dict, Any
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate

from src.models.schemas import AgentState, ThreatDetection, SecurityEvent
from src.config.settings import settings
from src.utils.logger import log


class NetworkAnalysisAgent:
    """Agent responsible for analyzing network traffic patterns."""
    
    def __init__(self):
        """Initialize the Network Analysis Agent."""
        self.llm = ChatOpenAI(
            model=settings.DEFAULT_MODEL,
            temperature=settings.TEMPERATURE,
        )
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an expert network security analyst specializing in traffic analysis and threat detection.
            
Your task is to analyze network flows and identify potential security threats based on:
1. Traffic patterns and anomalies
2. Protocol usage and port numbers
3. Source and destination IPs
4. Packet sizes and frequencies
5. Known threat indicators

Provide a detailed analysis including:
- Whether the traffic is malicious
- Confidence score (0.0 to 1.0)
- Specific threat indicators found
- Type of attack or threat
- Recommended actions"""),
            ("human", """Analyze the following network capture:

Capture ID: {capture_id}
Total Flows: {total_flows}
Suspicious Flows: {suspicious_flows}
Total Packets: {total_packets}

Suspicious Flow Details:
{flow_details}

Provide your analysis in JSON format with these fields:
- is_threat: boolean
- confidence_score: float (0.0-1.0)
- threat_indicators: list of strings
- threat_type: string
- reasoning: string
- detection_method: string""")
        ])
        
        self.chain = self.prompt | self.llm
        log.info("Network Analysis Agent initialized")
    
    def analyze(self, state: AgentState) -> AgentState:
        """Analyze captured network traffic for threats."""
        log.info("Network Analysis Agent: Analyzing network traffic")
        
        try:
            if not state.network_capture:
                state.messages.append("No network capture data available for analysis")
                state.current_stage = "detection"
                return state
            
            capture = state.network_capture
            
            # Prepare flow details for analysis
            flow_details = self._prepare_flow_details(capture)
            
            # Analyze with LLM
            result = self.chain.invoke({
                "capture_id": capture.capture_id,
                "total_flows": len(capture.flows),
                "suspicious_flows": len(capture.suspicious_flows),
                "total_packets": capture.packets_captured,
                "flow_details": flow_details
            })
            
            # Parse LLM response
            import json
            try:
                analysis = json.loads(result.content)
            except json.JSONDecodeError:
                # Fallback parsing
                analysis = self._parse_llm_response(result.content)
            
            # If threat detected, create security event and detection
            if analysis.get("is_threat", False):
                # Create a security event from network capture
                security_event = self._create_security_event_from_capture(capture)
                state.security_event = security_event
                
                # Create threat detection
                detection = ThreatDetection(
                    detection_id=str(uuid.uuid4()),
                    event=security_event,
                    threat_indicators=analysis.get("threat_indicators", []),
                    confidence_score=analysis.get("confidence_score", 0.5),
                    detected_at=datetime.now(),
                    detection_method=analysis.get("detection_method", "Network traffic analysis")
                )
                
                state.detection = detection
                state.messages.append(
                    f"Network threat detected: {analysis.get('threat_type', 'Unknown')} "
                    f"(confidence: {analysis.get('confidence_score', 0):.2%})"
                )
                state.current_stage = "analysis"
                
                log.warning(f"Network threat detected: {analysis.get('threat_type')}")
            else:
                state.messages.append("Network traffic analysis: No threats detected")
                state.current_stage = "completed"
                log.info("No threats detected in network traffic")
            
        except Exception as e:
            log.error(f"Error in network analysis: {str(e)}")
            state.error = f"Network analysis error: {str(e)}"
            state.current_stage = "error"
        
        return state
    
    def _prepare_flow_details(self, capture) -> str:
        """Prepare detailed flow information for analysis."""
        details = []
        
        for i, flow in enumerate(capture.suspicious_flows[:5], 1):  # Limit to top 5
            detail = f"""
Flow {i}:
  - Source: {flow.source_ip}:{flow.source_port or 'N/A'}
  - Destination: {flow.destination_ip}:{flow.destination_port or 'N/A'}
  - Protocol: {flow.protocol.value}
  - Packets: {flow.packet_count}
  - Bytes: {flow.byte_count}
  - Anomaly Score: {flow.anomaly_score:.2f}
  - Indicators: {', '.join(flow.threat_indicators) if flow.threat_indicators else 'None'}
"""
            details.append(detail)
        
        if not details:
            return "No suspicious flows detected"
        
        return "\n".join(details)
    
    def _create_security_event_from_capture(self, capture) -> SecurityEvent:
        """Create a security event from network capture."""
        # Get the most suspicious flow
        suspicious_flow = max(
            capture.suspicious_flows,
            key=lambda f: f.anomaly_score
        ) if capture.suspicious_flows else capture.flows[0]
        
        event = SecurityEvent(
            event_id=f"net_{capture.capture_id[:8]}",
            timestamp=suspicious_flow.start_time,
            source="network_capture",
            event_type="suspicious_network_traffic",
            raw_data={
                "capture_id": capture.capture_id,
                "flow_id": suspicious_flow.flow_id,
                "protocol": suspicious_flow.protocol.value,
                "packet_count": suspicious_flow.packet_count,
                "byte_count": suspicious_flow.byte_count,
                "anomaly_score": suspicious_flow.anomaly_score,
                "threat_indicators": suspicious_flow.threat_indicators
            },
            source_ip=suspicious_flow.source_ip,
            destination_ip=suspicious_flow.destination_ip,
            process="network_monitor"
        )
        
        return event
    
    def _parse_llm_response(self, content: str) -> dict:
        """Fallback parser for LLM response."""
        # Simple fallback parsing
        return {
            "is_threat": "threat" in content.lower() or "malicious" in content.lower(),
            "confidence_score": 0.7,
            "threat_indicators": ["Suspicious network pattern detected"],
            "threat_type": "Network anomaly",
            "reasoning": content,
            "detection_method": "AI-based network analysis"
        }
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make the agent callable for LangGraph."""
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        result_state = self.analyze(agent_state)
        return result_state.model_dump()
