"""Reporting Agent - Generates comprehensive incident reports."""

import uuid
from datetime import datetime
from typing import Dict, Any
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from src.models.schemas import IncidentReport, AgentState
from src.config.settings import settings
from src.utils.logger import log


class ReportingAgent:
    """Agent responsible for generating incident reports."""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=settings.DEFAULT_MODEL,
            temperature=settings.TEMPERATURE,
        )
        self.parser = JsonOutputParser()
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity incident reporting expert.
            Generate a comprehensive incident report based on the complete investigation and response.
            
            The report should include:
            - Executive summary for leadership
            - Technical details for security team
            - Lessons learned
            - Recommendations for future prevention
            
            Respond with a JSON object containing:
            - executive_summary: high-level summary for executives
            - technical_details: detailed technical analysis
            - lessons_learned: list of lessons learned
            - recommendations: list of recommendations
            """),
            ("human", "Incident Response Data:\n{response_data}")
        ])
        
        self.chain = self.prompt | self.llm | self.parser
    
    def generate_report(self, state: AgentState) -> AgentState:
        """Generate comprehensive incident report."""
        log.info(f"Reporting Agent generating report for: {state.response.response_id}")
        
        try:
            # Prepare complete incident data
            response_data = {
                "response_id": state.response.response_id,
                "severity": state.analysis.severity.value,
                "category": state.analysis.category.value,
                "detection": {
                    "detection_id": state.detection.detection_id,
                    "confidence_score": state.detection.confidence_score,
                    "threat_indicators": state.detection.threat_indicators,
                },
                "analysis": {
                    "attack_vector": state.analysis.attack_vector,
                    "affected_assets": state.analysis.affected_assets,
                    "iocs": state.analysis.iocs,
                    "summary": state.analysis.analysis_summary,
                },
                "investigation": {
                    "root_cause": state.investigation.root_cause,
                    "attack_chain": state.investigation.attack_chain,
                    "evidence_collected": state.investigation.evidence_collected,
                },
                "response": {
                    "actions_taken": [action.value for action in state.response.actions_taken],
                    "containment_status": state.response.containment_status,
                    "remediation_steps": state.response.remediation_steps,
                },
            }
            
            # Generate report
            result = self.chain.invoke({"response_data": str(response_data)})
            
            # Ensure technical_details is a string
            technical_details = result.get("technical_details", "")
            if isinstance(technical_details, dict):
                import json
                technical_details = json.dumps(technical_details, indent=2)
            elif not isinstance(technical_details, str):
                technical_details = str(technical_details)
            
            # Create IncidentReport object
            report = IncidentReport(
                report_id=str(uuid.uuid4()),
                response=state.response,
                executive_summary=result.get("executive_summary", ""),
                technical_details=technical_details,
                lessons_learned=result.get("lessons_learned", []),
                recommendations=result.get("recommendations", []),
                report_generated_at=datetime.now(),
            )
            
            state.report = report
            state.messages.append(f"Incident report generated: {report.report_id}")
            state.current_stage = "completed"
            log.info(f"Report generated: {report.report_id}")
            
        except Exception as e:
            log.error(f"Error in reporting agent: {str(e)}")
            state.error = f"Reporting error: {str(e)}"
            state.current_stage = "error"
        
        return state
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make the agent callable for LangGraph."""
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        result_state = self.generate_report(agent_state)
        return result_state.model_dump()
