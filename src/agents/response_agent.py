"""Response Agent - Executes incident response actions."""

import uuid
from datetime import datetime
from typing import Dict, Any
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from src.models.schemas import IncidentResponse, ResponseAction, AgentState
from src.config.settings import settings
from src.utils.logger import log


class ResponseAgent:
    """Agent responsible for executing incident response actions."""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=settings.DEFAULT_MODEL,
            temperature=settings.TEMPERATURE,
        )
        self.parser = JsonOutputParser()
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity incident response expert.
            Based on the investigation results, determine and plan appropriate response actions.
            
            Consider:
            - Severity of the threat
            - Recommended actions from analysis
            - Containment strategies
            - Remediation steps
            - Business impact
            
            Available actions: block_ip, quarantine_host, disable_account, alert_admin, collect_evidence, monitor, no_action
            
            Respond with a JSON object containing:
            - actions_to_take: list of response actions to execute
            - action_details: dict with details for each action
            - containment_status: current containment status
            - remediation_steps: list of remediation steps
            - justification: reasoning for the chosen actions
            """),
            ("human", "Investigation Results:\n{investigation_data}\n\nAuto-response enabled: {auto_response}")
        ])
        
        self.chain = self.prompt | self.llm | self.parser
    
    def respond(self, state: AgentState) -> AgentState:
        """Execute incident response actions."""
        log.info(f"Response Agent responding to: {state.investigation.investigation_id}")
        
        try:
            # Prepare investigation data
            investigation_data = {
                "investigation_id": state.investigation.investigation_id,
                "severity": state.analysis.severity.value,
                "category": state.analysis.category.value,
                "recommended_actions": [action.value for action in state.analysis.recommended_actions],
                "root_cause": state.investigation.root_cause,
                "attack_chain": state.investigation.attack_chain,
                "affected_assets": state.analysis.affected_assets,
                "iocs": state.analysis.iocs,
            }
            
            # Run response planning
            result = self.chain.invoke({
                "investigation_data": str(investigation_data),
                "auto_response": settings.AUTO_RESPONSE_ENABLED
            })
            
            # Parse actions
            actions_to_take = [ResponseAction(action) for action in result.get("actions_to_take", [])]
            
            # Create IncidentResponse object
            response = IncidentResponse(
                response_id=str(uuid.uuid4()),
                investigation=state.investigation,
                actions_taken=actions_to_take,
                action_details=result.get("action_details", {}),
                containment_status=result.get("containment_status", "pending"),
                remediation_steps=result.get("remediation_steps", []),
                responded_at=datetime.now(),
            )
            
            state.response = response
            state.messages.append(f"Response planned: {len(actions_to_take)} actions, status: {response.containment_status}")
            
            if settings.REQUIRE_HUMAN_APPROVAL:
                state.messages.append("Human approval required before executing actions")
            
            state.current_stage = "reporting"
            log.info(f"Response planned for {state.investigation.investigation_id}")
            
        except Exception as e:
            log.error(f"Error in response agent: {str(e)}")
            state.error = f"Response error: {str(e)}"
            state.current_stage = "error"
        
        return state
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make the agent callable for LangGraph."""
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        result_state = self.respond(agent_state)
        return result_state.model_dump()
