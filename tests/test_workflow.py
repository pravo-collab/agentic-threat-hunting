"""Tests for the LangGraph workflow."""

import pytest
import uuid
from datetime import datetime

from src.models.schemas import SecurityEvent, AgentState
from src.graph.workflow import ThreatHuntingWorkflow


@pytest.fixture
def sample_security_event():
    """Create a sample security event for testing."""
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(),
        source="test_source",
        event_type="suspicious_activity",
        raw_data={
            "test": "data",
            "suspicious_indicators": ["unusual_port", "unknown_destination"]
        },
        source_ip="192.168.1.100",
        destination_ip="185.220.101.50",
        user="admin",
        process="powershell.exe",
    )


@pytest.fixture
def initial_state(sample_security_event):
    """Create initial state for workflow testing."""
    return AgentState(
        security_event=sample_security_event,
        current_stage="detection"
    )


class TestThreatHuntingWorkflow:
    """Tests for ThreatHuntingWorkflow."""
    
    def test_workflow_initialization(self):
        """Test that workflow initializes correctly."""
        workflow = ThreatHuntingWorkflow()
        assert workflow is not None
        assert workflow.detection_agent is not None
        assert workflow.analysis_agent is not None
        assert workflow.investigation_agent is not None
        assert workflow.response_agent is not None
        assert workflow.reporting_agent is not None
        assert workflow.graph is not None
    
    @pytest.mark.skip(reason="Requires API key and takes time")
    def test_workflow_run(self, initial_state):
        """Test running the complete workflow."""
        workflow = ThreatHuntingWorkflow()
        result = workflow.run(initial_state)
        assert result is not None
        assert isinstance(result, AgentState)
