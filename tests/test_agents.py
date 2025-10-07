"""Tests for individual agents."""

import pytest
import uuid
from datetime import datetime

from src.models.schemas import SecurityEvent, AgentState, ThreatDetection
from src.agents import (
    DetectionAgent,
    AnalysisAgent,
    InvestigationAgent,
    ResponseAgent,
    ReportingAgent,
)


@pytest.fixture
def sample_security_event():
    """Create a sample security event for testing."""
    return SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(),
        source="test_source",
        event_type="test_event",
        raw_data={"test": "data"},
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        user="test_user",
        process="test.exe",
    )


@pytest.fixture
def sample_state(sample_security_event):
    """Create a sample agent state for testing."""
    return AgentState(
        security_event=sample_security_event,
        current_stage="detection"
    )


class TestDetectionAgent:
    """Tests for DetectionAgent."""
    
    def test_detection_agent_initialization(self):
        """Test that DetectionAgent initializes correctly."""
        agent = DetectionAgent()
        assert agent is not None
        assert agent.llm is not None
        assert agent.prompt is not None
    
    @pytest.mark.skip(reason="Requires API key")
    def test_detection_agent_detect(self, sample_state):
        """Test detection agent's detect method."""
        agent = DetectionAgent()
        result = agent.detect(sample_state)
        assert result is not None
        assert isinstance(result, AgentState)


class TestAnalysisAgent:
    """Tests for AnalysisAgent."""
    
    def test_analysis_agent_initialization(self):
        """Test that AnalysisAgent initializes correctly."""
        agent = AnalysisAgent()
        assert agent is not None
        assert agent.llm is not None
        assert agent.prompt is not None


class TestInvestigationAgent:
    """Tests for InvestigationAgent."""
    
    def test_investigation_agent_initialization(self):
        """Test that InvestigationAgent initializes correctly."""
        agent = InvestigationAgent()
        assert agent is not None
        assert agent.llm is not None
        assert agent.prompt is not None


class TestResponseAgent:
    """Tests for ResponseAgent."""
    
    def test_response_agent_initialization(self):
        """Test that ResponseAgent initializes correctly."""
        agent = ResponseAgent()
        assert agent is not None
        assert agent.llm is not None
        assert agent.prompt is not None


class TestReportingAgent:
    """Tests for ReportingAgent."""
    
    def test_reporting_agent_initialization(self):
        """Test that ReportingAgent initializes correctly."""
        agent = ReportingAgent()
        assert agent is not None
        assert agent.llm is not None
        assert agent.prompt is not None
