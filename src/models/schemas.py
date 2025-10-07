"""Data models and schemas for the threat hunting system."""

from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(str, Enum):
    """Categories of security threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    RECONNAISSANCE = "reconnaissance"
    UNKNOWN = "unknown"


class ResponseAction(str, Enum):
    """Available response actions."""
    BLOCK_IP = "block_ip"
    QUARANTINE_HOST = "quarantine_host"
    DISABLE_ACCOUNT = "disable_account"
    ALERT_ADMIN = "alert_admin"
    COLLECT_EVIDENCE = "collect_evidence"
    MONITOR = "monitor"
    NO_ACTION = "no_action"


class SecurityEvent(BaseModel):
    """Raw security event from logs or monitoring systems."""
    event_id: str = Field(description="Unique event identifier")
    timestamp: datetime = Field(description="Event timestamp")
    source: str = Field(description="Source system or log")
    event_type: str = Field(description="Type of event")
    raw_data: Dict[str, Any] = Field(description="Raw event data")
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None


class ThreatDetection(BaseModel):
    """Detected threat information."""
    detection_id: str = Field(description="Unique detection identifier")
    event: SecurityEvent = Field(description="Original security event")
    threat_indicators: List[str] = Field(description="List of threat indicators")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Detection confidence")
    detected_at: datetime = Field(default_factory=datetime.now)
    detection_method: str = Field(description="Method used for detection")


class ThreatAnalysis(BaseModel):
    """Analysis results for a detected threat."""
    analysis_id: str = Field(description="Unique analysis identifier")
    detection: ThreatDetection = Field(description="Original detection")
    severity: SeverityLevel = Field(description="Threat severity level")
    category: ThreatCategory = Field(description="Threat category")
    attack_vector: Optional[str] = None
    affected_assets: List[str] = Field(default_factory=list)
    iocs: List[str] = Field(default_factory=list, description="Indicators of Compromise")
    analysis_summary: str = Field(description="Summary of analysis")
    recommended_actions: List[ResponseAction] = Field(default_factory=list)
    analyzed_at: datetime = Field(default_factory=datetime.now)


class Investigation(BaseModel):
    """Forensic investigation results."""
    investigation_id: str = Field(description="Unique investigation identifier")
    analysis: ThreatAnalysis = Field(description="Original analysis")
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_collected: List[str] = Field(default_factory=list)
    root_cause: Optional[str] = None
    attack_chain: List[str] = Field(default_factory=list)
    investigation_notes: str = Field(default="")
    investigated_at: datetime = Field(default_factory=datetime.now)


class IncidentResponse(BaseModel):
    """Incident response actions and results."""
    response_id: str = Field(description="Unique response identifier")
    investigation: Investigation = Field(description="Investigation results")
    actions_taken: List[ResponseAction] = Field(default_factory=list)
    action_details: Dict[str, Any] = Field(default_factory=dict)
    containment_status: str = Field(default="pending")
    remediation_steps: List[str] = Field(default_factory=list)
    responded_at: datetime = Field(default_factory=datetime.now)


class IncidentReport(BaseModel):
    """Final incident report."""
    report_id: str = Field(description="Unique report identifier")
    response: IncidentResponse = Field(description="Response details")
    executive_summary: str = Field(description="Executive summary")
    technical_details: str = Field(description="Technical details")
    lessons_learned: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    report_generated_at: datetime = Field(default_factory=datetime.now)


class AgentState(BaseModel):
    """State passed between agents in the LangGraph workflow."""
    security_event: Optional[SecurityEvent] = None
    detection: Optional[ThreatDetection] = None
    analysis: Optional[ThreatAnalysis] = None
    investigation: Optional[Investigation] = None
    response: Optional[IncidentResponse] = None
    report: Optional[IncidentReport] = None
    messages: List[str] = Field(default_factory=list)
    current_stage: str = Field(default="detection")
    error: Optional[str] = None
    
    class Config:
        arbitrary_types_allowed = True
