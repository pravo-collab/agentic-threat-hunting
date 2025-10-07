# System Architecture

## Overview

The Agentic MultiStage Threat Hunting and Incident Response System is built on a **multi-agent architecture** orchestrated by **LangGraph**. Each agent specializes in a specific phase of the threat hunting and incident response lifecycle.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Security Event Input                      │
│                    (Logs, Alerts, Monitoring)                    │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      LangGraph Workflow                          │
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Detection   │───▶│   Analysis   │───▶│Investigation │      │
│  │    Agent     │    │    Agent     │    │    Agent     │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Response   │───▶│  Reporting   │───▶│    Output    │      │
│  │    Agent     │    │    Agent     │    │              │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Incident Report & Actions                     │
└─────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Agent Layer

Each agent is an autonomous unit with:
- **LLM Integration**: GPT-4 or GPT-3.5 for reasoning
- **Prompt Templates**: Specialized instructions
- **State Management**: Receives and updates AgentState
- **Error Handling**: Graceful failure recovery

```
┌─────────────────────────────────────────────────────────┐
│                      Agent Structure                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │            LLM (OpenAI GPT)                    │    │
│  └────────────────┬───────────────────────────────┘    │
│                   │                                      │
│  ┌────────────────▼───────────────────────────────┐    │
│  │         Prompt Template                        │    │
│  │  - System instructions                         │    │
│  │  - Task-specific guidance                      │    │
│  │  - Output format specification                 │    │
│  └────────────────┬───────────────────────────────┘    │
│                   │                                      │
│  ┌────────────────▼───────────────────────────────┐    │
│  │         JSON Output Parser                     │    │
│  └────────────────┬───────────────────────────────┘    │
│                   │                                      │
│  ┌────────────────▼───────────────────────────────┐    │
│  │         State Update Logic                     │    │
│  └────────────────────────────────────────────────┘    │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 2. Data Flow Architecture

```
SecurityEvent
    │
    ├─ event_id: str
    ├─ timestamp: datetime
    ├─ source: str
    ├─ event_type: str
    ├─ raw_data: dict
    ├─ source_ip: str
    ├─ destination_ip: str
    ├─ user: str
    └─ process: str
    │
    ▼
ThreatDetection
    │
    ├─ detection_id: str
    ├─ event: SecurityEvent
    ├─ threat_indicators: list
    ├─ confidence_score: float
    └─ detection_method: str
    │
    ▼
ThreatAnalysis
    │
    ├─ analysis_id: str
    ├─ detection: ThreatDetection
    ├─ severity: SeverityLevel
    ├─ category: ThreatCategory
    ├─ attack_vector: str
    ├─ affected_assets: list
    ├─ iocs: list
    └─ recommended_actions: list
    │
    ▼
Investigation
    │
    ├─ investigation_id: str
    ├─ analysis: ThreatAnalysis
    ├─ timeline: list
    ├─ evidence_collected: list
    ├─ root_cause: str
    └─ attack_chain: list
    │
    ▼
IncidentResponse
    │
    ├─ response_id: str
    ├─ investigation: Investigation
    ├─ actions_taken: list
    ├─ action_details: dict
    ├─ containment_status: str
    └─ remediation_steps: list
    │
    ▼
IncidentReport
    │
    ├─ report_id: str
    ├─ response: IncidentResponse
    ├─ executive_summary: str
    ├─ technical_details: str
    ├─ lessons_learned: list
    └─ recommendations: list
```

### 3. LangGraph Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                      Workflow State Graph                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│                        [START]                                    │
│                           │                                       │
│                           ▼                                       │
│                   ┌───────────────┐                              │
│                   │   Detection   │                              │
│                   │     Agent     │                              │
│                   └───────┬───────┘                              │
│                           │                                       │
│                    ┌──────┴──────┐                               │
│                    │             │                                │
│              Threat Detected?    No Threat                        │
│                    │             │                                │
│                   Yes            ▼                                │
│                    │          [END]                               │
│                    ▼                                              │
│            ┌───────────────┐                                     │
│            │   Analysis    │                                     │
│            │     Agent     │                                     │
│            └───────┬───────┘                                     │
│                    │                                              │
│                    ▼                                              │
│            ┌───────────────┐                                     │
│            │Investigation  │                                     │
│            │     Agent     │                                     │
│            └───────┬───────┘                                     │
│                    │                                              │
│                    ▼                                              │
│            ┌───────────────┐                                     │
│            │   Response    │                                     │
│            │     Agent     │                                     │
│            └───────┬───────┘                                     │
│                    │                                              │
│                    ▼                                              │
│            ┌───────────────┐                                     │
│            │   Reporting   │                                     │
│            │     Agent     │                                     │
│            └───────┬───────┘                                     │
│                    │                                              │
│                    ▼                                              │
│                  [END]                                            │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Agent Specifications

### Detection Agent

**Purpose**: Identify potential security threats from raw events

**Inputs**:
- SecurityEvent

**Outputs**:
- ThreatDetection (if threat found)
- Updated AgentState

**Key Capabilities**:
- Pattern recognition
- Anomaly detection
- Threat indicator identification
- Confidence scoring

**Decision Logic**:
```python
if is_threat:
    create ThreatDetection
    next_stage = "analysis"
else:
    next_stage = "completed"
```

### Analysis Agent

**Purpose**: Assess threat severity and categorize the attack

**Inputs**:
- ThreatDetection

**Outputs**:
- ThreatAnalysis
- Updated AgentState

**Key Capabilities**:
- Severity classification (Critical → Info)
- Threat categorization (Malware, Phishing, etc.)
- Attack vector identification
- IOC extraction
- Action recommendation

**Severity Levels**:
- **Critical**: Immediate action required
- **High**: Urgent response needed
- **Medium**: Timely investigation required
- **Low**: Monitor and track
- **Info**: Informational only

### Investigation Agent

**Purpose**: Perform deep forensic analysis

**Inputs**:
- ThreatAnalysis

**Outputs**:
- Investigation
- Updated AgentState

**Key Capabilities**:
- Timeline reconstruction
- Evidence collection planning
- Root cause analysis
- Attack chain mapping
- Forensic note taking

**Investigation Process**:
1. Reconstruct event timeline
2. Identify evidence sources
3. Determine root cause
4. Map attack progression
5. Document findings

### Response Agent

**Purpose**: Plan and coordinate incident response

**Inputs**:
- Investigation

**Outputs**:
- IncidentResponse
- Updated AgentState

**Key Capabilities**:
- Action planning
- Containment strategy
- Remediation planning
- Impact assessment

**Response Actions**:
- `block_ip`: Block malicious IP addresses
- `quarantine_host`: Isolate affected systems
- `disable_account`: Disable compromised accounts
- `alert_admin`: Notify administrators
- `collect_evidence`: Preserve forensic evidence
- `monitor`: Continue monitoring
- `no_action`: No action required

### Reporting Agent

**Purpose**: Generate comprehensive incident reports

**Inputs**:
- IncidentResponse

**Outputs**:
- IncidentReport
- Updated AgentState

**Key Capabilities**:
- Executive summary generation
- Technical detail compilation
- Lessons learned extraction
- Recommendation formulation

**Report Sections**:
1. Executive Summary (for leadership)
2. Technical Details (for security team)
3. Lessons Learned
4. Recommendations

## Technology Stack

### Core Framework
- **LangGraph**: Agent workflow orchestration
- **LangChain**: LLM application framework
- **OpenAI**: GPT models for reasoning

### Data & Validation
- **Pydantic**: Type-safe data models
- **Python 3.9+**: Core language

### Infrastructure
- **Loguru**: Structured logging
- **Rich**: CLI formatting
- **Python-dotenv**: Configuration management

### Testing
- **Pytest**: Test framework
- **Pytest-asyncio**: Async testing
- **Pytest-cov**: Coverage reporting

## Configuration Architecture

```
Environment Variables (.env)
    │
    ├─ API Keys
    │   ├─ OPENAI_API_KEY
    │   └─ LANGCHAIN_API_KEY
    │
    ├─ Model Configuration
    │   ├─ DEFAULT_MODEL
    │   └─ TEMPERATURE
    │
    ├─ System Settings
    │   ├─ LOG_LEVEL
    │   └─ MAX_ITERATIONS
    │
    └─ Response Configuration
        ├─ AUTO_RESPONSE_ENABLED
        └─ REQUIRE_HUMAN_APPROVAL
```

## State Management

The `AgentState` object flows through all agents:

```python
class AgentState:
    security_event: Optional[SecurityEvent]
    detection: Optional[ThreatDetection]
    analysis: Optional[ThreatAnalysis]
    investigation: Optional[Investigation]
    response: Optional[IncidentResponse]
    report: Optional[IncidentReport]
    messages: List[str]
    current_stage: str
    error: Optional[str]
```

Each agent:
1. Receives the current state
2. Performs its analysis
3. Updates relevant fields
4. Returns the modified state
5. LangGraph routes to next agent

## Error Handling

```
┌─────────────────────────────────────────┐
│         Error Handling Flow             │
├─────────────────────────────────────────┤
│                                          │
│  Agent Execution                         │
│       │                                  │
│       ├─ Success ──▶ Next Agent         │
│       │                                  │
│       └─ Error ──▶ Set error field      │
│                    Set stage = "error"   │
│                    Route to END          │
│                                          │
└─────────────────────────────────────────┘
```

## Scalability Considerations

### Current Implementation
- Synchronous processing
- Single event at a time
- In-memory state

### Future Enhancements
- Async processing (`arun` method available)
- Batch processing
- Persistent state storage (Redis/Database)
- Distributed agent execution
- Load balancing

## Security Architecture

### API Key Management
- Environment variables only
- No hardcoded credentials
- `.env` file gitignored

### Data Protection
- Type-safe models prevent injection
- Validation at every stage
- Comprehensive logging for audit

### Response Controls
- Human approval required (configurable)
- Action logging
- Rollback capabilities (future)

## Integration Points

The system can integrate with:

1. **SIEM Systems**: Ingest security events
2. **Ticketing Systems**: Create incidents
3. **SOAR Platforms**: Execute responses
4. **Threat Intelligence**: Enrich IOCs
5. **Notification Systems**: Alert teams
6. **Databases**: Store incidents

## Performance Characteristics

- **Latency**: ~10-30 seconds per event (LLM dependent)
- **Throughput**: 1-5 events/minute (single instance)
- **Accuracy**: Depends on LLM and prompt quality
- **Scalability**: Horizontal scaling possible with async

## Monitoring & Observability

### Logging
- Structured logs with Loguru
- Log levels: DEBUG, INFO, WARNING, ERROR
- File rotation (daily)
- 30-day retention

### Tracing
- LangChain tracing (optional)
- Agent execution tracking
- State transitions logged

### Metrics (Future)
- Event processing time
- Agent success rates
- Threat detection accuracy
- Response effectiveness

---

**This architecture provides a solid foundation for production cybersecurity operations while remaining flexible for customization and enhancement.**
