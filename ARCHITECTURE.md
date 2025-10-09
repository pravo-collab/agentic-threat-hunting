# System Architecture

## Overview

The Agentic MultiStage Threat Hunting and Incident Response System is built on a **multi-agent architecture** orchestrated by **LangGraph**. The system supports **two workflow paths** with intelligent routing: traditional file upload analysis and live network traffic capture with full pipeline analysis. Each agent specializes in a specific phase of the threat hunting and incident response lifecycle.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Input Options                             │
│     File Upload (JSON) OR Live Network Capture OR PCAP Chat     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   LangGraph Workflow (Dual Path)                 │
│                                                                   │
│                      ┌──────────────┐                            │
│                      │    ROUTER    │                            │
│                      │  (Entry Point)│                           │
│                      └──────┬───────┘                            │
│                             │                                     │
│              ┌──────────────┴──────────────┐                     │
│              │                             │                     │
│       current_stage =              current_stage =               │
│       "detection"                  "network_capture"             │
│              │                             │                     │
│              ▼                             ▼                     │
│      ┌──────────────┐              ┌──────────────┐             │
│      │  Detection   │              │   Network    │             │
│      │    Agent     │              │   Capture    │             │
│      └──────┬───────┘              └──────┬───────┘             │
│             │                             │                     │
│             │                             ▼                     │
│             │                      ┌──────────────┐             │
│             │                      │   Network    │             │
│             │                      │   Analysis   │             │
│             │                      └──────┬───────┘             │
│             │                             │                     │
│             │                             ▼                     │
│             │                      ┌──────────────┐             │
│             │                      │ ML Traffic   │             │
│             │                      │  Classifier  │             │
│             │                      └──────┬───────┘             │
│             │                             │                     │
│             └──────────┬──────────────────┘                     │
│                        │                                         │
│                        ▼                                         │
│                ┌──────────────┐                                 │
│                │   Analysis   │                                 │
│                │    Agent     │                                 │
│                └──────┬───────┘                                 │
│                       │                                          │
│                       ▼                                          │
│                ┌──────────────┐                                 │
│                │Investigation │                                 │
│                │    Agent     │                                 │
│                └──────┬───────┘                                 │
│                       │                                          │
│                       ▼                                          │
│                ┌──────────────┐                                 │
│                │   Response   │                                 │
│                │    Agent     │                                 │
│                └──────┬───────┘                                 │
│                       │                                          │
│                       ▼                                          │
│                ┌──────────────┐                                 │
│                │  Reporting   │                                 │
│                │    Agent     │                                 │
│                └──────┬───────┘                                 │
│                       │                                          │
└───────────────────────┼─────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Incident Report & Actions                     │
└─────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────┐
                    │  Parallel Analysis  │
                    │  (Streamlit UI)     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  AI Packet Analyzer │
                    │  (Conversational)   │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
            ┌──────────────┐      ┌──────────────┐
            │     Zeek     │      │   Pinecone   │
            │   Parsing    │      │  Vector DB   │
            └──────┬───────┘      └──────┬───────┘
                   │                     │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   RAG Pipeline      │
                   │  (Natural Language  │
                   │   Q&A Interface)    │
                   └─────────────────────┘
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

### 3. LangGraph Workflow (Dual Path)

The system implements a **dual-path workflow** with intelligent routing:

#### Workflow Routing Logic

```python
def route_initial_input(state):
    if state.current_stage == "network_capture":
        return "network_capture"  # Path 2
    return "detection_agent"      # Path 1
```

#### Path 1: File Upload Workflow

```
[START] → Router → Detection Agent
                        │
                   Threat Detected?
                    │         │
                   Yes        No → [END]
                    │
                    ▼
              Analysis Agent
                    │
                    ▼
            Investigation Agent
                    │
                    ▼
              Response Agent
                    │
                    ▼
             Reporting Agent
                    │
                    ▼
                  [END]
```

#### Path 2: Network Capture Workflow

```
[START] → Router → Network Capture Agent
                        │
                        ▼
                Network Analysis Agent
                        │
                   Threat Detected?
                    │         │
                   Yes        No → [END]
                    │
                    ▼
              Analysis Agent (Convergence Point)
                    │
                    ▼
            Investigation Agent
                    │
                    ▼
              Response Agent
                    │
                    ▼
             Reporting Agent
                    │
                    ▼
                  [END]
```

**Key Points:**
- Both paths use the same `AgentState` object
- Paths converge at the Analysis Agent
- Network path includes 2 additional agents (Capture + Analysis)
- Router determines path based on `current_stage` field

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

### Network Monitoring Agents
6. **Network Capture Agent**: Captures and organizes network traffic into flows (5-180s, up to 1M packets)
   - Automatic PCAP file generation
   - Saves to `captures/` directory
   - Compatible with Wireshark, tcpdump, etc.
7. **Network Analysis Agent**: AI-powered analysis of network patterns and anomalies
8. **ML Traffic Classifier Agent**: Deep Learning-based intrusion detection and traffic classification
   - 4-layer neural network (128→64→32→16 neurons)
   - 21 enhanced features extraction
   - 8-class intrusion detection (DoS, Probe, R2L, U2R, Malware, Botnet, Anomaly, Normal)
   - Application type classification (Web, Email, DNS, FTP, SSH, Database)
   - Real-time threat level assessment (Critical, High, Medium, Low, Safe)
   - TensorFlow/Keras backend for scalability
9. **AI Packet Analyzer Agent**: Conversational PCAP analysis with RAG (NEW)
   - **Zeek Integration**: Structured PCAP parsing (conn, dns, http, ssl, files, weird logs)
   - **OpenAI Embeddings**: 1536-dimensional vector representations of traffic
   - **Pinecone Vector DB**: Scalable similarity search for millions of flows
   - **RAG Pipeline**: Retrieval-Augmented Generation for intelligent Q&A
   - **Chat Interface**: Interactive conversational analysis
   - **Anomaly Detection**: Embedding-based deviation from baseline
   - **Threat Hunting**: Pattern matching against known malicious traffic
   - **Natural Language Queries**: Ask questions in plain English

**Key Capabilities**:
- Packet capture and parsing
- **Configurable capture duration (5-60 seconds)**
- Flow aggregation and tracking
- Anomaly detection in traffic patterns
- Suspicious flow identification
- Protocol analysis (TCP, UDP, HTTP, HTTPS, DNS, etc.)
- Dynamic packet scaling based on duration

**Detection Features**:
- Suspicious port detection (4444, 31337, 1337, etc.)
- Known malicious IP pattern matching
- High packet rate detection
- Protocol anomaly identification
- Anomaly score calculation (0.0 - 1.0)

## AI Packet Analyzer Workflow

The AI Packet Analyzer operates as a parallel analysis path, providing conversational intelligence for PCAP files:

```
┌─────────────────────────────────────────────────────────────────┐
│              AI Packet Analyzer Workflow                         │
└─────────────────────────────────────────────────────────────────┘

Step 1: PCAP Upload
    │
    ▼
┌─────────────────────┐
│  Upload PCAP File   │
│  (.pcap/.pcapng)    │
└──────────┬──────────┘
           │
           ▼
Step 2: Zeek Parsing
┌─────────────────────┐
│  Zeek Parser        │
│  ├─ conn.log        │
│  ├─ dns.log         │
│  ├─ http.log        │
│  ├─ ssl.log         │
│  ├─ files.log       │
│  └─ weird.log       │
└──────────┬──────────┘
           │
           ▼
Step 3: Text Representation
┌─────────────────────┐
│  Log → Text         │
│  "Network connection│
│   from 192.168.1.1  │
│   to 8.8.8.8..."    │
└──────────┬──────────┘
           │
           ▼
Step 4: Embedding Creation
┌─────────────────────┐
│  OpenAI Embeddings  │
│  text-embedding-    │
│  3-small            │
│  [1536 dimensions]  │
└──────────┬──────────┘
           │
           ▼
Step 5: Vector Storage
┌─────────────────────┐
│  Pinecone Vector DB │
│  ├─ Store vectors   │
│  ├─ Store metadata  │
│  └─ Index for search│
└──────────┬──────────┘
           │
           ▼
Step 6: Baseline & Anomaly Detection
┌─────────────────────┐
│  Baseline Model     │
│  ├─ First 100 flows │
│  ├─ Similarity calc │
│  └─ Anomaly scoring │
└──────────┬──────────┘
           │
           ▼
Step 7: Interactive Chat
┌─────────────────────────────────────┐
│  User Question                      │
│  "Show me DNS tunneling attempts"   │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────┐
│  Query Embedding    │
│  (OpenAI)           │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Vector Search      │
│  (Pinecone)         │
│  Top-K Similar      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Context Building   │
│  Retrieve relevant  │
│  traffic logs       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  RAG Pipeline       │
│  LLM + Context      │
│  (GPT-4)            │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────┐
│  Natural Language Response          │
│  "Found 3 potential DNS tunneling   │
│   attempts from 192.168.1.100..."   │
└─────────────────────────────────────┘
```

### AI Packet Analyzer Components

**1. Zeek Parser**
- Converts raw PCAP to structured logs
- Extracts protocol-specific information
- Generates 6 log types (conn, dns, http, ssl, files, weird)
- Fallback to Scapy if Zeek unavailable

**2. Embedding Engine**
- OpenAI text-embedding-3-small (1536 dimensions)
- Converts traffic descriptions to vectors
- Preserves semantic meaning
- ~50 flows/second processing

**3. Vector Database (Pinecone)**
- Serverless vector storage
- Cosine similarity search
- Sub-100ms query latency
- Scalable to millions of flows
- Metadata filtering

**4. RAG Pipeline**
- Retrieval-Augmented Generation
- Context-aware responses
- Top-K similarity retrieval (default: 5)
- LLM: GPT-4o-mini
- Temperature: 0.1 (factual responses)

**5. Anomaly Detection**
- Baseline establishment (first 100 flows)
- Embedding similarity comparison
- Z-score calculation
- Configurable threshold (default: 0.7)

**6. Threat Hunting**
- Known malicious pattern library
- Similarity search against patterns
- Pattern types: C2, Exfiltration, Malware, Scanning
- Ranking by similarity score

**Configuration**:
- Default duration: 10 seconds
- Maximum duration: 180 seconds (3 minutes)
- Default max packets: 100,000
- Maximum packets: 1,000,000
- Packet counts scale linearly with duration
- Additional flows generated for longer captures (>30s, >60s, >120s)

### Network Analysis Agent (NEW)

**Purpose**: AI-powered analysis of captured network traffic

**Inputs**:
- NetworkCapture
- AgentState

**Outputs**:
- ThreatDetection (if threats found)
- SecurityEvent (generated from network data)
- Updated AgentState

**Key Capabilities**:
- Traffic pattern analysis using LLM
- Behavioral anomaly detection
- Protocol-specific threat detection
- Threat confidence scoring
- Automatic security event generation

**Analysis Focus**:
- Connection patterns and frequencies
- Payload analysis
- Geolocation anomalies
- Encrypted traffic analysis
- Command and control (C2) detection

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
- **Streamlit**: Interactive web UI
- **Plotly**: Data visualization

### Network Monitoring (Optional)
- **Scapy**: Packet capture and manipulation
- **PyShark**: Network protocol analysis
- **dpkt**: Fast packet parsing

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
    network_capture: Optional[NetworkCapture]  # NEW
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
