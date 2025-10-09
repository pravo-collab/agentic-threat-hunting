# Agentic MultiStage Threat Hunting and Incident Response System

An intelligent, multi-agent cybersecurity system built with LangGraph for automated threat hunting, detection, analysis, and incident response.

## Overview

This project implements an agentic AI system that orchestrates multiple specialized agents to perform comprehensive threat hunting and incident response operations. The system uses LangGraph to coordinate agents through different stages of the security workflow.

## Features

- **Dual Workflow Paths**: Choose between file upload or live network capture
- **Multi-Stage Threat Detection**: Automated detection across multiple security layers
- **Intelligent Threat Analysis**: AI-powered analysis of security events and anomalies
- **Network Traffic Monitoring**: Real-time network capture and analysis (5-180 seconds, up to 1M packets)
- **PCAP File Generation**: Automatic PCAP file saving for forensic analysis and external tool integration
- **Deep Learning Intrusion Detection**: Neural network-based threat classification with 8 attack types
- **Real-Time Threat Detection**: Sub-10ms inference for live traffic analysis
- **Application Classification**: Automatic identification of traffic types (Web, Email, DNS, FTP, SSH, Database)
- **AI-Powered PCAP Chat**: Interactive conversational interface to ask questions about network traffic
- **Zeek Integration**: Advanced PCAP parsing with structured log extraction
- **Vector Database**: Pinecone-powered similarity search for threat hunting
- **RAG-Based Analysis**: Retrieval-Augmented Generation for intelligent traffic analysis
- **Full Pipeline Analysis**: Network capture → Analysis → Investigation → Response → Reporting
- **Automated Incident Response**: Coordinated response actions based on threat severity
- **Agent Orchestration**: LangGraph-based workflow management with intelligent routing
- **Real-time Monitoring**: Continuous security monitoring and alerting
- **Threat Intelligence Integration**: Integration with threat intelligence feeds
- **Forensic Analysis**: Detailed investigation and evidence collection
- **🎨 Interactive Streamlit UI**: Modern web interface with dual workflow support
## Architecture

The system consists of several specialized agents:

### Core Agents
1. **Detection Agent**: Analyzes security events and detects potential threats
2. **Analysis Agent**: Determines the severity of detected threats
3. **Investigation Agent**: Performs deep forensic analysis
4. **Response Agent**: Executes appropriate response actions
5. **Reporting Agent**: Generates comprehensive incident reports

### Network Monitoring Agents
6. **Network Capture Agent**: Captures and organizes network traffic into flows (5-180s, up to 1M packets)
   - Automatic PCAP file generation
   - Saves to `captures/` directory
   - Compatible with Wireshark, tcpdump, etc.
7. **Network Analysis Agent**: AI-powered analysis of network patterns and anomalies
8. **ML Traffic Classifier Agent**: Deep Learning intrusion detection system
   - 4-layer neural network (128→64→32→16)
   - 21 enhanced features per flow
   - 8 intrusion types: DoS, Probe, R2L, U2R, Malware, Botnet, Anomaly, Normal
   - Application classification: Web, Email, DNS, FTP, SSH, Database
   - Threat levels: Critical, High, Medium, Low, Safe
   - Real-time processing (<10ms per flow)
   - TensorFlow/Keras backend
9. **AI Packet Analyzer Agent**: Advanced conversational PCAP analysis (NEW)
   - Zeek-powered PCAP parsing with structured logs
   - OpenAI embeddings (text-embedding-3-small)
   - Pinecone vector database for similarity search
   - RAG-based natural language querying
   - Interactive chat interface for Q&A
   - Anomaly detection via embedding similarity
   - Threat hunting with known malicious patterns
   - Real-time conversational analysis

**Both paths converge** at the Analysis Agent for consistent threat handling.
### Workflow Routing
- **Router Node**: Intelligently routes to file upload or network capture path
- **Dual Paths**: Both converge at Analysis Agent for consistent threat handling
- **State Management**: Unified AgentState for both workflows

## Project Structure

```
.
├── src/
│   ├── agents/                    # Individual agent implementations
│   │   ├── detection_agent.py     # Threat detection
│   │   ├── analysis_agent.py      # Threat analysis
│   │   ├── investigation_agent.py # Forensic investigation
│   │   ├── response_agent.py      # Incident response
│   │   ├── reporting_agent.py     # Report generation
│   │   ├── network_capture_agent.py    # Network traffic capture (NEW)
│   │   └── network_analysis_agent.py   # Network analysis (NEW)
│   ├── graph/           # LangGraph workflow definitions
│   ├── models/          # Data models and schemas
│   │   └── schemas.py   # NetworkPacket, NetworkFlow, NetworkCapture models
│   ├── config/          # Configuration files
│   └── utils/           # Helper functions
├── data/                # Sample data and test cases
│   ├── sample_logs.json           # Malware detection event
│   ├── phishing_event.json        # Phishing attempt
│   ├── intrusion_event.json       # Unauthorized access
│   └── network_traffic_event.json # Network threat (NEW)
├── tests/               # Unit and integration tests
├── notebooks/           # Jupyter notebooks for analysis
├── app.py              # Streamlit web interface
├── network_monitor.py  # Standalone network monitor CLI (NEW)
├── requirements.txt    # Python dependencies
├── NETWORK_MONITORING.md  # Network monitoring guide (NEW)
└── README.md           # This file
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Praveen_Capstone1
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

## Configuration

Create a `.env` file with the following variables:

```
OPENAI_API_KEY=your_openai_api_key
LANGCHAIN_API_KEY=your_langchain_api_key
LANGCHAIN_TRACING_V2=true
LANGCHAIN_PROJECT=threat-hunting
```

## Usage

### Option 1: Streamlit Web UI (Recommended) 🎨

Launch the interactive web interface:

```bash
streamlit run app.py
```

Then open your browser to `http://localhost:8501`

**Two Workflow Paths:**

**Path 1: File Upload (Traditional)**
- Navigate to "Analyze Event"
- Upload or select sample event
- Run through Detection → Analysis → Investigation → Response → Report

**Path 2: Network Capture (Full Pipeline)**
- Navigate to "Network Monitor" → "Live Traffic Simulation (Full Pipeline)"
- Configure capture (5-180s, up to 1M packets)
- Run through Network Capture → Network Analysis → Detection → Analysis → Investigation → Response → Report
- 7 agent execution tracking
- Downloadable comprehensive reports

See [STREAMLIT_GUIDE.md](STREAMLIT_GUIDE.md) and [WORKFLOW_PATHS.md](WORKFLOW_PATHS.md) for detailed documentation.

### Option 2: Network Monitor CLI

Standalone network traffic monitoring tool:

```bash
# Analyze a network event file
python network_monitor.py --input data/network_traffic_event.json

# Simulate live traffic capture (default 10 seconds)
python network_monitor.py --live

# Capture for 30 seconds
python network_monitor.py --live --duration 30

# Maximum capture (180 seconds / 3 minutes)
python network_monitor.py --live --duration 180

# Custom packet limit
python network_monitor.py --live --duration 60 --max-packets 500000

# Maximum limits (3 min, 1M packets)
python network_monitor.py --live --duration 180 --max-packets 1000000
```

See [NETWORK_MONITORING.md](NETWORK_MONITORING.md) for detailed network monitoring documentation.

### Option 3: Command Line Interface

#### Running the System

```bash
python src/main.py
```

#### Running with Sample Data

```bash
# Analyze malware detection
python src/main.py --input data/sample_logs.json

# Analyze phishing attempt
python src/main.py --input data/phishing_event.json

# Analyze network traffic
python src/main.py --input data/network_traffic_event.json
```

#### Interactive Mode

```bash
python src/main.py --interactive
```

## Agent Workflow

The system uses a **dual-path LangGraph workflow** with intelligent routing:

### Path 1: File Upload
1. **Router** → **Detection Agent** analyzes security events
2. If threat detected → **Analysis Agent** determines severity
3. **Investigation Agent** performs forensic analysis
4. **Response Agent** plans containment actions
5. **Reporting Agent** generates final report

### Path 2: Network Capture (Full Pipeline)
1. **Router** → **Network Capture Agent** captures traffic (5-180s)
2. **Network Analysis Agent** analyzes flows with AI
3. If threat detected → **Detection Agent** (creates security event)
4. **Analysis Agent** determines severity
5. **Investigation Agent** performs forensic analysis
6. **Response Agent** plans containment actions
7. **Reporting Agent** generates final report

**Both paths converge** at the Analysis Agent for consistent threat handling.

See [WORKFLOW_PATHS.md](WORKFLOW_PATHS.md) for detailed workflow documentation.

## Development

### Running Tests

```bash
pytest tests/
```

### Code Formatting

```bash
black src/
flake8 src/
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License

## Contact

For questions or support, please open an issue in the repository.

## Acknowledgments

- Built with LangGraph and LangChain
- Powered by OpenAI GPT models
- Inspired by modern SOC (Security Operations Center) practices
