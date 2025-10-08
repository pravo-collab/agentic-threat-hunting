# Project Summary: Agentic MultiStage Threat Hunting and Incident Response

## 📋 Overview

This repository contains a complete, production-ready implementation of an **Agentic MultiStage Threat Hunting and Incident Response System** built with **LangGraph** and **LangChain**. The system uses AI-powered agents to automatically detect, analyze, investigate, and respond to cybersecurity threats.

## 🏗️ Project Structure

```
Praveen_Capstone1/
├── src/                          # Source code
│   ├── agents/                   # Individual agent implementations
│   │   ├── detection_agent.py    # Threat detection
│   │   ├── analysis_agent.py     # Threat analysis
│   │   ├── investigation_agent.py # Forensic investigation
│   │   ├── response_agent.py     # Incident response
│   │   ├── reporting_agent.py    # Report generation
│   │   ├── network_capture_agent.py    # Network capture (NEW)
│   │   ├── network_analysis_agent.py   # Network analysis (NEW)
│   │   └── ml_traffic_classifier_agent.py # Deep Learning classifier (NEW)
│   ├── graph/                    # LangGraph workflow
│   │   └── workflow.py           # Agent orchestration
│   ├── models/                   # Data models
│   │   └── schemas.py            # Pydantic schemas + Network models
│   ├── config/                   # Configuration
│   │   └── settings.py           # Settings management
│   ├── utils/                    # Utilities
│   │   └── logger.py             # Logging setup
│   └── main.py                   # Main entry point
├── tests/                        # Test suite
│   ├── test_agents.py            # Agent tests
│   └── test_workflow.py          # Workflow tests
├── data/                         # Sample data
│   ├── sample_logs.json          # Malware detection event
│   ├── phishing_event.json       # Phishing attempt
│   ├── intrusion_event.json      # Unauthorized access
│   └── network_traffic_event.json # Network threat (NEW)
├── notebooks/                    # Jupyter notebooks
│   └── demo.ipynb                # Interactive demo
├── app.py                        # Streamlit web UI (NEW)
├── network_monitor.py            # Network monitor CLI (NEW)
├── requirements.txt              # Python dependencies
├── README.md                     # Main documentation
├── QUICKSTART.md                 # Quick start guide
├── STREAMLIT_GUIDE.md            # Streamlit UI guide (NEW)
├── NETWORK_MONITORING.md         # Network monitoring guide (NEW)
├── ML_TRAFFIC_CLASSIFIER.md      # Deep Learning classifier docs (NEW)
├── ARCHITECTURE.md               # System architecture
├── PROJECT_SUMMARY.md            # This file
├── captures/                     # PCAP files directory (NEW)
├── models/                       # ML models directory (NEW)
├── Makefile                      # Build automation
├── setup.py                      # Package setup
├── pytest.ini                    # Test configuration
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore rules
└── LICENSE                       # MIT License
```

## 🎯 Key Features

### 1. **Multi-Agent Architecture**

#### Core Agents
- **Detection Agent**: Monitors security events and identifies potential threats
- **Analysis Agent**: Determines threat severity, category, and impact
- **Investigation Agent**: Performs deep forensic analysis
- **Response Agent**: Plans and executes containment actions
- **Reporting Agent**: Generates comprehensive incident reports

#### Network Monitoring Agents (NEW)
- **Network Capture Agent**: Captures and organizes network traffic into flows
  - Real-time packet capture with Scapy
  - PCAP file generation and saving
  - Configurable duration (5-180s) and packet limits (up to 1M)
  - Cross-platform interface detection
- **Network Analysis Agent**: AI-powered analysis of network patterns and anomalies
- **ML Traffic Classifier Agent**: Deep Learning intrusion detection system (NEW)
  - 4-layer neural network (128→64→32→16 neurons)
  - 21 enhanced features per flow
  - 8 intrusion types: DoS, Probe, R2L, U2R, Malware, Botnet, Anomaly, Normal
  - Application classification: Web, Email, DNS, FTP, SSH, Database
  - Real-time threat level assessment (Critical, High, Medium, Low, Safe)
  - TensorFlow/Keras backend for scalability
  - Sub-10ms inference per flow

### 2. **LangGraph Workflow**
- State-based agent orchestration
- Conditional routing between agents
- Memory persistence with checkpointing
- Error handling and recovery

### 3. **Comprehensive Data Models**
- Type-safe Pydantic schemas
- Severity levels (Critical, High, Medium, Low, Info)
- Threat categories (Malware, Phishing, Intrusion, etc.)
- Response actions (Block IP, Quarantine Host, etc.)

### 4. **Network Traffic Monitoring & Deep Learning (NEW)**
- **Real-time Packet Capture**: Scapy-based capture with PCAP file generation
- **Flow-based Analysis**: Intelligent traffic aggregation and flow tracking
- **Deep Learning Intrusion Detection**: 
  - Neural network with 21 features
  - 8-class classification (DoS, Probe, R2L, U2R, Malware, Botnet, Anomaly, Normal)
  - Real-time threat detection (<10ms per flow)
- **Application Classification**: Automatic traffic type identification
- **Anomaly Detection**: Statistical baseline modeling and deviation detection
- **Protocol Analysis**: TCP, UDP, ICMP, HTTP, HTTPS, DNS, FTP, SSH
- **Comprehensive PCAP Analysis**: 
  - File information and statistics
  - Protocol breakdown
  - Notable observations
  - Potential threat identification
  - Packet content analysis
  - Automated conclusions
- **Multiple Interfaces**: Standalone CLI, Streamlit UI, Python API

### 5. **Interactive Web UI (NEW)**
- Modern Streamlit-based interface
- Real-time agent execution tracking
- **ML Traffic Classifier Page**: 
  - Upload or select PCAP files
  - Real-time analysis with DL model
  - Interactive visualizations
  - Threat level assessment
  - Application type breakdown
  - Detailed flow classifications
  - Model training interface
  - Architecture visualization
- Network monitoring dashboard
- Visual workflow pipeline
- Interactive charts and metrics
- Downloadable reports (JSON, PCAP)

### 6. **Production-Ready Features**
- Environment-based configuration
- Structured logging with Loguru
- Rich CLI output with colors and tables
- Async support for scalability
- Comprehensive test suite

## 🚀 Quick Start

### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your OPENAI_API_KEY
```

### Running the System

#### Option 1: Streamlit Web UI (Recommended)
```bash
streamlit run app.py
# Navigate to Network Monitor for traffic analysis
```

#### Option 2: Network Monitor CLI
```bash
# Analyze network event
python network_monitor.py --input data/network_traffic_event.json

# Simulate live capture
python network_monitor.py --live
```

#### Option 3: Command Line
```bash
# Run with sample malware event
python src/main.py --input data/sample_logs.json

# Run with phishing event
python src/main.py --input data/phishing_event.json

# Run with network traffic event
python src/main.py --input data/network_traffic_event.json

# Run with intrusion event
python src/main.py --input data/intrusion_event.json

# Save report to file
python src/main.py --input data/sample_logs.json --output report.json
```

### Using Make Commands

```bash
make install      # Install dependencies
make run-sample   # Run with sample data
make test         # Run tests
make format       # Format code
make lint         # Lint code
```

## 🔄 Workflow Stages

The system processes security events through 5 sequential stages:

```
1. DETECTION
   ↓
2. ANALYSIS
   ↓
3. INVESTIGATION
   ↓
4. RESPONSE
   ↓
5. REPORTING
```

Each stage is handled by a specialized agent that:
- Receives state from the previous stage
- Performs its specific analysis
- Updates the state with new findings
- Passes control to the next agent

## 📊 Data Flow

```
SecurityEvent → ThreatDetection → ThreatAnalysis → Investigation → IncidentResponse → IncidentReport
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_agents.py -v
```

## 📦 Dependencies

**Core:**
- `langgraph` - Agent workflow orchestration
- `langchain` - LLM framework
- `langchain-openai` - OpenAI integration
- `openai` - OpenAI API client

**Deep Learning & ML:**
- `tensorflow` - Deep learning framework
- `keras` - Neural network API
- `scikit-learn` - Machine learning utilities
- `numpy` - Numerical computing
- `pandas` - Data manipulation

**Network Analysis:**
- `scapy` - Packet capture and analysis
- `streamlit` - Web UI framework
- `plotly` - Interactive visualizations

**Data & Utilities:**
- `pydantic` - Data validation
- `python-dotenv` - Environment management
- `loguru` - Logging
- `rich` - CLI formatting

**Testing:**
- `pytest` - Testing framework
- `pytest-asyncio` - Async testing
- `pytest-cov` - Coverage reporting

## 🎨 Example Output

When you run the system, you'll see:

1. **Workflow Messages** - Progress through each stage
2. **Detection Results** - Threat indicators and confidence scores
3. **Threat Analysis** - Severity, category, and IOCs
4. **Investigation Results** - Root cause and attack chain
5. **Response Plan** - Recommended actions and remediation
6. **Executive Summary** - High-level incident overview

## 🔧 Configuration

Edit `.env` to customize:

```env
# Required
OPENAI_API_KEY=your_key_here

# Optional
DEFAULT_MODEL=gpt-4o-mini
TEMPERATURE=0.1
LOG_LEVEL=INFO
AUTO_RESPONSE_ENABLED=false
REQUIRE_HUMAN_APPROVAL=true
```

## 📚 Use Cases

1. **Security Operations Center (SOC)** - Automated threat triage
2. **Incident Response** - Rapid investigation and containment
3. **Threat Hunting** - Proactive threat detection
4. **Security Training** - Educational demonstrations
5. **Research** - AI agent experimentation

## 🎓 Learning Objectives

This project demonstrates:

- **LangGraph** - Building multi-agent workflows
- **LangChain** - LLM application development
- **Agent Design** - Specialized agent architecture
- **State Management** - Complex state transitions
- **Production Practices** - Testing, logging, configuration
- **Cybersecurity** - Threat hunting and incident response

## 🔐 Security Considerations

- API keys stored in environment variables
- No hardcoded credentials
- Human approval required for response actions (configurable)
- Comprehensive logging for audit trails
- Type-safe data models prevent injection attacks

## 🚧 Future Enhancements

Potential extensions:

- [ ] Integration with SIEM systems
- [ ] Real-time log streaming
- [x] **Machine learning for anomaly detection** ✅ (Deep Learning implemented)
- [x] **PCAP file analysis** ✅ (Comprehensive analysis implemented)
- [ ] Multi-tenant support
- [x] **Web dashboard** ✅ (Streamlit UI implemented)
- [ ] Slack/Teams notifications
- [ ] Threat intelligence feeds integration
- [ ] Automated response execution
- [ ] Historical incident database
- [ ] Online learning for model updates
- [ ] Multi-model ensemble (LSTM, CNN)
- [ ] Explainable AI (SHAP values)
- [ ] Real-time streaming analytics

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## 📞 Support

For questions or issues:
- Review the QUICKSTART.md guide
- Check the code documentation
- Open an issue on GitHub

## ✅ Project Status

**Status**: Production-Ready with Advanced ML ✓

All core features implemented:
- ✅ 8 specialized agents (5 core + 3 network/ML)
- ✅ LangGraph workflow with dual paths
- ✅ Complete data models (including network schemas)
- ✅ CLI interface (main + network monitor)
- ✅ **Deep Learning intrusion detection** (NEW)
- ✅ **Real-time packet capture & PCAP generation** (NEW)
- ✅ **Streamlit web UI with ML classifier** (NEW)
- ✅ Test suite
- ✅ Comprehensive documentation
- ✅ Sample data (events + network traffic)
- ✅ Configuration management

## 🎯 Getting Started Checklist

- [ ] Clone/download the repository
- [ ] Create virtual environment
- [ ] Install dependencies
- [ ] Set up `.env` file with API key
- [ ] Run sample event: `make run-sample`
- [ ] Explore the code in `src/agents/`
- [ ] Try the Jupyter notebook
- [ ] Create custom security events
- [ ] Run tests: `make test`
- [ ] Customize for your use case

---

**Built with ❤️ for cybersecurity and AI enthusiasts**

*This project showcases the power of agentic AI systems in cybersecurity operations.*
