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
│   │   └── reporting_agent.py    # Report generation
│   ├── graph/                    # LangGraph workflow
│   │   └── workflow.py           # Agent orchestration
│   ├── models/                   # Data models
│   │   └── schemas.py            # Pydantic schemas
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
│   └── intrusion_event.json      # Unauthorized access
├── notebooks/                    # Jupyter notebooks
│   └── demo.ipynb                # Interactive demo
├── requirements.txt              # Python dependencies
├── README.md                     # Main documentation
├── QUICKSTART.md                 # Quick start guide
├── Makefile                      # Build automation
├── setup.py                      # Package setup
├── pytest.ini                    # Test configuration
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore rules
└── LICENSE                       # MIT License
```

## 🎯 Key Features

### 1. **Multi-Agent Architecture**
- **Detection Agent**: Monitors security events and identifies potential threats
- **Analysis Agent**: Determines threat severity, category, and impact
- **Investigation Agent**: Performs deep forensic analysis
- **Response Agent**: Plans and executes containment actions
- **Reporting Agent**: Generates comprehensive incident reports

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

### 4. **Production-Ready Features**
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

```bash
# Run with sample malware event
python src/main.py --input data/sample_logs.json

# Run with phishing event
python src/main.py --input data/phishing_event.json

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
- [ ] Machine learning for anomaly detection
- [ ] Multi-tenant support
- [ ] Web dashboard
- [ ] Slack/Teams notifications
- [ ] Threat intelligence feeds integration
- [ ] Automated response execution
- [ ] Historical incident database

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

**Status**: Production-Ready ✓

All core features implemented:
- ✅ 5 specialized agents
- ✅ LangGraph workflow
- ✅ Complete data models
- ✅ CLI interface
- ✅ Test suite
- ✅ Documentation
- ✅ Sample data
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
