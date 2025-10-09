---
title: Agentic Threat Hunting & Incident Response
emoji: 🛡️
colorFrom: red
colorTo: blue
sdk: streamlit
sdk_version: "1.28.0"
app_file: app.py
pinned: false
license: mit
---

# 🛡️ Agentic Threat Hunting & Incident Response System

An advanced AI-powered cybersecurity platform featuring multi-agent orchestration, deep learning intrusion detection, and conversational PCAP analysis.

## 🌟 Key Features

- **9 Specialized AI Agents** for comprehensive threat analysis
- **AI-Powered PCAP Chat** - Ask questions about network traffic in natural language
- **Deep Learning Intrusion Detection** - 8 attack types with 4-layer neural network
- **Zeek Integration** - Professional-grade PCAP parsing
- **RAG-Based Analysis** - Retrieval-Augmented Generation for intelligent insights
- **Vector Database** - Pinecone-powered similarity search for threat hunting
- **Real-Time Network Monitoring** - Live packet capture and analysis
- **Interactive Streamlit UI** - Modern web interface

## 🚀 Quick Start

### Prerequisites

Set the following secrets in your Hugging Face Space settings:

```
OPENAI_API_KEY=your_openai_api_key
PINECONE_API_KEY=your_pinecone_api_key (optional)
LANGCHAIN_API_KEY=your_langchain_api_key (optional)
```

### Usage

1. **AI Packet Analyzer** (Featured)
   - Upload a PCAP file
   - Ask questions in natural language
   - Get AI-powered insights

2. **ML Traffic Classifier**
   - Analyze network traffic with deep learning
   - Detect 8 types of intrusions
   - View detailed threat assessments

3. **Network Monitor**
   - Capture live network traffic
   - Generate PCAP files
   - Real-time analysis

## 🏗️ Architecture

- **LangGraph Workflow** - Multi-agent orchestration
- **9 Specialized Agents** - Detection, Analysis, Investigation, Response, Reporting, Network Capture, Network Analysis, ML Classifier, AI Packet Analyzer
- **Dual Workflow Paths** - File upload or live capture
- **Advanced ML** - TensorFlow/Keras neural networks
- **Vector Search** - Pinecone for semantic similarity

## 📊 Agents

1. **Detection Agent** - Threat detection and severity assessment
2. **Analysis Agent** - Deep threat analysis
3. **Investigation Agent** - Forensic investigation
4. **Response Agent** - Automated incident response
5. **Reporting Agent** - Comprehensive report generation
6. **Network Capture Agent** - Live packet capture
7. **Network Analysis Agent** - Network pattern analysis
8. **ML Traffic Classifier** - Deep learning intrusion detection
9. **AI Packet Analyzer** - Conversational PCAP analysis with RAG

## 🔧 Technologies

- **LangChain & LangGraph** - Agent orchestration
- **OpenAI GPT-4** - Natural language processing
- **TensorFlow/Keras** - Deep learning models
- **Zeek** - Network security monitoring
- **Pinecone** - Vector database
- **Scapy** - Packet manipulation
- **Streamlit** - Web interface

## 📝 Documentation

- [Architecture Guide](ARCHITECTURE.md)
- [Project Summary](PROJECT_SUMMARY.md)
- [ML Classifier Guide](ML_TRAFFIC_CLASSIFIER.md)
- [AI Packet Analyzer Guide](AI_PACKET_ANALYZER.md)

## 🎯 Use Cases

- **Security Operations Centers (SOC)** - Automated threat hunting
- **Incident Response Teams** - Rapid threat analysis and response
- **Network Security** - Real-time traffic monitoring
- **Forensic Analysis** - Deep packet inspection and investigation
- **Threat Intelligence** - Pattern recognition and threat hunting

## ⚠️ Note

This is a demonstration system. For production use:
- Configure proper authentication
- Set up secure API key management
- Implement rate limiting
- Add audit logging
- Follow security best practices

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please read the documentation and submit pull requests.

---

Built with ❤️ using LangChain, LangGraph, and OpenAI
