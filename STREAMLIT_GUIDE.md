# Streamlit UI Guide

## 🎨 Overview

The Streamlit UI provides an interactive web interface for the Agentic Threat Hunting and Incident Response System. It features a modern, user-friendly dashboard for analyzing security events in real-time.

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Activate your virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Streamlit and UI dependencies
pip install streamlit plotly streamlit-option-menu
```

Or install all requirements:

```bash
pip install -r requirements.txt
```

### 2. Run the Streamlit App

```bash
streamlit run app.py
```

The app will automatically open in your default web browser at `http://localhost:8501`

## 📋 Features

### Dashboard
- **System Overview**: View key metrics and system status
- **Quick Actions**: Quickly start analyzing events
- **Recent Activity**: Track recent threat analyses

### Analyze Event
- **Sample Events**: Choose from pre-loaded threat scenarios
  - Malware detection
  - Phishing attempts
  - Intrusion attempts
  - Network traffic events
- **Upload JSON**: Upload your own security event files
- **Manual Entry**: Create custom security events via form

### Network Monitor (NEW)
- **Analyze Network Event**: Analyze network traffic from sample events
- **Live Traffic Simulation**: Simulate real-time packet capture
  - **Configurable duration**: 5-60 seconds via slider
  - Network interface selection
  - BPF filter support
  - Packet limit configuration
- **Network Flow Analysis**: Analyze individual flows manually
  - Source/Destination IPs and ports
  - Protocol selection
  - Packet count configuration

### Real-Time Analysis
- **Progress Tracking**: Visual progress bar during analysis
- **Stage-by-Stage Results**: See each agent's output
- **Interactive Visualizations**:
  - Threat severity gauge
  - Workflow timeline
  - Attack chain visualization

### Results Display
- **Detection Results**: Confidence scores and threat indicators
- **Threat Analysis**: Severity, category, IOCs, and affected assets
- **Investigation**: Root cause analysis and attack chain
- **Response Plan**: Recommended actions and remediation steps
- **Incident Report**: Executive summary and technical details
- **Download Reports**: Export full reports as JSON

### Settings
- **API Configuration**: Check API key status
- **Model Settings**: View current model configuration
- **Alert Thresholds**: See configured alert levels

## 🎯 Usage Examples

### Analyzing a Sample Event

1. Navigate to **Analyze Event** from the sidebar
2. Select "Sample Events" as input method
3. Choose an event (e.g., "sample_logs")
4. Click "🔍 Analyze This Event"
5. Watch the real-time analysis progress
6. Review the comprehensive results

### Uploading Custom Events

1. Prepare a JSON file with the following structure:

```json
{
  "event_id": "custom_001",
  "timestamp": "2025-10-07T12:00:00",
  "source": "firewall",
  "event_type": "suspicious_connection",
  "raw_data": {
    "protocol": "TCP",
    "port": 4444
  },
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "user": "admin",
  "process": "unknown.exe"
}
```

2. Navigate to **Analyze Event**
3. Select "Upload JSON"
4. Upload your file
5. Click "🔍 Analyze This Event"

### Manual Event Entry

1. Navigate to **Analyze Event**
2. Select "Manual Entry"
3. Fill in the event details form
4. Click "🔍 Analyze Event"

## 🎨 UI Components

### Severity Gauge
- Visual representation of threat severity
- Color-coded from green (low) to red (critical)
- Real-time updates based on analysis

### Workflow Timeline
- Shows completed workflow stages
- Color-coded by stage type
- Interactive visualization

### Metrics Cards
- Key performance indicators
- Real-time system status
- Alert thresholds

## ⚙️ Configuration

### Environment Variables

Make sure your `.env` file is configured:

```env
OPENAI_API_KEY=your_key_here
DEFAULT_MODEL=gpt-4o-mini
TEMPERATURE=0.1
LOG_LEVEL=INFO
```

### Streamlit Configuration

Create `.streamlit/config.toml` for custom settings:

```toml
[theme]
primaryColor = "#1f77b4"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
font = "sans serif"

[server]
port = 8501
enableCORS = false
```

## 🐛 Troubleshooting

### App Won't Start

```bash
# Check if streamlit is installed
pip list | grep streamlit

# Reinstall if needed
pip install --upgrade streamlit
```

### Import Errors

```bash
# Make sure you're in the project root
cd /path/to/Praveen_Capstone1

# Install in development mode
pip install -e .
```

### API Key Issues

1. Check `.env` file exists
2. Verify `OPENAI_API_KEY` is set
3. Restart the Streamlit app

## 📱 Mobile Support

The UI is responsive and works on:
- Desktop browsers
- Tablets
- Mobile devices (limited functionality)

## 🔒 Security Notes

- Never commit `.env` files with real API keys
- Use environment variables for sensitive data
- The app runs locally by default (localhost:8501)
- For production deployment, use proper authentication

## 🚀 Deployment

### Deploy to Streamlit Cloud

1. Push your code to GitHub
2. Go to https://streamlit.io/cloud
3. Connect your GitHub repository
4. Add secrets in Streamlit Cloud dashboard
5. Deploy!

### Deploy to Heroku

```bash
# Create Procfile
echo "web: streamlit run app.py --server.port=$PORT" > Procfile

# Deploy
heroku create your-app-name
git push heroku main
```

## 📊 Performance Tips

- Use caching for expensive operations
- Limit concurrent analyses
- Monitor API usage
- Consider rate limiting for production

## 🎓 Learning Resources

- [Streamlit Documentation](https://docs.streamlit.io/)
- [Plotly Documentation](https://plotly.com/python/)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)

## 🤝 Contributing

To add new features to the UI:

1. Create a new function in `app.py`
2. Add navigation menu item
3. Test thoroughly
4. Submit a pull request

## 📝 License

Same as the main project (MIT License)

---

**Enjoy analyzing threats with the interactive UI!** 🛡️
