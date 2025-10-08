# Quick Start Guide

Get started with the Agentic MultiStage Threat Hunting and Incident Response System in minutes!

## Prerequisites

- Python 3.9 or higher
- OpenAI API key
- (Optional) LangChain API key for tracing

## Installation Steps

### 1. Set Up Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your API keys
# Required:
OPENAI_API_KEY=your_openai_api_key_here

# Optional:
LANGCHAIN_API_KEY=your_langchain_api_key_here
```

### 4. Run Your First Threat Hunt

#### Option A: Streamlit Web UI (Recommended)

```bash
streamlit run app.py
```

Then navigate to `http://localhost:8501` and:
- Try the **Network Monitor** for live traffic simulation
- Use the slider to set capture duration (5-60 seconds)
- Analyze sample events with real-time agent tracking

#### Option B: Command Line

```bash
# Run with sample malware detection event
python src/main.py --input data/sample_logs.json

# Or run with default sample event
python src/main.py
```

#### Option C: Network Monitor CLI

```bash
# Simulate live traffic capture (10 seconds)
python network_monitor.py --live

# Capture for 30 seconds
python network_monitor.py --live --duration 30
```

## Example Scenarios

### Analyze a Phishing Attempt

```bash
python src/main.py --input data/phishing_event.json
```

### Investigate an Intrusion

```bash
python src/main.py --input data/intrusion_event.json
```

### Analyze Network Traffic

```bash
# Via CLI
python src/main.py --input data/network_traffic_event.json

# Via Network Monitor with custom duration
python network_monitor.py --input data/network_traffic_event.json
python network_monitor.py --live --duration 60  # Max 1 minute
```

### Save Report to File

```bash
python src/main.py --input data/sample_logs.json --output reports/incident_report.json
```

## Using the Jupyter Notebook

```bash
# Start Jupyter
jupyter notebook

# Open notebooks/demo.ipynb
# Follow the interactive demo
```

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Using Make Commands

```bash
# Install dependencies
make install

# Run tests
make test

# Run application
make run

# Run with sample data
make run-sample

# Format code
make format

# Lint code
make lint

# Clean up
make clean
```

## Understanding the Output

The system will process your security event through 5 stages:

1. **Detection** - Identifies potential threats
2. **Analysis** - Determines severity and category
3. **Investigation** - Performs forensic analysis
4. **Response** - Plans containment actions
5. **Reporting** - Generates comprehensive report

Each stage builds upon the previous one, creating a complete incident response workflow.

## Customizing Security Events

Create your own security event JSON file:

```json
{
  "event_id": "custom_event_001",
  "timestamp": "2025-10-07T12:00:00",
  "source": "your_source",
  "event_type": "your_event_type",
  "raw_data": {
    "custom_field": "custom_value"
  },
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "user": "username",
  "process": "process.exe"
}
```

Then run:

```bash
python src/main.py --input path/to/your/event.json
```

## Troubleshooting

### API Key Issues

If you see API key errors:
1. Verify your `.env` file exists
2. Check that `OPENAI_API_KEY` is set correctly
3. Ensure no extra spaces or quotes around the key

### Import Errors

If you see import errors:
1. Make sure you're in the virtual environment
2. Run `pip install -r requirements.txt` again
3. Check Python version: `python --version` (should be 3.9+)

### Module Not Found

If you see "ModuleNotFoundError":
1. Make sure you're running from the project root directory
2. Check that all `__init__.py` files exist in the `src/` directories

## Next Steps

- Explore the code in `src/agents/` to understand each agent
- Modify `src/config/settings.py` to adjust system behavior
- Create custom security events for your use cases
- Integrate with your existing security tools
- Extend agents with additional capabilities

## Getting Help

- Check the main README.md for detailed documentation
- Review the code comments in each module
- Open an issue on GitHub for bugs or questions

Happy Threat Hunting! 🔍🛡️
