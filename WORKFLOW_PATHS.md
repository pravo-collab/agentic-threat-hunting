# Workflow Paths

## 🔀 Two Analysis Paths

The threat hunting system now supports **two distinct workflow paths** based on your input method:

### Path 1: File Upload (Traditional)
Upload a security event file for traditional threat detection and analysis.

```
┌─────────────────┐
│  Upload File    │
│  (JSON Event)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Detection      │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Analysis       │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Investigation  │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Response       │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Reporting      │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Final Report   │
└─────────────────┘
```

### Path 2: Network Capture (Full Pipeline)
Capture live network traffic and run the complete analysis pipeline.

```
┌─────────────────┐
│  Live Network   │
│  Capture        │
│  (5-180s)       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Network        │
│  Capture Agent  │
│  (Packets→Flows)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Network        │
│  Analysis Agent │
│  (AI Analysis)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Detection      │
│  (If threat)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Analysis       │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Investigation  │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Response       │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Reporting      │
│  Agent          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Final Report   │
└─────────────────┘
```

## 🎯 How It Works

### Workflow Routing

The system uses a **router node** at the entry point that determines which path to take based on the `current_stage` in the `AgentState`:

- **`current_stage = "detection"`** → File Upload Path
- **`current_stage = "network_capture"`** → Network Capture Path

### State Management

Both paths use the same `AgentState` object, which contains:

```python
class AgentState:
    security_event: Optional[SecurityEvent]      # From file upload
    network_capture: Optional[NetworkCapture]    # From live capture
    detection: Optional[ThreatDetection]
    analysis: Optional[ThreatAnalysis]
    investigation: Optional[Investigation]
    response: Optional[IncidentResponse]
    report: Optional[IncidentReport]
    messages: List[str]
    current_stage: str
    error: Optional[str]
```

## 📊 Usage Examples

### Option 1: File Upload (Streamlit UI)

```bash
streamlit run app.py
```

1. Navigate to **"Analyze Event"**
2. Select a sample event or upload JSON
3. Click **"Analyze This Event"**
4. View results through the pipeline

### Option 2: Network Capture (Streamlit UI)

```bash
streamlit run app.py
```

1. Navigate to **"Network Monitor"**
2. Select **"Live Traffic Simulation (Full Pipeline)"**
3. Configure:
   - Duration: 5-180 seconds
   - Packet limit: up to 1,000,000
   - Network interface
4. Click **"Start Full Pipeline Analysis"**
5. Watch all 7 agents execute in sequence
6. Download comprehensive report

### Option 3: Command Line (File Upload)

```bash
# Analyze uploaded file
python src/main.py --input data/sample_logs.json
python src/main.py --input data/phishing_event.json
python src/main.py --input data/network_traffic_event.json
```

### Option 4: Network Monitor CLI

```bash
# Network capture with full analysis
python network_monitor.py --live --duration 30
python network_monitor.py --live --duration 180 --max-packets 1000000
```

## 🔄 Workflow Convergence

Both paths **converge** at the Analysis Agent:

- **Path 1** goes directly to Analysis after Detection
- **Path 2** goes to Analysis after Network Analysis (if threat detected)

From that point forward, both paths follow the same sequence:
1. Analysis Agent
2. Investigation Agent  
3. Response Agent
4. Reporting Agent

This ensures consistent threat handling regardless of the input method.

## ⚙️ Configuration

### Network Capture Limits

- **Duration**: 5-180 seconds (3 minutes max)
- **Packets**: Up to 1,000,000
- **Default Duration**: 10 seconds
- **Default Packets**: 100,000

### Workflow Behavior

- **File Upload**: Immediate analysis of provided event
- **Network Capture**: 
  - Captures traffic for specified duration
  - Converts packets to flows
  - Analyzes flows with AI
  - Creates security event if threat found
  - Continues through full pipeline

## 🎨 Visual Indicators (Streamlit UI)

The UI shows real-time agent execution with 7 status cards:

1. 🌐 **Network Capture** - ⏳ Pending → ⚙️ Running → ✅ Done
2. 🔬 **Network Analysis** - ⏳ Pending → ⚙️ Running → ✅ Done  
3. 🎯 **Detection** - ⏳ Pending → ⚙️ Running → ✅ Done
4. 📊 **Deep Analysis** - ⏳ Pending → ⚙️ Running → ✅ Done
5. 🔎 **Investigation** - ⏳ Pending → ⚙️ Running → ✅ Done
6. 🚨 **Response** - ⏳ Pending → ⚙️ Running → ✅ Done
7. 📋 **Reporting** - ⏳ Pending → ⚙️ Running → ✅ Done

## 📈 Benefits

### Path 1 (File Upload)
- ✅ Quick analysis of known events
- ✅ Batch processing capability
- ✅ Historical event analysis
- ✅ Integration with SIEM systems

### Path 2 (Network Capture)
- ✅ Real-time threat detection
- ✅ Live traffic analysis
- ✅ Zero-day threat discovery
- ✅ Behavioral analysis
- ✅ Complete attack chain visibility

## 🔮 Future Enhancements

- [ ] Hybrid mode: File upload + network capture
- [ ] Multi-source correlation
- [ ] Continuous monitoring mode
- [ ] Automated response execution
- [ ] Integration with packet capture tools (Scapy, Wireshark)
- [ ] Real-time alerting and notifications
- [ ] Dashboard for ongoing captures

---

**Choose your path and start hunting threats!** 🛡️🔍
