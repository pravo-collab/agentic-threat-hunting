# Network Traffic Monitoring & Analysis

## 🌐 Overview

The threat hunting system includes advanced network traffic monitoring and analysis capabilities with **full pipeline integration**. The system supports two workflow paths:

1. **File Upload**: Traditional threat analysis from security event files
2. **Network Capture**: Live traffic capture with complete threat hunting pipeline

Network captures can run through the entire workflow: Capture → Analysis → Detection → Investigation → Response → Reporting
## 🎯 New Agents

### 1. Network Capture Agent
**Purpose:** Captures and organizes network traffic into flows

**Capabilities:**
- Packet capture and parsing
- **Configurable capture duration (5-180 seconds, max 3 minutes)**
- **Configurable packet limit (up to 1,000,000 packets)**
- Flow aggregation and tracking
- Anomaly detection in traffic patterns
- Suspicious flow identification
- Protocol analysis (TCP, UDP, HTTP, HTTPS, DNS, etc.)
- Dynamic packet scaling based on duration
- Integrates with full threat hunting pipeline

**Key Features:**
- Converts security events to network flows
- Simulates live traffic capture
- Identifies suspicious ports and IPs
- Calculates anomaly scores (0.0 - 1.0)
- Tracks packet counts and byte transfers
- Longer captures generate more flows and packets

### 2. Network Analysis Agent
**Purpose:** Analyzes captured network traffic for security threats

**Capabilities:**
- AI-powered traffic pattern analysis
- Threat detection and classification
- Protocol anomaly detection
- Behavioral analysis
- Threat indicator extraction

**Key Features:**
- Uses LLM for intelligent analysis
- Generates threat confidence scores
- Creates security events from network data
- Provides detailed threat reasoning
- Recommends response actions

## 📊 Data Models

### NetworkPacket
Represents individual network packets with:
- Packet ID and timestamp
- Protocol (TCP, UDP, ICMP, HTTP, HTTPS, DNS, etc.)
- Source and destination IPs/ports
- Packet size and payload
- Flags and raw data

### NetworkFlow
Represents network sessions/flows with:
- Flow ID and duration
- Protocol and endpoints
- Packet and byte counts
- Suspicious indicators
- Anomaly scores
- Threat indicators list

### NetworkCapture
Represents a capture session with:
- Capture ID and timeframe
- Network interface
- Filter expressions
- All flows (normal and suspicious)
- Capture statistics

## 🚀 Usage

### Option 1: Standalone Network Monitor

```bash
# Analyze a network event file
python network_monitor.py --input data/network_traffic_event.json

# Simulate live traffic capture (default 10 seconds)
python network_monitor.py --live

# Capture for 30 seconds
python network_monitor.py --live --duration 30

# Maximum capture duration (60 seconds / 1 minute)
python network_monitor.py --live --duration 60
```

### Option 2: Integrated with Main System

```bash
# Analyze network events through main system
python src/main.py --input data/network_traffic_event.json
```

### Option 3: Streamlit UI

```bash
# Use the web interface
streamlit run app.py
# Navigate to "Network Monitor" from the sidebar
# Choose "Live Traffic Simulation"
# Use the slider to set capture duration (5-60 seconds)
# Click "Start Live Capture"
```

## 📋 Sample Network Event

```json
{
  "event_id": "evt_004_suspicious_network",
  "timestamp": "2025-10-07T14:30:00",
  "source": "network_monitor",
  "event_type": "suspicious_connection",
  "raw_data": {
    "protocol": "tcp",
    "source_port": 49152,
    "destination_port": 4444,
    "packet_count": 150,
    "bytes_transferred": 225000,
    "payload_analysis": {
      "encrypted": true,
      "suspicious_patterns": ["shell", "cmd", "exec"]
    }
  },
  "source_ip": "192.168.1.100",
  "destination_ip": "185.220.101.50"
}
```

## 🔍 Detection Capabilities

### Suspicious Indicators
- **Unusual Ports:** 4444, 31337, 1337, 6667, 6666
- **Known Malicious IPs:** Pattern matching against threat intelligence
- **High Packet Rates:** Abnormal traffic volumes
- **Protocol Anomalies:** Unexpected protocol usage
- **Payload Patterns:** Suspicious command strings

### Anomaly Scoring
The system calculates anomaly scores (0.0 - 1.0) based on:
- Port reputation
- IP reputation
- Traffic volume
- Protocol patterns
- Payload analysis

## 🎨 Output Examples

### Network Capture Results
```
📡 Network Capture Results
Capture ID: abc123...
Interface: eth0
Duration: 5.23s
Total Packets: 150
Total Flows: 3
Suspicious Flows: 1

⚠️  Suspicious Flows Detected:
┌──────────┬─────────────────┬─────────────────┬──────────┬─────────┬───────────────┐
│ Flow ID  │ Source          │ Destination     │ Protocol │ Packets │ Anomaly Score │
├──────────┼─────────────────┼─────────────────┼──────────┼─────────┼───────────────┤
│ def456...│ 192.168.1.100:..│ 185.220.101.50:4│ TCP      │ 150     │ 0.80          │
└──────────┴─────────────────┴─────────────────┴──────────┴─────────┴───────────────┘
```

### Analysis Results
```
🔬 Network Analysis Results

⚠️  THREAT DETECTED
Detection ID: ghi789...
Confidence: 85.00%
Method: AI-based network analysis

Threat Indicators:
  • Suspicious destination port: 4444
  • Known malicious IP pattern: 185.
  • High packet count: 150
  • Encrypted payload with suspicious patterns
```

## 🔧 Real-World Integration

### With Scapy (for actual packet capture)
```python
from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if IP in packet:
        # Convert to NetworkPacket
        network_packet = NetworkPacket(
            packet_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            protocol=get_protocol(packet),
            source_ip=packet[IP].src,
            destination_ip=packet[IP].dst,
            packet_size=len(packet)
        )
        # Process packet...

# Capture packets
sniff(prn=packet_callback, count=100)
```

### With PyShark (for deep packet inspection)
```python
import pyshark

capture = pyshark.LiveCapture(interface='eth0')
for packet in capture.sniff_continuously(packet_count=100):
    # Analyze packet
    analyze_packet(packet)
```

## 📊 Performance Considerations

### Capture Performance
- **Duration Control:** User-configurable capture time (5-60 seconds)
- **Buffer Size:** Configurable packet buffer
- **Filter Expressions:** BPF filters to reduce load
- **Sampling:** Capture every Nth packet for high-volume networks
- **Flow Aggregation:** Group packets into flows to reduce memory
- **Dynamic Scaling:** Packet counts scale linearly with duration

### Analysis Performance
- **Batch Processing:** Analyze flows in batches
- **Async Processing:** Non-blocking analysis
- **Caching:** Cache threat intelligence lookups
- **Parallel Analysis:** Multi-threaded flow analysis

## 🛡️ Security Best Practices

1. **Permissions:** Packet capture requires elevated privileges
2. **Privacy:** Be mindful of capturing sensitive data
3. **Compliance:** Follow data retention policies
4. **Encryption:** Secure storage of captured data
5. **Access Control:** Restrict access to capture data

## 🔮 Future Enhancements

- [ ] Real-time packet capture with Scapy
- [ ] Deep packet inspection
- [ ] Protocol-specific analyzers (HTTP, DNS, TLS)
- [ ] Machine learning-based anomaly detection
- [ ] Integration with threat intelligence feeds
- [ ] Geolocation analysis
- [ ] Network baseline profiling
- [ ] Automated PCAP file analysis
- [ ] Real-time alerting and notifications
- [ ] Network topology mapping

## 📚 Dependencies

For full packet capture capabilities, install:

```bash
# Packet capture
pip install scapy pyshark

# Network analysis
pip install dpkt pcapy

# Optional: For better performance
pip install python-libpcap
```

## 🎓 Learning Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [PyShark Documentation](https://kiminewt.github.io/pyshark/)
- [Network Traffic Analysis](https://www.sans.org/white-papers/)
- [Wireshark User Guide](https://www.wireshark.org/docs/)

## 🤝 Contributing

To add new network analysis features:

1. Extend `NetworkPacket` or `NetworkFlow` models
2. Add new detection logic to `NetworkCaptureAgent`
3. Enhance analysis prompts in `NetworkAnalysisAgent`
4. Add new protocol support
5. Submit a pull request

---

**Happy Network Hunting!** 🌐🔍
