# PCAP Capture & Analysis

## 📦 Overview

The network capture agent now supports **PCAP file generation** for all captured network traffic. This allows you to:
- Save captured packets for later analysis
- Share captures with security teams
- Analyze captures with external tools (Wireshark, tcpdump, etc.)
- Maintain forensic evidence

## 🎯 Features

### Automatic PCAP Generation
- **Enabled by default** - All captures automatically save to PCAP files
- **Configurable** - Can be disabled via UI checkbox or agent parameter
- **Organized storage** - Files saved to `captures/` directory
- **Timestamped filenames** - Format: `capture_YYYYMMDD_HHMMSS_<id>.pcap`

### File Formats
- **With Scapy**: Real PCAP files compatible with Wireshark
- **Without Scapy**: JSON metadata files with capture information

### Download Capability
- **Direct download** from Streamlit UI
- **One-click access** to captured PCAP files
- **Forensic preservation** for incident response

## 🚀 Usage

### Option 1: Streamlit UI (Recommended)

```bash
streamlit run app.py
```

1. Navigate to **Network Monitor** → **Live Traffic Simulation (Full Pipeline)**
2. Configure capture settings:
   - **Interface**: eth0, wlan0, lo, or any
   - **Duration**: 5-180 seconds
   - **Packet Limit**: Up to 1,000,000 packets
   - **💾 Save PCAP file**: ✅ (checked by default)
3. Click **"Start Full Pipeline Analysis"**
4. After capture completes, click **"📥 Download PCAP"** button

### Option 2: Python API

```python
from src.agents.network_capture_agent import NetworkCaptureAgent
from src.models.schemas import AgentState

# Initialize with PCAP saving enabled
agent = NetworkCaptureAgent(
    capture_duration=30,
    max_packets=100000,
    save_pcap=True  # Enable PCAP saving
)

# Create initial state
state = AgentState(current_stage="network_capture")

# Capture traffic
result_state = agent.capture(state, duration=30)

# Access PCAP file path
if result_state.network_capture and result_state.network_capture.pcap_file:
    print(f"PCAP saved to: {result_state.network_capture.pcap_file}")
```

### Option 3: Real Packet Capture (Requires Scapy + Permissions)

```python
from src.agents.network_capture_agent import NetworkCaptureAgent

agent = NetworkCaptureAgent(save_pcap=True)

# Capture live traffic (requires sudo/admin)
capture = agent.capture_live_traffic(
    interface="eth0",
    duration=10,
    packet_count=1000,
    bpf_filter="tcp port 443"  # Optional filter
)

print(f"Captured {capture.packets_captured} packets")
```

## 📁 File Structure

```
Praveen_Capstone1/
├── captures/                           # PCAP storage directory
│   ├── capture_20251007_163000_abc123.pcap
│   ├── capture_20251007_164500_def456.pcap
│   └── capture_20251007_165000_ghi789.json  # Metadata (if scapy unavailable)
└── ...
```

## 🔧 Installation

### For Full PCAP Support (Recommended)

```bash
# Install scapy for real PCAP file generation
pip install scapy

# On macOS, you may need:
brew install libpcap

# On Linux:
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel     # RedHat/CentOS
```

### Without Scapy (Metadata Only)

The system works without scapy but will generate JSON metadata files instead of PCAP files:

```json
{
  "capture_id": "abc123...",
  "start_time": "2025-10-07T16:30:00",
  "end_time": "2025-10-07T16:30:10",
  "interface": "eth0",
  "packets_captured": 1523,
  "flows_count": 5,
  "suspicious_flows": 2,
  "note": "Scapy not installed - this is a metadata file"
}
```

## 📊 PCAP File Contents

### With Scapy Installed
- **Format**: Standard PCAP (libpcap format)
- **Compatible with**: Wireshark, tcpdump, tshark, etc.
- **Contains**: 
  - Ethernet frames
  - IP packets (source/destination)
  - TCP/UDP segments
  - Protocol-specific data

### Example Analysis with Wireshark

```bash
# Open in Wireshark
wireshark captures/capture_20251007_163000_abc123.pcap

# Or use tcpdump
tcpdump -r captures/capture_20251007_163000_abc123.pcap

# Filter for suspicious traffic
tcpdump -r captures/capture_20251007_163000_abc123.pcap 'dst port 4444'
```

## 🔒 Security & Privacy

### Best Practices
1. **Secure Storage**: PCAP files may contain sensitive data
2. **Access Control**: Restrict access to `captures/` directory
3. **Retention Policy**: Implement automatic cleanup of old captures
4. **Encryption**: Consider encrypting PCAP files at rest
5. **Compliance**: Ensure PCAP capture complies with privacy regulations

### Cleanup Script

```python
# cleanup_old_captures.py
import os
from pathlib import Path
from datetime import datetime, timedelta

def cleanup_old_captures(days=30):
    """Remove PCAP files older than specified days."""
    captures_dir = Path("captures")
    cutoff_date = datetime.now() - timedelta(days=days)
    
    for pcap_file in captures_dir.glob("*.pcap"):
        if datetime.fromtimestamp(pcap_file.stat().st_mtime) < cutoff_date:
            pcap_file.unlink()
            print(f"Deleted: {pcap_file}")

if __name__ == "__main__":
    cleanup_old_captures(days=30)
```

## 🎓 Advanced Usage

### Custom PCAP Processing

```python
from scapy.all import rdpcap, IP, TCP

# Read PCAP file
packets = rdpcap("captures/capture_20251007_163000_abc123.pcap")

# Analyze packets
for packet in packets:
    if IP in packet and TCP in packet:
        print(f"{packet[IP].src}:{packet[TCP].sport} → "
              f"{packet[IP].dst}:{packet[TCP].dport}")
```

### Integration with SIEM

```python
# Export to SIEM-friendly format
import json

def export_pcap_metadata(pcap_file):
    """Export PCAP metadata for SIEM ingestion."""
    from scapy.all import rdpcap
    
    packets = rdpcap(pcap_file)
    
    metadata = {
        "file": str(pcap_file),
        "packet_count": len(packets),
        "protocols": list(set(pkt.name for pkt in packets)),
        "timestamp": datetime.now().isoformat()
    }
    
    return json.dumps(metadata)
```

## 📈 Performance Considerations

### File Sizes
- **Small capture (10s, 100 packets)**: ~10-50 KB
- **Medium capture (60s, 1000 packets)**: ~100-500 KB
- **Large capture (180s, 100k packets)**: ~10-50 MB
- **Maximum capture (180s, 1M packets)**: ~100-500 MB

### Optimization Tips
1. **Use BPF filters** to capture only relevant traffic
2. **Limit packet count** for high-traffic interfaces
3. **Implement rotation** for long-running captures
4. **Compress old files** to save disk space

## 🐛 Troubleshooting

### "Scapy not installed"
```bash
pip install scapy
```

### "Permission denied" (Linux/macOS)
```bash
# Run with sudo for packet capture
sudo python network_monitor.py --live

# Or set capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
```

### "PCAP file not found"
- Check that `captures/` directory exists
- Verify `save_pcap=True` in agent initialization
- Check logs for save errors

### "Cannot open PCAP in Wireshark"
- Ensure scapy is installed
- Verify file is not a JSON metadata file
- Check file permissions

## 📚 Additional Resources

- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [PCAP File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [BPF Filter Syntax](https://biot.com/capstats/bpf.html)

---

**Note**: PCAP capture is a powerful forensic tool. Always ensure you have proper authorization before capturing network traffic in production environments.
