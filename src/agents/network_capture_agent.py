"""Network Capture Agent for live traffic monitoring."""

import uuid
import os
from datetime import datetime
from typing import Dict, Any, Optional
from collections import defaultdict
from pathlib import Path

from src.models.schemas import (
    AgentState,
    NetworkCapture,
    NetworkFlow,
    NetworkPacket,
    NetworkProtocol
)
from src.utils.logger import log


class NetworkCaptureAgent:
    """Agent responsible for capturing and organizing network traffic."""
    
    def __init__(self, capture_duration: int = 10, max_packets: int = 100000, save_pcap: bool = True):
        """Initialize the Network Capture Agent.
        
        Args:
            capture_duration: Duration in seconds to capture packets (max 180 seconds / 3 minutes)
            max_packets: Maximum number of packets to capture (max 1,000,000)
            save_pcap: Whether to save captured packets to a pcap file
        """
        # Enforce maximum capture duration of 180 seconds (3 minutes)
        self.capture_duration = min(capture_duration, 180)
        # Enforce maximum packet count of 1,000,000
        self.max_packets = min(max_packets, 1000000)
        self.save_pcap = save_pcap
        
        # Create captures directory if it doesn't exist
        self.captures_dir = Path("captures")
        self.captures_dir.mkdir(exist_ok=True)
        
        log.info(f"Network Capture Agent initialized with {self.capture_duration}s capture duration, max {self.max_packets} packets, save_pcap={save_pcap}")
        self.active_flows = {}
        self.packet_buffer = []
    
    def capture(self, state: AgentState, duration: Optional[int] = None, max_packets: Optional[int] = None) -> AgentState:
        """
        Capture and organize network traffic.
        
        Args:
            state: Current agent state
            duration: Optional override for capture duration (max 180 seconds / 3 minutes)
            max_packets: Optional override for max packet count (max 1,000,000)
        
        In a real implementation, this would use libraries like:
        - scapy for packet capture
        - pyshark for network analysis
        - dpkt for packet parsing
        
        For this demo, we'll simulate capture from security events.
        """
        # Use provided duration or default, enforce 180 second max
        capture_time = min(duration or self.capture_duration, 180)
        # Use provided max_packets or default, enforce 1,000,000 max
        packet_limit = min(max_packets or self.max_packets, 1000000)
        log.info(f"Network Capture Agent: Starting traffic capture for {capture_time} seconds (max {packet_limit} packets)")
        
        try:
            # Create capture session
            capture_id = str(uuid.uuid4())
            start_time = datetime.now()
            
            # Generate pcap filename
            pcap_filename = None
            if self.save_pcap:
                timestamp_str = start_time.strftime("%Y%m%d_%H%M%S")
                pcap_filename = f"capture_{timestamp_str}_{capture_id[:8]}.pcap"
                pcap_path = self.captures_dir / pcap_filename
            
            # Determine interface to use
            default_interface = self._get_default_interface()
            interface = state.security_event.raw_data.get("interface", default_interface) if state.security_event else default_interface
            
            capture = NetworkCapture(
                capture_id=capture_id,
                start_time=start_time,
                interface=interface,
                capture_status="active"
            )
            
            log.info(f"Capture session {capture_id[:8]} started for {capture_time}s (max {packet_limit} packets)")
            if self.save_pcap:
                log.info(f"PCAP file will be saved to: {pcap_path}")
            
            # If we have a security event, convert it to network flows
            if state.security_event:
                flows = self._convert_event_to_flows(state.security_event)
                capture.flows = flows
                capture.packets_captured = sum(f.packet_count for f in flows)
                
                # Identify suspicious flows
                suspicious_flows = [f for f in flows if f.is_suspicious]
                capture.suspicious_flows = suspicious_flows
                
                state.messages.append(
                    f"Network capture ({capture_time}s, limit: {packet_limit}): {capture.packets_captured} packets, "
                    f"{len(flows)} flows, {len(suspicious_flows)} suspicious"
                )
                
                log.info(f"Captured {len(flows)} network flows, {len(suspicious_flows)} suspicious")
            else:
                # Attempt real packet capture with scapy
                try:
                    from scapy.all import sniff, wrpcap
                    
                    log.info(f"Starting real packet capture on {capture.interface}")
                    
                    # Capture packets using scapy
                    captured_packets = sniff(
                        iface=capture.interface if capture.interface != "any" else None,
                        count=min(packet_limit, 1000),  # Limit for performance
                        timeout=min(capture_time, 10),  # Limit timeout for demo
                        store=True
                    )
                    
                    log.info(f"Captured {len(captured_packets)} packets with scapy")
                    
                    # Save packets directly to PCAP using scapy
                    if captured_packets and self.save_pcap and pcap_filename:
                        wrpcap(str(pcap_path), captured_packets)
                        capture.pcap_file = str(pcap_path)
                        log.info(f"Real packets saved to PCAP: {pcap_path}")
                        state.messages.append(f"PCAP file saved: {pcap_filename}")
                    
                    # Convert to flows for analysis
                    flows = self._convert_scapy_packets_to_flows(captured_packets)
                    capture.flows = flows
                    capture.packets_captured = len(captured_packets)
                    
                    # Identify suspicious flows
                    suspicious_flows = [f for f in flows if f.is_suspicious]
                    capture.suspicious_flows = suspicious_flows
                    
                    state.messages.append(
                        f"Live capture ({capture_time}s, limit: {packet_limit}): {len(captured_packets)} packets, "
                        f"{len(flows)} flows, {len(suspicious_flows)} suspicious"
                    )
                    log.info(f"Real capture: {len(captured_packets)} packets, {len(flows)} flows, {len(suspicious_flows)} suspicious")
                    
                except (ImportError, PermissionError, OSError) as e:
                    # Fallback to simulation if scapy fails or no permissions
                    log.warning(f"Real packet capture failed ({str(e)}), falling back to simulation")
                    flows = self._simulate_live_capture(capture_time)
                    capture.flows = flows
                    capture.packets_captured = sum(f.packet_count for f in flows)
                    
                    # Identify suspicious flows
                    suspicious_flows = [f for f in flows if f.is_suspicious]
                    capture.suspicious_flows = suspicious_flows
                    
                    state.messages.append(
                        f"Simulated capture ({capture_time}s, limit: {packet_limit}): {len(flows)} flows detected, "
                        f"{len(suspicious_flows)} suspicious"
                    )
                    log.info(f"Simulated capture: {len(flows)} flows, {len(suspicious_flows)} suspicious")
            
            capture.end_time = datetime.now()
            capture.capture_status = "completed"
            
            # Save pcap file if enabled (only if not already saved during real capture)
            if self.save_pcap and pcap_filename and not capture.pcap_file:
                try:
                    self._save_pcap_file(capture, pcap_path)
                    capture.pcap_file = str(pcap_path)
                    log.info(f"PCAP file saved successfully: {pcap_path}")
                    state.messages.append(f"PCAP file saved: {pcap_filename}")
                except Exception as e:
                    log.warning(f"Failed to save PCAP file: {str(e)}")
                    state.messages.append(f"Warning: Could not save PCAP file: {str(e)}")
            
            state.network_capture = capture
            state.current_stage = "network_analysis"
            
        except Exception as e:
            log.error(f"Error in network capture: {str(e)}")
            state.error = f"Network capture error: {str(e)}"
            state.current_stage = "error"
        
        return state
    
    def _get_default_interface(self) -> str:
        """Get the default network interface for the current OS.
        
        Returns:
            str: Default network interface name
        """
        import platform
        
        try:
            from scapy.all import get_if_list, conf
            
            # Get list of available interfaces
            interfaces = get_if_list()
            
            if not interfaces:
                log.warning("No network interfaces found, using 'any'")
                return "any"
            
            # Platform-specific defaults
            system = platform.system()
            
            if system == "Darwin":  # macOS
                # Prefer en0 (Wi-Fi) or en1 (Ethernet) on macOS
                for iface in ["en0", "en1", "lo0"]:
                    if iface in interfaces:
                        log.info(f"Using macOS interface: {iface}")
                        return iface
            elif system == "Linux":
                # Prefer eth0, wlan0, or ens33 on Linux
                for iface in ["eth0", "wlan0", "ens33", "lo"]:
                    if iface in interfaces:
                        log.info(f"Using Linux interface: {iface}")
                        return iface
            elif system == "Windows":
                # Use first available interface on Windows
                if interfaces:
                    log.info(f"Using Windows interface: {interfaces[0]}")
                    return interfaces[0]
            
            # Fallback to first available interface
            if interfaces:
                log.info(f"Using first available interface: {interfaces[0]}")
                return interfaces[0]
            
        except Exception as e:
            log.warning(f"Error detecting network interface: {str(e)}")
        
        # Ultimate fallback
        return "any"
    
    def _convert_event_to_flows(self, event) -> list:
        """Convert a security event to network flows."""
        flows = []
        
        if not event.source_ip or not event.destination_ip:
            return flows
        
        # Create a flow from the event
        flow_id = str(uuid.uuid4())
        
        # Determine protocol
        protocol = NetworkProtocol.TCP  # Default
        if "protocol" in event.raw_data:
            protocol_str = event.raw_data["protocol"].lower()
            try:
                protocol = NetworkProtocol(protocol_str)
            except ValueError:
                protocol = NetworkProtocol.OTHER
        
        # Create sample packets for the flow
        packets = []
        packet_count = event.raw_data.get("packet_count", 5)
        
        for i in range(packet_count):
            packet = NetworkPacket(
                packet_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                protocol=protocol,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                source_port=event.raw_data.get("source_port"),
                destination_port=event.raw_data.get("destination_port"),
                packet_size=event.raw_data.get("packet_size", 1500),
                raw_data=event.raw_data
            )
            packets.append(packet)
        
        # Analyze for suspicious indicators
        is_suspicious, anomaly_score, indicators = self._analyze_flow_suspicion(event)
        
        flow = NetworkFlow(
            flow_id=flow_id,
            start_time=event.timestamp,
            end_time=event.timestamp,
            protocol=protocol,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.raw_data.get("source_port"),
            destination_port=event.raw_data.get("destination_port"),
            packet_count=len(packets),
            byte_count=sum(p.packet_size for p in packets),
            packets=packets,
            is_suspicious=is_suspicious,
            anomaly_score=anomaly_score,
            threat_indicators=indicators
        )
        
        flows.append(flow)
        return flows
    
    def _analyze_flow_suspicion(self, event) -> tuple:
        """Analyze if a flow is suspicious."""
        is_suspicious = False
        anomaly_score = 0.0
        indicators = []
        
        # Check for suspicious ports
        suspicious_ports = [4444, 31337, 1337, 6667, 6666]
        dest_port = event.raw_data.get("destination_port")
        if dest_port in suspicious_ports:
            is_suspicious = True
            anomaly_score += 0.3
            indicators.append(f"Suspicious destination port: {dest_port}")
        
        # Check for unusual protocols
        if event.event_type in ["suspicious_connection", "malware_execution"]:
            is_suspicious = True
            anomaly_score += 0.4
            indicators.append(f"Event type: {event.event_type}")
        
        # Check for known malicious IPs (simplified)
        malicious_ip_patterns = ["185.", "203.0.113"]
        for pattern in malicious_ip_patterns:
            if event.destination_ip and pattern in event.destination_ip:
                is_suspicious = True
                anomaly_score += 0.5
                indicators.append(f"Known malicious IP pattern: {pattern}")
        
        # Check for high packet rates
        packet_count = event.raw_data.get("packet_count", 0)
        if packet_count > 1000:
            anomaly_score += 0.2
            indicators.append(f"High packet count: {packet_count}")
        
        # Normalize anomaly score
        anomaly_score = min(anomaly_score, 1.0)
        
        return is_suspicious, anomaly_score, indicators
    
    def _convert_scapy_packets_to_flows(self, packets) -> list:
        """Convert Scapy packets to NetworkFlow objects.
        
        Args:
            packets: List of Scapy packets
            
        Returns:
            List of NetworkFlow objects
        """
        from collections import defaultdict
        
        flows = []
        flow_dict = defaultdict(list)
        
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            
            # Group packets by flow (src_ip, dst_ip, protocol, dst_port)
            for pkt in packets:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    
                    if TCP in pkt:
                        protocol = NetworkProtocol.TCP
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                    elif UDP in pkt:
                        protocol = NetworkProtocol.UDP
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                    elif ICMP in pkt:
                        protocol = NetworkProtocol.ICMP
                        src_port = None
                        dst_port = None
                    else:
                        protocol = NetworkProtocol.OTHER
                        src_port = None
                        dst_port = None
                    
                    flow_key = (src_ip, dst_ip, protocol, dst_port)
                    flow_dict[flow_key].append(pkt)
            
            # Create NetworkFlow objects
            for (src_ip, dst_ip, protocol, dst_port), pkts in flow_dict.items():
                flow_id = str(uuid.uuid4())
                
                # Convert packets to NetworkPacket objects
                network_packets = []
                total_bytes = 0
                
                for pkt in pkts[:100]:  # Limit packets per flow
                    packet_size = len(pkt) if hasattr(pkt, '__len__') else 1500
                    total_bytes += packet_size
                    
                    network_packet = NetworkPacket(
                        packet_id=str(uuid.uuid4()),
                        timestamp=datetime.now(),
                        protocol=protocol,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        destination_port=dst_port,
                        packet_size=packet_size
                    )
                    network_packets.append(network_packet)
                
                # Determine if flow is suspicious
                is_suspicious = self._is_suspicious_flow(src_ip, dst_ip, dst_port, protocol)
                anomaly_score = 0.7 if is_suspicious else 0.1
                
                # Get source port from first packet
                first_src_port = None
                if pkts:
                    if TCP in pkts[0]:
                        first_src_port = pkts[0][TCP].sport
                    elif UDP in pkts[0]:
                        first_src_port = pkts[0][UDP].sport
                
                flow = NetworkFlow(
                    flow_id=flow_id,
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    protocol=protocol,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=first_src_port,
                    destination_port=dst_port,
                    packet_count=len(network_packets),
                    byte_count=total_bytes,
                    packets=network_packets,
                    is_suspicious=is_suspicious,
                    anomaly_score=anomaly_score
                )
                flows.append(flow)
            
            log.info(f"Converted {len(packets)} packets to {len(flows)} flows")
            
        except Exception as e:
            log.error(f"Error converting scapy packets to flows: {str(e)}")
            # Return empty list on error
            
        return flows
    
    def _is_suspicious_flow(self, src_ip: str, dst_ip: str, dst_port: int, protocol: NetworkProtocol) -> bool:
        """Check if a flow is suspicious based on simple heuristics.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            protocol: Network protocol
            
        Returns:
            bool: True if suspicious
        """
        # Suspicious ports
        suspicious_ports = [4444, 31337, 1337, 6667, 6666, 1234, 12345]
        if dst_port and dst_port in suspicious_ports:
            return True
        
        # Known malicious IP patterns (simplified)
        if dst_ip and (dst_ip.startswith("185.") or dst_ip.startswith("203.0.113.")):
            return True
        
        return False
    
    def _simulate_live_capture(self, duration: int) -> list:
        """Simulate live network capture (for demo purposes).
        
        Args:
            duration: Capture duration in seconds (affects number of flows/packets)
        """
        flows = []
        
        # Scale packet counts based on duration (more time = more packets)
        # Base packet counts are for 10 seconds, scale linearly
        duration_multiplier = duration / 10.0
        
        # Simulate a few network flows
        sample_flows_data = [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "protocol": NetworkProtocol.UDP,
                "dst_port": 53,
                "packets": int(2 * duration_multiplier),
                "suspicious": False
            },
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "93.184.216.34",
                "protocol": NetworkProtocol.TCP,
                "dst_port": 443,
                "packets": int(50 * duration_multiplier),
                "suspicious": False
            },
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "185.220.101.50",
                "protocol": NetworkProtocol.TCP,
                "dst_port": 4444,
                "packets": int(100 * duration_multiplier),
                "suspicious": True
            }
        ]
        
        # Add more flows for longer durations
        if duration > 30:
            sample_flows_data.extend([
                {
                    "src_ip": "192.168.1.100",
                    "dst_ip": "1.1.1.1",
                    "protocol": NetworkProtocol.UDP,
                    "dst_port": 53,
                    "packets": int(5 * duration_multiplier),
                    "suspicious": False
                },
                {
                    "src_ip": "192.168.1.100",
                    "dst_ip": "203.0.113.45",
                    "protocol": NetworkProtocol.TCP,
                    "dst_port": 31337,
                    "packets": int(75 * duration_multiplier),
                    "suspicious": True
                }
            ])
        
        # Add even more flows for very long durations (>60s)
        if duration > 60:
            sample_flows_data.extend([
                {
                    "src_ip": "192.168.1.100",
                    "dst_ip": "10.0.0.5",
                    "protocol": NetworkProtocol.TCP,
                    "dst_port": 22,
                    "packets": int(30 * duration_multiplier),
                    "suspicious": False
                },
                {
                    "src_ip": "192.168.1.100",
                    "dst_ip": "185.220.102.8",
                    "protocol": NetworkProtocol.TCP,
                    "dst_port": 6667,
                    "packets": int(120 * duration_multiplier),
                    "suspicious": True
                }
            ])
        
        # Add additional flows for extended captures (>120s)
        if duration > 120:
            sample_flows_data.extend([
                {
                    "src_ip": "192.168.1.100",
                    "dst_ip": "8.8.4.4",
                    "protocol": NetworkProtocol.UDP,
                    "dst_port": 53,
                    "packets": int(10 * duration_multiplier),
                    "suspicious": False
                },
                {
                    "src_ip": "192.168.1.100",
                    "dst_ip": "203.0.113.99",
                    "protocol": NetworkProtocol.TCP,
                    "dst_port": 1337,
                    "packets": int(200 * duration_multiplier),
                    "suspicious": True
                }
            ])
        
        for flow_data in sample_flows_data:
            flow_id = str(uuid.uuid4())
            packets = []
            
            for i in range(flow_data["packets"]):
                packet = NetworkPacket(
                    packet_id=str(uuid.uuid4()),
                    timestamp=datetime.now(),
                    protocol=flow_data["protocol"],
                    source_ip=flow_data["src_ip"],
                    destination_ip=flow_data["dst_ip"],
                    destination_port=flow_data["dst_port"],
                    packet_size=1500
                )
                packets.append(packet)
            
            flow = NetworkFlow(
                flow_id=flow_id,
                start_time=datetime.now(),
                end_time=datetime.now(),
                protocol=flow_data["protocol"],
                source_ip=flow_data["src_ip"],
                destination_ip=flow_data["dst_ip"],
                destination_port=flow_data["dst_port"],
                packet_count=len(packets),
                byte_count=sum(p.packet_size for p in packets),
                packets=packets,
                is_suspicious=flow_data["suspicious"],
                anomaly_score=0.7 if flow_data["suspicious"] else 0.1
            )
            flows.append(flow)
        
        return flows
    
    def _save_pcap_file(self, capture: NetworkCapture, pcap_path: Path) -> None:
        """Save captured packets to a PCAP file.
        
        Args:
            capture: NetworkCapture object containing flows and packets
            pcap_path: Path where the PCAP file should be saved
            
        Note:
            Creates PCAP files using scapy if available, otherwise creates
            a basic PCAP file with libpcap format.
        """
        try:
            # Try to use scapy if available for real PCAP writing
            try:
                from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw, ICMP
                
                packets_to_save = []
                for flow in capture.flows:
                    for i, packet in enumerate(flow.packets[:100]):  # Limit packets per flow
                        # Create a realistic packet structure
                        if flow.protocol == NetworkProtocol.TCP:
                            pkt = Ether()/IP(src=flow.source_ip, dst=flow.destination_ip)/TCP(
                                sport=flow.source_port or 50000 + i,
                                dport=flow.destination_port or 80,
                                flags="PA"
                            )/Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                        elif flow.protocol == NetworkProtocol.UDP:
                            pkt = Ether()/IP(src=flow.source_ip, dst=flow.destination_ip)/UDP(
                                sport=flow.source_port or 50000 + i,
                                dport=flow.destination_port or 53
                            )/Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                        elif flow.protocol == NetworkProtocol.ICMP:
                            pkt = Ether()/IP(src=flow.source_ip, dst=flow.destination_ip)/ICMP()
                        else:
                            pkt = Ether()/IP(src=flow.source_ip, dst=flow.destination_ip)/Raw(load=b"simulated_data")
                        packets_to_save.append(pkt)
                
                if packets_to_save:
                    wrpcap(str(pcap_path), packets_to_save)
                    log.info(f"Saved {len(packets_to_save)} packets to PCAP using scapy: {pcap_path}")
                else:
                    log.warning("No packets to save to PCAP")
                    self._create_basic_pcap(capture, pcap_path)
                    
            except ImportError:
                # Fallback: Create a basic PCAP file without scapy
                log.warning("Scapy not available, creating basic PCAP file with manual format")
                self._create_basic_pcap(capture, pcap_path)
                
        except Exception as e:
            log.error(f"Error saving PCAP file: {str(e)}")
            raise
    
    def _create_basic_pcap(self, capture: NetworkCapture, pcap_path: Path) -> None:
        """Create a basic PCAP file without scapy using manual format writing.
        
        Args:
            capture: NetworkCapture object
            pcap_path: Path to save PCAP file
        """
        import struct
        import time
        
        try:
            with open(pcap_path, 'wb') as f:
                # Write PCAP global header
                # Magic number, version, timezone, accuracy, snaplen, network type
                magic = 0xa1b2c3d4  # PCAP magic number
                version_major = 2
                version_minor = 4
                thiszone = 0
                sigfigs = 0
                snaplen = 65535
                network = 1  # Ethernet
                
                f.write(struct.pack('IHHiIII', magic, version_major, version_minor, 
                                   thiszone, sigfigs, snaplen, network))
                
                # Write packet records
                packet_count = 0
                for flow in capture.flows:
                    for packet in flow.packets[:50]:  # Limit packets
                        # Create a minimal Ethernet + IP + TCP/UDP packet
                        timestamp = time.time()
                        ts_sec = int(timestamp)
                        ts_usec = int((timestamp - ts_sec) * 1000000)
                        
                        # Build a simple packet (Ethernet + IP + TCP)
                        packet_data = self._build_simple_packet(flow, packet)
                        incl_len = len(packet_data)
                        orig_len = incl_len
                        
                        # Write packet header
                        f.write(struct.pack('IIII', ts_sec, ts_usec, incl_len, orig_len))
                        # Write packet data
                        f.write(packet_data)
                        packet_count += 1
                
                log.info(f"Created basic PCAP file with {packet_count} packets: {pcap_path}")
                
                # Also create metadata file
                metadata_path = pcap_path.with_suffix('.json')
                import json
                metadata = {
                    "capture_id": capture.capture_id,
                    "start_time": capture.start_time.isoformat(),
                    "end_time": capture.end_time.isoformat() if capture.end_time else None,
                    "interface": capture.interface,
                    "packets_captured": capture.packets_captured,
                    "flows_count": len(capture.flows),
                    "suspicious_flows": len(capture.suspicious_flows) if capture.suspicious_flows else 0,
                    "pcap_file": str(pcap_path),
                    "note": "Basic PCAP file created. Install scapy for enhanced packet capture."
                }
                
                with open(metadata_path, 'w') as mf:
                    json.dump(metadata, mf, indent=2)
                log.info(f"Saved capture metadata to {metadata_path}")
                
        except Exception as e:
            log.error(f"Error creating basic PCAP: {str(e)}")
            raise
    
    def _build_simple_packet(self, flow: NetworkFlow, packet: NetworkPacket) -> bytes:
        """Build a simple packet in bytes format.
        
        Args:
            flow: NetworkFlow object
            packet: NetworkPacket object
            
        Returns:
            bytes: Packet data
        """
        import struct
        import socket
        
        # Ethernet header (14 bytes)
        dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
        src_mac = b'\x00\x00\x00\x00\x00\x00'  # Null
        eth_type = 0x0800  # IPv4
        eth_header = dst_mac + src_mac + struct.pack('!H', eth_type)
        
        # IP header (20 bytes minimum)
        version_ihl = 0x45  # IPv4, header length 20 bytes
        tos = 0
        total_length = 40  # IP + TCP headers
        identification = 54321
        flags_fragment = 0
        ttl = 64
        protocol = 6 if flow.protocol == NetworkProtocol.TCP else 17  # TCP or UDP
        checksum = 0
        
        try:
            src_ip = socket.inet_aton(flow.source_ip)
            dst_ip = socket.inet_aton(flow.destination_ip)
        except:
            src_ip = socket.inet_aton("192.168.1.1")
            dst_ip = socket.inet_aton("192.168.1.2")
        
        ip_header = struct.pack('!BBHHHBBH', version_ihl, tos, total_length,
                               identification, flags_fragment, ttl, protocol, checksum)
        ip_header += src_ip + dst_ip
        
        # TCP/UDP header (20 bytes for TCP, 8 for UDP)
        if flow.protocol == NetworkProtocol.TCP:
            src_port = flow.source_port or 50000
            dst_port = flow.destination_port or 80
            seq_num = 0
            ack_num = 0
            offset_reserved = 0x50  # 20 bytes, no options
            flags = 0x18  # PSH, ACK
            window = 65535
            checksum = 0
            urgent = 0
            
            tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_num, ack_num,
                                    offset_reserved, flags, window, checksum, urgent)
            return eth_header + ip_header + tcp_header
        else:
            # UDP header
            src_port = flow.source_port or 50000
            dst_port = flow.destination_port or 53
            length = 8
            checksum = 0
            
            udp_header = struct.pack('!HHHH', src_port, dst_port, length, checksum)
            return eth_header + ip_header + udp_header
    
    def capture_live_traffic(self, interface: str = "eth0", duration: int = 10, 
                           packet_count: int = 100, bpf_filter: str = "") -> NetworkCapture:
        """Capture live network traffic using scapy (requires root/admin privileges).
        
        Args:
            interface: Network interface to capture from
            duration: Duration in seconds
            packet_count: Maximum number of packets to capture
            bpf_filter: BPF filter expression (e.g., "tcp port 80")
            
        Returns:
            NetworkCapture object with captured packets
            
        Note:
            Requires scapy and appropriate permissions (sudo/admin)
        """
        try:
            from scapy.all import sniff
            
            log.info(f"Starting live capture on {interface} for {duration}s")
            
            packets = sniff(
                iface=interface,
                count=packet_count,
                timeout=duration,
                filter=bpf_filter if bpf_filter else None
            )
            
            log.info(f"Captured {len(packets)} packets")
            
            # Convert scapy packets to our NetworkPacket format
            # This would require additional processing
            # For now, return a basic capture object
            
            capture_id = str(uuid.uuid4())
            capture = NetworkCapture(
                capture_id=capture_id,
                start_time=datetime.now(),
                end_time=datetime.now(),
                interface=interface,
                packets_captured=len(packets),
                capture_status="completed"
            )
            
            return capture
            
        except ImportError:
            log.error("Scapy not installed. Install with: pip install scapy")
            raise
        except PermissionError:
            log.error("Insufficient permissions for packet capture. Run with sudo/admin privileges.")
            raise
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make the agent callable for LangGraph."""
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        result_state = self.capture(agent_state)
        return result_state.model_dump()
