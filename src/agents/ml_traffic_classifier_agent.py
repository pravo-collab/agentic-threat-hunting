"""Deep Learning-based Network Traffic Classifier Agent for Intrusion Detection."""

import uuid
import pickle
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import json

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score

from src.models.schemas import AgentState, NetworkFlow, NetworkProtocol
from src.utils.logger import log


class MLTrafficClassifierAgent:
    """Agent for Deep Learning-based network traffic classification and intrusion detection."""
    
    def __init__(self, model_path: Optional[str] = None, use_deep_learning: bool = True):
        """Initialize the ML Traffic Classifier Agent.
        
        Args:
            model_path: Path to saved model file (optional)
            use_deep_learning: Use deep learning model (default: True)
        """
        self.model_path = model_path or "models/dl_traffic_classifier.h5"
        self.scaler_path = "models/dl_scaler.pkl"
        self.baseline_path = "models/network_baseline.pkl"
        self.encoder_path = "models/label_encoder.pkl"
        self.use_deep_learning = use_deep_learning
        
        # Create models directory
        Path("models").mkdir(exist_ok=True)
        
        # Initialize or load model
        self.model = None
        self.scaler = None
        self.baseline = None
        self.label_encoder = None
        
        # Enhanced feature set for deep learning
        self.feature_names = [
            'packet_count', 'byte_count', 'avg_packet_size',
            'duration', 'packets_per_second', 'bytes_per_second',
            'protocol_tcp', 'protocol_udp', 'protocol_icmp',
            'dst_port_range', 'flow_direction',
            'src_port', 'dst_port', 'packet_variance',
            'byte_variance', 'inter_arrival_time',
            'forward_packets', 'backward_packets',
            'syn_flag_count', 'ack_flag_count', 'psh_flag_count'
        ]
        
        # Extended traffic classes for intrusion detection
        self.traffic_classes = {
            0: 'normal',
            1: 'dos_attack',
            2: 'probe_scan',
            3: 'r2l_attack',
            4: 'u2r_attack',
            5: 'malware',
            6: 'botnet',
            7: 'anomaly'
        }
        
        # Application types for traffic classification
        self.application_types = {
            'web': [80, 443, 8080, 8443],
            'email': [25, 110, 143, 587, 993, 995],
            'dns': [53],
            'ftp': [20, 21],
            'ssh': [22],
            'database': [3306, 5432, 1433, 27017],
            'other': []
        }
        
        self._load_or_initialize_model()
        log.info(f"ML Traffic Classifier Agent initialized (Deep Learning: {use_deep_learning})")
    
    def _load_or_initialize_model(self):
        """Load existing model or initialize new deep learning model."""
        try:
            if self.use_deep_learning:
                # Try to load TensorFlow/Keras model
                try:
                    import tensorflow as tf
                    from tensorflow import keras
                    
                    if Path(self.model_path).exists():
                        self.model = keras.models.load_model(self.model_path)
                        log.info(f"Loaded DL model from {self.model_path}")
                    else:
                        # Initialize new deep learning model
                        self.model = self._build_dl_model()
                        log.info("Initialized new Deep Learning model")
                except ImportError:
                    log.warning("TensorFlow not available, falling back to SVM")
                    self.use_deep_learning = False
                    self._initialize_svm_model()
            else:
                self._initialize_svm_model()
            
            if Path(self.scaler_path).exists():
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                log.info("Loaded scaler")
            else:
                self.scaler = StandardScaler()
                log.info("Initialized new scaler")
            
            if Path(self.baseline_path).exists():
                with open(self.baseline_path, 'rb') as f:
                    self.baseline = pickle.load(f)
                log.info("Loaded network baseline")
            else:
                self.baseline = self._create_default_baseline()
                log.info("Created default network baseline")
            
            # Load label encoder
            if Path(self.encoder_path).exists():
                with open(self.encoder_path, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                log.info("Loaded label encoder")
            else:
                self.label_encoder = LabelEncoder()
                log.info("Initialized new label encoder")
        except Exception as e:
            log.error(f"Error loading model: {str(e)}")
            if self.use_deep_learning:
                self.model = self._build_dl_model()
            else:
                self._initialize_svm_model()
            self.scaler = StandardScaler()
            self.baseline = self._create_default_baseline()
    
    def _initialize_svm_model(self):
        """Initialize SVM model as fallback."""
        from sklearn.svm import SVC
        self.model = SVC(
            kernel='rbf',
            C=1.0,
            gamma='scale',
            probability=True,
            random_state=42
        )
        log.info("Initialized SVM model")
    
    def _build_dl_model(self):
        """Build deep learning model for intrusion detection.
        
        Returns:
            Keras Sequential model
        """
        try:
            import tensorflow as tf
            from tensorflow import keras
            from tensorflow.keras import layers
            
            # Build a deep neural network
            model = keras.Sequential([
                # Input layer
                layers.Input(shape=(len(self.feature_names),)),
                
                # First hidden layer with dropout
                layers.Dense(128, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                
                # Second hidden layer
                layers.Dense(64, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
                layers.BatchNormalization(),
                layers.Dropout(0.3),
                
                # Third hidden layer
                layers.Dense(32, activation='relu', kernel_regularizer=keras.regularizers.l2(0.001)),
                layers.BatchNormalization(),
                layers.Dropout(0.2),
                
                #Fourth hidden layer
                layers.Dense(16, activation='relu'),
                layers.Dropout(0.2),
                
                # Output layer (8 classes for intrusion types)
                layers.Dense(len(self.traffic_classes), activation='softmax')
            ])
            
            # Compile model
            model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=0.001),
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
            )
            
            log.info(f"Built DL model with {len(self.feature_names)} features and {len(self.traffic_classes)} classes")
            return model
            
        except Exception as e:
            log.error(f"Error building DL model: {str(e)}")
            raise
    
    def _create_default_baseline(self) -> Dict[str, Any]:
        """Create default network baseline."""
        return {
            'normal_packet_count': {'mean': 50, 'std': 20},
            'normal_byte_count': {'mean': 75000, 'std': 30000},
            'normal_packets_per_second': {'mean': 10, 'std': 5},
            'normal_bytes_per_second': {'mean': 15000, 'std': 8000},
            'common_ports': [80, 443, 53, 22, 21, 25, 110, 143],
            'suspicious_ports': [4444, 31337, 1337, 6667, 6666, 1234, 12345],
            'protocol_distribution': {'TCP': 0.7, 'UDP': 0.25, 'ICMP': 0.05}
        }
    
    def extract_features(self, flow: NetworkFlow) -> np.ndarray:
        """Extract enhanced features from a network flow for deep learning.
        
        Args:
            flow: NetworkFlow object
            
        Returns:
            Feature vector as numpy array
        """
        # Calculate derived features
        duration = (flow.end_time - flow.start_time).total_seconds() if flow.end_time and flow.start_time else 1.0
        duration = max(duration, 0.001)  # Avoid division by zero
        
        avg_packet_size = flow.byte_count / max(flow.packet_count, 1)
        packets_per_second = flow.packet_count / duration
        bytes_per_second = flow.byte_count / duration
        
        # Protocol encoding (one-hot)
        protocol_tcp = 1 if flow.protocol == NetworkProtocol.TCP else 0
        protocol_udp = 1 if flow.protocol == NetworkProtocol.UDP else 0
        protocol_icmp = 1 if flow.protocol == NetworkProtocol.ICMP else 0
        
        # Port range categorization
        dst_port = flow.destination_port or 0
        src_port = flow.source_port or 0
        
        if dst_port < 1024:
            dst_port_range = 0  # Well-known ports
        elif dst_port < 49152:
            dst_port_range = 1  # Registered ports
        else:
            dst_port_range = 2  # Dynamic/private ports
        
        # Flow direction (simplified)
        flow_direction = 1 if dst_port in [80, 443, 53] else 0
        
        # Enhanced features for deep learning
        # Packet variance (estimate based on flow characteristics)
        packet_variance = avg_packet_size * 0.1  # Simplified estimation
        byte_variance = flow.byte_count * 0.15  # Simplified estimation
        
        # Inter-arrival time (estimate)
        inter_arrival_time = duration / max(flow.packet_count, 1)
        
        # Forward/backward packets (simplified - assume 60/40 split for bidirectional)
        forward_packets = flow.packet_count * 0.6
        backward_packets = flow.packet_count * 0.4
        
        # TCP flags (estimate based on protocol and flow characteristics)
        if protocol_tcp:
            syn_flag_count = 1  # At least one SYN for connection
            ack_flag_count = max(flow.packet_count - 2, 0)  # Most packets have ACK
            psh_flag_count = max(flow.packet_count * 0.3, 0)  # Some packets push data
        else:
            syn_flag_count = 0
            ack_flag_count = 0
            psh_flag_count = 0
        
        features = np.array([
            flow.packet_count,
            flow.byte_count,
            avg_packet_size,
            duration,
            packets_per_second,
            bytes_per_second,
            protocol_tcp,
            protocol_udp,
            protocol_icmp,
            dst_port_range,
            flow_direction,
            src_port,
            dst_port,
            packet_variance,
            byte_variance,
            inter_arrival_time,
            forward_packets,
            backward_packets,
            syn_flag_count,
            ack_flag_count,
            psh_flag_count
        ])
        
        return features
    
    def classify_flow(self, flow: NetworkFlow) -> Dict[str, Any]:
        """Classify a single network flow using deep learning.
        
        Args:
            flow: NetworkFlow object
            
        Returns:
            Classification result dictionary with intrusion detection and application type
        """
        try:
            # Extract features
            features = self.extract_features(flow)
            
            # Classify application type
            application_type = self._classify_application_type(flow)
            
            # Check if model is trained
            if self.use_deep_learning:
                try:
                    import tensorflow as tf
                    # Check if DL model is trained
                    if not hasattr(self.model, 'predict'):
                        return self._rule_based_classification(flow, features, application_type)
                except:
                    return self._rule_based_classification(flow, features, application_type)
            else:
                if not hasattr(self.model, 'classes_'):
                    return self._rule_based_classification(flow, features, application_type)
            
            # Scale features
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Predict using appropriate model
            if self.use_deep_learning:
                # Deep learning prediction
                prediction_probs = self.model.predict(features_scaled, verbose=0)[0]
                prediction = int(np.argmax(prediction_probs))
                probabilities = prediction_probs
            else:
                # SVM prediction
                prediction = self.model.predict(features_scaled)[0]
                probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Get class name
            class_name = self.traffic_classes.get(prediction, 'unknown')
            
            # Calculate confidence
            confidence = float(np.max(probabilities))
            
            # Check against baseline
            baseline_deviation = self._calculate_baseline_deviation(features)
            
            # Determine threat level
            threat_level = self._determine_threat_level(class_name, confidence, baseline_deviation)
            
            result = {
                'flow_id': flow.flow_id,
                'classification': class_name,
                'application_type': application_type,
                'confidence': confidence,
                'threat_level': threat_level,
                'probabilities': {
                    self.traffic_classes[i]: float(prob) 
                    for i, prob in enumerate(probabilities)
                },
                'baseline_deviation': baseline_deviation,
                'features': {
                    name: float(val) 
                    for name, val in zip(self.feature_names, features)
                },
                'is_anomaly': baseline_deviation > 2.0 or class_name not in ['normal'],
                'is_intrusion': class_name in ['dos_attack', 'probe_scan', 'r2l_attack', 'u2r_attack', 'malware', 'botnet'],
                'model_type': 'Deep Learning' if self.use_deep_learning else 'SVM'
            }
            
            return result
            
        except Exception as e:
            log.error(f"Error classifying flow: {str(e)}")
            application_type = self._classify_application_type(flow)
            return self._rule_based_classification(flow, self.extract_features(flow), application_type)
    
    def _classify_application_type(self, flow: NetworkFlow) -> str:
        """Classify the application type based on port numbers.
        
        Args:
            flow: NetworkFlow object
            
        Returns:
            Application type string
        """
        dst_port = flow.destination_port or 0
        src_port = flow.source_port or 0
        
        # Check destination port first
        for app_type, ports in self.application_types.items():
            if dst_port in ports or src_port in ports:
                return app_type
        
        return 'other'
    
    def _determine_threat_level(self, classification: str, confidence: float, baseline_deviation: float) -> str:
        """Determine threat level based on classification and metrics.
        
        Args:
            classification: Traffic classification
            confidence: Model confidence
            baseline_deviation: Deviation from baseline
            
        Returns:
            Threat level: critical, high, medium, low, or safe
        """
        if classification in ['dos_attack', 'malware', 'botnet'] and confidence > 0.8:
            return 'critical'
        elif classification in ['r2l_attack', 'u2r_attack'] and confidence > 0.7:
            return 'high'
        elif classification == 'probe_scan' or baseline_deviation > 3.0:
            return 'medium'
        elif classification == 'anomaly' or baseline_deviation > 2.0:
            return 'low'
        else:
            return 'safe'
    
    def _rule_based_classification(self, flow: NetworkFlow, features: np.ndarray, application_type: str = 'other') -> Dict[str, Any]:
        """Fallback rule-based classification when model is not trained.
        
        Args:
            flow: NetworkFlow object
            features: Feature vector
            
        Returns:
            Classification result
        """
        classification = 'normal'
        confidence = 0.7
        is_anomaly = False
        
        # Check for suspicious indicators
        suspicious_score = 0
        
        # Check destination port
        if flow.destination_port in self.baseline['suspicious_ports']:
            suspicious_score += 0.4
            classification = 'suspicious'
        
        # Check packet rate
        packets_per_second = features[4]
        if packets_per_second > 100:
            suspicious_score += 0.3
            is_anomaly = True
        
        # Check byte rate
        bytes_per_second = features[5]
        if bytes_per_second > 1000000:  # > 1MB/s
            suspicious_score += 0.2
        
        # Check anomaly score from flow
        if flow.anomaly_score > 0.7:
            suspicious_score += 0.3
            classification = 'malicious' if suspicious_score > 0.7 else 'suspicious'
        
        if suspicious_score > 0.5:
            is_anomaly = True
        
        return {
            'flow_id': flow.flow_id,
            'classification': classification,
            'confidence': confidence,
            'probabilities': {
                'normal': 1.0 - suspicious_score,
                'suspicious': suspicious_score * 0.5,
                'malicious': suspicious_score * 0.3,
                'anomaly': suspicious_score * 0.2
            },
            'baseline_deviation': suspicious_score * 3,
            'features': {
                name: float(val) 
                for name, val in zip(self.feature_names, features)
            },
            'is_anomaly': is_anomaly,
            'note': 'Rule-based classification (model not trained)'
        }
    
    def _calculate_baseline_deviation(self, features: np.ndarray) -> float:
        """Calculate deviation from baseline.
        
        Args:
            features: Feature vector
            
        Returns:
            Deviation score (z-score)
        """
        try:
            packet_count = features[0]
            byte_count = features[1]
            packets_per_second = features[4]
            bytes_per_second = features[5]
            
            # Calculate z-scores
            packet_z = abs(packet_count - self.baseline['normal_packet_count']['mean']) / \
                       max(self.baseline['normal_packet_count']['std'], 1)
            
            byte_z = abs(byte_count - self.baseline['normal_byte_count']['mean']) / \
                    max(self.baseline['normal_byte_count']['std'], 1)
            
            pps_z = abs(packets_per_second - self.baseline['normal_packets_per_second']['mean']) / \
                   max(self.baseline['normal_packets_per_second']['std'], 1)
            
            bps_z = abs(bytes_per_second - self.baseline['normal_bytes_per_second']['mean']) / \
                   max(self.baseline['normal_bytes_per_second']['std'], 1)
            
            # Average z-score
            avg_z = (packet_z + byte_z + pps_z + bps_z) / 4
            
            return float(avg_z)
            
        except Exception as e:
            log.error(f"Error calculating baseline deviation: {str(e)}")
            return 0.0
    
    def classify_flows(self, flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """Classify multiple network flows.
        
        Args:
            flows: List of NetworkFlow objects
            
        Returns:
            List of classification results
        """
        results = []
        for flow in flows:
            result = self.classify_flow(flow)
            results.append(result)
        
        log.info(f"Classified {len(results)} flows")
        return results
    
    def train_model(self, flows: List[NetworkFlow], labels: List[int]) -> Dict[str, Any]:
        """Train the SVM model on labeled data.
        
        Args:
            flows: List of NetworkFlow objects
            labels: List of class labels (0=normal, 1=suspicious, 2=malicious, 3=anomaly)
            
        Returns:
            Training results dictionary
        """
        try:
            log.info(f"Training SVM model on {len(flows)} flows")
            
            # Extract features
            X = np.array([self.extract_features(flow) for flow in flows])
            y = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            self.scaler.fit(X_train)
            X_train_scaled = self.scaler.transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Save model
            self.save_model()
            
            # Update baseline
            self._update_baseline(flows, labels)
            
            log.info(f"Model trained successfully. Accuracy: {accuracy:.2f}")
            
            return {
                'accuracy': float(accuracy),
                'train_samples': len(X_train),
                'test_samples': len(X_test),
                'classification_report': classification_report(
                    y_test, y_pred, 
                    target_names=[self.traffic_classes[i] for i in sorted(self.traffic_classes.keys())],
                    output_dict=True
                ),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }
            
        except Exception as e:
            log.error(f"Error training model: {str(e)}")
            raise
    
    def _update_baseline(self, flows: List[NetworkFlow], labels: List[int]):
        """Update network baseline from training data.
        
        Args:
            flows: List of NetworkFlow objects
            labels: List of labels
        """
        try:
            # Get normal traffic flows
            normal_flows = [flow for flow, label in zip(flows, labels) if label == 0]
            
            if not normal_flows:
                return
            
            # Calculate statistics
            packet_counts = [flow.packet_count for flow in normal_flows]
            byte_counts = [flow.byte_count for flow in normal_flows]
            
            durations = []
            for flow in normal_flows:
                duration = (flow.end_time - flow.start_time).total_seconds() if flow.end_time and flow.start_time else 1.0
                durations.append(max(duration, 0.001))
            
            packets_per_second = [pc / d for pc, d in zip(packet_counts, durations)]
            bytes_per_second = [bc / d for bc, d in zip(byte_counts, durations)]
            
            self.baseline.update({
                'normal_packet_count': {
                    'mean': float(np.mean(packet_counts)),
                    'std': float(np.std(packet_counts))
                },
                'normal_byte_count': {
                    'mean': float(np.mean(byte_counts)),
                    'std': float(np.std(byte_counts))
                },
                'normal_packets_per_second': {
                    'mean': float(np.mean(packets_per_second)),
                    'std': float(np.std(packets_per_second))
                },
                'normal_bytes_per_second': {
                    'mean': float(np.mean(bytes_per_second)),
                    'std': float(np.std(bytes_per_second))
                }
            })
            
            # Save baseline
            with open(self.baseline_path, 'wb') as f:
                pickle.dump(self.baseline, f)
            
            log.info("Network baseline updated")
            
        except Exception as e:
            log.error(f"Error updating baseline: {str(e)}")
    
    def save_model(self):
        """Save model and scaler to disk."""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            
            log.info(f"Model saved to {self.model_path}")
            
        except Exception as e:
            log.error(f"Error saving model: {str(e)}")
    
    def analyze_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Analyze a PCAP file and classify traffic with comprehensive details.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Comprehensive analysis results
        """
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
            import os
            
            log.info(f"Analyzing PCAP file: {pcap_file}")
            
            # File information
            file_size = os.path.getsize(pcap_file)
            
            # Read PCAP
            packets = rdpcap(pcap_file)
            
            # Extract detailed packet information
            packet_details = self._extract_packet_details(packets)
            
            # Convert to flows
            flows = self._packets_to_flows(packets)
            
            # Classify flows
            classifications = self.classify_flows(flows)
            
            # Generate comprehensive analysis
            protocol_breakdown = self._analyze_protocols(packets)
            notable_observations = self._identify_notable_observations(packets, flows, classifications)
            potential_threats = self._identify_potential_threats(packets, flows, classifications)
            packet_content_analysis = self._analyze_packet_contents(packets)
            conclusion = self._generate_conclusion(notable_observations, potential_threats)
            
            # Generate summary
            summary = self._generate_summary(classifications)
            
            return {
                'file_info': {
                    'filename': os.path.basename(pcap_file),
                    'file_size': file_size,
                    'file_size_readable': self._format_bytes(file_size),
                    'status': 'Processed'
                },
                'pcap_file': pcap_file,
                'total_packets': len(packets),
                'total_flows': len(flows),
                'packet_details': packet_details,
                'protocol_breakdown': protocol_breakdown,
                'notable_observations': notable_observations,
                'potential_threats': potential_threats,
                'packet_content_analysis': packet_content_analysis,
                'conclusion': conclusion,
                'classifications': classifications,
                'summary': summary
            }
            
        except Exception as e:
            log.error(f"Error analyzing PCAP: {str(e)}")
            raise
    
    def _format_bytes(self, bytes_size: int) -> str:
        """Format bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"
    
    def _extract_packet_details(self, packets) -> Dict[str, Any]:
        """Extract detailed information from packets."""
        from scapy.all import IP
        
        protocols = set()
        total_bytes = 0
        time_range = {'start': None, 'end': None}
        
        for pkt in packets:
            # Protocols
            if pkt.haslayer('IP'):
                protocols.add('IP')
            if pkt.haslayer('TCP'):
                protocols.add('TCP')
            if pkt.haslayer('UDP'):
                protocols.add('UDP')
            if pkt.haslayer('ICMP'):
                protocols.add('ICMP')
            if pkt.haslayer('DNS'):
                protocols.add('DNS')
            if pkt.haslayer('Ether'):
                protocols.add('Ether')
            if pkt.haslayer('Raw'):
                protocols.add('Raw')
            
            # Size
            total_bytes += len(pkt)
            
            # Time
            if hasattr(pkt, 'time'):
                pkt_time = datetime.fromtimestamp(float(pkt.time))
                if time_range['start'] is None or pkt_time < time_range['start']:
                    time_range['start'] = pkt_time
                if time_range['end'] is None or pkt_time > time_range['end']:
                    time_range['end'] = pkt_time
        
        return {
            'unique_protocols': list(protocols),
            'total_data_size': total_bytes,
            'total_data_size_readable': self._format_bytes(total_bytes),
            'data_size_percentage': 100.0,  # Of file size
            'time_range': time_range
        }
    
    def _analyze_protocols(self, packets) -> Dict[str, Any]:
        """Analyze protocol distribution and details."""
        from scapy.all import IP, TCP, UDP, DNS
        
        protocol_counts = defaultdict(int)
        dns_queries = []
        tcp_connections = []
        udp_packets = []
        
        for pkt in packets:
            if pkt.haslayer('TCP'):
                protocol_counts['TCP'] += 1
                if pkt.haslayer(IP):
                    tcp_connections.append({
                        'src': pkt[IP].src,
                        'dst': pkt[IP].dst,
                        'sport': pkt['TCP'].sport,
                        'dport': pkt['TCP'].dport,
                        'flags': pkt['TCP'].flags
                    })
            
            if pkt.haslayer('UDP'):
                protocol_counts['UDP'] += 1
                if pkt.haslayer(DNS):
                    try:
                        if pkt[DNS].qd:
                            query = pkt[DNS].qd.qname.decode('utf-8') if isinstance(pkt[DNS].qd.qname, bytes) else str(pkt[DNS].qd.qname)
                            dns_queries.append(query)
                    except:
                        pass
                
                if pkt.haslayer(IP):
                    udp_packets.append({
                        'src': pkt[IP].src,
                        'dst': pkt[IP].dst,
                        'sport': pkt['UDP'].sport,
                        'dport': pkt['UDP'].dport
                    })
            
            if pkt.haslayer('ICMP'):
                protocol_counts['ICMP'] += 1
            
            if pkt.haslayer('Ether'):
                protocol_counts['Ether'] += 1
        
        return {
            'protocol_counts': dict(protocol_counts),
            'dns_queries': dns_queries[:10],  # Top 10
            'tcp_connections': tcp_connections[:10],  # Top 10
            'udp_packets': udp_packets[:10]  # Top 10
        }
    
    def _identify_notable_observations(self, packets, flows, classifications) -> List[str]:
        """Identify notable observations in the traffic."""
        from scapy.all import IP, TCP, UDP
        
        observations = []
        
        # Check for multiple source ports
        source_ports = set()
        dest_ips = set()
        
        for pkt in packets:
            if pkt.haslayer(TCP):
                source_ports.add(pkt['TCP'].sport)
                if pkt.haslayer(IP):
                    dest_ips.add(pkt[IP].dst)
            elif pkt.haslayer(UDP):
                source_ports.add(pkt['UDP'].sport)
                if pkt.haslayer(IP):
                    dest_ips.add(pkt[IP].dst)
        
        if len(source_ports) > 10:
            observations.append(f"Client is using multiple source ports ({len(source_ports)} unique ports) to connect to destination servers. This could be indicative of port scanning or connection attempts.")
        
        # Check for TCP flags
        tcp_flags_set = set()
        for pkt in packets:
            if pkt.haslayer(TCP):
                tcp_flags_set.add(str(pkt['TCP'].flags))
        
        if 'S' in str(tcp_flags_set) and len(tcp_flags_set) > 1:
            observations.append(f"TCP connections show various flag combinations ({', '.join(tcp_flags_set)}), indicating normal connection establishment.")
        
        # Check for DNS queries
        dns_count = sum(1 for pkt in packets if pkt.haslayer('DNS'))
        if dns_count > 0:
            observations.append(f"DNS queries observed ({dns_count} packets), targeting domain name resolution.")
        
        # Check UDP packets
        udp_count = sum(1 for pkt in packets if pkt.haslayer('UDP'))
        if udp_count > 0:
            observations.append(f"UDP packets detected ({udp_count} packets), which may include DNS queries or other UDP-based protocols.")
        
        # Check packet sizes
        packet_sizes = [len(pkt) for pkt in packets]
        if packet_sizes:
            avg_size = sum(packet_sizes) / len(packet_sizes)
            observations.append(f"Average packet size is {avg_size:.0f} bytes.")
        
        return observations
    
    def _identify_potential_threats(self, packets, flows, classifications) -> List[str]:
        """Identify potential security threats."""
        from scapy.all import IP, TCP
        
        threats = []
        
        # Check for suspicious classifications
        suspicious_count = sum(1 for c in classifications if c['classification'] in ['suspicious', 'malicious'])
        if suspicious_count > 0:
            threats.append(f"⚠️ {suspicious_count} flows classified as suspicious or malicious by ML model.")
        
        # Check for multiple source ports to same destination
        dest_port_map = defaultdict(set)
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                dest_port_map[pkt[IP].dst].add(pkt['TCP'].sport)
        
        for dest_ip, ports in dest_port_map.items():
            if len(ports) > 20:
                threats.append(f"⚠️ Multiple source ports ({len(ports)}) connecting to same destination ({dest_ip}). Could indicate port scanning or connection attempts.")
        
        # Check for uncommon ports
        uncommon_ports = [4444, 31337, 1337, 6667, 6666, 12345, 54321]
        for pkt in packets:
            if pkt.haslayer(TCP):
                if pkt['TCP'].dport in uncommon_ports:
                    threats.append(f"⚠️ Connection to suspicious port {pkt['TCP'].dport} detected.")
                    break
        
        # Check for potential reconnaissance
        syn_packets = sum(1 for pkt in packets if pkt.haslayer(TCP) and pkt['TCP'].flags == 'S')
        if syn_packets > len(packets) * 0.5:
            threats.append(f"⚠️ High ratio of SYN packets ({syn_packets}/{len(packets)}). Possible reconnaissance or scanning activity.")
        
        if not threats:
            threats.append("✅ No clear indication of specific threats or vulnerabilities based on packet analysis.")
        
        return threats
    
    def _analyze_packet_contents(self, packets) -> Dict[str, Any]:
        """Analyze packet payload contents."""
        from scapy.all import Raw
        
        has_payload = sum(1 for pkt in packets if pkt.haslayer(Raw))
        total_packets = len(packets)
        
        analysis = {
            'packets_with_payload': has_payload,
            'packets_without_payload': total_packets - has_payload,
            'payload_percentage': (has_payload / total_packets * 100) if total_packets > 0 else 0
        }
        
        if has_payload == 0:
            analysis['note'] = "No packet payloads found for deep content analysis."
        else:
            analysis['note'] = f"{has_payload} packets contain payload data that could be analyzed further."
        
        return analysis
    
    def _generate_conclusion(self, observations: List[str], threats: List[str]) -> str:
        """Generate overall conclusion from analysis."""
        
        has_threats = any('⚠️' in t for t in threats)
        
        if has_threats:
            conclusion = "⚠️ **Conclusion**: While there are some notable observations in the captured traffic, "
            conclusion += "there are potential security concerns that warrant further monitoring and analysis. "
            conclusion += "The identified patterns suggest possible reconnaissance or suspicious connection attempts. "
            conclusion += "It is recommended to investigate the flagged activities and implement appropriate security measures."
        else:
            conclusion = "✅ **Conclusion**: The captured traffic appears to be within normal parameters. "
            conclusion += "While there are some notable observations, there is no clear indication of specific threats or vulnerabilities. "
            conclusion += "However, continuous monitoring is recommended to ensure network security."
        
        return conclusion
    
    def _packets_to_flows(self, packets) -> List[NetworkFlow]:
        """Convert Scapy packets to NetworkFlow objects.
        
        Args:
            packets: List of Scapy packets
            
        Returns:
            List of NetworkFlow objects
        """
        from scapy.all import IP, TCP, UDP, ICMP
        
        flow_dict = defaultdict(list)
        
        # Group packets by flow
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
        flows = []
        for (src_ip, dst_ip, protocol, dst_port), pkts in flow_dict.items():
            flow_id = str(uuid.uuid4())
            
            total_bytes = sum(len(pkt) for pkt in pkts)
            
            flow = NetworkFlow(
                flow_id=flow_id,
                start_time=datetime.now(),
                end_time=datetime.now(),
                protocol=protocol,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=pkts[0][TCP].sport if TCP in pkts[0] else (pkts[0][UDP].sport if UDP in pkts[0] else None),
                destination_port=dst_port,
                packet_count=len(pkts),
                byte_count=total_bytes,
                packets=[],
                is_suspicious=False,
                anomaly_score=0.0
            )
            flows.append(flow)
        
        return flows
    
    def _generate_summary(self, classifications: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics from classifications.
        
        Args:
            classifications: List of classification results
            
        Returns:
            Summary dictionary
        """
        total = len(classifications)
        
        # Count by class
        class_counts = defaultdict(int)
        for result in classifications:
            class_counts[result['classification']] += 1
        
        # Count anomalies
        anomaly_count = sum(1 for r in classifications if r['is_anomaly'])
        
        # Average confidence
        avg_confidence = np.mean([r['confidence'] for r in classifications])
        
        # Average baseline deviation
        avg_deviation = np.mean([r['baseline_deviation'] for r in classifications])
        
        return {
            'total_flows': total,
            'class_distribution': dict(class_counts),
            'anomaly_count': anomaly_count,
            'anomaly_percentage': (anomaly_count / total * 100) if total > 0 else 0,
            'average_confidence': float(avg_confidence),
            'average_baseline_deviation': float(avg_deviation),
            'risk_level': self._calculate_risk_level(class_counts, anomaly_count, total)
        }
    
    def _calculate_risk_level(self, class_counts: Dict, anomaly_count: int, total: int) -> str:
        """Calculate overall risk level.
        
        Args:
            class_counts: Dictionary of class counts
            anomaly_count: Number of anomalies
            total: Total flows
            
        Returns:
            Risk level string
        """
        if total == 0:
            return 'unknown'
        
        malicious_pct = (class_counts.get('malicious', 0) / total) * 100
        suspicious_pct = (class_counts.get('suspicious', 0) / total) * 100
        anomaly_pct = (anomaly_count / total) * 100
        
        if malicious_pct > 10 or anomaly_pct > 20:
            return 'critical'
        elif malicious_pct > 5 or suspicious_pct > 15 or anomaly_pct > 10:
            return 'high'
        elif suspicious_pct > 5 or anomaly_pct > 5:
            return 'medium'
        else:
            return 'low'
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make the agent callable for LangGraph."""
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        
        # Classify flows if available
        if agent_state.network_capture and agent_state.network_capture.flows:
            classifications = self.classify_flows(agent_state.network_capture.flows)
            
            # Store results in messages
            summary = self._generate_summary(classifications)
            agent_state.messages.append(
                f"ML Classification: {summary['total_flows']} flows analyzed, "
                f"Risk Level: {summary['risk_level'].upper()}, "
                f"{summary['anomaly_count']} anomalies detected"
            )
        
        return agent_state.model_dump()
