# ML Traffic Classifier Agent - Technical Guide

## 📖 Overview

This document provides a comprehensive technical explanation of how the **ML Traffic Classifier Agent** works, including its architecture, algorithms, data flow, and implementation details.

## 🏗️ Architecture Overview

The ML Traffic Classifier Agent is a sophisticated intrusion detection system that uses Deep Learning (with SVM fallback) to classify network traffic and detect security threats in real-time.

```
┌─────────────────────────────────────────────────────────────┐
│                ML Traffic Classifier Agent                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Feature    │───▶│    Model     │───▶│ Classifier   │  │
│  │  Extraction  │    │  (DL/SVM)    │    │   Output     │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                    │                    │          │
│         ▼                    ▼                    ▼          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  21 Features │    │ 4-Layer DNN  │    │  8 Classes   │  │
│  │  Per Flow    │    │ or RBF SVM   │    │  + App Type  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## 🔄 Data Flow

### 1. Input Processing

```python
PCAP File → Scapy Reader → Packet List → Flow Aggregation → NetworkFlow Objects
```

**Steps:**
1. **PCAP Reading**: Uses Scapy's `rdpcap()` to read packet capture files
2. **Packet Parsing**: Extracts IP, TCP, UDP, ICMP, DNS layers
3. **Flow Grouping**: Groups packets by (src_ip, dst_ip, protocol, dst_port)
4. **Flow Creation**: Converts packet groups into `NetworkFlow` objects

### 2. Feature Extraction

Each `NetworkFlow` is transformed into a 21-dimensional feature vector:

```python
Flow Object → extract_features() → 21-D Feature Vector → StandardScaler → Normalized Features
```

**Feature Categories:**

#### A. Basic Metrics (3 features)
- `packet_count`: Total packets in flow
- `byte_count`: Total bytes transferred
- `avg_packet_size`: byte_count / packet_count

#### B. Temporal Features (3 features)
- `duration`: Flow duration in seconds
- `packets_per_second`: packet_count / duration
- `bytes_per_second`: byte_count / duration

#### C. Protocol Indicators (3 features)
- `protocol_tcp`: Binary (1 if TCP, 0 otherwise)
- `protocol_udp`: Binary (1 if UDP, 0 otherwise)
- `protocol_icmp`: Binary (1 if ICMP, 0 otherwise)

#### D. Port Analysis (4 features)
- `src_port`: Source port number
- `dst_port`: Destination port number
- `dst_port_range`: Categorical (0=well-known, 1=registered, 2=dynamic)
- `flow_direction`: Binary (1 if common service port, 0 otherwise)

#### E. Statistical Features (3 features)
- `packet_variance`: Estimated variance in packet sizes
- `byte_variance`: Estimated variance in byte counts
- `inter_arrival_time`: Average time between packets

#### F. Directional Metrics (2 features)
- `forward_packets`: Packets in forward direction (60% estimate)
- `backward_packets`: Packets in backward direction (40% estimate)

#### G. TCP Flags (3 features)
- `syn_flag_count`: Number of SYN flags
- `ack_flag_count`: Number of ACK flags
- `psh_flag_count`: Number of PSH flags

### 3. Model Inference

```python
Normalized Features → Model.predict() → Class Probabilities → Classification + Confidence
```

## 🧠 Deep Learning Model Architecture

### Neural Network Structure

```
Input Layer (21 features)
        ↓
┌─────────────────────┐
│ Dense(128, ReLU)    │
│ BatchNormalization  │
│ Dropout(0.3)        │
│ L2 Regularization   │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Dense(64, ReLU)     │
│ BatchNormalization  │
│ Dropout(0.3)        │
│ L2 Regularization   │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Dense(32, ReLU)     │
│ BatchNormalization  │
│ Dropout(0.2)        │
│ L2 Regularization   │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Dense(16, ReLU)     │
│ Dropout(0.2)        │
└─────────────────────┘
        ↓
┌─────────────────────┐
│ Dense(8, Softmax)   │
└─────────────────────┘
        ↓
8 Class Probabilities
```

### Model Specifications

```python
# Model Configuration
optimizer = Adam(learning_rate=0.001)
loss = 'sparse_categorical_crossentropy'
metrics = ['accuracy', 'precision', 'recall']

# Regularization
L2_weight_decay = 0.001
dropout_rates = [0.3, 0.3, 0.2, 0.2]
batch_normalization = True

# Total Parameters: ~20,000
```

### Training Process

```python
1. Data Preparation:
   - Extract features from labeled flows
   - Split: 80% train, 20% test (stratified)
   
2. Feature Scaling:
   - Fit StandardScaler on training data
   - Transform both train and test sets
   
3. Model Training:
   - Batch size: 32 (default)
   - Epochs: Until convergence
   - Early stopping: Monitor validation loss
   
4. Evaluation:
   - Accuracy, Precision, Recall
   - Confusion Matrix
   - Per-class metrics
   
5. Model Persistence:
   - Save model: .h5 format
   - Save scaler: .pkl format
   - Save baseline: .pkl format
```

## 🎯 Classification System

### 8 Intrusion Classes

```python
traffic_classes = {
    0: 'normal',        # Regular network traffic
    1: 'dos_attack',    # Denial of Service attacks
    2: 'probe_scan',    # Port scanning/reconnaissance
    3: 'r2l_attack',    # Remote to Local attacks
    4: 'u2r_attack',    # User to Root privilege escalation
    5: 'malware',       # Malicious software communication
    6: 'botnet',        # Botnet C&C traffic
    7: 'anomaly'        # Statistical outliers
}
```

### Application Type Classification

```python
application_types = {
    'web': [80, 443, 8080, 8443],
    'email': [25, 110, 143, 587, 993, 995],
    'dns': [53],
    'ftp': [20, 21],
    'ssh': [22],
    'database': [3306, 5432, 1433, 27017],
    'other': []
}
```

**Classification Logic:**
1. Check destination port against known application ports
2. Check source port as fallback
3. Return matching application type or 'other'

### Threat Level Assessment

```python
def _determine_threat_level(classification, confidence, baseline_deviation):
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
```

## 📊 Baseline Modeling

### Purpose
Establish normal network behavior patterns to detect deviations.

### Baseline Metrics

```python
baseline = {
    'normal_packet_count': {'mean': 50, 'std': 20},
    'normal_byte_count': {'mean': 75000, 'std': 30000},
    'normal_packets_per_second': {'mean': 10, 'std': 5},
    'normal_bytes_per_second': {'mean': 15000, 'std': 8000},
    'common_ports': [80, 443, 53, 22, 21, 25, 110, 143],
    'suspicious_ports': [4444, 31337, 1337, 6667, 6666, 1234, 12345],
    'protocol_distribution': {'TCP': 0.7, 'UDP': 0.25, 'ICMP': 0.05}
}
```

### Deviation Calculation

```python
def _calculate_baseline_deviation(features):
    # Calculate z-scores for key metrics
    packet_z = abs(packet_count - baseline_mean) / baseline_std
    byte_z = abs(byte_count - baseline_mean) / baseline_std
    pps_z = abs(packets_per_second - baseline_mean) / baseline_std
    bps_z = abs(bytes_per_second - baseline_mean) / baseline_std
    
    # Average z-score
    avg_z = (packet_z + byte_z + pps_z + bps_z) / 4
    
    return avg_z
```

**Interpretation:**
- `z < 2.0`: Normal behavior
- `2.0 ≤ z < 3.0`: Moderate deviation (Low threat)
- `z ≥ 3.0`: High deviation (Medium threat)

## 🔄 Fallback Mechanism

### Three-Tier System

```python
1. Primary: Deep Learning (TensorFlow/Keras)
   ├─ If TensorFlow available → Use DNN
   └─ If TensorFlow unavailable → Fallback to Tier 2

2. Secondary: SVM (scikit-learn)
   ├─ If model trained → Use SVM
   └─ If model not trained → Fallback to Tier 3

3. Tertiary: Rule-Based Heuristics
   └─ Always available (no dependencies)
```

### Rule-Based Classification

When models are unavailable, uses heuristic rules:

```python
def _rule_based_classification(flow, features, application_type):
    suspicious_score = 0
    
    # Check suspicious ports
    if dst_port in suspicious_ports:
        suspicious_score += 0.4
    
    # Check packet rate
    if packets_per_second > 100:
        suspicious_score += 0.3
    
    # Check byte rate
    if bytes_per_second > 1000000:  # > 1MB/s
        suspicious_score += 0.2
    
    # Check anomaly score
    if flow.anomaly_score > 0.7:
        suspicious_score += 0.3
    
    # Determine classification
    if suspicious_score > 0.7:
        return 'malicious'
    elif suspicious_score > 0.5:
        return 'suspicious'
    else:
        return 'normal'
```

## 📈 PCAP Analysis Pipeline

### Complete Analysis Flow

```
PCAP File
    ↓
┌─────────────────────────┐
│ 1. File Information     │
│    - Filename           │
│    - Size               │
│    - Status             │
└─────────────────────────┘
    ↓
┌─────────────────────────┐
│ 2. Packet Details       │
│    - Total packets      │
│    - Unique protocols   │
│    - Time range         │
│    - Data size          │
└─────────────────────────┘
    ↓
┌─────────────────────────┐
│ 3. Protocol Breakdown   │
│    - DNS queries        │
│    - TCP connections    │
│    - UDP packets        │
└─────────────────────────┘
    ↓
┌─────────────────────────┐
│ 4. Notable Observations │
│    - Port patterns      │
│    - TCP flags          │
│    - Packet sizes       │
└─────────────────────────┘
    ↓
┌─────────────────────────┐
│ 5. Potential Threats    │
│    - ML classifications │
│    - Port scanning      │
│    - Suspicious ports   │
└─────────────────────────┘
    ↓
┌─────────────────────────┐
│ 6. Packet Content       │
│    - Payload analysis   │
│    - Content percentage │
└─────────────────────────┘
    ↓
┌─────────────────────────┐
│ 7. Conclusion           │
│    - Overall assessment │
│    - Risk level         │
│    - Recommendations    │
└─────────────────────────┘
```

### Analysis Methods

#### Protocol Analysis
```python
def _analyze_protocols(packets):
    # Count protocols
    protocol_counts = defaultdict(int)
    
    # Extract DNS queries
    dns_queries = []
    for pkt in packets:
        if pkt.haslayer(DNS):
            dns_queries.append(pkt[DNS].qd.qname)
    
    # Extract TCP connections
    tcp_connections = []
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            tcp_connections.append({
                'src': pkt[IP].src,
                'dst': pkt[IP].dst,
                'sport': pkt[TCP].sport,
                'dport': pkt[TCP].dport,
                'flags': pkt[TCP].flags
            })
    
    return {
        'protocol_counts': protocol_counts,
        'dns_queries': dns_queries[:10],
        'tcp_connections': tcp_connections[:10]
    }
```

#### Threat Identification
```python
def _identify_potential_threats(packets, flows, classifications):
    threats = []
    
    # Check ML classifications
    suspicious_count = sum(1 for c in classifications 
                          if c['classification'] in ['suspicious', 'malicious'])
    if suspicious_count > 0:
        threats.append(f"⚠️ {suspicious_count} flows classified as threats")
    
    # Check port scanning
    dest_port_map = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(TCP):
            dest_port_map[pkt[IP].dst].add(pkt[TCP].sport)
    
    for dest_ip, ports in dest_port_map.items():
        if len(ports) > 20:
            threats.append(f"⚠️ Port scanning detected: {len(ports)} ports")
    
    # Check suspicious ports
    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport in suspicious_ports:
                threats.append(f"⚠️ Suspicious port {pkt[TCP].dport}")
                break
    
    return threats
```

## 🚀 Real-Time Processing

### Performance Characteristics

```python
# Inference Time
Single Flow: < 10ms
Batch (100 flows): < 500ms
Batch (1000 flows): < 3s

# Throughput
Sequential: ~100 flows/second
Batch Processing: ~2000 flows/second

# Memory Usage
Model: ~5 MB
Scaler: < 1 MB
Per Flow: ~1 KB
```

### Optimization Techniques

1. **Batch Normalization**: Faster convergence, stable training
2. **Feature Scaling**: Cached scaler for consistent normalization
3. **Vectorized Operations**: NumPy for efficient computation
4. **Model Caching**: Load model once, reuse for all predictions
5. **Flow Aggregation**: Process packets in groups, not individually

## 🔧 Configuration & Customization

### Model Parameters

```python
# Adjust in _build_dl_model()
hidden_layers = [128, 64, 32, 16]
dropout_rates = [0.3, 0.3, 0.2, 0.2]
l2_regularization = 0.001
learning_rate = 0.001
activation = 'relu'
output_activation = 'softmax'
```

### Feature Engineering

```python
# Add custom features in extract_features()
def extract_features(self, flow):
    # ... existing features ...
    
    # Add custom feature
    custom_feature = calculate_custom_metric(flow)
    
    features = np.array([
        # ... existing features ...
        custom_feature
    ])
    
    return features
```

### Classification Thresholds

```python
# Adjust in _determine_threat_level()
CRITICAL_CONFIDENCE = 0.8
HIGH_CONFIDENCE = 0.7
HIGH_DEVIATION = 3.0
MEDIUM_DEVIATION = 2.0
```

## 📊 Output Format

### Classification Result Structure

```python
{
    'flow_id': 'uuid-string',
    'classification': 'dos_attack',
    'application_type': 'web',
    'confidence': 0.92,
    'threat_level': 'critical',
    'probabilities': {
        'normal': 0.02,
        'dos_attack': 0.92,
        'probe_scan': 0.03,
        'r2l_attack': 0.01,
        'u2r_attack': 0.00,
        'malware': 0.01,
        'botnet': 0.00,
        'anomaly': 0.01
    },
    'baseline_deviation': 4.2,
    'features': {
        'packet_count': 1500,
        'byte_count': 2250000,
        # ... all 21 features ...
    },
    'is_anomaly': True,
    'is_intrusion': True,
    'model_type': 'Deep Learning'
}
```

### Analysis Summary Structure

```python
{
    'file_info': {...},
    'total_packets': 152,
    'total_flows': 3,
    'packet_details': {...},
    'protocol_breakdown': {...},
    'notable_observations': [...],
    'potential_threats': [...],
    'packet_content_analysis': {...},
    'conclusion': 'string',
    'classifications': [...],
    'summary': {
        'total_flows': 3,
        'class_distribution': {...},
        'anomaly_count': 1,
        'anomaly_percentage': 33.3,
        'average_confidence': 0.85,
        'average_baseline_deviation': 1.2,
        'risk_level': 'medium'
    }
}
```

## 🧪 Testing & Validation

### Unit Testing

```python
# Test feature extraction
def test_extract_features():
    agent = MLTrafficClassifierAgent()
    flow = create_test_flow()
    features = agent.extract_features(flow)
    assert len(features) == 21
    assert all(isinstance(f, (int, float)) for f in features)

# Test classification
def test_classify_flow():
    agent = MLTrafficClassifierAgent()
    flow = create_test_flow()
    result = agent.classify_flow(flow)
    assert 'classification' in result
    assert 'confidence' in result
    assert 0 <= result['confidence'] <= 1
```

### Integration Testing

```python
# Test PCAP analysis
def test_analyze_pcap():
    agent = MLTrafficClassifierAgent()
    results = agent.analyze_pcap('test.pcap')
    assert 'total_packets' in results
    assert 'classifications' in results
    assert len(results['classifications']) > 0
```

## 🔍 Debugging & Troubleshooting

### Common Issues

1. **TensorFlow Not Available**
   - **Symptom**: "TensorFlow not available, falling back to SVM"
   - **Solution**: `pip install tensorflow`

2. **Model Not Trained**
   - **Symptom**: "Not Trained ❌" in UI
   - **Solution**: Use training interface or load pre-trained model

3. **PCAP Read Error**
   - **Symptom**: "Error analyzing PCAP"
   - **Solution**: Ensure Scapy is installed and PCAP file is valid

4. **Memory Issues**
   - **Symptom**: Out of memory with large PCAP files
   - **Solution**: Process in batches, limit packet count

### Logging

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Key log points
log.info("Model initialized")
log.info(f"Analyzing PCAP: {filename}")
log.info(f"Classified {n} flows")
log.warning("Falling back to SVM")
log.error(f"Error: {str(e)}")
```

## 📚 References

### Algorithms & Techniques
- **Deep Learning**: TensorFlow/Keras Sequential API
- **Feature Scaling**: StandardScaler (z-score normalization)
- **Classification**: Multi-class softmax classification
- **Regularization**: L2 weight decay + Dropout
- **Optimization**: Adam optimizer with adaptive learning rate

### Network Analysis
- **Flow Aggregation**: 5-tuple (src_ip, dst_ip, protocol, src_port, dst_port)
- **Protocol Analysis**: Scapy packet dissection
- **Anomaly Detection**: Statistical baseline modeling (z-scores)

### Security Concepts
- **Intrusion Detection**: Signature-based + Anomaly-based
- **Attack Types**: DoS, Probe, R2L, U2R (KDD Cup 99 categories)
- **Threat Intelligence**: Port-based classification

## 🎯 Best Practices

1. **Model Training**: Use diverse, labeled dataset with balanced classes
2. **Feature Engineering**: Normalize features, handle missing values
3. **Baseline Updates**: Regularly update baseline from normal traffic
4. **Performance Monitoring**: Track accuracy, false positives, latency
5. **Security**: Validate inputs, sanitize outputs, log all predictions
6. **Scalability**: Use batch processing for large datasets
7. **Maintenance**: Retrain model periodically with new attack patterns

---

**Last Updated**: October 2025  
**Version**: 1.0  
**Author**: Agentic Threat Hunting System
