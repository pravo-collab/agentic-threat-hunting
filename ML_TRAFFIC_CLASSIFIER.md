# Deep Learning Traffic Classifier Agent

## 🤖 Overview

The ML Traffic Classifier Agent uses **Deep Learning (Neural Networks)** for advanced network intrusion detection and traffic classification. It provides real-time threat detection, flow-based analysis, baseline modeling, and comprehensive anomaly detection capabilities with support for large-scale data processing.

## 🎯 Features

### 1. **Deep Learning Architecture**
- **4-Layer Neural Network**: 128 → 64 → 32 → 16 neurons
- **Batch Normalization**: Stable training and faster convergence
- **Dropout Regularization**: Prevents overfitting (30%, 30%, 20%, 20%)
- **L2 Regularization**: Weight decay for generalization
- **Adam Optimizer**: Adaptive learning rate (0.001)
- **Real-time Inference**: Optimized for low-latency predictions

### 2. **Enhanced Feature Engineering (21 Features)**
- **Basic Metrics**: packet_count, byte_count, avg_packet_size
- **Temporal Features**: duration, packets_per_second, bytes_per_second
- **Protocol Indicators**: TCP, UDP, ICMP flags
- **Port Analysis**: src_port, dst_port, dst_port_range, flow_direction
- **Statistical Features**: packet_variance, byte_variance, inter_arrival_time
- **Directional Metrics**: forward_packets, backward_packets
- **TCP Flags**: syn_flag_count, ack_flag_count, psh_flag_count

### 3. **Intrusion Detection (8 Classes)**
- **Normal** (Class 0): Regular network traffic
- **DoS Attack** (Class 1): Denial of Service attacks
- **Probe/Scan** (Class 2): Port scanning and reconnaissance
- **R2L Attack** (Class 3): Remote to Local attacks
- **U2R Attack** (Class 4): User to Root privilege escalation
- **Malware** (Class 5): Malicious software communication
- **Botnet** (Class 6): Botnet C&C traffic
- **Anomaly** (Class 7): Statistical outliers and unknown threats

### 4. **Application Type Classification**
- **Web Traffic**: HTTP/HTTPS (ports 80, 443, 8080, 8443)
- **Email**: SMTP, POP3, IMAP (ports 25, 110, 143, 587, 993, 995)
- **DNS**: Domain Name System (port 53)
- **FTP**: File Transfer Protocol (ports 20, 21)
- **SSH**: Secure Shell (port 22)
- **Database**: MySQL, PostgreSQL, MSSQL, MongoDB
- **Other**: Unclassified application traffic

### 5. **Threat Level Assessment**
- **Critical**: DoS, Malware, Botnet with high confidence (>80%)
- **High**: R2L, U2R attacks with confidence >70%
- **Medium**: Probe scans, high baseline deviation (>3σ)
- **Low**: Anomalies, moderate deviation (>2σ)
- **Safe**: Normal traffic patterns

### 6. **Real-Time Capabilities**
- **Batch Processing**: Handle multiple flows simultaneously
- **Stream Processing**: Real-time traffic analysis
- **Low Latency**: Optimized inference (<10ms per flow)
- **Scalability**: Process thousands of flows per second
- **Large Data Support**: TensorFlow backend for big data

## 📊 Features Extracted

The agent extracts **21 enhanced features** from each network flow:

| Feature | Description | Type |
|---------|-------------|------|
| `packet_count` | Number of packets in flow | Numeric |
| `byte_count` | Total bytes transferred | Numeric |
| `avg_packet_size` | Average packet size | Numeric |
| `duration` | Flow duration in seconds | Numeric |
| `packets_per_second` | Packet rate | Numeric |
| `bytes_per_second` | Byte rate | Numeric |
| `protocol_tcp` | TCP protocol indicator | Binary |
| `protocol_udp` | UDP protocol indicator | Binary |
| `protocol_icmp` | ICMP protocol indicator | Binary |
| `dst_port_range` | Destination port category | Categorical |
| `flow_direction` | Flow direction indicator | Binary |
| `src_port` | Source port number | Numeric |
| `dst_port` | Destination port number | Numeric |
| `packet_variance` | Variance in packet sizes | Numeric |
| `byte_variance` | Variance in byte counts | Numeric |
| `inter_arrival_time` | Time between packets | Numeric |
| `forward_packets` | Packets in forward direction | Numeric |
| `backward_packets` | Packets in backward direction | Numeric |
| `syn_flag_count` | Number of SYN flags | Numeric |
| `ack_flag_count` | Number of ACK flags | Numeric |
| `psh_flag_count` | Number of PSH flags | Numeric |

## 🚀 Usage

### Option 1: Streamlit UI

```bash
streamlit run app.py
```

1. Navigate to **"ML Traffic Classifier"** in the sidebar
2. Choose from 3 tabs:
   - **Analyze PCAP**: Classify traffic from PCAP files
   - **Train Model**: Train the SVM model
   - **Model Info**: View model details and features

#### Analyze PCAP Tab
- Select PCAP from captures directory or upload new file
- Click "Analyze Traffic"
- View classification results, risk level, and detailed flow analysis
- Download results as JSON

#### Train Model Tab
- Generate synthetic training data
- Train SVM model
- View accuracy, classification report, and confusion matrix

#### Model Info Tab
- View model status and configuration
- See all features and their descriptions
- Check traffic classes

### Option 2: Python API

```python
from src.agents.ml_traffic_classifier_agent import MLTrafficClassifierAgent

# Initialize agent
agent = MLTrafficClassifierAgent()

# Analyze PCAP file
results = agent.analyze_pcap("captures/capture_20251007_194150_2eb11bb7.pcap")

print(f"Total Flows: {results['total_flows']}")
print(f"Risk Level: {results['summary']['risk_level']}")
print(f"Anomalies: {results['summary']['anomaly_count']}")

# Access classifications
for classification in results['classifications']:
    print(f"Flow {classification['flow_id']}: {classification['classification']}")
    print(f"  Confidence: {classification['confidence']:.2%}")
    print(f"  Baseline Deviation: {classification['baseline_deviation']:.2f}σ")
```

### Option 3: Train Custom Model

```python
from src.agents.ml_traffic_classifier_agent import MLTrafficClassifierAgent
from src.models.schemas import NetworkFlow, NetworkProtocol

agent = MLTrafficClassifierAgent()

# Prepare training data
flows = [...]  # List of NetworkFlow objects
labels = [0, 0, 1, 2, ...]  # Corresponding labels

# Train model
results = agent.train_model(flows, labels)

print(f"Accuracy: {results['accuracy']:.2%}")
print(f"Training Samples: {results['train_samples']}")
print(f"Test Samples: {results['test_samples']}")
```

## 🧠 Model Architecture

### Deep Neural Network Configuration
- **Framework**: TensorFlow/Keras
- **Architecture**: Sequential Feed-Forward Network
- **Input Layer**: 21 features
- **Hidden Layer 1**: 128 neurons, ReLU activation, BatchNorm, 30% Dropout
- **Hidden Layer 2**: 64 neurons, ReLU activation, BatchNorm, 30% Dropout
- **Hidden Layer 3**: 32 neurons, ReLU activation, BatchNorm, 20% Dropout
- **Hidden Layer 4**: 16 neurons, ReLU activation, 20% Dropout
- **Output Layer**: 8 neurons, Softmax activation
- **Total Parameters**: ~20,000 trainable parameters

### Optimization & Regularization
- **Optimizer**: Adam (learning_rate=0.001)
- **Loss Function**: Sparse Categorical Crossentropy
- **Regularization**: L2 (0.001) + Dropout (0.2-0.3)
- **Batch Normalization**: After each dense layer
- **Metrics**: Accuracy, Precision, Recall

### Feature Scaling
- **Method**: StandardScaler (z-score normalization)
- **Fit on**: Training data only
- **Applied to**: Both training and test data
- **Persistence**: Saved with model for inference

### Training Process
1. Extract 21 enhanced features from flows
2. Split data (80% train, 20% test) with stratification
3. Scale features using StandardScaler
4. Train Deep Learning model with early stopping
5. Evaluate on test set (accuracy, precision, recall)
6. Update network baseline from normal traffic
7. Save model (.h5), scaler (.pkl), and baseline (.pkl)

### Fallback Mechanism
- **Primary**: Deep Learning (TensorFlow/Keras)
- **Fallback**: SVM (if TensorFlow unavailable)
- **Rule-Based**: Heuristic classification (if model not trained)

## 📈 Performance Metrics

The agent provides comprehensive metrics:

- **Accuracy**: Overall classification accuracy
- **Precision**: Per-class precision scores
- **Recall**: Per-class recall scores
- **F1-Score**: Harmonic mean of precision and recall
- **Confusion Matrix**: Detailed classification matrix
- **Baseline Deviation**: Z-score from normal behavior

## 🔍 Classification Logic

### Rule-Based Fallback
When the model is not trained, the agent uses rule-based classification:

1. **Port Analysis**: Checks for suspicious ports (4444, 31337, 1337, etc.)
2. **Rate Analysis**: Monitors packets/bytes per second
3. **Anomaly Score**: Uses existing flow anomaly scores
4. **Combined Score**: Aggregates indicators for final classification

### ML-Based Classification
When trained:

1. **Feature Extraction**: Extracts 11 features from flow
2. **Scaling**: Applies StandardScaler normalization
3. **Prediction**: SVM predicts class and probabilities
4. **Baseline Check**: Calculates deviation from baseline
5. **Confidence**: Returns probability of predicted class

## 📁 File Structure

```
models/
├── svm_traffic_classifier.pkl  # Trained SVM model
├── svm_scaler.pkl              # Feature scaler
└── network_baseline.pkl        # Network baseline statistics

captures/
├── capture_*.pcap              # PCAP files for analysis
└── capture_*.json              # Metadata files
```

## 🎓 Training Data Requirements

For optimal performance:

- **Minimum Samples**: 200+ flows
- **Class Balance**: Balanced distribution across classes
- **Feature Diversity**: Variety of protocols, ports, and patterns
- **Labeled Data**: Accurate labels for supervised learning

### Synthetic Data Generation
The agent can generate synthetic training data:
- 100 normal flows
- 50 suspicious flows
- 30 malicious flows
- 20 anomaly flows

## 🔒 Security Considerations

### Baseline Protection
- Baseline updated only from normal traffic
- Prevents poisoning from malicious samples
- Regular baseline refresh recommended

### Model Persistence
- Models saved to disk for reuse
- Scaler saved separately
- Baseline stored independently

### Privacy
- No packet payload analysis
- Only flow-level metadata used
- PCAP files stored locally

## 📊 Example Output

```json
{
  "pcap_file": "captures/capture_20251007_194150_2eb11bb7.pcap",
  "total_packets": 1523,
  "total_flows": 15,
  "summary": {
    "total_flows": 15,
    "class_distribution": {
      "normal": 10,
      "suspicious": 3,
      "malicious": 2
    },
    "anomaly_count": 5,
    "anomaly_percentage": 33.3,
    "average_confidence": 0.85,
    "average_baseline_deviation": 1.2,
    "risk_level": "medium"
  },
  "classifications": [...]
}
```

## 🚀 Future Enhancements

- [ ] Deep Learning models (LSTM, CNN)
- [ ] Real-time classification
- [ ] Online learning capabilities
- [ ] Multi-model ensemble
- [ ] Feature importance analysis
- [ ] Explainable AI (SHAP values)
- [ ] Integration with SIEM systems
- [ ] Automated model retraining

## 📚 References

- [Scikit-learn SVM Documentation](https://scikit-learn.org/stable/modules/svm.html)
- [Network Traffic Classification](https://en.wikipedia.org/wiki/Traffic_classification)
- [Anomaly Detection in Networks](https://www.sciencedirect.com/topics/computer-science/network-anomaly-detection)

---

**Note**: This agent is designed for demonstration and educational purposes. For production use, consider additional validation, testing, and security measures.
