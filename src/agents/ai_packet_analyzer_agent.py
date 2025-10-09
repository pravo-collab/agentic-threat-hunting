"""AI Packet Analyzer Agent using Zeek, OpenAI Embeddings, Pinecone, and RAG."""

import uuid
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from src.models.schemas import AgentState
from src.utils.logger import log
from src.config.settings import settings


class AIPacketAnalyzerAgent:
    """Advanced AI-powered packet analyzer using Zeek, embeddings, and RAG.
    
    This agent provides:
    - PCAP parsing with Zeek into structured logs
    - Traffic representation as embeddings (OpenAI)
    - Vector storage in Pinecone
    - Natural language querying via RAG
    - Anomaly detection via embedding similarity
    - Threat hunting with known malicious patterns
    """
    
    def __init__(
        self,
        pinecone_api_key: Optional[str] = None,
        pinecone_environment: Optional[str] = None,
        index_name: str = "network-traffic",
        embedding_model: str = "text-embedding-3-small"
    ):
        """Initialize the AI Packet Analyzer Agent.
        
        Args:
            pinecone_api_key: Pinecone API key (optional, uses env var)
            pinecone_environment: Pinecone environment (optional, uses env var)
            index_name: Name of Pinecone index
            embedding_model: OpenAI embedding model to use
        """
        self.index_name = index_name
        self.embedding_model = embedding_model
        
        # Initialize OpenAI embeddings
        try:
            self.embeddings = OpenAIEmbeddings(
                model=embedding_model,
                openai_api_key=settings.OPENAI_API_KEY
            )
            log.info(f"Initialized OpenAI embeddings: {embedding_model}")
        except Exception as e:
            log.error(f"Failed to initialize OpenAI embeddings: {str(e)}")
            self.embeddings = None
        
        # Initialize Pinecone
        self.pinecone_index = None
        self._initialize_pinecone(pinecone_api_key, pinecone_environment)
        
        # Initialize LLM for RAG
        try:
            self.llm = ChatOpenAI(
                model=settings.DEFAULT_MODEL,
                temperature=0.1,
                openai_api_key=settings.OPENAI_API_KEY
            )
            log.info("Initialized LLM for RAG queries")
        except Exception as e:
            log.error(f"Failed to initialize LLM: {str(e)}")
            self.llm = None
        
        # Known malicious patterns (for threat hunting)
        self.malicious_patterns = []
        
        # Normal traffic baseline (for anomaly detection)
        self.baseline_embeddings = []
        
        log.info("AI Packet Analyzer Agent initialized")
    
    def _initialize_pinecone(self, api_key: Optional[str], environment: Optional[str]):
        """Initialize Pinecone vector database.
        
        Args:
            api_key: Pinecone API key
            environment: Pinecone environment
        """
        try:
            from pinecone import Pinecone, ServerlessSpec
            
            # Get API key from parameter or environment
            api_key = api_key or settings.PINECONE_API_KEY
            
            if not api_key:
                log.warning("Pinecone API key not provided. Vector storage disabled.")
                return
            
            # Initialize Pinecone
            pc = Pinecone(api_key=api_key)
            
            # Check if index exists, create if not
            existing_indexes = pc.list_indexes()
            index_names = [idx.name for idx in existing_indexes]
            
            if self.index_name not in index_names:
                log.info(f"Creating Pinecone index: {self.index_name}")
                pc.create_index(
                    name=self.index_name,
                    dimension=1536,  # text-embedding-3-small dimension
                    metric='cosine',
                    spec=ServerlessSpec(
                        cloud='aws',
                        region='us-east-1'
                    )
                )
            
            # Connect to index
            self.pinecone_index = pc.Index(self.index_name)
            log.info(f"Connected to Pinecone index: {self.index_name}")
            
        except ImportError:
            log.warning("Pinecone not installed. Install with: pip install pinecone-client")
            self.pinecone_index = None
        except Exception as e:
            log.error(f"Failed to initialize Pinecone: {str(e)}")
            self.pinecone_index = None
    
    def parse_pcap_with_zeek(self, pcap_file: str) -> Dict[str, Any]:
        """Parse PCAP file using Zeek to extract structured logs.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary containing parsed Zeek logs
        """
        log.info(f"Parsing PCAP with Zeek: {pcap_file}")
        
        try:
            # Create temporary directory for Zeek output
            with tempfile.TemporaryDirectory() as temp_dir:
                # Convert to absolute path for Zeek
                pcap_abs_path = str(Path(pcap_file).resolve())
                
                # Run Zeek on the PCAP file
                result = subprocess.run(
                    ['zeek', '-r', pcap_abs_path, '-C'],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode != 0:
                    log.error(f"Zeek parsing failed: {result.stderr}")
                    return self._fallback_pcap_parsing(pcap_file)
                
                # Parse Zeek log files
                zeek_logs = self._parse_zeek_logs(temp_dir)
                
                log.info(f"Zeek parsing complete. Found {len(zeek_logs)} log entries")
                return zeek_logs
                
        except FileNotFoundError:
            log.warning("Zeek not found. Using fallback Scapy parsing.")
            return self._fallback_pcap_parsing(pcap_file)
        except subprocess.TimeoutExpired:
            log.error("Zeek parsing timed out")
            return self._fallback_pcap_parsing(pcap_file)
        except Exception as e:
            log.error(f"Error parsing PCAP with Zeek: {str(e)}")
            return self._fallback_pcap_parsing(pcap_file)
    
    def _parse_zeek_logs(self, log_dir: str) -> Dict[str, List[Dict]]:
        """Parse Zeek log files from directory.
        
        Args:
            log_dir: Directory containing Zeek logs
            
        Returns:
            Dictionary of parsed logs by type
        """
        zeek_logs = {
            'conn': [],
            'dns': [],
            'http': [],
            'ssl': [],
            'files': [],
            'weird': []
        }
        
        log_dir_path = Path(log_dir)
        
        # Parse each log type
        for log_type in zeek_logs.keys():
            log_file = log_dir_path / f"{log_type}.log"
            
            if log_file.exists():
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            # Skip comments
                            if line.startswith('#'):
                                continue
                            
                            # Parse TSV format
                            fields = line.strip().split('\t')
                            if fields:
                                zeek_logs[log_type].append(self._parse_zeek_line(log_type, fields))
                                
                except Exception as e:
                    log.error(f"Error parsing {log_type}.log: {str(e)}")
        
        return zeek_logs
    
    def _parse_zeek_line(self, log_type: str, fields: List[str]) -> Dict[str, Any]:
        """Parse a single Zeek log line.
        
        Args:
            log_type: Type of Zeek log
            fields: List of field values
            
        Returns:
            Parsed log entry
        """
        # Basic parsing - in production, use proper Zeek log parser
        if log_type == 'conn' and len(fields) >= 10:
            return {
                'timestamp': fields[0],
                'uid': fields[1],
                'src_ip': fields[2],
                'src_port': fields[3],
                'dst_ip': fields[4],
                'dst_port': fields[5],
                'proto': fields[6],
                'service': fields[7] if len(fields) > 7 else '',
                'duration': fields[8] if len(fields) > 8 else '0',
                'orig_bytes': fields[9] if len(fields) > 9 else '0'
            }
        elif log_type == 'dns' and len(fields) >= 9:
            return {
                'timestamp': fields[0],
                'uid': fields[1],
                'src_ip': fields[2],
                'src_port': fields[3],
                'dst_ip': fields[4],
                'dst_port': fields[5],
                'proto': fields[6],
                'query': fields[8] if len(fields) > 8 else '',
                'qtype': fields[13] if len(fields) > 13 else ''
            }
        else:
            return {'raw': '\t'.join(fields)}
    
    def _fallback_pcap_parsing(self, pcap_file: str) -> Dict[str, List[Dict]]:
        """Fallback PCAP parsing using Scapy when Zeek is unavailable.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary of parsed packets
        """
        log.info("Using Scapy fallback for PCAP parsing")
        
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS
            
            packets = rdpcap(pcap_file)
            
            parsed_logs = {
                'conn': [],
                'dns': [],
                'http': [],
                'ssl': [],
                'files': [],
                'weird': []
            }
            
            for pkt in packets:
                if IP in pkt:
                    # Connection log
                    conn_entry = {
                        'timestamp': str(datetime.fromtimestamp(float(pkt.time))),
                        'uid': str(uuid.uuid4()),
                        'src_ip': pkt[IP].src,
                        'dst_ip': pkt[IP].dst,
                        'proto': pkt[IP].proto
                    }
                    
                    if TCP in pkt:
                        conn_entry.update({
                            'src_port': pkt[TCP].sport,
                            'dst_port': pkt[TCP].dport,
                            'service': 'tcp'
                        })
                    elif UDP in pkt:
                        conn_entry.update({
                            'src_port': pkt[UDP].sport,
                            'dst_port': pkt[UDP].dport,
                            'service': 'udp'
                        })
                    
                    parsed_logs['conn'].append(conn_entry)
                    
                    # DNS log
                    if DNS in pkt:
                        if pkt[DNS].qd:
                            dns_entry = {
                                'timestamp': str(datetime.fromtimestamp(float(pkt.time))),
                                'uid': str(uuid.uuid4()),
                                'src_ip': pkt[IP].src,
                                'dst_ip': pkt[IP].dst,
                                'query': pkt[DNS].qd.qname.decode('utf-8') if isinstance(pkt[DNS].qd.qname, bytes) else str(pkt[DNS].qd.qname),
                                'qtype': pkt[DNS].qd.qtype
                            }
                            parsed_logs['dns'].append(dns_entry)
            
            log.info(f"Scapy parsing complete. Found {len(parsed_logs['conn'])} connections")
            return parsed_logs
            
        except Exception as e:
            log.error(f"Scapy fallback parsing failed: {str(e)}")
            return {'conn': [], 'dns': [], 'http': [], 'ssl': [], 'files': [], 'weird': []}
    
    def create_traffic_embeddings(self, zeek_logs: Dict[str, List[Dict]], pcap_filename: str = None) -> List[Dict[str, Any]]:
        """Convert Zeek logs to text and create embeddings.
        
        Args:
            zeek_logs: Parsed Zeek logs
            pcap_filename: Name of the PCAP file being analyzed
            
        Returns:
            List of embeddings with metadata
        """
        if not self.embeddings:
            log.error("OpenAI embeddings not initialized")
            return []
        
        log.info("Creating traffic embeddings")
        
        embeddings_data = []
        
        # Process each log type
        for log_type, entries in zeek_logs.items():
            for entry in entries:
                # Convert log entry to descriptive text
                text = self._log_to_text(log_type, entry)
                
                try:
                    # Create embedding
                    embedding = self.embeddings.embed_query(text)
                    
                    embeddings_data.append({
                        'id': entry.get('uid', str(uuid.uuid4())),
                        'text': text,
                        'embedding': embedding,
                        'metadata': {
                            'log_type': log_type,
                            'timestamp': entry.get('timestamp', ''),
                            'src_ip': entry.get('src_ip', ''),
                            'dst_ip': entry.get('dst_ip', ''),
                            'src_port': entry.get('src_port', ''),
                            'dst_port': entry.get('dst_port', ''),
                            'proto': entry.get('proto', ''),
                            'service': entry.get('service', ''),
                            'query': entry.get('query', ''),
                            'pcap_file': pcap_filename or 'unknown'
                        }
                    })
                    
                except Exception as e:
                    log.error(f"Error creating embedding: {str(e)}")
                    continue
        
        log.info(f"Created {len(embeddings_data)} embeddings")
        return embeddings_data
    
    def _log_to_text(self, log_type: str, entry: Dict[str, Any]) -> str:
        """Convert log entry to descriptive text for embedding.
        
        Args:
            log_type: Type of log
            entry: Log entry dictionary
            
        Returns:
            Descriptive text
        """
        if log_type == 'conn':
            return (
                f"Network connection from {entry.get('src_ip', 'unknown')}:{entry.get('src_port', '')} "
                f"to {entry.get('dst_ip', 'unknown')}:{entry.get('dst_port', '')} "
                f"using {entry.get('proto', 'unknown')} protocol. "
                f"Service: {entry.get('service', 'unknown')}. "
                f"Duration: {entry.get('duration', '0')} seconds. "
                f"Bytes transferred: {entry.get('orig_bytes', '0')}"
            )
        elif log_type == 'dns':
            return (
                f"DNS query from {entry.get('src_ip', 'unknown')} "
                f"to {entry.get('dst_ip', 'unknown')} "
                f"for domain {entry.get('query', 'unknown')} "
                f"with query type {entry.get('qtype', 'unknown')}"
            )
        elif log_type == 'http':
            return (
                f"HTTP request from {entry.get('src_ip', 'unknown')} "
                f"to {entry.get('dst_ip', 'unknown')} "
                f"for {entry.get('method', 'GET')} {entry.get('uri', '/')} "
                f"with user agent {entry.get('user_agent', 'unknown')}"
            )
        else:
            return json.dumps(entry)
    
    def store_in_pinecone(self, embeddings_data: List[Dict[str, Any]]) -> bool:
        """Store embeddings in Pinecone vector database.
        
        Args:
            embeddings_data: List of embeddings with metadata
            
        Returns:
            Success status
        """
        if not self.pinecone_index:
            log.warning("Pinecone not initialized. Skipping vector storage.")
            return False
        
        log.info(f"Storing {len(embeddings_data)} embeddings in Pinecone")
        
        try:
            # Prepare vectors for upsert
            vectors = []
            for data in embeddings_data:
                vectors.append({
                    'id': data['id'],
                    'values': data['embedding'],
                    'metadata': {
                        **data['metadata'],
                        'text': data['text']
                    }
                })
            
            # Upsert in batches of 100
            batch_size = 100
            for i in range(0, len(vectors), batch_size):
                batch = vectors[i:i + batch_size]
                self.pinecone_index.upsert(vectors=batch)
            
            log.info("Successfully stored embeddings in Pinecone")
            return True
            
        except Exception as e:
            log.error(f"Error storing in Pinecone: {str(e)}")
            return False
    
    def query_with_rag(self, query: str, top_k: int = 5, pcap_filter: str = None) -> str:
        """Query network traffic using RAG (Retrieval-Augmented Generation).
        
        Args:
            query: Natural language query
            top_k: Number of similar results to retrieve
            pcap_filter: Filter results to specific PCAP file
            
        Returns:
            LLM-generated response
        """
        if not self.embeddings or not self.llm:
            return "RAG components not initialized"
        
        log.info(f"Processing RAG query: {query}")
        
        try:
            # Create query embedding
            query_embedding = self.embeddings.embed_query(query)
            
            # Retrieve similar traffic from Pinecone
            # Build filter for specific PCAP file if provided
            filter_dict = None
            if pcap_filter:
                filter_dict = {'pcap_file': pcap_filter}
            if self.pinecone_index:
                query_params = {
                    'vector': query_embedding,
                    'top_k': top_k,
                    'include_metadata': True
                }
                if filter_dict:
                    query_params['filter'] = filter_dict
                
                results = self.pinecone_index.query(**query_params)
                
                # Extract context from results
                context = self._build_context_from_results(results)
            else:
                context = "No vector database available. Using general knowledge."
            
            # Create RAG prompt
            prompt = ChatPromptTemplate.from_messages([
                ("system", """You are a cybersecurity analyst expert in network traffic analysis. 
                Analyze the provided network traffic logs and answer the user's question.
                Be specific, technical, and provide actionable insights.
                If you detect potential threats, explain them clearly."""),
                ("user", """Network Traffic Context:
                {context}
                
                Question: {question}
                
                Provide a detailed analysis:""")
            ])
            
            # Generate response
            chain = prompt | self.llm | StrOutputParser()
            response = chain.invoke({
                "context": context,
                "question": query
            })
            
            log.info("RAG query completed successfully")
            return response
            
        except Exception as e:
            log.error(f"Error in RAG query: {str(e)}")
            return f"Error processing query: {str(e)}"
    
    def _build_context_from_results(self, results) -> str:
        """Build context string from Pinecone query results.
        
        Args:
            results: Pinecone query results
            
        Returns:
            Formatted context string
        """
        context_parts = []
        
        for match in results.matches:
            metadata = match.metadata
            score = match.score
            
            context_parts.append(
                f"[Similarity: {score:.3f}] {metadata.get('text', 'No description')}\n"
                f"  Source: {metadata.get('src_ip', 'unknown')} → "
                f"Destination: {metadata.get('dst_ip', 'unknown')}\n"
                f"  Protocol: {metadata.get('proto', 'unknown')}, "
                f"Service: {metadata.get('service', 'unknown')}\n"
            )
        
        return "\n".join(context_parts)
    
    def detect_anomalies(self, embeddings_data: List[Dict[str, Any]], threshold: float = 0.7) -> List[Dict[str, Any]]:
        """Detect anomalies using embedding similarity against baseline.
        
        Args:
            embeddings_data: List of traffic embeddings
            threshold: Similarity threshold (lower = more anomalous)
            
        Returns:
            List of anomalous traffic entries
        """
        if not self.baseline_embeddings:
            log.warning("No baseline established. Building baseline from current data.")
            self._build_baseline(embeddings_data[:100])  # Use first 100 as baseline
        
        log.info(f"Detecting anomalies with threshold {threshold}")
        
        anomalies = []
        
        for data in embeddings_data:
            # Calculate similarity to baseline
            max_similarity = self._calculate_max_similarity(
                data['embedding'],
                self.baseline_embeddings
            )
            
            # If similarity is below threshold, it's anomalous
            if max_similarity < threshold:
                anomalies.append({
                    **data,
                    'anomaly_score': 1.0 - max_similarity,
                    'baseline_similarity': max_similarity
                })
        
        log.info(f"Detected {len(anomalies)} anomalies")
        return anomalies
    
    def _build_baseline(self, embeddings_data: List[Dict[str, Any]]):
        """Build baseline from normal traffic embeddings.
        
        Args:
            embeddings_data: List of normal traffic embeddings
        """
        self.baseline_embeddings = [data['embedding'] for data in embeddings_data]
        log.info(f"Built baseline with {len(self.baseline_embeddings)} embeddings")
    
    def _calculate_max_similarity(self, embedding: List[float], baseline: List[List[float]]) -> float:
        """Calculate maximum cosine similarity to baseline.
        
        Args:
            embedding: Query embedding
            baseline: List of baseline embeddings
            
        Returns:
            Maximum similarity score
        """
        if not baseline:
            return 0.0
        
        embedding_array = np.array(embedding)
        similarities = []
        
        for base_emb in baseline:
            base_array = np.array(base_emb)
            # Cosine similarity
            similarity = np.dot(embedding_array, base_array) / (
                np.linalg.norm(embedding_array) * np.linalg.norm(base_array)
            )
            similarities.append(similarity)
        
        return max(similarities)
    
    def threat_hunt(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """Hunt for threats using similarity search against known malicious patterns.
        
        Args:
            query: Threat description or pattern
            top_k: Number of results to return
            
        Returns:
            List of potentially malicious traffic
        """
        if not self.embeddings:
            log.error("Embeddings not initialized")
            return []
        
        log.info(f"Threat hunting for: {query}")
        
        try:
            # Create query embedding
            query_embedding = self.embeddings.embed_query(query)
            
            # Search in Pinecone
            if self.pinecone_index:
                results = self.pinecone_index.query(
                    vector=query_embedding,
                    top_k=top_k,
                    include_metadata=True
                )
                
                threats = []
                for match in results.matches:
                    threats.append({
                        'id': match.id,
                        'similarity': match.score,
                        'metadata': match.metadata,
                        'threat_type': query
                    })
                
                log.info(f"Found {len(threats)} potential threats")
                return threats
            else:
                log.warning("Pinecone not available for threat hunting")
                return []
                
        except Exception as e:
            log.error(f"Error in threat hunting: {str(e)}")
            return []
    
    def add_malicious_pattern(self, description: str, metadata: Dict[str, Any]):
        """Add known malicious pattern for threat hunting.
        
        Args:
            description: Description of malicious pattern
            metadata: Additional metadata
        """
        if not self.embeddings:
            return
        
        try:
            embedding = self.embeddings.embed_query(description)
            
            self.malicious_patterns.append({
                'description': description,
                'embedding': embedding,
                'metadata': metadata
            })
            
            # Store in Pinecone with special tag
            if self.pinecone_index:
                self.pinecone_index.upsert(vectors=[{
                    'id': f"malicious_{uuid.uuid4()}",
                    'values': embedding,
                    'metadata': {
                        **metadata,
                        'text': description,
                        'is_malicious': True
                    }
                }])
            
            log.info(f"Added malicious pattern: {description}")
            
        except Exception as e:
            log.error(f"Error adding malicious pattern: {str(e)}")
    
    def analyze_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Complete PCAP analysis pipeline.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Complete analysis results
        """
        log.info(f"Starting AI-powered PCAP analysis: {pcap_file}")
        
        # Step 1: Parse with Zeek
        zeek_logs = self.parse_pcap_with_zeek(pcap_file)
        
        # Step 2: Create embeddings
        import os
        pcap_filename = os.path.basename(pcap_file)
        embeddings_data = self.create_traffic_embeddings(zeek_logs, pcap_filename)
        
        # Step 3: Store in Pinecone
        stored = self.store_in_pinecone(embeddings_data)
        
        # Step 4: Detect anomalies
        anomalies = self.detect_anomalies(embeddings_data)
        
        # Step 5: Generate summary
        summary = {
            'pcap_file': pcap_file,
            'total_logs': sum(len(entries) for entries in zeek_logs.values()),
            'log_types': {k: len(v) for k, v in zeek_logs.items()},
            'embeddings_created': len(embeddings_data),
            'stored_in_vector_db': stored,
            'anomalies_detected': len(anomalies),
            'anomaly_details': anomalies[:10],  # Top 10 anomalies
            'zeek_logs': zeek_logs,
            'embeddings_available': len(embeddings_data) > 0
        }
        
        log.info("AI PCAP analysis complete")
        return summary
    
    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Make agent callable for LangGraph integration.
        
        Args:
            state: Agent state
            
        Returns:
            Updated state
        """
        if isinstance(state, AgentState):
            agent_state = state
        else:
            agent_state = AgentState.model_validate(state)
        
        # Process network capture if available
        if agent_state.network_capture and agent_state.network_capture.pcap_file:
            pcap_file = agent_state.network_capture.pcap_file
            
            # Analyze PCAP
            results = self.analyze_pcap(pcap_file)
            
            # Add to messages
            agent_state.messages.append(
                f"AI Packet Analysis: Processed {results['total_logs']} logs, "
                f"created {results['embeddings_created']} embeddings, "
                f"detected {results['anomalies_detected']} anomalies"
            )
        
        return agent_state.model_dump()
