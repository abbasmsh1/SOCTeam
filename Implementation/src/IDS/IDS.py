import os
import sys
import subprocess
import json
import uuid
import warnings
import time
from queue import Queue, Full
from threading import Thread, Lock
from collections import Counter

# Suppress optional libpcap warning (not needed for CSV-based flow processing)
warnings.filterwarnings("ignore", message=".*No libpcap provider available.*")

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

# Load .env first so RAGARENN_API_KEY and other vars are available
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '..', '..', '.env'))

from fastapi import FastAPI
from datetime import datetime
from Implementation.src.IDS.ann_model import IDSModel
from Implementation.src.IDS.preprocess import InferencePreprocessor
import pandas as pd
import torch
import joblib
import os
import uvicorn
import numpy as np
from typing import Dict, Any, Optional, List
from Implementation.src.Database.FlowHistoryManager import FlowHistoryManager
from Implementation.src.Database.LiveFlowTracker import LiveFlowTracker
from Implementation.src.Database.FlowAnalytics import FlowAnalytics
from Implementation.src.Database.NetworkSegmentMonitor import NetworkSegmentMonitor

# Import FlowExtractor for pcap processing (optional)
try:
    from Implementation.src.IDS.FlowExtractor import FlowExtractor, check_cicflowmeter_installation
    FLOW_EXTRACTOR_AVAILABLE = True
except ImportError:
    FLOW_EXTRACTOR_AVAILABLE = False


from fastapi import Header, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
from collections import deque

# Global Event Queue for Live Monitor
live_events = deque(maxlen=50)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Calculate base directory relative to this file
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

class IDSConfig:
    """Centralized configuration for IDS."""
    MODEL_PATH = os.getenv("IDS_MODEL_PATH", os.path.join(_BASE_DIR, "Models", "best_ids_model.pth"))
    ARTIFACTS_DIR = os.getenv("IDS_ARTIFACTS_DIR", os.path.join(_BASE_DIR, "Models"))
    API_KEY = os.getenv("IDS_API_KEY", "ids-secret-key")
    REPORTS_DIR = os.path.join(_BASE_DIR, "Reports")
    HOST = "0.0.0.0"
    PORT = 6050  # FIX: removed duplicate PORT assignment
    AUTO_WORKFLOW_CONFIDENCE = float(os.getenv("IDS_AUTO_WORKFLOW_CONFIDENCE", "0.85"))
    AUTO_WORKFLOW_COOLDOWN_SEC = float(os.getenv("IDS_AUTO_WORKFLOW_COOLDOWN_SEC", "10"))
    WORKFLOW_QUEUE_MAXSIZE = int(os.getenv("IDS_WORKFLOW_QUEUE_MAXSIZE", "200"))
    REPORTS_CACHE_TTL_SEC = float(os.getenv("IDS_REPORTS_CACHE_TTL_SEC", "5"))
    REPORTS_LIST_LIMIT = int(os.getenv("IDS_REPORTS_LIST_LIMIT", "200"))
    REMEDIATION_LOG_LIMIT = int(os.getenv("IDS_REMEDIATION_LOG_LIMIT", "200"))
    ENTROPY_WINDOW_SECONDS = int(os.getenv("IDS_ENTROPY_WINDOW_SECONDS", "10"))
    PREDICT_MODE = os.getenv("IDS_PREDICT_MODE", "ann_only")  # ann_only|tree_only|ensemble

# ---------------------------------------------------
# IDS Predictor Class (for standalone use)
# ---------------------------------------------------
class IDSPredictor:
    """Standalone IDS predictor that can be imported and used directly."""
    
    def __init__(self, model_path: str = None, artifacts_dir: str = None):
        """
        Initialize IDS predictor with model and artifacts.
        
        Args:
            model_path: Path to the trained model (.pth file)
            artifacts_dir: Directory containing encoders and scaler
        """
        self.model_path = model_path or IDSConfig.MODEL_PATH
        self.artifacts_dir = artifacts_dir or IDSConfig.ARTIFACTS_DIR
        self.model = None
        self.tree_model = None
        self.ensemble_weight = None
        self.predict_mode = IDSConfig.PREDICT_MODE
        self.label_encoder = None
        self.preprocessor = None  # Use InferencePreprocessor
        self._entropy = RollingEntropyWindow(window_seconds=IDSConfig.ENTROPY_WINDOW_SECONDS)
        self._load_model()
    
    def _load_model(self):
        """Load model and preprocessing artifacts."""
        logger.info("Loading IDS model and artifacts...")
        logger.info(f"  Artifacts directory: {self.artifacts_dir}")
        logger.info(f"  Model path: {self.model_path}")
        
        # Load label encoder for the output
        label_encoder_path = os.path.join(self.artifacts_dir, "label_encoder.joblib")
        if not os.path.exists(label_encoder_path):
             logger.error(f"Label encoder not found at {label_encoder_path}")
             raise FileNotFoundError(f"Label encoder not found at {label_encoder_path}")
        
        self.label_encoder = joblib.load(label_encoder_path)
        
        # Initialize inference preprocessor (loads encoders and scaler)
        self.preprocessor = InferencePreprocessor(artifacts_dir=self.artifacts_dir)
        
        # Get feature names from preprocessor
        feature_names = self.preprocessor.feature_names
        
        # Define model architecture before loading weights
        input_size = len(feature_names)
        hidden_size = 128
        output_size = len(self.label_encoder.classes_)
        
        self.model = IDSModel(input_size=input_size, hidden_size=hidden_size, output_size=output_size)
        
        # Load checkpoint
        checkpoint = torch.load(self.model_path, map_location=torch.device("cpu"))
        
        # Handle new checkpoint format (dict with metadata) vs old format (just state_dict)
        if isinstance(checkpoint, dict) and "model_state" in checkpoint:
            logger.info(f"  Loading model from checkpoint (Epoch {checkpoint.get('epoch', '?')}, Val Acc: {checkpoint.get('val_acc', '?')}%)")
            state_dict = checkpoint["model_state"]
        else:
            state_dict = checkpoint
            
        self.model.load_state_dict(state_dict)
        
        # Move model to device
        self.device = torch.device("cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu")
        self.model.to(self.device)
        self.model.eval()
        
        logger.info(f"IDS model loaded successfully. Using device: {self.device}")

        # Optional: load ensemble artifacts (tree model + weight)
        manifest_path = os.path.join(self.artifacts_dir, "ids_manifest.json")
        try:
            if os.path.exists(manifest_path):
                with open(manifest_path, "r", encoding="utf-8") as fh:
                    manifest = json.load(fh)
                self.predict_mode = os.getenv("IDS_PREDICT_MODE", manifest.get("default_mode", self.predict_mode))
                self.ensemble_weight = manifest.get("ensemble_weight", None)
                tree_path = manifest.get("tree_model") or os.path.join(self.artifacts_dir, "tree_model.joblib")
                if tree_path and os.path.exists(tree_path):
                    self.tree_model = joblib.load(tree_path)
                    logger.info(f"Loaded tree model for ensemble: {tree_path}")
        except Exception as e:
            logger.warning(f"Could not load ensemble artifacts: {e}")
    
    def preprocess_for_inference(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess incoming data for inference using the preprocessing pipeline.
        Handles feature mismatches by creating a DataFrame with only expected features.
        """
        if self.preprocessor is None:
            raise ValueError("Preprocessor not initialized. Call _load_model() first.")
        
        return self.preprocessor.transform(df)

    def predict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict intrusion class from a dictionary record.
        Returns textual label (not encoded).
        """
        enriched = dict(data)
        enriched.update(self._entropy.observe_and_compute(enriched))

        # Convert input dictionary to DataFrame
        df = pd.DataFrame([enriched])
        
        # Preprocess the DataFrame
        features = self.preprocess_for_inference(df)
        features_tensor = torch.tensor(features.values, dtype=torch.float32).to(self.device)
        
        # Run prediction
        if hasattr(torch, 'inference_mode'):
            with torch.inference_mode():
                output = self.model(features_tensor)
        else:
            with torch.no_grad():
                output = self.model(features_tensor)
                
        ann_probs = torch.softmax(output, dim=1).detach().cpu().numpy()[0]
        probs = ann_probs
        mode = (self.predict_mode or "ann_only").lower().strip()

        # Tree-only or ensemble mode if tree artifact is available
        if self.tree_model is not None:
            try:
                X_np = features.values.astype(np.float32)
                tree_probs = self.tree_model.predict_proba(X_np)[0]
                if mode == "tree_only":
                    probs = tree_probs
                elif mode == "ensemble":
                    w = float(self.ensemble_weight) if self.ensemble_weight is not None else 0.5
                    probs = (w * ann_probs) + ((1.0 - w) * tree_probs)
            except Exception as e:
                logger.warning(f"Tree inference failed; falling back to ANN: {e}")

        pred_idx = int(np.argmax(probs))
        pred_label = self.label_encoder.inverse_transform([pred_idx])[0]
        confidence = float(probs[pred_idx])

        return {
            "predicted_label": pred_label,
            "predicted_index": int(pred_idx),
            "confidence": confidence,
            "predict_mode": mode,
        }


class RollingEntropyWindow:
    """
    Rolling window entropy features for online inference.

    Stores recent observations and computes Shannon entropy (base2) across the
    last `window_seconds` for key categorical fields.
    """

    def __init__(self, window_seconds: int = 10):
        self.window_seconds = max(int(window_seconds), 1)
        self._events: deque = deque()

    @staticmethod
    def _entropy(counter: Counter) -> float:
        total = sum(counter.values())
        if total <= 0:
            return 0.0
        probs = [c / total for c in counter.values() if c > 0]
        return float(-sum(p * np.log2(p) for p in probs))

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def observe_and_compute(self, record: Dict[str, Any]) -> Dict[str, float]:
        now = time.time()
        self._prune(now)

        src_ip = str(record.get("Source IP", record.get("SourceIP", record.get("IPV4_SRC_ADDR", "UNKNOWN"))))
        dst_ip = str(record.get("Destination IP", record.get("DestinationIP", record.get("IPV4_DST_ADDR", "UNKNOWN"))))
        src_port = str(record.get("L4_SRC_PORT", record.get("Source Port", record.get("src_port", "0"))))
        dst_port = str(record.get("L4_DST_PORT", record.get("Destination Port", record.get("dst_port", "0"))))
        proto = str(record.get("Protocol", record.get("PROTOCOL", "0")))
        l7 = str(record.get("L7_PROTO", record.get("Application Protocol", "0")))

        self._events.append((now, src_ip, dst_ip, src_port, dst_port, proto, l7))

        src_ip_c = Counter(e[1] for e in self._events)
        dst_ip_c = Counter(e[2] for e in self._events)
        src_port_c = Counter(e[3] for e in self._events)
        dst_port_c = Counter(e[4] for e in self._events)
        proto_c = Counter(e[5] for e in self._events)
        l7_c = Counter(e[6] for e in self._events)

        return {
            "ENT_SRC_IP": self._entropy(src_ip_c),
            "ENT_DST_IP": self._entropy(dst_ip_c),
            "ENT_SRC_PORT": self._entropy(src_port_c),
            "ENT_DST_PORT": self._entropy(dst_port_c),
            "ENT_PROTOCOL": self._entropy(proto_c),
            "ENT_L7_PROTO": self._entropy(l7_c),
            "ENT_PKT_LEN_BIN": 0.0,  # unavailable from live API payloads by default
            "WINDOW_FLOW_COUNT": float(len(self._events)),
        }
    
    def predict_batch(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Predict intrusion class for multiple flows (truly batch prediction).
        """
        if df.empty:
            return []
            
        try:
            # 1. Preprocess all at once
            features = self.preprocess_for_inference(df)
            features_tensor = torch.tensor(features.values, dtype=torch.float32).to(self.device)
            
            # 2. Forward pass in bulk
            if hasattr(torch, 'inference_mode'):
                with torch.inference_mode():
                    outputs = self.model(features_tensor)
            else:
                with torch.no_grad():
                    outputs = self.model(features_tensor)
            
            # 3. Process outputs
            confidences = torch.softmax(outputs, dim=1)
            pred_indices = outputs.argmax(dim=1).cpu().numpy()
            pred_labels = self.label_encoder.inverse_transform(pred_indices)
            
            results = []
            for i, idx in enumerate(df.index):
                results.append({
                    "flow_index": idx,
                    "predicted_label": pred_labels[i],
                    "predicted_index": int(pred_indices[i]),
                    "confidence": float(confidences[i][pred_indices[i]].item())
                })
            return results
            
        except Exception as e:
            logger.error(f"Error in batch prediction: {e}")
            # Fallback to row-by-row if batch fails
            results = []
            for idx, row in df.iterrows():
                try:
                    prediction = self.predict(row.to_dict())
                    prediction['flow_index'] = idx
                    results.append(prediction)
                except Exception as row_e:
                    results.append({
                        'flow_index': idx,
                        'error': str(row_e),
                        'predicted_label': 'ERROR',
                        'predicted_index': -1,
                        'confidence': 0.0
                    })
            return results
    
    def predict_from_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        Process a PCAP file and predict intrusions for all flows.
        
        Args:
            pcap_path: Path to PCAP file
            
        Returns:
            Dictionary containing:
                - flows: DataFrame of extracted flows
                - predictions: List of predictions for each flow
                - statistics: Flow statistics
                - summary: Attack summary
                
        Raises:
            ImportError: If FlowExtractor is not available
            FileNotFoundError: If pcap file doesn't exist
        """
        if not FLOW_EXTRACTOR_AVAILABLE:
            raise ImportError(
                "FlowExtractor not available. Install cicflowmeter: pip install cicflowmeter"
            )
        
        # Extract flows from pcap
        extractor = FlowExtractor()
        flows_df = extractor.extract_from_pcap(pcap_path)
        
        # Run predictions on all flows
        predictions = self.predict_batch(flows_df)
        
        # Calculate statistics
        stats = extractor.get_flow_statistics(flows_df)
        
        # Summarize attacks
        attack_summary = {}
        for pred in predictions:
            label = pred.get('predicted_label', 'UNKNOWN')
            if label != 'BENIGN' and label != 'ERROR':
                attack_summary[label] = attack_summary.get(label, 0) + 1
        
        return {
            'pcap_file': pcap_path,
            'total_flows': len(flows_df),
            'flows': flows_df,
            'predictions': predictions,
            'statistics': stats,
            'attack_summary': attack_summary,
            'attacks_detected': sum(attack_summary.values()),
            'benign_flows': sum(1 for p in predictions if p.get('predicted_label') == 'BENIGN')
        }

# Global Instances
# ---------------------------------------------------
_predictor = None
_workflow = None
_history_mgr = None
_workflow_queue: "Queue[Dict[str, Any]]" = Queue(maxsize=IDSConfig.WORKFLOW_QUEUE_MAXSIZE)
_workflow_worker_started = False
_workflow_worker_lock = Lock()
_last_auto_workflow_ts = 0.0
_auto_workflow_lock = Lock()
_reports_cache: List[Dict[str, str]] = []
_reports_cache_ts = 0.0
_reports_cache_lock = Lock()

# Advanced IDS Components
_flow_tracker = None
_analytics = None
_segment_monitor = None
_analytics_worker_started = False
_analytics_worker_lock = Lock()

def _run_soc_workflow(alert_data: dict, current_status: str) -> Dict[str, Any]:
    """Run SOC workflow synchronously and return result payload."""
    workflow = get_workflow()
    input_data = {
        "alert_data": alert_data,
        "current_status": current_status,
        "context_logs": "System live monitoring active",
        "current_incidents": "N/A"
    }
    return workflow.process(input_data)

def _workflow_worker_loop():
    """Dedicated daemon worker that drains queued workflow requests."""
    while True:
        job = _workflow_queue.get()
        try:
            _run_soc_workflow(job["alert_data"], job["current_status"])
            logger.info(
                "Queued workflow complete for %s",
                job["alert_data"].get("predicted_label", "Unknown")
            )
        except Exception as e:
            logger.error(f"Queued workflow failed: {e}")
        finally:
            _workflow_queue.task_done()

def _ensure_workflow_worker():
    """Start workflow worker once, lazily."""
    global _workflow_worker_started
    if _workflow_worker_started:
        return
    with _workflow_worker_lock:
        if _workflow_worker_started:
            return
        worker = Thread(target=_workflow_worker_loop, name="soc-workflow-worker", daemon=True)
        worker.start()
        _workflow_worker_started = True
        logger.info("SOC workflow background worker started")

def get_flow_tracker():
    global _flow_tracker
    if _flow_tracker is None:
        _flow_tracker = LiveFlowTracker()
    return _flow_tracker

def get_analytics():
    global _analytics
    if _analytics is None:
        _analytics = FlowAnalytics(get_flow_tracker())
    return _analytics

def get_segment_monitor():
    global _segment_monitor
    if _segment_monitor is None:
        _segment_monitor = NetworkSegmentMonitor()
    return _segment_monitor

def _analytics_worker_loop():
    """Periodic analytics processing."""
    analytics = get_analytics()
    segment_monitor = get_segment_monitor()
    while True:
        try:
            # Run pattern detection
            results = analytics.analyze_flows()
            if results["anomalies_detected"] > 0:
                logger.info(f"Analytics pattern detection: Found {len(results['patterns'])} anomalies")
            
            # Run segment integrity check
            integrity = segment_monitor.check_segment_integrity()
            if len(integrity["integrity_threats"]) > 0:
                logger.warning(f"Segment integrity threat: {integrity['integrity_threats']}")
                
        except Exception as e:
            logger.error(f"Analytics worker error: {e}")
        time.sleep(30) # Run every 30 seconds

def _ensure_analytics_worker():
    global _analytics_worker_started
    if _analytics_worker_started:
        return
    with _analytics_worker_lock:
        if _analytics_worker_started:
            return
        worker = Thread(target=_analytics_worker_loop, name="ids-analytics-worker", daemon=True)
        worker.start()
        _analytics_worker_started = True
        logger.info("Advanced IDS analytics background worker started")

def _queue_workflow(alert_data: dict, current_status: str) -> Dict[str, Any]:
    """Queue workflow job and return queue status."""
    _ensure_workflow_worker()
    try:
        _workflow_queue.put_nowait({
            "alert_data": alert_data,
            "current_status": current_status
        })
        return {
            "queued": True,
            "queue_size": _workflow_queue.qsize(),
            "message": "Workflow queued"
        }
    except Full:
        logger.warning("Workflow queue is full; dropping workflow request")
        return {
            "queued": False,
            "queue_size": _workflow_queue.qsize(),
            "message": "Workflow queue full"
        }

def get_history_manager():
    """Get or create global FlowHistoryManager instance."""
    global _history_mgr
    if _history_mgr is None:
        try:
            # We don't provide path, let it resolve to Data/flow_history.db
            _history_mgr = FlowHistoryManager()
        except Exception as e:
            logger.error(f"Failed to initialize FlowHistoryManager: {e}")
            # Don't raise, we want the IDS to still function even if logging fails
    return _history_mgr

def get_predictor():
    """Get or create global predictor instance."""
    global _predictor
    if _predictor is None:
        try:
            _predictor = IDSPredictor()
        except Exception as e:
            logger.error(f"Failed to initialize IDSPredictor: {e}")
            raise
    return _predictor

def get_workflow():
    """Get or create global SOC workflow instance."""
    global _workflow
    if _workflow is None:
        from Implementation.src.Agents.SOCWorkflow import SOCWorkflow
        api_key = os.getenv("RAGARENN_API_KEY")
        
        # Read agent URLs from environment if they are configured to run as microservices
        agent_urls = {}
        if os.getenv("TIER1_URL"): agent_urls["tier1"] = os.getenv("TIER1_URL")
        if os.getenv("TIER2_URL"): agent_urls["tier2"] = os.getenv("TIER2_URL")
        if os.getenv("TIER3_URL"): agent_urls["tier3"] = os.getenv("TIER3_URL")
        if os.getenv("WARROOM_URL"): agent_urls["warroom"] = os.getenv("WARROOM_URL")
        if os.getenv("REPORTER_URL"): agent_urls["reporter"] = os.getenv("REPORTER_URL")
        if os.getenv("REMEDIATION_URL"): agent_urls["remediation"] = os.getenv("REMEDIATION_URL")
        
        logger.info(f"Initializing SOCWorkflow with remote agents: {agent_urls}")
        _workflow = SOCWorkflow(api_key=api_key, agent_urls=agent_urls)
    return _workflow

# Lazy singleton for AutoSOCRuleGenerator
_auto_soc = None
_auto_soc_lock = Lock()

def get_auto_soc():
    """Get or create global AutoSOCRuleGenerator instance."""
    global _auto_soc
    if _auto_soc is None:
        with _auto_soc_lock:
            if _auto_soc is None:
                from Implementation.src.Agents.AutoSOCRuleGenerator import AutoSOCRuleGenerator
                api_key = os.getenv("RAGARENN_API_KEY")
                _auto_soc = AutoSOCRuleGenerator(api_key=api_key)
                logger.info("AutoSOCRuleGenerator initialised")
    return _auto_soc

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AI-Powered Intrusion Detection System")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["X-API-Key", "Content-Type", "Authorization", "*"],
)

@app.get("/")
@app.get("/health")
@app.get("/v1/agl/health")
def health_check():
    return {"status": "healthy", "service": "IDS Backend Gateway"}

# ---------------------------------------------------
# Security Middleware
# ---------------------------------------------------
async def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    if not x_api_key:
        logger.warning("Missing X-API-Key header")
        return "public" # Allow public for health checks if needed, but the routes have dependency
    
    if x_api_key != IDSConfig.API_KEY:
        logger.warning(f"Unauthorized access attempt with API Key: {x_api_key}")
        raise HTTPException(status_code=403, detail="Could not validate credentials")
    return x_api_key

# ---------------------------------------------------
# API Routes
# ---------------------------------------------------
@app.post("/predict/", dependencies=[Depends(verify_api_key)])
async def predict_api(data: dict):
    """Predict intrusion class from a JSON record (API endpoint)."""
    predictor = get_predictor()
    result = predictor.predict(data)
    logger.info(f"Prediction: {result['predicted_label']} (Confidence: {result['confidence']:.4f})")
    
    # Dashboard event tracking
    pred_label = result['predicted_label']
    dashboard_event = {
        "id": str(uuid.uuid4()),
        "SourceIP": data.get("Source IP", "Unknown"),
        "DestinationIP": data.get("Destination IP", "Unknown"),
        "Protocol": str(data.get("Protocol", "TCP")),
        "Attack": "Benign" if pred_label == "BENIGN" else pred_label,
        "timestamp": datetime.now().isoformat(),
        "severity": "high" if pred_label != "BENIGN" else "low"
    }
    live_events.appendleft(dashboard_event)

    # Log flow to history database
    try:
        history_mgr = get_history_manager()
        if history_mgr:
            history_mgr.add_flow(data, result['predicted_label'], result['confidence'])
    except Exception as e:
        logger.error(f"Critical: Failed to persist flow to history DB: {e}")

    # Automated Response under load control: queue workflows and enforce cooldown.
    if result['predicted_label'] != 'BENIGN' and result['confidence'] > IDSConfig.AUTO_WORKFLOW_CONFIDENCE:
        now = time.monotonic()
        should_queue = False
        with _auto_workflow_lock:
            global _last_auto_workflow_ts
            if now - _last_auto_workflow_ts >= IDSConfig.AUTO_WORKFLOW_COOLDOWN_SEC:
                _last_auto_workflow_ts = now
                should_queue = True

        if should_queue:
            queue_result = _queue_workflow(result, "Automated API Response")
            if queue_result["queued"]:
                logger.warning("High-confidence threat detected; workflow queued")
                result["automated_response"] = "SOC Workflow Queued"
            else:
                result["automated_response"] = "SOC Workflow Skipped (Queue Full)"
        else:
            result["automated_response"] = "SOC Workflow Deferred (Cooldown)"
        
    # Update Advanced IDS Tracking
    try:
        tracker = get_flow_tracker()
        segment_monitor = get_segment_monitor()
        _ensure_analytics_worker()

        # Update real-time flow stats
        tracker.update_flow(data)

        # Update segment monitoring
        segment_monitor.update_traffic(data)
    except Exception as e:
        logger.error(f"Error updating advanced IDS components: {e}")

    return result

@app.post("/workflow/process", dependencies=[Depends(verify_api_key)])
async def process_workflow(alert_data: dict, sync: bool = Query(False)):
    """
    Process an alert through SOC workflow.
    - sync=true: run inline and return full workflow result
    - sync=false (default): enqueue and return immediately
    """
    logger.info(f"Workflow request for alert: {alert_data.get('Attack', 'Unknown')} (sync={sync})")

    if sync:
        try:
            return _run_soc_workflow(alert_data, "API Triggered Workflow")
        except Exception as e:
            logger.error(f"Workflow processing failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    queue_result = _queue_workflow(alert_data, "API Triggered Workflow")
    if not queue_result["queued"]:
        raise HTTPException(status_code=503, detail=queue_result["message"])
    return {
        "status": "accepted",
        "detail": queue_result["message"],
        "queue_size": queue_result["queue_size"]
    }

@app.get("/reports", dependencies=[Depends(verify_api_key)])
def list_reports():
    """List all generated security incident reports."""
    reports_dir = IDSConfig.REPORTS_DIR
    if not os.path.exists(reports_dir):
        return []

    now = time.monotonic()
    global _reports_cache_ts, _reports_cache
    if now - _reports_cache_ts < IDSConfig.REPORTS_CACHE_TTL_SEC:
        return _reports_cache

    with _reports_cache_lock:
        if now - _reports_cache_ts < IDSConfig.REPORTS_CACHE_TTL_SEC:
            return _reports_cache

        reports = []
        with os.scandir(reports_dir) as entries:
            for entry in entries:
                if not entry.is_file() or not entry.name.endswith(".md"):
                    continue
                try:
                    created_at = datetime.fromtimestamp(entry.stat().st_ctime).isoformat()
                except OSError:
                    continue
                reports.append({
                    "id": entry.name,
                    "name": entry.name,
                    "created_at": created_at
                })

        reports.sort(key=lambda x: x["created_at"], reverse=True)
        _reports_cache = reports[:IDSConfig.REPORTS_LIST_LIMIT]
        _reports_cache_ts = time.monotonic()
        return _reports_cache

@app.get("/reports/{report_id}", dependencies=[Depends(verify_api_key)])
def get_report(report_id: str):
    """Retrieve content of a specific report."""
    report_path = os.path.join(IDSConfig.REPORTS_DIR, report_id)
    if not os.path.exists(report_path) or not report_id.endswith(".md"):
        raise HTTPException(status_code=404, detail="Report not found")
    
    with open(report_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    return {"id": report_id, "content": content}

@app.get("/events", dependencies=[Depends(verify_api_key)])
def get_events():
    """Get the latest live monitoring events."""
    return list(live_events)

@app.post("/events/add", dependencies=[Depends(verify_api_key)])
def add_event(event: dict):
    """Add a new event from the live monitor."""
    event['timestamp'] = datetime.now().isoformat()
    live_events.appendleft(event)
    return {"status": "success"}

@app.get("/events/stats", dependencies=[Depends(verify_api_key)])
def get_stats():
    """Get dynamic statistics for the dashboard."""
    total_events = len(live_events)
    # FIX: use 'Attack' key (matching dashboard_event structure), not 'predicted_label'
    threats = [e for e in live_events if e.get('Attack', 'Benign') != 'Benign']
    active_threats = len(threats)
    
    # Calculate packets/sec (approximate based on last 10 seconds)
    now = datetime.now()
    recent_events = []
    for e in live_events:
        ts = e.get('timestamp')
        if not ts:
            continue
        try:
            if (now - datetime.fromisoformat(ts)).total_seconds() < 10:
                recent_events.append(e)
        except Exception:
            continue
    packets_sec = len(recent_events) / 10 if recent_events else 0
    
    return {
        "packets_per_second": int(packets_sec * 60) if packets_sec > 0 else 0,
        "pending_alerts": total_events - active_threats,
        "confirmed_threats": active_threats,
        "active_agents": 5
    }

@app.get("/remediation/logs", dependencies=[Depends(verify_api_key)])
def get_remediation_logs():
    """Retrieve the automated remediation execution logs."""
    log_path = os.path.join(IDSConfig.REPORTS_DIR, "remediation_log.json")
    if not os.path.exists(log_path):
        return []
    
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            logs = json.load(f)
            return logs[::-1][:IDSConfig.REMEDIATION_LOG_LIMIT] # latest first + bounded payload
    except Exception as e:
        logger.error(f"Failed to read remediation logs: {e}")
        return []

# ---------------------------------------------------
# Autonomous SOC Rule Generator Routes
# ---------------------------------------------------

@app.post("/soc/auto-rules", dependencies=[Depends(verify_api_key)])
async def soc_auto_rules(detection: dict):
    """
    Run the AutoSOCRuleGenerator on an IDS detection dict and return
    the enforcement summary.  Accepts the same payload shape as /predict/.

    Example body:
      {
        "Source IP": "10.0.0.155",
        "Destination IP": "10.0.0.21",
        "Protocol": "TCP",
        "Destination Port": 445,
        "prediction": "SMB-Lateral",
        "confidence": 0.97
      }
    """
    try:
        generator = get_auto_soc()
        result = generator.process_ids_detection(detection)
        logger.info(
            "[SOC/auto-rules] %s rules enforced, %s failed for attack=%s",
            len(result.get("rules_enforced", [])),
            len(result.get("rules_failed", [])),
            result.get("threat_context", {}).get("attack_type", "Unknown"),
        )
        return result
    except Exception as exc:
        logger.error("[SOC/auto-rules] Error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/sandbox/state", dependencies=[Depends(verify_api_key)])
def get_sandbox_state():
    """
    Return the current DefensiveActionSandbox enforcement state:
    blocked IPs, rate limits, isolated hosts, firewall rules, etc.
    """
    try:
        generator = get_auto_soc()
        return generator.sandbox.list_active_rules()
    except Exception as exc:
        logger.error("[sandbox/state] Error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/sandbox/clear", dependencies=[Depends(verify_api_key)])
def clear_sandbox():
    """
    Reset the DefensiveActionSandbox to an empty state.
    Use during testing or after a drill exercise.
    """
    try:
        generator = get_auto_soc()
        generator.sandbox.clear_sandbox()
        logger.info("[sandbox/clear] Sandbox state reset by API call")
        return {"status": "cleared", "detail": "Sandbox state has been reset"}
    except Exception as exc:
        logger.error("[sandbox/clear] Error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------
# Advanced IDS Analytics Routes
# ---------------------------------------------------
@app.get("/api/v1/stats/realtime", dependencies=[Depends(verify_api_key)])
def get_realtime_stats():
    """Get real-time flow statistics from LiveFlowTracker."""
    tracker = get_flow_tracker()
    return tracker.get_flow_stats()

@app.get("/api/v1/stats/analytics", dependencies=[Depends(verify_api_key)])
def get_analytics_results():
    """Get current pattern analysis results from FlowAnalytics."""
    analytics = get_analytics()
    # We trigger a quick re-run if it's been a while, but usually worker handles it
    return analytics.analyze_flows()

@app.get("/api/v1/stats/segments", dependencies=[Depends(verify_api_key)])
def get_segment_stats():
    """Get network segment analysis and lateral movement detection results."""
    monitor = get_segment_monitor()
    return monitor.get_segment_analysis()

feed_process = None

@app.get("/feed-status", dependencies=[Depends(verify_api_key)])
@app.get("/v1/agl/feed-status", dependencies=[Depends(verify_api_key)])
def get_feed_status():
    """Check if the flow feed is currently running."""
    global feed_process
    is_running = feed_process is not None and feed_process.poll() is None
    return {
        "is_running": is_running,
        "detail": "Feed is active" if is_running else "Feed is stopped"
    }

@app.post("/start-feed", dependencies=[Depends(verify_api_key)])
@app.post("/v1/agl/start-feed", dependencies=[Depends(verify_api_key)])
def start_feed():
    """Start feeding flows from CSV."""
    global feed_process
    if feed_process and feed_process.poll() is None:
        return {"status": "success", "is_running": True, "message": "Feed is already running."}
    
    # FIX: correct path — feed_csv_flows.py is at Implementation/ root, not Implementation/tools/
    script_path = os.path.join(_BASE_DIR, "Implementation", "feed_csv_flows.py")
    try:
        # Pass --delay 1.5 by default for a good dashboard visualization speed
        feed_process = subprocess.Popen([sys.executable, script_path, "--delay", "1.5"])
        return {"status": "success", "is_running": True, "message": "Started feeding CSV flows."}
    except Exception as e:
        logger.error(f"Failed to start feed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/stop-feed", dependencies=[Depends(verify_api_key)])
@app.post("/v1/agl/stop-feed", dependencies=[Depends(verify_api_key)])
def stop_feed():
    """Stop feeding flows from CSV."""
    global feed_process
    if feed_process and feed_process.poll() is None:
        feed_process.terminate()
        feed_process.wait() # Ensure it's fully cleaned up
        feed_process = None
        return {"status": "success", "is_running": False, "message": "Stopped feeding CSV flows."}
    return {"status": "success", "is_running": False, "message": "No feed process was running."}

# ---------------------------------------------------
# Main
# ---------------------------------------------------
if __name__ == "__main__":
    logger.info(f"Starting IDS API server on {IDSConfig.HOST}:{IDSConfig.PORT}")
    uvicorn.run(app, host=IDSConfig.HOST, port=IDSConfig.PORT)
