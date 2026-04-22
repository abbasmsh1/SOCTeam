import os
import sys
import subprocess
import json
import uuid
import math
import warnings
import time
from queue import Queue, Full
from threading import Thread, Lock
from collections import Counter

# Windows-only: the default ProactorEventLoop has a known bug where the IOCP
# accept-loop can die on abrupt client resets (WinError 64) leaving the server
# process alive but no longer accepting connections. The selector policy is
# stable for HTTP workloads.  Must run before uvicorn creates its loop.
if sys.platform == "win32":
    import asyncio as _asyncio
    _asyncio.set_event_loop_policy(_asyncio.WindowsSelectorEventLoopPolicy())

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


from fastapi import Header, HTTPException, Depends, Query, Request
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
from collections import deque
from Implementation.src.IDS.api_models import (
    FlowRecord,
    AutoRuleRequest,
    LiveEvent,
    AlertData,
    to_plain_dict,
)

try:
    from slowapi import Limiter
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address as _slowapi_get_remote_address
    from slowapi.middleware import SlowAPIMiddleware
    _SLOWAPI_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dep
    _SLOWAPI_AVAILABLE = False

    def _slowapi_get_remote_address(request):  # type: ignore[no-redef]
        return "unknown"


class _NoopLimiter:
    """Fallback used when slowapi is not installed: disables rate limiting."""

    def limit(self, _spec: str):
        def decorator(func):
            return func
        return decorator


def _rate_limit_key(request):
    """
    Per-request rate-limit bucket.

    Admin-keyed requests get a unique bucket per request, which in practice
    skips rate limiting — the CSV feeder, live-capture worker, and any
    trusted internal tool all authenticate with the admin key. Read-key or
    unauthenticated requests fall back to per-remote-address throttling.
    """
    try:
        key = request.headers.get("X-API-Key") or ""
    except Exception:
        key = ""
    if key and key == os.environ.get("IDS_ADMIN_API_KEY"):
        # Unique per-request token → effectively unlimited
        return f"admin:{uuid.uuid4().hex}"
    return _slowapi_get_remote_address(request)


limiter = Limiter(key_func=_rate_limit_key) if _SLOWAPI_AVAILABLE else _NoopLimiter()

# Defaults tuned for internal scrapers / feeders; admin-keyed callers bypass
# entirely via the custom key_func above. These limits protect unauthenticated
# / read-only clients only.
RATE_LIMIT_PREDICT = os.getenv("IDS_RATE_LIMIT_PREDICT", "600/minute")
RATE_LIMIT_AUTO_RULES = os.getenv("IDS_RATE_LIMIT_AUTO_RULES", "30/minute")
RATE_LIMIT_SANDBOX_CLEAR = os.getenv("IDS_RATE_LIMIT_SANDBOX_CLEAR", "10/minute")

# Global Event Queue for Live Monitor
live_events = deque(maxlen=50)

# Quarantine queue — blocked flows + PENDING_HUMAN cases awaiting analyst decision
quarantine_queue: deque = deque(maxlen=200)

# Live capture state (mutated by /start-live-capture and /stop-live-capture)
import threading as _threading

_live_capture_state: Dict[str, Any] = {
    "active": False,
    "interface": None,
    "source": "idle",  # idle | live | csv
    "started_at": None,
    "flows_processed": 0,
    "last_error": None,
}
_live_capture_thread: Optional[_threading.Thread] = None
_live_capture_stop = _threading.Event()
_live_capture_lock = _threading.Lock()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
# Optional JSON-structured logs with context vars (alert_id / workflow_id).
# Opt in via IDS_JSON_LOGS=true. No-op otherwise.
from Implementation.src.IDS.logging_setup import configure_logging, set_log_context, clear_log_context  # noqa: E402
configure_logging()
logger = logging.getLogger(__name__)

# Calculate base directory relative to this file
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Drift monitor singleton (needs _BASE_DIR)
from Implementation.src.IDS.metrics.drift import DriftMonitor

_drift_baseline_path = os.path.join(_BASE_DIR, "Reports", "drift_baseline.json")
_drift_monitor = DriftMonitor(
    window_size=int(os.getenv("IDS_DRIFT_WINDOW", "500")),
    baseline_path=_drift_baseline_path if os.path.exists(_drift_baseline_path) else None,
)

def _resolve_model_path() -> str:
    """Prefer Models/manifest.json's `active_checkpoint`, fall back to default path."""
    explicit = os.getenv("IDS_MODEL_PATH")
    if explicit:
        return explicit
    models_dir = os.path.join(_BASE_DIR, "Models")
    manifest_path = os.path.join(models_dir, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as fh:
                active = json.load(fh).get("active_checkpoint")
            if active:
                return os.path.join(models_dir, active)
        except (OSError, json.JSONDecodeError):
            pass
    return os.path.join(models_dir, "best_ids_model.pth")


class IDSConfig:
    """Centralized configuration for IDS."""
    MODEL_PATH = _resolve_model_path()
    ARTIFACTS_DIR = os.getenv("IDS_ARTIFACTS_DIR", os.path.join(_BASE_DIR, "Models"))
    API_KEY = os.getenv("IDS_API_KEY", "ids-secret-key")
    ADMIN_API_KEY = os.getenv("IDS_ADMIN_API_KEY") or API_KEY
    ALLOW_DEFAULT_KEY = os.getenv("IDS_ALLOW_DEFAULT_KEY", "false").lower() == "true"
    REPORTS_DIR = os.path.join(_BASE_DIR, "Reports")
    HOST = "0.0.0.0"
    PORT = 6050  # FIX: removed duplicate PORT assignment
    # Queue SOC workflow when malicious class confidence is above this (0–1). Default: >85%.
    AUTO_WORKFLOW_CONFIDENCE = float(os.getenv("IDS_AUTO_WORKFLOW_CONFIDENCE", "0.85"))
    AUTO_WORKFLOW_COOLDOWN_SEC = float(os.getenv("IDS_AUTO_WORKFLOW_COOLDOWN_SEC", "10"))
    WORKFLOW_QUEUE_MAXSIZE = int(os.getenv("IDS_WORKFLOW_QUEUE_MAXSIZE", "200"))
    REPORTS_CACHE_TTL_SEC = float(os.getenv("IDS_REPORTS_CACHE_TTL_SEC", "30"))
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
                
        # Apply temperature scaling if a calibration file exists.
        _calib_T = getattr(self, "_calib_T", None)
        if _calib_T is None:
            try:
                cpath = os.path.join(self.artifacts_dir, "calibration.json")
                if os.path.exists(cpath):
                    with open(cpath, "r", encoding="utf-8") as _fh:
                        _calib_T = float(json.load(_fh).get("temperature", 1.0))
                else:
                    _calib_T = 1.0
                self._calib_T = _calib_T  # cache
            except Exception:
                self._calib_T = _calib_T = 1.0
        scaled = output / max(0.05, _calib_T)
        ann_probs = torch.softmax(scaled, dim=1).detach().cpu().numpy()[0]
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

        # Optional: gradient×input attributions for the predicted class.
        # Skipped on tree-only mode because the tree has its own feature importances.
        top_features = []
        if os.getenv("IDS_EXPLAIN", "true").lower() in ("1", "true", "yes") and mode != "tree_only":
            try:
                from Implementation.src.IDS.explainability import explain_top_features
                top_features = explain_top_features(
                    self.model, features_tensor, list(features.columns), pred_idx, k=5,
                )
            except Exception as exc:
                logger.debug("Explainability failed: %s", exc)

        return {
            "predicted_label": pred_label,
            "predicted_index": int(pred_idx),
            "confidence": confidence,
            "predict_mode": mode,
            "top_features": top_features,
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
    """Periodic analytics processing. Tolerates shape mismatches in the
    underlying analyzers (they sometimes return lists instead of dicts when the
    flow tracker is empty)."""
    analytics = get_analytics()
    segment_monitor = get_segment_monitor()
    _warned = {"analyze": False, "segment": False}
    while True:
        try:
            results = analytics.analyze_flows()
            if isinstance(results, dict) and results.get("anomalies_detected", 0) > 0:
                logger.info(
                    "Analytics pattern detection: %d anomalies",
                    len(results.get("patterns", []) or []),
                )
        except Exception as e:
            # Log once at error, then suppress — noisy loop otherwise
            if not _warned["analyze"]:
                logger.warning("Analytics pattern detection disabled: %s", e)
                _warned["analyze"] = True

        try:
            integrity = segment_monitor.check_segment_integrity()
            threats = integrity.get("integrity_threats", []) if isinstance(integrity, dict) else []
            if threats:
                logger.warning("Segment integrity threat: %s", threats)
        except Exception as e:
            if not _warned["segment"]:
                logger.warning("Segment integrity check disabled: %s", e)
                _warned["segment"] = True

        time.sleep(30)

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

# Lazy singleton for IPBlockingManager (shared by /predict gate + quarantine endpoints)
_ip_blocking_mgr = None
_ip_blocking_mgr_lock = Lock()


def get_ip_blocking_manager():
    """Get or create the global IPBlockingManager instance."""
    global _ip_blocking_mgr
    if _ip_blocking_mgr is None:
        with _ip_blocking_mgr_lock:
            if _ip_blocking_mgr is None:
                from Implementation.src.Agents.IPBlockingManager import IPBlockingManager
                _ip_blocking_mgr = IPBlockingManager()
                logger.info("IPBlockingManager initialised")
    return _ip_blocking_mgr

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

if _SLOWAPI_AVAILABLE:
    from starlette.responses import JSONResponse

    async def _rate_limit_exceeded_handler(request, exc):  # type: ignore[unused-argument]
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)


_BLOCKLIST_SWEEP_INTERVAL = float(os.getenv("IDS_BLOCKLIST_SWEEP_SEC", "60"))


# --- RL pipeline wiring ------------------------------------------------------
_rl_policy_singleton = None
_rl_policy_lock = Lock()


def _rl_policy():
    """Lazy-init of the adaptive confidence-threshold policy."""
    global _rl_policy_singleton
    if _rl_policy_singleton is None:
        with _rl_policy_lock:
            if _rl_policy_singleton is None:
                from Implementation.src.IDS.rl.policy import AdaptiveConfidencePolicy
                _rl_policy_singleton = AdaptiveConfidencePolicy(
                    base_threshold=IDSConfig.AUTO_WORKFLOW_CONFIDENCE,
                    persistence_path=os.path.join(_BASE_DIR, "Reports", "rl_policy.json"),
                )
    return _rl_policy_singleton


def _make_alert_id(src_ip: str, predicted_label: str) -> str:
    """Deterministic-ish alert id used to correlate /predict with the finalize hook."""
    return f"RL-{(src_ip or 'unknown').replace(':','_')}-{(predicted_label or 'UNK')[:24]}-{uuid.uuid4().hex[:8]}"


async def _blocklist_sweeper():
    import asyncio
    while True:
        try:
            generator = get_auto_soc()
            evicted = generator.ip_manager.sweep_expired()
            if evicted:
                logger.info("[blocklist-sweep] expired=%d", len(evicted))
        except Exception as exc:
            logger.warning("[blocklist-sweep] error: %s", exc)
        await asyncio.sleep(_BLOCKLIST_SWEEP_INTERVAL)


@app.on_event("startup")
async def _on_startup():
    import asyncio
    _ensure_boot_keys()
    asyncio.create_task(_blocklist_sweeper())


# Configure CORS
# CORS spec violation: allow_origins=["*"] with allow_credentials=True is
# invalid and browsers reject it. Use an explicit list (override via
# IDS_CORS_ORIGINS as comma-separated values for production).
_cors_origins = [
    o.strip() for o in os.getenv(
        "IDS_CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173,http://127.0.0.1:4173,http://localhost:4173",
    ).split(",") if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
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
_DEFAULT_API_KEY = "ids-secret-key"


def _ensure_boot_keys():
    """Refuse to boot with the shipped default unless explicitly opted in."""
    if IDSConfig.API_KEY == _DEFAULT_API_KEY and not IDSConfig.ALLOW_DEFAULT_KEY:
        raise RuntimeError(
            "IDS_API_KEY is set to the insecure default. Set IDS_API_KEY in the "
            "environment, or IDS_ALLOW_DEFAULT_KEY=true for local dev only."
        )
    if IDSConfig.ADMIN_API_KEY == _DEFAULT_API_KEY and not IDSConfig.ALLOW_DEFAULT_KEY:
        raise RuntimeError(
            "IDS_ADMIN_API_KEY is set to the insecure default. Provide a distinct "
            "admin key or set IDS_ALLOW_DEFAULT_KEY=true."
        )


async def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Read-scope auth: any caller with the read key (or admin key) is allowed."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    if x_api_key not in (IDSConfig.API_KEY, IDSConfig.ADMIN_API_KEY):
        logger.warning("Unauthorized access attempt")
        raise HTTPException(status_code=403, detail="Could not validate credentials")
    return x_api_key


async def verify_admin_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    """Admin-scope auth: only the admin key may call enforcement endpoints."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    if x_api_key != IDSConfig.ADMIN_API_KEY:
        logger.warning("Unauthorized admin access attempt")
        raise HTTPException(status_code=403, detail="Admin credentials required")
    return x_api_key


def _flow_endpoint_str(data: dict, *candidate_keys: str) -> str:
    """
    Resolve source/destination IP from heterogeneous flow JSON (manual POST, CSV/NetFlow rows).
    Pandas/JSON may supply NaN or 0.0 for missing fields; those must not become truthy bugs.
    """
    if not isinstance(data, dict):
        return "Unknown"
    for k in candidate_keys:
        if k not in data:
            continue
        v = data[k]
        if v is None:
            continue
        if isinstance(v, float):
            if math.isnan(v) or math.isinf(v) or v == 0.0:
                continue
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            s = str(v).strip()
            if s in ("", "0", "0.0"):
                continue
            return s
        if isinstance(v, str):
            s = v.strip()
            if not s or s.lower() == "nan":
                continue
            return s
        s = str(v).strip()
        if s:
            return s
    return "Unknown"


def _dashboard_protocol_label(data: dict) -> str:
    """Prefer human Protocol; map numeric PROTOCOL (e.g. 6) from CSV exports."""
    p = data.get("Protocol")
    if p is not None and str(p).strip():
        return str(p)
    pn = data.get("PROTOCOL")
    if pn is None:
        return "TCP"
    try:
        if isinstance(pn, float) and math.isnan(pn):
            return "TCP"
        n = int(float(pn))
    except (TypeError, ValueError):
        return str(pn)
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(n, f"proto-{n}")


# ---------------------------------------------------
# API Routes
# ---------------------------------------------------
def _resolve_flow_src_ip(data: dict) -> str:
    """Shared src-IP resolver for predict + live capture + quarantine gate."""
    return _flow_endpoint_str(
        data, "SourceIP", "Source IP", "src_ip",
        "IPV4_SRC_ADDR", "ipv4_src_addr", "Src IP", "source_ip",
    )


def _quarantine_blocked_flow(src_ip: str, data: dict) -> dict:
    """Record a drop for a flow whose source IP is on the active block list."""
    entry = {
        "id": str(uuid.uuid4()),
        "ip": src_ip,
        "reason": "Active block rule — traffic intercepted",
        "timestamp": datetime.now().isoformat(),
        "status": "BLOCKED",
        "raw_flow": data,
    }
    quarantine_queue.appendleft(entry)
    return entry


def _maybe_pending_human(src_ip: str, predicted_label: str, confidence: float, data: dict) -> Optional[dict]:
    """
    For medium-confidence threats (0.6 <= c < 0.9) where IP reputation says RATE_LIMIT,
    add a PENDING_HUMAN record and return it. Returns None if no human intervention needed.
    """
    if confidence < 0.6 or confidence >= 0.9 or predicted_label == "BENIGN":
        return None
    if not src_ip or src_ip == "Unknown":
        return None
    try:
        ip_mgr = get_ip_blocking_manager()
        should_block, reasoning = ip_mgr.should_block_ip(
            src_ip,
            {"Attack": predicted_label, "confidence": confidence},
        )
    except Exception as exc:
        logger.debug("should_block_ip failed for %s: %s", src_ip, exc)
        return None
    if reasoning.get("decision") != "RATE_LIMIT":
        return None
    entry = {
        "id": str(uuid.uuid4()),
        "ip": src_ip,
        "threat_label": predicted_label,
        "confidence": confidence,
        "reasoning": reasoning,
        "timestamp": datetime.now().isoformat(),
        "status": "PENDING_HUMAN",
        "raw_flow": data,
    }
    quarantine_queue.appendleft(entry)
    logger.info("Quarantined PENDING_HUMAN: %s (%s, %.2f)", src_ip, predicted_label, confidence)
    return entry


@app.post("/predict/", dependencies=[Depends(verify_api_key)])
@limiter.limit(RATE_LIMIT_PREDICT)
async def predict_api(request: Request, flow: FlowRecord):
    """Predict intrusion class from a JSON record (API endpoint)."""
    data = to_plain_dict(flow)

    # Blocked-IP gate — active firewall rules drop flows before inference
    src_ip_early = _resolve_flow_src_ip(data)
    if src_ip_early and src_ip_early != "Unknown":
        try:
            if get_ip_blocking_manager().is_ip_blocked(src_ip_early):
                _quarantine_blocked_flow(src_ip_early, data)
                try: _prom_blocked.inc()
                except Exception: pass
                return {"status": "blocked", "ip": src_ip_early, "reason": "Active firewall rule"}
        except Exception as exc:
            logger.warning("IP block lookup failed for %s: %s", src_ip_early, exc)

    predictor = get_predictor()
    with _prom_predict_latency.time():
        result = predictor.predict(data)
    logger.info(f"Prediction: {result['predicted_label']} (Confidence: {result['confidence']:.4f})")
    try:
        _prom_flows.labels(predicted_label=result['predicted_label'], source='predict_api').inc()
        _prom_confidence.labels(predicted_label=result['predicted_label']).observe(float(result.get('confidence', 0.0)))
    except Exception:
        pass
    
    # Dashboard event tracking
    pred_label = result['predicted_label']
    src = _flow_endpoint_str(
        data,
        "SourceIP",
        "Source IP",
        "src_ip",
        "IPV4_SRC_ADDR",
        "ipv4_src_addr",
        "Src IP",
        "source_ip",
    )
    dst = _flow_endpoint_str(
        data,
        "DestinationIP",
        "Destination IP",
        "dst_ip",
        "IPV4_DST_ADDR",
        "ipv4_dst_addr",
        "Dest IP",
        "destination_ip",
    )
    dashboard_event = {
        "id": str(uuid.uuid4()),
        "SourceIP": src,
        "DestinationIP": dst,
        # Mirror NetFlow keys so older UIs / bookmarks still resolve addresses
        "IPV4_SRC_ADDR": src,
        "IPV4_DST_ADDR": dst,
        "Protocol": _dashboard_protocol_label(data),
        "Attack": "Benign" if pred_label == "BENIGN" else pred_label,
        "confidence": result.get("confidence", 0.0),
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

    try:
        _drift_monitor.observe({
            k: v for k, v in data.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        })
    except Exception as e:
        logger.debug(f"Drift observe failed: {e}")

    # Medium-confidence + RATE_LIMIT reputation -> park for human review
    _maybe_pending_human(src, result['predicted_label'], result.get('confidence', 0.0), data)

    # RL: record this prediction so the agent-analysis feedback loop can label it later
    alert_id = _make_alert_id(src, result['predicted_label'])
    try:
        from Implementation.src.IDS.rl import FeedbackHook
        FeedbackHook.instance().on_prediction(
            features=data,
            predicted_label=result['predicted_label'],
            predicted_idx=int(result.get('predicted_index', 0) or 0),
            predicted_confidence=float(result.get('confidence', 0.0) or 0.0),
            src_ip=src,
            dst_ip=dst,
            alert_id=alert_id,
        )
    except Exception as exc:
        logger.debug("RL record_prediction skipped: %s", exc)

    # Automated Response under load control: queue workflows and enforce cooldown.
    # RL adaptive policy: use per-class threshold instead of the global constant.
    _rl_threshold = IDSConfig.AUTO_WORKFLOW_CONFIDENCE
    try:
        _rl_threshold = _rl_policy().threshold_for(result['predicted_label'])
    except Exception:
        pass
    if result['predicted_label'] != 'BENIGN' and result['confidence'] > _rl_threshold:
        now = time.monotonic()
        should_queue = False
        with _auto_workflow_lock:
            global _last_auto_workflow_ts
            if now - _last_auto_workflow_ts >= IDSConfig.AUTO_WORKFLOW_COOLDOWN_SEC:
                _last_auto_workflow_ts = now
                should_queue = True

        if should_queue:
            # Merge original flow fields with prediction so async worker has IPs / NetFlow keys for DB context & tiers
            workflow_payload = {**data, **result, "rl_alert_id": alert_id}
            queue_result = _queue_workflow(workflow_payload, "Automated API Response")
            if queue_result["queued"]:
                logger.warning("High-confidence threat detected; workflow queued")
                result["automated_response"] = "SOC Workflow Queued"
                try: _prom_wf_queued.labels(result='queued').inc()
                except Exception: pass
            else:
                result["automated_response"] = "SOC Workflow Skipped (Queue Full)"
                try: _prom_wf_queued.labels(result='skipped_queue_full').inc()
                except Exception: pass
        else:
            result["automated_response"] = "SOC Workflow Deferred (Cooldown)"
            try: _prom_wf_queued.labels(result='deferred_cooldown').inc()
            except Exception: pass
        
    # Update Advanced IDS Tracking
    try:
        tracker = get_flow_tracker()
        segment_monitor = get_segment_monitor()
        _ensure_analytics_worker()

        # Update real-time flow stats
        def _as_int(key, default=0):
            try:
                v = data.get(key, default)
                return int(float(v)) if v is not None else default
            except (TypeError, ValueError):
                return default

        src_ip = _flow_endpoint_str(data, "SourceIP", "Source IP", "src_ip", "IPV4_SRC_ADDR")
        dst_ip = _flow_endpoint_str(data, "DestinationIP", "Destination IP", "dst_ip", "IPV4_DST_ADDR")
        if src_ip and dst_ip and src_ip != "Unknown" and dst_ip != "Unknown":
            tracker.add_or_update_flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=_as_int("L4_SRC_PORT") or _as_int("src_port"),
                dst_port=_as_int("L4_DST_PORT") or _as_int("dst_port"),
                protocol=_dashboard_protocol_label(data),
                packet_info={
                    "size": _as_int("IN_BYTES"),
                    "packets": _as_int("IN_PKTS"),
                },
            )

        # Segment monitoring is interface-scoped; skip if no interface metadata in payload.
        iface = data.get("interface") or data.get("NIC")
        if iface and src_ip and dst_ip:
            try:
                segment_monitor.add_flow_update(
                    interface_name=str(iface),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=_as_int("L4_SRC_PORT") or _as_int("src_port"),
                    dst_port=_as_int("L4_DST_PORT") or _as_int("dst_port"),
                    protocol=_dashboard_protocol_label(data),
                    packet_info={"size": _as_int("IN_BYTES"), "packets": _as_int("IN_PKTS")},
                )
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Error updating advanced IDS components: {e}")

    return result

@app.post("/workflow/process", dependencies=[Depends(verify_admin_api_key)])
async def process_workflow(alert: AlertData, sync: bool = Query(False)):
    alert_data = to_plain_dict(alert)
    """
    Process an alert through SOC workflow.
    - sync=true: run the workflow in-process. Tier 1 completes on the request thread; if the alert
      escalates to Tier 2 (direct/microservice mode), Tier 2+ may continue on a background thread
      and the JSON may include tier2_processing=background with Tier 1 fields only until the report exists.
    - sync=false (default): enqueue full run on the workflow worker and return immediately.
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


def _report_markdown_escalated_to_tier2(file_path: str) -> bool:
    """
    Reports generated with escalated_to_tier2 include a Tier 2 section from ReportGeneratorAgent.
    Tier-1-only runs omit it (Classification: Tier 1 Analysis Only).
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read(262144)
    except OSError:
        return False
    return "## Tier 2 Analysis" in text


@app.get("/reports", dependencies=[Depends(verify_api_key)])
def list_reports():
    """List generated security incident reports escalated to Tier 2 (incident ledger)."""
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
                # Skip archive/ and other subdirs — `rotate_reports` moves
                # old reports there to keep this scan fast.
                if not entry.is_file() or not entry.name.endswith(".md"):
                    continue
                # Defensive extra filter in case archive dir ever contains loose .md
                if entry.name.startswith(".") or "archive" in entry.name.lower():
                    continue
                full_path = os.path.join(reports_dir, entry.name)
                if not _report_markdown_escalated_to_tier2(full_path):
                    continue
                try:
                    created_at = datetime.fromtimestamp(entry.stat().st_ctime).isoformat()
                except OSError:
                    continue
                reports.append({
                    "id": entry.name,
                    "name": entry.name,
                    "created_at": created_at,
                    "escalated_to_tier2": True,
                })

        reports.sort(key=lambda x: x["created_at"], reverse=True)
        _reports_cache = reports[:IDSConfig.REPORTS_LIST_LIMIT]
        _reports_cache_ts = time.monotonic()
        return _reports_cache

@app.get("/reports/{report_id}", dependencies=[Depends(verify_api_key)])
async def get_report(report_id: str):
    """Retrieve content of a specific report (async so it doesn't compete with
    slow workflow endpoints for the sync thread pool)."""
    import anyio

    if not report_id.endswith(".md"):
        raise HTTPException(status_code=404, detail="Report not found")
    report_path = os.path.join(IDSConfig.REPORTS_DIR, report_id)

    def _read() -> Optional[str]:
        if not os.path.exists(report_path):
            return None
        with open(report_path, 'r', encoding='utf-8') as f:
            return f.read()

    content = await anyio.to_thread.run_sync(_read)
    if content is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"id": report_id, "content": content}

@app.get("/events", dependencies=[Depends(verify_api_key)])
def get_events():
    """Get the latest live monitoring events."""
    return list(live_events)


@app.get("/events/stream")
async def events_stream(x_api_key: Optional[str] = Query(None), request: Request = None):
    """
    Server-Sent Events stream of dashboard state.

    Emits a JSON payload every IDS_SSE_INTERVAL_SEC seconds. Streams
    self-terminate after IDS_SSE_MAX_LIFETIME_SEC so half-dead connections
    that browsers don't properly close get cleaned up — otherwise uvicorn's
    connection pool accumulates CloseWait sockets and eventually saturates.
    """
    import asyncio
    from starlette.responses import StreamingResponse

    if x_api_key not in (IDSConfig.API_KEY, IDSConfig.ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Could not validate credentials")

    interval = float(os.getenv("IDS_SSE_INTERVAL_SEC", "2"))
    max_lifetime = float(os.getenv("IDS_SSE_MAX_LIFETIME_SEC", "300"))  # 5 minutes
    reports_every_n = int(os.getenv("IDS_SSE_REPORTS_EVERY_N", "5"))  # expensive — throttle

    async def _is_disconnected() -> bool:
        if request is None:
            return False
        try:
            return await request.is_disconnected()
        except Exception:
            return True

    import anyio

    def _build_payload_sync(fetch_reports: bool, cached_reports: list) -> dict:
        """All sync work for one SSE tick. Runs in a worker thread so the
        event loop stays responsive under file I/O / directory scans."""
        try:
            sandbox_state = get_auto_soc().sandbox.dashboard_ui_state()
        except Exception:
            sandbox_state = {"blocked_ips": [], "firewall_rules": [], "rate_limited_hosts": [], "total_actions": 0}
        try:
            remediation_logs = get_remediation_logs()
        except Exception:
            remediation_logs = []
        if fetch_reports:
            try:
                cached_reports = list_reports()
            except Exception:
                cached_reports = cached_reports or []
        return {
            "events": list(live_events),
            "stats": get_stats(),
            "sandbox": sandbox_state,
            "timeseries": get_events_timeseries(1800, 6),
            "remediation_logs": remediation_logs,
            "reports": cached_reports,
            "ts": datetime.now().isoformat(),
        }

    async def gen():
        import json as _json
        start = time.monotonic()
        tick = 0
        cached_reports: list = []
        try:
            while True:
                if await _is_disconnected():
                    break
                if time.monotonic() - start > max_lifetime:
                    yield f"event: close\ndata: lifetime_expired\n\n"
                    break

                # Sync work goes to a worker thread — never block the event loop
                fetch_reports = (tick % reports_every_n == 0)
                payload = await anyio.to_thread.run_sync(
                    _build_payload_sync, fetch_reports, cached_reports
                )
                cached_reports = payload["reports"]
                tick += 1

                yield f"data: {_json.dumps(payload)}\n\n"

                slept = 0.0
                while slept < interval:
                    step = min(0.5, interval - slept)
                    await asyncio.sleep(step)
                    slept += step
                    if await _is_disconnected():
                        return
        except (asyncio.CancelledError, GeneratorExit):
            return
        except Exception as exc:
            logger.warning("SSE stream terminated: %s: %s", type(exc).__name__, exc)
            return

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",  # disable nginx/proxy buffering if present
        },
    )

@app.post("/events/add", dependencies=[Depends(verify_api_key)])
def add_event(event: LiveEvent):
    """Add a new event from the live monitor."""
    payload = to_plain_dict(event)
    payload['timestamp'] = datetime.now().isoformat()
    live_events.appendleft(payload)
    return {"status": "success"}

@app.get("/events/timeseries", dependencies=[Depends(verify_api_key)])
def get_events_timeseries(window: int = 1800, buckets: int = 6):
    """
    Bucket the live_events deque into `buckets` equal time slices over the last
    `window` seconds and return per-bucket flow counts for the dashboard chart.
    """
    window = max(60, min(int(window), 86400))
    buckets = max(1, min(int(buckets), 60))
    bucket_sec = window / buckets
    now = datetime.now()
    start = now.timestamp() - window

    counts = [0] * buckets
    for event in live_events:
        ts = event.get("timestamp")
        if not ts:
            continue
        try:
            event_ts = datetime.fromisoformat(ts).timestamp()
        except (ValueError, TypeError):
            continue
        if event_ts < start:
            continue
        idx = int((event_ts - start) / bucket_sec)
        if 0 <= idx < buckets:
            counts[idx] += 1

    series = []
    for i, flows in enumerate(counts):
        bucket_end = now.timestamp() - (buckets - i - 1) * bucket_sec
        label = datetime.fromtimestamp(bucket_end).strftime("%H:%M")
        series.append({"name": label, "flows": flows})
    return series

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

@app.get("/metrics/drift", dependencies=[Depends(verify_api_key)])
def get_drift_metrics():
    """Current PSI report; empty if no baseline has been registered."""
    return _drift_monitor.report()


@app.get("/metrics/calibration", dependencies=[Depends(verify_api_key)])
def get_calibration_metrics():
    """Read the latest calibration report from Reports/calibration.json."""
    path = os.path.join(IDSConfig.REPORTS_DIR, "calibration.json")
    if not os.path.exists(path):
        return {"status": "unavailable", "hint": "Run metrics.calibration to populate."}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# Prometheus scrape endpoint. No auth — standard ops pattern; firewall as needed.
from Implementation.src.IDS.metrics.prometheus import (
    render as _render_prometheus,
    flows_processed_total as _prom_flows,
    workflows_queued_total as _prom_wf_queued,
    predictions_blocked_total as _prom_blocked,
    rl_feedback_total as _prom_rl_fb,
    workflow_queue_depth as _prom_queue_depth,
    live_events_in_window as _prom_live_events,
    rl_buffer_total as _prom_rl_buf,
    rl_avg_reward as _prom_rl_reward,
    prediction_latency_seconds as _prom_predict_latency,
    classifier_confidence as _prom_confidence,
)


@app.get("/metrics")
def prometheus_metrics():
    """Prometheus scrape endpoint (text/plain; version=0.0.4)."""
    from starlette.responses import Response
    # Refresh dynamic gauges before rendering
    try:
        _prom_queue_depth.set(_workflow_queue.qsize())
        _prom_live_events.set(len(live_events))
        from Implementation.src.IDS.rl import FeedbackHook
        stats = FeedbackHook.instance().stats()
        for status, n in (stats.get("by_status") or {}).items():
            _prom_rl_buf.labels(status=status).set(n)
        _prom_rl_reward.set(float(stats.get("avg_reward") or 0.0))
    except Exception:
        pass
    body, ctype = _render_prometheus()
    return Response(content=body, media_type=ctype)


@app.get("/metrics/class-balance", dependencies=[Depends(verify_api_key)])
def get_class_balance_metrics():
    """Read the latest class-balance report from Reports/class_balance.json."""
    path = os.path.join(IDSConfig.REPORTS_DIR, "class_balance.json")
    if not os.path.exists(path):
        return {"status": "unavailable", "hint": "Run metrics.class_balance to populate."}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------
# RL feedback pipeline
# ---------------------------------------------------
@app.get("/rl/stats", dependencies=[Depends(verify_api_key)])
def rl_stats():
    """Current RL experience-buffer state + per-class FP rates + thresholds."""
    from Implementation.src.IDS.rl import FeedbackHook
    hook = FeedbackHook.instance()
    stats = hook.stats()
    try:
        policy = _rl_policy()
        # Refresh policy from latest stats opportunistically
        policy.refresh_from_buffer(stats)
        stats["policy"] = policy.snapshot()
    except Exception as exc:
        stats["policy_error"] = str(exc)
    return stats


class _RLFeedbackBody(BaseModel):
    src_ip: str
    decision: str            # "allow" | "deny"
    predicted_label: Optional[str] = ""


@app.post("/rl/feedback", dependencies=[Depends(verify_admin_api_key)])
def rl_manual_feedback(body: _RLFeedbackBody):
    """
    Manually inject human feedback for an IP. Useful for CLI / scripted labeling
    outside the quarantine UI. Mirrors /quarantine/{ip}/{allow|deny} but without
    touching the firewall state.
    """
    if body.decision.lower() not in ("allow", "deny"):
        raise HTTPException(status_code=400, detail="decision must be allow|deny")
    from Implementation.src.IDS.rl import FeedbackHook
    result = FeedbackHook.instance().on_quarantine_decision(
        src_ip=body.src_ip,
        decision=body.decision.lower(),
        predicted_label=body.predicted_label or "",
    )
    return {"status": "recorded", "signal": result}


class _RLTrainBody(BaseModel):
    limit: int = 500
    epochs: int = 3
    lr: float = 1e-4
    dry_run: bool = False


@app.post("/rl/train", dependencies=[Depends(verify_admin_api_key)])
def rl_trigger_training(body: _RLTrainBody):
    """
    Run the offline fine-tuning loop. Spawns a subprocess so it doesn't block
    the event loop. Returns the subprocess result as parsed JSON.
    """
    import subprocess as _sp
    cmd = [
        sys.executable, "-m", "Implementation.src.IDS.rl.trainer",
        "--limit", str(body.limit),
        "--epochs", str(body.epochs),
        "--lr", str(body.lr),
    ]
    if body.dry_run:
        cmd.append("--dry-run")
    try:
        proc = _sp.run(
            cmd, cwd=_BASE_DIR, capture_output=True, text=True, timeout=900,
        )
    except _sp.TimeoutExpired:
        raise HTTPException(status_code=504, detail="RL training subprocess timed out after 15m")
    stdout = (proc.stdout or "").strip()
    try:
        parsed = json.loads(stdout.splitlines()[-1]) if stdout else {}
    except Exception:
        parsed = {"raw_stdout": stdout[:4000]}
    return {
        "exit": proc.returncode,
        "result": parsed,
        "stderr_tail": (proc.stderr or "")[-1500:],
    }


@app.get("/rl/policy", dependencies=[Depends(verify_api_key)])
def rl_policy_snapshot():
    """Read-only snapshot of the adaptive confidence-threshold policy."""
    try:
        return _rl_policy().snapshot()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------
# Incident graph
# ---------------------------------------------------
@app.get("/graph/summary", dependencies=[Depends(verify_api_key)])
def graph_summary():
    from Implementation.src.IDS.incident_graph import get_incident_graph
    try:
        return get_incident_graph().summary()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/graph/ip/{ip}", dependencies=[Depends(verify_api_key)])
def graph_ip(ip: str, limit: int = 25):
    from Implementation.src.IDS.incident_graph import get_incident_graph
    try:
        return {"ip": ip, "incidents": get_incident_graph().incidents_for_ip(ip, limit=limit)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/graph/attack/{attack_type}", dependencies=[Depends(verify_api_key)])
def graph_attack(attack_type: str, limit: int = 25):
    from Implementation.src.IDS.incident_graph import get_incident_graph
    try:
        return {"attack": attack_type, "ips": get_incident_graph().ips_for_attack(attack_type, limit=limit)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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

@app.post("/soc/auto-rules", dependencies=[Depends(verify_admin_api_key)])
@limiter.limit(RATE_LIMIT_AUTO_RULES)
async def soc_auto_rules(request: Request, payload: AutoRuleRequest):
    detection = to_plain_dict(payload)
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


_sandbox_cache: Dict[str, Any] = {"ts": 0.0, "payload": None}
_sandbox_cache_lock = Lock()
_SANDBOX_CACHE_TTL = float(os.getenv("IDS_SANDBOX_CACHE_TTL_SEC", "3"))


@app.get("/sandbox/state", dependencies=[Depends(verify_api_key)])
def get_sandbox_state():
    """
    Return the current DefensiveActionSandbox enforcement state.

    Merges summarized counters with dashboard_ui_state(). Cached for
    IDS_SANDBOX_CACHE_TTL_SEC because load_state() opens the SQLite sandbox DB
    with many queries and gets throttled under heavy write contention from
    live-capture workflows (many flows/sec each triggering sandbox writes).
    """
    now = time.monotonic()
    if _sandbox_cache["payload"] is not None and now - _sandbox_cache["ts"] < _SANDBOX_CACHE_TTL:
        return _sandbox_cache["payload"]
    with _sandbox_cache_lock:
        now = time.monotonic()
        if _sandbox_cache["payload"] is not None and now - _sandbox_cache["ts"] < _SANDBOX_CACHE_TTL:
            return _sandbox_cache["payload"]
        try:
            generator = get_auto_soc()
            summary = generator.sandbox.list_active_rules()
            ui = generator.sandbox.dashboard_ui_state()
            payload = {**summary, **ui}
            _sandbox_cache["payload"] = payload
            _sandbox_cache["ts"] = now
            return payload
        except Exception as exc:
            logger.error("[sandbox/state] Error: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc))


@app.post("/sandbox/clear", dependencies=[Depends(verify_admin_api_key)])
@limiter.limit(RATE_LIMIT_SANDBOX_CLEAR)
def clear_sandbox(request: Request):
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
# Live Capture Routes
# ---------------------------------------------------
def _process_flow_record(data: dict) -> Optional[Dict[str, Any]]:
    """
    Core inference + event/routing logic shared by /predict and live capture.
    Returns the prediction dict, or None if the flow was dropped (blocked IP).
    """
    src_early = _resolve_flow_src_ip(data)
    if src_early and src_early != "Unknown":
        try:
            if get_ip_blocking_manager().is_ip_blocked(src_early):
                _quarantine_blocked_flow(src_early, data)
                return None
        except Exception as exc:
            logger.warning("IP block lookup failed for %s: %s", src_early, exc)

    predictor = get_predictor()
    result = predictor.predict(data)
    pred_label = result.get("predicted_label", "UNKNOWN")
    confidence = float(result.get("confidence", 0.0))

    src = src_early
    dst = _flow_endpoint_str(
        data, "DestinationIP", "Destination IP", "dst_ip",
        "IPV4_DST_ADDR", "ipv4_dst_addr", "Dest IP", "destination_ip",
    )
    dashboard_event = {
        "id": str(uuid.uuid4()),
        "SourceIP": src,
        "DestinationIP": dst,
        "IPV4_SRC_ADDR": src,
        "IPV4_DST_ADDR": dst,
        "Protocol": _dashboard_protocol_label(data),
        "Attack": "Benign" if pred_label == "BENIGN" else pred_label,
        "confidence": confidence,
        "timestamp": datetime.now().isoformat(),
        "severity": "high" if pred_label != "BENIGN" else "low",
    }
    live_events.appendleft(dashboard_event)

    try:
        history_mgr = get_history_manager()
        if history_mgr:
            history_mgr.add_flow(data, pred_label, confidence)
    except Exception as exc:
        logger.debug("history add_flow failed: %s", exc)

    try:
        _drift_monitor.observe({
            k: v for k, v in data.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        })
    except Exception:
        pass

    _maybe_pending_human(src, pred_label, confidence, data)

    if pred_label != "BENIGN" and confidence > IDSConfig.AUTO_WORKFLOW_CONFIDENCE:
        now = time.monotonic()
        should_queue = False
        with _auto_workflow_lock:
            global _last_auto_workflow_ts
            if now - _last_auto_workflow_ts >= IDSConfig.AUTO_WORKFLOW_COOLDOWN_SEC:
                _last_auto_workflow_ts = now
                should_queue = True
        if should_queue:
            _queue_workflow({**data, **result}, "Live Capture Auto-Response")

    return result


def _live_capture_loop(interface: str, duration_per_cycle: int):
    """Background thread: repeatedly call FlowExtractor.extract_live() and feed the predictor."""
    try:
        from Implementation.src.IDS.FlowExtractor import FlowExtractor
    except Exception as exc:
        logger.error("Live capture disabled — FlowExtractor import failed: %s", exc)
        _live_capture_state["active"] = False
        _live_capture_state["source"] = "idle"
        _live_capture_state["last_error"] = f"import: {exc}"
        return

    extractor = FlowExtractor()
    logger.info("Live capture loop started on %s (cycle=%ds)", interface, duration_per_cycle)

    while not _live_capture_stop.is_set():
        try:
            flows_df = extractor.extract_live(interface=interface, duration=duration_per_cycle)
            if flows_df is None or flows_df.empty:
                continue
            for _, row in flows_df.iterrows():
                if _live_capture_stop.is_set():
                    break
                flow_dict = row.dropna().to_dict()
                try:
                    _process_flow_record(flow_dict)
                    _live_capture_state["flows_processed"] += 1
                except Exception as exc:
                    logger.warning("Live flow processing error: %s", exc)
        except Exception as exc:
            logger.error("Live capture cycle failed: %s", exc)
            _live_capture_state["last_error"] = str(exc)
            _live_capture_stop.wait(timeout=2.0)

    logger.info("Live capture loop exited for %s", interface)
    _live_capture_state["active"] = False
    _live_capture_state["source"] = "idle"


@app.get("/interfaces", dependencies=[Depends(verify_api_key)])
def list_interfaces():
    """List available network interfaces for live capture."""
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
    except ImportError:
        raise HTTPException(status_code=501, detail="scapy not installed")
    except Exception as exc:
        logger.error("get_if_list failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    return {"interfaces": ifaces}


class _StartCaptureBody(BaseModel):
    interface: str
    duration_per_cycle: int = 5


@app.post("/start-live-capture", dependencies=[Depends(verify_admin_api_key)])
def start_live_capture(body: _StartCaptureBody):
    """Begin continuous live capture on the given interface."""
    global _live_capture_thread
    with _live_capture_lock:
        if _live_capture_state["active"]:
            raise HTTPException(status_code=409, detail=f"capture already running on {_live_capture_state['interface']}")
        _live_capture_stop.clear()
        _live_capture_state.update({
            "active": True,
            "interface": body.interface,
            "source": "live",
            "started_at": datetime.now().isoformat(),
            "flows_processed": 0,
            "last_error": None,
        })
        _live_capture_thread = _threading.Thread(
            target=_live_capture_loop,
            args=(body.interface, max(1, int(body.duration_per_cycle))),
            name=f"live-capture-{body.interface}",
            daemon=True,
        )
        _live_capture_thread.start()
    return {"status": "started", "interface": body.interface}


@app.post("/stop-live-capture", dependencies=[Depends(verify_admin_api_key)])
def stop_live_capture():
    """Stop the active live-capture loop (if any)."""
    global _live_capture_thread
    with _live_capture_lock:
        if not _live_capture_state["active"]:
            return {"status": "idle"}
        _live_capture_stop.set()
        thread = _live_capture_thread
    if thread is not None:
        thread.join(timeout=10)
    with _live_capture_lock:
        _live_capture_state["active"] = False
        _live_capture_state["source"] = "idle"
        _live_capture_thread = None
    return {"status": "stopped"}


@app.get("/capture-status", dependencies=[Depends(verify_api_key)])
def capture_status():
    """Return current capture state (live | csv | idle)."""
    return dict(_live_capture_state)


# ---------------------------------------------------
# Quarantine / Human Intervention Routes
# ---------------------------------------------------
def _pop_quarantine(ip: str) -> Optional[dict]:
    """Remove the most recent quarantine entry for this IP and return it."""
    for i, entry in enumerate(list(quarantine_queue)):
        if entry.get("ip") == ip:
            del quarantine_queue[i]
            return entry
    return None


@app.get("/quarantine", dependencies=[Depends(verify_api_key)])
def list_quarantine():
    """Return all quarantine entries (BLOCKED + PENDING_HUMAN) newest-first."""
    return list(quarantine_queue)


@app.post("/quarantine/{ip}/allow", dependencies=[Depends(verify_admin_api_key)])
def allow_quarantined_ip(ip: str):
    """Analyst decision: whitelist the IP and drop the quarantine entry."""
    entry = _pop_quarantine(ip)
    try:
        get_ip_blocking_manager().add_to_whitelist(ip, reason="Analyst ALLOW decision via /quarantine")
    except Exception as exc:
        logger.error("allow_quarantined_ip whitelist error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    try:
        from Implementation.src.IDS.rl import FeedbackHook
        FeedbackHook.instance().on_quarantine_decision(
            src_ip=ip, decision="allow",
            predicted_label=(entry or {}).get("threat_label", ""),
        )
    except Exception as exc:
        logger.debug("RL quarantine-allow hook skipped: %s", exc)
    return {"status": "allowed", "ip": ip, "entry": entry}


@app.post("/quarantine/{ip}/deny", dependencies=[Depends(verify_admin_api_key)])
def deny_quarantined_ip(ip: str):
    """Analyst decision: persist a block via IPBlockingManager + sandbox auto-pilot."""
    entry = _pop_quarantine(ip) or {}
    reason = entry.get("reason") or f"Analyst DENY decision for {entry.get('threat_label', 'unknown')}"
    duration = "permanent"
    severity = "high"
    try:
        ip_mgr = get_ip_blocking_manager()
        ip_mgr.add_blocked_ip(ip=ip, reason=reason, duration=duration, threat_severity=severity)
        sandbox = get_auto_soc().sandbox
        sandbox_result = sandbox.execute_rule(
            rule={"action": "BLOCK_IP", "target": ip, "reason": reason, "duration": duration},
            threat_info={"confidence": entry.get("confidence", 0.99), "Attack": entry.get("threat_label", "UNKNOWN"), "SourceIP": ip},
            auto_pilot=True,
        )
    except Exception as exc:
        logger.error("deny_quarantined_ip error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    try:
        from Implementation.src.IDS.rl import FeedbackHook
        FeedbackHook.instance().on_quarantine_decision(
            src_ip=ip, decision="deny",
            predicted_label=entry.get("threat_label", ""),
        )
    except Exception as exc:
        logger.debug("RL quarantine-deny hook skipped: %s", exc)
    return {"status": "blocked", "ip": ip, "entry": entry, "sandbox_result": sandbox_result}


@app.get("/blocked-ips", dependencies=[Depends(verify_api_key)])
def list_blocked_ips():
    """Return the full IPBlockingManager block list (with expiry)."""
    try:
        return get_ip_blocking_manager().get_block_list()
    except Exception as exc:
        logger.error("list_blocked_ips error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/blocked-ips/{ip}", dependencies=[Depends(verify_admin_api_key)])
def unblock_ip(ip: str):
    """Manual unblock — removes the IP from IPBlockingManager's active list."""
    try:
        removed = get_ip_blocking_manager().remove_blocked_ip(ip)
    except Exception as exc:
        logger.error("unblock_ip error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))
    if not removed:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found in block list")
    return {"status": "unblocked", "ip": ip}


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
