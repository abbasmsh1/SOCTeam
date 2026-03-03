import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))

# Load .env first so MISTRAL_API_KEY and other vars are available
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

# Import FlowExtractor for pcap processing
try:
    from Implementation.src.IDS.FlowExtractor import FlowExtractor, check_cicflowmeter_installation
    FLOW_EXTRACTOR_AVAILABLE = True
except ImportError:
    FLOW_EXTRACTOR_AVAILABLE = False
    import warnings
    warnings.warn("FlowExtractor not available. PCAP processing disabled.")


from fastapi import Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
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
    PORT = 6050

    PORT = 6050

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
        self.label_encoder = None
        self.preprocessor = None  # Use InferencePreprocessor
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
        # Convert input dictionary to DataFrame
        df = pd.DataFrame([data])
        
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
                
        pred_idx = output.argmax(dim=1).item()
        pred_label = self.label_encoder.inverse_transform([pred_idx])[0]
        
        return {
            "predicted_label": pred_label,
            "predicted_index": int(pred_idx),
            "confidence": float(torch.softmax(output, dim=1)[0][pred_idx].item())
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
        api_key = os.getenv("MISTRAL_API_KEY")
        
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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AI-Powered Intrusion Detection System")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development, allow all origins. In production, specify the frontend URL.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "IDS Backend Gateway"}

# ---------------------------------------------------
# Security Middleware
# ---------------------------------------------------
async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != IDSConfig.API_KEY:
        logger.warning(f"Unauthorized access attempt with API Key: {x_api_key}")
        raise HTTPException(status_code=403, detail="Could not validate credentials")
    return x_api_key

# ---------------------------------------------------
# API Routes
# ---------------------------------------------------
@app.get("/")
def home():
    return {"message": "Intrusion Detection System is up and running!"}

@app.post("/predict/", dependencies=[Depends(verify_api_key)])
async def predict_api(data: dict, background_tasks: BackgroundTasks):
    """Predict intrusion class from a JSON record (API endpoint)."""
    predictor = get_predictor()
    result = predictor.predict(data)
    logger.info(f"Prediction: {result['predicted_label']} (Confidence: {result['confidence']:.4f})")
    
    # Automated Response: If confidence is high and it's a threat, trigger workflow in background
    if result['predicted_label'] != 'BENIGN' and result['confidence'] > 0.85:
        logger.warning(f"High-confidence threat detected! Auto-triggering SOC Workflow...")
        background_tasks.add_task(process_workflow_background, result)
        result["automated_response"] = "SOC Workflow Triggered"
        
    return result

async def process_workflow_background(alert_data: dict):
    """Background task to run the full SOC workflow for a detection."""
    try:
        workflow = get_workflow()
        input_data = {
            "alert_data": alert_data,
            "current_status": "Automated API Response",
            "context_logs": "System live monitoring active",
            "current_incidents": "N/A"
        }
        workflow.process(input_data)
        logger.info(f"Automated workflow complete for {alert_data.get('predicted_label')}")
    except Exception as e:
        logger.error(f"Failed automated workflow: {e}")

@app.post("/workflow/process", dependencies=[Depends(verify_api_key)])
async def process_workflow(alert_data: dict):
    """Process an alert through the full SOC Workflow."""
    workflow = get_workflow()
    logger.info(f"Starting SOC Workflow for alert: {alert_data.get('Attack', 'Unknown')}")
    
    input_data = {
        "alert_data": alert_data,
        "current_status": "API Triggered Workflow",
        "context_logs": "System live monitoring active",
        "current_incidents": "N/A"
    }
    
    try:
        result = workflow.process(input_data)
        return result
    except Exception as e:
        logger.error(f"Workflow processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports", dependencies=[Depends(verify_api_key)])
def list_reports():
    """List all generated security incident reports."""
    reports_dir = IDSConfig.REPORTS_DIR
    if not os.path.exists(reports_dir):
        return []
    
    reports = []
    for f in os.listdir(reports_dir):
        if f.endswith(".md"):
            reports.append({
                "id": f,
                "name": f,
                "created_at": datetime.fromtimestamp(os.path.getctime(os.path.join(reports_dir, f))).isoformat()
            })
    return sorted(reports, key=lambda x: x["created_at"], reverse=True)

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
    threats = [e for e in live_events if e.get('predicted_label', 'BENIGN') != 'BENIGN']
    active_threats = len(threats)
    
    # Calculate packets/sec (approximate based on last 10 seconds)
    now = datetime.now()
    recent_events = [e for e in live_events if (now - datetime.fromisoformat(e['timestamp'])).total_seconds() < 10]
    packets_sec = len(recent_events) / 10 if recent_events else 0
    
    return {
        "packets_per_second": int(packets_sec * 60) if packets_sec > 0 else 0, # Scaling for demo effect if traffic is low
        "pending_alerts": total_events - active_threats,
        "confirmed_threats": active_threats,
        "active_agents": 5 # Fixed for now, or dynamic if we track agent states
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
            return logs[::-1] # Return reversed (latest first)
    except Exception as e:
        logger.error(f"Failed to read remediation logs: {e}")
        return []

# ---------------------------------------------------
# Main
# ---------------------------------------------------
if __name__ == "__main__":
    logger.info(f"Starting IDS API server on {IDSConfig.HOST}:{IDSConfig.PORT}")
    uvicorn.run(app, host=IDSConfig.HOST, port=IDSConfig.PORT)
