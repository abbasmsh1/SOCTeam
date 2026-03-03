"""
Feed CSV Network Flows to Dashboard

This script reads network flows from CSV, processes them through the IDS,
and sends detected attacks to the backend API for display in the dashboard.
"""

import pandas as pd
import requests
import time
import sys
import os
from pathlib import Path

# Configuration
API_URL = "http://127.0.0.1:6050"
API_KEY = "ids-secret-key"
CSV_PATH = r"E:\IMT\2nd Sem\Project\Implementation\Data\dataset_subset.csv"
BATCH_SIZE = 5  # Process 5 flows at a time
DELAY = 2  # Seconds between batches

def send_to_dashboard(flow_data, prediction):
    """Send a detected flow to the dashboard via /events/add endpoint."""
    event = {
        "timestamp": pd.Timestamp.now().isoformat(),
        "SourceIP": str(flow_data.get('IPV4_SRC_ADDR', '0.0.0.0')),
        "DestinationIP": str(flow_data.get('IPV4_DST_ADDR', '0.0.0.0')),
        "SourcePort": int(flow_data.get('L4_SRC_PORT', 0)),
        "DestinationPort": int(flow_data.get('L4_DST_PORT', 0)),
        "Attack": prediction['predicted_label'],
        "confidence": prediction['confidence']
    }
    
    try:
        response = requests.post(
            f"{API_URL}/events/add",
            json=event,
            headers={"X-API-Key": API_KEY},
            timeout=5
        )
        if response.status_code == 200:
            return True
        else:
            print(f"   [!] API returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"   [X] Failed to send to dashboard: {e}")
        return False


def send_prediction_to_api(flow_data):
    """Send flow to IDS /predict/ endpoint for classification."""
    # Convert flow data to dict, handling NaN values
    flow_dict = {}
    for key, value in flow_data.items():
        if pd.isna(value):
            flow_dict[key] = 0
        else:
            flow_dict[key] = float(value) if isinstance(value, (int, float)) else str(value)
    
    try:
        response = requests.post(
            f"{API_URL}/predict/",
            json=flow_dict,
            headers={"X-API-Key": API_KEY},
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"   [!] Prediction API returned status {response.status_code}")
            return None
    except Exception as e:
        print(f"   [X] Prediction failed: {e}")
        return None


def main():
    print("=" * 60)
    print("        SOC Dashboard - CSV Network Flow Feeder           ")
    print("          Feeding Traffic Data to Live Monitor            ")
    print("=" * 60 + "\n")
    
    # Check if backend is running
    print("[*] Checking backend connection...")
    try:
        response = requests.get(f"{API_URL}/", headers={"X-API-Key": API_KEY}, timeout=3)
        if response.status_code == 200:
            resp_json = response.json()
            message = resp_json.get('message', resp_json.get('status', 'Connected'))
            print(f"[OK] Backend connected: {message}\n")
        else:
            print(f"[X] Backend returned unexpected status: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"[X] Cannot connect to backend at {API_URL}")
        print(f"   Error: {e}")
        print(f"\n[TIP] Make sure the backend is running:")
        print(f"   python -m Implementation.src.IDS.IDS\n")
        sys.exit(1)
    
    # Load CSV
    csv_full_path = Path(CSV_PATH)
    if not csv_full_path.exists():
        print(f"[X] CSV file not found: {CSV_PATH}")
        sys.exit(1)
    
    print(f"[*] Loading dataset: {CSV_PATH}")
    try:
        df = pd.read_csv(csv_full_path)
        print(f"[OK] Loaded {len(df)} network flows\n")
    except Exception as e:
        print(f"[X] Failed to load CSV: {e}")
        sys.exit(1)
    
    # Process flows in batches
    print(f"[>>] Starting to feed flows to dashboard...")
    print(f"   Batch size: {BATCH_SIZE} flows")
    print(f"   Delay: {DELAY} seconds between batches\n")
    print("="*60)
    
    total_sent = 0
    total_attacks = 0
    total_workflows = 0
    
    for i in range(0, len(df), BATCH_SIZE):
        batch = df.iloc[i:i+BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        
        print(f"\n[Batch {batch_num}] (Flows {i+1}-{min(i+BATCH_SIZE, len(df))}):")
        
        for idx, (_, flow) in enumerate(batch.iterrows(), 1):
            # Get prediction from IDS
            prediction = send_prediction_to_api(flow.to_dict())
            
            if prediction:
                attack_type = prediction['predicted_label']
                confidence = prediction['confidence'] * 100
                
                # Send to dashboard for live monitor
                if send_to_dashboard(flow.to_dict(), prediction):
                    total_sent += 1
                    symbol = "[!]" if attack_type != "BENIGN" else "[OK]"
                    print(f"   {symbol} Flow {idx}: {attack_type} ({confidence:.1f}% confidence)")
                    
                    # If malicious, trigger SOC workflow
                    if attack_type != "BENIGN" and confidence > 50:  # Only process high-confidence attacks
                        try:
                            print(f"      [->] Triggering SOC workflow...")
                            workflow_response = requests.post(
                                f"{API_URL}/workflow/process",
                                json=prediction,
                                headers={"X-API-Key": API_KEY},
                                timeout=60
                            )
                            if workflow_response.status_code == 200:
                                result = workflow_response.json()
                                total_workflows += 1
                                print(f"      [OK] Workflow complete - Severity: {result.get('final_severity', 'Unknown')}")
                            else:
                                print(f"      [!] Workflow returned status {workflow_response.status_code}")
                        except Exception as e:
                            print(f"      [X] Workflow failed: {e}")
                    
                    if attack_type != "BENIGN":
                        total_attacks += 1
        
        # Wait before next batch
        if i + BATCH_SIZE < len(df):
            print(f"\n   [...] Waiting {DELAY}s before next batch...")
            time.sleep(DELAY)
    
    print("\n" + "="*60)
    print(f"\n[OK] Complete!")
    print(f"   Total flows processed: {total_sent}")
    print(f"   Attacks detected: {total_attacks}")
    print(f"   Workflows executed: {total_workflows}")
    print(f"   Benign flows: {total_sent - total_attacks}\n")
    print(f"[*] Check your dashboard at: http://localhost:5173")
    print(f"   - Live Traffic Monitor should show the flows")
    print(f"   - Recent Reports should show {total_workflows} incident reports!\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Stopping...")
        sys.exit(0)
