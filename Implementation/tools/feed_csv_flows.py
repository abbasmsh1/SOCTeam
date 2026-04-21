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
import argparse
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    pass

# Configuration
API_URL = os.getenv("IDS_BASE_URL", "http://127.0.0.1:6050")
# Feeder posts to /predict (read scope) AND /workflow/process (admin scope),
# so default to the admin key if set; fall back to read-only.
API_KEY = os.getenv("IDS_ADMIN_API_KEY") or os.getenv("IDS_API_KEY") or "ids-secret-key"
CSV_PATH = r"E:\IMT\2nd Sem\Project\Implementation\Data\dataset_subset.csv"
BATCH_SIZE = 5  # Process 5 flows at a time
DELAY = 2  # Seconds between batches


def normalize_flow_record(flow_row) -> dict:
    """Convert a pandas Series (or any .items() mapping) to a JSON-safe dict for the IDS API."""
    out = {}
    for key, value in flow_row.items():
        if pd.isna(value):
            out[key] = 0
        else:
            out[key] = float(value) if isinstance(value, (int, float)) else str(value)
    return out


# Label columns we recognise (first hit wins)
_LABEL_COLUMN_CANDIDATES = ("Attack", "attack_type", "Label", "label", "category")
# Timestamp columns we recognise
_TS_COLUMN_CANDIDATES = ("Timestamp", "timestamp", "flow_start", "FLOW_START", "TIMESTAMP")


def _detect_label_col(df: pd.DataFrame):
    for c in _LABEL_COLUMN_CANDIDATES:
        if c in df.columns:
            return c
    return None


def _detect_ts_col(df: pd.DataFrame):
    for c in _TS_COLUMN_CANDIDATES:
        if c in df.columns:
            return c
    return None


def build_priority_schedule(df: pd.DataFrame, ratio: int = 3):
    """
    Produce an iterable of DataFrame rows ordered as (ratio * attack) : (1 * benign).

    Recency: within each bucket, rows are sorted newest-first when a timestamp
    column is detected, so the freshest threats fire first — closer to how a
    real SIEM queues incoming alerts.

    Falls back to original insertion order when the label column is missing
    (so the feeder still works with any dataset shape).
    """
    label_col = _detect_label_col(df)
    if label_col is None:
        return list(df.itertuples(index=False))

    ts_col = _detect_ts_col(df)
    if ts_col is not None:
        try:
            parsed = pd.to_datetime(df[ts_col], errors="coerce")
            df = df.assign(_ts=parsed).sort_values("_ts", ascending=False, na_position="last").drop(columns=["_ts"])
        except Exception:
            pass

    labels = df[label_col].astype(str).str.upper().fillna("BENIGN")
    is_attack = ~labels.isin({"BENIGN", "NORMAL", "", "NAN"})
    attacks = df[is_attack]
    benign = df[~is_attack]

    print(f"[priority] detected label column '{label_col}' — {len(attacks)} attacks / {len(benign)} benign (ratio {ratio}:1)")

    scheduled = []
    a_iter = iter(attacks.itertuples(index=False))
    b_iter = iter(benign.itertuples(index=False))
    a_exhausted = b_exhausted = False
    while not (a_exhausted and b_exhausted):
        # ratio attacks then one benign
        for _ in range(ratio):
            try:
                scheduled.append(next(a_iter))
            except StopIteration:
                a_exhausted = True
                break
        try:
            scheduled.append(next(b_iter))
        except StopIteration:
            b_exhausted = True
    return scheduled


def send_prediction_to_api(flow_row, backend_url):
    """Send flow to IDS /predict/ endpoint for classification."""
    flow_dict = normalize_flow_record(flow_row)
    
    try:
        response = requests.post(
            f"{backend_url}/predict/",
            json=flow_dict,
            headers={"X-API-Key": API_KEY},
            timeout=30
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
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Feed CSV Network Flows to SOC Dashboard')
    parser.add_argument('--backend-port', type=int, default=6050, help='Backend IDS API port (default: 6050)')
    parser.add_argument('--frontend-port', type=int, default=5173, help='Frontend dashboard port (default: 5173)')
    parser.add_argument('--delay', type=float, default=2, help='Seconds between batches (default: 2)')
    parser.add_argument('--batch-size', type=int, default=5, help='Flows per batch (default: 5)')
    parser.add_argument('--priority', action='store_true',
                        help='Prioritise attack-classified flows (recency-first within buckets)')
    parser.add_argument('--priority-ratio', type=int, default=3,
                        help='When --priority: N attack flows per 1 benign (default: 3)')
    args = parser.parse_args()
    
    # Update configuration based on arguments
    backend_url = f"http://127.0.0.1:{args.backend_port}"
    frontend_url = f"http://127.0.0.1:{args.frontend_port}"
    
    print("=" * 60)
    print("        SOC Dashboard - CSV Network Flow Feeder           ")
    print("          Feeding Traffic Data to Live Monitor            ")
    print("=" * 60 + "\n")
    
    # Check if backend is running
    print("[*] Checking backend connection...")
    try:
        response = requests.get(f"{backend_url}/", headers={"X-API-Key": API_KEY}, timeout=15)
        if response.status_code == 200:
            resp_json = response.json()
            message = resp_json.get('message', resp_json.get('status', 'Connected'))
            print(f"[OK] Backend connected: {message}\n")
        else:
            print(f"[X] Backend returned unexpected status: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"[X] Cannot connect to backend at {backend_url}")
        print(f"   Error: {e}")
        print(f"\n[TIP] Make sure the backend is running:")
        print(f"   python -m uvicorn Implementation.src.IDS.IDS:app --host 127.0.0.1 --port {args.backend_port}\n")
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
    
    # Build the send schedule
    if args.priority:
        schedule = build_priority_schedule(df, ratio=args.priority_ratio)
        print(f"[>>] Priority mode: {len(schedule)} flows scheduled (attacks first, {args.priority_ratio}:1 ratio)")
    else:
        schedule = list(df.itertuples(index=False))
        print(f"[>>] Sequential mode: {len(schedule)} flows in CSV order")

    # Process flows in batches
    print(f"   Batch size: {args.batch_size} flows")
    print(f"   Delay: {args.delay} seconds between batches\n")
    print("="*60)

    total_sent = 0
    total_attacks = 0
    total_workflows = 0

    def _row_to_series(row):
        """namedtuple -> pandas-like dict-compatible .items()."""
        return pd.Series(row._asdict())

    for i in range(0, len(schedule), args.batch_size):
        batch = schedule[i:i + args.batch_size]
        batch_num = (i // args.batch_size) + 1

        print(f"\n[Batch {batch_num}] (Flows {i+1}-{min(i+args.batch_size, len(schedule))}):")

        for idx, row in enumerate(batch, 1):
            flow = _row_to_series(row)
            prediction = send_prediction_to_api(flow, backend_url)
            
            if prediction:
                attack_type = prediction['predicted_label']
                confidence = prediction['confidence'] * 100
                
                # Backend predict API now automatically adds event to dashboard
                total_sent += 1
                symbol = "[!]" if attack_type != "BENIGN" else "[OK]"
                print(f"   {symbol} Flow {idx}: {attack_type} ({confidence:.1f}% confidence)")
                
                # If malicious, trigger SOC workflow
                if attack_type != "BENIGN" and confidence > 50:  # Only process high-confidence attacks
                    try:
                        print(f"      [->] Triggering SOC workflow (sync)...")
                        # Merge original NetFlow row with prediction IDs so `/workflow/process` has IPV4_*, ports,
                        # etc. for tier analysts and flow_history.db context (prediction JSON alone has no IPs).
                        workflow_body = {**normalize_flow_record(flow), **prediction}
                        # sync=true runs the workflow inline and returns final_result including final_severity.
                        # Default sync=false only acknowledges the job to the queue — no severity in the body.
                        workflow_response = requests.post(
                            f"{backend_url}/workflow/process",
                            json=workflow_body,
                            params={"sync": True},
                            headers={"X-API-Key": API_KEY},
                            timeout=300,
                        )
                        if workflow_response.status_code == 200:
                            result = workflow_response.json()
                            total_workflows += 1
                            if result.get("status") == "accepted":
                                print(
                                    "      [OK] Workflow queued (async); response has no final_severity — "
                                    "call with ?sync=true for a full result."
                                )
                            elif result.get("error"):
                                print(f"      [!] Workflow error: {result.get('error')}")
                            else:
                                sev = result.get("final_severity")
                                if sev is None:
                                    sev = "Unknown"
                                print(f"      [OK] Workflow complete - Severity: {sev}")
                        else:
                            print(f"      [!] Workflow returned status {workflow_response.status_code}")
                    except Exception as e:
                        print(f"      [X] Workflow failed: {e}")
                
                if attack_type != "BENIGN":
                    total_attacks += 1
        
        # Wait before next batch
        if i + args.batch_size < len(schedule):
            print(f"\n   [...] Waiting {args.delay}s before next batch...")
            time.sleep(args.delay)
    
    print("\n" + "="*60)
    print(f"\n[OK] Complete!")
    print(f"   Total flows processed: {total_sent}")
    print(f"   Attacks detected: {total_attacks}")
    print(f"   Workflows executed: {total_workflows}")
    print(f"   Benign flows: {total_sent - total_attacks}\n")
    print(f"[*] Check your dashboard at: {frontend_url}")
    print(f"   - Live Traffic Monitor should show the flows")
    print(f"   - Recent Reports should show {total_workflows} incident reports!\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Stopping...")
        sys.exit(0)
