import os
import sys
import pandas as pd
import requests
import json
import time
import argparse

def main():
    parser = argparse.ArgumentParser(description="Feed CSV flows to the IDS API to simulate live traffic.")
    parser.add_argument("--csv", type=str, default="Data/dataset_subset.csv", help="Path to the CSV dataset")
    parser.add_argument("--url", type=str, default="http://localhost:6050/predict/", help="IDS API URL")
    parser.add_argument("--api-key", type=str, default="ids-secret-key", help="API Key for IDS API")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay in seconds between requests")
    parser.add_argument("--skip", type=int, default=0, help="Skip the first N rows")
    
    args = parser.parse_args()
    
    # Resolve CSV path relative to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = args.csv if os.path.isabs(args.csv) else os.path.join(script_dir, args.csv)
    
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}")
        sys.exit(1)
        
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    headers = {
        "X-API-Key": args.api_key,
        "Content-Type": "application/json"
    }
    
    print(f"Starting simulation. Sending to {args.url} with {args.delay}s delay between requests...")
    count = 0
    for idx, row in df.iterrows():
        if count < args.skip:
            count += 1
            continue
            
        data = row.to_dict()
        try:
            # Handle any non-serializable types like NaN or integers
            clean_data = {}
            for k, v in data.items():
                if pd.isna(v):
                    clean_data[k] = 0.0
                else:
                    clean_data[k] = v
                    
            start_time = time.time()
            response = requests.post(args.url, json=clean_data, headers=headers)
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                label = result.get('predicted_label', 'UNKNOWN')
                confidence = result.get('confidence', 0.0)
                automated = result.get('automated_response', '')
                
                print(f"[{count}] Flow {idx} -> {label} ({confidence:.2f}) {f'[{automated}]' if automated else ''} - {elapsed:.2f}s")
            else:
                print(f"[{count}] Flow {idx} -> HTTP {response.status_code}: {response.text}")
                
        except requests.exceptions.ConnectionError:
            print(f"[{count}] Error: Cannot connect to {args.url}. Is the IDS server running?")
            time.sleep(5) # Wait and retry
            continue
        except Exception as e:
            print(f"[{count}] Error sending flow {idx}: {e}")
            
        count += 1
        if args.delay > 0:
            time.sleep(args.delay)

if __name__ == "__main__":
    main()
