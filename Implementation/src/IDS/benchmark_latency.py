import os
import time
import pandas as pd
import torch
import numpy as np
import sys

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from IDS import IDSPredictor
except ImportError:
    # If running from outside, we might need to adjust path
    # File is at: e:\IMT\2nd Sem\Project\Implementation\src\IDS\benchmark_latency.py
    # Root is 4 levels up
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    sys.path.append(root_dir)
    from Implementation.src.IDS.IDS import IDSPredictor

def benchmark():
    base_dir = r"e:\IMT\2nd Sem\Project"
    model_path = os.path.join(base_dir, "Models", "best_ids_model.pth")
    artifacts_dir = os.path.join(base_dir, "Models")
    data_path = os.path.join(base_dir, "Implementation", "Data", "NF-UQ-NIDS-v2.part-000")
    
    print(f"Loading benchmark data from {data_path}...")
    try:
        df = pd.read_csv(data_path, nrows=5000)
    except FileNotFoundError:
        print(f"❌ Error: Benchmark data file not found at {data_path}")
        return
    
    # Initialize predictor
    print("Initializing IDSPredictor...")
    try:
        predictor = IDSPredictor(model_path=model_path, artifacts_dir=artifacts_dir)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error initializing predictor: {e}")
        return

    # Benchmark Single Record Latency
    print("\n--- Single Record Benchmarking ---")
    single_record = df.iloc[0].to_dict()
    
    # Warmup
    for _ in range(5):
        _ = predictor.predict(single_record)
        
    start_time = time.time()
    num_iterations = 100
    for _ in range(num_iterations):
        _ = predictor.predict(single_record)
    end_time = time.time()
    
    avg_latency = (end_time - start_time) / num_iterations * 1000
    print(f"Average Single Record Latency: {avg_latency:.4f} ms")

    # Benchmark Batch Latency
    print("\n--- Batch Benchmarking ---")
    batch_sizes = [1, 10, 100, 1000, 5000]
    
    for size in batch_sizes:
        batch_df = df.head(size)
        
        # Warmup
        _ = predictor.predict_batch(batch_df.head(10)) if size > 10 else None
        
        start_time = time.time()
        _ = predictor.predict_batch(batch_df)
        end_time = time.time()
        
        total_time = (end_time - start_time) * 1000
        per_record = total_time / size
        print(f"Batch Size {size:5}: Total Time: {total_time:10.2f} ms | Per Record: {per_record:10.4f} ms")

if __name__ == "__main__":
    benchmark()
