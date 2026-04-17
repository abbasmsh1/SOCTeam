import os
import torch
import pandas as pd
import joblib
import numpy as np
import json
import hashlib
from torch.utils.data import IterableDataset, DataLoader
from ann_model import IDSModel, IDSTrainer
from preprocess import fit_pipeline_and_encoder, process_data_chunks
import glob
import re
from tree_ensemble import (
    train_tree_model,
    save_tree_model,
    predict_proba_tree,
    tune_ensemble_weight,
)
from sklearn.model_selection import train_test_split

# Calculate base directory relative to this file
# This file is at: Implementation/src/IDS/train.py
# Base project directory is 3 levels up
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

class ChunkedDataset(IterableDataset):
    def __init__(self, path, pipeline, label_encoder, split='train', chunksize=50000):
        self.path = path
        self.pipeline = pipeline
        self.label_encoder = label_encoder
        self.split = split
        self.chunksize = chunksize

    def __iter__(self):
        # Create a generator that yields (X, y) batches from chunks
        for X_chunk, y_chunk in process_data_chunks(self.path, self.pipeline, self.label_encoder, 
                                                    chunksize=self.chunksize, split=self.split):
            # Convert to tensors
            X_tensor = torch.tensor(X_chunk, dtype=torch.float32)
            y_tensor = torch.tensor(y_chunk, dtype=torch.long)
            # Yield sample by sample
            for i in range(len(X_tensor)):
                yield X_tensor[i], y_tensor[i]

    def __len__(self):
        # NF-UQ-NIDS-v2 has ~16.2M flows total. 
        # Using 16,223,463 as the base for calculation.
        total_rows = 16223463
        if self.split == 'train':
            return int(total_rows * 0.8)
        elif self.split == 'val':
            return int(total_rows * 0.1)
        else: # test
            return int(total_rows * 0.1)

def train_ids_model():
    print("Starting IDS Model Training (Chunked Mode)...")
    torch.manual_seed(42)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(42)

    # Update to new dataset path (partitioned) - Use relative path from base
    data_path = os.path.join(_BASE_DIR, "Implementation", "Data", "NF-UQ-NIDS-v2.part-*")
    
    # Check if any files match the pattern
    import glob
    if not glob.glob(data_path):
        print(f"Dataset parts not found at {data_path}. Falling back to old dataset (if exists).")
        data_path = os.path.join(_BASE_DIR, "Data", "Preprocessed_CICIDS2018.csv")
    
    print(f"Using dataset pattern: {data_path}")
    
    models_dir = os.path.join(_BASE_DIR, "Models")
    os.makedirs(models_dir, exist_ok=True)
    
    # 1. Fit pipeline and encoder on a sample
    print("\nPreparing pipeline and encoders...")
    # Use a smaller sample for fitting to be fast, but large enough to capture distribution
    pipeline, label_encoder = fit_pipeline_and_encoder(
        data_path,
        sample_size=100000,
        save_dir=models_dir,
        enable_entropy=True,
        entropy_window_seconds=10,
    )
    
    # 2. Determine input size by transforming a small dummy chunk
    print("Determining input size...")
    # Get first part for dummy load
    first_part = glob.glob(data_path)[0]
    dummy_df = pd.read_csv(first_part, nrows=1000) # Load more for better weight estimate
    # We need to handle the label column dropping inside pipeline or manually
    # The pipeline expects the full dataframe
    processed_dummy = pipeline.transform(dummy_df)
    # Identify label col to drop for input size check
    label_col = 'Attack' if 'Attack' in dummy_df.columns else 'Label' if 'Label' in dummy_df.columns else None
    if label_col and label_col in processed_dummy.columns:
        input_size = processed_dummy.shape[1] - 1 # Subtract label column
    else:
        input_size = processed_dummy.shape[1]
        
    num_classes = len(label_encoder.classes_)
    print(f"Input Features: {input_size}, Classes: {num_classes}")
    print(f"Classes: {label_encoder.classes_}")

    # 3. Create Datasets and Loaders
    # We use a larger chunksize for efficiency
    chunksize = 100000 
    
    train_dataset = ChunkedDataset(data_path, pipeline, label_encoder, split='train', chunksize=chunksize)
    val_dataset = ChunkedDataset(data_path, pipeline, label_encoder, split='val', chunksize=chunksize)
    test_dataset = ChunkedDataset(data_path, pipeline, label_encoder, split='test', chunksize=chunksize)

    # num_workers=0 because we are reading a file sequentially. 
    # If we want parallel, we need complex logic to seek file.
    # Optimize: Increase batch size and use pin_memory
    batch_size = 524288
    use_pin_memory = torch.cuda.is_available()
    
    train_loader = DataLoader(train_dataset, batch_size=batch_size, pin_memory=use_pin_memory) 
    val_loader = DataLoader(val_dataset, batch_size=batch_size, pin_memory=use_pin_memory)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, pin_memory=use_pin_memory)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training on: {device}")
    
    model = IDSModel(input_size=input_size, hidden_size=128, output_size=num_classes).to(device)

    # 4. Calculate Class Weights for focal/weighted loss
    print("Calculating class weights for imbalanced dataset...")
    label_counts = dummy_df[label_col].value_counts()
    # For a more accurate weight, we should ideally scan the dataset or use a large sample
    # But since we have all_labels from get_unique_labels, we can at least initialize them
    total_samples = label_counts.sum()
    weights = []
    for cls in label_encoder.classes_:
        count = label_counts.get(cls, 1) # Default to 1 if not in sample
        weight = total_samples / (len(label_encoder.classes_) * count)
        weights.append(weight)
    
    # Normalize weights
    weights = np.array(weights)
    weights = weights / weights.min()
    print(f"Computed Weights: {dict(zip(label_encoder.classes_, weights))}")

    trainer = IDSTrainer(model, train_loader, val_loader, test_loader, device=device, save_path=os.path.join(models_dir, "best_ids_model.pth"))
    
    # Check for existing checkpoints to resume
    start_epoch = 1
    
    checkpoint_pattern = os.path.join(models_dir, "best_ids_model_epoch_*.pth")
    checkpoints = glob.glob(checkpoint_pattern)
    
    if checkpoints:
        # Extract epoch numbers
        epoch_nums = []
        for cp in checkpoints:
            match = re.search(r"epoch_(\d+)\.pth", cp)
            if match:
                epoch_nums.append(int(match.group(1)))
        
        if epoch_nums:
            latest_epoch = max(epoch_nums)
            latest_checkpoint = os.path.join(models_dir, f"best_ids_model_epoch_{latest_epoch}.pth")
            
            print(f"Found existing checkpoint: {latest_checkpoint}")
            try:
                print(f"Resuming training from epoch {latest_epoch + 1}...")
                trainer.load_checkpoint(latest_checkpoint)
            except RuntimeError as e:
                print(f"⚠️ Could not load checkpoint due to schema mismatch (likely class count changed): {e}")
                print("Starting training from scratch instead.")
            except Exception as e:
                print(f"⚠️ Unexpected error loading checkpoint: {e}")
                print("Starting training from scratch instead.")
            start_epoch = latest_epoch + 1
    
    # Train
    # Set epochs=15 for finetuning as OneCycleLR is very efficient
    trainer.train(epochs=15, start_epoch=start_epoch, class_weights=weights, use_one_cycle=True)
    
    # Evaluate
    trainer.evaluate()

    # ------------------------------------------------------------------
    # Tree model + ensemble tuning (sampled, to keep memory bounded)
    # ------------------------------------------------------------------
    print("\nTraining tree model (sampled) for hybrid ensemble...")
    # Sample a bounded amount of data from the already-processed stream
    X_buf = []
    y_buf = []
    max_rows = 200000  # keep manageable on Windows
    for X_chunk, y_chunk in process_data_chunks(
        data_path, pipeline, label_encoder, chunksize=50000, split="train"
    ):
        X_buf.append(X_chunk)
        y_buf.append(y_chunk)
        if sum(x.shape[0] for x in X_buf) >= max_rows:
            break

    manifest = {
        "feature_schema_version": "entropy_v1",
        "artifacts_dir": models_dir,
        "ann_checkpoint": os.path.join(models_dir, "best_ids_model.pth"),
        "tree_model": None,
        "ensemble_weight": None,
        "metrics": {},
    }

    # Hash feature schema for safety
    feature_names_path = os.path.join(models_dir, "feature_names.txt")
    if os.path.exists(feature_names_path):
        with open(feature_names_path, "rb") as fh:
            manifest["feature_names_sha256"] = hashlib.sha256(fh.read()).hexdigest()

    if X_buf and y_buf:
        X_all = np.vstack(X_buf)
        y_all = np.concatenate(y_buf)
        X_train_s, X_val_s, y_train_s, y_val_s = train_test_split(
            X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
        )

        tree_model = train_tree_model(X_train_s, y_train_s, random_state=42)
        tree_path = os.path.join(models_dir, "tree_model.joblib")
        save_tree_model(tree_model, tree_path)
        print(f"✅ Tree model saved to {tree_path}")
        manifest["tree_model"] = tree_path

        # ANN logits on validation sample
        model.eval()
        with torch.no_grad():
            logits = model(torch.tensor(X_val_s, dtype=torch.float32).to(device)).cpu().numpy()
        tree_proba = predict_proba_tree(tree_model, X_val_s)
        tune = tune_ensemble_weight(logits, tree_proba, y_val_s)
        print(
            f"✅ Ensemble tuning: best_w={tune.best_weight:.2f} macroF1={tune.best_macro_f1:.4f} "
            f"(ann={tune.ann_macro_f1:.4f}, tree={tune.tree_macro_f1:.4f})"
        )
        manifest["ensemble_weight"] = tune.best_weight
        manifest["metrics"]["macro_f1"] = {
            "ann": tune.ann_macro_f1,
            "tree": tune.tree_macro_f1,
            "ensemble": tune.best_macro_f1,
        }
    else:
        print("⚠️ Skipping tree model training: could not sample training data.")

    # Persist manifest
    manifest_path = os.path.join(models_dir, "ids_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"✅ IDS manifest saved to {manifest_path}")

    model_path = os.path.join(models_dir, "best_ids_model.pth")
    print(f"✅ Model training complete. Saved to {model_path}")

if __name__ == "__main__":
    train_ids_model()