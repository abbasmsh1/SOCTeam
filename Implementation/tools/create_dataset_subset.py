"""
Create a stratified subset of the NF-UQ-NIDS-v2 dataset with N examples per class.

This script reads the partitioned dataset files and extracts a balanced subset
with a specified number of examples from each attack class.
"""

import os
import sys
import pandas as pd
import glob
from collections import defaultdict

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from Implementation.src.IDS.preprocess import get_unique_labels

# Calculate base directory
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def create_stratified_subset(data_pattern: str, samples_per_class: int = 15, output_path: str = None, chunksize: int = 100000):
    """
    Create a stratified subset with N samples per class.
    
    Args:
        data_pattern: Glob pattern for dataset files (e.g., "Data/NF-UQ-NIDS-v2.part-*")
        samples_per_class: Number of samples to extract per class
        output_path: Path to save the subset CSV
        chunksize: Chunk size for reading large files
    
    Returns:
        Path to the created subset file
    """
    print("=" * 80)
    print(f"Creating Dataset Subset with {samples_per_class} samples per class")
    print("=" * 80)
    
    # Find all dataset files
    paths = sorted(glob.glob(data_pattern))
    if not paths:
        raise FileNotFoundError(f"No files found matching pattern: {data_pattern}")
    
    print(f"\nFound {len(paths)} dataset files:")
    for p in paths:
        print(f"  - {os.path.basename(p)}")
    
    # Get schema from first file
    print("\nReading dataset schema...")
    header_df = pd.read_csv(paths[0], nrows=0)
    all_columns = header_df.columns.tolist()
    label_col = 'Attack' if 'Attack' in all_columns else 'Label' if 'Label' in all_columns else None
    
    if not label_col:
        raise ValueError("Could not find 'Attack' or 'Label' column in dataset")
    
    print(f"Label column: {label_col}")
    
    # Get all unique labels
    print("\nScanning for unique attack classes...")
    all_labels = get_unique_labels(data_pattern, chunksize=chunksize)
    print(f"\nFound {len(all_labels)} unique classes:")
    for i, label in enumerate(all_labels, 1):
        print(f"  {i:2d}. {label}")
    
    # Dictionary to store samples for each class
    class_samples = defaultdict(list)
    samples_needed = {label: samples_per_class for label in all_labels}
    
    print(f"\nExtracting {samples_per_class} samples per class...")
    print("-" * 80)
    
    # Read files and collect samples
    for i, file_path in enumerate(paths):
        print(f"\nProcessing file {i+1}/{len(paths)}: {os.path.basename(file_path)}")
        
        try:
            # Read with appropriate header handling
            if i == 0:
                reader = pd.read_csv(file_path, chunksize=chunksize, low_memory=False)
            else:
                # Subsequent files might not have headers
                reader = pd.read_csv(
                    file_path, 
                    header=None, 
                    names=all_columns, 
                    chunksize=chunksize, 
                    skiprows=1, 
                    on_bad_lines='skip', 
                    low_memory=False
                )
            
            for chunk_idx, chunk in enumerate(reader):
                # Get value counts for this chunk
                label_counts = chunk[label_col].value_counts()
                
                # Extract samples for each class
                for label in all_labels:
                    if samples_needed[label] > 0 and label in label_counts.index:
                        # Get rows for this label
                        label_rows = chunk[chunk[label_col] == label]
                        
                        # Take up to the number we still need
                        num_to_take = min(len(label_rows), samples_needed[label])
                        sampled_rows = label_rows.head(num_to_take)
                        
                        class_samples[label].extend(sampled_rows.to_dict('records'))
                        samples_needed[label] -= num_to_take
                        
                        if num_to_take > 0:
                            print(f"  Chunk {chunk_idx}: Collected {num_to_take} samples for '{label}' (need {samples_needed[label]} more)")
                
                # Check if we have enough samples for all classes
                if all(n == 0 for n in samples_needed.values()):
                    print("\n✅ Collected enough samples for all classes!")
                    break
            
            # Break outer loop if we have all samples
            if all(n == 0 for n in samples_needed.values()):
                break
                
        except Exception as e:
            print(f"  ⚠️ Warning: Error reading {os.path.basename(file_path)}: {e}")
            continue
    
    # Report on collection status
    print("\n" + "=" * 80)
    print("Collection Summary:")
    print("=" * 80)
    
    all_samples = []
    for label in all_labels:
        num_collected = len(class_samples[label])
        all_samples.extend(class_samples[label])
        
        status = "✅" if num_collected >= samples_per_class else "⚠️"
        print(f"{status} {label:30s}: {num_collected:3d} / {samples_per_class} samples")
    
    # Create DataFrame from collected samples
    print(f"\nCreating subset DataFrame with {len(all_samples)} total samples...")
    subset_df = pd.DataFrame(all_samples)
    
    # Shuffle the dataset
    subset_df = subset_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Determine output path
    if output_path is None:
        output_path = os.path.join(_BASE_DIR, "Implementation", "Data", "dataset_subset.csv")
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save to CSV
    print(f"\nSaving subset to: {output_path}")
    subset_df.to_csv(output_path, index=False)
    
    # Final statistics
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"\n" + "=" * 80)
    print(f"✅ Subset created successfully!")
    print(f"   File: {output_path}")
    print(f"   Size: {file_size_mb:.2f} MB")
    print(f"   Rows: {len(subset_df):,}")
    print(f"   Columns: {len(subset_df.columns)}")
    print(f"=" * 80)
    
    return output_path


def main():
    """Main function to create dataset subset."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Create stratified dataset subset")
    parser.add_argument(
        "--samples", 
        type=int, 
        default=15, 
        help="Number of samples per class (default: 15)"
    )
    parser.add_argument(
        "--output", 
        type=str, 
        default=None, 
        help="Output path for subset CSV (default: Implementation/Data/dataset_subset.csv)"
    )
    
    args = parser.parse_args()
    
    # Dataset pattern
    data_pattern = os.path.join(_BASE_DIR, "Implementation", "Data", "NF-UQ-NIDS-v2.part-*")
    
    try:
        create_stratified_subset(
            data_pattern=data_pattern,
            samples_per_class=args.samples,
            output_path=args.output
        )
        print("\n✨ Done!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
