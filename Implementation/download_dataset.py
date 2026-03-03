import kagglehub
import os
import shutil

def download_dataset():
    print("Downloading NF-UQ-NIDS-v2 dataset...")
    try:
        # Download latest version
        path = kagglehub.dataset_download("aryashah2k/nfuqnidsv2-network-intrusion-detection-dataset")
        print("Dataset downloaded to:", path)
        
        # Define target directory
        target_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Data")
        os.makedirs(target_dir, exist_ok=True)
        
        # Move files to project Data directory
        print(f"Moving files to {target_dir}...")
        for filename in os.listdir(path):
            source_file = os.path.join(path, filename)
            target_file = os.path.join(target_dir, filename)
            if os.path.isfile(source_file):
                shutil.copy2(source_file, target_file)
                print(f"   - Copied {filename}")
        
        print("Download and setup complete!")
        
    except Exception as e:
        print(f"Error downloading dataset: {e}")

if __name__ == "__main__":
    download_dataset()
