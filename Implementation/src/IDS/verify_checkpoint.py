import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import os
import shutil
from ann_model import IDSModel, IDSTrainer

def verify_checkpoints():
    print("Starting verification...")
    
    # 1. Setup Mock Data
    input_size = 10
    num_classes = 2
    X = torch.randn(20, input_size)
    y = torch.randint(0, num_classes, (20,))
    
    dataset = TensorDataset(X, y)
    loader = DataLoader(dataset, batch_size=5)
    
    # 2. Setup Model and Trainer
    device = torch.device("cpu") # Use CPU for quick test
    model = IDSModel(input_size=input_size, hidden_size=16, output_size=num_classes)
    
    save_dir = "test_checkpoints"
    if os.path.exists(save_dir):
        shutil.rmtree(save_dir)
    os.makedirs(save_dir)
    
    save_path = os.path.join(save_dir, "test_model.pth")
    
    trainer = IDSTrainer(model, loader, loader, loader, device=device, save_path=save_path)
    
    # 3. Run Training for 2 epochs
    print("Running training for 2 epochs...")
    trainer.train(epochs=2)
    
    # 4. Verify Files
    expected_files = [
        "test_model_epoch_1.pth",
        "test_model_epoch_2.pth",
        "test_model.pth" # Best model might be one of them
    ]
    
    missing_files = []
    for f in expected_files:
        if not os.path.exists(os.path.join(save_dir, f)):
            missing_files.append(f)
            
    if missing_files:
        print(f"❌ Verification FAILED. Missing files: {missing_files}")
    else:
        print("✅ Verification PASSED. All checkpoint files found.")
        
    # 5. Cleanup
    # shutil.rmtree(save_dir)
    # print("Cleanup complete.")

if __name__ == "__main__":
    verify_checkpoints()
