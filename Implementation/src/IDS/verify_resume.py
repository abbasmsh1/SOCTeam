import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import os
import shutil
import glob
import re
from ann_model import IDSModel, IDSTrainer

def verify_resume():
    print("Starting resume verification...")
    
    # 1. Setup Mock Data
    input_size = 10
    num_classes = 2
    X = torch.randn(20, input_size)
    y = torch.randint(0, num_classes, (20,))
    
    dataset = TensorDataset(X, y)
    loader = DataLoader(dataset, batch_size=5)
    
    # 2. Setup Model and Trainer
    device = torch.device("cpu")
    model = IDSModel(input_size=input_size, hidden_size=16, output_size=num_classes)
    
    save_dir = "test_resume_checkpoints"
    if os.path.exists(save_dir):
        shutil.rmtree(save_dir)
    os.makedirs(save_dir)
    
    save_path = os.path.join(save_dir, "best_ids_model.pth")
    
    trainer = IDSTrainer(model, loader, loader, loader, device=device, save_path=save_path)
    
    # 3. Run Training for 2 epochs
    print("Running initial training for 2 epochs...")
    trainer.train(epochs=2)
    
    # 4. Simulate Resume
    print("\nSimulating resume...")
    # Find latest checkpoint
    checkpoint_pattern = os.path.join(save_dir, "best_ids_model_epoch_*.pth")
    checkpoints = glob.glob(checkpoint_pattern)
    
    start_epoch = 1
    if checkpoints:
        epoch_nums = []
        for cp in checkpoints:
            match = re.search(r"epoch_(\d+)\.pth", cp)
            if match:
                epoch_nums.append(int(match.group(1)))
        
        if epoch_nums:
            latest_epoch = max(epoch_nums)
            latest_checkpoint = os.path.join(save_dir, f"best_ids_model_epoch_{latest_epoch}.pth")
            print(f"Found checkpoint: {latest_checkpoint}")
            
            # Create NEW trainer instance
            model_new = IDSModel(input_size=input_size, hidden_size=16, output_size=num_classes)
            trainer_new = IDSTrainer(model_new, loader, loader, loader, device=device, save_path=save_path)
            
            trainer_new.load_checkpoint(latest_checkpoint)
            start_epoch = latest_epoch + 1
            
            print(f"Resuming from epoch {start_epoch}...")
            trainer_new.train(epochs=4, start_epoch=start_epoch)
            
            # Verify that we trained for epochs 3 and 4
            # Check if epoch 4 checkpoint exists
            if os.path.exists(os.path.join(save_dir, "best_ids_model_epoch_4.pth")):
                 print("✅ Verification PASSED. Resumed and trained to epoch 4.")
            else:
                 print("❌ Verification FAILED. Epoch 4 checkpoint not found.")
        else:
            print("❌ Verification FAILED. No epochs found in checkpoints.")
    else:
        print("❌ Verification FAILED. No checkpoints found.")

    # Cleanup
    # shutil.rmtree(save_dir)

if __name__ == "__main__":
    verify_resume()
