import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import os


# -------------------------------------------------------
#               RESIDUAL BLOCK
# -------------------------------------------------------
class ResidualBlock(nn.Module):
    """Residual block with BatchNorm, ReLU, and Dropout."""
    def __init__(self, size, dropout=0.3):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(size, size),
            nn.BatchNorm1d(size),
            nn.LeakyReLU(negative_slope=0.01),
            nn.Dropout(dropout)
        )

    def forward(self, x):
        return x + self.block(x)  # residual connection


# -------------------------------------------------------
#               IDS MODEL (Improved)
# -------------------------------------------------------
class IDSModel(nn.Module):
    """Deep IDS model with residuals, batchnorm, and dropout."""
    def __init__(self, input_size, hidden_size, output_size, num_hidden_layers=7, dropout=0.3):
        super().__init__()
        layers = [
            nn.Linear(input_size, hidden_size),
            nn.BatchNorm1d(hidden_size),
            nn.LeakyReLU(negative_slope=0.01),
            nn.Dropout(dropout)
        ]

        # Replace linear blocks with residuals
        for _ in range(num_hidden_layers):
            layers.append(ResidualBlock(hidden_size, dropout))

        layers.append(nn.Linear(hidden_size, output_size))
        self.model = nn.Sequential(*layers)

    def forward(self, x):
        return self.model(x)


# -------------------------------------------------------
#               TRAINER CLASS (Enhanced)
# -------------------------------------------------------
class IDSTrainer:
    """Trainer for IDSModel with metrics, checkpoints, and plots."""
    def __init__(self, model, train_loader, val_loader, test_loader, device=None, save_path="best_ids_model.pth"):
        self.model = model
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.test_loader = test_loader
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.save_path = save_path
        self.scaler = torch.amp.GradScaler('cuda') if self.device == "cuda" else None

        # Tracking
        self.train_losses, self.val_losses = [], []
        self.train_accuracies, self.val_accuracies = [], []

    # ---------------------------------------------------
    def train_epoch(self, optimizer, criterion, scheduler=None, clip_grad=1.0):
        self.model.train()
        total_loss, correct, total = 0, 0, 0
        
        for batch_idx, (x, y) in enumerate(self.train_loader):
            # Use non_blocking=True for faster transfer
            x, y = x.to(self.device, non_blocking=True), y.to(self.device, non_blocking=True)

            optimizer.zero_grad()
            
            # Use AMP autocast
            if self.scaler:
                with torch.amp.autocast('cuda'):
                    out = self.model(x)
                    loss = criterion(out, y)
                
                self.scaler.scale(loss).backward()
                self.scaler.unscale_(optimizer)
                nn.utils.clip_grad_norm_(self.model.parameters(), clip_grad)
                self.scaler.step(optimizer)
                self.scaler.update()
            else:
                out = self.model(x)
                loss = criterion(out, y)
                loss.backward()
                nn.utils.clip_grad_norm_(self.model.parameters(), clip_grad)
                optimizer.step()

            # Step scheduler if it's OneCycleLR or similar per-batch scheduler
            if scheduler and isinstance(scheduler, optim.lr_scheduler.OneCycleLR):
                scheduler.step()

            total_loss += loss.item() * y.size(0)
            correct += out.argmax(1).eq(y).sum().item()
            total += y.size(0)

            if batch_idx % 1000 == 0:
                print(f"  Batch {batch_idx:05d} | Loss {loss.item():.4f}")

        return total_loss / total, 100 * correct / total

    # ---------------------------------------------------
    def validate(self, criterion):
        self.model.eval()
        total_loss, correct, total = 0, 0, 0

        with torch.no_grad():
            for x, y in self.val_loader:
                x, y = x.to(self.device, non_blocking=True), y.to(self.device, non_blocking=True)
                
                if self.scaler:
                    with torch.amp.autocast('cuda'):
                        out = self.model(x)
                        loss = criterion(out, y)
                else:
                    out = self.model(x)
                    loss = criterion(out, y)
                    
                total_loss += loss.item() * y.size(0)
                correct += out.argmax(1).eq(y).sum().item()
                total += y.size(0)

        return total_loss / total, 100 * correct / total

    # ---------------------------------------------------
    def save_checkpoint(self, optimizer, epoch, val_acc, path=None):
        if path is None:
            path = self.save_path
            
        state = {
            "epoch": epoch,
            "model_state": self.model.state_dict(),
            "optimizer_state": optimizer.state_dict(),
            "val_acc": val_acc
        }
        torch.save(state, path)
        print(f"  ✔ Model checkpoint saved to {path} (Val Acc: {val_acc:.2f}%)")

    # ---------------------------------------------------
    def load_checkpoint(self, path):
        print(f"Loading checkpoint from {path}...")
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint["model_state"])
        return checkpoint

    # ---------------------------------------------------
    def train(self, epochs=50, lr=1e-3, weight_decay=1e-4, betas=(0.9, 0.99), start_epoch=1, 
              class_weights=None, use_one_cycle=True, steps_per_epoch=None):
        print("\n" + "="*60)
        print("                STARTING IDS TRAINING")
        print("="*60)

        optimizer = optim.AdamW(self.model.parameters(), lr=lr, weight_decay=weight_decay, betas=betas)
        
        # Enable weighted loss if weights provided
        if class_weights is not None:
            class_weights = torch.tensor(class_weights, dtype=torch.float32).to(self.device)
            criterion = nn.CrossEntropyLoss(weight=class_weights)
            print(f"  ✔ Using Weighted CrossEntropyLoss")
        else:
            criterion = nn.CrossEntropyLoss()

        # Choose scheduler
        if use_one_cycle:
            # For OneCycle, we need steps per epoch
            if steps_per_epoch is None:
                try:
                    steps_per_epoch = len(self.train_loader)
                except (TypeError, AttributeError):
                    # Fallback for IterableDatasets without len
                    steps_per_epoch = 100 # Default fallback, ideally provided by caller
                    print("  ⚠ Warning: Could not determine train_loader length. Using default steps_per_epoch=100")
            
            scheduler = optim.lr_scheduler.OneCycleLR(
                optimizer, max_lr=lr*10, epochs=epochs, 
                steps_per_epoch=steps_per_epoch, pct_start=0.3
            )
            print(f"  ✔ Using OneCycleLR Scheduler ({steps_per_epoch} steps/epoch, Max LR: {lr*10:.4f})")
        else:
            scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=5)
            print(f"  ✔ Using ReduceLROnPlateau Scheduler")

        best_acc = 0
        patience, patience_ctr = 10, 0
        
        # If resuming, we might want to load optimizer state if available in checkpoint
        # But for now, we'll just restart optimizer or assume it's handled by caller if they want strict resume
        # Ideally, load_checkpoint should return optimizer state too if we want to resume perfectly.
        # Let's update load_checkpoint to return the whole checkpoint dict so we can use it here.

        for epoch in range(start_epoch, epochs + 1):
            print(f"\nEpoch {epoch}/{epochs}")
            print("-" * 60)

            # Pass scheduler to train_epoch if it's OneCycle
            train_loss, train_acc = self.train_epoch(optimizer, criterion, scheduler=scheduler if use_one_cycle else None)
            val_loss, val_acc = self.validate(criterion)

            if not use_one_cycle:
                scheduler.step(val_loss)

            self.train_losses.append(train_loss)
            self.val_losses.append(val_loss)
            self.train_accuracies.append(train_acc)
            self.val_accuracies.append(val_acc)

            lr_now = optimizer.param_groups[0]['lr']
            print(f"Train Loss {train_loss:.4f} | Train Acc {train_acc:.2f}%")
            print(f"Val Loss   {val_loss:.4f} | Val Acc   {val_acc:.2f}% | LR: {lr_now:.6f}")

            # Save model for this epoch
            epoch_save_path = self.save_path.replace(".pth", f"_epoch_{epoch}.pth")
            self.save_checkpoint(optimizer, epoch, val_acc, path=epoch_save_path)

            # Save best model
            if val_acc > best_acc:
                self.save_checkpoint(optimizer, epoch, val_acc)
                best_acc = val_acc
                patience_ctr = 0
            else:
                patience_ctr += 1
            print(f"Patience Counter: {patience_ctr}/{patience}")
            if patience_ctr >= patience:
                print("Early stopping triggered.")
                break

        print(f"\nTraining complete. Best Val Acc: {best_acc:.2f}%")
        if os.path.exists(self.save_path):
            checkpoint = torch.load(self.save_path, map_location=self.device)
            self.model.load_state_dict(checkpoint["model_state"])

    # ---------------------------------------------------
    def evaluate(self):
        print("\n" + "="*60)
        print("                  MODEL EVALUATION")
        print("="*60)

        self.model.eval()
        preds, labels = [], []

        with torch.no_grad():
            for x, y in self.test_loader:
                x, y = x.to(self.device), y.to(self.device)
                out = self.model(x)
                preds.extend(out.argmax(1).cpu().tolist())
                labels.extend(y.cpu().tolist())

        print(classification_report(labels, preds, digits=4))
        print("Confusion Matrix:")
        print(confusion_matrix(labels, preds))

    # ---------------------------------------------------
    def plot_training_history(self):
        plt.figure(figsize=(12, 5))

        # Loss curves
        plt.subplot(1, 2, 1)
        plt.plot(self.train_losses, label="Train Loss", linewidth=2)
        plt.plot(self.val_losses, label="Val Loss", linewidth=2)
        plt.xlabel("Epochs")
        plt.ylabel("Loss")
        plt.grid(True)
        plt.legend()
        plt.title("Loss Curve")

        # Accuracy curves
        plt.subplot(1, 2, 2)
        plt.plot(self.train_accuracies, label="Train Accuracy", linewidth=2)
        plt.plot(self.val_accuracies, label="Val Accuracy", linewidth=2)
        plt.xlabel("Epochs")
        plt.ylabel("Accuracy (%)")
        plt.grid(True)
        plt.legend()
        plt.title("Accuracy Curve")

        plt.tight_layout()
        plt.savefig("training_history.png", dpi=300)
        plt.show()


# -------------------------------------------------------
#             MODEL SUMMARY UTILITY
# -------------------------------------------------------
def display_model_architecture(model, num_features, num_classes):
    print("\nModel Summary")
    print("=" * 60)
    print(f"Input size:  {num_features}")
    print(f"Output size: {num_classes}")

    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)

    print(f"Total Parameters:     {total_params:,}")
    print(f"Trainable Parameters: {trainable_params:,}")
    print("-" * 60)

    for name, module in model.named_modules():
        if isinstance(module, nn.Linear):
            print(f"{name}: Linear {module.in_features} → {module.out_features}")
        elif isinstance(module, nn.BatchNorm1d):
            print(f"{name}: BatchNorm1d ({module.num_features})")
        elif isinstance(module, nn.Dropout):
            print(f"{name}: Dropout (p={module.p})")
    print("=" * 60)
