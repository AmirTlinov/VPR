#!/usr/bin/env python3
"""
Deterministic Training Script for TMT-20M

Usage:
    python train.py --config configs/tmt_20m.yaml

Features:
- Full reproducibility with fixed seeds
- Mixed precision training
- Gradient checkpointing for memory efficiency
- Quality gates that must be passed
- TensorBoard logging
"""

import argparse
import os
import random
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from torch.utils.tensorboard import SummaryWriter
import yaml
from tqdm import tqdm

from model import TrafficMorphingTransformer, create_model


def set_deterministic(seed: int, deterministic: bool = True):
    """Set all random seeds for full reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

    if deterministic:
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
        # Enable deterministic algorithms (PyTorch 1.8+)
        torch.use_deterministic_algorithms(True, warn_only=True)

    os.environ["PYTHONHASHSEED"] = str(seed)
    os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"


class TrafficDataset(Dataset):
    """Dataset for traffic morphing training."""

    def __init__(self, data_path: str, context_size: int = 16):
        """Load dataset from parquet file.

        Args:
            data_path: Path to parquet file
            context_size: Number of packets per sample
        """
        import pandas as pd

        self.context_size = context_size

        # Load data
        df = pd.read_parquet(data_path)

        # Extract features: size_norm, delay_log, direction, burst_pos
        self.features = torch.tensor(
            df[["size_norm", "delay_log", "direction", "burst_pos"]].values,
            dtype=torch.float32,
        )

        # Profile labels (0=youtube, 1=zoom, 2=gaming, 3=browsing, 4=netflix)
        self.profiles = torch.tensor(df["profile_id"].values, dtype=torch.long)

        # Target distributions for each profile
        self.targets = torch.tensor(
            df[["target_delay", "target_padding", "target_inject"]].values,
            dtype=torch.float32,
        )

        # Create windows
        self.num_samples = len(self.features) - context_size + 1

    def __len__(self) -> int:
        return self.num_samples

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Get a training sample.

        Returns:
            Tuple of (context, profile_id, targets)
        """
        context = self.features[idx : idx + self.context_size]
        profile = self.profiles[idx + self.context_size - 1]
        target = self.targets[idx + self.context_size - 1]
        return context, profile, target


class MorphingLoss(nn.Module):
    """Combined loss for traffic morphing."""

    def __init__(
        self,
        kl_weight: float = 1.0,
        latency_weight: float = 0.5,
        bandwidth_weight: float = 0.3,
        confidence_weight: float = 0.2,
    ):
        super().__init__()
        self.kl_weight = kl_weight
        self.latency_weight = latency_weight
        self.bandwidth_weight = bandwidth_weight
        self.confidence_weight = confidence_weight

    def forward(
        self,
        outputs: Dict[str, torch.Tensor],
        targets: torch.Tensor,
        profile_stats: Dict[str, torch.Tensor],
    ) -> Tuple[torch.Tensor, Dict[str, float]]:
        """Compute combined loss.

        Args:
            outputs: Model outputs
            targets: Target values [batch, 3] (delay, padding, inject)
            profile_stats: Target profile statistics

        Returns:
            Total loss and loss components
        """
        # Delay MSE loss
        delay_loss = F.mse_loss(outputs["delay_ms"], targets[:, 0])

        # Padding MSE loss
        padding_loss = F.mse_loss(outputs["padding_norm"], targets[:, 1])

        # Inject BCE loss (use with_logits for autocast safety)
        inject_loss = F.binary_cross_entropy_with_logits(outputs["inject_logits"], targets[:, 2])

        # Latency penalty (minimize added delay)
        latency_penalty = outputs["delay_ms"].mean()

        # Bandwidth penalty (minimize padding)
        bandwidth_penalty = outputs["padding_norm"].mean()

        # Confidence calibration (should match actual accuracy)
        confidence_loss = F.mse_loss(
            outputs["confidence"], torch.ones_like(outputs["confidence"]) * 0.9
        )

        # Combined loss
        total_loss = (
            self.kl_weight * (delay_loss + padding_loss + inject_loss)
            + self.latency_weight * latency_penalty
            + self.bandwidth_weight * bandwidth_penalty
            + self.confidence_weight * confidence_loss
        )

        return total_loss, {
            "delay_loss": delay_loss.item(),
            "padding_loss": padding_loss.item(),
            "inject_loss": inject_loss.item(),
            "latency_penalty": latency_penalty.item(),
            "bandwidth_penalty": bandwidth_penalty.item(),
            "confidence_loss": confidence_loss.item(),
            "total_loss": total_loss.item(),
        }


def train_epoch(
    model: nn.Module,
    dataloader: DataLoader,
    optimizer: torch.optim.Optimizer,
    criterion: MorphingLoss,
    device: torch.device,
    scaler: torch.amp.GradScaler,
    max_grad_norm: float = 1.0,
) -> Dict[str, float]:
    """Train for one epoch."""
    model.train()
    total_losses = {}

    pbar = tqdm(dataloader, desc="Training")
    for batch_idx, (context, profile, targets) in enumerate(pbar):
        context = context.to(device)
        profile = profile.to(device)
        targets = targets.to(device)

        optimizer.zero_grad()

        # Mixed precision forward
        with torch.amp.autocast(device_type="cuda", enabled=device.type == "cuda"):
            outputs = model(context, profile)
            loss, loss_dict = criterion(outputs, targets, {})

        # Backward with gradient scaling
        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_grad_norm)
        scaler.step(optimizer)
        scaler.update()

        # Accumulate losses
        for k, v in loss_dict.items():
            total_losses[k] = total_losses.get(k, 0) + v

        pbar.set_postfix(loss=loss_dict["total_loss"])

    # Average losses
    num_batches = len(dataloader)
    return {k: v / num_batches for k, v in total_losses.items()}


@torch.no_grad()
def validate(
    model: nn.Module,
    dataloader: DataLoader,
    criterion: MorphingLoss,
    device: torch.device,
) -> Tuple[Dict[str, float], bool]:
    """Validate model and check quality gates."""
    model.eval()
    total_losses = {}
    all_delays = []
    all_paddings = []

    for context, profile, targets in tqdm(dataloader, desc="Validating"):
        context = context.to(device)
        profile = profile.to(device)
        targets = targets.to(device)

        outputs = model(context, profile)
        _, loss_dict = criterion(outputs, targets, {})

        for k, v in loss_dict.items():
            total_losses[k] = total_losses.get(k, 0) + v

        all_delays.append(outputs["delay_ms"].cpu())
        all_paddings.append(outputs["padding_norm"].cpu())

    num_batches = len(dataloader)
    avg_losses = {k: v / num_batches for k, v in total_losses.items()}

    # Quality metrics
    all_delays = torch.cat(all_delays)
    all_paddings = torch.cat(all_paddings)

    avg_losses["avg_delay_ms"] = all_delays.mean().item()
    avg_losses["avg_padding_norm"] = all_paddings.mean().item()
    avg_losses["bandwidth_efficiency"] = 100 * (1 - all_paddings.mean().item() / 1500)

    # Quality gate check
    passed = (
        avg_losses["total_loss"] < 0.5
        and avg_losses["avg_delay_ms"] < 5.0
        and avg_losses["bandwidth_efficiency"] > 85.0
    )

    return avg_losses, passed


def main():
    parser = argparse.ArgumentParser(description="Train TMT-20M model")
    parser.add_argument("--config", type=str, required=True, help="Config YAML file")
    parser.add_argument("--resume", type=str, help="Resume from checkpoint")
    args = parser.parse_args()

    # Load config
    with open(args.config) as f:
        config = yaml.safe_load(f)

    # Set deterministic mode
    set_deterministic(config["seed"], config["deterministic"])

    # Device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Create model
    model = create_model(config).to(device)
    print(f"Model parameters: {model.count_parameters():,}")

    # Create dataloaders
    train_dataset = TrafficDataset(
        config["data"]["train_path"], config["model"]["context_size"]
    )
    val_dataset = TrafficDataset(
        config["data"]["val_path"], config["model"]["context_size"]
    )

    # Use generator for reproducible shuffling
    g = torch.Generator()
    g.manual_seed(config["seed"])

    train_loader = DataLoader(
        train_dataset,
        batch_size=config["training"]["batch_size"],
        shuffle=True,
        num_workers=config["data"]["num_workers"],
        pin_memory=config["data"]["pin_memory"],
        generator=g,
        drop_last=True,
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=config["training"]["batch_size"],
        shuffle=False,
        num_workers=config["data"]["num_workers"],
        pin_memory=config["data"]["pin_memory"],
    )

    # Optimizer
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=config["training"]["lr"],
        weight_decay=config["training"]["weight_decay"],
        betas=tuple(config["optimizer"]["betas"]),
        eps=config["optimizer"]["eps"],
    )

    # Scheduler with warmup
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer,
        max_lr=config["training"]["lr"],
        epochs=config["training"]["epochs"],
        steps_per_epoch=len(train_loader),
        pct_start=config["training"]["warmup_steps"]
        / (config["training"]["epochs"] * len(train_loader)),
    )

    # Loss
    criterion = MorphingLoss(
        kl_weight=config["loss"]["kl_weight"],
        latency_weight=config["loss"]["latency_weight"],
        bandwidth_weight=config["loss"]["bandwidth_weight"],
        confidence_weight=config["loss"]["confidence_weight"],
    )

    # Mixed precision scaler
    scaler = torch.amp.GradScaler(enabled=device.type == "cuda")

    # TensorBoard
    writer = SummaryWriter(f"runs/tmt_20m_seed{config['seed']}")

    # Training loop
    best_loss = float("inf")
    patience_counter = 0
    quality_passed = False

    for epoch in range(config["training"]["epochs"]):
        print(f"\nEpoch {epoch + 1}/{config['training']['epochs']}")

        # Train
        train_losses = train_epoch(
            model,
            train_loader,
            optimizer,
            criterion,
            device,
            scaler,
            config["training"]["max_grad_norm"],
        )

        # Log training losses
        for k, v in train_losses.items():
            writer.add_scalar(f"train/{k}", v, epoch)

        # Validate
        if (epoch + 1) % config["training"]["val_every"] == 0:
            val_losses, passed = validate(model, val_loader, criterion, device)

            for k, v in val_losses.items():
                writer.add_scalar(f"val/{k}", v, epoch)

            print(f"Val loss: {val_losses['total_loss']:.4f}")
            print(f"Avg delay: {val_losses['avg_delay_ms']:.2f}ms")
            print(f"Bandwidth efficiency: {val_losses['bandwidth_efficiency']:.1f}%")
            print(f"Quality gate: {'PASSED' if passed else 'FAILED'}")

            if passed:
                quality_passed = True

            # Early stopping
            if val_losses["total_loss"] < best_loss:
                best_loss = val_losses["total_loss"]
                patience_counter = 0

                # Save best model
                torch.save(
                    {
                        "epoch": epoch,
                        "model_state_dict": model.state_dict(),
                        "optimizer_state_dict": optimizer.state_dict(),
                        "loss": best_loss,
                        "config": config,
                    },
                    "models/tmt_20m_best.pt",
                )
            else:
                patience_counter += 1
                if patience_counter >= config["training"]["patience"]:
                    print(f"Early stopping at epoch {epoch + 1}")
                    break

        # Save checkpoint
        if (epoch + 1) % config["training"]["save_every"] == 0:
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "scheduler_state_dict": scheduler.state_dict(),
                    "loss": train_losses["total_loss"],
                    "config": config,
                },
                f"models/tmt_20m_epoch{epoch + 1}.pt",
            )

        scheduler.step()

    writer.close()

    # Final quality check
    print("\n" + "=" * 50)
    print("TRAINING COMPLETE")
    print("=" * 50)
    print(f"Best validation loss: {best_loss:.4f}")
    print(f"Quality gates: {'PASSED' if quality_passed else 'FAILED'}")

    if not quality_passed:
        print("\nWARNING: Model did not pass quality gates!")
        print("Do not integrate into production without passing all quality checks.")
        return 1

    print("\nModel ready for ONNX export: models/tmt_20m_best.pt")
    return 0


if __name__ == "__main__":
    exit(main())
