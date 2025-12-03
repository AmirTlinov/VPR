#!/usr/bin/env python3
"""
Adversarial Training Script for TMT-20M with DPI-Aware Loss.

This training approach uses the DPI simulator as an adversary:
- Model learns to output padding/delay that evades DPI detection
- Loss function penalizes HIGH detection scores (opposite of old approach)
- No contradictory minimization penalties

Key differences from original train.py:
1. DPI detection score is part of the loss (higher detection = higher loss)
2. Profile similarity loss replaces contradictory minimization
3. Efficiency constraints are soft (bounded, not minimized)
"""

import argparse
import os
import random
from pathlib import Path
from typing import Dict, Tuple, Optional

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from torch.utils.tensorboard import SummaryWriter
import yaml
from tqdm import tqdm

from model import TrafficMorphingTransformer, create_model
from dpi_simulator import ParanoidDpi, DpiConfig, DpiVerdict


def set_deterministic(seed: int, deterministic: bool = True):
    """Set all random seeds for full reproducibility."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)

    if deterministic:
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
        torch.use_deterministic_algorithms(True, warn_only=True)

    os.environ["PYTHONHASHSEED"] = str(seed)
    os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"


class AdversarialTrafficDataset(Dataset):
    """Dataset with DPI-adversarial context."""

    def __init__(self, data_path: str, context_size: int = 16):
        import pandas as pd

        self.context_size = context_size
        df = pd.read_parquet(data_path)

        # Packet features
        self.features = torch.tensor(
            df[["size_norm", "delay_log", "direction", "burst_pos"]].values,
            dtype=torch.float32,
        )

        # Raw values for DPI simulation
        self.raw_sizes = torch.tensor(
            (df["size_norm"].values * 1500).astype(int), dtype=torch.int32
        )
        self.raw_delays = torch.tensor(
            np.expm1(df["delay_log"].values), dtype=torch.float32
        )
        self.raw_directions = torch.tensor(
            df["direction"].values.astype(int), dtype=torch.int32
        )

        # Profile labels
        self.profiles = torch.tensor(df["profile_id"].values, dtype=torch.long)

        # Profile statistics for similarity matching
        self.profile_stats = self._compute_profile_stats(df)

        self.num_samples = len(self.features) - context_size + 1

    def _compute_profile_stats(self, df) -> Dict[int, Dict[str, float]]:
        """Compute target statistics per profile for similarity loss."""
        stats = {}
        for profile_id in df["profile_id"].unique():
            mask = df["profile_id"] == profile_id
            stats[int(profile_id)] = {
                "size_mean": df.loc[mask, "size_norm"].mean(),
                "size_std": df.loc[mask, "size_norm"].std(),
                "delay_mean": df.loc[mask, "delay_log"].mean(),
                "delay_std": df.loc[mask, "delay_log"].std(),
                "direction_ratio": (df.loc[mask, "direction"] > 0).mean(),
            }
        return stats

    def __len__(self) -> int:
        return self.num_samples

    def __getitem__(self, idx: int):
        """Get a training sample with context for DPI."""
        end_idx = idx + self.context_size

        context = self.features[idx:end_idx]
        profile = self.profiles[end_idx - 1]

        # Raw values for DPI simulation
        raw_sizes = self.raw_sizes[idx:end_idx]
        raw_delays = self.raw_delays[idx:end_idx]
        raw_directions = self.raw_directions[idx:end_idx]

        return context, profile, raw_sizes, raw_delays, raw_directions


class AdversarialMorphingLoss(nn.Module):
    """
    DPI-Aware Adversarial Loss.

    Loss components:
    1. DPI evasion: penalize high detection scores
    2. Profile similarity: match target profile statistics
    3. Efficiency bounds: soft constraints on overhead (not minimization!)
    4. Confidence calibration: confidence should match actual evasion rate
    """

    def __init__(
        self,
        dpi_weight: float = 2.0,  # Main objective: evade DPI
        similarity_weight: float = 0.5,
        efficiency_weight: float = 0.3,
        confidence_weight: float = 0.2,
        # Efficiency bounds (not targets to minimize!)
        max_delay_ms: float = 20.0,
        max_padding_ratio: float = 0.3,
        dpi_configs: Optional[list] = None,
    ):
        super().__init__()
        self.dpi_weight = dpi_weight
        self.similarity_weight = similarity_weight
        self.efficiency_weight = efficiency_weight
        self.confidence_weight = confidence_weight
        self.max_delay_ms = max_delay_ms
        self.max_padding_ratio = max_padding_ratio

        # DPI configurations for adversarial training
        if dpi_configs is None:
            self.dpi_configs = [
                DpiConfig.china_gfw(),
                DpiConfig.russia_rkn(),
                DpiConfig.iran(),
                DpiConfig.paranoid(),
            ]
        else:
            self.dpi_configs = dpi_configs

    def forward(
        self,
        outputs: Dict[str, torch.Tensor],
        raw_sizes: torch.Tensor,
        raw_delays: torch.Tensor,
        raw_directions: torch.Tensor,
        profile_ids: torch.Tensor,
        profile_stats: Dict[int, Dict[str, float]],
    ) -> Tuple[torch.Tensor, Dict[str, float]]:
        """
        Compute adversarial loss.

        The key insight: we want to MAXIMIZE evasion (minimize detection),
        not minimize the morphing values themselves!
        """
        batch_size = outputs["delay_ms"].shape[0]
        device = outputs["delay_ms"].device

        # 1. DPI Evasion Loss (main objective)
        # Run DPI simulation and penalize detection
        dpi_scores = self._compute_dpi_scores(
            raw_sizes, raw_delays, raw_directions,
            outputs["padding_norm"], outputs["delay_ms"]
        )
        dpi_scores_tensor = torch.tensor(dpi_scores, dtype=torch.float32, device=device)

        # Normalize scores and use as loss (higher score = higher loss)
        # Target: get score below block_threshold (e.g., < 30)
        dpi_loss = F.relu(dpi_scores_tensor - 15.0).mean() / 30.0  # Normalized

        # 2. Profile Similarity Loss
        # Morphed traffic should match target profile's statistics
        similarity_loss = self._compute_similarity_loss(
            outputs, profile_ids, profile_stats, device
        )

        # 3. Efficiency Bounds (soft constraints, NOT minimization!)
        # Only penalize if exceeding bounds, don't minimize within bounds
        delay_excess = F.relu(outputs["delay_ms"] - self.max_delay_ms)
        padding_excess = F.relu(outputs["padding_norm"] - self.max_padding_ratio)
        efficiency_loss = delay_excess.mean() / self.max_delay_ms + padding_excess.mean()

        # 4. Confidence Calibration
        # Confidence should reflect actual evasion probability
        evasion_rate = (dpi_scores_tensor < 30.0).float()  # Below block threshold
        confidence_loss = F.mse_loss(outputs["confidence"], evasion_rate)

        # Combined loss
        total_loss = (
            self.dpi_weight * dpi_loss
            + self.similarity_weight * similarity_loss
            + self.efficiency_weight * efficiency_loss
            + self.confidence_weight * confidence_loss
        )

        return total_loss, {
            "dpi_loss": dpi_loss.item(),
            "similarity_loss": similarity_loss.item(),
            "efficiency_loss": efficiency_loss.item(),
            "confidence_loss": confidence_loss.item(),
            "total_loss": total_loss.item(),
            "avg_dpi_score": dpi_scores.mean(),
            "evasion_rate": evasion_rate.mean().item(),
            "avg_delay_ms": outputs["delay_ms"].mean().item(),
            "avg_padding": outputs["padding_norm"].mean().item(),
        }

    def _compute_dpi_scores(
        self,
        raw_sizes: torch.Tensor,
        raw_delays: torch.Tensor,
        raw_directions: torch.Tensor,
        padding_norm: torch.Tensor,
        delay_ms: torch.Tensor,
    ) -> np.ndarray:
        """Run DPI simulation on morphed traffic."""
        batch_size = raw_sizes.shape[0]
        seq_len = raw_sizes.shape[1]

        # Convert to numpy
        sizes_np = raw_sizes.cpu().numpy()
        delays_np = raw_delays.cpu().numpy()
        directions_np = raw_directions.cpu().numpy()
        padding_np = padding_norm.detach().cpu().numpy()
        delay_applied_np = delay_ms.detach().cpu().numpy()

        scores = np.zeros(batch_size)

        for i in range(batch_size):
            # Test against random DPI config (curriculum learning style)
            config = random.choice(self.dpi_configs)
            dpi = ParanoidDpi(config=config)

            for j in range(seq_len):
                size = int(sizes_np[i, j])
                delay = float(delays_np[i, j])
                direction = int(directions_np[i, j])

                # Apply morphing to last packet
                if j == seq_len - 1:
                    # Add padding (convert from ratio to bytes)
                    size = size + int(padding_np[i] * 1500)
                    size = min(size, 1500)  # Cap at MTU
                    # Add delay
                    delay = delay + delay_applied_np[i]

                dpi.analyze_packet(size, delay, direction)

            scores[i] = dpi.suspicion_score

        return scores

    def _compute_similarity_loss(
        self,
        outputs: Dict[str, torch.Tensor],
        profile_ids: torch.Tensor,
        profile_stats: Dict[int, Dict[str, float]],
        device: torch.device,
    ) -> torch.Tensor:
        """Compute how well morphed traffic matches target profile."""
        batch_size = profile_ids.shape[0]
        losses = []

        for i in range(batch_size):
            pid = profile_ids[i].item()
            if pid not in profile_stats:
                continue

            stats = profile_stats[pid]

            # Target delay should be profile-appropriate
            # (e.g., gaming wants low delay, browsing tolerates higher)
            target_delay_factor = {
                0: 2.0,   # YouTube: moderate
                1: 1.0,   # Zoom: low
                2: 0.5,   # Gaming: very low
                3: 5.0,   # Browsing: high variability ok
                4: 3.0,   # Netflix: moderate
            }.get(pid, 2.0)

            delay_diff = (outputs["delay_ms"][i] - target_delay_factor).abs()

            # Target padding should add variability matching profile
            target_padding = {
                0: 0.08,  # YouTube: some padding
                1: 0.12,  # Zoom: moderate
                2: 0.05,  # Gaming: minimal
                3: 0.15,  # Browsing: variable
                4: 0.10,  # Netflix: some
            }.get(pid, 0.10)

            padding_diff = (outputs["padding_norm"][i] - target_padding).abs()

            losses.append(delay_diff + padding_diff)

        if losses:
            return torch.stack(losses).mean()
        return torch.tensor(0.0, device=device)


def train_epoch(
    model: nn.Module,
    dataloader: DataLoader,
    optimizer: torch.optim.Optimizer,
    criterion: AdversarialMorphingLoss,
    device: torch.device,
    scaler: torch.amp.GradScaler,
    profile_stats: Dict,
    max_grad_norm: float = 1.0,
) -> Dict[str, float]:
    """Train for one epoch with adversarial loss."""
    model.train()
    total_losses = {}

    pbar = tqdm(dataloader, desc="Training")
    for batch_idx, (context, profile, raw_sizes, raw_delays, raw_dirs) in enumerate(pbar):
        context = context.to(device)
        profile = profile.to(device)
        raw_sizes = raw_sizes.to(device)
        raw_delays = raw_delays.to(device)
        raw_dirs = raw_dirs.to(device)

        optimizer.zero_grad()

        with torch.amp.autocast(device_type="cuda", enabled=device.type == "cuda"):
            outputs = model(context, profile)
            loss, loss_dict = criterion(
                outputs, raw_sizes, raw_delays, raw_dirs, profile, profile_stats
            )

        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_grad_norm)
        scaler.step(optimizer)
        scaler.update()

        for k, v in loss_dict.items():
            total_losses[k] = total_losses.get(k, 0) + v

        pbar.set_postfix(
            loss=f"{loss_dict['total_loss']:.3f}",
            evasion=f"{loss_dict['evasion_rate']:.1%}",
            delay=f"{loss_dict['avg_delay_ms']:.1f}ms",
            pad=f"{loss_dict['avg_padding']*100:.0f}%",
        )

    num_batches = len(dataloader)
    return {k: v / num_batches for k, v in total_losses.items()}


@torch.no_grad()
def validate(
    model: nn.Module,
    dataloader: DataLoader,
    criterion: AdversarialMorphingLoss,
    device: torch.device,
    profile_stats: Dict,
) -> Tuple[Dict[str, float], bool]:
    """Validate model with DPI evasion metrics."""
    model.eval()
    total_losses = {}
    all_evasion_rates = []

    for context, profile, raw_sizes, raw_delays, raw_dirs in tqdm(dataloader, desc="Validating"):
        context = context.to(device)
        profile = profile.to(device)
        raw_sizes = raw_sizes.to(device)
        raw_delays = raw_delays.to(device)
        raw_dirs = raw_dirs.to(device)

        outputs = model(context, profile)
        _, loss_dict = criterion(
            outputs, raw_sizes, raw_delays, raw_dirs, profile, profile_stats
        )

        for k, v in loss_dict.items():
            total_losses[k] = total_losses.get(k, 0) + v

        all_evasion_rates.append(loss_dict["evasion_rate"])

    num_batches = len(dataloader)
    avg_losses = {k: v / num_batches for k, v in total_losses.items()}

    # Quality gate: must achieve >70% evasion rate
    avg_evasion = np.mean(all_evasion_rates)
    avg_losses["final_evasion_rate"] = avg_evasion

    passed = (
        avg_evasion > 0.70  # 70% evasion rate
        and avg_losses["avg_delay_ms"] < 15.0  # Reasonable delay
        and avg_losses["avg_padding"] < 0.25  # Reasonable overhead
    )

    return avg_losses, passed


def main():
    parser = argparse.ArgumentParser(description="Adversarial training for TMT-20M")
    parser.add_argument("--config", type=str, required=True, help="Config YAML file")
    parser.add_argument("--resume", type=str, help="Resume from checkpoint")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    set_deterministic(config["seed"], config["deterministic"])

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Create model
    model = create_model(config).to(device)
    print(f"Model parameters: {model.count_parameters():,}")

    # Datasets
    train_dataset = AdversarialTrafficDataset(
        config["data"]["train_path"], config["model"]["context_size"]
    )
    val_dataset = AdversarialTrafficDataset(
        config["data"]["val_path"], config["model"]["context_size"]
    )

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

    # Scheduler
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer,
        max_lr=config["training"]["lr"],
        epochs=config["training"]["epochs"],
        steps_per_epoch=len(train_loader),
        pct_start=0.1,
    )

    # Adversarial Loss
    criterion = AdversarialMorphingLoss(
        dpi_weight=config.get("loss", {}).get("dpi_weight", 2.0),
        similarity_weight=config.get("loss", {}).get("similarity_weight", 0.5),
        efficiency_weight=config.get("loss", {}).get("efficiency_weight", 0.3),
        confidence_weight=config.get("loss", {}).get("confidence_weight", 0.2),
    )

    scaler = torch.amp.GradScaler(enabled=device.type == "cuda")
    writer = SummaryWriter(f"runs/tmt_20m_adversarial_seed{config['seed']}")

    best_evasion = 0.0
    patience_counter = 0
    quality_passed = False

    # Ensure models directory exists
    Path("models").mkdir(exist_ok=True)

    for epoch in range(config["training"]["epochs"]):
        print(f"\n{'='*60}")
        print(f"Epoch {epoch + 1}/{config['training']['epochs']}")
        print(f"{'='*60}")

        # Train
        train_losses = train_epoch(
            model, train_loader, optimizer, criterion, device, scaler,
            train_dataset.profile_stats, config["training"]["max_grad_norm"]
        )

        for k, v in train_losses.items():
            writer.add_scalar(f"train/{k}", v, epoch)

        print(f"\nTrain - Loss: {train_losses['total_loss']:.4f}, "
              f"Evasion: {train_losses['evasion_rate']:.1%}, "
              f"Delay: {train_losses['avg_delay_ms']:.1f}ms, "
              f"Padding: {train_losses['avg_padding']*100:.0f}%")

        # Validate
        if (epoch + 1) % config["training"]["val_every"] == 0:
            val_losses, passed = validate(
                model, val_loader, criterion, device, val_dataset.profile_stats
            )

            for k, v in val_losses.items():
                writer.add_scalar(f"val/{k}", v, epoch)

            print(f"\nVal - Loss: {val_losses['total_loss']:.4f}")
            print(f"Evasion rate: {val_losses['final_evasion_rate']:.1%}")
            print(f"Avg delay: {val_losses['avg_delay_ms']:.1f}ms")
            print(f"Avg padding: {val_losses['avg_padding']*100:.0f}%")
            print(f"Quality gate: {'PASSED ✓' if passed else 'FAILED ✗'}")

            if passed:
                quality_passed = True

            # Save best model by evasion rate
            if val_losses["final_evasion_rate"] > best_evasion:
                best_evasion = val_losses["final_evasion_rate"]
                patience_counter = 0

                torch.save({
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "evasion_rate": best_evasion,
                    "config": config,
                }, "models/tmt_20m_adversarial_best.pt")
                print(f"Saved best model (evasion: {best_evasion:.1%})")
            else:
                patience_counter += 1
                if patience_counter >= config["training"]["patience"]:
                    print(f"Early stopping at epoch {epoch + 1}")
                    break

        scheduler.step()

    writer.close()

    print("\n" + "=" * 60)
    print("ADVERSARIAL TRAINING COMPLETE")
    print("=" * 60)
    print(f"Best evasion rate: {best_evasion:.1%}")
    print(f"Quality gates: {'PASSED ✓' if quality_passed else 'FAILED ✗'}")

    if quality_passed:
        print("\n✓ Model ready for ONNX export: models/tmt_20m_adversarial_best.pt")
        return 0
    else:
        print("\n✗ Model did not pass quality gates!")
        print("Consider: more epochs, larger dataset, or tuning loss weights")
        return 1


if __name__ == "__main__":
    exit(main())
