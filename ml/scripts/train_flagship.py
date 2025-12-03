#!/usr/bin/env python3
"""
Flagship Training Script for TMT-20M with Curriculum Learning.

Key improvements:
1. 5-level curriculum: No DPI -> Standard -> Russia -> China -> Iran -> Paranoid
2. Dynamic difficulty progression based on evasion rate
3. Mixed batches: 70% current level + 30% previous levels
4. Adaptive loss weights that increase with curriculum level
5. Detector-specific auxiliary losses
6. Cosine annealing with warm restarts
7. Strict quality gates: 85% evasion vs Paranoid DPI
"""

import argparse
import os
import random
from pathlib import Path
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass
from enum import IntEnum

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from torch.utils.tensorboard import SummaryWriter
from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts
import yaml
from tqdm import tqdm

from model import TrafficMorphingTransformer, create_model
from dpi_simulator import ParanoidDpi, DpiConfig, DpiVerdict


class CurriculumLevel(IntEnum):
    """Curriculum difficulty levels."""
    NO_DPI = 0      # Baseline: only profile matching
    STANDARD = 1    # Default DPI (threshold=60)
    RUSSIA = 2      # Russia RKN (threshold=40)
    CHINA = 3       # China GFW (threshold=30)
    IRAN = 4        # Iran (threshold=35)
    PARANOID = 5    # Maximum paranoia (threshold=25)


@dataclass
class CurriculumConfig:
    """Configuration for curriculum learning."""
    # Thresholds for level progression
    promotion_threshold: float = 0.85   # Evasion rate to advance
    demotion_threshold: float = 0.60    # Evasion rate to go back
    # Mixing ratio
    current_level_ratio: float = 0.70   # 70% current, 30% previous
    # Minimum epochs per level
    min_epochs_per_level: int = 3
    # DPI configs per level
    level_configs: Dict[int, DpiConfig] = None

    def __post_init__(self):
        if self.level_configs is None:
            self.level_configs = {
                CurriculumLevel.NO_DPI: None,
                CurriculumLevel.STANDARD: DpiConfig(),  # Default
                CurriculumLevel.RUSSIA: DpiConfig.russia_rkn(),
                CurriculumLevel.CHINA: DpiConfig.china_gfw(),
                CurriculumLevel.IRAN: DpiConfig.iran(),
                CurriculumLevel.PARANOID: DpiConfig.paranoid(),
            }


class CurriculumManager:
    """Manages curriculum progression during training."""

    def __init__(self, config: CurriculumConfig):
        self.config = config
        self.current_level = CurriculumLevel.NO_DPI
        self.epochs_at_level = 0
        self.level_history: List[Tuple[int, int, float]] = []  # (epoch, level, evasion)

    def get_current_dpi_configs(self) -> List[Optional[DpiConfig]]:
        """Get DPI configs for current curriculum level with mixing."""
        configs = []

        # Current level (70%)
        current_config = self.config.level_configs[self.current_level]
        configs.append(current_config)

        # Previous levels (30%)
        if self.current_level > CurriculumLevel.NO_DPI:
            prev_levels = list(range(CurriculumLevel.NO_DPI, self.current_level))
            for level in prev_levels:
                configs.append(self.config.level_configs[level])

        return configs

    def select_dpi_config(self, rng: random.Random) -> Optional[DpiConfig]:
        """Select a DPI config based on curriculum mixing."""
        if rng.random() < self.config.current_level_ratio:
            return self.config.level_configs[self.current_level]
        else:
            # Sample from previous levels
            if self.current_level > CurriculumLevel.NO_DPI:
                prev_level = rng.randint(0, self.current_level - 1)
                return self.config.level_configs[prev_level]
            return None

    def update(self, epoch: int, evasion_rate: float) -> Tuple[bool, str]:
        """Update curriculum based on evasion rate.

        Returns:
            Tuple of (level_changed, message)
        """
        self.epochs_at_level += 1
        self.level_history.append((epoch, self.current_level, evasion_rate))

        message = ""
        level_changed = False

        # Check for promotion
        if (evasion_rate >= self.config.promotion_threshold and
            self.epochs_at_level >= self.config.min_epochs_per_level and
            self.current_level < CurriculumLevel.PARANOID):

            self.current_level = CurriculumLevel(self.current_level + 1)
            self.epochs_at_level = 0
            level_changed = True
            message = f"PROMOTED to level {self.current_level.name} (evasion: {evasion_rate:.1%})"

        # Check for demotion
        elif (evasion_rate < self.config.demotion_threshold and
              self.current_level > CurriculumLevel.NO_DPI):

            self.current_level = CurriculumLevel(self.current_level - 1)
            self.epochs_at_level = 0
            level_changed = True
            message = f"DEMOTED to level {self.current_level.name} (evasion: {evasion_rate:.1%})"

        return level_changed, message

    def get_adaptive_dpi_weight(self, base_weight: float) -> float:
        """Get adaptive DPI weight based on curriculum level."""
        # Higher weight at higher levels
        level_multiplier = 1.0 + 0.3 * self.current_level
        return base_weight * level_multiplier


def set_deterministic(seed: int, deterministic: bool = True):
    """Set all random seeds for reproducibility."""
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


class FlagshipTrafficDataset(Dataset):
    """Dataset optimized for flagship training."""

    def __init__(self, data_path: str, context_size: int = 32):
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

        # Target values
        self.target_delay = torch.tensor(df["target_delay"].values, dtype=torch.float32)
        self.target_padding = torch.tensor(df["target_padding"].values, dtype=torch.float32)
        self.target_inject = torch.tensor(df["target_inject"].values, dtype=torch.float32)

        # Profile statistics
        self.profile_stats = self._compute_profile_stats(df)

        self.num_samples = len(self.features) - context_size + 1

    def _compute_profile_stats(self, df) -> Dict[int, Dict[str, float]]:
        """Compute target statistics per profile."""
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
        end_idx = idx + self.context_size

        context = self.features[idx:end_idx]
        profile = self.profiles[end_idx - 1]

        raw_sizes = self.raw_sizes[idx:end_idx]
        raw_delays = self.raw_delays[idx:end_idx]
        raw_directions = self.raw_directions[idx:end_idx]

        target_delay = self.target_delay[end_idx - 1]
        target_padding = self.target_padding[end_idx - 1]
        target_inject = self.target_inject[end_idx - 1]

        return (context, profile, raw_sizes, raw_delays, raw_directions,
                target_delay, target_padding, target_inject)


class FlagshipMorphingLoss(nn.Module):
    """
    Flagship loss with curriculum-aware weighting and detector-specific losses.
    """

    def __init__(
        self,
        dpi_weight: float = 3.0,
        similarity_weight: float = 0.3,
        efficiency_weight: float = 0.2,
        confidence_weight: float = 0.2,
        detector_weight: float = 0.5,  # NEW: detector-specific losses
        max_delay_ms: float = 15.0,
        max_padding_ratio: float = 0.25,
        label_smoothing: float = 0.1,
    ):
        super().__init__()
        self.dpi_weight = dpi_weight
        self.similarity_weight = similarity_weight
        self.efficiency_weight = efficiency_weight
        self.confidence_weight = confidence_weight
        self.detector_weight = detector_weight
        self.max_delay_ms = max_delay_ms
        self.max_padding_ratio = max_padding_ratio
        self.label_smoothing = label_smoothing

        # Curriculum manager will be set externally
        self.curriculum_manager: Optional[CurriculumManager] = None

    def set_curriculum_manager(self, manager: CurriculumManager):
        """Set curriculum manager for adaptive weighting."""
        self.curriculum_manager = manager

    def forward(
        self,
        outputs: Dict[str, torch.Tensor],
        raw_sizes: torch.Tensor,
        raw_delays: torch.Tensor,
        raw_directions: torch.Tensor,
        profile_ids: torch.Tensor,
        profile_stats: Dict[int, Dict[str, float]],
        target_delay: torch.Tensor,
        target_padding: torch.Tensor,
        target_inject: torch.Tensor,
    ) -> Tuple[torch.Tensor, Dict[str, float]]:
        """Compute flagship loss with curriculum awareness."""
        batch_size = outputs["delay_ms"].shape[0]
        device = outputs["delay_ms"].device

        # Get adaptive DPI weight
        effective_dpi_weight = self.dpi_weight
        if self.curriculum_manager:
            effective_dpi_weight = self.curriculum_manager.get_adaptive_dpi_weight(self.dpi_weight)

        # 1. DPI Evasion Loss
        dpi_scores, detector_scores = self._compute_dpi_scores_detailed(
            raw_sizes, raw_delays, raw_directions,
            outputs["padding_norm"], outputs["delay_ms"]
        )
        dpi_scores_tensor = torch.tensor(dpi_scores, dtype=torch.float32, device=device)

        # Progressive target: start with 30, decrease to 15 at higher curriculum levels
        target_score = 30.0
        if self.curriculum_manager:
            target_score = 30.0 - 3.0 * self.curriculum_manager.current_level

        dpi_loss = F.relu(dpi_scores_tensor - target_score).mean() / 30.0

        # 2. Detector-Specific Losses (NEW)
        detector_loss = self._compute_detector_loss(detector_scores, device)

        # 3. Profile Similarity Loss (with target values)
        similarity_loss = self._compute_similarity_loss(
            outputs, target_delay, target_padding, target_inject
        )

        # 4. Efficiency Bounds
        delay_excess = F.relu(outputs["delay_ms"] - self.max_delay_ms)
        padding_excess = F.relu(outputs["padding_norm"] - self.max_padding_ratio)
        efficiency_loss = delay_excess.mean() / self.max_delay_ms + padding_excess.mean()

        # 5. Confidence Calibration with label smoothing
        evasion_rate = (dpi_scores_tensor < 25.0).float()
        smoothed_target = evasion_rate * (1 - self.label_smoothing) + 0.5 * self.label_smoothing
        confidence_loss = F.mse_loss(outputs["confidence"], smoothed_target)

        # Combined loss
        total_loss = (
            effective_dpi_weight * dpi_loss
            + self.detector_weight * detector_loss
            + self.similarity_weight * similarity_loss
            + self.efficiency_weight * efficiency_loss
            + self.confidence_weight * confidence_loss
        )

        return total_loss, {
            "dpi_loss": dpi_loss.item(),
            "detector_loss": detector_loss.item(),
            "similarity_loss": similarity_loss.item(),
            "efficiency_loss": efficiency_loss.item(),
            "confidence_loss": confidence_loss.item(),
            "total_loss": total_loss.item(),
            "avg_dpi_score": dpi_scores.mean(),
            "evasion_rate": (dpi_scores < 25.0).mean(),  # Against block threshold
            "avg_delay_ms": outputs["delay_ms"].mean().item(),
            "avg_padding": outputs["padding_norm"].mean().item(),
        }

    def _compute_dpi_scores_detailed(
        self,
        raw_sizes: torch.Tensor,
        raw_delays: torch.Tensor,
        raw_directions: torch.Tensor,
        padding_norm: torch.Tensor,
        delay_ms: torch.Tensor,
    ) -> Tuple[np.ndarray, Dict[str, np.ndarray]]:
        """Run DPI simulation with detailed detector scores."""
        batch_size = raw_sizes.shape[0]
        seq_len = raw_sizes.shape[1]

        sizes_np = raw_sizes.cpu().numpy()
        delays_np = raw_delays.cpu().numpy()
        directions_np = raw_directions.cpu().numpy()
        padding_np = padding_norm.detach().cpu().numpy()
        delay_applied_np = delay_ms.detach().cpu().numpy()

        scores = np.zeros(batch_size)
        detector_scores = {
            "size_pattern": np.zeros(batch_size),
            "timing": np.zeros(batch_size),
            "direction": np.zeros(batch_size),
            "entropy": np.zeros(batch_size),
            "burst": np.zeros(batch_size),
        }

        # Get config from curriculum manager
        config = None
        if self.curriculum_manager:
            config = self.curriculum_manager.select_dpi_config(random.Random())

        if config is None:
            config = DpiConfig()

        for i in range(batch_size):
            dpi = ParanoidDpi(config=config)

            for j in range(seq_len):
                size = int(sizes_np[i, j])
                delay = float(delays_np[i, j])
                direction = int(directions_np[i, j])

                # Apply modifications to ALL packets, not just the last one
                size = min(size + int(padding_np[i] * 1500), 1500)
                delay = delay + delay_applied_np[i]

                verdict, score, reasons = dpi.analyze_packet(size, delay, direction)

                # Track which detectors fired
                for reason in reasons:
                    if "size" in reason.lower():
                        detector_scores["size_pattern"][i] += 1
                    if "timing" in reason.lower() or "periodic" in reason.lower():
                        detector_scores["timing"][i] += 1
                    if "direction" in reason.lower():
                        detector_scores["direction"][i] += 1
                    if "entropy" in reason.lower():
                        detector_scores["entropy"][i] += 1
                    if "burst" in reason.lower():
                        detector_scores["burst"][i] += 1

            scores[i] = dpi.suspicion_score

        return scores, detector_scores

    def _compute_detector_loss(
        self,
        detector_scores: Dict[str, np.ndarray],
        device: torch.device,
    ) -> torch.Tensor:
        """Compute loss based on which specific detectors fired."""
        losses = []

        for name, scores in detector_scores.items():
            # Penalize any detector firing
            scores_tensor = torch.tensor(scores, dtype=torch.float32, device=device)
            # Normalize by max expected fires
            losses.append(scores_tensor.mean() / 10.0)

        return torch.stack(losses).mean() if losses else torch.tensor(0.0, device=device)

    def _compute_similarity_loss(
        self,
        outputs: Dict[str, torch.Tensor],
        target_delay: torch.Tensor,
        target_padding: torch.Tensor,
        target_inject: torch.Tensor,
    ) -> torch.Tensor:
        """Compute similarity to target morphing parameters."""
        delay_loss = F.smooth_l1_loss(outputs["delay_ms"], target_delay)
        padding_loss = F.smooth_l1_loss(outputs["padding_norm"], target_padding)
        # Use logits with BCE for autocast safety
        inject_loss = F.binary_cross_entropy_with_logits(
            outputs["inject_logits"],
            target_inject,
            reduction="mean"
        )

        return delay_loss + padding_loss + 0.5 * inject_loss


def train_epoch(
    model: nn.Module,
    dataloader: DataLoader,
    optimizer: torch.optim.Optimizer,
    criterion: FlagshipMorphingLoss,
    device: torch.device,
    scaler: torch.amp.GradScaler,
    profile_stats: Dict,
    max_grad_norm: float = 0.5,
) -> Dict[str, float]:
    """Train for one epoch with curriculum-aware loss."""
    model.train()
    total_losses = {}

    pbar = tqdm(dataloader, desc="Training")
    for batch in pbar:
        (context, profile, raw_sizes, raw_delays, raw_dirs,
         target_delay, target_padding, target_inject) = batch

        context = context.to(device)
        profile = profile.to(device)
        raw_sizes = raw_sizes.to(device)
        raw_delays = raw_delays.to(device)
        raw_dirs = raw_dirs.to(device)
        target_delay = target_delay.to(device)
        target_padding = target_padding.to(device)
        target_inject = target_inject.to(device)

        optimizer.zero_grad()

        with torch.amp.autocast(device_type="cuda", enabled=device.type == "cuda"):
            outputs = model(context, profile)
            loss, loss_dict = criterion(
                outputs, raw_sizes, raw_delays, raw_dirs, profile, profile_stats,
                target_delay, target_padding, target_inject
            )

        scaler.scale(loss).backward()
        scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_grad_norm)
        scaler.step(optimizer)
        scaler.update()

        for k, v in loss_dict.items():
            total_losses[k] = total_losses.get(k, 0) + v

        # Show curriculum level in progress bar
        level_name = "N/A"
        if criterion.curriculum_manager:
            level_name = criterion.curriculum_manager.current_level.name

        pbar.set_postfix(
            loss=f"{loss_dict['total_loss']:.3f}",
            evasion=f"{loss_dict['evasion_rate']:.1%}",
            level=level_name,
        )

    num_batches = len(dataloader)
    return {k: v / num_batches for k, v in total_losses.items()}


@torch.no_grad()
def validate_all_dpi_levels(
    model: nn.Module,
    dataloader: DataLoader,
    device: torch.device,
    profile_stats: Dict,
    max_batches: int = 50,
) -> Dict[str, float]:
    """Validate model against ALL DPI levels."""
    model.eval()

    level_evasion = {}
    dpi_configs = {
        "standard": DpiConfig(),
        "russia": DpiConfig.russia_rkn(),
        "china": DpiConfig.china_gfw(),
        "iran": DpiConfig.iran(),
        "paranoid": DpiConfig.paranoid(),
    }

    for level_name, config in dpi_configs.items():
        blocked_count = 0
        total_count = 0

        for batch_idx, batch in enumerate(dataloader):
            if batch_idx >= max_batches:
                break

            (context, profile, raw_sizes, raw_delays, raw_dirs,
             target_delay, target_padding, target_inject) = batch

            context = context.to(device)
            profile = profile.to(device)

            outputs = model(context, profile)

            # Run DPI simulation
            batch_size = raw_sizes.shape[0]
            seq_len = raw_sizes.shape[1]

            sizes_np = raw_sizes.cpu().numpy()
            delays_np = raw_delays.cpu().numpy()
            directions_np = raw_dirs.cpu().numpy()
            padding_np = outputs["padding_norm"].detach().cpu().numpy()
            delay_applied_np = outputs["delay_ms"].detach().cpu().numpy()

            for i in range(batch_size):
                dpi = ParanoidDpi(config=config)

                for j in range(seq_len):
                    size = int(sizes_np[i, j])
                    delay = float(delays_np[i, j])
                    direction = int(directions_np[i, j])

                    # Apply modifications to ALL packets, not just the last one
                    size = min(size + int(padding_np[i] * 1500), 1500)
                    delay = delay + delay_applied_np[i]

                    dpi.analyze_packet(size, delay, direction)

                if dpi.suspicion_score >= config.block_threshold:
                    blocked_count += 1
                total_count += 1

        evasion_rate = 1.0 - (blocked_count / total_count) if total_count > 0 else 0.0
        level_evasion[level_name] = evasion_rate

    return level_evasion


@torch.no_grad()
def validate(
    model: nn.Module,
    dataloader: DataLoader,
    criterion: FlagshipMorphingLoss,
    device: torch.device,
    profile_stats: Dict,
) -> Tuple[Dict[str, float], bool]:
    """Validate model with strict quality gates."""
    model.eval()
    total_losses = {}
    all_evasion_rates = []

    for batch in tqdm(dataloader, desc="Validating"):
        (context, profile, raw_sizes, raw_delays, raw_dirs,
         target_delay, target_padding, target_inject) = batch

        context = context.to(device)
        profile = profile.to(device)
        raw_sizes = raw_sizes.to(device)
        raw_delays = raw_delays.to(device)
        raw_dirs = raw_dirs.to(device)
        target_delay = target_delay.to(device)
        target_padding = target_padding.to(device)
        target_inject = target_inject.to(device)

        outputs = model(context, profile)
        _, loss_dict = criterion(
            outputs, raw_sizes, raw_delays, raw_dirs, profile, profile_stats,
            target_delay, target_padding, target_inject
        )

        for k, v in loss_dict.items():
            total_losses[k] = total_losses.get(k, 0) + v

        all_evasion_rates.append(loss_dict["evasion_rate"])

    num_batches = len(dataloader)
    avg_losses = {k: v / num_batches for k, v in total_losses.items()}
    avg_evasion = np.mean(all_evasion_rates)
    avg_losses["final_evasion_rate"] = avg_evasion

    # STRICT quality gates for flagship
    passed = (
        avg_evasion > 0.85  # 85% evasion rate (was 70%)
        and avg_losses["avg_delay_ms"] < 12.0  # Tighter delay (was 15)
        and avg_losses["avg_padding"] < 0.20  # Tighter padding (was 25%)
    )

    return avg_losses, passed


def main():
    parser = argparse.ArgumentParser(description="Flagship training for TMT-20M")
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
    train_dataset = FlagshipTrafficDataset(
        config["data"]["train_path"], config["model"]["context_size"]
    )
    val_dataset = FlagshipTrafficDataset(
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

    # Cosine Annealing with Warm Restarts
    scheduler = CosineAnnealingWarmRestarts(
        optimizer,
        T_0=config["training"].get("restart_period", 20),
        T_mult=1,
        eta_min=config["training"]["lr"] * 0.01,
    )

    # Curriculum Manager
    curriculum_config = CurriculumConfig(
        promotion_threshold=config.get("curriculum", {}).get("promotion_threshold", 0.85),
        demotion_threshold=config.get("curriculum", {}).get("demotion_threshold", 0.60),
        min_epochs_per_level=config.get("curriculum", {}).get("min_epochs_per_level", 3),
    )
    curriculum_manager = CurriculumManager(curriculum_config)

    # Flagship Loss
    criterion = FlagshipMorphingLoss(
        dpi_weight=config.get("loss", {}).get("dpi_weight", 3.0),
        similarity_weight=config.get("loss", {}).get("similarity_weight", 0.3),
        efficiency_weight=config.get("loss", {}).get("efficiency_weight", 0.2),
        confidence_weight=config.get("loss", {}).get("confidence_weight", 0.2),
        detector_weight=config.get("loss", {}).get("detector_weight", 0.5),
        label_smoothing=config.get("loss", {}).get("label_smoothing", 0.1),
    )
    criterion.set_curriculum_manager(curriculum_manager)

    scaler = torch.amp.GradScaler(enabled=device.type == "cuda")
    writer = SummaryWriter(f"runs/tmt_20m_flagship_seed{config['seed']}")

    best_paranoid_evasion = 0.0
    patience_counter = 0
    quality_passed = False

    Path("models").mkdir(exist_ok=True)

    print("\n" + "=" * 70)
    print("FLAGSHIP TRAINING WITH CURRICULUM LEARNING")
    print("=" * 70)
    print(f"Curriculum levels: NO_DPI -> STANDARD -> RUSSIA -> CHINA -> IRAN -> PARANOID")
    print(f"Promotion threshold: {curriculum_config.promotion_threshold:.0%}")
    print(f"Demotion threshold: {curriculum_config.demotion_threshold:.0%}")
    print(f"Quality gate: 85% evasion vs Paranoid DPI")
    print("=" * 70)

    for epoch in range(config["training"]["epochs"]):
        print(f"\n{'='*70}")
        print(f"Epoch {epoch + 1}/{config['training']['epochs']} | "
              f"Curriculum: {curriculum_manager.current_level.name}")
        print(f"{'='*70}")

        # Train
        train_losses = train_epoch(
            model, train_loader, optimizer, criterion, device, scaler,
            train_dataset.profile_stats, config["training"]["max_grad_norm"]
        )

        for k, v in train_losses.items():
            writer.add_scalar(f"train/{k}", v, epoch)
        writer.add_scalar("curriculum/level", curriculum_manager.current_level, epoch)

        print(f"\nTrain - Loss: {train_losses['total_loss']:.4f}, "
              f"Evasion: {train_losses['evasion_rate']:.1%}, "
              f"Delay: {train_losses['avg_delay_ms']:.1f}ms, "
              f"Padding: {train_losses['avg_padding']*100:.0f}%")

        # Validate
        if (epoch + 1) % config["training"]["val_every"] == 0:
            val_losses, passed = validate(
                model, val_loader, criterion, device, val_dataset.profile_stats
            )

            # Validate against all DPI levels
            level_evasion = validate_all_dpi_levels(
                model, val_loader, device, val_dataset.profile_stats
            )

            for k, v in val_losses.items():
                writer.add_scalar(f"val/{k}", v, epoch)
            for level, evasion in level_evasion.items():
                writer.add_scalar(f"val/evasion_{level}", evasion, epoch)

            print(f"\nValidation Results:")
            print(f"  Loss: {val_losses['total_loss']:.4f}")
            print(f"  Current level evasion: {val_losses['final_evasion_rate']:.1%}")
            print(f"\n  Evasion by DPI level:")
            for level, evasion in level_evasion.items():
                status = "OK" if evasion >= 0.80 else "NEEDS WORK"
                print(f"    {level:12s}: {evasion:6.1%} [{status}]")

            paranoid_evasion = level_evasion.get("paranoid", 0.0)
            print(f"\n  Quality gate (85% vs Paranoid): "
                  f"{'PASSED' if paranoid_evasion >= 0.85 else 'FAILED'}")

            if paranoid_evasion >= 0.85:
                quality_passed = True

            # Update curriculum
            level_changed, message = curriculum_manager.update(
                epoch, val_losses["final_evasion_rate"]
            )
            if level_changed:
                print(f"\n  *** CURRICULUM: {message} ***")

            # Save best model by paranoid evasion
            if paranoid_evasion > best_paranoid_evasion:
                best_paranoid_evasion = paranoid_evasion
                patience_counter = 0

                torch.save({
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "paranoid_evasion": best_paranoid_evasion,
                    "all_level_evasion": level_evasion,
                    "curriculum_level": curriculum_manager.current_level,
                    "config": config,
                }, "models/tmt_20m_flagship_best.pt")
                print(f"\n  Saved best model (paranoid evasion: {best_paranoid_evasion:.1%})")
            else:
                patience_counter += 1
                if patience_counter >= config["training"]["patience"]:
                    print(f"\n  Early stopping at epoch {epoch + 1}")
                    break

        scheduler.step()

    writer.close()

    print("\n" + "=" * 70)
    print("FLAGSHIP TRAINING COMPLETE")
    print("=" * 70)
    print(f"Best paranoid evasion: {best_paranoid_evasion:.1%}")
    print(f"Quality gates: {'PASSED' if quality_passed else 'FAILED'}")
    print(f"Final curriculum level: {curriculum_manager.current_level.name}")

    if quality_passed:
        print("\nModel ready for ONNX export: models/tmt_20m_flagship_best.pt")
        return 0
    else:
        print("\nModel did not pass quality gates!")
        print("Consider: more epochs, better data, or hyperparameter tuning")
        return 1


if __name__ == "__main__":
    exit(main())
