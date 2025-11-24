#!/usr/bin/env python3
"""
Ultimate Dataset Generator for TMT-20M Training.

Creates high-quality synthetic traffic with realistic patterns:
- Bimodal/multimodal size distributions (ACK + data packets)
- Burst patterns with realistic inter-burst gaps
- Correlated features (large packets = longer delays in streaming)
- Session dynamics (warmup, steady, cooldown phases)
"""

import argparse
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from dataclasses import dataclass


@dataclass
class ProfileConfig:
    """Realistic profile configuration based on traffic analysis papers."""
    name: str
    # Size distribution (bimodal: small ACKs + large data)
    size_modes: List[Tuple[float, float, float]]  # (mean, std, weight)
    # Delay distribution (log-normal base + burst structure)
    delay_base_log: float
    delay_std: float
    # Burst characteristics
    burst_size_range: Tuple[int, int]
    inter_burst_ms: Tuple[float, float]
    # Direction ratio and correlation
    outbound_ratio: float
    size_direction_corr: float  # Large packets more likely inbound for streaming
    # Session dynamics
    warmup_packets: int
    cooldown_packets: int
    # Target morphing parameters (what we want model to learn)
    target_delay_ms: float
    target_padding_ratio: float
    target_inject_prob: float


PROFILES: Dict[str, ProfileConfig] = {
    "youtube": ProfileConfig(
        name="youtube",
        # Bimodal: ~64 byte ACKs, ~1200 byte video chunks
        size_modes=[(64, 10, 0.2), (1200, 200, 0.7), (600, 150, 0.1)],
        delay_base_log=2.3,
        delay_std=1.2,
        burst_size_range=(8, 32),
        inter_burst_ms=(50, 200),
        outbound_ratio=0.15,
        size_direction_corr=-0.4,  # Large = inbound
        warmup_packets=50,
        cooldown_packets=30,
        target_delay_ms=2.0,
        target_padding_ratio=0.1,
        target_inject_prob=0.05,
    ),
    "zoom": ProfileConfig(
        name="zoom",
        # RTP packets: mostly fixed sizes with some variation
        size_modes=[(200, 40, 0.3), (800, 100, 0.5), (1200, 80, 0.2)],
        delay_base_log=1.8,
        delay_std=0.6,
        burst_size_range=(2, 8),
        inter_burst_ms=(15, 40),
        outbound_ratio=0.48,  # Symmetric for video calls
        size_direction_corr=0.0,  # No correlation
        warmup_packets=20,
        cooldown_packets=10,
        target_delay_ms=1.0,
        target_padding_ratio=0.15,
        target_inject_prob=0.1,
    ),
    "gaming": ProfileConfig(
        name="gaming",
        # Small, frequent packets: game state updates
        size_modes=[(80, 20, 0.5), (150, 40, 0.35), (300, 60, 0.15)],
        delay_base_log=1.2,
        delay_std=0.4,
        burst_size_range=(1, 4),
        inter_burst_ms=(8, 25),
        outbound_ratio=0.52,  # Slightly more outbound (inputs)
        size_direction_corr=0.2,  # Outbound slightly larger (commands)
        warmup_packets=10,
        cooldown_packets=5,
        target_delay_ms=0.5,
        target_padding_ratio=0.05,
        target_inject_prob=0.02,
    ),
    "browsing": ProfileConfig(
        name="browsing",
        # Highly variable: small requests, large responses
        size_modes=[(100, 30, 0.25), (500, 200, 0.35), (1400, 100, 0.4)],
        delay_base_log=3.2,
        delay_std=1.8,
        burst_size_range=(5, 50),
        inter_burst_ms=(200, 2000),
        outbound_ratio=0.25,
        size_direction_corr=-0.5,  # Large = inbound (content)
        warmup_packets=5,
        cooldown_packets=3,
        target_delay_ms=5.0,
        target_padding_ratio=0.2,
        target_inject_prob=0.15,
    ),
    "netflix": ProfileConfig(
        name="netflix",
        # Similar to YouTube but larger chunks, more regular
        size_modes=[(64, 10, 0.15), (1350, 100, 0.75), (800, 150, 0.1)],
        delay_base_log=2.1,
        delay_std=0.9,
        burst_size_range=(10, 40),
        inter_burst_ms=(30, 150),
        outbound_ratio=0.10,  # Mostly download
        size_direction_corr=-0.6,  # Strong: large = inbound
        warmup_packets=40,
        cooldown_packets=20,
        target_delay_ms=3.0,
        target_padding_ratio=0.12,
        target_inject_prob=0.08,
    ),
}

PROFILE_IDS = {name: i for i, name in enumerate(PROFILES.keys())}
MTU = 1500
CONTEXT_SIZE = 16


def sample_size(profile: ProfileConfig, rng: np.random.Generator, direction: int) -> int:
    """Sample packet size from multimodal distribution with direction correlation."""
    modes = profile.size_modes
    weights = np.array([m[2] for m in modes])

    # Adjust weights based on direction correlation
    if profile.size_direction_corr != 0:
        # Inbound (direction=-1) gets larger packets if corr < 0
        adjustment = profile.size_direction_corr * direction * 0.3
        weights = weights * (1 + adjustment * np.arange(len(weights)) / len(weights))
        weights = weights / weights.sum()

    # Pick mode
    mode_idx = rng.choice(len(modes), p=weights)
    mean, std, _ = modes[mode_idx]

    # Sample from mode
    size = int(rng.normal(mean, std))
    return max(40, min(size, MTU))


def generate_session(
    profile: ProfileConfig,
    num_packets: int,
    rng: np.random.Generator,
    session_seed: int,
) -> List[Dict]:
    """Generate a realistic session with warmup/steady/cooldown phases."""
    packets = []
    timestamp = time.time() + session_seed * 1000  # Offset for uniqueness

    # Session phases
    warmup_end = profile.warmup_packets
    cooldown_start = num_packets - profile.cooldown_packets

    burst_remaining = 0
    burst_start_idx = 0

    for i in range(num_packets):
        # Phase-dependent behavior
        if i < warmup_end:
            # Warmup: more variable, establishing connection
            delay_mult = 1.5
            size_mult = 0.7
        elif i >= cooldown_start:
            # Cooldown: slower, smaller packets
            delay_mult = 2.0
            size_mult = 0.5
        else:
            # Steady state
            delay_mult = 1.0
            size_mult = 1.0

        # Burst structure
        if burst_remaining <= 0:
            # Start new burst
            burst_size = rng.integers(*profile.burst_size_range)
            burst_remaining = burst_size
            burst_start_idx = i

            # Inter-burst delay
            if i > 0:
                inter_burst = rng.uniform(*profile.inter_burst_ms)
                timestamp += inter_burst / 1000.0

        # Intra-burst delay
        delay_log = rng.normal(profile.delay_base_log, profile.delay_std) * delay_mult
        delay_log = max(0.001, delay_log)
        delay_ms = np.expm1(delay_log)

        if burst_remaining > 1:
            # Within burst: shorter delays
            delay_ms = delay_ms * 0.3

        timestamp += delay_ms / 1000.0

        # Direction
        direction = 1 if rng.random() < profile.outbound_ratio else -1

        # Size
        size = int(sample_size(profile, rng, direction) * size_mult)
        size = max(40, min(size, MTU))

        # Burst position
        burst_pos = min((i - burst_start_idx) / 32.0, 1.0)

        packets.append({
            "timestamp": timestamp,
            "size": size,
            "size_norm": size / MTU,
            "delay_log": np.log1p(delay_ms),
            "direction": float(direction),
            "burst_pos": burst_pos,
            "profile_id": PROFILE_IDS[profile.name],
            "target_delay": profile.target_delay_ms,
            "target_padding": profile.target_padding_ratio,
            "target_inject": profile.target_inject_prob,
        })

        burst_remaining -= 1

    return packets


def generate_profile_data(
    profile: ProfileConfig,
    total_packets: int,
    num_sessions: int,
    base_seed: int,
) -> pd.DataFrame:
    """Generate data for one profile across multiple sessions."""
    packets_per_session = total_packets // num_sessions
    all_packets = []

    for session in range(num_sessions):
        seed = base_seed + session * 1000
        rng = np.random.default_rng(seed)

        packets = generate_session(
            profile,
            packets_per_session,
            rng,
            session,
        )
        all_packets.extend(packets)

    return pd.DataFrame(all_packets)


def create_training_windows(df: pd.DataFrame) -> pd.DataFrame:
    """Create sliding window samples for training."""
    # Already have per-packet features, just need to ensure context availability
    # Model uses context from FeatureContext, so we keep individual samples
    return df[df.index >= CONTEXT_SIZE - 1].reset_index(drop=True)


def main():
    parser = argparse.ArgumentParser(description="Generate ultimate TMT-20M dataset")
    parser.add_argument("--packets-per-profile", type=int, default=200000,
                        help="Packets per profile")
    parser.add_argument("--sessions-per-profile", type=int, default=50,
                        help="Sessions per profile for diversity")
    parser.add_argument("--seed", type=int, default=42, help="Base random seed")
    parser.add_argument("--output-dir", type=str, default="data/ultimate",
                        help="Output directory")
    parser.add_argument("--train-ratio", type=float, default=0.8)
    parser.add_argument("--val-ratio", type=float, default=0.1)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("Ultimate Dataset Generator for TMT-20M")
    print("=" * 60)
    print(f"Packets per profile: {args.packets_per_profile:,}")
    print(f"Sessions per profile: {args.sessions_per_profile}")
    print(f"Total packets: {args.packets_per_profile * len(PROFILES):,}")
    print()

    all_dfs = []

    for i, (name, profile) in enumerate(PROFILES.items()):
        print(f"[{i+1}/{len(PROFILES)}] Generating {name}...")

        df = generate_profile_data(
            profile,
            args.packets_per_profile,
            args.sessions_per_profile,
            args.seed + i * 10000,
        )

        # Stats
        print(f"    Size: mean={df['size_norm'].mean():.3f}, std={df['size_norm'].std():.3f}")
        print(f"    Delay: mean={df['delay_log'].mean():.3f}, std={df['delay_log'].std():.3f}")
        print(f"    Direction: outbound={df['direction'].mean():.1%}")

        all_dfs.append(df)

    # Combine all profiles
    print("\nCombining datasets...")
    combined = pd.concat(all_dfs, ignore_index=True)

    # Shuffle
    combined = combined.sample(frac=1, random_state=args.seed).reset_index(drop=True)

    # Split
    n = len(combined)
    train_end = int(n * args.train_ratio)
    val_end = int(n * (args.train_ratio + args.val_ratio))

    train_df = combined.iloc[:train_end]
    val_df = combined.iloc[train_end:val_end]
    test_df = combined.iloc[val_end:]

    # Save
    train_df.to_parquet(output_dir / "train.parquet", index=False)
    val_df.to_parquet(output_dir / "val.parquet", index=False)
    test_df.to_parquet(output_dir / "test.parquet", index=False)

    print("\n" + "=" * 60)
    print("Dataset saved to:", output_dir)
    print("=" * 60)
    print(f"  train.parquet: {len(train_df):,} samples ({len(train_df)/n:.1%})")
    print(f"  val.parquet:   {len(val_df):,} samples ({len(val_df)/n:.1%})")
    print(f"  test.parquet:  {len(test_df):,} samples ({len(test_df)/n:.1%})")

    # Profile distribution
    print("\nProfile distribution:")
    for name, pid in PROFILE_IDS.items():
        count = (combined['profile_id'] == pid).sum()
        print(f"  {name}: {count:,} ({count/n:.1%})")

    # Overall stats
    print("\nOverall statistics:")
    print(f"  Size (norm): mean={combined['size_norm'].mean():.3f}, std={combined['size_norm'].std():.3f}")
    print(f"  Delay (log): mean={combined['delay_log'].mean():.3f}, std={combined['delay_log'].std():.3f}")
    print(f"  Burst pos:   mean={combined['burst_pos'].mean():.3f}")

    print("\nDone!")
    return 0


if __name__ == "__main__":
    exit(main())
