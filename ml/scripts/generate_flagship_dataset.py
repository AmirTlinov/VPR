#!/usr/bin/env python3
"""
Flagship Dataset Generator for TMT-20M Training.

Key improvements over ultimate dataset:
1. Sub-profiles for each traffic type (YouTube 1080p, 4K, live, etc.)
2. Data augmentation (noise injection, time warping, size jitter)
3. DPI-adversarial examples (hard negatives that trigger specific detectors)
4. Improved session dynamics with realistic patterns
5. 5x more data volume for better generalization
"""

import argparse
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

import numpy as np
import pandas as pd


class AugmentationType(Enum):
    """Types of data augmentation."""
    NONE = "none"
    NOISE = "noise"
    TIME_WARP = "time_warp"
    SIZE_JITTER = "size_jitter"
    BURST_SHUFFLE = "burst_shuffle"


@dataclass
class SubProfile:
    """Sub-profile configuration for fine-grained traffic patterns."""
    name: str
    parent: str
    # Size distribution adjustments
    size_scale: float = 1.0
    size_shift: float = 0.0
    # Delay adjustments
    delay_scale: float = 1.0
    # Burst adjustments
    burst_scale: float = 1.0
    # Target morphing (what model should learn)
    target_delay_ms: float = 2.0
    target_padding_ratio: float = 0.1
    target_inject_prob: float = 0.05
    # Weight for sampling
    weight: float = 1.0


@dataclass
class ProfileConfig:
    """Realistic profile configuration with sub-profiles."""
    name: str
    profile_id: int
    # Size distribution (multimodal)
    size_modes: List[Tuple[float, float, float]]  # (mean, std, weight)
    # Delay distribution
    delay_base_log: float
    delay_std: float
    # Burst characteristics
    burst_size_range: Tuple[int, int]
    inter_burst_ms: Tuple[float, float]
    # Direction ratio
    outbound_ratio: float
    size_direction_corr: float
    # Session dynamics
    warmup_packets: int
    cooldown_packets: int
    # Sub-profiles
    sub_profiles: List[SubProfile] = field(default_factory=list)


# Enhanced profiles with sub-profiles
PROFILES: Dict[str, ProfileConfig] = {
    "youtube": ProfileConfig(
        name="youtube",
        profile_id=0,
        size_modes=[(64, 10, 0.15), (1200, 200, 0.70), (600, 150, 0.15)],
        delay_base_log=2.3,
        delay_std=1.2,
        burst_size_range=(8, 32),
        inter_burst_ms=(50, 200),
        outbound_ratio=0.15,
        size_direction_corr=-0.4,
        warmup_packets=50,
        cooldown_packets=30,
        sub_profiles=[
            SubProfile("youtube_480p", "youtube", size_scale=0.6, target_delay_ms=3.0, weight=0.15),
            SubProfile("youtube_720p", "youtube", size_scale=0.8, target_delay_ms=2.5, weight=0.25),
            SubProfile("youtube_1080p", "youtube", size_scale=1.0, target_delay_ms=2.0, weight=0.30),
            SubProfile("youtube_4k", "youtube", size_scale=1.3, delay_scale=0.8, target_delay_ms=1.5, weight=0.15),
            SubProfile("youtube_live", "youtube", size_scale=0.9, delay_scale=0.6, burst_scale=0.5, target_delay_ms=1.0, weight=0.15),
        ],
    ),
    "zoom": ProfileConfig(
        name="zoom",
        profile_id=1,
        size_modes=[(200, 40, 0.30), (800, 100, 0.50), (1200, 80, 0.20)],
        delay_base_log=1.8,
        delay_std=0.6,
        burst_size_range=(2, 8),
        inter_burst_ms=(15, 40),
        outbound_ratio=0.48,
        size_direction_corr=0.0,
        warmup_packets=20,
        cooldown_packets=10,
        sub_profiles=[
            SubProfile("zoom_audio", "zoom", size_scale=0.4, target_delay_ms=0.5, target_padding_ratio=0.05, weight=0.20),
            SubProfile("zoom_video_low", "zoom", size_scale=0.7, target_delay_ms=1.0, weight=0.25),
            SubProfile("zoom_video_hd", "zoom", size_scale=1.0, target_delay_ms=1.5, weight=0.30),
            SubProfile("zoom_screenshare", "zoom", size_scale=1.2, burst_scale=2.0, target_delay_ms=2.0, weight=0.15),
            SubProfile("zoom_gallery", "zoom", size_scale=0.8, delay_scale=1.2, target_delay_ms=1.2, weight=0.10),
        ],
    ),
    "gaming": ProfileConfig(
        name="gaming",
        profile_id=2,
        size_modes=[(80, 20, 0.50), (150, 40, 0.35), (300, 60, 0.15)],
        delay_base_log=1.2,
        delay_std=0.4,
        burst_size_range=(1, 4),
        inter_burst_ms=(8, 25),
        outbound_ratio=0.52,
        size_direction_corr=0.2,
        warmup_packets=10,
        cooldown_packets=5,
        sub_profiles=[
            SubProfile("gaming_fps", "gaming", size_scale=0.8, delay_scale=0.5, target_delay_ms=0.3, weight=0.30),
            SubProfile("gaming_moba", "gaming", size_scale=1.0, target_delay_ms=0.5, weight=0.25),
            SubProfile("gaming_mmo", "gaming", size_scale=1.3, delay_scale=1.5, target_delay_ms=1.0, weight=0.20),
            SubProfile("gaming_casual", "gaming", size_scale=1.1, delay_scale=2.0, target_delay_ms=2.0, weight=0.15),
            SubProfile("gaming_stream", "gaming", size_scale=1.5, burst_scale=2.0, target_delay_ms=1.5, weight=0.10),
        ],
    ),
    "browsing": ProfileConfig(
        name="browsing",
        profile_id=3,
        size_modes=[(100, 30, 0.25), (500, 200, 0.35), (1400, 100, 0.40)],
        delay_base_log=3.2,
        delay_std=1.8,
        burst_size_range=(5, 50),
        inter_burst_ms=(200, 2000),
        outbound_ratio=0.25,
        size_direction_corr=-0.5,
        warmup_packets=5,
        cooldown_packets=3,
        sub_profiles=[
            SubProfile("browsing_text", "browsing", size_scale=0.5, target_delay_ms=3.0, weight=0.15),
            SubProfile("browsing_images", "browsing", size_scale=1.0, target_delay_ms=5.0, weight=0.30),
            SubProfile("browsing_spa", "browsing", size_scale=0.8, delay_scale=0.6, target_delay_ms=2.0, weight=0.25),
            SubProfile("browsing_video", "browsing", size_scale=1.2, burst_scale=1.5, target_delay_ms=4.0, weight=0.20),
            SubProfile("browsing_api", "browsing", size_scale=0.6, delay_scale=0.4, target_delay_ms=1.0, weight=0.10),
        ],
    ),
    "netflix": ProfileConfig(
        name="netflix",
        profile_id=4,
        size_modes=[(64, 10, 0.15), (1350, 100, 0.75), (800, 150, 0.10)],
        delay_base_log=2.1,
        delay_std=0.9,
        burst_size_range=(10, 40),
        inter_burst_ms=(30, 150),
        outbound_ratio=0.10,
        size_direction_corr=-0.6,
        warmup_packets=40,
        cooldown_packets=20,
        sub_profiles=[
            SubProfile("netflix_sd", "netflix", size_scale=0.6, target_delay_ms=4.0, weight=0.10),
            SubProfile("netflix_hd", "netflix", size_scale=0.85, target_delay_ms=3.0, weight=0.30),
            SubProfile("netflix_fhd", "netflix", size_scale=1.0, target_delay_ms=2.5, weight=0.35),
            SubProfile("netflix_4k", "netflix", size_scale=1.3, delay_scale=0.7, target_delay_ms=2.0, weight=0.15),
            SubProfile("netflix_dolby", "netflix", size_scale=1.4, delay_scale=0.6, target_delay_ms=1.5, weight=0.10),
        ],
    ),
}

MTU = 1500
CONTEXT_SIZE = 32  # Increased from 16 for better pattern learning


class DataAugmentor:
    """Data augmentation for traffic patterns."""

    def __init__(self, rng: np.random.Generator, intensity: float = 0.3):
        self.rng = rng
        self.intensity = intensity

    def apply_noise(self, packets: List[Dict]) -> List[Dict]:
        """Add Gaussian noise to features."""
        for pkt in packets:
            # Size noise (up to 5% of size)
            size_noise = self.rng.normal(0, pkt["size"] * 0.05 * self.intensity)
            pkt["size"] = max(40, min(MTU, int(pkt["size"] + size_noise)))
            pkt["size_norm"] = pkt["size"] / MTU

            # Delay noise (multiplicative)
            delay_factor = self.rng.normal(1.0, 0.1 * self.intensity)
            pkt["delay_log"] = max(0.001, pkt["delay_log"] * delay_factor)
        return packets

    def apply_time_warp(self, packets: List[Dict]) -> List[Dict]:
        """Apply time warping to delay sequence."""
        n = len(packets)
        if n < 10:
            return packets

        # Create warping function
        warp_points = self.rng.integers(2, 5)
        warp_x = np.sort(self.rng.choice(n, warp_points, replace=False))
        warp_y = warp_x + self.rng.normal(0, n * 0.1 * self.intensity, warp_points)
        warp_y = np.clip(warp_y, 0, n - 1)

        # Interpolate warping
        indices = np.arange(n)
        warped_indices = np.interp(indices, warp_x, warp_y).astype(int)
        warped_indices = np.clip(warped_indices, 0, n - 1)

        # Apply warping to delays only
        original_delays = [p["delay_log"] for p in packets]
        for i, pkt in enumerate(packets):
            pkt["delay_log"] = original_delays[warped_indices[i]]

        return packets

    def apply_size_jitter(self, packets: List[Dict]) -> List[Dict]:
        """Apply size jitter within realistic bounds."""
        for pkt in packets:
            # Jitter to nearby "bucket" size
            buckets = [40, 64, 128, 256, 512, 576, 800, 1024, 1200, 1400, 1460, 1500]
            current_size = pkt["size"]

            # Find nearby buckets
            distances = [abs(b - current_size) for b in buckets]
            nearby = [b for b, d in zip(buckets, distances) if d < 200]

            if nearby and self.rng.random() < self.intensity:
                new_size = self.rng.choice(nearby)
                pkt["size"] = new_size
                pkt["size_norm"] = new_size / MTU

        return packets

    def apply_burst_shuffle(self, packets: List[Dict]) -> List[Dict]:
        """Shuffle packets within bursts (preserving burst structure)."""
        # Find burst boundaries
        burst_starts = [0]
        for i in range(1, len(packets)):
            if packets[i]["burst_pos"] < packets[i-1]["burst_pos"]:
                burst_starts.append(i)
        burst_starts.append(len(packets))

        # Shuffle within bursts
        result = []
        for i in range(len(burst_starts) - 1):
            burst = packets[burst_starts[i]:burst_starts[i+1]]
            if len(burst) > 2 and self.rng.random() < self.intensity:
                self.rng.shuffle(burst)
            result.extend(burst)

        return result


class DpiAdversarialGenerator:
    """Generate adversarial examples that challenge specific DPI detectors."""

    def __init__(self, rng: np.random.Generator):
        self.rng = rng

    def generate_anti_size_pattern(self, profile: ProfileConfig, n_packets: int) -> List[Dict]:
        """Generate traffic that avoids common VPN size patterns."""
        packets = []
        timestamp = time.time()

        # Avoid VPN-typical sizes: 64, 128, 256, 512, 1024, 1280, 1400, 1420, 1440, 1460
        vpn_sizes = {64, 128, 256, 512, 1024, 1280, 1400, 1420, 1440, 1460, 1500, 1492, 1472}
        safe_sizes = [s for s in range(40, MTU + 1) if s not in vpn_sizes]

        for i in range(n_packets):
            # Sample size avoiding VPN patterns
            base_size = int(self.rng.choice(safe_sizes))

            # Add small random offset to further avoid detection
            offset = self.rng.integers(-5, 6)
            size = max(40, min(MTU, base_size + offset))

            if size in vpn_sizes:
                size = size + self.rng.choice([-1, 1, -2, 2])

            delay_ms = max(0.1, self.rng.lognormal(profile.delay_base_log, profile.delay_std))
            timestamp += delay_ms / 1000.0
            direction = 1 if self.rng.random() < profile.outbound_ratio else -1

            packets.append({
                "timestamp": timestamp,
                "size": size,
                "size_norm": size / MTU,
                "delay_log": np.log1p(delay_ms),
                "direction": float(direction),
                "burst_pos": (i % 10) / 10.0,
                "profile_id": profile.profile_id,
                "target_delay": 1.0,  # Low delay for this adversarial type
                "target_padding": 0.05,
                "target_inject": 0.02,
                "adversarial_type": "anti_size_pattern",
            })

        return packets

    def generate_anti_timing_pattern(self, profile: ProfileConfig, n_packets: int) -> List[Dict]:
        """Generate traffic with high timing variance to avoid timing detection."""
        packets = []
        timestamp = time.time()

        for i in range(n_packets):
            # High variance timing (avoid regular patterns)
            base_delay = self.rng.lognormal(profile.delay_base_log, profile.delay_std * 2)

            # Add random spike/dip
            if self.rng.random() < 0.2:
                base_delay *= self.rng.uniform(0.1, 5.0)

            delay_ms = max(0.1, base_delay)
            timestamp += delay_ms / 1000.0

            size = self._sample_profile_size(profile)
            direction = 1 if self.rng.random() < profile.outbound_ratio else -1

            packets.append({
                "timestamp": timestamp,
                "size": size,
                "size_norm": size / MTU,
                "delay_log": np.log1p(delay_ms),
                "direction": float(direction),
                "burst_pos": self.rng.random(),  # Random burst position
                "profile_id": profile.profile_id,
                "target_delay": 5.0,  # Higher delay OK for timing evasion
                "target_padding": 0.15,
                "target_inject": 0.1,
                "adversarial_type": "anti_timing_pattern",
            })

        return packets

    def generate_anti_direction_ratio(self, profile: ProfileConfig, n_packets: int) -> List[Dict]:
        """Generate traffic with asymmetric direction ratio (avoid 0.4-0.6 balance)."""
        packets = []
        timestamp = time.time()

        # Force asymmetric ratio (like real browsing: mostly inbound)
        target_ratio = self.rng.choice([0.15, 0.20, 0.25, 0.75, 0.80, 0.85])

        for i in range(n_packets):
            delay_ms = max(0.1, self.rng.lognormal(profile.delay_base_log, profile.delay_std))
            timestamp += delay_ms / 1000.0

            size = self._sample_profile_size(profile)
            direction = 1 if self.rng.random() < target_ratio else -1

            packets.append({
                "timestamp": timestamp,
                "size": size,
                "size_norm": size / MTU,
                "delay_log": np.log1p(delay_ms),
                "direction": float(direction),
                "burst_pos": (i % 10) / 10.0,
                "profile_id": profile.profile_id,
                "target_delay": 2.0,
                "target_padding": 0.1,
                "target_inject": 0.08,
                "adversarial_type": "anti_direction_ratio",
            })

        return packets

    def generate_anti_entropy(self, profile: ProfileConfig, n_packets: int) -> List[Dict]:
        """Generate traffic with medium entropy (avoid too low/high)."""
        packets = []
        timestamp = time.time()

        # Target entropy ~2.5 (medium - not suspicious)
        # Use 5-6 distinct size buckets
        bucket_sizes = self.rng.choice([200, 400, 600, 800, 1000, 1200, 1400], 6, replace=False)

        for i in range(n_packets):
            # Sample from buckets with noise
            base_size = int(self.rng.choice(bucket_sizes))
            size = max(40, min(MTU, base_size + self.rng.integers(-30, 31)))

            delay_ms = max(0.1, self.rng.lognormal(profile.delay_base_log, profile.delay_std))
            timestamp += delay_ms / 1000.0
            direction = 1 if self.rng.random() < profile.outbound_ratio else -1

            packets.append({
                "timestamp": timestamp,
                "size": size,
                "size_norm": size / MTU,
                "delay_log": np.log1p(delay_ms),
                "direction": float(direction),
                "burst_pos": (i % 8) / 8.0,
                "profile_id": profile.profile_id,
                "target_delay": 2.0,
                "target_padding": 0.12,
                "target_inject": 0.06,
                "adversarial_type": "anti_entropy",
            })

        return packets

    def _sample_profile_size(self, profile: ProfileConfig) -> int:
        """Sample size from profile distribution."""
        modes = profile.size_modes
        weights = np.array([m[2] for m in modes])
        weights = weights / weights.sum()
        mode_idx = self.rng.choice(len(modes), p=weights)
        mean, std, _ = modes[mode_idx]
        size = int(self.rng.normal(mean, std))
        return max(40, min(size, MTU))


def sample_size(
    profile: ProfileConfig,
    sub_profile: Optional[SubProfile],
    rng: np.random.Generator,
    direction: int
) -> int:
    """Sample packet size from multimodal distribution with sub-profile adjustments."""
    modes = profile.size_modes
    weights = np.array([m[2] for m in modes])

    # Adjust weights based on direction correlation
    if profile.size_direction_corr != 0:
        adjustment = profile.size_direction_corr * direction * 0.3
        weights = weights * (1 + adjustment * np.arange(len(weights)) / len(weights))
        weights = weights / weights.sum()

    # Pick mode
    mode_idx = rng.choice(len(modes), p=weights)
    mean, std, _ = modes[mode_idx]

    # Apply sub-profile scaling
    if sub_profile:
        mean = mean * sub_profile.size_scale + sub_profile.size_shift
        std = std * sub_profile.size_scale

    # Sample from mode
    size = int(rng.normal(mean, std))
    return max(40, min(size, MTU))


def select_sub_profile(profile: ProfileConfig, rng: np.random.Generator) -> Optional[SubProfile]:
    """Select a sub-profile based on weights."""
    if not profile.sub_profiles:
        return None

    weights = np.array([sp.weight for sp in profile.sub_profiles])
    weights = weights / weights.sum()
    idx = rng.choice(len(profile.sub_profiles), p=weights)
    return profile.sub_profiles[idx]


def generate_session(
    profile: ProfileConfig,
    num_packets: int,
    rng: np.random.Generator,
    session_seed: int,
    augmentor: Optional[DataAugmentor] = None,
    augmentation_prob: float = 0.3,
) -> List[Dict]:
    """Generate a realistic session with sub-profiles and optional augmentation."""
    packets = []
    timestamp = time.time() + session_seed * 1000

    # Select sub-profile for this session
    sub_profile = select_sub_profile(profile, rng)

    # Session phases
    warmup_end = profile.warmup_packets
    cooldown_start = num_packets - profile.cooldown_packets

    burst_remaining = 0
    burst_start_idx = 0

    # Get target values from sub-profile or use defaults
    target_delay = sub_profile.target_delay_ms if sub_profile else 2.0
    target_padding = sub_profile.target_padding_ratio if sub_profile else 0.1
    target_inject = sub_profile.target_inject_prob if sub_profile else 0.05

    for i in range(num_packets):
        # Phase-dependent behavior
        if i < warmup_end:
            delay_mult = 1.5
            size_mult = 0.7
        elif i >= cooldown_start:
            delay_mult = 2.0
            size_mult = 0.5
        else:
            delay_mult = 1.0
            size_mult = 1.0

        # Apply sub-profile delay scaling
        if sub_profile:
            delay_mult *= sub_profile.delay_scale

        # Burst structure
        if burst_remaining <= 0:
            burst_min, burst_max = profile.burst_size_range
            if sub_profile:
                burst_min = int(burst_min * sub_profile.burst_scale)
                burst_max = int(burst_max * sub_profile.burst_scale)
            burst_size = rng.integers(max(1, burst_min), max(2, burst_max))
            burst_remaining = burst_size
            burst_start_idx = i

            if i > 0:
                inter_burst = rng.uniform(*profile.inter_burst_ms)
                timestamp += inter_burst / 1000.0

        # Delay calculation
        delay_log = rng.normal(profile.delay_base_log, profile.delay_std) * delay_mult
        delay_log = max(0.001, delay_log)
        delay_ms = np.expm1(delay_log)

        if burst_remaining > 1:
            delay_ms = delay_ms * 0.3

        timestamp += delay_ms / 1000.0

        # Direction
        direction = 1 if rng.random() < profile.outbound_ratio else -1

        # Size
        size = int(sample_size(profile, sub_profile, rng, direction) * size_mult)
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
            "profile_id": profile.profile_id,
            "target_delay": target_delay,
            "target_padding": target_padding,
            "target_inject": target_inject,
            "sub_profile": sub_profile.name if sub_profile else profile.name,
        })

        burst_remaining -= 1

    # Apply augmentation
    if augmentor and rng.random() < augmentation_prob:
        aug_type = rng.choice([
            AugmentationType.NOISE,
            AugmentationType.TIME_WARP,
            AugmentationType.SIZE_JITTER,
        ])

        if aug_type == AugmentationType.NOISE:
            packets = augmentor.apply_noise(packets)
        elif aug_type == AugmentationType.TIME_WARP:
            packets = augmentor.apply_time_warp(packets)
        elif aug_type == AugmentationType.SIZE_JITTER:
            packets = augmentor.apply_size_jitter(packets)

    return packets


def generate_profile_data(
    profile: ProfileConfig,
    total_packets: int,
    num_sessions: int,
    base_seed: int,
    augmentation_prob: float = 0.3,
    adversarial_ratio: float = 0.15,
) -> pd.DataFrame:
    """Generate data for one profile with sub-profiles and adversarial examples."""
    packets_per_session = total_packets // num_sessions
    all_packets = []

    rng = np.random.default_rng(base_seed)
    augmentor = DataAugmentor(rng, intensity=0.3)
    adversarial_gen = DpiAdversarialGenerator(rng)

    # Regular sessions
    regular_sessions = int(num_sessions * (1 - adversarial_ratio))
    for session in range(regular_sessions):
        seed = base_seed + session * 1000
        session_rng = np.random.default_rng(seed)

        packets = generate_session(
            profile,
            packets_per_session,
            session_rng,
            session,
            augmentor,
            augmentation_prob,
        )
        all_packets.extend(packets)

    # Adversarial sessions (distributed across types)
    adversarial_sessions = num_sessions - regular_sessions
    adversarial_packets = packets_per_session

    adversarial_methods = [
        adversarial_gen.generate_anti_size_pattern,
        adversarial_gen.generate_anti_timing_pattern,
        adversarial_gen.generate_anti_direction_ratio,
        adversarial_gen.generate_anti_entropy,
    ]

    for i in range(adversarial_sessions):
        method = adversarial_methods[i % len(adversarial_methods)]
        packets = method(profile, adversarial_packets)
        all_packets.extend(packets)

    return pd.DataFrame(all_packets)


def main():
    parser = argparse.ArgumentParser(description="Generate flagship TMT-20M dataset")
    parser.add_argument("--packets-per-profile", type=int, default=1000000,
                        help="Packets per profile (default: 1M)")
    parser.add_argument("--sessions-per-profile", type=int, default=200,
                        help="Sessions per profile for diversity (default: 200)")
    parser.add_argument("--seed", type=int, default=42, help="Base random seed")
    parser.add_argument("--output-dir", type=str, default="data/flagship",
                        help="Output directory")
    parser.add_argument("--train-ratio", type=float, default=0.8)
    parser.add_argument("--val-ratio", type=float, default=0.1)
    parser.add_argument("--augmentation-prob", type=float, default=0.3,
                        help="Probability of applying augmentation")
    parser.add_argument("--adversarial-ratio", type=float, default=0.15,
                        help="Ratio of adversarial examples")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("FLAGSHIP Dataset Generator for TMT-20M")
    print("=" * 70)
    print(f"Packets per profile: {args.packets_per_profile:,}")
    print(f"Sessions per profile: {args.sessions_per_profile}")
    print(f"Total packets: {args.packets_per_profile * len(PROFILES):,}")
    print(f"Augmentation probability: {args.augmentation_prob:.0%}")
    print(f"Adversarial ratio: {args.adversarial_ratio:.0%}")
    print(f"Context size: {CONTEXT_SIZE}")
    print()

    all_dfs = []

    for i, (name, profile) in enumerate(PROFILES.items()):
        print(f"[{i+1}/{len(PROFILES)}] Generating {name}...")
        print(f"    Sub-profiles: {[sp.name for sp in profile.sub_profiles]}")

        df = generate_profile_data(
            profile,
            args.packets_per_profile,
            args.sessions_per_profile,
            args.seed + i * 100000,
            args.augmentation_prob,
            args.adversarial_ratio,
        )

        # Stats
        print(f"    Size: mean={df['size_norm'].mean():.3f}, std={df['size_norm'].std():.3f}")
        print(f"    Delay: mean={df['delay_log'].mean():.3f}, std={df['delay_log'].std():.3f}")
        outbound_ratio = (df['direction'] > 0).mean()
        print(f"    Direction: outbound={outbound_ratio:.1%}")

        # Sub-profile distribution
        if "sub_profile" in df.columns:
            sub_dist = df["sub_profile"].value_counts(normalize=True)
            print(f"    Sub-profiles: {dict(sub_dist.head(3))}")

        all_dfs.append(df)

    # Combine all profiles
    print("\nCombining datasets...")
    combined = pd.concat(all_dfs, ignore_index=True)

    # Shuffle
    combined = combined.sample(frac=1, random_state=args.seed).reset_index(drop=True)

    # Remove sub_profile column (not needed for training)
    if "sub_profile" in combined.columns:
        combined = combined.drop(columns=["sub_profile"])
    if "adversarial_type" in combined.columns:
        combined = combined.drop(columns=["adversarial_type"])

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

    print("\n" + "=" * 70)
    print("FLAGSHIP Dataset saved to:", output_dir)
    print("=" * 70)
    print(f"  train.parquet: {len(train_df):,} samples ({len(train_df)/n:.1%})")
    print(f"  val.parquet:   {len(val_df):,} samples ({len(val_df)/n:.1%})")
    print(f"  test.parquet:  {len(test_df):,} samples ({len(test_df)/n:.1%})")

    # Profile distribution
    print("\nProfile distribution:")
    for name, profile in PROFILES.items():
        count = (combined['profile_id'] == profile.profile_id).sum()
        print(f"  {name}: {count:,} ({count/n:.1%})")

    # Overall stats
    print("\nOverall statistics:")
    print(f"  Size (norm): mean={combined['size_norm'].mean():.3f}, std={combined['size_norm'].std():.3f}")
    print(f"  Delay (log): mean={combined['delay_log'].mean():.3f}, std={combined['delay_log'].std():.3f}")
    print(f"  Burst pos:   mean={combined['burst_pos'].mean():.3f}")

    # File sizes
    train_size = (output_dir / "train.parquet").stat().st_size / 1024 / 1024
    val_size = (output_dir / "val.parquet").stat().st_size / 1024 / 1024
    test_size = (output_dir / "test.parquet").stat().st_size / 1024 / 1024
    print(f"\nFile sizes:")
    print(f"  train.parquet: {train_size:.1f} MB")
    print(f"  val.parquet:   {val_size:.1f} MB")
    print(f"  test.parquet:  {test_size:.1f} MB")

    print("\n" + "=" * 70)
    print("DONE! Ready for training with:")
    print(f"  python train_flagship.py --config config/tmt_20m_flagship.yaml")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    exit(main())
