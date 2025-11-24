#!/usr/bin/env python3
"""
Traffic Data Collection Pipeline for TMT-20M Training.

Captures real network traffic and extracts features for training
the Traffic Morphing Transformer model.

Usage:
    # Capture YouTube traffic for 60 seconds
    sudo python collect_data.py --interface eth0 --profile youtube --duration 60

    # Capture from pcap file
    python collect_data.py --pcap captures/zoom_call.pcap --profile zoom

Features extracted per packet:
    - size_norm: Normalized packet size (0-1, relative to MTU)
    - delay_log: Log-transformed inter-packet delay
    - direction: 1.0 for outbound, -1.0 for inbound
    - burst_pos: Position within current burst (0-1)

Output: Parquet files with labeled training data
"""

import argparse
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, List, Optional, Tuple

import numpy as np
import pandas as pd

# Scapy is only needed for live capture and pcap reading, not synthetic data
SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, UDP, PcapReader, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    pass


# Constants
MTU = 1500
MAX_DELAY_MS = 10000  # Cap delays at 10 seconds
BURST_GAP_MS = 50  # Packets within 50ms considered same burst


@dataclass
class PacketFeatures:
    """Extracted features from a single packet."""

    timestamp: float
    size: int
    direction: int  # 1 = outbound, -1 = inbound
    protocol: str  # "tcp" or "udp"
    src_port: int
    dst_port: int

    # Derived features (computed after collection)
    size_norm: float = 0.0
    delay_log: float = 0.0
    burst_pos: float = 0.0


@dataclass
class ProfileTargets:
    """Target morphing values for a traffic profile."""

    target_delay: float  # Target delay adjustment (ms)
    target_padding: float  # Target padding (normalized)
    target_inject: float  # Cover traffic injection probability


# Profile-specific target generators
PROFILE_TARGETS = {
    "youtube": ProfileTargets(target_delay=2.0, target_padding=0.1, target_inject=0.05),
    "zoom": ProfileTargets(target_delay=1.0, target_padding=0.15, target_inject=0.1),
    "gaming": ProfileTargets(target_delay=0.5, target_padding=0.05, target_inject=0.02),
    "browsing": ProfileTargets(target_delay=5.0, target_padding=0.2, target_inject=0.15),
    "netflix": ProfileTargets(target_delay=3.0, target_padding=0.12, target_inject=0.08),
}

PROFILE_IDS = {
    "youtube": 0,
    "zoom": 1,
    "gaming": 2,
    "browsing": 3,
    "netflix": 4,
}


def extract_packet_features(
    packet,
    local_ips: set,
    prev_timestamp: Optional[float] = None,
) -> Optional[PacketFeatures]:
    """Extract features from a scapy packet.

    Args:
        packet: Scapy packet object
        local_ips: Set of local IP addresses (for direction detection)
        prev_timestamp: Previous packet timestamp (for delay calculation)

    Returns:
        PacketFeatures or None if packet should be skipped
    """
    if IP not in packet:
        return None

    ip_layer = packet[IP]

    # Determine direction
    is_outbound = ip_layer.src in local_ips
    direction = 1 if is_outbound else -1

    # Get transport layer info
    if TCP in packet:
        transport = packet[TCP]
        protocol = "tcp"
    elif UDP in packet:
        transport = packet[UDP]
        protocol = "udp"
    else:
        return None

    # Extract basic features
    size = len(packet)
    timestamp = float(packet.time)

    return PacketFeatures(
        timestamp=timestamp,
        size=size,
        direction=direction,
        protocol=protocol,
        src_port=transport.sport,
        dst_port=transport.dport,
    )


def compute_derived_features(packets: List[PacketFeatures]) -> List[PacketFeatures]:
    """Compute derived features (delay, burst position, normalization).

    Args:
        packets: List of packet features with basic info

    Returns:
        Same list with derived features computed
    """
    if not packets:
        return packets

    # Compute delays
    prev_ts = packets[0].timestamp
    for pkt in packets:
        delay_ms = (pkt.timestamp - prev_ts) * 1000
        delay_ms = min(delay_ms, MAX_DELAY_MS)  # Cap at max
        delay_ms = max(delay_ms, 0.001)  # Min 1 microsecond
        pkt.delay_log = np.log1p(delay_ms)  # log(1 + delay) for stability
        prev_ts = pkt.timestamp

    # Compute burst positions
    burst_start_idx = 0
    for i, pkt in enumerate(packets):
        if i > 0:
            delay_ms = (pkt.timestamp - packets[i - 1].timestamp) * 1000
            if delay_ms > BURST_GAP_MS:
                # New burst started
                burst_start_idx = i

        burst_len = i - burst_start_idx + 1
        # Normalize position within burst (max burst size assumed 32)
        pkt.burst_pos = min(burst_len / 32.0, 1.0)

    # Normalize sizes
    for pkt in packets:
        pkt.size_norm = min(pkt.size / MTU, 1.0)

    return packets


def collect_live_traffic(
    interface: str,
    duration: int,
    local_ips: set,
    filter_expr: str = "ip",
) -> List[PacketFeatures]:
    """Capture live traffic from network interface.

    Args:
        interface: Network interface name (e.g., "eth0")
        duration: Capture duration in seconds
        local_ips: Set of local IP addresses
        filter_expr: BPF filter expression

    Returns:
        List of extracted packet features
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy is required for live capture. Install with: pip install scapy")

    print(f"Capturing on {interface} for {duration}s...")
    print(f"Filter: {filter_expr}")
    print(f"Local IPs: {local_ips}")

    packets = []

    def process_packet(pkt):
        features = extract_packet_features(pkt, local_ips)
        if features:
            packets.append(features)

    # Capture with timeout
    sniff(
        iface=interface,
        filter=filter_expr,
        prn=process_packet,
        timeout=duration,
        store=False,
    )

    print(f"Captured {len(packets)} packets")
    return compute_derived_features(packets)


def load_pcap_traffic(
    pcap_path: str,
    local_ips: set,
) -> List[PacketFeatures]:
    """Load traffic from pcap file.

    Args:
        pcap_path: Path to pcap file
        local_ips: Set of local IP addresses

    Returns:
        List of extracted packet features
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("scapy is required for pcap loading. Install with: pip install scapy")

    print(f"Loading pcap: {pcap_path}")

    packets = []

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            features = extract_packet_features(pkt, local_ips)
            if features:
                packets.append(features)

    print(f"Loaded {len(packets)} packets")
    return compute_derived_features(packets)


def create_training_samples(
    packets: List[PacketFeatures],
    profile: str,
    context_size: int = 16,
) -> pd.DataFrame:
    """Create training samples from packet sequence.

    Each sample is a sliding window of context_size packets with
    labels for the target profile.

    Args:
        packets: List of packet features
        profile: Traffic profile name
        context_size: Number of packets per sample

    Returns:
        DataFrame with training samples
    """
    if len(packets) < context_size:
        print(f"Warning: Only {len(packets)} packets, need {context_size}")
        return pd.DataFrame()

    profile_id = PROFILE_IDS[profile]
    targets = PROFILE_TARGETS[profile]

    # Create samples
    samples = []
    for i in range(len(packets) - context_size + 1):
        window = packets[i:i + context_size]

        # Use last packet in window as the "current" packet
        current = window[-1]

        samples.append({
            # Features
            "size_norm": current.size_norm,
            "delay_log": current.delay_log,
            "direction": float(current.direction),
            "burst_pos": current.burst_pos,
            # Labels
            "profile_id": profile_id,
            "target_delay": targets.target_delay,
            "target_padding": targets.target_padding,
            "target_inject": targets.target_inject,
            # Metadata
            "timestamp": current.timestamp,
            "raw_size": current.size,
            "protocol": current.protocol,
        })

    df = pd.DataFrame(samples)
    print(f"Created {len(df)} training samples")
    return df


def generate_synthetic_traffic(
    profile: str,
    num_packets: int = 10000,
    seed: int = 42,
) -> List[PacketFeatures]:
    """Generate synthetic traffic matching profile statistics.

    Used for data augmentation when real captures are limited.

    Args:
        profile: Traffic profile name
        num_packets: Number of packets to generate
        seed: Random seed for reproducibility

    Returns:
        List of synthetic packet features
    """
    np.random.seed(seed)

    # Profile statistics (from tmt_20m.yaml)
    STATS = {
        "youtube": {
            "mean_size": 1100, "size_std": 400,
            "mean_delay_log": 2.5, "delay_std": 1.5,
            "outbound_ratio": 0.15,
        },
        "zoom": {
            "mean_size": 800, "size_std": 300,
            "mean_delay_log": 2.0, "delay_std": 0.8,
            "outbound_ratio": 0.45,
        },
        "gaming": {
            "mean_size": 150, "size_std": 80,
            "mean_delay_log": 1.5, "delay_std": 0.5,
            "outbound_ratio": 0.50,
        },
        "browsing": {
            "mean_size": 600, "size_std": 500,
            "mean_delay_log": 3.5, "delay_std": 2.0,
            "outbound_ratio": 0.25,
        },
        "netflix": {
            "mean_size": 1200, "size_std": 350,
            "mean_delay_log": 2.3, "delay_std": 1.2,
            "outbound_ratio": 0.10,
        },
    }

    stats = STATS[profile]
    packets = []

    timestamp = time.time()
    burst_count = 0
    in_burst = False

    for i in range(num_packets):
        # Generate delay
        delay_log = np.random.normal(stats["mean_delay_log"], stats["delay_std"])
        delay_log = max(0.001, delay_log)
        delay_ms = np.expm1(delay_log)
        timestamp += delay_ms / 1000.0

        # Generate size
        size = int(np.random.normal(stats["mean_size"], stats["size_std"]))
        size = max(40, min(size, MTU))  # Clamp to valid range

        # Generate direction
        direction = 1 if np.random.random() < stats["outbound_ratio"] else -1

        # Burst detection
        if delay_ms < BURST_GAP_MS:
            if not in_burst:
                in_burst = True
                burst_count = 0
            burst_count += 1
        else:
            in_burst = False
            burst_count = 0

        pkt = PacketFeatures(
            timestamp=timestamp,
            size=size,
            direction=direction,
            protocol="udp" if profile in ["zoom", "gaming"] else "tcp",
            src_port=12345 if direction == 1 else 443,
            dst_port=443 if direction == 1 else 12345,
            size_norm=size / MTU,
            delay_log=delay_log,
            burst_pos=min(burst_count / 32.0, 1.0),
        )
        packets.append(pkt)

    print(f"Generated {len(packets)} synthetic {profile} packets")
    return packets


def split_dataset(
    df: pd.DataFrame,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split dataset into train/val/test sets.

    Args:
        df: Full dataset
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
        seed: Random seed

    Returns:
        Tuple of (train_df, val_df, test_df)
    """
    np.random.seed(seed)

    n = len(df)
    indices = np.random.permutation(n)

    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))

    train_idx = indices[:train_end]
    val_idx = indices[train_end:val_end]
    test_idx = indices[val_end:]

    return df.iloc[train_idx], df.iloc[val_idx], df.iloc[test_idx]


def main():
    parser = argparse.ArgumentParser(description="Collect traffic data for TMT-20M")

    # Input source (mutually exclusive)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", type=str, help="Network interface for live capture")
    source.add_argument("--pcap", type=str, help="Path to pcap file")
    source.add_argument("--synthetic", action="store_true", help="Generate synthetic data")

    # Common options
    parser.add_argument(
        "--profile",
        type=str,
        required=True,
        choices=list(PROFILE_IDS.keys()),
        help="Traffic profile label",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data",
        help="Output directory for parquet files",
    )
    parser.add_argument(
        "--context-size",
        type=int,
        default=16,
        help="Context window size",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )

    # Live capture options
    parser.add_argument("--duration", type=int, default=60, help="Capture duration (seconds)")
    parser.add_argument("--filter", type=str, default="ip", help="BPF filter expression")
    parser.add_argument(
        "--local-ip",
        type=str,
        action="append",
        default=[],
        help="Local IP address (can specify multiple)",
    )

    # Synthetic options
    parser.add_argument("--num-packets", type=int, default=100000, help="Synthetic packet count")

    # Split options
    parser.add_argument("--split", action="store_true", help="Split into train/val/test")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Training set ratio")
    parser.add_argument("--val-ratio", type=float, default=0.1, help="Validation set ratio")

    args = parser.parse_args()

    # Setup
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collect packets
    if args.interface:
        local_ips = set(args.local_ip) if args.local_ip else {"192.168.1.1"}
        packets = collect_live_traffic(
            args.interface,
            args.duration,
            local_ips,
            args.filter,
        )
    elif args.pcap:
        local_ips = set(args.local_ip) if args.local_ip else {"192.168.1.1"}
        packets = load_pcap_traffic(args.pcap, local_ips)
    else:
        packets = generate_synthetic_traffic(
            args.profile,
            args.num_packets,
            args.seed,
        )

    if not packets:
        print("Error: No packets collected!")
        return 1

    # Create training samples
    df = create_training_samples(packets, args.profile, args.context_size)

    if df.empty:
        print("Error: No training samples created!")
        return 1

    # Save
    if args.split:
        train_df, val_df, test_df = split_dataset(
            df, args.train_ratio, args.val_ratio, args.seed
        )

        train_df.to_parquet(output_dir / "train.parquet", index=False)
        val_df.to_parquet(output_dir / "val.parquet", index=False)
        test_df.to_parquet(output_dir / "test.parquet", index=False)

        print(f"\nSaved to {output_dir}/:")
        print(f"  train.parquet: {len(train_df)} samples")
        print(f"  val.parquet: {len(val_df)} samples")
        print(f"  test.parquet: {len(test_df)} samples")
    else:
        output_path = output_dir / f"{args.profile}_raw.parquet"
        df.to_parquet(output_path, index=False)
        print(f"\nSaved {len(df)} samples to {output_path}")

    # Statistics
    print(f"\nDataset statistics:")
    print(f"  Size (norm): mean={df['size_norm'].mean():.3f}, std={df['size_norm'].std():.3f}")
    print(f"  Delay (log): mean={df['delay_log'].mean():.3f}, std={df['delay_log'].std():.3f}")
    print(f"  Direction: outbound={df['direction'].mean():.2%}")
    print(f"  Burst pos: mean={df['burst_pos'].mean():.3f}")

    return 0


if __name__ == "__main__":
    exit(main())
