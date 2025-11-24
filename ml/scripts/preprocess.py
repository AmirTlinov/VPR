#!/usr/bin/env python3
"""
Data Preprocessing Pipeline for TMT-20M Training.

Combines traffic data from multiple profiles into unified training dataset
with proper balancing and validation.

Usage:
    python preprocess.py --input-dir data/raw --output-dir data/processed

Features:
- Profile balancing (equal representation)
- Train/val/test splitting with stratification
- Data validation and quality checks
- Statistics reporting
"""

import argparse
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from collections import Counter


# Profile definitions
PROFILES = ["youtube", "zoom", "gaming", "browsing", "netflix"]
PROFILE_IDS = {name: idx for idx, name in enumerate(PROFILES)}


def load_profile_data(input_dir: Path) -> Dict[str, pd.DataFrame]:
    """Load all profile datasets from directory.

    Args:
        input_dir: Directory containing *_raw.parquet files

    Returns:
        Dictionary mapping profile name to DataFrame
    """
    datasets = {}

    for profile in PROFILES:
        path = input_dir / f"{profile}_raw.parquet"
        if path.exists():
            df = pd.read_parquet(path)
            datasets[profile] = df
            print(f"Loaded {profile}: {len(df)} samples")
        else:
            print(f"Warning: Missing {path}")

    return datasets


def validate_dataset(df: pd.DataFrame, name: str) -> bool:
    """Validate dataset quality.

    Args:
        df: DataFrame to validate
        name: Dataset name for logging

    Returns:
        True if valid
    """
    issues = []

    # Check required columns
    required = ["size_norm", "delay_log", "direction", "burst_pos", "profile_id"]
    missing = [col for col in required if col not in df.columns]
    if missing:
        issues.append(f"Missing columns: {missing}")

    # Check for NaN values
    nan_counts = df[required].isna().sum()
    if nan_counts.any():
        issues.append(f"NaN values: {nan_counts[nan_counts > 0].to_dict()}")

    # Check value ranges
    if df["size_norm"].min() < 0 or df["size_norm"].max() > 1.5:
        issues.append(f"size_norm out of range: [{df['size_norm'].min():.3f}, {df['size_norm'].max():.3f}]")

    if df["delay_log"].min() < -1:
        issues.append(f"delay_log negative: min={df['delay_log'].min():.3f}")

    if not df["direction"].isin([-1.0, 1.0]).all():
        unique_dirs = df["direction"].unique()
        issues.append(f"Invalid direction values: {unique_dirs}")

    if df["burst_pos"].min() < 0 or df["burst_pos"].max() > 1.0:
        issues.append(f"burst_pos out of range: [{df['burst_pos'].min():.3f}, {df['burst_pos'].max():.3f}]")

    if issues:
        print(f"\n{name} validation FAILED:")
        for issue in issues:
            print(f"  - {issue}")
        return False

    print(f"{name} validation PASSED")
    return True


def balance_profiles(
    datasets: Dict[str, pd.DataFrame],
    target_samples: int | None = None,
    seed: int = 42,
) -> pd.DataFrame:
    """Balance samples across profiles.

    Args:
        datasets: Dictionary of profile DataFrames
        target_samples: Target samples per profile (None = min across profiles)
        seed: Random seed

    Returns:
        Balanced DataFrame with all profiles
    """
    np.random.seed(seed)

    if not datasets:
        raise ValueError("No datasets provided")

    # Determine target sample count
    counts = {name: len(df) for name, df in datasets.items()}
    min_count = min(counts.values())

    if target_samples is None:
        target_samples = min_count
    else:
        target_samples = min(target_samples, min_count)

    print(f"\nBalancing to {target_samples} samples per profile")
    print(f"Original counts: {counts}")

    # Sample from each profile
    balanced_dfs = []
    for profile, df in datasets.items():
        if len(df) > target_samples:
            # Undersample
            indices = np.random.choice(len(df), target_samples, replace=False)
            sampled = df.iloc[indices].copy()
        else:
            sampled = df.copy()

        balanced_dfs.append(sampled)

    combined = pd.concat(balanced_dfs, ignore_index=True)
    print(f"Combined dataset: {len(combined)} samples")

    return combined


def stratified_split(
    df: pd.DataFrame,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split dataset maintaining profile distribution.

    Args:
        df: Full dataset
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
        seed: Random seed

    Returns:
        Tuple of (train_df, val_df, test_df)
    """
    np.random.seed(seed)

    train_dfs, val_dfs, test_dfs = [], [], []

    # Split each profile separately to maintain distribution
    for profile_id in df["profile_id"].unique():
        profile_df = df[df["profile_id"] == profile_id]
        n = len(profile_df)

        indices = np.random.permutation(n)
        train_end = int(n * train_ratio)
        val_end = int(n * (train_ratio + val_ratio))

        train_dfs.append(profile_df.iloc[indices[:train_end]])
        val_dfs.append(profile_df.iloc[indices[train_end:val_end]])
        test_dfs.append(profile_df.iloc[indices[val_end:]])

    train_df = pd.concat(train_dfs, ignore_index=True)
    val_df = pd.concat(val_dfs, ignore_index=True)
    test_df = pd.concat(test_dfs, ignore_index=True)

    # Shuffle within each split
    train_df = train_df.sample(frac=1, random_state=seed).reset_index(drop=True)
    val_df = val_df.sample(frac=1, random_state=seed).reset_index(drop=True)
    test_df = test_df.sample(frac=1, random_state=seed).reset_index(drop=True)

    return train_df, val_df, test_df


def compute_statistics(df: pd.DataFrame) -> Dict:
    """Compute dataset statistics for reporting.

    Args:
        df: Dataset

    Returns:
        Dictionary of statistics
    """
    stats = {
        "total_samples": len(df),
        "profile_distribution": df["profile_id"].value_counts().to_dict(),
        "features": {},
    }

    for col in ["size_norm", "delay_log", "direction", "burst_pos"]:
        stats["features"][col] = {
            "mean": df[col].mean(),
            "std": df[col].std(),
            "min": df[col].min(),
            "max": df[col].max(),
        }

    return stats


def print_statistics(stats: Dict, name: str) -> None:
    """Pretty print dataset statistics.

    Args:
        stats: Statistics dictionary
        name: Dataset name
    """
    print(f"\n{'=' * 50}")
    print(f"{name} Statistics")
    print(f"{'=' * 50}")
    print(f"Total samples: {stats['total_samples']}")
    print(f"\nProfile distribution:")
    for pid, count in sorted(stats["profile_distribution"].items()):
        profile_name = PROFILES[pid]
        print(f"  {profile_name}: {count} ({count/stats['total_samples']*100:.1f}%)")

    print(f"\nFeature statistics:")
    for feat, fstats in stats["features"].items():
        print(f"  {feat}:")
        print(f"    mean: {fstats['mean']:.4f}, std: {fstats['std']:.4f}")
        print(f"    range: [{fstats['min']:.4f}, {fstats['max']:.4f}]")


def main():
    parser = argparse.ArgumentParser(description="Preprocess TMT-20M training data")
    parser.add_argument(
        "--input-dir",
        type=str,
        default="data/raw",
        help="Directory with raw parquet files",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data",
        help="Output directory for processed data",
    )
    parser.add_argument(
        "--target-samples",
        type=int,
        default=None,
        help="Target samples per profile (default: min across profiles)",
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Training set ratio",
    )
    parser.add_argument(
        "--val-ratio",
        type=float,
        default=0.1,
        help="Validation set ratio",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate existing processed data",
    )
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.validate_only:
        # Validate existing processed data
        print("Validating processed data...")

        for split in ["train", "val", "test"]:
            path = output_dir / f"{split}.parquet"
            if path.exists():
                df = pd.read_parquet(path)
                validate_dataset(df, f"{split}.parquet")
                stats = compute_statistics(df)
                print_statistics(stats, f"{split}")
            else:
                print(f"Missing: {path}")

        return 0

    # Load raw data
    print(f"Loading data from {input_dir}")
    datasets = load_profile_data(input_dir)

    if not datasets:
        print("Error: No datasets found!")
        return 1

    # Validate raw data
    print("\nValidating raw datasets...")
    all_valid = True
    for profile, df in datasets.items():
        if not validate_dataset(df, profile):
            all_valid = False

    if not all_valid:
        print("\nWarning: Some datasets have validation issues")
        # Continue anyway for now

    # Balance profiles
    combined = balance_profiles(datasets, args.target_samples, args.seed)

    # Split data
    train_df, val_df, test_df = stratified_split(
        combined, args.train_ratio, args.val_ratio, args.seed
    )

    # Save
    train_df.to_parquet(output_dir / "train.parquet", index=False)
    val_df.to_parquet(output_dir / "val.parquet", index=False)
    test_df.to_parquet(output_dir / "test.parquet", index=False)

    print(f"\nSaved to {output_dir}/")

    # Print statistics
    for name, df in [("Train", train_df), ("Val", val_df), ("Test", test_df)]:
        stats = compute_statistics(df)
        print_statistics(stats, name)

    # Final validation
    print("\n" + "=" * 50)
    print("PREPROCESSING COMPLETE")
    print("=" * 50)
    print(f"Train: {len(train_df)} samples")
    print(f"Val: {len(val_df)} samples")
    print(f"Test: {len(test_df)} samples")

    return 0


if __name__ == "__main__":
    exit(main())
