#!/usr/bin/env python3
"""
Dataset Quality Auditor for Flagship TMT-20M Training Data.

Checks:
1. Data integrity and completeness
2. Feature distributions per profile
3. Sub-profile diversity
4. Adversarial examples presence
5. DPI evasion potential (pre-training estimation)
6. Statistical properties matching real traffic patterns
"""

import argparse
from pathlib import Path
from typing import Dict, List, Tuple
import sys

import numpy as np
import pandas as pd


class DatasetAuditor:
    """Audits dataset quality for flagship training."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.issues: List[str] = []
        self.warnings: List[str] = []
        self.stats: Dict = {}

    def load_data(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Load train, val, test datasets."""
        train = pd.read_parquet(self.data_dir / "train.parquet")
        val = pd.read_parquet(self.data_dir / "val.parquet")
        test = pd.read_parquet(self.data_dir / "test.parquet")
        return train, val, test

    def check_completeness(self, df: pd.DataFrame, name: str) -> bool:
        """Check for missing values and required columns."""
        required_cols = [
            "size_norm", "delay_log", "direction", "burst_pos",
            "profile_id", "target_delay", "target_padding", "target_inject"
        ]

        missing_cols = [c for c in required_cols if c not in df.columns]
        if missing_cols:
            self.issues.append(f"[{name}] Missing columns: {missing_cols}")
            return False

        # Check for NaN values
        nan_counts = df[required_cols].isna().sum()
        if nan_counts.any():
            self.issues.append(f"[{name}] NaN values found: {dict(nan_counts[nan_counts > 0])}")
            return False

        # Check for inf values
        numeric_cols = ["size_norm", "delay_log", "burst_pos", "target_delay", "target_padding"]
        for col in numeric_cols:
            if np.isinf(df[col]).any():
                self.issues.append(f"[{name}] Inf values in {col}")
                return False

        return True

    def check_value_ranges(self, df: pd.DataFrame, name: str) -> bool:
        """Check that values are in expected ranges."""
        ok = True

        # Size normalized should be 0-1
        if df["size_norm"].min() < 0 or df["size_norm"].max() > 1.1:
            self.issues.append(f"[{name}] size_norm out of range: [{df['size_norm'].min():.3f}, {df['size_norm'].max():.3f}]")
            ok = False

        # Direction should be -1 or 1
        unique_dirs = df["direction"].unique()
        if not set(unique_dirs).issubset({-1.0, 1.0}):
            self.issues.append(f"[{name}] Invalid direction values: {unique_dirs}")
            ok = False

        # Profile IDs should be 0-4
        if df["profile_id"].min() < 0 or df["profile_id"].max() > 4:
            self.issues.append(f"[{name}] Invalid profile_id range: [{df['profile_id'].min()}, {df['profile_id'].max()}]")
            ok = False

        # Burst position should be 0-1
        if df["burst_pos"].min() < 0 or df["burst_pos"].max() > 1.1:
            self.warnings.append(f"[{name}] burst_pos slightly out of range: [{df['burst_pos'].min():.3f}, {df['burst_pos'].max():.3f}]")

        return ok

    def check_profile_balance(self, df: pd.DataFrame, name: str) -> bool:
        """Check that profiles are balanced."""
        profile_counts = df["profile_id"].value_counts(normalize=True)

        # Each profile should have ~20% (+/- 5%)
        for pid, ratio in profile_counts.items():
            if ratio < 0.15 or ratio > 0.25:
                self.warnings.append(f"[{name}] Profile {pid} imbalanced: {ratio:.1%}")

        return True

    def check_feature_distributions(self, df: pd.DataFrame, name: str) -> Dict:
        """Analyze feature distributions per profile."""
        profile_stats = {}
        profile_names = ["youtube", "zoom", "gaming", "browsing", "netflix"]

        for pid in range(5):
            mask = df["profile_id"] == pid
            subset = df[mask]

            if len(subset) == 0:
                self.issues.append(f"[{name}] No samples for profile {pid}")
                continue

            stats = {
                "count": len(subset),
                "size_mean": subset["size_norm"].mean(),
                "size_std": subset["size_norm"].std(),
                "delay_mean": subset["delay_log"].mean(),
                "delay_std": subset["delay_log"].std(),
                "outbound_ratio": (subset["direction"] > 0).mean(),
                "target_delay_mean": subset["target_delay"].mean(),
                "target_padding_mean": subset["target_padding"].mean(),
            }
            profile_stats[profile_names[pid]] = stats

        return profile_stats

    def check_realistic_patterns(self, profile_stats: Dict) -> bool:
        """Check if distributions match expected real traffic patterns."""
        expected = {
            "youtube": {"outbound_ratio": (0.10, 0.20), "size_mean": (0.4, 0.8)},
            "zoom": {"outbound_ratio": (0.40, 0.55), "size_mean": (0.3, 0.6)},
            "gaming": {"outbound_ratio": (0.45, 0.58), "size_mean": (0.05, 0.25)},
            "browsing": {"outbound_ratio": (0.18, 0.35), "size_mean": (0.3, 0.6)},
            "netflix": {"outbound_ratio": (0.05, 0.18), "size_mean": (0.5, 0.9)},
        }

        ok = True
        for profile, checks in expected.items():
            if profile not in profile_stats:
                continue

            stats = profile_stats[profile]

            for metric, (low, high) in checks.items():
                value = stats[metric]
                if value < low or value > high:
                    self.warnings.append(
                        f"[{profile}] {metric}={value:.3f} outside expected range [{low}, {high}]"
                    )
                    ok = False

        return ok

    def check_dpi_evasion_potential(self, df: pd.DataFrame) -> Dict:
        """Estimate DPI evasion potential before training."""
        # Check for VPN-detectable patterns in raw data

        # 1. Size pattern analysis
        vpn_sizes = {64, 128, 256, 512, 1024, 1280, 1400, 1420, 1440, 1460, 1500, 1492, 1472}
        raw_sizes = (df["size_norm"] * 1500).astype(int)
        vpn_size_ratio = raw_sizes.isin(vpn_sizes).mean()

        # 2. Direction balance analysis (VPN often has 0.4-0.6 ratio)
        direction_ratio = (df["direction"] > 0).mean()
        balanced_traffic = 0.4 <= direction_ratio <= 0.6

        # 3. Size entropy (VPN has lower entropy)
        size_buckets = (df["size_norm"] * 15).astype(int).clip(0, 15)
        size_entropy = self._calculate_entropy(size_buckets)

        # 4. Delay regularity (VPN has more regular timing)
        delay_std = df["delay_log"].std()

        # Scoring
        evasion_score = 100
        issues = []

        if vpn_size_ratio > 0.3:
            evasion_score -= 20
            issues.append(f"High VPN-like size ratio: {vpn_size_ratio:.1%}")

        if balanced_traffic:
            evasion_score -= 15
            issues.append(f"Balanced direction ratio (VPN-like): {direction_ratio:.2f}")

        if size_entropy < 2.0:
            evasion_score -= 15
            issues.append(f"Low size entropy: {size_entropy:.2f}")

        if delay_std < 0.5:
            evasion_score -= 10
            issues.append(f"Low delay variance (regular timing): {delay_std:.2f}")

        return {
            "score": evasion_score,
            "vpn_size_ratio": vpn_size_ratio,
            "direction_ratio": direction_ratio,
            "size_entropy": size_entropy,
            "delay_std": delay_std,
            "issues": issues,
        }

    def _calculate_entropy(self, series: pd.Series) -> float:
        """Calculate Shannon entropy of a series."""
        counts = series.value_counts(normalize=True)
        return -np.sum(counts * np.log2(counts + 1e-10))

    def check_adversarial_diversity(self, df: pd.DataFrame) -> Dict:
        """Check diversity of training examples for DPI evasion."""
        # Size diversity
        size_unique = df["size_norm"].nunique()

        # Delay diversity
        delay_unique = df["delay_log"].round(2).nunique()

        # Per-profile diversity
        profile_diversity = {}
        for pid in range(5):
            subset = df[df["profile_id"] == pid]
            profile_diversity[pid] = {
                "size_unique": subset["size_norm"].nunique(),
                "delay_unique": subset["delay_log"].round(2).nunique(),
            }

        return {
            "total_size_unique": size_unique,
            "total_delay_unique": delay_unique,
            "profile_diversity": profile_diversity,
        }

    def run_audit(self) -> Dict:
        """Run complete audit and return results."""
        print("=" * 70)
        print("FLAGSHIP DATASET QUALITY AUDIT")
        print("=" * 70)
        print(f"Data directory: {self.data_dir}")
        print()

        # Load data
        print("Loading datasets...")
        try:
            train, val, test = self.load_data()
        except Exception as e:
            self.issues.append(f"Failed to load data: {e}")
            return self._generate_report()

        print(f"  Train: {len(train):,} samples")
        print(f"  Val:   {len(val):,} samples")
        print(f"  Test:  {len(test):,} samples")
        print()

        # 1. Completeness checks
        print("Checking data completeness...")
        for df, name in [(train, "train"), (val, "val"), (test, "test")]:
            self.check_completeness(df, name)
        print(f"  Issues: {len([i for i in self.issues if 'completeness' in i.lower()])}")

        # 2. Value range checks
        print("Checking value ranges...")
        for df, name in [(train, "train"), (val, "val"), (test, "test")]:
            self.check_value_ranges(df, name)

        # 3. Profile balance
        print("Checking profile balance...")
        self.check_profile_balance(train, "train")

        # 4. Feature distributions
        print("Analyzing feature distributions...")
        profile_stats = self.check_feature_distributions(train, "train")
        self.stats["profile_stats"] = profile_stats

        # 5. Realistic patterns
        print("Checking realistic traffic patterns...")
        self.check_realistic_patterns(profile_stats)

        # 6. DPI evasion potential
        print("Estimating DPI evasion potential...")
        dpi_analysis = self.check_dpi_evasion_potential(train)
        self.stats["dpi_analysis"] = dpi_analysis

        # 7. Adversarial diversity
        print("Checking adversarial diversity...")
        diversity = self.check_adversarial_diversity(train)
        self.stats["diversity"] = diversity

        return self._generate_report()

    def _generate_report(self) -> Dict:
        """Generate final audit report."""
        print()
        print("=" * 70)
        print("AUDIT RESULTS")
        print("=" * 70)

        # Issues
        if self.issues:
            print(f"\n ISSUES ({len(self.issues)}):")
            for issue in self.issues:
                print(f"  - {issue}")
        else:
            print("\n ISSUES: None")

        # Warnings
        if self.warnings:
            print(f"\n WARNINGS ({len(self.warnings)}):")
            for warn in self.warnings:
                print(f"  - {warn}")
        else:
            print("\n WARNINGS: None")

        # Profile statistics
        if "profile_stats" in self.stats:
            print("\n PROFILE STATISTICS:")
            for profile, stats in self.stats["profile_stats"].items():
                print(f"\n  {profile.upper()}:")
                print(f"    Samples:       {stats['count']:,}")
                print(f"    Size mean/std: {stats['size_mean']:.3f} / {stats['size_std']:.3f}")
                print(f"    Delay mean/std:{stats['delay_mean']:.3f} / {stats['delay_std']:.3f}")
                print(f"    Outbound ratio:{stats['outbound_ratio']:.1%}")
                print(f"    Target delay:  {stats['target_delay_mean']:.1f}ms")
                print(f"    Target padding:{stats['target_padding_mean']:.1%}")

        # DPI analysis
        if "dpi_analysis" in self.stats:
            dpi = self.stats["dpi_analysis"]
            print(f"\n DPI EVASION POTENTIAL:")
            print(f"    Pre-training score: {dpi['score']}/100")
            print(f"    VPN-like sizes:     {dpi['vpn_size_ratio']:.1%}")
            print(f"    Direction ratio:    {dpi['direction_ratio']:.2f}")
            print(f"    Size entropy:       {dpi['size_entropy']:.2f}")
            print(f"    Delay variance:     {dpi['delay_std']:.2f}")
            if dpi["issues"]:
                print("    Potential issues:")
                for issue in dpi["issues"]:
                    print(f"      - {issue}")

        # Diversity
        if "diversity" in self.stats:
            div = self.stats["diversity"]
            print(f"\n SAMPLE DIVERSITY:")
            print(f"    Unique sizes:  {div['total_size_unique']:,}")
            print(f"    Unique delays: {div['total_delay_unique']:,}")

        # Final verdict
        print("\n" + "=" * 70)
        if self.issues:
            print(" VERDICT: FAILED - Fix issues before training")
            verdict = "FAILED"
        elif len(self.warnings) > 5:
            print(" VERDICT: WARNING - Review warnings, may affect training quality")
            verdict = "WARNING"
        else:
            print(" VERDICT: PASSED - Dataset ready for flagship training")
            verdict = "PASSED"
        print("=" * 70)

        return {
            "verdict": verdict,
            "issues": self.issues,
            "warnings": self.warnings,
            "stats": self.stats,
        }


def main():
    parser = argparse.ArgumentParser(description="Audit flagship dataset quality")
    parser.add_argument("--data-dir", type=str, default="data/flagship",
                        help="Path to dataset directory")
    args = parser.parse_args()

    auditor = DatasetAuditor(args.data_dir)
    result = auditor.run_audit()

    # Exit code based on verdict
    if result["verdict"] == "FAILED":
        sys.exit(1)
    elif result["verdict"] == "WARNING":
        sys.exit(0)  # Warnings are OK to proceed
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
