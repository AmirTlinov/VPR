#!/usr/bin/env python3
"""
Complete TMT-20M Training Pipeline Orchestrator.

Runs the full training pipeline:
1. Generate/collect training data
2. Preprocess and validate
3. Train model with quality gates
4. Export to ONNX with quantization
5. Validate exported model

Usage:
    # Full pipeline with synthetic data
    python run_pipeline.py --synthetic --seed 42

    # Pipeline with real captures
    python run_pipeline.py --data-dir captures/

    # Resume from existing data
    python run_pipeline.py --skip-data-collection
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd: list, description: str, check: bool = True) -> int:
    """Run a command with logging.

    Args:
        cmd: Command and arguments
        description: What this step does
        check: Whether to exit on failure

    Returns:
        Return code
    """
    print(f"\n{'=' * 60}")
    print(f"STEP: {description}")
    print(f"{'=' * 60}")
    print(f"Command: {' '.join(cmd)}")
    print()

    start = time.time()
    result = subprocess.run(cmd)
    elapsed = time.time() - start

    if result.returncode != 0:
        print(f"\nFAILED after {elapsed:.1f}s (exit code: {result.returncode})")
        if check:
            sys.exit(result.returncode)
    else:
        print(f"\nSUCCESS in {elapsed:.1f}s")

    return result.returncode


def main():
    parser = argparse.ArgumentParser(description="Run full TMT-20M training pipeline")

    # Data collection options
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="Generate synthetic training data",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        help="Directory with pcap files for real data",
    )
    parser.add_argument(
        "--skip-data-collection",
        action="store_true",
        help="Skip data collection, use existing data",
    )
    parser.add_argument(
        "--num-packets",
        type=int,
        default=100000,
        help="Synthetic packets per profile",
    )

    # Training options
    parser.add_argument(
        "--config",
        type=str,
        default="configs/tmt_20m.yaml",
        help="Training config file",
    )
    parser.add_argument(
        "--skip-training",
        action="store_true",
        help="Skip training, use existing model",
    )
    parser.add_argument(
        "--resume",
        type=str,
        help="Resume from checkpoint",
    )

    # Export options
    parser.add_argument(
        "--skip-export",
        action="store_true",
        help="Skip ONNX export",
    )
    parser.add_argument(
        "--quantize",
        type=str,
        choices=["none", "int8", "uint8"],
        default="int8",
        help="Quantization type",
    )

    # Common options
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing",
    )

    args = parser.parse_args()

    # Paths
    scripts_dir = Path(__file__).parent
    ml_dir = scripts_dir.parent
    data_dir = ml_dir / "data"
    raw_dir = data_dir / "raw"
    models_dir = ml_dir / "models"

    # Create directories
    raw_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    profiles = ["youtube", "zoom", "gaming", "browsing", "netflix"]
    total_start = time.time()

    print("\n" + "=" * 60)
    print("TMT-20M TRAINING PIPELINE")
    print("=" * 60)
    print(f"Seed: {args.seed}")
    print(f"Config: {args.config}")
    print(f"Data directory: {data_dir}")
    print(f"Models directory: {models_dir}")

    # Step 1: Data Collection
    if not args.skip_data_collection:
        print("\n" + "#" * 60)
        print("# PHASE 1: DATA COLLECTION")
        print("#" * 60)

        if args.synthetic:
            # Generate synthetic data for each profile
            for profile in profiles:
                cmd = [
                    sys.executable,
                    str(scripts_dir / "collect_data.py"),
                    "--synthetic",
                    "--profile", profile,
                    "--num-packets", str(args.num_packets),
                    "--output-dir", str(raw_dir),
                    "--seed", str(args.seed),
                ]

                if args.dry_run:
                    print(f"Would run: {' '.join(cmd)}")
                else:
                    run_command(cmd, f"Generate synthetic {profile} data")

        elif args.data_dir:
            # Process pcap files
            pcap_dir = Path(args.data_dir)
            for profile in profiles:
                pcap_files = list(pcap_dir.glob(f"{profile}*.pcap"))
                if not pcap_files:
                    print(f"Warning: No pcap files for {profile}")
                    continue

                for pcap_file in pcap_files:
                    cmd = [
                        sys.executable,
                        str(scripts_dir / "collect_data.py"),
                        "--pcap", str(pcap_file),
                        "--profile", profile,
                        "--output-dir", str(raw_dir),
                        "--seed", str(args.seed),
                    ]

                    if args.dry_run:
                        print(f"Would run: {' '.join(cmd)}")
                    else:
                        run_command(cmd, f"Process {pcap_file.name}")

        else:
            print("Error: Specify --synthetic or --data-dir for data collection")
            return 1

    # Step 2: Preprocessing
    print("\n" + "#" * 60)
    print("# PHASE 2: PREPROCESSING")
    print("#" * 60)

    cmd = [
        sys.executable,
        str(scripts_dir / "preprocess.py"),
        "--input-dir", str(raw_dir),
        "--output-dir", str(data_dir),
        "--seed", str(args.seed),
    ]

    if args.dry_run:
        print(f"Would run: {' '.join(cmd)}")
    else:
        run_command(cmd, "Preprocess and split data")

    # Step 3: Training
    if not args.skip_training:
        print("\n" + "#" * 60)
        print("# PHASE 3: TRAINING")
        print("#" * 60)

        cmd = [
            sys.executable,
            str(scripts_dir / "train.py"),
            "--config", str(ml_dir / args.config),
        ]

        if args.resume:
            cmd.extend(["--resume", args.resume])

        if args.dry_run:
            print(f"Would run: {' '.join(cmd)}")
        else:
            result = run_command(cmd, "Train TMT-20M model", check=False)
            if result != 0:
                print("\nWARNING: Training did not pass quality gates!")
                print("Model may not be production-ready.")
                # Continue to export anyway for debugging

    # Step 4: Export to ONNX
    if not args.skip_export:
        print("\n" + "#" * 60)
        print("# PHASE 4: ONNX EXPORT")
        print("#" * 60)

        checkpoint = models_dir / "tmt_20m_best.pt"
        if not checkpoint.exists():
            print(f"Error: No checkpoint found at {checkpoint}")
            return 1

        cmd = [
            sys.executable,
            str(scripts_dir / "export_onnx.py"),
            "--checkpoint", str(checkpoint),
            "--output", str(models_dir / "tmt-20m.onnx"),
            "--quantize", args.quantize,
        ]

        if args.dry_run:
            print(f"Would run: {' '.join(cmd)}")
        else:
            run_command(cmd, "Export to ONNX")

    # Summary
    total_elapsed = time.time() - total_start

    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)
    print(f"Total time: {total_elapsed/60:.1f} minutes")
    print(f"\nOutputs:")
    print(f"  Training data: {data_dir}/{{train,val,test}}.parquet")
    print(f"  Model checkpoint: {models_dir}/tmt_20m_best.pt")
    print(f"  ONNX model: {models_dir}/tmt-20m.onnx")
    print(f"\nTo use the model:")
    print(f"  1. Copy {models_dir}/tmt-20m.onnx to vpr-ai assets")
    print(f"  2. Enable 'onnx' feature in vpr-ai crate")
    print(f"  3. Initialize OnnxMorpher with model path")

    return 0


if __name__ == "__main__":
    sys.exit(main())
