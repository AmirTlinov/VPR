#!/usr/bin/env python3
"""
Export Flagship TMT-20M model to ONNX format.

Supports:
1. FP32 (full precision, ~75MB)
2. FP16 (half precision, ~40MB)
3. INT8 quantization (for edge deployment, ~20MB)
"""

import argparse
from pathlib import Path
import torch
import torch.onnx
import onnx
from onnxruntime.quantization import quantize_dynamic, QuantType

# Import model
import sys
sys.path.insert(0, str(Path(__file__).parent))
from model_flagship import TrafficMorphingTransformerFlagship


def load_checkpoint(checkpoint_path: str) -> dict:
    """Load checkpoint and extract config and state dict."""
    checkpoint = torch.load(checkpoint_path, map_location="cpu")
    return checkpoint


def export_to_onnx(
    model: TrafficMorphingTransformerFlagship,
    output_path: str,
    context_size: int = 32,
    opset_version: int = 17,
):
    """Export model to ONNX format."""
    model.eval()

    # Create dummy inputs
    dummy_context = torch.randn(1, context_size, 4)
    dummy_profile = torch.zeros(1, dtype=torch.long)

    # Export
    torch.onnx.export(
        model,
        (dummy_context, dummy_profile),
        output_path,
        export_params=True,
        opset_version=opset_version,
        do_constant_folding=True,
        input_names=["context", "profile_id"],
        output_names=["delay_ms", "padding_norm", "inject_prob", "confidence"],
        dynamic_axes={
            "context": {0: "batch_size"},
            "profile_id": {0: "batch_size"},
            "delay_ms": {0: "batch_size"},
            "padding_norm": {0: "batch_size"},
            "inject_prob": {0: "batch_size"},
            "confidence": {0: "batch_size"},
        },
    )

    # Verify the model
    onnx_model = onnx.load(output_path)
    onnx.checker.check_model(onnx_model)

    print(f"Exported to: {output_path}")
    return output_path


def convert_to_fp16(input_path: str, output_path: str):
    """Convert ONNX model to FP16."""
    from onnxconverter_common import float16

    model = onnx.load(input_path)
    model_fp16 = float16.convert_float_to_float16(model)
    onnx.save(model_fp16, output_path)

    print(f"FP16 model saved to: {output_path}")
    return output_path


def quantize_to_int8(input_path: str, output_path: str):
    """Quantize ONNX model to INT8."""
    quantize_dynamic(
        input_path,
        output_path,
        weight_type=QuantType.QUInt8,
    )

    print(f"INT8 model saved to: {output_path}")
    return output_path


def main():
    parser = argparse.ArgumentParser(description="Export TMT-20M Flagship to ONNX")
    parser.add_argument("--checkpoint", type=str, required=True,
                        help="Path to checkpoint (.pt file)")
    parser.add_argument("--output", type=str, default="models/tmt-20m-flagship.onnx",
                        help="Output ONNX path")
    parser.add_argument("--context-size", type=int, default=32,
                        help="Context size (default: 32)")
    parser.add_argument("--quantize", type=str, choices=["none", "fp16", "int8"],
                        default="fp16", help="Quantization type")
    parser.add_argument("--copy-to-rust", action="store_true",
                        help="Copy to Rust assets directory")
    args = parser.parse_args()

    print("=" * 60)
    print("TMT-20M Flagship ONNX Exporter")
    print("=" * 60)

    # Load checkpoint
    print(f"\nLoading checkpoint: {args.checkpoint}")
    checkpoint = load_checkpoint(args.checkpoint)

    config = checkpoint.get("config", {})
    model_config = config.get("model", {})

    # Create model with config from checkpoint or defaults
    model = TrafficMorphingTransformerFlagship(
        input_dim=model_config.get("input_dim", 4),
        context_size=model_config.get("context_size", args.context_size),
        embed_dim=model_config.get("embed_dim", 512),
        num_layers=model_config.get("num_layers", 6),
        num_heads=model_config.get("num_heads", 8),
        ffn_dim=model_config.get("ffn_dim", 2048),
        dropout=0.0,  # Disable dropout for inference
    )

    # Load weights
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    print(f"Model parameters: {model.count_parameters():,}")
    print(f"Context size: {model_config.get('context_size', args.context_size)}")

    # Export to ONNX
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    fp32_path = args.output.replace(".onnx", "_fp32.onnx")
    print(f"\nExporting FP32 model...")
    export_to_onnx(model, fp32_path, args.context_size)

    fp32_size = Path(fp32_path).stat().st_size / 1024 / 1024
    print(f"FP32 model size: {fp32_size:.1f} MB")

    final_path = fp32_path

    # Apply quantization
    if args.quantize == "fp16":
        print(f"\nConverting to FP16...")
        fp16_path = args.output.replace(".onnx", "_fp16.onnx")
        convert_to_fp16(fp32_path, fp16_path)
        fp16_size = Path(fp16_path).stat().st_size / 1024 / 1024
        print(f"FP16 model size: {fp16_size:.1f} MB")
        final_path = fp16_path

    elif args.quantize == "int8":
        print(f"\nQuantizing to INT8...")
        int8_path = args.output.replace(".onnx", "_int8.onnx")
        quantize_to_int8(fp32_path, int8_path)
        int8_size = Path(int8_path).stat().st_size / 1024 / 1024
        print(f"INT8 model size: {int8_size:.1f} MB")
        final_path = int8_path

    # Copy final model to standard name
    import shutil
    shutil.copy(final_path, args.output)
    print(f"\nFinal model: {args.output}")

    # Copy to Rust assets if requested
    if args.copy_to_rust:
        rust_assets = Path(__file__).parent.parent.parent / "src" / "vpr-ai" / "assets"
        rust_assets.mkdir(parents=True, exist_ok=True)
        rust_path = rust_assets / "tmt-20m.onnx"
        shutil.copy(args.output, rust_path)
        print(f"Copied to Rust: {rust_path}")

    # Print metrics from checkpoint
    print("\n" + "=" * 60)
    print("CHECKPOINT METRICS")
    print("=" * 60)

    if "paranoid_evasion" in checkpoint:
        print(f"Paranoid evasion: {checkpoint['paranoid_evasion']:.1%}")

    if "all_level_evasion" in checkpoint:
        print("\nEvasion by DPI level:")
        for level, evasion in checkpoint["all_level_evasion"].items():
            print(f"  {level:12s}: {evasion:.1%}")

    if "curriculum_level" in checkpoint:
        print(f"\nFinal curriculum level: {checkpoint['curriculum_level']}")

    print("\n" + "=" * 60)
    print("EXPORT COMPLETE!")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    exit(main())
