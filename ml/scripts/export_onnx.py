#!/usr/bin/env python3
"""
Export trained TMT-20M model to ONNX format.

Usage:
    python export_onnx.py --checkpoint models/tmt_20m_best.pt --output models/tmt-20m.onnx

Features:
- Full ONNX export with all metadata
- Optional INT8 quantization
- Validation of exported model
- Size and performance benchmarking
"""

import argparse
from pathlib import Path
import time

import numpy as np
import torch
import onnx
import onnxruntime as ort
import yaml

from model import TrafficMorphingTransformer, create_model


def export_to_onnx(
    model: torch.nn.Module,
    output_path: str,
    context_size: int = 16,
    input_dim: int = 4,
    opset_version: int = 17,
) -> None:
    """Export PyTorch model to ONNX format.

    Args:
        model: Trained PyTorch model
        output_path: Path for ONNX file
        context_size: Input sequence length
        input_dim: Features per packet
        opset_version: ONNX opset version
    """
    model.eval()

    # Create dummy inputs
    batch_size = 1
    dummy_context = torch.randn(batch_size, context_size, input_dim)
    dummy_profile = torch.zeros(batch_size, dtype=torch.long)

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

    print(f"Exported to: {output_path}")


def quantize_model(input_path: str, output_path: str, quantize_type: str = "int8"):
    """Quantize ONNX model for smaller size and faster inference.

    Args:
        input_path: Path to FP32 ONNX model
        output_path: Path for quantized model
        quantize_type: Quantization type (int8, uint8)
    """
    from onnxruntime.quantization import quantize_dynamic, QuantType

    qtype = QuantType.QInt8 if quantize_type == "int8" else QuantType.QUInt8

    quantize_dynamic(
        model_input=input_path,
        model_output=output_path,
        weight_type=qtype,
    )

    print(f"Quantized to: {output_path}")


def validate_onnx(
    onnx_path: str,
    pytorch_model: torch.nn.Module,
    context_size: int = 16,
    input_dim: int = 4,
    rtol: float = 1e-3,
    atol: float = 1e-5,
) -> bool:
    """Validate ONNX model outputs match PyTorch.

    Args:
        onnx_path: Path to ONNX model
        pytorch_model: Original PyTorch model
        context_size: Input sequence length
        input_dim: Features per packet
        rtol: Relative tolerance
        atol: Absolute tolerance

    Returns:
        True if outputs match within tolerance
    """
    # Load ONNX model
    ort_session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])

    # Create test inputs
    np.random.seed(42)
    test_context = np.random.randn(1, context_size, input_dim).astype(np.float32)
    test_profile = np.zeros(1, dtype=np.int64)

    # ONNX inference
    ort_outputs = ort_session.run(
        None,
        {"context": test_context, "profile_id": test_profile},
    )

    # PyTorch inference
    pytorch_model.eval()
    with torch.no_grad():
        pt_outputs = pytorch_model(
            torch.tensor(test_context),
            torch.tensor(test_profile),
        )

    # Compare outputs
    output_names = ["delay_ms", "padding_norm", "inject_prob", "confidence"]
    all_match = True

    for i, name in enumerate(output_names):
        ort_val = ort_outputs[i]
        pt_val = pt_outputs[name].numpy()

        if np.allclose(ort_val, pt_val, rtol=rtol, atol=atol):
            print(f"  {name}: MATCH")
        else:
            print(f"  {name}: MISMATCH")
            print(f"    ONNX: {ort_val}")
            print(f"    PyTorch: {pt_val}")
            all_match = False

    return all_match


def benchmark_onnx(onnx_path: str, context_size: int = 16, input_dim: int = 4) -> dict:
    """Benchmark ONNX model inference speed.

    Args:
        onnx_path: Path to ONNX model
        context_size: Input sequence length
        input_dim: Features per packet

    Returns:
        Benchmark results
    """
    # Load model
    ort_session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])

    # Create test input
    test_context = np.random.randn(1, context_size, input_dim).astype(np.float32)
    test_profile = np.zeros(1, dtype=np.int64)

    # Warmup
    for _ in range(10):
        ort_session.run(None, {"context": test_context, "profile_id": test_profile})

    # Benchmark
    num_runs = 1000
    start = time.perf_counter()
    for _ in range(num_runs):
        ort_session.run(None, {"context": test_context, "profile_id": test_profile})
    end = time.perf_counter()

    avg_time_ms = (end - start) / num_runs * 1000

    # Model size
    model_size_mb = Path(onnx_path).stat().st_size / (1024 * 1024)

    return {
        "avg_inference_ms": avg_time_ms,
        "model_size_mb": model_size_mb,
        "throughput_per_sec": 1000 / avg_time_ms,
    }


def main():
    parser = argparse.ArgumentParser(description="Export TMT-20M to ONNX")
    parser.add_argument(
        "--checkpoint", type=str, required=True, help="PyTorch checkpoint path"
    )
    parser.add_argument(
        "--output", type=str, default="models/tmt-20m.onnx", help="Output ONNX path"
    )
    parser.add_argument(
        "--quantize",
        type=str,
        choices=["none", "int8", "uint8"],
        default="int8",
        help="Quantization type",
    )
    parser.add_argument(
        "--opset", type=int, default=17, help="ONNX opset version"
    )
    args = parser.parse_args()

    # Load checkpoint
    print(f"Loading checkpoint: {args.checkpoint}")
    checkpoint = torch.load(args.checkpoint, map_location="cpu", weights_only=False)
    config = checkpoint["config"]

    # Create and load model
    model = create_model(config)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    print(f"Model parameters: {model.count_parameters():,}")

    # Export to ONNX
    fp32_path = args.output.replace(".onnx", "_fp32.onnx")
    export_to_onnx(
        model,
        fp32_path,
        context_size=config["model"]["context_size"],
        input_dim=config["model"]["input_dim"],
        opset_version=args.opset,
    )

    # Validate ONNX
    print("\nValidating ONNX export...")
    if validate_onnx(
        fp32_path,
        model,
        context_size=config["model"]["context_size"],
        input_dim=config["model"]["input_dim"],
    ):
        print("ONNX validation: PASSED")
    else:
        print("ONNX validation: FAILED")
        return 1

    # Quantize if requested
    if args.quantize != "none":
        print(f"\nQuantizing to {args.quantize}...")
        quantize_model(fp32_path, args.output, args.quantize)
    else:
        # Just rename FP32 to final output
        Path(fp32_path).rename(args.output)

    # Benchmark
    print("\nBenchmarking...")
    results = benchmark_onnx(
        args.output,
        context_size=config["model"]["context_size"],
        input_dim=config["model"]["input_dim"],
    )

    print(f"\n{'=' * 50}")
    print("EXPORT COMPLETE")
    print(f"{'=' * 50}")
    print(f"Output: {args.output}")
    print(f"Model size: {results['model_size_mb']:.2f} MB")
    print(f"Avg inference: {results['avg_inference_ms']:.3f} ms")
    print(f"Throughput: {results['throughput_per_sec']:.0f} packets/sec")

    # Quality checks
    if results["avg_inference_ms"] > 2.0:
        print("\nWARNING: Inference too slow (>2ms), consider optimization")
    if results["model_size_mb"] > 30:
        print("\nWARNING: Model too large (>30MB), consider stronger quantization")

    return 0


if __name__ == "__main__":
    exit(main())
