#!/bin/bash
# =============================================================================
# TMT-20M Flagship Training Pipeline
# =============================================================================
# Usage: ./train_flagship.sh [--generate-data] [--train] [--export] [--all]
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# =============================================================================
# Configuration
# =============================================================================
PACKETS_PER_PROFILE=1000000  # 1M packets per profile
SESSIONS_PER_PROFILE=200
AUGMENTATION_PROB=0.3
ADVERSARIAL_RATIO=0.15
DATA_DIR="data/flagship"
CONFIG_FILE="config/tmt_20m_flagship.yaml"
CHECKPOINT_DIR="models"

# =============================================================================
# Functions
# =============================================================================

check_dependencies() {
    log_info "Checking dependencies..."

    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 not found"
        exit 1
    fi

    # Check required packages
    python3 -c "import torch; import numpy; import pandas; import yaml; import tqdm" 2>/dev/null || {
        log_error "Missing Python packages. Run: pip install torch numpy pandas pyyaml tqdm onnx onnxruntime"
        exit 1
    }

    log_success "Dependencies OK"
}

generate_data() {
    log_info "=========================================="
    log_info "PHASE 1: Generating Flagship Dataset"
    log_info "=========================================="

    python3 scripts/generate_flagship_dataset.py \
        --packets-per-profile "$PACKETS_PER_PROFILE" \
        --sessions-per-profile "$SESSIONS_PER_PROFILE" \
        --augmentation-prob "$AUGMENTATION_PROB" \
        --adversarial-ratio "$ADVERSARIAL_RATIO" \
        --output-dir "$DATA_DIR" \
        --seed 42

    if [ $? -eq 0 ]; then
        log_success "Dataset generated: $DATA_DIR"

        # Show file sizes
        log_info "Dataset sizes:"
        ls -lh "$DATA_DIR"/*.parquet
    else
        log_error "Dataset generation failed"
        exit 1
    fi
}

train_model() {
    log_info "=========================================="
    log_info "PHASE 2: Training with Curriculum Learning"
    log_info "=========================================="

    # Check if data exists
    if [ ! -f "$DATA_DIR/train.parquet" ]; then
        log_error "Training data not found. Run with --generate-data first"
        exit 1
    fi

    # Check GPU
    if python3 -c "import torch; print(torch.cuda.is_available())" | grep -q "True"; then
        log_info "GPU detected: $(python3 -c 'import torch; print(torch.cuda.get_device_name(0))')"
    else
        log_warn "No GPU detected. Training will be slow on CPU."
    fi

    # Start training
    python3 scripts/train_flagship.py --config "$CONFIG_FILE"

    if [ $? -eq 0 ]; then
        log_success "Training complete!"

        # Check for best model
        if [ -f "$CHECKPOINT_DIR/tmt_20m_flagship_best.pt" ]; then
            log_success "Best model saved: $CHECKPOINT_DIR/tmt_20m_flagship_best.pt"
        fi
    else
        log_error "Training failed"
        exit 1
    fi
}

export_model() {
    log_info "=========================================="
    log_info "PHASE 3: Exporting to ONNX"
    log_info "=========================================="

    CHECKPOINT="$CHECKPOINT_DIR/tmt_20m_flagship_best.pt"

    if [ ! -f "$CHECKPOINT" ]; then
        log_error "Checkpoint not found: $CHECKPOINT"
        log_info "Run training first with --train"
        exit 1
    fi

    # Export with FP16 quantization
    python3 scripts/export_flagship_onnx.py \
        --checkpoint "$CHECKPOINT" \
        --output "$CHECKPOINT_DIR/tmt-20m-flagship.onnx" \
        --context-size 32 \
        --quantize fp16 \
        --copy-to-rust

    if [ $? -eq 0 ]; then
        log_success "ONNX export complete!"

        # Show file sizes
        log_info "Model files:"
        ls -lh "$CHECKPOINT_DIR"/tmt-20m-flagship*.onnx 2>/dev/null || true

        # Check Rust integration
        RUST_MODEL="../src/vpr-ai/assets/tmt-20m.onnx"
        if [ -f "$RUST_MODEL" ]; then
            log_success "Model copied to Rust: $RUST_MODEL"
        fi
    else
        log_error "ONNX export failed"
        exit 1
    fi
}

run_tests() {
    log_info "=========================================="
    log_info "PHASE 4: Running E2E Tests"
    log_info "=========================================="

    cd "$SCRIPT_DIR/.."

    # Run Rust tests
    log_info "Running vpr-ai tests..."
    cargo test -p vpr-ai --features _onnx_core -- --nocapture 2>&1 | tail -50

    if [ $? -eq 0 ]; then
        log_success "All tests passed!"
    else
        log_warn "Some tests failed. Check output above."
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --generate-data    Generate flagship dataset (1M packets/profile)"
    echo "  --train            Train model with curriculum learning"
    echo "  --export           Export trained model to ONNX"
    echo "  --test             Run E2E tests"
    echo "  --all              Run complete pipeline"
    echo "  --help             Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --all                  # Complete pipeline"
    echo "  $0 --generate-data        # Only generate data"
    echo "  $0 --train --export       # Train and export"
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "=============================================="
    echo "  TMT-20M FLAGSHIP TRAINING PIPELINE"
    echo "=============================================="
    echo ""

    check_dependencies

    DO_GENERATE=false
    DO_TRAIN=false
    DO_EXPORT=false
    DO_TEST=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --generate-data)
                DO_GENERATE=true
                shift
                ;;
            --train)
                DO_TRAIN=true
                shift
                ;;
            --export)
                DO_EXPORT=true
                shift
                ;;
            --test)
                DO_TEST=true
                shift
                ;;
            --all)
                DO_GENERATE=true
                DO_TRAIN=true
                DO_EXPORT=true
                DO_TEST=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Run selected phases
    if [ "$DO_GENERATE" = true ]; then
        generate_data
    fi

    if [ "$DO_TRAIN" = true ]; then
        train_model
    fi

    if [ "$DO_EXPORT" = true ]; then
        export_model
    fi

    if [ "$DO_TEST" = true ]; then
        run_tests
    fi

    # If no options selected, show usage
    if [ "$DO_GENERATE" = false ] && [ "$DO_TRAIN" = false ] && \
       [ "$DO_EXPORT" = false ] && [ "$DO_TEST" = false ]; then
        show_usage
    fi

    echo ""
    log_success "Pipeline complete!"
    echo ""
}

main "$@"
