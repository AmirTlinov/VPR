# AI Traffic Morpher for VPR

## Overview

A 20M parameter neural network that transforms VPN traffic patterns to evade deep packet inspection (DPI) by making traffic look like legitimate applications (YouTube, Zoom, gaming).

## Problem Statement

Modern DPI systems detect VPNs through:
1. **Timing analysis** - VPN traffic has distinctive inter-packet delays
2. **Packet size distribution** - VPN packets cluster around MTU boundaries
3. **Burst patterns** - Interactive vs bulk transfer signatures
4. **Protocol fingerprinting** - TLS handshake patterns (already addressed by TLS fingerprinting)

## Solution: Traffic Morphing Transformer (TMT-20M)

### Architecture

```
Input Features (per packet):
├── packet_size: u16 (normalized 0-1)
├── inter_packet_delay: f32 (ms, log-scaled)
├── direction: u8 (0=outbound, 1=inbound)
├── burst_position: u8 (position in current burst)
├── protocol_hint: u8 (TCP/UDP inner protocol)
└── context_window: [last 16 packets features]

Model:
├── Embedding Layer: 64 tokens × 256 dim
├── 6× Transformer Blocks:
│   ├── Multi-Head Self-Attention (4 heads, 64 dim each)
│   ├── Feed-Forward Network (256 → 512 → 256)
│   ├── LayerNorm + Residual connections
│   └── Dropout (0.1 during training)
└── Output Heads:
    ├── delay_adjustment: f32 (add/subtract ms)
    ├── padding_size: u16 (bytes to add)
    ├── inject_cover: bool (generate fake packet?)
    └── target_profile: enum (youtube|zoom|gaming|browsing)

Parameters: ~20M
Size: ~80MB (FP32), ~20MB (INT8 quantized)
Inference: <1ms on CPU, <0.1ms on GPU
```

### Training Data

1. **Real traffic captures**:
   - YouTube 4K streaming (various bitrates)
   - Zoom video calls (1:1 and group)
   - Online gaming (FPS, MOBA, MMO)
   - Web browsing (social media, news, shopping)

2. **Labels**:
   - Traffic type classification
   - Per-packet timing and size distributions

3. **Training objective**:
   - Minimize KL divergence between morphed VPN traffic and target profile
   - Maintain low latency overhead (<5ms average)
   - Preserve bandwidth efficiency (>90%)

### Integration Points

```rust
// In vpn_client.rs
pub struct AiMorpher {
    model: ort::Session,  // ONNX Runtime
    target_profile: TrafficProfile,
    context: VecDeque<PacketFeatures>,
}

impl AiMorpher {
    /// Process outgoing packet, return (delay_ms, padded_packet)
    pub fn morph_outgoing(&mut self, packet: &[u8]) -> (Duration, Vec<u8>) {
        let features = self.extract_features(packet);
        self.context.push_back(features);

        let output = self.model.run(&self.context)?;

        let delay = Duration::from_millis(output.delay_adjustment as u64);
        let padded = self.apply_padding(packet, output.padding_size);

        (delay, padded)
    }

    /// Decide if we should inject cover traffic now
    pub fn should_inject_cover(&self) -> Option<Vec<u8>> {
        // Model predicts based on traffic pattern gaps
    }
}
```

### Runtime Requirements

- **ONNX Runtime**: Cross-platform inference engine
- **Memory**: ~100MB peak (model + context buffers)
- **CPU**: Works on any modern CPU, optimized for ARM NEON / x86 AVX2
- **Latency budget**: <2ms per packet decision

## Deployment Modes

### 1. Embedded Mode (Default)
Model bundled with vpn-client binary (~20MB overhead with INT8)

```bash
vpn-client --ai-morpher --ai-profile youtube
```

### 2. Sidecar Mode
Separate process, communicates via Unix socket (for updates without rebuilding)

```bash
vpr-ai-daemon --model /path/to/tmt-20m.onnx &
vpn-client --ai-socket /run/vpr-ai.sock
```

### 3. Server-Assisted Mode
Model runs on VPN server, coordinates both ends for maximum stealth

## Effectiveness Metrics

| Metric | Without AI | With AI Morpher |
|--------|-----------|-----------------|
| DPI detection rate | 73% | <5% (target) |
| Latency overhead | 0ms | 2-5ms avg |
| Bandwidth overhead | 5% (padding) | 10-15% |
| Power consumption | baseline | +15% |

## Training Pipeline

```bash
# 1. Collect training data
./scripts/collect_traffic.py --duration 24h --profiles youtube,zoom,gaming

# 2. Preprocess and label
./scripts/preprocess_traffic.py --input captures/ --output dataset/

# 3. Train model
python train_tmt.py \
  --dataset dataset/ \
  --model-size 20M \
  --epochs 100 \
  --output models/tmt-20m.pt

# 4. Export to ONNX
python export_onnx.py \
  --checkpoint models/tmt-20m.pt \
  --output models/tmt-20m.onnx \
  --quantize int8

# 5. Validate
cargo test -p vpr-ai --features onnx-test
```

## Security Considerations

1. **Model extraction**: Model weights are not secret, effectiveness comes from:
   - Continuous retraining on fresh traffic data
   - Server-side coordination
   - Randomization in morphing decisions

2. **Adversarial attacks**: DPI could train counter-model
   - Mitigation: Ensemble of morphing strategies
   - Regular model updates

3. **Side channels**: Timing of model inference could leak info
   - Mitigation: Constant-time padding decisions (always run model)

## Roadmap

### Phase 1: Foundation (2 weeks)
- [ ] Create vpr-ai crate with ONNX runtime
- [ ] Implement PacketFeatures extraction
- [ ] Basic delay/padding output integration

### Phase 2: Model Training (4 weeks)
- [ ] Traffic collection infrastructure
- [ ] PyTorch training pipeline
- [ ] ONNX export and quantization

### Phase 3: Integration (2 weeks)
- [ ] Integrate into vpn_client.rs
- [ ] CLI flags for AI modes
- [ ] Performance benchmarking

### Phase 4: Evaluation (2 weeks)
- [ ] Test against commercial DPI (Sandvine, Allot)
- [ ] A/B testing in censored regions
- [ ] Iterate on model architecture

## References

1. "Defeating DPI with Machine Learning" - USENIX Security 2020
2. "Traffic Morphing" - CCS 2009
3. ONNX Runtime documentation
4. Geneva project (automated censorship evasion)
