# VPR AI

AI-powered traffic morphing for DPI evasion.

## Features

- **Traffic Morphing** - Transform VPN traffic to mimic legitimate apps
- **ONNX Runtime** - Optional ~20M parameter neural network
- **Rule-based Fallback** - Works without AI model
- **Cover Traffic** - Profile-aware packet synthesis
- **DPI Simulator** - Test morphing effectiveness

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TrafficMorpher                           │
│  ┌─────────────────┐        ┌─────────────────────────────┐ │
│  │ RuleBasedMorpher│        │      OnnxMorpher            │ │
│  │ (fallback)      │   OR   │ (AI-powered, ~20M params)   │ │
│  └────────┬────────┘        └──────────────┬──────────────┘ │
│           │                                │                │
│           ▼                                ▼                │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              CoverGenerator                             ││
│  │  - Profile-aware packet synthesis                       ││
│  │  - Realistic payload patterns (RTP/TLS/Game)            ││
│  │  - Cryptographically random content                     ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Traffic Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| YouTube | 4K streaming pattern | Video watching |
| Zoom | Video call pattern | Business calls |
| Gaming | FPS-like traffic | Online gaming |
| Browsing | Web browsing | General use |
| Netflix | Streaming pattern | Video streaming |

## Quick Start

```rust
use vpr_ai::{TrafficProfile, morpher::create_morpher};

let mut morpher = create_morpher(TrafficProfile::YouTube, None);

// Process outgoing packet
let decision = morpher.morph_outgoing(&packet)?;
// Apply: decision.delay, decision.padding_size, decision.inject_cover
```

## Morph Decision

The morpher returns a `MorphDecision` containing:
- `delay` - Additional delay before sending
- `padding_size` - Bytes to pad packet
- `inject_cover` - Whether to inject cover traffic
- `confidence` - Confidence score (0.0-1.0)

## Testing

```bash
# Without ONNX (rule-based only)
cargo test -p vpr-ai

# With ONNX support
cargo test -p vpr-ai --features onnx
```

## DPI Simulation

Test morphing effectiveness:

```rust
use vpr_ai::dpi_simulator::DpiSimulator;

let simulator = DpiSimulator::new();
let score = simulator.analyze_traffic(&packets);
// score < 0.5 = looks legitimate
```
