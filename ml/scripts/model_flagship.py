"""
Traffic Morphing Transformer - Flagship Edition (TMT-20M-F)

Enhanced architecture with:
1. Larger context window (32 packets)
2. Detector-specific auxiliary heads
3. Sliding window attention for efficiency
4. Improved positional encoding
5. Better regularization
"""

import math
from typing import Dict, Optional

import torch
import torch.nn as nn
import torch.nn.functional as F


class RotaryPositionalEncoding(nn.Module):
    """Rotary Positional Encoding (RoPE) for better position awareness."""

    def __init__(self, d_model: int, max_len: int = 64):
        super().__init__()
        self.d_model = d_model

        # Compute inverse frequencies
        inv_freq = 1.0 / (10000 ** (torch.arange(0, d_model, 2).float() / d_model))
        self.register_buffer("inv_freq", inv_freq)

        # Precompute sin/cos for all positions
        positions = torch.arange(max_len).float()
        sincos = torch.einsum("i,j->ij", positions, self.inv_freq)
        self.register_buffer("sin", sincos.sin())
        self.register_buffer("cos", sincos.cos())

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Apply rotary positional encoding.

        Args:
            x: Input tensor [batch, seq_len, d_model]

        Returns:
            Tensor with rotary encoding applied
        """
        seq_len = x.size(1)

        # Split into even/odd dimensions
        x1 = x[..., 0::2]
        x2 = x[..., 1::2]

        # Apply rotation
        sin = self.sin[:seq_len, :].unsqueeze(0)
        cos = self.cos[:seq_len, :].unsqueeze(0)

        # Truncate sin/cos to match x dimensions
        sin = sin[..., :x1.size(-1)]
        cos = cos[..., :x1.size(-1)]

        out1 = x1 * cos - x2 * sin
        out2 = x1 * sin + x2 * cos

        # Interleave back
        out = torch.zeros_like(x)
        out[..., 0::2] = out1
        out[..., 1::2] = out2

        return out


class SlidingWindowAttention(nn.Module):
    """Sliding window attention for efficient long-context processing."""

    def __init__(
        self,
        d_model: int,
        num_heads: int,
        window_size: int = 16,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.d_model = d_model
        self.num_heads = num_heads
        self.window_size = window_size
        self.head_dim = d_model // num_heads

        self.qkv = nn.Linear(d_model, 3 * d_model)
        self.proj = nn.Linear(d_model, d_model)
        self.dropout = nn.Dropout(dropout)

        self.scale = self.head_dim ** -0.5

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Apply sliding window attention.

        Args:
            x: Input tensor [batch, seq_len, d_model]

        Returns:
            Output tensor [batch, seq_len, d_model]
        """
        batch_size, seq_len, _ = x.shape

        # Compute Q, K, V
        qkv = self.qkv(x).reshape(batch_size, seq_len, 3, self.num_heads, self.head_dim)
        qkv = qkv.permute(2, 0, 3, 1, 4)  # [3, batch, heads, seq, head_dim]
        q, k, v = qkv[0], qkv[1], qkv[2]

        # Create sliding window mask
        mask = torch.zeros(seq_len, seq_len, device=x.device, dtype=torch.bool)
        for i in range(seq_len):
            start = max(0, i - self.window_size // 2)
            end = min(seq_len, i + self.window_size // 2 + 1)
            mask[i, start:end] = True

        # Attention scores
        attn = (q @ k.transpose(-2, -1)) * self.scale

        # Apply window mask
        attn = attn.masked_fill(~mask.unsqueeze(0).unsqueeze(0), float('-inf'))

        attn = F.softmax(attn, dim=-1)
        attn = self.dropout(attn)

        # Apply attention to values
        out = attn @ v
        out = out.transpose(1, 2).reshape(batch_size, seq_len, self.d_model)

        return self.proj(out)


class FlagshipTransformerBlock(nn.Module):
    """Enhanced transformer block with sliding window attention."""

    def __init__(
        self,
        d_model: int,
        num_heads: int,
        ffn_dim: int,
        window_size: int = 16,
        dropout: float = 0.1,
        use_sliding_window: bool = True,
    ):
        super().__init__()

        # Attention
        self.norm1 = nn.LayerNorm(d_model)
        if use_sliding_window:
            self.attn = SlidingWindowAttention(d_model, num_heads, window_size, dropout)
        else:
            self.attn = nn.MultiheadAttention(
                embed_dim=d_model,
                num_heads=num_heads,
                dropout=dropout,
                batch_first=True,
            )
        self.use_sliding_window = use_sliding_window

        # Feed-forward
        self.norm2 = nn.LayerNorm(d_model)
        self.ffn = nn.Sequential(
            nn.Linear(d_model, ffn_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(ffn_dim, d_model),
            nn.Dropout(dropout),
        )

        # Stochastic depth
        self.drop_path = nn.Dropout(dropout * 0.5)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Attention with residual
        normed = self.norm1(x)
        if self.use_sliding_window:
            attn_out = self.attn(normed)
        else:
            attn_out, _ = self.attn(normed, normed, normed)
        x = x + self.drop_path(attn_out)

        # FFN with residual
        x = x + self.drop_path(self.ffn(self.norm2(x)))

        return x


class DetectorHead(nn.Module):
    """Auxiliary head for predicting specific detector activations."""

    def __init__(self, d_model: int, num_detectors: int = 5):
        super().__init__()
        self.head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(d_model // 2, num_detectors),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.head(x)


class TrafficMorphingTransformerFlagship(nn.Module):
    """
    Traffic Morphing Transformer - Flagship Edition (TMT-20M-F)

    Enhanced architecture for better DPI evasion.
    """

    def __init__(
        self,
        input_dim: int = 4,
        context_size: int = 32,
        embed_dim: int = 512,
        num_layers: int = 6,
        num_heads: int = 8,
        ffn_dim: int = 2048,
        dropout: float = 0.15,
        num_profiles: int = 5,
        num_detectors: int = 5,
        use_sliding_window: bool = True,
        window_size: int = 16,
    ):
        super().__init__()

        self.input_dim = input_dim
        self.context_size = context_size
        self.embed_dim = embed_dim

        # Input projection with layer norm
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, embed_dim),
            nn.LayerNorm(embed_dim),
            nn.Dropout(dropout * 0.5),
        )

        # Rotary positional encoding
        self.pos_encoder = RotaryPositionalEncoding(embed_dim, context_size)

        # Profile embedding
        self.profile_embed = nn.Embedding(num_profiles, embed_dim)

        # Transformer blocks (mix of sliding window and full attention)
        self.blocks = nn.ModuleList()
        for i in range(num_layers):
            # Use full attention for first and last layers, sliding window for middle
            use_sw = use_sliding_window and (0 < i < num_layers - 1)
            self.blocks.append(
                FlagshipTransformerBlock(
                    embed_dim, num_heads, ffn_dim, window_size, dropout, use_sw
                )
            )

        # Final normalization
        self.final_norm = nn.LayerNorm(embed_dim)

        # Main output heads
        self.delay_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, 1),
            nn.Softplus(),
        )

        self.padding_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, 1),
            nn.Softplus(),
        )

        self.inject_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, 1),
        )

        self.confidence_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, 1),
            nn.Sigmoid(),
        )

        # Detector-specific auxiliary head
        self.detector_head = DetectorHead(embed_dim, num_detectors)

        # Initialize weights
        self._init_weights()

    def _init_weights(self):
        """Initialize weights with careful scaling."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight, gain=0.8)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.Embedding):
                nn.init.normal_(module.weight, mean=0.0, std=0.02)
            elif isinstance(module, nn.LayerNorm):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

    def forward(
        self,
        x: torch.Tensor,
        profile_id: torch.Tensor,
        return_detector_preds: bool = False,
    ) -> Dict[str, torch.Tensor]:
        """Forward pass.

        Args:
            x: Packet features [batch, context_size, input_dim]
            profile_id: Target profile index [batch]
            return_detector_preds: Whether to return detector predictions

        Returns:
            Dictionary with morphing decisions
        """
        batch_size = x.size(0)

        # Project input
        x = self.input_proj(x)

        # Apply rotary positional encoding
        x = self.pos_encoder(x)

        # Add profile embedding to first position
        profile_emb = self.profile_embed(profile_id)
        x[:, 0, :] = x[:, 0, :] + profile_emb

        # Pass through transformer blocks
        for block in self.blocks:
            x = block(x)

        # Final normalization
        x = self.final_norm(x)

        # Use last position for prediction
        last_hidden = x[:, -1, :]

        # Generate outputs
        delay = self.delay_head(last_hidden).squeeze(-1)
        padding = self.padding_head(last_hidden).squeeze(-1)
        inject_logits = self.inject_head(last_hidden).squeeze(-1)
        confidence = self.confidence_head(last_hidden).squeeze(-1)

        outputs = {
            "delay_ms": delay,
            "padding_norm": padding,
            "inject_logits": inject_logits,
            "inject_prob": torch.sigmoid(inject_logits),
            "confidence": confidence,
        }

        if return_detector_preds:
            outputs["detector_preds"] = self.detector_head(last_hidden)

        return outputs

    def count_parameters(self) -> int:
        """Count total trainable parameters."""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def create_model(config: dict) -> TrafficMorphingTransformerFlagship:
    """Create flagship model from config."""
    model_cfg = config["model"]
    return TrafficMorphingTransformerFlagship(
        input_dim=model_cfg["input_dim"],
        context_size=model_cfg["context_size"],
        embed_dim=model_cfg["embed_dim"],
        num_layers=model_cfg["num_layers"],
        num_heads=model_cfg["num_heads"],
        ffn_dim=model_cfg["ffn_dim"],
        dropout=model_cfg["dropout"],
    )


if __name__ == "__main__":
    # Test model creation
    model = TrafficMorphingTransformerFlagship()
    print(f"Flagship model parameters: {model.count_parameters():,}")

    # Test forward pass
    batch_size = 4
    context_size = 32
    input_dim = 4

    x = torch.randn(batch_size, context_size, input_dim)
    profile = torch.zeros(batch_size, dtype=torch.long)

    outputs = model(x, profile, return_detector_preds=True)

    print(f"Delay shape: {outputs['delay_ms'].shape}")
    print(f"Padding shape: {outputs['padding_norm'].shape}")
    print(f"Inject shape: {outputs['inject_prob'].shape}")
    print(f"Confidence shape: {outputs['confidence'].shape}")
    print(f"Detector preds shape: {outputs['detector_preds'].shape}")

    # Verify parameter count
    param_count = model.count_parameters()
    print(f"\nParameter count: {param_count:,}")
    print("Flagship model ready!")
