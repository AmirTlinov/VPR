"""
Traffic Morphing Transformer (TMT-20M)

A 20M parameter transformer model for traffic pattern morphing.
Deterministic architecture with fixed seeds for reproducibility.
"""

import math
from typing import Dict, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


class PositionalEncoding(nn.Module):
    """Sinusoidal positional encoding for sequence position awareness."""

    def __init__(self, d_model: int, max_len: int = 64, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        # Create position encoding matrix
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # [1, max_len, d_model]
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Add positional encoding to input.

        Args:
            x: Input tensor [batch, seq_len, d_model]

        Returns:
            Tensor with positional encoding added
        """
        x = x + self.pe[:, : x.size(1), :]
        return self.dropout(x)


class TransformerBlock(nn.Module):
    """Single transformer block with pre-norm architecture."""

    def __init__(
        self,
        d_model: int,
        num_heads: int,
        ffn_dim: int,
        dropout: float = 0.1,
    ):
        super().__init__()

        # Self-attention
        self.norm1 = nn.LayerNorm(d_model)
        self.attn = nn.MultiheadAttention(
            embed_dim=d_model,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True,
        )

        # Feed-forward network
        self.norm2 = nn.LayerNorm(d_model)
        self.ffn = nn.Sequential(
            nn.Linear(d_model, ffn_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(ffn_dim, d_model),
            nn.Dropout(dropout),
        )

    def forward(
        self, x: torch.Tensor, mask: torch.Tensor | None = None
    ) -> torch.Tensor:
        """Forward pass through transformer block.

        Args:
            x: Input tensor [batch, seq_len, d_model]
            mask: Optional attention mask

        Returns:
            Output tensor [batch, seq_len, d_model]
        """
        # Self-attention with residual
        normed = self.norm1(x)
        attn_out, _ = self.attn(normed, normed, normed, attn_mask=mask)
        x = x + attn_out

        # FFN with residual
        x = x + self.ffn(self.norm2(x))
        return x


class TrafficMorphingTransformer(nn.Module):
    """
    Traffic Morphing Transformer (TMT-20M)

    Input: Sequence of packet features [batch, context_size, input_dim]
    Output: Morphing decisions [batch, 4] (delay, padding, inject_prob, confidence)
    """

    def __init__(
        self,
        input_dim: int = 4,
        context_size: int = 16,
        embed_dim: int = 512,
        num_layers: int = 6,
        num_heads: int = 8,
        ffn_dim: int = 2048,
        dropout: float = 0.1,
        num_profiles: int = 5,
    ):
        super().__init__()

        self.input_dim = input_dim
        self.context_size = context_size
        self.embed_dim = embed_dim

        # Input projection
        self.input_proj = nn.Linear(input_dim, embed_dim)

        # Positional encoding
        self.pos_encoder = PositionalEncoding(embed_dim, context_size, dropout)

        # Profile embedding (learnable)
        self.profile_embed = nn.Embedding(num_profiles, embed_dim)

        # Transformer blocks
        self.blocks = nn.ModuleList(
            [
                TransformerBlock(embed_dim, num_heads, ffn_dim, dropout)
                for _ in range(num_layers)
            ]
        )

        # Final normalization
        self.final_norm = nn.LayerNorm(embed_dim)

        # Output heads
        self.delay_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Linear(embed_dim // 2, 1),
            nn.Softplus(),  # Ensure non-negative delay
        )

        self.padding_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Linear(embed_dim // 2, 1),
            nn.Softplus(),  # Ensure non-negative padding
        )

        # Inject head outputs logits (no sigmoid for autocast safety in training)
        self.inject_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Linear(embed_dim // 2, 1),
        )

        self.confidence_head = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.ReLU(),
            nn.Linear(embed_dim // 2, 1),
            nn.Sigmoid(),  # Confidence 0-1
        )

        # Initialize weights deterministically
        self._init_weights()

    def _init_weights(self):
        """Initialize weights using Xavier uniform for reproducibility."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
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
        mask: torch.Tensor | None = None,
    ) -> Dict[str, torch.Tensor]:
        """Forward pass.

        Args:
            x: Packet features [batch, context_size, input_dim]
            profile_id: Target profile index [batch]
            mask: Optional attention mask

        Returns:
            Dictionary with morphing decisions
        """
        batch_size = x.size(0)

        # Project input to embedding dimension
        x = self.input_proj(x)  # [batch, context_size, embed_dim]

        # Add positional encoding
        x = self.pos_encoder(x)

        # Add profile embedding to first position
        profile_emb = self.profile_embed(profile_id)  # [batch, embed_dim]
        x[:, 0, :] = x[:, 0, :] + profile_emb

        # Pass through transformer blocks
        for block in self.blocks:
            x = block(x, mask)

        # Final normalization
        x = self.final_norm(x)

        # Use last position for prediction (most recent packet context)
        last_hidden = x[:, -1, :]  # [batch, embed_dim]

        # Generate outputs
        delay = self.delay_head(last_hidden).squeeze(-1)  # [batch]
        padding = self.padding_head(last_hidden).squeeze(-1)  # [batch]
        inject_logits = self.inject_head(last_hidden).squeeze(-1)  # [batch]
        confidence = self.confidence_head(last_hidden).squeeze(-1)  # [batch]

        return {
            "delay_ms": delay,
            "padding_norm": padding,
            "inject_logits": inject_logits,  # Raw logits for training
            "inject_prob": torch.sigmoid(inject_logits),  # Probability for inference
            "confidence": confidence,
        }

    def count_parameters(self) -> int:
        """Count total trainable parameters."""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def create_model(config: dict) -> TrafficMorphingTransformer:
    """Create model from config dictionary.

    Args:
        config: Model configuration

    Returns:
        Initialized model
    """
    model_cfg = config["model"]
    return TrafficMorphingTransformer(
        input_dim=model_cfg["input_dim"],
        context_size=model_cfg["context_size"],
        embed_dim=model_cfg["embed_dim"],
        num_layers=model_cfg["num_layers"],
        num_heads=model_cfg["num_heads"],
        ffn_dim=model_cfg["ffn_dim"],
        dropout=model_cfg["dropout"],
    )


if __name__ == "__main__":
    # Test model creation and parameter count
    model = TrafficMorphingTransformer()
    print(f"Model parameters: {model.count_parameters():,}")

    # Test forward pass
    batch_size = 4
    context_size = 16
    input_dim = 4

    x = torch.randn(batch_size, context_size, input_dim)
    profile = torch.zeros(batch_size, dtype=torch.long)

    outputs = model(x, profile)
    print(f"Delay shape: {outputs['delay_ms'].shape}")
    print(f"Padding shape: {outputs['padding_norm'].shape}")
    print(f"Inject shape: {outputs['inject_prob'].shape}")
    print(f"Confidence shape: {outputs['confidence'].shape}")

    # Verify parameter count is ~20M (19.4M with default config)
    param_count = model.count_parameters()
    assert 15_000_000 < param_count < 25_000_000, f"Expected ~20M params, got {param_count:,}"
    print(f"Parameter count verified: {param_count:,} (~20M) ✓")
