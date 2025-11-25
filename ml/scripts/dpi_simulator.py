"""
DPI Simulator for Adversarial Training.

Python port of the Rust DPI simulator for use in training loop.
This allows the model to learn to evade detection during training.
"""

import numpy as np
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple, List


class DpiVerdict(Enum):
    PASS = "pass"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


@dataclass
class DpiConfig:
    """DPI detection sensitivity configuration."""
    window_size: int = 50
    block_threshold: float = 60.0
    warn_threshold: float = 35.0
    check_entropy: bool = True
    check_timing: bool = True
    check_size_patterns: bool = True
    check_direction_ratio: bool = True
    check_bursts: bool = True

    @classmethod
    def paranoid(cls) -> "DpiConfig":
        """Maximum paranoia - blocks at slightest suspicion."""
        return cls(
            window_size=30,
            block_threshold=25.0,
            warn_threshold=10.0,
        )

    @classmethod
    def china_gfw(cls) -> "DpiConfig":
        """China-style DPI (very aggressive)."""
        return cls(
            window_size=20,
            block_threshold=30.0,
            warn_threshold=15.0,
        )

    @classmethod
    def russia_rkn(cls) -> "DpiConfig":
        """Russia-style DPI (Roskomnadzor)."""
        return cls(
            window_size=40,
            block_threshold=40.0,
            warn_threshold=20.0,
            check_direction_ratio=False,
        )

    @classmethod
    def iran(cls) -> "DpiConfig":
        """Iran-style DPI."""
        return cls(
            window_size=25,
            block_threshold=35.0,
            warn_threshold=18.0,
        )


@dataclass
class ParanoidDpi:
    """Paranoid DPI simulator with aggressive detection rules."""
    config: DpiConfig = field(default_factory=DpiConfig)
    size_history: deque = field(default_factory=lambda: deque(maxlen=50))
    timing_history: deque = field(default_factory=lambda: deque(maxlen=50))
    direction_history: deque = field(default_factory=lambda: deque(maxlen=50))
    consecutive_similar: int = 0
    total_packets: int = 0
    suspicion_score: float = 0.0

    def __post_init__(self):
        self.size_history = deque(maxlen=self.config.window_size)
        self.timing_history = deque(maxlen=self.config.window_size)
        self.direction_history = deque(maxlen=self.config.window_size)

    def reset(self):
        """Reset DPI state."""
        self.size_history.clear()
        self.timing_history.clear()
        self.direction_history.clear()
        self.consecutive_similar = 0
        self.total_packets = 0
        self.suspicion_score = 0.0

    def analyze_packet(
        self, size: int, delay_ms: float, direction: int
    ) -> Tuple[DpiVerdict, float, List[str]]:
        """Analyze a packet and return DPI verdict.

        Returns:
            Tuple of (verdict, suspicion_score, reasons)
        """
        self.total_packets += 1

        # Update histories
        self.size_history.append(size)
        self.timing_history.append(delay_ms)
        self.direction_history.append(direction)

        # Reset suspicion with decay
        self.suspicion_score *= 0.95

        # Run all detection checks
        reasons = []

        if self.config.check_size_patterns:
            if reason := self._check_size_patterns(size):
                reasons.append(reason)

        if self.config.check_timing:
            if reason := self._check_timing_patterns(delay_ms):
                reasons.append(reason)

        if self.config.check_direction_ratio:
            if reason := self._check_direction_ratio():
                reasons.append(reason)

        if self.config.check_entropy:
            if reason := self._check_size_entropy():
                reasons.append(reason)

        if self.config.check_bursts:
            if reason := self._check_burst_patterns():
                reasons.append(reason)

        # Additional VPN-specific checks
        if reason := self._check_mtu_signatures(size):
            reasons.append(reason)

        if reason := self._check_keepalive_patterns(size, delay_ms):
            reasons.append(reason)

        # Determine verdict
        if self.suspicion_score >= self.config.block_threshold:
            verdict = DpiVerdict.BLOCKED
        elif self.suspicion_score >= self.config.warn_threshold:
            verdict = DpiVerdict.SUSPICIOUS
        else:
            verdict = DpiVerdict.PASS

        return verdict, self.suspicion_score, reasons

    def _check_size_patterns(self, size: int) -> Optional[str]:
        """Check for VPN-like size patterns."""
        # Check for consecutive similar sizes
        if len(self.size_history) > 1:
            last_size = list(self.size_history)[-2]
            diff = abs(size - last_size)
            if diff < 10:
                self.consecutive_similar += 1
                if self.consecutive_similar > 5:
                    self.suspicion_score += 8.0
                    return "consecutive similar sizes"
            else:
                self.consecutive_similar = 0

        # Check for fixed-size patterns (common in VPN protocols)
        common_vpn_sizes = [64, 128, 256, 512, 1024, 1280, 1400, 1420, 1440, 1460]
        if size in common_vpn_sizes:
            self.suspicion_score += 3.0
            return f"common VPN packet size: {size}"

        # Check for MTU-aligned sizes
        if size in [1500, 1492, 1472]:
            self.suspicion_score += 5.0
            return "MTU-aligned packet"

        return None

    def _check_timing_patterns(self, delay_ms: float) -> Optional[str]:
        """Check for VPN-like timing patterns."""
        if len(self.timing_history) < 5:
            return None

        times = list(self.timing_history)
        mean = np.mean(times)
        std_dev = np.std(times)

        # Very regular timing is suspicious (VPN keepalive)
        if std_dev < 2.0 and mean > 10.0:
            self.suspicion_score += 12.0
            return f"regular timing (std_dev: {std_dev:.2f}ms)"

        # Very low latency bursts (tunnel traffic)
        rapid_count = sum(1 for t in times if t < 1.0)
        if delay_ms < 1.0 and rapid_count > 3:
            self.suspicion_score += 6.0
            return "rapid packet bursts"

        # Check for periodic patterns
        if len(times) >= 10:
            diffs = [abs(times[i+1] - times[i]) for i in range(len(times)-1)]
            mean_diff = np.mean(diffs)
            periodic = sum(1 for d in diffs if abs(d - mean_diff) < 5.0)
            if periodic > len(diffs) * 0.7:
                self.suspicion_score += 15.0
                return "periodic timing pattern"

        return None

    def _check_direction_ratio(self) -> Optional[str]:
        """Check direction ratio (VPN typically has more balanced ratio)."""
        if len(self.direction_history) < 20:
            return None

        directions = list(self.direction_history)
        outbound = sum(1 for d in directions if d > 0)
        ratio = outbound / len(directions)

        # VPN traffic often has balanced ratio (0.4-0.6)
        # Real browsing is more asymmetric (0.1-0.3 outbound)
        if 0.4 <= ratio <= 0.6:
            self.suspicion_score += 8.0
            return f"balanced direction ratio: {ratio:.2f}"

        return None

    def _check_size_entropy(self) -> Optional[str]:
        """Check size entropy (VPN has lower entropy due to padding)."""
        if len(self.size_history) < 20:
            return None

        # Bucket sizes and calculate entropy
        sizes = list(self.size_history)
        buckets = [0] * 16
        for size in sizes:
            bucket = min(size // 100, 15)
            buckets[bucket] += 1

        total = len(sizes)
        entropy = 0.0
        for count in buckets:
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)

        # Low entropy = more uniform = suspicious
        if entropy < 1.5:
            self.suspicion_score += 10.0
            return f"low size entropy: {entropy:.2f}"

        # Very high entropy with many unique sizes = also suspicious (random padding)
        if entropy > 3.5:
            self.suspicion_score += 5.0
            return f"high size entropy (random padding?): {entropy:.2f}"

        return None

    def _check_burst_patterns(self) -> Optional[str]:
        """Check for burst patterns typical of tunneled traffic."""
        if len(self.timing_history) < 10:
            return None

        times = list(self.timing_history)
        rapid_count = sum(1 for t in times if t < 5.0)
        rapid_ratio = rapid_count / len(times)

        if rapid_ratio > 0.6:
            self.suspicion_score += 10.0
            return f"high burst ratio: {rapid_ratio*100:.1f}%"

        return None

    def _check_mtu_signatures(self, size: int) -> Optional[str]:
        """Check for MTU-related signatures."""
        # WireGuard-like sizes (148 header + payload)
        if size > 148 and (size - 148) % 16 == 0:
            self.suspicion_score += 4.0
            return "WireGuard-like alignment"

        # OpenVPN-like sizes
        if size > 48 and (size - 48) % 16 == 0:
            self.suspicion_score += 3.0
            return "OpenVPN-like alignment"

        # IPsec ESP patterns
        if size > 20 and (size - 20) % 8 == 0 and size > 100:
            self.suspicion_score += 2.0

        return None

    def _check_keepalive_patterns(self, size: int, delay_ms: float) -> Optional[str]:
        """Check for keepalive patterns."""
        # Small packets with regular timing = keepalive
        if size < 100 and delay_ms > 1000:
            small_count = sum(1 for s in self.size_history if s < 100)
            if small_count > len(self.size_history) / 3:
                self.suspicion_score += 7.0
                return "keepalive pattern detected"

        return None


def compute_dpi_loss_batch(
    sizes: np.ndarray,
    delays: np.ndarray,
    directions: np.ndarray,
    padding_applied: np.ndarray,
    delay_applied: np.ndarray,
    config: DpiConfig = None,
) -> Tuple[np.ndarray, np.ndarray]:
    """Compute DPI detection scores for a batch of morphed traffic.

    Args:
        sizes: Original packet sizes [batch, seq_len]
        delays: Original delays [batch, seq_len]
        directions: Packet directions [batch, seq_len]
        padding_applied: Model's padding decisions [batch]
        delay_applied: Model's delay decisions [batch]
        config: DPI config (defaults to China GFW)

    Returns:
        Tuple of (detection_scores, suspicion_history) for adversarial loss
    """
    if config is None:
        config = DpiConfig.china_gfw()

    batch_size = sizes.shape[0]
    detection_scores = np.zeros(batch_size)

    for i in range(batch_size):
        dpi = ParanoidDpi(config=config)

        # Apply morphing to last packet (model's decision)
        seq_len = sizes.shape[1]

        for j in range(seq_len):
            size = int(sizes[i, j])
            delay = float(delays[i, j])
            direction = int(directions[i, j])

            # Apply morphing to last packet
            if j == seq_len - 1:
                size = size + int(padding_applied[i] * 1500)  # padding_norm to bytes
                delay = delay + float(delay_applied[i])  # add delay_ms

            verdict, score, _ = dpi.analyze_packet(size, delay, direction)

        detection_scores[i] = score

    return detection_scores


def evaluate_morphing_effectiveness(
    raw_traffic: List[Tuple[int, float, int]],
    morphed_traffic: List[Tuple[int, float, int]],
    config: DpiConfig = None,
) -> Tuple[float, float]:
    """Compare DPI detection rates between raw and morphed traffic.

    Returns:
        Tuple of (raw_detection_rate, morphed_detection_rate)
    """
    if config is None:
        config = DpiConfig.china_gfw()

    # Test raw traffic
    dpi_raw = ParanoidDpi(config=config)
    raw_blocked = 0
    for size, delay, direction in raw_traffic:
        verdict, _, _ = dpi_raw.analyze_packet(size, delay, direction)
        if verdict == DpiVerdict.BLOCKED:
            raw_blocked += 1

    # Test morphed traffic
    dpi_morphed = ParanoidDpi(config=config)
    morphed_blocked = 0
    for size, delay, direction in morphed_traffic:
        verdict, _, _ = dpi_morphed.analyze_packet(size, delay, direction)
        if verdict == DpiVerdict.BLOCKED:
            morphed_blocked += 1

    return raw_blocked / len(raw_traffic), morphed_blocked / len(morphed_traffic)
