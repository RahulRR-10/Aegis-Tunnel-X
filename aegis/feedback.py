"""Phase 6 — Detection Feedback Loop.

Continuously measures the statistical detectability of outgoing tunnel
traffic and automatically tunes the morphic engine to minimise the
detection probability score.

Metrics computed on a rolling window of the last N packets:
  - Shannon entropy of payload bytes
  - Inter-packet delay coefficient of variation (CV)
  - Packet-size chi-squared goodness-of-fit against the reference profile
  - Burstiness index (Fano factor of packet counts per 100 ms bin)
  - Periodicity score (autocorrelation of IPDs at lags 1–10)

Composite detection score ∈ [0.0, 1.0]:
  0.0 = perfectly mimics the profile (undetectable)
  1.0 = trivially distinguishable from real traffic

Classes:
  TrafficAnalyzer — records packets, computes the five metrics and the
                    composite detection score.
  FeedbackLoop   — periodically reads the analyzer, triggers adaptive
                    tuning on the morphic engine when the score is too high.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import math
import os
import time
from typing import Any

__all__ = ["TrafficAnalyzer", "FeedbackLoop"]

logger = logging.getLogger("aegis.feedback")


# ===================================================================
# TrafficAnalyzer
# ===================================================================

class TrafficAnalyzer:
    """Rolling-window traffic analyser for detectability metrics.

    Records packet metadata (size, timestamp, a payload sample) in a
    fixed-size circular buffer and exposes five statistical metrics plus
    a composite detection score.

    Args:
        window_size: Number of most-recent packets to keep.
    """

    def __init__(self, window_size: int = 200) -> None:
        self._window_size = window_size

        # Ring buffers
        self._sizes: collections.deque[int] = collections.deque(maxlen=window_size)
        self._timestamps_ns: collections.deque[int] = collections.deque(maxlen=window_size)
        self._payload_bytes: bytearray = bytearray()
        self._max_payload_bytes = window_size * 64  # keep ~64 B sample per pkt

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_packet(
        self,
        size: int,
        timestamp_ns: int,
        payload_sample: bytes,
    ) -> None:
        """Record one outgoing packet for analysis.

        Args:
            size:            Total packet size in bytes.
            timestamp_ns:    Monotonic timestamp in nanoseconds.
            payload_sample:  First N bytes of the encrypted payload
                             (used for entropy calculation).
        """
        self._sizes.append(size)
        self._timestamps_ns.append(timestamp_ns)
        self._payload_bytes.extend(payload_sample[:64])
        # Trim payload buffer to cap memory
        if len(self._payload_bytes) > self._max_payload_bytes:
            self._payload_bytes = self._payload_bytes[-self._max_payload_bytes:]

    @property
    def sample_count(self) -> int:
        """Number of packets currently in the window."""
        return len(self._sizes)

    # ------------------------------------------------------------------
    # Metric 1: Shannon entropy of payload bytes
    # ------------------------------------------------------------------

    def compute_entropy(self) -> float:
        """Shannon entropy (bits) of recorded payload bytes.

        Uniform random data → ~8.0.  Structured/compressible data → lower.
        """
        if not self._payload_bytes:
            return 0.0

        counts = collections.Counter(self._payload_bytes)
        n = len(self._payload_bytes)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ------------------------------------------------------------------
    # Metric 2: Inter-packet delay coefficient of variation
    # ------------------------------------------------------------------

    def compute_ipd_cv(self) -> float:
        """Coefficient of variation of inter-packet delays.

        CV = std_dev / mean.  A higher CV means more variable timing.
        """
        ipds = self._get_ipds_ms()
        if len(ipds) < 2:
            return 0.0

        mean = sum(ipds) / len(ipds)
        if mean == 0:
            return 0.0
        variance = sum((x - mean) ** 2 for x in ipds) / len(ipds)
        std_dev = math.sqrt(variance)
        return std_dev / mean

    # ------------------------------------------------------------------
    # Metric 3: Packet-size chi-squared (returns p-value)
    # ------------------------------------------------------------------

    def compute_size_chi2(self, reference_profile: dict) -> float:
        """Chi-squared goodness-of-fit of observed packet sizes against
        the reference profile's expected bimodal distribution.

        Returns an approximate p-value: >0.05 means the observed sizes
        are consistent with the profile.

        Args:
            reference_profile: The traffic profile dict (with
                               ``packet_size_distribution``).
        """
        if len(self._sizes) < 10:
            return 1.0  # not enough data

        dist = reference_profile.get("packet_size_distribution", {})
        peaks = dist.get("peaks", [1400])
        weights = dist.get("weights", [1.0])

        # Bin observed sizes into two clusters around a midpoint
        if len(peaks) >= 2:
            midpoint = (peaks[0] + peaks[1]) / 2.0
        else:
            midpoint = peaks[0]

        n = len(self._sizes)
        observed_low = sum(1 for s in self._sizes if s < midpoint)
        observed_high = n - observed_low

        # Expected counts from profile weights
        w_total = sum(weights)
        expected_low = n * (weights[0] / w_total) if len(weights) >= 2 else 0
        expected_high = n * (weights[-1] / w_total) if len(weights) >= 2 else n

        # Avoid division by zero
        if expected_low < 1:
            expected_low = 1
        if expected_high < 1:
            expected_high = 1

        chi2 = ((observed_low - expected_low) ** 2 / expected_low +
                (observed_high - expected_high) ** 2 / expected_high)

        # Approximate p-value for chi2 with df=1
        # Using the complementary error function approximation
        p_value = math.exp(-chi2 / 2.0)
        return min(p_value, 1.0)

    # ------------------------------------------------------------------
    # Metric 4: Burstiness (Fano factor)
    # ------------------------------------------------------------------

    def compute_burstiness(self) -> float:
        """Fano factor of packet counts per 100 ms bin.

        Fano = variance(counts) / mean(counts).
        Poisson process → Fano ≈ 1.  Bursty traffic → Fano > 1.
        """
        if len(self._timestamps_ns) < 2:
            return 1.0

        bin_width_ns = 100_000_000  # 100 ms
        ts = sorted(self._timestamps_ns)
        t_start = ts[0]
        t_end = ts[-1]

        if t_end <= t_start:
            return 1.0

        num_bins = max(1, int((t_end - t_start) / bin_width_ns) + 1)
        bins = [0] * num_bins

        for t in ts:
            idx = min(int((t - t_start) / bin_width_ns), num_bins - 1)
            bins[idx] += 1

        mean = sum(bins) / len(bins)
        if mean == 0:
            return 1.0
        variance = sum((b - mean) ** 2 for b in bins) / len(bins)
        return variance / mean

    # ------------------------------------------------------------------
    # Metric 5: Periodicity score (autocorrelation)
    # ------------------------------------------------------------------

    def compute_periodicity_score(self) -> float:
        """Maximum autocorrelation of IPDs at lags 1–10.

        Periodic traffic (e.g., constant-rate) produces high autocorrelation.
        Returns a value in [0.0, 1.0]; <0.15 is non-periodic.
        """
        ipds = self._get_ipds_ms()
        if len(ipds) < 12:
            return 0.0

        mean = sum(ipds) / len(ipds)
        var = sum((x - mean) ** 2 for x in ipds) / len(ipds)
        if var == 0:
            return 1.0  # perfectly periodic

        max_autocorr = 0.0
        for lag in range(1, min(11, len(ipds))):
            cov = sum(
                (ipds[i] - mean) * (ipds[i + lag] - mean)
                for i in range(len(ipds) - lag)
            ) / (len(ipds) - lag)
            autocorr = abs(cov / var)
            max_autocorr = max(max_autocorr, autocorr)

        return min(max_autocorr, 1.0)

    # ------------------------------------------------------------------
    # Composite detection score
    # ------------------------------------------------------------------

    def detection_score(self, reference_profile: dict) -> float:
        """Composite detection probability score in [0.0, 1.0].

        Weighted average of normalised deviations from the reference
        profile.  Lower is better (less detectable).
        """
        if self.sample_count < 5:
            return 0.0

        entropy = self.compute_entropy()
        ipd_cv = self.compute_ipd_cv()
        chi2_p = self.compute_size_chi2(reference_profile)
        burstiness = self.compute_burstiness()
        periodicity = self.compute_periodicity_score()

        # Normalise each metric to [0, 1] deviation
        # Entropy: ideal is ~8.0 for encrypted data
        entropy_dev = min(abs(entropy - 8.0) / 4.0, 1.0) if entropy > 0 else 1.0

        # IPD CV: compare to profile's expected CV (~1.5 for Pareto)
        ipd_dist = reference_profile.get("inter_packet_delay_ms", {})
        alpha = ipd_dist.get("alpha", 1.5)
        # Theoretical CV of Pareto: sqrt(alpha / ((alpha-1)^2 * (alpha-2)))
        # For alpha > 2; otherwise CV is infinite → we target a moderate CV
        target_cv = 1.0 if alpha <= 2 else math.sqrt(alpha / ((alpha - 1) ** 2 * (alpha - 2)))
        ipd_dev = min(abs(ipd_cv - target_cv) / max(target_cv, 0.5), 1.0)

        # Chi-squared p-value: higher is better; 1.0 = perfect match
        chi2_dev = 1.0 - chi2_p

        # Burstiness: Fano ≈ 1 is Poisson; deviation from expected
        burst_profile = reference_profile.get("burst_profile", {})
        expected_fano = 2.0  # moderate burstiness expected
        burstiness_dev = min(abs(burstiness - expected_fano) / max(expected_fano, 1.0), 1.0)

        # Periodicity: 0 is ideal, 1 is perfectly periodic
        periodicity_dev = periodicity

        # Weighted average
        weights = {
            "entropy": 0.15,
            "ipd_cv": 0.25,
            "chi2": 0.25,
            "burstiness": 0.15,
            "periodicity": 0.20,
        }

        score = (
            weights["entropy"] * entropy_dev
            + weights["ipd_cv"] * ipd_dev
            + weights["chi2"] * chi2_dev
            + weights["burstiness"] * burstiness_dev
            + weights["periodicity"] * periodicity_dev
        )

        return max(0.0, min(score, 1.0))

    # ------------------------------------------------------------------
    # Individual metrics as a dict (for logging / history)
    # ------------------------------------------------------------------

    def metrics(self, reference_profile: dict) -> dict[str, float]:
        """Return all metrics as a dict."""
        return {
            "entropy": self.compute_entropy(),
            "ipd_cv": self.compute_ipd_cv(),
            "size_chi2_pvalue": self.compute_size_chi2(reference_profile),
            "burstiness": self.compute_burstiness(),
            "periodicity": self.compute_periodicity_score(),
            "detection_score": self.detection_score(reference_profile),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_ipds_ms(self) -> list[float]:
        """Compute inter-packet delays in milliseconds."""
        if len(self._timestamps_ns) < 2:
            return []
        ts = list(self._timestamps_ns)
        return [(ts[i + 1] - ts[i]) / 1_000_000.0 for i in range(len(ts) - 1)]


# ===================================================================
# FeedbackLoop
# ===================================================================

class FeedbackLoop:
    """Periodic detection-score check and adaptive morphic tuning.

    Every ``check_interval_s`` seconds:
      1. Compute the detection score from the analyzer.
      2. If score > ``score_threshold``, call ``_adapt()`` to tweak
         the morphic engine's parameters.
      3. Log the result to ``history``.

    Args:
        analyzer:         A ``TrafficAnalyzer`` instance.
        morphic:          A ``MorphicEngine`` instance to tune.
        check_interval_s: Seconds between detection checks.
        score_threshold:  Adaptation is triggered above this score.
    """

    def __init__(
        self,
        analyzer: TrafficAnalyzer,
        morphic: Any,
        check_interval_s: float = 2.0,
        score_threshold: float = 0.25,
    ) -> None:
        self._analyzer = analyzer
        self._morphic = morphic
        self._check_interval_s = check_interval_s
        self._score_threshold = score_threshold
        self._history: list[dict[str, Any]] = []
        self._running = False

    @property
    def history(self) -> list[dict[str, Any]]:
        """Last 100 ``{timestamp, score, action, metrics}`` records."""
        return self._history[-100:]

    @property
    def is_running(self) -> bool:
        return self._running

    async def run(self) -> None:
        """Long-running feedback loop — cancel the task to stop."""
        self._running = True
        while self._running:
            await asyncio.sleep(self._check_interval_s)
            self._check_and_adapt()

    def stop(self) -> None:
        """Signal the loop to stop."""
        self._running = False

    def _check_and_adapt(self) -> None:
        """Single check-adapt cycle (also callable directly for testing)."""
        profile = self._morphic.current_profile
        score = self._analyzer.detection_score(profile)
        all_metrics = self._analyzer.metrics(profile)
        action = "none"

        if score > self._score_threshold:
            action = self._adapt(score, all_metrics)

        record = {
            "timestamp": time.time(),
            "score": round(score, 4),
            "action": action,
            "metrics": {k: round(v, 4) for k, v in all_metrics.items()},
        }
        self._history.append(record)

        # Keep only last 100 records
        if len(self._history) > 100:
            self._history = self._history[-100:]

        logger.debug(
            "Feedback: score=%.4f action=%s", score, action
        )

    def _adapt(self, score: float, metrics: dict[str, float]) -> str:
        """Apply adaptive tuning to the morphic engine.

        Returns a string describing the action taken.
        """
        actions: list[str] = []
        delta: dict[str, Any] = {}

        # 1. Periodicity too high → inject jitter randomness
        periodicity = metrics.get("periodicity", 0.0)
        if periodicity > 0.15:
            ipd = self._morphic.current_profile.get(
                "inter_packet_delay_ms", {}
            )
            current_max = ipd.get("max_ms", 500)
            delta["inter_packet_delay_ms"] = {
                "max_ms": current_max * 1.1  # widen jitter range by 10%
            }
            actions.append("widen_jitter")

        # 2. Size distribution mismatch → nudge peaks
        chi2_p = metrics.get("size_chi2_pvalue", 1.0)
        if chi2_p < 0.10:
            dist = self._morphic.current_profile.get(
                "packet_size_distribution", {}
            )
            peaks = dist.get("peaks", [])
            std_devs = dist.get("std_dev", [])
            # Increase std_dev by 5% to broaden the distribution
            new_std = [s * 1.05 for s in std_devs]
            delta["packet_size_distribution"] = {"std_dev": new_std}
            actions.append("broaden_sizes")

        # 3. IPD CV mismatch → adjust alpha
        ipd_cv = metrics.get("ipd_cv", 0.0)
        ipd_dist = self._morphic.current_profile.get(
            "inter_packet_delay_ms", {}
        )
        alpha = ipd_dist.get("alpha", 1.5)
        target_cv = 1.0 if alpha <= 2 else math.sqrt(
            alpha / ((alpha - 1) ** 2 * (alpha - 2))
        )
        if abs(ipd_cv - target_cv) > 0.15 * max(target_cv, 0.5):
            # Nudge alpha toward the direction that reduces CV gap
            if ipd_cv > target_cv:
                new_alpha = alpha * 1.05
            else:
                new_alpha = alpha * 0.95
            if "inter_packet_delay_ms" not in delta:
                delta["inter_packet_delay_ms"] = {}
            delta["inter_packet_delay_ms"]["alpha"] = new_alpha
            actions.append("tune_ipd_alpha")

        # Apply changes if any
        if delta:
            self._morphic.update_params(delta)

        return "+".join(actions) if actions else "nudge"
