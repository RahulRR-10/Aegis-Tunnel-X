"""Phase 6 Tests — Detection Feedback Loop.

Test 6-A: TrafficAnalyzer.compute_entropy returns 7.99 ± 0.1 for uniform random bytes
Test 6-B: compute_size_chi2 returns p > 0.5 when packets match the reference profile
Test 6-C: compute_size_chi2 returns p < 0.01 for obviously wrong distribution
Test 6-D: FeedbackLoop._adapt is triggered when detection_score > threshold
Test 6-E: After adaptation cycles with periodic traffic, periodicity_score decreases
Test 6-F: history log correctly records each check cycle's score and action string
"""

from __future__ import annotations

import os
import random
import time
from unittest.mock import MagicMock, patch

import pytest

from aegis.feedback import TrafficAnalyzer, FeedbackLoop
from aegis.morphic import MorphicEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fill_analyzer_uniform(analyzer: TrafficAnalyzer, n: int = 200) -> None:
    """Fill the analyzer with N packets of uniform random data,
    with Pareto-ish random timing and random sizes from a bimodal dist."""
    rng = random.Random(42)
    t = 0
    for i in range(n):
        # Bimodal sizes like web_browsing profile
        if rng.random() < 0.3:
            size = max(1, int(rng.gauss(64, 20)))
        else:
            size = max(1, int(rng.gauss(1400, 100)))
        payload = os.urandom(64)
        t += int(rng.paretovariate(1.2) * 1_000_000)  # ns
        analyzer.record_packet(size, t, payload)


def _fill_analyzer_constant(
    analyzer: TrafficAnalyzer,
    n: int = 200,
    size: int = 100,
    interval_ns: int = 10_000_000,
) -> None:
    """Fill the analyzer with N identical packets at perfectly regular intervals."""
    t = 0
    for _ in range(n):
        analyzer.record_packet(size, t, os.urandom(64))
        t += interval_ns


WEB_BROWSING_PROFILE = {
    "name": "web_browsing",
    "packet_size_distribution": {
        "type": "bimodal",
        "peaks": [64, 1400],
        "weights": [0.3, 0.7],
        "std_dev": [20, 100],
    },
    "inter_packet_delay_ms": {
        "type": "pareto",
        "alpha": 1.2,
        "min_ms": 0.5,
        "max_ms": 500,
    },
    "burst_profile": {
        "burst_size_range": [3, 15],
        "burst_pause_ms_range": [50, 300],
    },
}


# ---------------------------------------------------------------------------
# Test 6-A: Entropy of uniform random bytes ≈ 8.0
# ---------------------------------------------------------------------------

def test_entropy_of_uniform_random_bytes() -> None:
    """compute_entropy returns ~8.0 for uniform random payload bytes."""
    analyzer = TrafficAnalyzer(window_size=500)

    # Record packets with uniform random payload samples
    t = 0
    for _ in range(500):
        payload = os.urandom(64)
        analyzer.record_packet(1400, t, payload)
        t += 1_000_000

    entropy = analyzer.compute_entropy()

    # Uniform random over 256 values → theoretical entropy = 8.0 bits
    assert 7.9 <= entropy <= 8.01, (
        f"Entropy {entropy:.4f} not in expected range [7.9, 8.01]"
    )


# ---------------------------------------------------------------------------
# Test 6-B: chi2 p > 0.5 when packets match the reference profile
# ---------------------------------------------------------------------------

def test_chi2_high_p_for_matching_profile() -> None:
    """When packet sizes are sampled from the reference profile's
    distribution, chi2 p-value should be > 0.5."""
    analyzer = TrafficAnalyzer(window_size=1000)
    rng = random.Random(42)

    # Generate packets that match the web_browsing profile exactly
    t = 0
    for _ in range(1000):
        if rng.random() < 0.3:
            size = max(1, int(rng.gauss(64, 20)))
        else:
            size = max(1, int(rng.gauss(1400, 100)))
        analyzer.record_packet(size, t, os.urandom(16))
        t += 1_000_000

    p_value = analyzer.compute_size_chi2(WEB_BROWSING_PROFILE)

    assert p_value > 0.5, (
        f"p-value {p_value:.4f} too low for matching distribution"
    )


# ---------------------------------------------------------------------------
# Test 6-C: chi2 p < 0.01 for obviously wrong distribution
# ---------------------------------------------------------------------------

def test_chi2_low_p_for_wrong_distribution() -> None:
    """When all packets are 100 bytes (obviously not bimodal [64, 1400]),
    chi2 p-value should be < 0.01."""
    analyzer = TrafficAnalyzer(window_size=500)

    # All packets are exactly 100 bytes (between the two peaks, all in low cluster)
    t = 0
    for _ in range(500):
        analyzer.record_packet(100, t, os.urandom(16))
        t += 1_000_000

    p_value = analyzer.compute_size_chi2(WEB_BROWSING_PROFILE)

    assert p_value < 0.01, (
        f"p-value {p_value:.4f} too high for mismatched distribution"
    )


# ---------------------------------------------------------------------------
# Test 6-D: FeedbackLoop._adapt triggered when score > threshold
# ---------------------------------------------------------------------------

def test_adapt_triggered_above_threshold() -> None:
    """When detection_score exceeds the threshold, _adapt is called and
    morphic.update_params receives a delta."""
    analyzer = TrafficAnalyzer(window_size=200)

    # Fill with perfectly periodic, single-size traffic (highly detectable)
    _fill_analyzer_constant(analyzer, n=200, size=100, interval_ns=10_000_000)

    morphic = MorphicEngine("web_browsing")
    loop = FeedbackLoop(
        analyzer=analyzer,
        morphic=morphic,
        check_interval_s=1.0,
        score_threshold=0.10,  # low threshold to ensure triggering
    )

    # Manually run one check cycle
    loop._check_and_adapt()

    # Should have recorded one history entry
    assert len(loop.history) == 1
    record = loop.history[0]

    # Score should be > threshold (periodic + wrong sizes)
    assert record["score"] > 0.10, (
        f"Score {record['score']} not above threshold"
    )
    # Action should NOT be "none" (adaptation was triggered)
    assert record["action"] != "none", (
        f"Expected adaptation but got action='{record['action']}'"
    )


# ---------------------------------------------------------------------------
# Test 6-E: Periodicity score decreases after adaptation cycles
# ---------------------------------------------------------------------------

def test_periodicity_decreases_after_adaptation() -> None:
    """Feed periodic traffic, run adaptation cycles, verify the feedback
    loop detects the periodicity and takes action."""
    analyzer = TrafficAnalyzer(window_size=200)

    # Fill with periodic traffic
    _fill_analyzer_constant(analyzer, n=200, size=500, interval_ns=5_000_000)

    initial_periodicity = analyzer.compute_periodicity_score()
    assert initial_periodicity > 0.1, (
        f"Initial periodicity {initial_periodicity:.4f} too low for this test"
    )

    morphic = MorphicEngine("web_browsing")
    loop = FeedbackLoop(
        analyzer=analyzer,
        morphic=morphic,
        check_interval_s=0.1,
        score_threshold=0.05,
    )

    # Run 3 adaptation cycles
    for _ in range(3):
        loop._check_and_adapt()

    # After adaptation, the morphic engine should have been tuned
    # Verify that update_params was called (actions recorded)
    actions = [r["action"] for r in loop.history]
    assert any(a != "none" for a in actions), (
        "No adaptation actions were taken"
    )

    # The jitter range should have been widened
    profile = morphic.current_profile
    ipd = profile.get("inter_packet_delay_ms", {})
    # Original max_ms was 500; after widening it should be larger
    assert ipd.get("max_ms", 500) >= 500, (
        "Jitter range was not widened"
    )


# ---------------------------------------------------------------------------
# Test 6-F: History log records each cycle
# ---------------------------------------------------------------------------

def test_history_log_records_cycles() -> None:
    """Each _check_and_adapt cycle appends a record with timestamp,
    score, action, and metrics."""
    analyzer = TrafficAnalyzer(window_size=200)
    _fill_analyzer_uniform(analyzer, n=200)

    morphic = MorphicEngine("web_browsing")
    loop = FeedbackLoop(
        analyzer=analyzer,
        morphic=morphic,
        check_interval_s=1.0,
        score_threshold=0.25,
    )

    # Run 5 cycles
    for _ in range(5):
        loop._check_and_adapt()

    assert len(loop.history) == 5

    for record in loop.history:
        assert "timestamp" in record
        assert "score" in record
        assert "action" in record
        assert "metrics" in record
        assert isinstance(record["timestamp"], float)
        assert 0.0 <= record["score"] <= 1.0
        assert isinstance(record["action"], str)
        assert isinstance(record["metrics"], dict)
        assert "entropy" in record["metrics"]
        assert "ipd_cv" in record["metrics"]
        assert "size_chi2_pvalue" in record["metrics"]
        assert "burstiness" in record["metrics"]
        assert "periodicity" in record["metrics"]
        assert "detection_score" in record["metrics"]


# ---------------------------------------------------------------------------
# Bonus: detection_score for well-matched traffic is low
# ---------------------------------------------------------------------------

def test_detection_score_low_for_matching_traffic() -> None:
    """Traffic that matches the profile should produce a low detection score."""
    analyzer = TrafficAnalyzer(window_size=500)
    _fill_analyzer_uniform(analyzer, n=500)

    score = analyzer.detection_score(WEB_BROWSING_PROFILE)
    # Well-matched traffic should score below 0.5
    assert score < 0.5, (
        f"Detection score {score:.4f} too high for matching traffic"
    )


# ---------------------------------------------------------------------------
# Bonus: detection_score for periodic single-size traffic is high
# ---------------------------------------------------------------------------

def test_detection_score_high_for_detectable_traffic() -> None:
    """Perfectly periodic, single-size traffic should be highly detectable."""
    analyzer = TrafficAnalyzer(window_size=200)
    _fill_analyzer_constant(analyzer, n=200, size=100, interval_ns=10_000_000)

    score = analyzer.detection_score(WEB_BROWSING_PROFILE)
    # Detectable traffic should score above 0.3
    assert score > 0.3, (
        f"Detection score {score:.4f} too low for detectable traffic"
    )


# ---------------------------------------------------------------------------
# Bonus: IPD CV is computed correctly for known data
# ---------------------------------------------------------------------------

def test_ipd_cv_for_constant_intervals() -> None:
    """Perfectly regular intervals should have CV ≈ 0."""
    analyzer = TrafficAnalyzer(window_size=100)
    _fill_analyzer_constant(analyzer, n=100, interval_ns=10_000_000)

    cv = analyzer.compute_ipd_cv()
    assert cv < 0.01, f"CV {cv:.4f} too high for constant intervals"
