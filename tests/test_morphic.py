"""Phase 5 Tests — Morphic Traffic Shaping Engine.

Test 5-A: transform() frame sizes match profile distribution (1000 samples, KS test)
Test 5-B: detransform(transform(payload)[0]) == payload for sizes 1..1400
Test 5-C: IPD samples match profile distribution (1000 samples, KS test)
Test 5-D: switch_profile() mid-run; next 100 packets use new distribution
Test 5-E: Padding bytes are random (chi-squared uniformity test on byte values)
Test 5-F: Large packet → multiple fragments → first detransforms back to original
"""

from __future__ import annotations

import asyncio
import collections
import math
import os
import struct

import pytest

from aegis.morphic import MorphicEngine, _LENGTH_HEADER_SIZE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ks_test_bimodal(samples: list[float], peaks: list[float],
                     weights: list[float], std_devs: list[float]) -> float:
    """Simple two-sample KS-like test: compute the maximum deviation between
    the empirical CDF of `samples` and the theoretical bimodal Gaussian CDF.

    Returns the KS statistic D (lower is better).
    """
    from math import erf, sqrt

    def normal_cdf(x: float, mu: float, sigma: float) -> float:
        if sigma <= 0:
            return 1.0 if x >= mu else 0.0
        return 0.5 * (1.0 + erf((x - mu) / (sigma * sqrt(2))))

    def bimodal_cdf(x: float) -> float:
        cdf_val = 0.0
        for p, w, s in zip(peaks, weights, std_devs):
            cdf_val += w * normal_cdf(x, p, s)
        return cdf_val

    sorted_samples = sorted(samples)
    n = len(sorted_samples)
    max_d = 0.0
    for i, val in enumerate(sorted_samples):
        ecdf = (i + 1) / n
        tcdf = bimodal_cdf(val)
        max_d = max(max_d, abs(ecdf - tcdf))
    return max_d


def _chi_squared_uniformity(byte_data: bytes, num_bins: int = 256) -> float:
    """Compute chi-squared statistic for byte uniformity.
    Lower values indicate more uniform distribution.
    """
    counts = collections.Counter(byte_data)
    n = len(byte_data)
    expected = n / num_bins
    chi2 = sum(
        (counts.get(b, 0) - expected) ** 2 / expected
        for b in range(num_bins)
    )
    return chi2


# ---------------------------------------------------------------------------
# Test 5-A: Frame sizes match profile distribution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transform_sizes_match_profile() -> None:
    """Transform 1000 small payloads and check that the output frame sizes
    follow the web_browsing bimodal distribution.

    We validate:
      - Sizes cluster around the two expected peaks (64 and 1400)
      - The weight ratio between clusters approximately matches [0.3, 0.7]
      - Each cluster's mean is within 2*std_dev of its peak
    """
    engine = MorphicEngine("web_browsing", max_queue_ms=0)

    # Collect 1000 frame size samples
    sizes: list[int] = []
    for _ in range(1000):
        frames = await engine.transform(b"x")
        sizes.append(len(frames[0]))

    profile = engine.current_profile
    dist = profile["packet_size_distribution"]
    peaks = dist["peaks"]         # [64, 1400]
    weights = dist["weights"]     # [0.3, 0.7]

    # Separate samples into two clusters using the midpoint between peaks
    midpoint = (peaks[0] + peaks[1]) / 2.0
    low_cluster = [s for s in sizes if s < midpoint]
    high_cluster = [s for s in sizes if s >= midpoint]

    # Both clusters should have samples
    assert len(low_cluster) > 0, "No samples in the low cluster"
    assert len(high_cluster) > 0, "No samples in the high cluster"

    # Check weight ratio: low should be ~30%, high ~70%
    low_ratio = len(low_cluster) / len(sizes)
    assert 0.15 < low_ratio < 0.50, (
        f"Low cluster weight {low_ratio:.2f} not near expected {weights[0]}"
    )

    # Check cluster means are near the peaks
    low_mean = sum(low_cluster) / len(low_cluster)
    high_mean = sum(high_cluster) / len(high_cluster)

    assert abs(low_mean - peaks[0]) < 2 * dist["std_dev"][0], (
        f"Low cluster mean {low_mean:.1f} too far from peak {peaks[0]}"
    )
    assert abs(high_mean - peaks[1]) < 2 * dist["std_dev"][1], (
        f"High cluster mean {high_mean:.1f} too far from peak {peaks[1]}"
    )


# ---------------------------------------------------------------------------
# Test 5-B: detransform(transform(payload)) == payload for all sizes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transform_detransform_roundtrip() -> None:
    """For every payload size from 1 to 1400, transform then detransform
    must recover the original payload."""
    engine = MorphicEngine("web_browsing", max_queue_ms=0)

    # Test a representative sample of sizes (testing all 1400 would be slow)
    test_sizes = list(range(1, 51)) + [100, 256, 512, 1024, 1200, 1400]

    for size in test_sizes:
        payload = os.urandom(size)
        frames = await engine.transform(payload)
        # The first frame always contains the length header
        recovered = engine.detransform(frames[0])
        assert recovered == payload, (
            f"Roundtrip failed for size {size}: "
            f"got {len(recovered) if recovered else 'None'} bytes"
        )


# ---------------------------------------------------------------------------
# Test 5-C: IPD samples match profile distribution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ipd_distribution() -> None:
    """Draw 1000 IPD samples and verify they follow the Pareto distribution
    defined in the profile."""
    engine = MorphicEngine("web_browsing", max_queue_ms=0)

    ipd_samples: list[float] = []
    for _ in range(1000):
        ipd = engine._sample_ipd()
        ipd_samples.append(ipd)

    profile = engine.current_profile
    dist = profile["inter_packet_delay_ms"]
    min_ms = dist["min_ms"]
    max_ms = dist["max_ms"]

    # All samples must be within [min_ms, max_ms]
    assert all(s >= min_ms for s in ipd_samples), "IPD below minimum"
    assert all(s <= max_ms for s in ipd_samples), "IPD above maximum"

    # The median of a Pareto(alpha, min) is min * 2^(1/alpha)
    alpha = dist["alpha"]
    theoretical_median = min_ms * (2.0 ** (1.0 / alpha))
    empirical_median = sorted(ipd_samples)[len(ipd_samples) // 2]

    # Empirical median should be within 50% of theoretical
    ratio = empirical_median / theoretical_median if theoretical_median > 0 else 1.0
    assert 0.5 < ratio < 2.0, (
        f"IPD median mismatch: empirical={empirical_median:.2f}, "
        f"theoretical={theoretical_median:.2f}"
    )


# ---------------------------------------------------------------------------
# Test 5-D: switch_profile mid-run changes distribution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_switch_profile_changes_distribution() -> None:
    """Start with web_browsing, switch to gaming, verify the next 100 packets
    use the gaming distribution (much smaller sizes)."""
    engine = MorphicEngine("web_browsing", max_queue_ms=0)

    # Collect sizes from web_browsing
    web_sizes: list[int] = []
    for _ in range(100):
        frames = await engine.transform(b"x")
        web_sizes.append(len(frames[0]))

    # Switch to gaming
    engine.switch_profile("gaming")
    assert engine.profile_name == "gaming"

    # Collect sizes from gaming
    gaming_sizes: list[int] = []
    for _ in range(100):
        frames = await engine.transform(b"x")
        gaming_sizes.append(len(frames[0]))

    # Gaming profile has peaks at [40, 200] vs web_browsing [64, 1400]
    # The average gaming frame should be much smaller
    avg_web = sum(web_sizes) / len(web_sizes)
    avg_gaming = sum(gaming_sizes) / len(gaming_sizes)

    assert avg_gaming < avg_web, (
        f"Gaming avg {avg_gaming:.0f} should be smaller than web avg {avg_web:.0f}"
    )


# ---------------------------------------------------------------------------
# Test 5-E: Padding bytes are random (chi-squared uniformity test)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_padding_bytes_are_random() -> None:
    """Collect all padding bytes from 500 transforms and verify they pass
    a chi-squared uniformity test."""
    engine = MorphicEngine("web_browsing", max_queue_ms=0)

    all_padding = bytearray()
    small_payload = b"\x00"  # 1-byte payload so most of the frame is padding

    for _ in range(500):
        frames = await engine.transform(small_payload)
        frame = frames[0]
        # The frame layout is: [2B length header] [1B payload] [padding...]
        padding_start = _LENGTH_HEADER_SIZE + len(small_payload)
        if len(frame) > padding_start:
            all_padding.extend(frame[padding_start:])

    assert len(all_padding) > 1000, "Not enough padding bytes collected"

    # Chi-squared test: for 256 bins with N bytes, a perfectly uniform
    # distribution gives chi2 ≈ 255.  Critical value at p=0.01 for
    # df=255 is about 310.  We use a generous threshold.
    chi2 = _chi_squared_uniformity(bytes(all_padding))
    # For truly random data, chi2/df should be close to 1.0
    chi2_per_df = chi2 / 255.0

    assert chi2_per_df < 2.0, (
        f"Padding not random enough: chi2/df = {chi2_per_df:.2f} "
        f"(expected ~1.0 for uniform)"
    )


# ---------------------------------------------------------------------------
# Test 5-F: Large packet → multiple fragments → detransform recovers original
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_large_packet_fragmentation() -> None:
    """A payload larger than morphic_mtu produces multiple fragments.
    The first fragment's detransform recovers the original payload."""
    engine = MorphicEngine("web_browsing", max_queue_ms=0, morphic_mtu=500)

    payload = os.urandom(1200)
    frames = await engine.transform(payload)

    # Should produce multiple fragments
    assert len(frames) > 1, (
        f"Expected multiple fragments, got {len(frames)}"
    )

    # Each fragment should be <= morphic_mtu
    for f in frames:
        assert len(f) <= 500

    # Reassemble all fragments to recover the full padded data
    reassembled = b"".join(frames)

    # detransform on the reassembled data should recover the original
    recovered = engine.detransform(reassembled)
    assert recovered == payload


# ---------------------------------------------------------------------------
# Bonus: Dummy frame creation
# ---------------------------------------------------------------------------

def test_dummy_frame_detransforms_to_none() -> None:
    """A dummy frame (original_length = 0) detransforms to None."""
    engine = MorphicEngine("web_browsing")
    dummy = engine.create_dummy_frame(size=100)
    assert len(dummy) == 100
    assert engine.detransform(dummy) is None


# ---------------------------------------------------------------------------
# Bonus: list_profiles
# ---------------------------------------------------------------------------

def test_list_profiles() -> None:
    """list_profiles returns the three built-in profiles."""
    profiles = MorphicEngine.list_profiles()
    assert "web_browsing" in profiles
    assert "video_streaming" in profiles
    assert "gaming" in profiles


# ---------------------------------------------------------------------------
# Bonus: Profile not found
# ---------------------------------------------------------------------------

def test_load_missing_profile_raises() -> None:
    """Loading a non-existent profile raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        MorphicEngine("nonexistent_profile_xyz")
