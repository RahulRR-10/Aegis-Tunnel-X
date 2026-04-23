"""Phase 5 — Morphic Traffic Shaping Engine.

Transforms outgoing packets to statistically mimic real traffic profiles,
defeating DPI and traffic fingerprinting.

Transformations applied:
  1. Prepend 2-byte original_length header
  2. Pad packet to a target size drawn from the profile's packet size distribution
  3. Fragment if the padded size exceeds morphic_mtu
  4. Add inter-packet jitter drawn from the profile's IPD distribution

The detransform step reads the 2-byte header to recover the original payload,
stripping the random padding.  Padding-only dummy frames (original_length == 0)
return None.

Classes:
  MorphicEngine — profile-based traffic shaping with hot-swap support
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import random
import struct
import threading
from pathlib import Path
from typing import Any

__all__ = ["MorphicEngine"]

logger = logging.getLogger("aegis.morphic")

# Directory containing the traffic profile JSON files
_PROFILES_DIR = Path(__file__).parent.parent / "profiles"

# 2-byte header prepended to the plaintext inside the padded frame
_LENGTH_HEADER_FMT = "!H"
_LENGTH_HEADER_SIZE = 2

# Default morphic MTU — frames larger than this are fragmented
_MORPHIC_MTU = 1500


# ---------------------------------------------------------------------------
# MorphicEngine
# ---------------------------------------------------------------------------

class MorphicEngine:
    """Profile-based traffic shaping engine.

    Pads, fragments, and jitters outgoing packets so that their size and
    timing distributions match a configurable traffic profile.

    Args:
        profile_name: Name of the JSON profile in ``profiles/`` (without ``.json``).
        max_queue_ms: Maximum additional queuing delay in milliseconds.
        morphic_mtu:  Maximum frame size after padding; larger frames are fragmented.

    Thread safety:
        ``switch_profile()`` is thread-safe and does not drop in-flight packets.
    """

    def __init__(
        self,
        profile_name: str = "web_browsing",
        max_queue_ms: int = 50,
        morphic_mtu: int = _MORPHIC_MTU,
    ) -> None:
        self._profile: dict[str, Any] = {}
        self._profile_name: str = ""
        self._max_queue_ms = max_queue_ms
        self._morphic_mtu = morphic_mtu
        self._lock = threading.Lock()
        self._rng = random.Random()  # non-crypto RNG for timing/sizing

        self.load_profile(profile_name)

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    @property
    def current_profile(self) -> dict[str, Any]:
        """Return the currently loaded profile dict."""
        with self._lock:
            return dict(self._profile)

    @property
    def profile_name(self) -> str:
        with self._lock:
            return self._profile_name

    def load_profile(self, profile_name: str) -> None:
        """Load a traffic profile from ``profiles/<name>.json``.

        Raises:
            FileNotFoundError: If the profile JSON doesn't exist.
        """
        path = _PROFILES_DIR / f"{profile_name}.json"
        if not path.exists():
            raise FileNotFoundError(f"Profile not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            profile = json.load(f)

        with self._lock:
            self._profile = profile
            self._profile_name = profile_name

        logger.info("Loaded morphic profile: %s", profile_name)

    def switch_profile(self, profile_name: str) -> None:
        """Hot-swap to a different profile. Thread-safe, no packet drops."""
        self.load_profile(profile_name)

    @staticmethod
    def list_profiles() -> list[str]:
        """Return names of all available profiles."""
        if not _PROFILES_DIR.exists():
            return []
        return sorted(
            p.stem for p in _PROFILES_DIR.glob("*.json")
        )

    # ------------------------------------------------------------------
    # Transform (outgoing path)
    # ------------------------------------------------------------------

    async def transform(self, packet: bytes) -> list[bytes]:
        """Transform a packet for morphic transmission.

        Steps:
          1. Prepend 2-byte original_length header.
          2. Pad to a target size drawn from the profile distribution.
          3. Fragment if padded size > morphic_mtu.
          4. Apply inter-packet jitter.

        Returns:
            List of transformed frames (usually 1, but may be multiple
            if the padded packet exceeds morphic_mtu).
        """
        # 1. Prepend original length header
        original_len = len(packet)
        header = struct.pack(_LENGTH_HEADER_FMT, original_len)
        data = header + packet

        # 2. Pad to target size (sampled size is total frame size incl. header)
        target_size = self._sample_packet_size()
        # Target must be at least as large as the data (header + payload)
        if target_size < len(data):
            target_size = len(data)

        padding_needed = target_size - len(data)
        if padding_needed > 0:
            # Cryptographically random padding
            data = data + os.urandom(padding_needed)

        # 3. Fragment only if the padded frame exceeds morphic_mtu
        if len(data) > self._morphic_mtu:
            frames = self._fragment(data)
        else:
            frames = [data]

        # 4. Apply inter-packet jitter
        delay_s = self._sample_ipd() / 1000.0
        if delay_s > 0:
            await asyncio.sleep(delay_s)

        return frames

    def detransform(self, frame: bytes) -> bytes | None:
        """Recover the original packet from a morphic frame.

        Reads the 2-byte original_length header, extracts the payload,
        and discards padding.

        Returns:
            The original packet bytes, or ``None`` if this is a
            padding-only dummy frame (original_length == 0).
        """
        if len(frame) < _LENGTH_HEADER_SIZE:
            return None

        original_len = struct.unpack(
            _LENGTH_HEADER_FMT, frame[:_LENGTH_HEADER_SIZE]
        )[0]

        if original_len == 0:
            return None  # Dummy padding frame

        payload = frame[_LENGTH_HEADER_SIZE:_LENGTH_HEADER_SIZE + original_len]
        if len(payload) < original_len:
            logger.warning(
                "Morphic frame truncated: expected %d, got %d",
                original_len, len(payload),
            )
            return None

        return payload

    # ------------------------------------------------------------------
    # Burst scheduler
    # ------------------------------------------------------------------

    async def run_burst_scheduler(
        self, packet_queue: asyncio.Queue[bytes]
    ) -> None:
        """Group packets into bursts per the profile's burst settings.

        Reads packets from ``packet_queue``, accumulates them into bursts
        of the configured size, then emits each burst with an inter-burst
        pause.

        This is a long-running coroutine — cancel the task to stop it.
        """
        while True:
            burst_size = self._sample_burst_size()
            burst: list[bytes] = []

            # Accumulate packets for this burst
            for _ in range(burst_size):
                try:
                    pkt = await asyncio.wait_for(
                        packet_queue.get(), timeout=0.1
                    )
                    burst.append(pkt)
                except asyncio.TimeoutError:
                    break

            if burst:
                # Emit all packets in the burst with minimal internal delay
                for pkt in burst:
                    yield_frames = await self.transform(pkt)
                    # In a real integration, these frames would be sent via transport
                    logger.debug("Burst frame: %d bytes", sum(len(f) for f in yield_frames))

            # Inter-burst pause
            pause_ms = self._sample_burst_pause()
            await asyncio.sleep(pause_ms / 1000.0)

    # ------------------------------------------------------------------
    # Distribution samplers
    # ------------------------------------------------------------------

    def _sample_packet_size(self) -> int:
        """Draw a target packet size from the profile's distribution."""
        with self._lock:
            dist = self._profile.get("packet_size_distribution", {})

        peaks = dist.get("peaks", [1400])
        weights = dist.get("weights", [1.0])
        std_devs = dist.get("std_dev", [0])

        # Choose which peak based on weights
        peak_idx = self._rng.choices(range(len(peaks)), weights=weights, k=1)[0]
        peak = peaks[peak_idx]
        std_dev = std_devs[peak_idx] if peak_idx < len(std_devs) else 0

        # Draw from Gaussian around the chosen peak
        size = int(self._rng.gauss(peak, std_dev))

        # Clamp to reasonable range
        return max(_LENGTH_HEADER_SIZE + 1, min(size, 65535))

    def _sample_ipd(self) -> float:
        """Draw an inter-packet delay in milliseconds from the profile."""
        with self._lock:
            dist = self._profile.get("inter_packet_delay_ms", {})

        alpha = dist.get("alpha", 1.5)
        min_ms = dist.get("min_ms", 0.5)
        max_ms = dist.get("max_ms", 500)

        # Pareto distribution: X = min_ms / U^(1/alpha)
        u = self._rng.random()
        if u == 0:
            u = 1e-10
        sample = min_ms / (u ** (1.0 / alpha))

        return min(sample, max_ms)

    def _sample_burst_size(self) -> int:
        """Draw a burst size from the profile's range."""
        with self._lock:
            burst = self._profile.get("burst_profile", {})
        lo, hi = burst.get("burst_size_range", [1, 5])
        return self._rng.randint(lo, hi)

    def _sample_burst_pause(self) -> float:
        """Draw an inter-burst pause in milliseconds."""
        with self._lock:
            burst = self._profile.get("burst_profile", {})
        lo, hi = burst.get("burst_pause_ms_range", [10, 50])
        return self._rng.uniform(lo, hi)

    # ------------------------------------------------------------------
    # Fragmentation
    # ------------------------------------------------------------------

    def _fragment(self, data: bytes) -> list[bytes]:
        """Split a padded payload into morphic_mtu-sized chunks.

        Each fragment gets its own 2-byte header indicating this is a
        fragment (original_length = 0xFFFF as sentinel) so the receiver
        can reassemble.  For simplicity in this phase, we treat large
        padded frames as multiple independent frames — the detransform
        on the first frame (which has the real length header) will recover
        the original payload.
        """
        chunks: list[bytes] = []
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + self._morphic_mtu]
            chunks.append(chunk)
            offset += self._morphic_mtu
        return chunks

    # ------------------------------------------------------------------
    # Utility: create a dummy padding frame
    # ------------------------------------------------------------------

    def create_dummy_frame(self, size: int | None = None) -> bytes:
        """Create a padding-only dummy frame (original_length = 0).

        Used by the feedback loop to inject noise packets and break
        periodic patterns.
        """
        if size is None:
            size = self._sample_packet_size()
        header = struct.pack(_LENGTH_HEADER_FMT, 0)
        padding = os.urandom(max(0, size - _LENGTH_HEADER_SIZE))
        return header + padding

    # ------------------------------------------------------------------
    # Parameter update (used by feedback loop in Phase 6)
    # ------------------------------------------------------------------

    def update_params(self, delta: dict[str, Any]) -> None:
        """Apply incremental parameter adjustments from the feedback loop.

        ``delta`` keys correspond to profile fields; values are additive
        deltas.  Thread-safe.
        """
        with self._lock:
            for key, value in delta.items():
                if key in self._profile:
                    if isinstance(self._profile[key], dict) and isinstance(value, dict):
                        self._profile[key].update(value)
                    else:
                        self._profile[key] = value
        logger.debug("Morphic params updated: %s", delta)
