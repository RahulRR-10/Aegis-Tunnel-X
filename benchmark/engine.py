import os
import random
import socket
import threading
import time
from typing import List, Optional

from benchmark.config import BenchmarkConfig, PayloadType
from benchmark.metrics import BenchmarkResult, ComparisonResult
from crypto import encrypt as crypto_encrypt, decrypt as crypto_decrypt
from morphic import morph_packet, shannon_entropy


def _make_payload(size: int, seq: int, ptype: PayloadType) -> bytes:
    if ptype == PayloadType.RANDOM:
        return os.urandom(size)
    elif ptype == PayloadType.PATTERN:
        pattern = bytes([0xAB, 0xCD, 0x00, 0xFF])
        return (pattern * (size // 4 + 1))[:size]
    else:
        text = f"BENCH-PKT-{seq}-" + "X" * max(0, size - 20)
        return text.encode()[:size].ljust(size, b'\x00')


class BenchmarkEngine:
    def __init__(self, session_key: bytes, server_addr: tuple = None):
        if len(session_key) != 32:
            session_key = os.urandom(32)
        self.session_key = session_key
        self.server_addr = server_addr or ("127.0.0.1", 9001)
        self._abort_flag = threading.Event()
        self._progress_callback = None
        self._current_phase = ""

    def on_progress(self, callback):
        self._progress_callback = callback

    def abort(self):
        self._abort_flag.set()

    def _report(self, phase: str, pct: float, data: dict = None):
        self._current_phase = phase
        if self._progress_callback:
            self._progress_callback({
                "phase": phase,
                "percent": pct,
                "data": data or {},
            })

    def run_test(self, config: BenchmarkConfig,
                 progress_offset: float = 0.0,
                 progress_scale: float = 1.0,
                 phase_label: str = "running") -> BenchmarkResult:
        self._abort_flag.clear()
        samples: List[dict] = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)

        config_size = config.payload_sizes[0] if len(config.payload_sizes) == 1 else config.payload_sizes
        total = config.packet_count

        for i in range(config.packet_count):
            if self._abort_flag.is_set():
                break

            payload_size = _pick_size(config_size, i)
            payload = _make_payload(payload_size, i, config.payload_type)

            t0 = time.perf_counter()
            encrypted = crypto_encrypt(payload, self.session_key)
            t1 = time.perf_counter()

            morph_start = time.perf_counter()
            morph_result = morph_packet(encrypted, engine_on=config.engine_on)
            t2 = time.perf_counter()

            wire_data = morph_result.get("packet", encrypted)
            length_header = len(encrypted).to_bytes(2, "big")
            full_data = length_header + wire_data

            try:
                sock.sendto(full_data, self.server_addr)
                sent_ok = True
            except Exception:
                sent_ok = False

            sample = {
                "seq": i,
                "payload_size": payload_size,
                "encrypted_size": len(encrypted),
                "wire_size": len(full_data),
                "padding_size": morph_result["padding_size"],
                "raw_entropy": morph_result["raw_entropy"],
                "final_entropy": morph_result["final_entropy"],
                "jitter_ms": morph_result["jitter_ms"],
                "engine_on": morph_result["engine_on"],
                "encrypt_time_ms": round((t1 - t0) * 1000, 3),
                "morph_time_ms": round((t2 - morph_start) * 1000, 3),
                "total_time_ms": round((t2 - t0) * 1000, 3),
                "sent_ok": sent_ok,
                "original_size": morph_result["original_size"],
            }
            samples.append(sample)

            raw_pct = (i + 1) / total * 100
            mapped_pct = progress_offset + raw_pct * progress_scale
            self._report(phase_label, mapped_pct, {
                "seq": i,
                "throughput": _compute_throughput(samples),
                "avg_entropy": _avg_entropy(samples),
                "current_latency": sample["total_time_ms"],
            })

        sock.close()
        return BenchmarkResult.compute(samples, config)

    def run_comparison(self, config: BenchmarkConfig) -> ComparisonResult:
        self._abort_flag.clear()

        self._report("warming_up", 0)
        time.sleep(0.5)

        config_on = BenchmarkConfig(
            packet_count=config.packet_count,
            payload_sizes=config.payload_sizes,
            engine_on=True,
            payload_type=config.payload_type,
        )
        self._report("engine_on", 0)
        result_on = self.run_test(
            config_on,
            progress_offset=0.0,
            progress_scale=0.5,
            phase_label="Engine ON",
        )
        if self._abort_flag.is_set():
            return ComparisonResult(on=result_on, off=None)

        time.sleep(0.3)

        config_off = BenchmarkConfig(
            packet_count=config.packet_count,
            payload_sizes=config.payload_sizes,
            engine_on=False,
            payload_type=config.payload_type,
        )
        self._report("engine_off", 50)
        result_off = self.run_test(
            config_off,
            progress_offset=50.0,
            progress_scale=0.5,
            phase_label="Engine OFF",
        )

        return ComparisonResult(on=result_on, off=result_off)


def _pick_size(sizes, idx):
    if isinstance(sizes, int):
        return sizes
    return sizes[idx % len(sizes)]


def _compute_throughput(samples: list) -> float:
    if len(samples) < 2:
        return 0.0
    total_bytes = sum(s["wire_size"] for s in samples)
    total_time = sum(s["total_time_ms"] for s in samples) / 1000
    if total_time <= 0:
        return 0.0
    return (total_bytes * 8) / total_time / 1_000_000


def _avg_entropy(samples: list) -> float:
    if not samples:
        return 0.0
    return sum(s["final_entropy"] for s in samples) / len(samples)
