import math
import statistics
from typing import List, Optional


class BenchmarkResult:
    def __init__(self):
        self.samples: List[dict] = []
        self.packet_count: int = 0
        self.engine_on: bool = True
        self.payload_sizes: list = None

        self.throughput_mbps: float = 0.0
        self.avg_latency_ms: float = 0.0
        self.jitter_ms: float = 0.0
        self.min_latency_ms: float = 0.0
        self.max_latency_ms: float = 0.0
        self.p50_latency_ms: float = 0.0
        self.p95_latency_ms: float = 0.0
        self.p99_latency_ms: float = 0.0

        self.avg_raw_entropy: float = 0.0
        self.avg_final_entropy: float = 0.0
        self.entropy_reduction_pct: float = 0.0

        self.total_data_sent_bytes: int = 0
        self.total_padding_bytes: int = 0
        self.avg_padding_per_packet: float = 0.0
        self.overhead_pct: float = 0.0

        self.dpi_evasion_score: float = 0.0
        self.dpi_status: str = ""

        self.avg_encrypt_time_ms: float = 0.0
        self.avg_morph_time_ms: float = 0.0

    @staticmethod
    def compute(samples: List[dict], config) -> "BenchmarkResult":
        r = BenchmarkResult()
        r.samples = samples
        r.packet_count = len(samples)
        r.engine_on = config.engine_on if samples else True
        r.payload_sizes = config.payload_sizes

        if not samples:
            return r

        latencies = [s["total_time_ms"] for s in samples]
        r.avg_latency_ms = round(statistics.mean(latencies), 3)
        r.jitter_ms = round(statistics.stdev(latencies), 3) if len(latencies) > 1 else 0.0
        r.min_latency_ms = round(min(latencies), 3)
        r.max_latency_ms = round(max(latencies), 3)

        sorted_lat = sorted(latencies)
        r.p50_latency_ms = _percentile(sorted_lat, 50)
        r.p95_latency_ms = _percentile(sorted_lat, 95)
        r.p99_latency_ms = _percentile(sorted_lat, 99)

        r.avg_raw_entropy = round(sum(s["raw_entropy"] for s in samples) / len(samples), 4)
        r.avg_final_entropy = round(sum(s["final_entropy"] for s in samples) / len(samples), 4)
        if r.avg_raw_entropy > 0:
            r.entropy_reduction_pct = round(
                (r.avg_raw_entropy - r.avg_final_entropy) / r.avg_raw_entropy * 100, 2
            )

        r.total_data_sent_bytes = sum(s["wire_size"] for s in samples)
        r.total_padding_bytes = sum(s["padding_size"] for s in samples)
        r.avg_padding_per_packet = round(r.total_padding_bytes / len(samples), 1)

        total_original = sum(s["original_size"] for s in samples)
        if total_original > 0:
            r.overhead_pct = round(
                (r.total_data_sent_bytes - total_original) / total_original * 100, 2
            )

        total_time_sec = sum(s["total_time_ms"] for s in samples) / 1000
        if total_time_sec > 0:
            r.throughput_mbps = round(
                (r.total_data_sent_bytes * 8) / total_time_sec / 1_000_000, 3
            )

        r.avg_encrypt_time_ms = round(sum(s["encrypt_time_ms"] for s in samples) / len(samples), 3)
        r.avg_morph_time_ms = round(sum(s["morph_time_ms"] for s in samples) / len(samples), 3)

        r.dpi_evasion_score = r._compute_dpi_score()
        r.dpi_status = "EVADED" if r.dpi_evasion_score < 0.4 else \
                       "MODERATE" if r.dpi_evasion_score < 0.7 else "DETECTED"

        return r

    def _compute_dpi_score(self) -> float:
        if self.avg_final_entropy >= 7.9:
            return 1.0
        if self.avg_final_entropy <= 6.0:
            return 0.0
        return round((self.avg_final_entropy - 6.0) / (7.9 - 6.0), 4)

    def summary_dict(self) -> dict:
        return {
            "packet_count": self.packet_count,
            "engine_on": self.engine_on,
            "throughput_mbps": self.throughput_mbps,
            "avg_latency_ms": self.avg_latency_ms,
            "jitter_ms": self.jitter_ms,
            "p50_latency_ms": self.p50_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "p99_latency_ms": self.p99_latency_ms,
            "min_latency_ms": self.min_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "avg_raw_entropy": self.avg_raw_entropy,
            "avg_final_entropy": self.avg_final_entropy,
            "entropy_reduction_pct": self.entropy_reduction_pct,
            "total_data_sent_bytes": self.total_data_sent_bytes,
            "total_padding_bytes": self.total_padding_bytes,
            "avg_padding_per_packet": self.avg_padding_per_packet,
            "overhead_pct": self.overhead_pct,
            "dpi_evasion_score": self.dpi_evasion_score,
            "dpi_status": self.dpi_status,
            "avg_encrypt_time_ms": self.avg_encrypt_time_ms,
            "avg_morph_time_ms": self.avg_morph_time_ms,
        }


class ComparisonResult:
    def __init__(self, on: Optional[BenchmarkResult], off: Optional[BenchmarkResult]):
        self.on = on
        self.off = off
        self.speed_impact_pct: float = 0.0
        self.entropy_improvement_pct: float = 0.0
        self.dpi_status_change: str = ""
        self._compute()

    def _compute(self):
        if self.on and self.off:
            on_tp = self.on.throughput_mbps
            off_tp = self.off.throughput_mbps
            if off_tp > 0:
                self.speed_impact_pct = round((on_tp - off_tp) / off_tp * 100, 2)
            self.entropy_improvement_pct = round(
                self.off.avg_final_entropy - self.on.avg_final_entropy, 4
            )
            self.dpi_status_change = f"{self.off.dpi_status} → {self.on.dpi_status}"
        elif self.on:
            self.speed_impact_pct = 0.0
            self.entropy_improvement_pct = 0.0
            self.dpi_status_change = f"→ {self.on.dpi_status}"

    def summary_dict(self) -> dict:
        return {
            "speed_impact_pct": self.speed_impact_pct,
            "entropy_improvement_pct": self.entropy_improvement_pct,
            "dpi_status_change": self.dpi_status_change,
            "on": self.on.summary_dict() if self.on else None,
            "off": self.off.summary_dict() if self.off else None,
        }

    def throughput_comparison(self) -> dict:
        return {
            "on_label": f"{self.on.throughput_mbps} Mbps" if self.on else "N/A",
            "off_label": f"{self.off.throughput_mbps} Mbps" if self.off else "N/A",
            "on_value": self.on.throughput_mbps if self.on else 0,
            "off_value": self.off.throughput_mbps if self.off else 0,
        }

    def entropy_comparison(self) -> dict:
        return {
            "on_raw": self.on.avg_raw_entropy if self.on else 0,
            "on_final": self.on.avg_final_entropy if self.on else 0,
            "off_raw": self.off.avg_raw_entropy if self.off else 0,
            "off_final": self.off.avg_final_entropy if self.off else 0,
        }

    def latency_comparison(self) -> dict:
        return {
            "on_avg": self.on.avg_latency_ms if self.on else 0,
            "on_jitter": self.on.jitter_ms if self.on else 0,
            "off_avg": self.off.avg_latency_ms if self.off else 0,
            "off_jitter": self.off.jitter_ms if self.off else 0,
        }


def _percentile(sorted_data: list, pct: float) -> float:
    if not sorted_data:
        return 0.0
    k = (len(sorted_data) - 1) * pct / 100
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    return sorted_data[f] * (c - k) + sorted_data[c] * (k - f)
