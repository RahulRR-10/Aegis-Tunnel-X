import math
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class PayloadType(Enum):
    RANDOM = "random"
    PATTERN = "pattern"
    TEXT = "text"


@dataclass
class BenchmarkConfig:
    packet_count: int = 200
    payload_sizes: List[int] = field(default_factory=lambda: [64, 256, 512, 1024, 1400])
    engine_on: bool = True
    payload_type: PayloadType = PayloadType.RANDOM

    @property
    def estimated_duration_seconds(self) -> float:
        jitter_per_packet = 0.030
        base = self.packet_count * jitter_per_packet
        return math.ceil(base)
