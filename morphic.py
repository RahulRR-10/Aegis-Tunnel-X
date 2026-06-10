import math
import random
import time
from collections import Counter


def shannon_entropy(data: bytes) -> float:
	if not data:
		return 0.0

	counts = Counter(data)
	total = len(data)
	entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
	return round(entropy, 4)


def morph_packet(encrypted_payload: bytes, engine_on: bool) -> dict:
	original_size = len(encrypted_payload)
	raw_entropy = shannon_entropy(encrypted_payload)

	if not engine_on:
		return {
			"original_size": original_size,
			"padding_size": 0,
			"final_size": original_size,
			"raw_entropy": raw_entropy,
			"final_entropy": raw_entropy,
			"jitter_ms": 0,
			"engine_on": False,
		}

	# Use low-entropy structured padding so overall packet entropy drops.
	padding_size = random.randint(60, 180)
	pattern = bytes([0xAB, 0xCD, 0x00, 0xFF])
	padding = (pattern * (padding_size // len(pattern) + 1))[:padding_size]

	morphed_packet = encrypted_payload + padding
	final_entropy = shannon_entropy(morphed_packet)

	jitter_ms = random.randint(10, 50)
	time.sleep(jitter_ms / 1000)

	return {
		"original_size": original_size,
		"padding_size": padding_size,
		"final_size": len(morphed_packet),
		"raw_entropy": raw_entropy,
		"final_entropy": final_entropy,
		"jitter_ms": jitter_ms,
		"engine_on": True,
		"packet": morphed_packet,
	}
