"""Aegis-Tunnel X — Post-quantum encrypted UDP tunnel with morphic traffic shaping."""

from aegis.tun import TunInterface, TunInterfaceError
from aegis.crypto import (
    KyberKeyPair,
    SessionCrypto,
    X25519KeyPair,
    kyber_encapsulate,
    derive_master_key,
    derive_session_keys,
)
from aegis.transport import AegisTunnelServer, AegisTunnelClient
from aegis.tunnel import AegisTunnel
from aegis.morphic import MorphicEngine
from aegis.feedback import TrafficAnalyzer, FeedbackLoop
from aegis.config import AegisConfig

__all__ = [
    # Phase 1 — TUN
    "TunInterface",
    "TunInterfaceError",
    # Phase 2 — Crypto
    "KyberKeyPair",
    "SessionCrypto",
    "X25519KeyPair",
    "kyber_encapsulate",
    "derive_master_key",
    "derive_session_keys",
    # Phase 3 — Transport
    "AegisTunnelServer",
    "AegisTunnelClient",
    # Phase 4 — Tunnel
    "AegisTunnel",
    # Phase 5 — Morphic
    "MorphicEngine",
    # Phase 6 — Feedback
    "TrafficAnalyzer",
    "FeedbackLoop",
    # Phase 7 — Config
    "AegisConfig",
]
