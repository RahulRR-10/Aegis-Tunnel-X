"""Phase 7 — Configuration Schema & Loader.

Parses YAML configuration files for both server and client modes.
Resolves ``~`` to the user's home directory, auto-creates missing
directories (key_dir, log dir), and validates required fields.

Usage::

    cfg = AegisConfig.from_file("server.conf")
    print(cfg.mode)           # "server"
    print(cfg.listen.host)    # "0.0.0.0"
    print(cfg.tun.ip)         # "10.10.0.1"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

__all__ = ["AegisConfig", "ListenConfig", "ConnectConfig", "TunConfig",
           "CryptoConfig", "MorphicConfig", "FeedbackConfig", "LoggingConfig"]

logger = logging.getLogger("aegis.config")


# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------

@dataclass
class ListenConfig:
    host: str = "0.0.0.0"
    port: int = 5555


@dataclass
class ConnectConfig:
    host: str = "127.0.0.1"
    port: int = 5555


@dataclass
class TunConfig:
    name: str = "aegis0"
    ip: str = "10.10.0.1"
    peer_ip: str = "10.10.0.2"
    mtu: int = 1400


@dataclass
class CryptoConfig:
    key_dir: Path = field(default_factory=lambda: Path.home() / ".aegis" / "keys")


@dataclass
class MorphicConfig:
    profile: str = "web_browsing"
    max_queue_ms: int = 50


@dataclass
class FeedbackConfig:
    enabled: bool = True
    check_interval_s: float = 2.0
    score_threshold: float = 0.25


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: Path = field(default_factory=lambda: Path.home() / ".aegis" / "aegis.log")


# ---------------------------------------------------------------------------
# Main config
# ---------------------------------------------------------------------------

@dataclass
class AegisConfig:
    """Top-level Aegis Tunnel X configuration."""

    mode: str = "server"
    listen: ListenConfig = field(default_factory=ListenConfig)
    connect: ConnectConfig = field(default_factory=ConnectConfig)
    tun: TunConfig = field(default_factory=TunConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    morphic: MorphicConfig = field(default_factory=MorphicConfig)
    feedback: FeedbackConfig = field(default_factory=FeedbackConfig)
    logging_cfg: LoggingConfig = field(default_factory=LoggingConfig)

    # ------------------------------------------------------------------
    # Factory: from YAML file
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> AegisConfig:
        """Load configuration from a YAML file.

        Raises:
            FileNotFoundError: If the config file doesn't exist.
            ValueError:        If required fields are missing/invalid.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AegisConfig:
        """Build config from a raw dict (parsed YAML).

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        cfg = cls()

        # Mode (required)
        if "mode" not in raw:
            raise ValueError("Config missing required field: 'mode'")
        cfg.mode = raw["mode"]
        if cfg.mode not in ("server", "client"):
            raise ValueError(f"Invalid mode '{cfg.mode}'; must be 'server' or 'client'")

        # Listen
        if "listen" in raw:
            listen = raw["listen"]
            cfg.listen = ListenConfig(
                host=listen.get("host", "0.0.0.0"),
                port=int(listen.get("port", 5555)),
            )

        # Connect (required for client mode)
        if "connect" in raw:
            connect = raw["connect"]
            cfg.connect = ConnectConfig(
                host=connect.get("host", "127.0.0.1"),
                port=int(connect.get("port", 5555)),
            )
        elif cfg.mode == "client":
            raise ValueError("Client mode requires 'connect' section")

        # TUN
        if "tun" in raw:
            tun = raw["tun"]
            cfg.tun = TunConfig(
                name=tun.get("name", "aegis0"),
                ip=tun.get("ip", "10.10.0.1"),
                peer_ip=tun.get("peer_ip", "10.10.0.2"),
                mtu=int(tun.get("mtu", 1400)),
            )

        # Crypto
        if "crypto" in raw:
            crypto = raw["crypto"]
            key_dir = crypto.get("key_dir", str(Path.home() / ".aegis" / "keys"))
            cfg.crypto = CryptoConfig(
                key_dir=_resolve_path(key_dir),
            )

        # Morphic
        if "morphic" in raw:
            morphic = raw["morphic"]
            cfg.morphic = MorphicConfig(
                profile=morphic.get("profile", "web_browsing"),
                max_queue_ms=int(morphic.get("max_queue_ms", 50)),
            )

        # Feedback
        if "feedback" in raw:
            fb = raw["feedback"]
            cfg.feedback = FeedbackConfig(
                enabled=bool(fb.get("enabled", True)),
                check_interval_s=float(fb.get("check_interval_s", 2.0)),
                score_threshold=float(fb.get("score_threshold", 0.25)),
            )

        # Logging
        if "logging" in raw:
            log = raw["logging"]
            log_file = log.get("file", str(Path.home() / ".aegis" / "aegis.log"))
            cfg.logging_cfg = LoggingConfig(
                level=log.get("level", "INFO").upper(),
                file=_resolve_path(log_file),
            )

        return cfg

    # ------------------------------------------------------------------
    # Ensure directories exist
    # ------------------------------------------------------------------

    def ensure_dirs(self) -> None:
        """Create key_dir and log directory if they don't exist."""
        self.crypto.key_dir.mkdir(parents=True, exist_ok=True)
        self.logging_cfg.file.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Dump back to dict (for serialisation / display)
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialise config to a plain dict."""
        return {
            "mode": self.mode,
            "listen": {"host": self.listen.host, "port": self.listen.port},
            "connect": {"host": self.connect.host, "port": self.connect.port},
            "tun": {
                "name": self.tun.name,
                "ip": self.tun.ip,
                "peer_ip": self.tun.peer_ip,
                "mtu": self.tun.mtu,
            },
            "crypto": {"key_dir": str(self.crypto.key_dir)},
            "morphic": {
                "profile": self.morphic.profile,
                "max_queue_ms": self.morphic.max_queue_ms,
            },
            "feedback": {
                "enabled": self.feedback.enabled,
                "check_interval_s": self.feedback.check_interval_s,
                "score_threshold": self.feedback.score_threshold,
            },
            "logging": {
                "level": self.logging_cfg.level,
                "file": str(self.logging_cfg.file),
            },
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_path(p: str) -> Path:
    """Resolve ``~`` to the user's home directory."""
    return Path(p).expanduser().resolve()
