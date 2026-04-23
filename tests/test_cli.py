"""Phase 7 Tests — CLI & Configuration.

Test 7-A: keygen creates kyber + x25519 key files in key_dir
Test 7-B: Config loader parses server.conf and client.conf; raises ValueError on missing fields
Test 7-C: Config loader resolves ~ and creates key_dir if missing
Test 7-D: CLI server command starts without error (validated via argparse)
Test 7-E: profile list and profile set commands work
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

from aegis.config import AegisConfig
from aegis.cli import main as cli_main, build_parser, cmd_keygen, cmd_profile_list


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_config(tmpdir: Path, content: dict) -> Path:
    """Write a config dict as YAML to a temp file."""
    path = tmpdir / "test.conf"
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(content, f)
    return path


# ---------------------------------------------------------------------------
# Test 7-A: keygen creates key files
# ---------------------------------------------------------------------------

def test_keygen_creates_key_files(tmp_path: Path) -> None:
    """keygen command creates x25519_priv.bin and x25519_pub.bin.
    If liboqs is available, also creates kyber_priv.bin and kyber_pub.bin."""
    import argparse

    args = argparse.Namespace(output=str(tmp_path))
    cmd_keygen(args)

    # X25519 keys should always be created
    assert (tmp_path / "x25519_priv.bin").exists()
    assert (tmp_path / "x25519_pub.bin").exists()
    assert (tmp_path / "x25519_priv.bin").stat().st_size == 32  # X25519 = 32 bytes
    assert (tmp_path / "x25519_pub.bin").stat().st_size == 32

    # Kyber keys depend on liboqs availability
    from aegis.crypto import OQS_AVAILABLE
    if OQS_AVAILABLE:
        assert (tmp_path / "kyber_priv.bin").exists()
        assert (tmp_path / "kyber_pub.bin").exists()
        assert (tmp_path / "kyber_priv.bin").stat().st_size > 0
        assert (tmp_path / "kyber_pub.bin").stat().st_size > 0


# ---------------------------------------------------------------------------
# Test 7-B: Config loader parses valid configs; rejects invalid ones
# ---------------------------------------------------------------------------

def test_config_loader_parses_server_config(tmp_path: Path) -> None:
    """Server config with all fields parses correctly."""
    config_data = {
        "mode": "server",
        "listen": {"host": "0.0.0.0", "port": 5555},
        "tun": {"name": "aegis0", "ip": "10.10.0.1", "peer_ip": "10.10.0.2", "mtu": 1400},
        "crypto": {"key_dir": str(tmp_path / "keys")},
        "morphic": {"profile": "web_browsing", "max_queue_ms": 50},
        "feedback": {"enabled": True, "check_interval_s": 2.0, "score_threshold": 0.25},
        "logging": {"level": "DEBUG", "file": str(tmp_path / "test.log")},
    }
    path = _write_config(tmp_path, config_data)
    cfg = AegisConfig.from_file(path)

    assert cfg.mode == "server"
    assert cfg.listen.host == "0.0.0.0"
    assert cfg.listen.port == 5555
    assert cfg.tun.name == "aegis0"
    assert cfg.tun.ip == "10.10.0.1"
    assert cfg.morphic.profile == "web_browsing"
    assert cfg.feedback.enabled is True
    assert cfg.logging_cfg.level == "DEBUG"


def test_config_loader_parses_client_config(tmp_path: Path) -> None:
    """Client config with connect section parses correctly."""
    config_data = {
        "mode": "client",
        "connect": {"host": "192.168.1.10", "port": 5555},
        "tun": {"name": "aegis_cli", "ip": "10.10.0.2", "peer_ip": "10.10.0.1"},
        "crypto": {"key_dir": str(tmp_path / "keys")},
    }
    path = _write_config(tmp_path, config_data)
    cfg = AegisConfig.from_file(path)

    assert cfg.mode == "client"
    assert cfg.connect.host == "192.168.1.10"
    assert cfg.connect.port == 5555


def test_config_missing_mode_raises(tmp_path: Path) -> None:
    """Config without 'mode' field raises ValueError."""
    config_data = {"listen": {"host": "0.0.0.0", "port": 5555}}
    path = _write_config(tmp_path, config_data)

    with pytest.raises(ValueError, match="mode"):
        AegisConfig.from_file(path)


def test_config_client_missing_connect_raises(tmp_path: Path) -> None:
    """Client config without 'connect' section raises ValueError."""
    config_data = {"mode": "client", "tun": {"name": "test"}}
    path = _write_config(tmp_path, config_data)

    with pytest.raises(ValueError, match="connect"):
        AegisConfig.from_file(path)


def test_config_invalid_mode_raises(tmp_path: Path) -> None:
    """Config with invalid mode raises ValueError."""
    config_data = {"mode": "relay"}
    path = _write_config(tmp_path, config_data)

    with pytest.raises(ValueError, match="Invalid mode"):
        AegisConfig.from_file(path)


def test_config_file_not_found_raises() -> None:
    """Loading a non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        AegisConfig.from_file("/nonexistent/path/config.yaml")


# ---------------------------------------------------------------------------
# Test 7-C: Config resolves ~ and creates directories
# ---------------------------------------------------------------------------

def test_config_resolves_tilde_and_creates_dirs(tmp_path: Path) -> None:
    """~ in key_dir is resolved to home dir, and ensure_dirs creates it."""
    config_data = {
        "mode": "server",
        "listen": {"host": "0.0.0.0", "port": 5555},
        "crypto": {"key_dir": str(tmp_path / "new_keys_dir")},
        "logging": {"level": "INFO", "file": str(tmp_path / "logs" / "test.log")},
    }
    path = _write_config(tmp_path, config_data)
    cfg = AegisConfig.from_file(path)

    # Dirs shouldn't exist yet
    assert not cfg.crypto.key_dir.exists()
    assert not cfg.logging_cfg.file.parent.exists()

    # ensure_dirs creates them
    cfg.ensure_dirs()
    assert cfg.crypto.key_dir.exists()
    assert cfg.logging_cfg.file.parent.exists()


def test_config_tilde_expansion(tmp_path: Path) -> None:
    """Tilde in paths is expanded to user home."""
    config_data = {
        "mode": "server",
        "listen": {"host": "0.0.0.0", "port": 5555},
        "crypto": {"key_dir": "~/.aegis/test_keys"},
    }
    path = _write_config(tmp_path, config_data)
    cfg = AegisConfig.from_file(path)

    # Should be resolved to an absolute path under the home directory
    assert cfg.crypto.key_dir.is_absolute()
    assert str(Path.home()) in str(cfg.crypto.key_dir)


# ---------------------------------------------------------------------------
# Test 7-D: CLI parser validates server command
# ---------------------------------------------------------------------------

def test_cli_parser_server_command() -> None:
    """argparse correctly parses 'server --config server.conf'."""
    parser = build_parser()
    args = parser.parse_args(["server", "--config", "server.conf"])
    assert args.command == "server"
    assert args.config == "server.conf"


def test_cli_parser_client_command() -> None:
    """argparse correctly parses 'client --config client.conf'."""
    parser = build_parser()
    args = parser.parse_args(["client", "--config", "client.conf"])
    assert args.command == "client"
    assert args.config == "client.conf"


def test_cli_parser_keygen_command() -> None:
    """argparse correctly parses 'keygen --output <dir>'."""
    parser = build_parser()
    args = parser.parse_args(["keygen", "--output", "C:\\keys"])
    assert args.command == "keygen"
    assert args.output == "C:\\keys"


def test_cli_parser_no_command(capsys: pytest.CaptureFixture[str]) -> None:
    """No command prints help and exits cleanly."""
    with pytest.raises(SystemExit) as exc_info:
        cli_main([])
    assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Test 7-E: profile list and profile set
# ---------------------------------------------------------------------------

def test_profile_list_command(capsys: pytest.CaptureFixture[str]) -> None:
    """'profile list' shows available profiles."""
    cli_main(["profile", "list"])
    captured = capsys.readouterr()
    assert "web_browsing" in captured.out
    assert "video_streaming" in captured.out
    assert "gaming" in captured.out


def test_profile_set_valid(capsys: pytest.CaptureFixture[str]) -> None:
    """'profile set video_streaming' validates the profile."""
    cli_main(["profile", "set", "video_streaming"])
    captured = capsys.readouterr()
    assert "valid" in captured.out.lower() or "✓" in captured.out


def test_profile_set_invalid(capsys: pytest.CaptureFixture[str]) -> None:
    """'profile set nonexistent' exits with error."""
    with pytest.raises(SystemExit) as exc_info:
        cli_main(["profile", "set", "nonexistent_profile_xyz"])
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Bonus: Config to_dict round-trip
# ---------------------------------------------------------------------------

def test_config_to_dict_roundtrip(tmp_path: Path) -> None:
    """Config → to_dict → from_dict produces an equivalent config."""
    config_data = {
        "mode": "server",
        "listen": {"host": "0.0.0.0", "port": 5555},
        "tun": {"name": "aegis0", "ip": "10.10.0.1", "peer_ip": "10.10.0.2", "mtu": 1400},
        "crypto": {"key_dir": str(tmp_path / "keys")},
        "morphic": {"profile": "gaming", "max_queue_ms": 30},
        "feedback": {"enabled": False, "check_interval_s": 5.0, "score_threshold": 0.5},
        "logging": {"level": "WARNING", "file": str(tmp_path / "test.log")},
    }
    cfg1 = AegisConfig.from_dict(config_data)
    d = cfg1.to_dict()
    cfg2 = AegisConfig.from_dict(d)

    assert cfg2.mode == cfg1.mode
    assert cfg2.listen.port == cfg1.listen.port
    assert cfg2.tun.ip == cfg1.tun.ip
    assert cfg2.morphic.profile == cfg1.morphic.profile
    assert cfg2.feedback.enabled == cfg1.feedback.enabled
