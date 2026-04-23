"""Phase 7 — CLI Entry Point for Aegis Tunnel X.

Commands::

    aegis server --config server.conf
    aegis client --config client.conf
    aegis keygen --output <dir>
    aegis status
    aegis profile list
    aegis profile set <name>

All commands run natively on Windows (no WSL/Docker).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Any

from aegis.config import AegisConfig

__all__ = ["main"]

logger = logging.getLogger("aegis.cli")


# ===================================================================
# Keygen
# ===================================================================

def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate Kyber-768 + X25519 keypairs and save to disk."""
    output_dir = Path(args.output).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    from aegis.crypto import X25519KeyPair, OQS_AVAILABLE

    # X25519 keypair
    x25519 = X25519KeyPair()
    x25519_priv_path = output_dir / "x25519_priv.bin"
    x25519_pub_path = output_dir / "x25519_pub.bin"

    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )
    x25519_priv_bytes = x25519._private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    x25519_pub_bytes = x25519.public_key_bytes

    x25519_priv_path.write_bytes(x25519_priv_bytes)
    x25519_pub_path.write_bytes(x25519_pub_bytes)
    print(f"  ✓ X25519 private key → {x25519_priv_path}")
    print(f"  ✓ X25519 public key  → {x25519_pub_path}")

    # Kyber-768 keypair (if liboqs available)
    if OQS_AVAILABLE:
        import oqs
        kem = oqs.KeyEncapsulation("Kyber768")
        pub = kem.generate_keypair()
        priv = kem.export_secret_key()

        kyber_priv_path = output_dir / "kyber_priv.bin"
        kyber_pub_path = output_dir / "kyber_pub.bin"
        kyber_priv_path.write_bytes(priv)
        kyber_pub_path.write_bytes(pub)
        print(f"  ✓ Kyber-768 private key → {kyber_priv_path}")
        print(f"  ✓ Kyber-768 public key  → {kyber_pub_path}")
        kem.free()
    else:
        print("  ⚠ liboqs not available — Kyber-768 keys skipped")
        print("    Set OQS_INSTALL_PATH and ensure oqs.dll is in bin/")

    print(f"\nKeys saved to: {output_dir}")


# ===================================================================
# Profile commands
# ===================================================================

def cmd_profile_list(args: argparse.Namespace) -> None:
    """List available morphic traffic profiles."""
    from aegis.morphic import MorphicEngine
    profiles = MorphicEngine.list_profiles()
    print("Available morphic profiles:")
    for p in profiles:
        print(f"  • {p}")


def cmd_profile_set(args: argparse.Namespace) -> None:
    """Hot-swap the morphic profile (placeholder for integration)."""
    name = args.name
    # Validate the profile exists
    from aegis.morphic import MorphicEngine
    try:
        engine = MorphicEngine(name)
        print(f"✓ Profile '{name}' is valid and can be loaded.")
        print(f"  Peaks: {engine.current_profile.get('packet_size_distribution', {}).get('peaks')}")
    except FileNotFoundError:
        print(f"✗ Profile '{name}' not found.")
        sys.exit(1)


# ===================================================================
# Server / Client
# ===================================================================

def cmd_server(args: argparse.Namespace) -> None:
    """Start the Aegis Tunnel server."""
    cfg = _load_config(args.config)
    if cfg.mode != "server":
        print(f"✗ Config mode is '{cfg.mode}', expected 'server'")
        sys.exit(1)

    _setup_logging(cfg)
    cfg.ensure_dirs()

    print("╔══════════════════════════════════════════════════╗")
    print("║            AEGIS-TUNNEL X  —  SERVER             ║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"  Listen:  {cfg.listen.host}:{cfg.listen.port}")
    print(f"  TUN:     {cfg.tun.name} ({cfg.tun.ip} ↔ {cfg.tun.peer_ip})")
    print(f"  Profile: {cfg.morphic.profile}")
    print(f"  Feedback: {'enabled' if cfg.feedback.enabled else 'disabled'}")
    print()

    asyncio.run(_run_tunnel(cfg))


def cmd_client(args: argparse.Namespace) -> None:
    """Start the Aegis Tunnel client."""
    cfg = _load_config(args.config)
    if cfg.mode != "client":
        print(f"✗ Config mode is '{cfg.mode}', expected 'client'")
        sys.exit(1)

    _setup_logging(cfg)
    cfg.ensure_dirs()

    print("╔══════════════════════════════════════════════════╗")
    print("║            AEGIS-TUNNEL X  —  CLIENT             ║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"  Connect: {cfg.connect.host}:{cfg.connect.port}")
    print(f"  TUN:     {cfg.tun.name} ({cfg.tun.ip} ↔ {cfg.tun.peer_ip})")
    print(f"  Profile: {cfg.morphic.profile}")
    print()

    asyncio.run(_run_tunnel(cfg))


async def _run_tunnel(cfg: AegisConfig) -> None:
    """Orchestrate TUN + transport + morphic + feedback."""
    from aegis.tun import TunInterface
    from aegis.transport import AegisTunnelServer, AegisTunnelClient
    from aegis.tunnel import AegisTunnel
    from aegis.morphic import MorphicEngine
    from aegis.feedback import TrafficAnalyzer, FeedbackLoop

    # TUN interface
    tun = TunInterface(
        name=cfg.tun.name,
        ip=cfg.tun.ip,
        peer_ip=cfg.tun.peer_ip,
        mtu=cfg.tun.mtu,
    )
    tun.open()

    # Transport
    if cfg.mode == "server":
        transport = AegisTunnelServer(cfg.listen.host, cfg.listen.port)
        await transport.start()
        logger.info("Server started on %s:%d", cfg.listen.host, cfg.listen.port)
        # Wait for a client to connect
        print("  Waiting for client connection...")
    else:
        transport = AegisTunnelClient(cfg.connect.host, cfg.connect.port)
        await transport.connect(timeout=30.0)
        logger.info("Connected to %s:%d", cfg.connect.host, cfg.connect.port)

    # Morphic engine
    morphic = MorphicEngine(
        profile_name=cfg.morphic.profile,
        max_queue_ms=cfg.morphic.max_queue_ms,
    )

    # Feedback loop
    feedback = None
    feedback_task = None
    if cfg.feedback.enabled:
        analyzer = TrafficAnalyzer()
        feedback = FeedbackLoop(
            analyzer=analyzer,
            morphic=morphic,
            check_interval_s=cfg.feedback.check_interval_s,
            score_threshold=cfg.feedback.score_threshold,
        )
        feedback_task = asyncio.create_task(feedback.run())

    # Tunnel
    tunnel = AegisTunnel(tun, transport, morphic=morphic, feedback=feedback)

    # Handle Ctrl-C
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler() -> None:
        print("\n  Shutting down...")
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _signal_handler)
    except NotImplementedError:
        # Windows doesn't support add_signal_handler for SIGINT in some cases
        pass

    # Run tunnel in background
    tunnel_task = asyncio.create_task(tunnel.run())

    print("  ✓ Tunnel active. Press Ctrl-C to stop.\n")

    # Wait for stop signal or tunnel completion
    try:
        await stop_event.wait()
    except KeyboardInterrupt:
        pass

    # Cleanup
    await tunnel.stop()
    if feedback:
        feedback.stop()
        if feedback_task:
            feedback_task.cancel()
            try:
                await feedback_task
            except asyncio.CancelledError:
                pass

    if cfg.mode == "server":
        await transport.stop()
    else:
        await transport.disconnect()

    tun.close()
    print("  ✓ Tunnel stopped cleanly.")


# ===================================================================
# Status command
# ===================================================================

def cmd_status(args: argparse.Namespace) -> None:
    """Show a live status dashboard (placeholder/snapshot)."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text

        console = Console()
        status_text = Text()
        status_text.append("Session: ", style="bold cyan")
        status_text.append("(not connected)\n")
        status_text.append("Detection Score: ", style="bold")
        status_text.append("N/A\n")
        status_text.append("Profile: ", style="bold")
        status_text.append("web_browsing\n")
        status_text.append("Pkts TX/RX: ", style="bold")
        status_text.append("0 / 0\n")
        status_text.append("PQ Handshake: ", style="bold")

        from aegis.crypto import OQS_AVAILABLE
        if OQS_AVAILABLE:
            status_text.append("✓ Kyber768 available", style="green")
        else:
            status_text.append("✗ Kyber768 unavailable", style="red")

        panel = Panel(
            status_text,
            title="[bold white]AEGIS-TUNNEL X[/bold white]",
            border_style="cyan",
            width=55,
        )
        console.print(panel)

    except ImportError:
        # Fallback if Rich is not installed
        print("╔══════════════════ AEGIS-TUNNEL X ══════════════════╗")
        print("║  Session: (not connected)                          ║")
        print("║  Detection Score: N/A                              ║")
        print("║  Profile: web_browsing                             ║")
        print("║  Pkts TX/RX: 0 / 0                                 ║")
        print("╚════════════════════════════════════════════════════╝")


# ===================================================================
# Helpers
# ===================================================================

def _load_config(config_path: str) -> AegisConfig:
    """Load and validate config from file."""
    try:
        cfg = AegisConfig.from_file(config_path)
    except FileNotFoundError as e:
        print(f"✗ {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"✗ Config error: {e}")
        sys.exit(1)
    return cfg


def _setup_logging(cfg: AegisConfig) -> None:
    """Configure logging based on config."""
    level = getattr(logging, cfg.logging_cfg.level, logging.INFO)
    log_file = cfg.logging_cfg.file
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(str(log_file), encoding="utf-8"),
        ],
    )


# ===================================================================
# Argument parser
# ===================================================================

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis Tunnel X — Post-quantum encrypted tunnel with morphic traffic shaping",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # server
    srv = subparsers.add_parser("server", help="Start the tunnel server")
    srv.add_argument("--config", required=True, help="Path to server.conf")

    # client
    cli = subparsers.add_parser("client", help="Start the tunnel client")
    cli.add_argument("--config", required=True, help="Path to client.conf")

    # keygen
    kg = subparsers.add_parser("keygen", help="Generate cryptographic keypairs")
    kg.add_argument(
        "--output", default=str(Path.home() / ".aegis" / "keys"),
        help="Output directory for keys (default: ~/.aegis/keys)",
    )

    # status
    subparsers.add_parser("status", help="Show tunnel status dashboard")

    # profile
    profile = subparsers.add_parser("profile", help="Manage morphic profiles")
    profile_sub = profile.add_subparsers(dest="profile_command")
    profile_sub.add_parser("list", help="List available profiles")
    profile_set = profile_sub.add_parser("set", help="Set active profile")
    profile_set.add_argument("name", help="Profile name")

    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "server": cmd_server,
        "client": cmd_client,
        "keygen": cmd_keygen,
        "status": cmd_status,
        "profile": lambda a: (
            cmd_profile_list(a) if getattr(a, "profile_command", None) == "list"
            else cmd_profile_set(a) if getattr(a, "profile_command", None) == "set"
            else parser.parse_args(["profile", "--help"])
        ),
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
