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
import io
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Any

# Force UTF-8 output on Windows to avoid cp1252 crashes when output is
# redirected by Start-Process.  This must run before any print().
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )
if sys.stderr.encoding != "utf-8":
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )

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
    print(f"  [OK] X25519 private key -> {x25519_priv_path}")
    print(f"  [OK] X25519 public key  -> {x25519_pub_path}")

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
        print(f"  [OK] Kyber-768 private key -> {kyber_priv_path}")
        print(f"  [OK] Kyber-768 public key  -> {kyber_pub_path}")
        kem.free()
    else:
        print("  [!!] liboqs not available -- Kyber-768 keys skipped")
        print("       Set OQS_INSTALL_PATH and ensure oqs.dll is in bin/")

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
        print(f"  - {p}")


def cmd_profile_set(args: argparse.Namespace) -> None:
    """Hot-swap the morphic profile (placeholder for integration)."""
    name = args.name
    # Validate the profile exists
    from aegis.morphic import MorphicEngine
    try:
        engine = MorphicEngine(name)
        print(f"[OK] Profile '{name}' is valid and can be loaded.")
        print(f"  Peaks: {engine.current_profile.get('packet_size_distribution', {}).get('peaks')}")
    except FileNotFoundError:
        print(f"[X] Profile '{name}' not found.")
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

    print("=" * 52)
    print("          AEGIS-TUNNEL X  --  SERVER")
    print("=" * 52)
    print(f"  Listen:   {cfg.listen.host}:{cfg.listen.port}")
    print(f"  TUN:      {cfg.tun.name} ({cfg.tun.ip} <-> {cfg.tun.peer_ip})")
    print(f"  Profile:  {cfg.morphic.profile}")
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

    print("=" * 52)
    print("          AEGIS-TUNNEL X  --  CLIENT")
    print("=" * 52)
    print(f"  Connect:  {cfg.connect.host}:{cfg.connect.port}")
    print(f"  TUN:      {cfg.tun.name} ({cfg.tun.ip} <-> {cfg.tun.peer_ip})")
    print(f"  Profile:  {cfg.morphic.profile}")
    print()

    asyncio.run(_run_tunnel(cfg))


async def _run_tunnel(cfg: AegisConfig) -> None:
    """Orchestrate TUN + transport + morphic + feedback."""
    import json as _json

    from aegis.tun import TunInterface
    from aegis.transport import AegisTunnelServer, AegisTunnelClient
    from aegis.tunnel import AegisTunnel
    from aegis.morphic import MorphicEngine
    from aegis.feedback import TrafficAnalyzer, FeedbackLoop

    # Status file for `aegis status` to read
    status_file = Path.home() / ".aegis" / "status.json"
    status_file.parent.mkdir(parents=True, exist_ok=True)

    # TUN interface
    tun = TunInterface(name=cfg.tun.name, mtu=cfg.tun.mtu)
    tun.ip = cfg.tun.ip
    tun.peer_ip = cfg.tun.peer_ip
    tun.open()
    _add_peer_route(cfg)

    # Transport
    if cfg.mode == "server":
        transport = AegisTunnelServer(cfg.listen.host, cfg.listen.port)
        await transport.start()
        logger.info("Server started on %s:%d", cfg.listen.host, cfg.listen.port)
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
    analyzer = None
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
        pass

    # Status writer task — updates ~/.aegis/status.json every second
    async def _write_status() -> None:
        import time as _time
        start_time = _time.time()
        while not stop_event.is_set():
            try:
                stats = tunnel.packet_stats
                det_score = "N/A"
                if analyzer is not None:
                    try:
                        profile = morphic.current_profile
                        det_score = f"{analyzer.detection_score(profile):.4f}"
                    except Exception:
                        det_score = "N/A"

                status = {
                    "mode": cfg.mode,
                    "session": "active",
                    "uptime_s": round(_time.time() - start_time, 1),
                    "tun_name": cfg.tun.name,
                    "tun_ip": cfg.tun.ip,
                    "peer_ip": cfg.tun.peer_ip,
                    "profile": morphic._profile_name,
                    "detection_score": det_score,
                    "pkts_tx": stats.get("sent_count", 0),
                    "pkts_rx": stats.get("recv_count", 0),
                    "bytes_tx": stats.get("bytes_sent", 0),
                    "bytes_rx": stats.get("bytes_recv", 0),
                    "feedback_enabled": cfg.feedback.enabled,
                    "pq_available": True,
                }
                status_file.write_text(
                    _json.dumps(status, indent=2), encoding="utf-8"
                )
            except Exception:
                pass
            await asyncio.sleep(1.0)

    # Run tunnel + status writer
    tunnel_task = asyncio.create_task(tunnel.run())
    status_task = asyncio.create_task(_write_status())

    print("  [OK] Tunnel active. Press Ctrl-C to stop.")
    print()

    # Wait for stop signal or tunnel completion
    try:
        await stop_event.wait()
    except KeyboardInterrupt:
        pass

    # Cleanup
    status_task.cancel()
    try:
        await status_task
    except asyncio.CancelledError:
        pass

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
    _remove_peer_route(cfg)

    # Remove status file on clean shutdown
    try:
        status_file.unlink(missing_ok=True)
    except Exception:
        pass

    print("  [OK] Tunnel stopped cleanly.")


# ===================================================================
# Status command
# ===================================================================

def cmd_status(args: argparse.Namespace) -> None:
    """Show live tunnel status by reading ~/.aegis/status.json."""
    import json as _json
    from aegis.crypto import OQS_AVAILABLE

    status_file = Path.home() / ".aegis" / "status.json"

    print("====================================================")
    print("                  AEGIS-TUNNEL X                     ")
    print("====================================================")

    if status_file.exists():
        try:
            data = _json.loads(status_file.read_text(encoding="utf-8"))
            mode = data.get("mode", "?").upper()
            session = data.get("session", "unknown")
            uptime = data.get("uptime_s", 0)
            profile = data.get("profile", "?")
            score = data.get("detection_score", "N/A")
            pkts_tx = data.get("pkts_tx", 0)
            pkts_rx = data.get("pkts_rx", 0)
            bytes_tx = data.get("bytes_tx", 0)
            bytes_rx = data.get("bytes_rx", 0)
            tun_name = data.get("tun_name", "?")
            tun_ip = data.get("tun_ip", "?")
            peer_ip = data.get("peer_ip", "?")
            fb = data.get("feedback_enabled", False)

            print(f"  Mode:            {mode}")
            print(f"  Session:         {session}")
            print(f"  Uptime:          {uptime}s")
            print(f"  TUN:             {tun_name} ({tun_ip} <-> {peer_ip})")
            print(f"  Profile:         {profile}")
            print(f"  Detection Score: {score}")
            print(f"  Pkts TX/RX:      {pkts_tx} / {pkts_rx}")
            print(f"  Bytes TX/RX:     {bytes_tx} / {bytes_rx}")
            print(f"  Feedback:        {'enabled' if fb else 'disabled'}")
        except Exception:
            print("  Session:         (error reading status)")
    else:
        print("  Session:         (not connected)")
        print("  Detection Score: N/A")
        print("  Profile:         N/A")
        print("  Pkts TX/RX:      0 / 0")

    pq = "[OK] Kyber768 available" if OQS_AVAILABLE else "[X] Kyber768 unavailable"
    print(f"  PQ Handshake:    {pq}")
    print("====================================================")


# ===================================================================
# Routing helpers
# ===================================================================

def _add_peer_route(cfg: AegisConfig) -> None:
    """Add a host route for the peer IP through the TUN adapter.

    On Windows, ``netsh interface ip set address`` alone does not always
    create the route.  We explicitly add a /32 host route so the OS
    knows to deliver packets for the peer through the TUN adapter.
    """
    import subprocess

    # route ADD <peer_ip> MASK 255.255.255.255 <local_tun_ip>
    try:
        subprocess.run(
            ["route", "ADD", cfg.tun.peer_ip, "MASK", "255.255.255.255",
             cfg.tun.ip],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        logger.info("Added route: %s -> %s", cfg.tun.peer_ip, cfg.tun.ip)
    except subprocess.CalledProcessError as exc:
        # Route may already exist from a previous run
        detail = (exc.stderr or exc.stdout).strip()
        logger.warning("Route add failed (may already exist): %s", detail)
    except FileNotFoundError:
        logger.warning("route command not found; skipping route setup")


def _remove_peer_route(cfg: AegisConfig) -> None:
    """Remove the peer host route on shutdown."""
    import subprocess
    try:
        subprocess.run(
            ["route", "DELETE", cfg.tun.peer_ip],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        logger.info("Removed route: %s", cfg.tun.peer_ip)
    except FileNotFoundError:
        pass


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
