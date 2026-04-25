"""Phase F0 — FastAPI Backend API Bridge.

Non-invasive FastAPI server that exposes all existing backend state
via REST + WebSocket endpoints.  Does **not** modify any Phase 1-8 modules.

Running (standalone, alongside a running tunnel)::

    uvicorn aegis.api:app --host 127.0.0.1 --port 8765 --reload

The API shares the running AegisTunnel instance via a module-level
singleton.  Call ``register()`` from the tunnel orchestrator for full
live access, or run standalone (reads ``~/.aegis/status.json`` as
fallback written by ``cli.py``).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import yaml

__all__ = ["app", "register", "get_state"]

logger = logging.getLogger("aegis.api")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_STATUS_FILE = Path.home() / ".aegis" / "status.json"
_PROFILES_DIR = Path(__file__).parent.parent / "profiles"
_PROJECT_ROOT = Path(__file__).parent.parent
_DEMO_SCRIPT = _PROJECT_ROOT / "demo" / "run_demo.ps1"


# ===================================================================
# State Management — Module-level singleton
# ===================================================================

class AegisState:
    """Holds references to live backend components.

    When the API runs in-process with the tunnel (via ``register()``),
    all fields are populated with live object references.

    When running standalone, fields are ``None`` and the API falls back
    to reading ``~/.aegis/status.json``.
    """

    def __init__(self) -> None:
        self.tunnel: Any = None          # AegisTunnel
        self.transport: Any = None       # AegisTunnelServer | AegisTunnelClient
        self.tun: Any = None             # TunInterface
        self.morphic: Any = None         # MorphicEngine
        self.analyzer: Any = None        # TrafficAnalyzer
        self.feedback: Any = None        # FeedbackLoop
        self.config: Any = None          # AegisConfig
        self.start_time: float = time.time()
        self._live: bool = False

    @property
    def is_live(self) -> bool:
        """True if live backend objects are registered."""
        return self._live and self.tunnel is not None

    def read_status_file(self) -> dict[str, Any] | None:
        """Read the status.json file written by the CLI."""
        if not _STATUS_FILE.exists():
            return None
        try:
            return json.loads(_STATUS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return None

    @property
    def is_tunnel_available(self) -> bool:
        """True if tunnel state is available (live or via status file)."""
        if self.is_live:
            return True
        return self.read_status_file() is not None


# Module-level singleton
_state = AegisState()


def register(
    *,
    tunnel: Any = None,
    transport: Any = None,
    tun: Any = None,
    morphic: Any = None,
    analyzer: Any = None,
    feedback: Any = None,
    config: Any = None,
) -> None:
    """Register live backend components with the API bridge.

    Call this from the tunnel orchestrator to enable full-fidelity
    API access to all backend state.
    """
    if tunnel is not None:
        _state.tunnel = tunnel
    if transport is not None:
        _state.transport = transport
    if tun is not None:
        _state.tun = tun
    if morphic is not None:
        _state.morphic = morphic
    if analyzer is not None:
        _state.analyzer = analyzer
    if feedback is not None:
        _state.feedback = feedback
    if config is not None:
        _state.config = config
    _state.start_time = time.time()
    _state._live = True
    logger.info("Live backend state registered with API bridge")


def get_state() -> AegisState:
    """Return the module-level state singleton."""
    return _state


# ===================================================================
# Helpers
# ===================================================================

def _truncate_hex(data: bytes, head: int = 4, tail: int = 4) -> str:
    """Truncate bytes to ``head…tail`` hex representation."""
    h = data.hex()
    if len(data) <= head + tail:
        return h
    return f"{h[:head * 2]}...{h[-(tail * 2):]}"


def _get_session() -> Any | None:
    """Get the active UDPSession from the transport layer."""
    transport = _state.transport
    if transport is None:
        return None
    # Client mode
    if hasattr(transport, "_session") and transport._session is not None:
        return transport._session
    # Server mode — first active session
    if hasattr(transport, "_sessions") and transport._sessions:
        return next(iter(transport._sessions.values()))
    return None


def _require_tunnel() -> None:
    """Raise 503 if no tunnel state is available."""
    if not _state.is_tunnel_available:
        raise HTTPException(
            status_code=503,
            detail="Tunnel is not running. Start the tunnel first.",
        )


def _load_profile_json(name: str) -> dict[str, Any]:
    """Load a profile JSON file from the profiles directory."""
    path = _PROFILES_DIR / f"{name}.json"
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _key_file_status(key_dir: Path) -> list[dict[str, Any]]:
    """Check existence and size of expected key files."""
    expected = [
        "kyber_priv.bin", "kyber_pub.bin",
        "x25519_priv.bin", "x25519_pub.bin",
    ]
    result = []
    for fname in expected:
        fpath = key_dir / fname
        result.append({
            "name": fname,
            "exists": fpath.exists(),
            "size_bytes": fpath.stat().st_size if fpath.exists() else 0,
        })
    return result


def _resolve_key_dir(key_dir_value: Any) -> Path | None:
    """Resolve key_dir path from config content."""
    if not key_dir_value:
        return None

    key_dir = Path(str(key_dir_value)).expanduser()
    if not key_dir.is_absolute():
        key_dir = (_PROJECT_ROOT / key_dir).resolve()
    return key_dir


def _redacted_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return config with sensitive path details redacted."""
    redacted = json.loads(json.dumps(config))
    crypto = redacted.get("crypto")
    if isinstance(crypto, dict) and "key_dir" in crypto:
        crypto["key_dir"] = "[REDACTED]"
    return redacted


def _config_snapshot_from_live() -> dict[str, Any] | None:
    """Build a normalized config snapshot from live in-process state."""
    if not (_state.is_live and _state.config):
        return None

    cfg_dict = _state.config.to_dict()
    key_dir = _state.config.crypto.key_dir
    return {
        "live": True,
        "mode": _state.config.mode,
        "config_file": "live",
        "config": _redacted_config(cfg_dict),
        "key_dir": str(key_dir),
        "key_files": _key_file_status(key_dir),
    }


def _config_snapshot_from_file(conf_path: Path) -> dict[str, Any] | None:
    """Build a normalized config snapshot from a demo config file."""
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except Exception:
        return None

    mode = str(raw.get("mode", "unknown")).lower()
    key_dir = _resolve_key_dir(raw.get("crypto", {}).get("key_dir"))

    return {
        "live": False,
        "mode": mode,
        "config_file": conf_path.name,
        "config": _redacted_config(raw),
        "key_dir": str(key_dir) if key_dir else "N/A",
        "key_files": _key_file_status(key_dir) if key_dir else [],
    }


def _fallback_config_snapshots() -> list[dict[str, Any]]:
    """Collect normalized snapshots from demo config files."""
    snapshots: list[dict[str, Any]] = []
    for conf_name in ["server.conf", "client.conf"]:
        conf_path = _PROJECT_ROOT / "demo" / conf_name
        if not conf_path.exists():
            continue
        snap = _config_snapshot_from_file(conf_path)
        if snap:
            snapshots.append(snap)
    return snapshots


def _preferred_mode_from_status() -> str | None:
    """Infer preferred mode from status.json if available."""
    data = _state.read_status_file() or {}
    mode = str(data.get("mode", "")).lower()
    return mode if mode in {"server", "client"} else None


def _select_config_snapshot(
    snapshots: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Select the best config snapshot for UI display and actions."""
    if not snapshots:
        return None

    preferred_mode = _preferred_mode_from_status()
    if preferred_mode:
        for snap in snapshots:
            if snap.get("mode") == preferred_mode:
                return snap

    return snapshots[0]


# ===================================================================
# Demo Manager
# ===================================================================

class _DemoManager:
    """Manages demo subprocess lifecycle."""

    _STEP_NAMES = [
        "Key generation", "Start server", "Start client",
        "Await handshake", "Send test traffic", "Bulk 10MB xfer",
        "Switch profile", "Print status",
    ]

    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.status: str = "idle"
        self.steps: list[dict[str, str]] = self._init_steps()
        self.output_lines: list[str] = []

    def _init_steps(self) -> list[dict[str, str]]:
        return [{"name": n, "status": "pending"} for n in self._STEP_NAMES]

    async def start(self) -> dict[str, str]:
        if self.status == "running":
            return {"detail": "Demo is already running"}
        self.steps = self._init_steps()
        self.output_lines = []
        self.status = "running"
        try:
            self.process = subprocess.Popen(
                ["powershell", "-ExecutionPolicy", "Bypass",
                 "-File", str(_DEMO_SCRIPT)],
                cwd=str(_PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW
                if sys.platform == "win32" else 0,
            )
            # Start background reader
            asyncio.get_event_loop().run_in_executor(
                None, self._read_output,
            )
        except Exception as exc:
            self.status = "failed"
            return {"detail": f"Failed to start demo: {exc}"}
        return {"detail": "Demo started"}

    def _read_output(self) -> None:
        """Read stdout lines from the demo subprocess."""
        if self.process is None or self.process.stdout is None:
            return
        step_idx = 0
        for line in self.process.stdout:
            line = line.rstrip()
            self.output_lines.append(line)
            if len(self.output_lines) > 500:
                self.output_lines = self.output_lines[-500:]
            # Track steps by [N/8] markers
            for i in range(8):
                marker = f"[{i + 1}/8]"
                if marker in line:
                    if step_idx < len(self.steps):
                        self.steps[step_idx]["status"] = "done"
                    step_idx = i
                    if step_idx < len(self.steps):
                        self.steps[step_idx]["status"] = "active"
        # Mark final step done
        if step_idx < len(self.steps):
            self.steps[step_idx]["status"] = "done"
        rc = self.process.wait()
        self.status = "completed" if rc == 0 else "failed"

    def stop(self) -> dict[str, str]:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process = None
            self.status = "stopped"
            return {"detail": "Demo stopped"}
        return {"detail": "No demo process running"}

    def get_status(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "steps": self.steps,
            "output_lines": self.output_lines[-50:],
        }


_demo = _DemoManager()


class _TestManager:
    """Manages E2E test suite subprocess lifecycle."""

    _TEST_NAMES = [
        "E2E-1: Handshake < 500ms",
        "E2E-2: 10MB transfer integrity",
        "E2E-3: Detection score < 0.30",
        "E2E-4: Profile hot-swap",
        "E2E-5: Client reconnect",
        "E2E-6: Forged packet drop",
    ]

    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.status: str = "idle"
        self.tests: list[dict[str, str]] = self._init_tests()
        self.output_lines: list[str] = []

    def _init_tests(self) -> list[dict[str, str]]:
        return [{"name": n, "status": "pending"} for n in self._TEST_NAMES]

    async def start(self) -> dict[str, str]:
        if self.status == "running":
            return {"detail": "Tests are already running"}
        self.tests = self._init_tests()
        self.output_lines = []
        self.status = "running"
        try:
            # We run pytest against tests/test_e2e.py
            self.process = subprocess.Popen(
                ["pytest", "tests/test_e2e.py", "-v"],
                cwd=str(_PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            asyncio.get_event_loop().run_in_executor(None, self._read_output)
        except Exception as exc:
            self.status = "failed"
            return {"detail": f"Failed to start tests: {exc}"}
        return {"detail": "Tests started"}

    def _read_output(self) -> None:
        """Read stdout lines from pytest."""
        if self.process is None or self.process.stdout is None:
            return
        
        current_test_idx = -1
        
        for line in self.process.stdout:
            line = line.rstrip()
            self.output_lines.append(line)
            if len(self.output_lines) > 500:
                self.output_lines = self.output_lines[-500:]
            
            # Very basic parsing of pytest -v output
            # tests/test_e2e.py::test_handshake_under_500ms PASSED
            if "tests/test_e2e.py::" in line:
                if "test_handshake_under_500ms" in line:
                    current_test_idx = 0
                elif "test_data_transfer_integrity" in line:
                    current_test_idx = 1
                elif "test_detection_score_low_for_profile_traffic" in line:
                    current_test_idx = 2
                elif "test_profile_hotswap_no_packet_loss" in line:
                    current_test_idx = 3
                elif "test_client_reconnect" in line:
                    current_test_idx = 4
                elif "test_forged_packet_dropped" in line:
                    current_test_idx = 5
                
                if current_test_idx != -1 and current_test_idx < len(self.tests):
                    if "PASSED" in line:
                        self.tests[current_test_idx]["status"] = "passed"
                    elif "FAILED" in line or "ERROR" in line:
                        self.tests[current_test_idx]["status"] = "failed"
                    elif "SKIPPED" in line:
                        self.tests[current_test_idx]["status"] = "skipped"
                    else:
                        self.tests[current_test_idx]["status"] = "active"

        rc = self.process.wait()
        self.status = "completed" if rc == 0 else "failed"

    def get_status(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "tests": self.tests,
            "output_lines": self.output_lines[-50:],
        }


_tests = _TestManager()


# ===================================================================
# FastAPI Application
# ===================================================================

app = FastAPI(
    title="Aegis-Tunnel X API",
    description="Backend API bridge for the Aegis-Tunnel X dashboard",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===================================================================
# REST Endpoints
# ===================================================================

@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    """Session ID, uptime, mode, connection info."""
    _require_tunnel()

    # Live mode
    if _state.is_live:
        session = _get_session()
        stats = _state.tunnel.packet_stats if _state.tunnel else {}
        session_id = _truncate_hex(session.session_id) if session else "N/A"
        mode = "unknown"
        if _state.config:
            mode = _state.config.mode
        handshake = session is not None
        connected_to = ""
        if session:
            connected_to = f"{session.remote_addr[0]}:{session.remote_addr[1]}"
        return {
            "session_id": session_id,
            "mode": mode,
            "uptime_s": round(time.time() - _state.start_time, 1),
            "handshake_done": handshake,
            "connected_to": connected_to,
            "bytes_tx": stats.get("bytes_sent", 0),
            "bytes_rx": stats.get("bytes_recv", 0),
            "pkts_tx": stats.get("sent_count", 0),
            "pkts_rx": stats.get("recv_count", 0),
            "avg_latency_ms": stats.get("avg_latency_ms", 0.0),
        }

    # Fallback: status.json
    data = _state.read_status_file()
    if data is None:
        raise HTTPException(503, "Tunnel is not running.")
    return {
        "session_id": "N/A",
        "mode": data.get("mode", "unknown"),
        "uptime_s": data.get("uptime_s", 0),
        "handshake_done": data.get("session") == "active",
        "connected_to": "",
        "bytes_tx": data.get("bytes_tx", 0),
        "bytes_rx": data.get("bytes_rx", 0),
        "pkts_tx": data.get("pkts_tx", 0),
        "pkts_rx": data.get("pkts_rx", 0),
        "avg_latency_ms": 0.0,
    }


@app.get("/api/crypto")
async def get_crypto() -> dict[str, Any]:
    """Algorithm names, handshake status, key fingerprints."""
    _require_tunnel()

    session = _get_session() if _state.is_live else None

    result: dict[str, Any] = {
        "algorithms": {
            "kem": "Kyber-768",
            "dh": "X25519",
            "aead": "AES-256-GCM",
            "kdf": "HKDF-SHA256",
        },
        "key_sizes": {
            "aes_key": 256,
            "nonce": 96,
            "kyber_pub": 1184,
            "x25519_pub": 256,
        },
        "handshake_done": session is not None,
        "nonce_counter": 0,
        "fingerprints": {"kyber_pub": "N/A", "x25519_pub": "N/A"},
    }

    if session and hasattr(session, "crypto"):
        result["nonce_counter"] = session.crypto.counter
    if session and hasattr(session, "session_id"):
        result["session_id"] = _truncate_hex(session.session_id)

    # Try to read key fingerprints from disk
    key_dir = None
    if _state.config:
        key_dir = _state.config.crypto.key_dir
    else:
        # Guess from demo config
        for candidate in [
            _PROJECT_ROOT / "demo" / "keys" / "server",
            _PROJECT_ROOT / "demo" / "keys" / "client",
        ]:
            if candidate.exists():
                key_dir = candidate
                break

    if key_dir:
        kyber_pub = key_dir / "kyber_pub.bin"
        x25519_pub = key_dir / "x25519_pub.bin"
        if kyber_pub.exists():
            result["fingerprints"]["kyber_pub"] = _truncate_hex(
                kyber_pub.read_bytes()
            )
        if x25519_pub.exists():
            result["fingerprints"]["x25519_pub"] = _truncate_hex(
                x25519_pub.read_bytes()
            )

    return result


@app.get("/api/transport")
async def get_transport() -> dict[str, Any]:
    """Seq counter, recv_window size, keepalive timer."""
    _require_tunnel()

    session = _get_session() if _state.is_live else None
    if session is None:
        # Return basic info from status file
        data = _state.read_status_file() or {}
        return {
            "seq_counter": 0,
            "recv_window_fill": 0,
            "recv_window_size": 64,
            "keepalive_interval_s": 25.0,
            "missed_keepalives": 0,
            "remote_addr": "",
            "session_id": "N/A",
        }

    elapsed = time.monotonic() - session.last_seen
    return {
        "seq_counter": session.seq_counter,
        "recv_window_fill": len(session.recv_window),
        "recv_window_size": session.recv_window.maxlen or 64,
        "keepalive_interval_s": 25.0,
        "keepalive_timer_remaining_s": round(
            max(0, 25.0 - elapsed), 1
        ),
        "missed_keepalives": session.missed_keepalives,
        "remote_addr": f"{session.remote_addr[0]}:{session.remote_addr[1]}",
        "session_id": _truncate_hex(session.session_id),
    }


@app.get("/api/tunnel")
async def get_tunnel() -> dict[str, Any]:
    """TX/RX bytes, packet counts, avg latency, TUN IP/peer."""
    _require_tunnel()

    if _state.is_live and _state.tunnel:
        stats = _state.tunnel.packet_stats
        tun_info = {}
        if _state.tun:
            tun_info = {
                "name": getattr(_state.tun, "name", "N/A"),
                "ip": getattr(_state.tun, "ip", "N/A"),
                "peer_ip": getattr(_state.tun, "peer_ip", "N/A"),
                "mtu": getattr(_state.tun, "mtu", 1400),
                "state": "UP" if _state.tunnel.is_running else "DOWN",
            }
        return {
            "tun": tun_info,
            "bytes_tx": stats.get("bytes_sent", 0),
            "bytes_rx": stats.get("bytes_recv", 0),
            "pkts_tx": stats.get("sent_count", 0),
            "pkts_rx": stats.get("recv_count", 0),
            "avg_latency_ms": stats.get("avg_latency_ms", 0.0),
        }

    data = _state.read_status_file() or {}
    return {
        "tun": {
            "name": data.get("tun_name", "N/A"),
            "ip": data.get("tun_ip", "N/A"),
            "peer_ip": data.get("peer_ip", "N/A"),
            "mtu": 1400,
            "state": "UP" if data.get("session") == "active" else "DOWN",
        },
        "bytes_tx": data.get("bytes_tx", 0),
        "bytes_rx": data.get("bytes_rx", 0),
        "pkts_tx": data.get("pkts_tx", 0),
        "pkts_rx": data.get("pkts_rx", 0),
        "avg_latency_ms": 0.0,
    }


@app.get("/api/morphic")
async def get_morphic() -> dict[str, Any]:
    """Active profile name, current distribution params."""
    _require_tunnel()

    if _state.is_live and _state.morphic:
        profile_name = _state.morphic.profile_name
        return {
            "profile": profile_name,
            "available_profiles": _state.morphic.list_profiles(),
            "params": _state.morphic.current_profile,
        }

    # Standalone: read from status file + profile JSON
    data = _state.read_status_file() or {}
    profile_name = data.get("profile", "web_browsing")
    profiles = sorted(
        p.stem for p in _PROFILES_DIR.glob("*.json")
    ) if _PROFILES_DIR.exists() else []
    return {
        "profile": profile_name,
        "available_profiles": profiles,
        "params": _load_profile_json(profile_name),
    }


@app.get("/api/feedback")
async def get_feedback() -> dict[str, Any]:
    """Detection score, all 5 metrics, history (last 100)."""
    _require_tunnel()

    if _state.is_live and _state.analyzer and _state.morphic:
        profile = _state.morphic.current_profile
        score = _state.analyzer.detection_score(profile)
        metrics = _state.analyzer.metrics(profile)
        history = _state.feedback.history if _state.feedback else []
        return {
            "detection_score": round(score, 4),
            "threshold": 0.25,
            "adaptation_count": sum(
                1 for h in history if h.get("action", "none") != "none"
            ),
            "metrics": {
                "entropy": round(metrics.get("entropy", 0), 4),
                "ipd_cv": round(metrics.get("ipd_cv", 0), 4),
                "size_chi2_p": round(metrics.get("size_chi2_pvalue", 0), 4),
                "burstiness": round(metrics.get("burstiness", 0), 4),
                "periodicity": round(metrics.get("periodicity", 0), 4),
            },
            "history": history,
            "sample_count": _state.analyzer.sample_count,
        }

    data = _state.read_status_file() or {}
    score_str = data.get("detection_score", "N/A")
    try:
        score_val = float(score_str)
    except (ValueError, TypeError):
        score_val = 0.0
    return {
        "detection_score": score_val,
        "threshold": 0.25,
        "adaptation_count": 0,
        "metrics": {
            "entropy": 0.0, "ipd_cv": 0.0, "size_chi2_p": 0.0,
            "burstiness": 0.0, "periodicity": 0.0,
        },
        "history": [],
        "sample_count": 0,
    }


@app.get("/api/config")
async def get_config() -> dict[str, Any]:
    """Rendered server/client config (secrets redacted)."""
    live_snapshot = _config_snapshot_from_live()
    if live_snapshot:
        return live_snapshot

    snapshots = _fallback_config_snapshots()
    selected = _select_config_snapshot(snapshots)

    if selected is None:
        raise HTTPException(503, "No configuration available.")

    return {
        **selected,
        "available_configs": [
            {
                "config_file": snap.get("config_file", "unknown"),
                "mode": snap.get("mode", "unknown"),
            }
            for snap in snapshots
        ],
    }


@app.post("/api/keygen")
async def regenerate_keys() -> dict[str, Any]:
    """Generate key files into the active config key directory."""
    live_snapshot = _config_snapshot_from_live()
    if live_snapshot:
        target_key_dir = Path(live_snapshot["key_dir"])
    else:
        snapshots = _fallback_config_snapshots()
        selected = _select_config_snapshot(snapshots)
        if selected is None or selected.get("key_dir") in (None, "N/A"):
            raise HTTPException(503, "No configuration with key_dir is available.")
        target_key_dir = Path(str(selected["key_dir"]))

    try:
        from aegis.cli import cmd_keygen

        args = argparse.Namespace(output=str(target_key_dir))
        output_buffer = io.StringIO()
        with contextlib.redirect_stdout(output_buffer):
            cmd_keygen(args)

        output_lines = [
            line for line in output_buffer.getvalue().splitlines()
            if line.strip()
        ]
        return {
            "detail": "Keys generated",
            "output_dir": str(target_key_dir),
            "key_files": _key_file_status(target_key_dir),
            "output_lines": output_lines[-20:],
        }
    except Exception as exc:
        raise HTTPException(500, f"Key generation failed: {exc}") from exc


@app.post("/api/profile/{name}")
async def switch_profile(name: str) -> dict[str, str]:
    """Switch the morphic traffic profile."""
    if _state.is_live and _state.morphic:
        try:
            _state.morphic.switch_profile(name)
            return {"detail": f"Switched to profile: {name}"}
        except FileNotFoundError:
            raise HTTPException(404, f"Profile '{name}' not found")

    # Validate the profile exists even in standalone mode
    path = _PROFILES_DIR / f"{name}.json"
    if not path.exists():
        raise HTTPException(404, f"Profile '{name}' not found")
    raise HTTPException(
        503, "Profile switching requires the tunnel to be running.",
    )


@app.post("/api/demo/start")
async def demo_start() -> dict[str, str]:
    """Start the demo subprocess sequence."""
    return await _demo.start()


@app.post("/api/demo/stop")
async def demo_stop() -> dict[str, str]:
    """Kill demo processes."""
    return _demo.stop()


@app.get("/api/demo/status")
async def demo_status() -> dict[str, Any]:
    """Demo step progress and output."""
    return _demo.get_status()


@app.post("/api/demo/run_tests")
async def run_e2e_tests() -> dict[str, str]:
    """Run E2E tests in background."""
    return await _tests.start()


@app.get("/api/demo/test_status")
async def test_status() -> dict[str, Any]:
    """Test progress and output."""
    return _tests.get_status()


# ===================================================================
# WebSocket — /ws/metrics
# ===================================================================

@app.websocket("/ws/metrics")
async def ws_metrics(websocket: WebSocket) -> None:
    """Push a JSON metrics frame every ~500 ms."""
    await websocket.accept()
    logger.info("WebSocket client connected")

    try:
        while True:
            frame = _build_ws_frame()
            await websocket.send_json(frame)
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as exc:
        logger.debug("WebSocket error: %s", exc)


def _build_ws_frame() -> dict[str, Any]:
    """Construct a single WebSocket metrics frame."""
    frame: dict[str, Any] = {
        "ts": time.time(),
        "bytes_tx": 0,
        "bytes_rx": 0,
        "pkts_tx": 0,
        "pkts_rx": 0,
        "latency_ms": 0.0,
        "detection_score": 0.0,
        "metrics": {
            "entropy": 0.0,
            "ipd_cv": 0.0,
            "size_chi2_p": 0.0,
            "burstiness": 0.0,
            "periodicity": 0.0,
        },
        "profile": "N/A",
        "seq_counter": 0,
        "handshake_done": False,
    }

    # Live mode — full fidelity
    if _state.is_live:
        if _state.tunnel:
            stats = _state.tunnel.packet_stats
            frame["bytes_tx"] = stats.get("bytes_sent", 0)
            frame["bytes_rx"] = stats.get("bytes_recv", 0)
            frame["pkts_tx"] = stats.get("sent_count", 0)
            frame["pkts_rx"] = stats.get("recv_count", 0)
            frame["latency_ms"] = stats.get("avg_latency_ms", 0.0)

        session = _get_session()
        if session:
            frame["seq_counter"] = session.seq_counter
            frame["handshake_done"] = True

        if _state.morphic:
            frame["profile"] = _state.morphic.profile_name

        if _state.analyzer and _state.morphic:
            profile = _state.morphic.current_profile
            try:
                frame["detection_score"] = round(
                    _state.analyzer.detection_score(profile), 4
                )
                m = _state.analyzer.metrics(profile)
                frame["metrics"] = {
                    "entropy": round(m.get("entropy", 0), 4),
                    "ipd_cv": round(m.get("ipd_cv", 0), 4),
                    "size_chi2_p": round(m.get("size_chi2_pvalue", 0), 4),
                    "burstiness": round(m.get("burstiness", 0), 4),
                    "periodicity": round(m.get("periodicity", 0), 4),
                }
            except Exception:
                pass

        return frame

    # Standalone — read status.json
    data = _state.read_status_file()
    if data:
        frame["bytes_tx"] = data.get("bytes_tx", 0)
        frame["bytes_rx"] = data.get("bytes_rx", 0)
        frame["pkts_tx"] = data.get("pkts_tx", 0)
        frame["pkts_rx"] = data.get("pkts_rx", 0)
        frame["profile"] = data.get("profile", "N/A")
        frame["handshake_done"] = data.get("session") == "active"
        try:
            frame["detection_score"] = float(
                data.get("detection_score", 0)
            )
        except (ValueError, TypeError):
            pass

    return frame
