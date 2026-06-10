import os
import json
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

# Explicitly point Python's DLL search path at the local oqs.dll before importing oqs.
OQS_DLL_PATH = Path(__file__).resolve().parent / "oqs.dll"
if OQS_DLL_PATH.exists():
    dll_dir = str(OQS_DLL_PATH.parent)
    os.environ["PATH"] = dll_dir + os.pathsep + os.environ.get("PATH", "")
    if hasattr(os, "add_dll_directory"):
        os.add_dll_directory(dll_dir)

try:
    import oqs
except Exception as exc:
    raise RuntimeError(
        "Failed to import oqs. Ensure liboqs is installed and loadable. "
        "If using liboqs-python 0.14.1, its auto-installer may fail due a missing upstream tag."
    ) from exc

from crypto import encrypt
from morphic import morph_packet
from shared.config import SERVER_IP, HANDSHAKE_PORT, DATA_PORT, CHAT_PORT
from shared.chat import pack_chat_message

DASHBOARD_BASE_URL = os.getenv("DASHBOARD_BASE_URL", "http://127.0.0.1:5000").rstrip("/")


def recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("Handshake socket closed before all bytes were received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def run_handshake_client() -> bytes:
    kem = oqs.KeyEncapsulation("Kyber512")

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.connect((SERVER_IP, HANDSHAKE_PORT))

    with tcp:
        pk_len = int.from_bytes(recv_exact(tcp, 4), "big")
        public_key = recv_exact(tcp, pk_len)

        ciphertext, shared_secret = kem.encap_secret(public_key)
        tcp.sendall(len(ciphertext).to_bytes(4, "big") + ciphertext)

    print("[PQC] Kyber512 handshake complete.")
    print(f"[PQC] Session key prefix: {shared_secret.hex()[:8]}...")
    return shared_secret


def env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def fetch_engine_state(default: bool) -> bool:
    request = urllib.request.Request(f"{DASHBOARD_BASE_URL}/engine", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return bool(payload.get("engine_on", default))
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return default


def fetch_tunnel_state(default: bool) -> bool:
    """Return True if the dashboard tunnel is currently running."""
    request = urllib.request.Request(f"{DASHBOARD_BASE_URL}/tunnel", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return bool(payload.get("tunnel_running", default))
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        print(f"[DEBUG] fetch_tunnel_state error: {e}")
        return default


def push_stats(stats: dict) -> None:
    payload = json.dumps(stats).encode("utf-8")
    request = urllib.request.Request(
        f"{DASHBOARD_BASE_URL}/stats",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=1.5):
            pass
    except (OSError, urllib.error.URLError, TimeoutError):
        pass


def fetch_chat_outbox() -> list:
    request = urllib.request.Request(f"{DASHBOARD_BASE_URL}/chat/outbox", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=1.5) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data.get("messages", [])
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return []


def main() -> None:
    session_key = run_handshake_client()
    default_engine_on = env_flag("MORPHIC_ENGINE_ON", True)
    packet_interval_ms = env_int("PACKET_INTERVAL_MS", 400)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    chat_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(
        "[CLIENT] Continuous packet loop started. "
        f"interval={packet_interval_ms}ms, dashboard={DASHBOARD_BASE_URL}"
    )
    print("[CLIENT] Waiting for START TUNNEL signal from dashboard...")

    i = 0
    while True:
        tunnel_running = fetch_tunnel_state(default=False)
        if not tunnel_running:
            time.sleep(0.5)
            continue

        pending = fetch_chat_outbox()
        for msg in pending:
            chat_payload = pack_chat_message(msg)
            chat_encrypted = encrypt(chat_payload, session_key)
            chat_stats = morph_packet(chat_encrypted, engine_on=True)
            send_data = chat_stats.get("packet", chat_encrypted)
            length_header = len(chat_encrypted).to_bytes(2, "big")
            chat_sock.sendto(length_header + send_data, (SERVER_IP, CHAT_PORT))
            print(f"[CHAT] Sent encrypted message: {msg}")

        engine_on = fetch_engine_state(default_engine_on)
        payload = f"TEST PACKET {i} - hello from client".encode()
        encrypted = encrypt(payload, session_key)
        stats = morph_packet(encrypted, engine_on=engine_on)

        send_data = stats.get("packet", encrypted)
        length_header = len(encrypted).to_bytes(2, "big")
        sock.sendto(length_header + send_data, (SERVER_IP, DATA_PORT))

        stats_for_dashboard = dict(stats)
        stats_for_dashboard.pop("packet", None)
        stats_for_dashboard["session_key_prefix"] = session_key.hex()[:8]
        push_stats(stats_for_dashboard)

        if stats["engine_on"]:
            print(
                "[MORPH] "
                f"{stats['original_size']}b -> +{stats['padding_size']}b pad | "
                f"entropy {stats['raw_entropy']}->{stats['final_entropy']} | "
                f"jitter {stats['jitter_ms']}ms"
            )
        else:
            print(
                "[WARN ] "
                f"{stats['original_size']}b | entropy {stats['raw_entropy']} | "
                "ENGINE OFF"
            )

        i += 1
        time.sleep(packet_interval_ms / 1000)


if __name__ == "__main__":
    main()
