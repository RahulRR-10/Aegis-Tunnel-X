import os
import socket
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

from crypto import decrypt
from shared.config import SERVER_IP, HANDSHAKE_PORT, DATA_PORT


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


def run_handshake_server() -> bytes:
    kem = oqs.KeyEncapsulation("Kyber512")
    public_key = kem.generate_keypair()

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((SERVER_IP, HANDSHAKE_PORT))
    tcp.listen(1)
    print(f"[PQC] Waiting for handshake on TCP {HANDSHAKE_PORT}...")

    conn, addr = tcp.accept()
    with conn:
        print(f"[PQC] Handshake connection from {addr}")
        conn.sendall(len(public_key).to_bytes(4, "big") + public_key)

        ct_len = int.from_bytes(recv_exact(conn, 4), "big")
        ciphertext = recv_exact(conn, ct_len)

    tcp.close()

    shared_secret = kem.decap_secret(ciphertext)
    print("[PQC] Kyber512 handshake complete.")
    print(f"[PQC] Session key prefix: {shared_secret.hex()[:8]}...")
    return shared_secret


def main() -> None:
    session_key = run_handshake_server()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, DATA_PORT))
    print(f"[SERVER] Listening on UDP {DATA_PORT}")

    while True:
        data, addr = sock.recvfrom(65535)
        if len(data) < 2:
            print(f"[SERVER] Dropped malformed packet from {addr}: missing length header")
            continue

        encrypted_len = int.from_bytes(data[:2], "big")
        if len(data) < 2 + encrypted_len:
            print(
                f"[SERVER] Dropped malformed packet from {addr}: "
                f"expected {encrypted_len} encrypted bytes, got {len(data) - 2}"
            )
            continue

        encrypted_payload = data[2:2 + encrypted_len]
        padding_size = len(data) - 2 - encrypted_len

        print(
            f"[SERVER] UDP {len(data)}b from {addr} | encrypted={encrypted_len}b | "
            f"padding={padding_size}b"
        )
        print(f"[SERVER] Ciphertext preview: {encrypted_payload[:40]}")
        plaintext = decrypt(encrypted_payload, session_key)
        print(f"[SERVER] Decrypted: {plaintext}")


if __name__ == "__main__":
    main()
