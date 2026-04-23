"""Phase 2 Tests — Encryption Engine.

Test 2-A: Kyber keypair generates; encapsulate + decapsulate → same shared secret
Test 2-B: SessionCrypto.encrypt → SessionCrypto.decrypt roundtrip (256 random payloads)
Test 2-C: Bit-flip in ciphertext raises cryptography.exceptions.InvalidTag
Test 2-D: Nonce counter increments per call; two encryptions of identical plaintext
          produce different ciphertexts
Test 2-E: Full hybrid handshake simulation → both sides derive identical master_key
Test 2-F: AAD mismatch raises InvalidTag
"""

from __future__ import annotations

import os
import time

import pytest
from cryptography.exceptions import InvalidTag

from aegis.crypto import (
    OQS_AVAILABLE,
    KyberKeyPair,
    SessionCrypto,
    X25519KeyPair,
    derive_master_key,
    derive_session_keys,
    kyber_encapsulate,
    perform_handshake_client,
    perform_handshake_server,
)


# ---------------------------------------------------------------------------
# Marks
# ---------------------------------------------------------------------------

requires_oqs = pytest.mark.skipif(
    not OQS_AVAILABLE,
    reason="liboqs native library not available on this system",
)


# ---------------------------------------------------------------------------
# Test 2-A: Kyber keypair generates; encapsulate + decapsulate → same secret
# ---------------------------------------------------------------------------

@requires_oqs
def test_kyber_encapsulate_decapsulate() -> None:
    """Kyber-768: server keypair → client encapsulates → server decapsulates
    → both sides share the same secret."""
    server_kp = KyberKeyPair()

    # Client encapsulates against server's public key
    ciphertext, client_secret = kyber_encapsulate(server_kp.public_key)

    # Server decapsulates
    server_secret = server_kp.decapsulate(ciphertext)

    # Both sides must have the same shared secret
    assert client_secret == server_secret
    assert len(client_secret) == 32  # Kyber768 shared secret is 32 bytes


# ---------------------------------------------------------------------------
# Test 2-B: Encrypt → decrypt roundtrip (256 random payloads)
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip() -> None:
    """SessionCrypto: encrypt then decrypt 256 random payloads of varying
    sizes — all must roundtrip correctly."""
    master_key = os.urandom(32)
    crypto = SessionCrypto(master_key)
    session_id = os.urandom(8)

    for i in range(256):
        # Vary payload sizes: 0, 1, 16, 64, 256, 1024, up to ~1400 bytes
        size = (i * 7) % 1401
        plaintext = os.urandom(size)
        aad = session_id

        encrypted = crypto.encrypt(plaintext, aad=aad)

        # Decrypt with a fresh SessionCrypto sharing the same master_key
        # (simulates the other side)
        # Note: we use the SAME crypto instance here since decrypt doesn't
        # depend on the counter — it reads the nonce from the blob
        decrypted = crypto.decrypt(encrypted, aad=aad)

        assert decrypted == plaintext, f"roundtrip failed at iteration {i}"


# ---------------------------------------------------------------------------
# Test 2-C: Bit-flip in ciphertext raises InvalidTag
# ---------------------------------------------------------------------------

def test_bitflip_raises_invalid_tag() -> None:
    """A single bit-flip in the ciphertext must cause InvalidTag on decrypt."""
    master_key = os.urandom(32)
    crypto = SessionCrypto(master_key)

    plaintext = b"sensitive payload for tamper test"
    aad = b"session-123"
    encrypted = crypto.encrypt(plaintext, aad=aad)

    # Flip a bit in the middle of the ciphertext (past the 12-byte nonce)
    corrupted = bytearray(encrypted)
    flip_pos = len(corrupted) // 2
    corrupted[flip_pos] ^= 0x01
    corrupted = bytes(corrupted)

    with pytest.raises(InvalidTag):
        crypto.decrypt(corrupted, aad=aad)


# ---------------------------------------------------------------------------
# Test 2-D: Nonce counter increments; identical plaintext → different output
# ---------------------------------------------------------------------------

def test_nonce_counter_and_ciphertext_uniqueness() -> None:
    """Two encryptions of the same plaintext must produce different
    ciphertexts, and the internal counter must increment."""
    master_key = os.urandom(32)
    crypto = SessionCrypto(master_key)

    assert crypto.counter == 0

    plaintext = b"identical payload"
    aad = b"session-456"

    ct1 = crypto.encrypt(plaintext, aad=aad)
    assert crypto.counter == 1

    ct2 = crypto.encrypt(plaintext, aad=aad)
    assert crypto.counter == 2

    # Same plaintext, but different nonces → different ciphertexts
    assert ct1 != ct2

    # The nonce prefix (first 12 bytes) must be different
    assert ct1[:12] != ct2[:12]

    # But both must decrypt to the same plaintext
    assert crypto.decrypt(ct1, aad=aad) == plaintext
    assert crypto.decrypt(ct2, aad=aad) == plaintext


# ---------------------------------------------------------------------------
# Test 2-E: Full hybrid handshake → both sides derive identical master_key
# ---------------------------------------------------------------------------

@requires_oqs
def test_full_hybrid_handshake() -> None:
    """Simulate the complete Kyber-768 + X25519 hybrid handshake:
    server and client must derive the same master_key and be able to
    cross-encrypt/decrypt."""
    salt = os.urandom(16)

    # --- Server side ---
    server_kyber = KyberKeyPair()
    server_x25519 = X25519KeyPair()

    # --- Client side ---
    # Client receives server's public keys and performs handshake
    kyber_ct, client_x25519_pub, client_session = perform_handshake_client(
        server_kyber_pub=server_kyber.public_key,
        server_x25519_pub=server_x25519.public_key_bytes,
        salt=salt,
    )

    # --- Server side (continued) ---
    # Server receives client's ciphertext and X25519 pub, completes handshake
    server_session = perform_handshake_server(
        kyber_kp=server_kyber,
        x25519_kp=server_x25519,
        client_kyber_ciphertext=kyber_ct,
        client_x25519_pub=client_x25519_pub,
        salt=salt,
    )

    # --- Verify cross-encryption works ---
    # Client encrypts, server decrypts
    session_id = os.urandom(8)
    client_msg = b"Hello from client"
    ct = client_session.encrypt(client_msg, aad=session_id)
    assert server_session.decrypt(ct, aad=session_id) == client_msg

    # Server encrypts, client decrypts
    server_msg = b"Hello from server"
    ct2 = server_session.encrypt(server_msg, aad=session_id)
    assert client_session.decrypt(ct2, aad=session_id) == server_msg


# ---------------------------------------------------------------------------
# Test 2-F: AAD mismatch raises InvalidTag
# ---------------------------------------------------------------------------

def test_aad_mismatch_raises_invalid_tag() -> None:
    """Encrypting with one AAD and decrypting with a different AAD
    must raise InvalidTag."""
    master_key = os.urandom(32)
    crypto = SessionCrypto(master_key)

    plaintext = b"aad mismatch test"
    encrypted = crypto.encrypt(plaintext, aad=b"correct-session-id")

    with pytest.raises(InvalidTag):
        crypto.decrypt(encrypted, aad=b"wrong-session-id")


# ---------------------------------------------------------------------------
# Bonus: X25519 standalone exchange test (always runs, no liboqs needed)
# ---------------------------------------------------------------------------

def test_x25519_key_exchange() -> None:
    """X25519: two parties generate keypairs and derive the same shared secret."""
    alice = X25519KeyPair()
    bob = X25519KeyPair()

    alice_secret = alice.exchange(bob.public_key_bytes)
    bob_secret = bob.exchange(alice.public_key_bytes)

    assert alice_secret == bob_secret
    assert len(alice_secret) == 32


# ---------------------------------------------------------------------------
# Bonus: derive_session_keys determinism
# ---------------------------------------------------------------------------

def test_derive_session_keys_deterministic() -> None:
    """Same master_key and salt must produce the same AES key and nonce base."""
    master_key = os.urandom(32)
    salt = os.urandom(16)

    aes_key_1, nonce_base_1 = derive_session_keys(master_key, salt=salt)
    aes_key_2, nonce_base_2 = derive_session_keys(master_key, salt=salt)

    assert aes_key_1 == aes_key_2
    assert nonce_base_1 == nonce_base_2
    assert len(aes_key_1) == 32
    assert len(nonce_base_1) == 12


# ---------------------------------------------------------------------------
# Bonus: derive_master_key XOR correctness
# ---------------------------------------------------------------------------

def test_derive_master_key_xor() -> None:
    """derive_master_key XORs the two secrets correctly."""
    a = bytes(range(32))
    b = bytes(range(32, 64))
    result = derive_master_key(a, b)
    expected = bytes(x ^ y for x, y in zip(a, b))
    assert result == expected


# ---------------------------------------------------------------------------
# Bonus: Throughput benchmark (informational, not a pass/fail gate)
# ---------------------------------------------------------------------------

def test_encryption_throughput() -> None:
    """Encrypt 1 MB of data and verify throughput > 50 MB/s."""
    master_key = os.urandom(32)
    crypto = SessionCrypto(master_key)
    payload = os.urandom(1024)  # 1 KB chunks
    num_chunks = 1024            # 1024 * 1KB = 1 MB total

    start = time.perf_counter()
    for _ in range(num_chunks):
        crypto.encrypt(payload)
    elapsed = time.perf_counter() - start

    total_mb = (num_chunks * len(payload)) / (1024 * 1024)
    throughput = total_mb / elapsed if elapsed > 0 else float("inf")

    # Print for informational purposes
    print(f"\n  Encryption throughput: {throughput:.1f} MB/s ({total_mb:.1f} MB in {elapsed:.3f}s)")

    # The build plan says > 50 MB/s on modern hardware
    assert throughput > 50, (
        f"Encryption throughput {throughput:.1f} MB/s is below 50 MB/s threshold"
    )
