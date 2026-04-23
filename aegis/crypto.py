"""Phase 2 — Encryption Engine.

Provides hybrid post-quantum key exchange (Kyber-768 + X25519) and
per-packet AES-256-GCM AEAD encryption.

Handshake flow (one-time per session):
  1. Server generates Kyber-768 keypair + X25519 keypair
  2. Server → Client: kyber_pub, x25519_pub
  3. Client encapsulates against kyber_pub, generates own X25519 keypair
  4. Client → Server: kyber_ciphertext, client_x25519_pub
  5. Both sides derive: kyber_shared_secret XOR x25519_shared_secret → master_key
  6. master_key → HKDF-SHA256 → (aes_key 32B, nonce_base 12B)

Classes:
  KyberKeyPair    — Kyber-768 keypair via liboqs-python
  X25519KeyPair   — X25519 keypair via cryptography
  SessionCrypto   — AES-256-GCM encrypt/decrypt with HKDF-derived keys

Functions:
  kyber_encapsulate()        — client-side Kyber encapsulation
  derive_master_key()        — XOR two shared secrets into a master key
  derive_session_keys()      — HKDF expansion of master_key into AES key + nonce base
  perform_handshake_server() — server-side full hybrid handshake
  perform_handshake_client() — client-side full hybrid handshake
"""

from __future__ import annotations

import hmac
import os
import threading
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# liboqs is optional — it requires a native C library that may not be
# available on all Windows systems.  We try to import it and set a flag.
# Note: the oqs package raises SystemExit(1) if it can't auto-install
# the native library, so we must catch BaseException.
try:
    import oqs  # type: ignore[import-untyped]

    _OQS_AVAILABLE = True
except BaseException:
    oqs = None  # type: ignore[assignment]
    _OQS_AVAILABLE = False

if TYPE_CHECKING:
    pass

__all__ = [
    "KyberKeyPair",
    "X25519KeyPair",
    "SessionCrypto",
    "kyber_encapsulate",
    "derive_master_key",
    "derive_session_keys",
    "perform_handshake_server",
    "perform_handshake_client",
    "OQS_AVAILABLE",
]

# Re-export for test introspection
OQS_AVAILABLE = _OQS_AVAILABLE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HKDF_INFO = b"aegis-tunnel-x-v1"
_AES_KEY_LEN = 32   # 256-bit AES key
_NONCE_LEN = 12     # 96-bit GCM nonce


# ===================================================================
# Kyber-768 Key Encapsulation
# ===================================================================

class KyberKeyPair:
    """Kyber-768 key pair generated via liboqs-python.

    The server creates one of these, sends ``public_key`` to the client,
    then calls ``decapsulate(ciphertext)`` on the client's reply to get
    the shared secret.

    Raises ``RuntimeError`` if liboqs native library is not installed.
    """

    def __init__(self) -> None:
        if not _OQS_AVAILABLE:
            raise RuntimeError(
                "liboqs native library is not available. "
                "Install liboqs (https://github.com/open-quantum-safe/liboqs) "
                "and ensure oqs.dll / liboqs.so is on the system PATH."
            )
        self._kem = oqs.KeyEncapsulation("Kyber768")
        self._public_key: bytes = self._kem.generate_keypair()

    @property
    def public_key(self) -> bytes:
        """Raw Kyber-768 public key bytes."""
        return self._public_key

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate a Kyber ciphertext → shared secret.

        Args:
            ciphertext: The ciphertext produced by ``kyber_encapsulate()``.

        Returns:
            The shared secret bytes (32 bytes for Kyber768).
        """
        return self._kem.decap_secret(ciphertext)


def kyber_encapsulate(server_public_key: bytes) -> tuple[bytes, bytes]:
    """Client-side Kyber encapsulation against the server's public key.

    Args:
        server_public_key: The server's Kyber-768 public key.

    Returns:
        ``(ciphertext, shared_secret)`` — send ciphertext to server;
        both sides now share the secret.

    Raises:
        RuntimeError: If liboqs native library is not available.
    """
    if not _OQS_AVAILABLE:
        raise RuntimeError(
            "liboqs native library is not available. "
            "Install liboqs and ensure oqs.dll / liboqs.so is on the system PATH."
        )
    kem = oqs.KeyEncapsulation("Kyber768")
    ciphertext, shared_secret = kem.encap_secret(server_public_key)
    return ciphertext, shared_secret


# ===================================================================
# X25519 Key Exchange
# ===================================================================

class X25519KeyPair:
    """X25519 Diffie-Hellman key pair.

    Used alongside Kyber to form a hybrid key exchange.
    """

    def __init__(self) -> None:
        self._private_key = X25519PrivateKey.generate()

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte X25519 public key."""
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def exchange(self, peer_public_key_bytes: bytes) -> bytes:
        """Perform X25519 DH exchange with a peer's public key.

        Args:
            peer_public_key_bytes: The peer's 32-byte X25519 public key.

        Returns:
            32-byte shared secret.
        """
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return self._private_key.exchange(peer_pub)


# ===================================================================
# Key Derivation
# ===================================================================

def derive_master_key(
    kyber_secret: bytes,
    x25519_secret: bytes,
) -> bytes:
    """XOR two shared secrets into a single master key.

    Both inputs must be the same length (32 bytes for Kyber768 + X25519).

    Args:
        kyber_secret:  Shared secret from Kyber KEM.
        x25519_secret: Shared secret from X25519 DH.

    Returns:
        32-byte master key.
    """
    if len(kyber_secret) != len(x25519_secret):
        raise ValueError(
            f"Secret lengths must match: Kyber={len(kyber_secret)}, "
            f"X25519={len(x25519_secret)}"
        )
    return bytes(a ^ b for a, b in zip(kyber_secret, x25519_secret))


def derive_session_keys(
    master_key: bytes,
    salt: bytes | None = None,
    info: bytes = _HKDF_INFO,
) -> tuple[bytes, bytes]:
    """Derive AES-256 key and nonce base from master_key via HKDF-SHA256.

    Expands ``master_key`` into 44 bytes: first 32 for AES-256 key,
    last 12 for the nonce base.

    Args:
        master_key: 32-byte master key from the hybrid handshake.
        salt:       Optional salt for HKDF (can be None).
        info:       Context info for HKDF (default: ``b"aegis-tunnel-x-v1"``).

    Returns:
        ``(aes_key, nonce_base)`` — 32 bytes and 12 bytes respectively.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_LEN + _NONCE_LEN,   # 44 bytes total
        salt=salt,
        info=info,
    )
    derived = hkdf.derive(master_key)
    aes_key = derived[:_AES_KEY_LEN]
    nonce_base = derived[_AES_KEY_LEN:]
    return aes_key, nonce_base


# ===================================================================
# Session Crypto — AES-256-GCM AEAD
# ===================================================================

class SessionCrypto:
    """Per-session AES-256-GCM encryption with HKDF-derived keys.

    Each call to ``encrypt()`` uses a unique nonce derived from
    ``nonce_base XOR counter``.  The counter auto-increments and is
    protected by a lock for thread safety.

    Wire format of ``encrypt()`` output::

        nonce (12 bytes) || ciphertext || tag (16 bytes)

    Args:
        master_key: 32-byte master key from the hybrid handshake.
        salt:       Optional HKDF salt.
        info:       HKDF context info.
    """

    def __init__(
        self,
        master_key: bytes,
        salt: bytes | None = None,
        info: bytes = _HKDF_INFO,
    ) -> None:
        if len(master_key) < 16:
            raise ValueError("master_key must be at least 16 bytes")

        aes_key, self._nonce_base = derive_session_keys(master_key, salt, info)
        self._aesgcm = AESGCM(aes_key)
        self._counter: int = 0
        self._lock = threading.Lock()

    # -- public properties ------------------------------------------------

    @property
    def counter(self) -> int:
        """Current nonce counter value (read-only)."""
        return self._counter

    # -- encrypt / decrypt ------------------------------------------------

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: Data to encrypt.
            aad:       Additional Authenticated Data (e.g. session_id).

        Returns:
            ``nonce (12B) || ciphertext || tag (16B)``
        """
        nonce = self._next_nonce()
        # AESGCM.encrypt returns ciphertext + tag concatenated
        ct_and_tag = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ct_and_tag

    def decrypt(self, ciphertext_blob: bytes, aad: bytes = b"") -> bytes:
        """Decrypt a blob produced by ``encrypt()``.

        Args:
            ciphertext_blob: ``nonce (12B) || ciphertext || tag (16B)``
            aad:             Must match the AAD used during encryption.

        Returns:
            The original plaintext.

        Raises:
            cryptography.exceptions.InvalidTag: On tamper or AAD mismatch.
            ValueError: If the blob is too short.
        """
        if len(ciphertext_blob) < _NONCE_LEN + 16:
            raise ValueError(
                f"ciphertext_blob too short: {len(ciphertext_blob)} bytes "
                f"(minimum {_NONCE_LEN + 16})"
            )

        nonce = ciphertext_blob[:_NONCE_LEN]
        ct_and_tag = ciphertext_blob[_NONCE_LEN:]
        return self._aesgcm.decrypt(nonce, ct_and_tag, aad)

    # -- internal ---------------------------------------------------------

    def _next_nonce(self) -> bytes:
        """Derive the next unique nonce by XOR-ing nonce_base with counter."""
        with self._lock:
            counter_bytes = self._counter.to_bytes(_NONCE_LEN, "big")
            self._counter += 1

        return bytes(
            a ^ b for a, b in zip(self._nonce_base, counter_bytes)
        )


# ===================================================================
# Full Hybrid Handshake Helpers
# ===================================================================

def perform_handshake_server(
    kyber_kp: KyberKeyPair,
    x25519_kp: X25519KeyPair,
    client_kyber_ciphertext: bytes,
    client_x25519_pub: bytes,
    salt: bytes | None = None,
) -> SessionCrypto:
    """Server-side: complete the hybrid handshake and return a SessionCrypto.

    Args:
        kyber_kp:                Server's Kyber keypair.
        x25519_kp:               Server's X25519 keypair.
        client_kyber_ciphertext: Kyber ciphertext from the client.
        client_x25519_pub:       Client's X25519 public key (32 bytes).
        salt:                    Optional HKDF salt.

    Returns:
        A ready-to-use ``SessionCrypto`` instance.
    """
    kyber_secret = kyber_kp.decapsulate(client_kyber_ciphertext)
    x25519_secret = x25519_kp.exchange(client_x25519_pub)
    master_key = derive_master_key(kyber_secret, x25519_secret)
    return SessionCrypto(master_key, salt=salt)


def perform_handshake_client(
    server_kyber_pub: bytes,
    server_x25519_pub: bytes,
    salt: bytes | None = None,
) -> tuple[bytes, bytes, SessionCrypto]:
    """Client-side: complete the hybrid handshake and return a SessionCrypto.

    Args:
        server_kyber_pub:  Server's Kyber-768 public key.
        server_x25519_pub: Server's X25519 public key (32 bytes).
        salt:              Optional HKDF salt.

    Returns:
        ``(kyber_ciphertext, client_x25519_pub, session_crypto)`` —
        send the first two to the server.
    """
    # Kyber encapsulation
    kyber_ct, kyber_secret = kyber_encapsulate(server_kyber_pub)

    # X25519 exchange
    client_x25519 = X25519KeyPair()
    x25519_secret = client_x25519.exchange(server_x25519_pub)

    # Derive master key and session crypto
    master_key = derive_master_key(kyber_secret, x25519_secret)
    session = SessionCrypto(master_key, salt=salt)

    return kyber_ct, client_x25519.public_key_bytes, session
