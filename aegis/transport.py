"""Phase 3 — UDP Transport Layer.

Provides framed, encrypted UDP communication with:
  - Custom packet framing (0xAE91 magic, version, flags, type, session ID,
    sequence number, payload length, encrypted payload)
  - 3-way handshake using X25519 key exchange
  - Per-packet AES-256-GCM encryption via SessionCrypto
  - Sequence-number replay protection (sliding window of 64)
  - Keepalive mechanism (25s interval, disconnect after 3 misses)
  - asyncio DatagramProtocol for native Windows compatibility

Classes:
  PacketFrame       — encode/decode the wire format
  UDPSession        — per-peer session state (crypto, seq, replay window)
  AegisTunnelServer — asyncio UDP server with handshake + packet dispatch
  AegisTunnelClient — asyncio UDP client with handshake + send/receive
"""

from __future__ import annotations

import asyncio
import enum
import logging
import os
import struct
import time
from collections import deque
from typing import Any

from aegis.crypto import (
    SessionCrypto,
    X25519KeyPair,
    derive_master_key,
)

__all__ = [
    "PacketType",
    "PacketFlags",
    "PacketFrame",
    "UDPSession",
    "AegisTunnelServer",
    "AegisTunnelClient",
]

logger = logging.getLogger("aegis.transport")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC = 0xAE91
VERSION = 0x01
HEADER_SIZE = 17  # 2(magic) + 1(ver) + 1(flags) + 1(type) + 8(session) + 4(seq)
HEADER_FMT = "!HBBB8sI"  # magic, version, flags, type, session_id, seq_num

KEEPALIVE_INTERVAL_S = 25.0
KEEPALIVE_MISS_LIMIT = 3
REPLAY_WINDOW_SIZE = 64


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PacketType(enum.IntEnum):
    """Aegis tunnel packet types."""
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    CLIENT_ACK = 0x03
    DATA = 0x10
    KEEPALIVE = 0x20
    FIN = 0x30


class PacketFlags(enum.IntFlag):
    """Aegis tunnel packet flags."""
    HANDSHAKE = 0x01
    DATA = 0x02
    KEEPALIVE = 0x04
    FIN = 0x08


# ---------------------------------------------------------------------------
# PacketFrame — wire format encode / decode
# ---------------------------------------------------------------------------

class PacketFrame:
    """Represents an Aegis tunnel packet on the wire.

    Wire format::

        Magic (2B) | Version (1B) | Flags (1B) | Type (1B)
        Session ID (8B) | Sequence Number (4B) | Payload (variable)

    The header is always 17 bytes.  Payload is the raw encrypted data
    (or handshake data for HELLO/ACK packets).
    """

    __slots__ = ("magic", "version", "flags", "ptype", "session_id",
                 "seq_num", "payload")

    def __init__(
        self,
        ptype: PacketType,
        session_id: bytes = b"\x00" * 8,
        seq_num: int = 0,
        payload: bytes = b"",
        flags: PacketFlags | int = PacketFlags(0),
    ) -> None:
        self.magic = MAGIC
        self.version = VERSION
        self.flags = PacketFlags(flags)
        self.ptype = ptype
        self.session_id = session_id
        self.seq_num = seq_num
        self.payload = payload

    def encode(self) -> bytes:
        """Serialize the frame to bytes for transmission."""
        header = struct.pack(
            HEADER_FMT,
            self.magic,
            self.version,
            int(self.flags),
            int(self.ptype),
            self.session_id,
            self.seq_num,
        )
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> PacketFrame:
        """Deserialize bytes into a PacketFrame.

        Raises:
            ValueError: If the data is too short or has invalid magic/version.
        """
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"Packet too short: {len(data)} bytes (minimum {HEADER_SIZE})"
            )

        magic, version, flags, ptype, session_id, seq_num = struct.unpack(
            HEADER_FMT, data[:HEADER_SIZE]
        )

        if magic != MAGIC:
            raise ValueError(f"Invalid magic: 0x{magic:04X} (expected 0x{MAGIC:04X})")
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        return cls(
            ptype=PacketType(ptype),
            session_id=session_id,
            seq_num=seq_num,
            payload=data[HEADER_SIZE:],
            flags=PacketFlags(flags),
        )

    def __repr__(self) -> str:
        return (
            f"PacketFrame(type={self.ptype.name}, flags={self.flags!r}, "
            f"session={self.session_id.hex()[:8]}..., "
            f"seq={self.seq_num}, payload_len={len(self.payload)})"
        )


# ---------------------------------------------------------------------------
# UDPSession — per-peer session state
# ---------------------------------------------------------------------------

class UDPSession:
    """Per-peer session: crypto context, sequence counter, replay window.

    Attributes:
        session_id:   8 random bytes identifying this session.
        remote_addr:  (host, port) tuple of the peer.
        crypto:       SessionCrypto for encrypt/decrypt.
        seq_counter:  Monotonically increasing send sequence number.
        recv_window:  Sliding window of last N received seq numbers.
        last_seen:    Monotonic timestamp of last received packet.
    """

    def __init__(
        self,
        session_id: bytes,
        remote_addr: tuple[str, int],
        crypto: SessionCrypto,
    ) -> None:
        self.session_id = session_id
        self.remote_addr = remote_addr
        self.crypto = crypto
        self.seq_counter: int = 0
        self.recv_window: deque[int] = deque(maxlen=REPLAY_WINDOW_SIZE)
        self.last_seen: float = time.monotonic()
        self.missed_keepalives: int = 0

    def next_seq(self) -> int:
        """Return and increment the send sequence counter."""
        seq = self.seq_counter
        self.seq_counter += 1
        return seq

    def is_replay(self, seq_num: int) -> bool:
        """Check if a sequence number has already been seen."""
        if seq_num in self.recv_window:
            return True
        self.recv_window.append(seq_num)
        self.last_seen = time.monotonic()
        self.missed_keepalives = 0
        return False

    def encrypt_payload(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using the session's crypto context."""
        return self.crypto.encrypt(plaintext, aad=self.session_id)

    def decrypt_payload(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using the session's crypto context."""
        return self.crypto.decrypt(ciphertext, aad=self.session_id)


# ---------------------------------------------------------------------------
# Server Protocol
# ---------------------------------------------------------------------------

class _ServerProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol for the Aegis tunnel server."""

    def __init__(self, server: AegisTunnelServer) -> None:
        self.server = server
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.ensure_future(self.server._handle_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.error("Server UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug("Server connection lost: %s", exc)


class AegisTunnelServer:
    """Asyncio UDP server with X25519 handshake and encrypted packet dispatch.

    Usage::

        server = AegisTunnelServer("127.0.0.1", 5555)
        await server.start()
        # ... read from server.recv_queue ...
        await server.stop()
    """

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

        # Handshake keypair (X25519 — generated fresh each server start)
        self._x25519: X25519KeyPair | None = None

        # Active sessions keyed by remote_addr
        self._sessions: dict[tuple[str, int], UDPSession] = {}

        # Pending handshakes keyed by remote_addr
        self._pending_handshakes: dict[tuple[str, int], dict[str, Any]] = {}

        # Queue for decrypted plaintext packets from clients
        self.recv_queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue()

        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _ServerProtocol | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        """Start listening for UDP datagrams."""
        if self._running:
            return

        self._x25519 = X25519KeyPair()

        loop = asyncio.get_running_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: _ServerProtocol(self),
            local_addr=(self.host, self.port),
        )
        self._running = True
        self._keepalive_task = asyncio.create_task(self._keepalive_monitor())
        logger.info("Server listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Stop the server and close all sessions."""
        self._running = False
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            self._keepalive_task = None

        # Send FIN to all active sessions
        for session in list(self._sessions.values()):
            self._send_frame(
                PacketFrame(
                    ptype=PacketType.FIN,
                    session_id=session.session_id,
                    seq_num=session.next_seq(),
                    flags=PacketFlags.FIN,
                ),
                session.remote_addr,
            )

        self._sessions.clear()
        self._pending_handshakes.clear()

        if self._transport:
            self._transport.close()
            self._transport = None
        self._protocol = None
        logger.info("Server stopped")

    def get_session(self, addr: tuple[str, int]) -> UDPSession | None:
        """Get the active session for a given remote address."""
        return self._sessions.get(addr)

    async def send_to(self, data: bytes, addr: tuple[str, int]) -> None:
        """Encrypt and send a data packet to a specific client."""
        session = self._sessions.get(addr)
        if not session:
            raise RuntimeError(f"No active session for {addr}")

        encrypted = session.encrypt_payload(data)
        frame = PacketFrame(
            ptype=PacketType.DATA,
            session_id=session.session_id,
            seq_num=session.next_seq(),
            payload=encrypted,
            flags=PacketFlags.DATA,
        )
        self._send_frame(frame, addr)

    async def _handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Route an incoming datagram based on its type."""
        try:
            frame = PacketFrame.decode(data)
        except ValueError as e:
            logger.warning("Invalid packet from %s: %s", addr, e)
            return

        if frame.ptype == PacketType.CLIENT_HELLO:
            await self._handle_client_hello(frame, addr)
        elif frame.ptype == PacketType.CLIENT_ACK:
            await self._handle_client_ack(frame, addr)
        elif frame.ptype == PacketType.DATA:
            await self._handle_data(frame, addr)
        elif frame.ptype == PacketType.KEEPALIVE:
            self._handle_keepalive(frame, addr)
        elif frame.ptype == PacketType.FIN:
            self._handle_fin(addr)
        else:
            logger.warning("Unknown packet type %s from %s", frame.ptype, addr)

    async def _handle_client_hello(
        self, frame: PacketFrame, addr: tuple[str, int]
    ) -> None:
        """Process CLIENT_HELLO: extract client X25519 pub, send SERVER_HELLO."""
        if len(frame.payload) < 32:
            logger.warning("CLIENT_HELLO payload too short from %s", addr)
            return

        client_x25519_pub = frame.payload[:32]
        assert self._x25519 is not None

        # Generate a session ID
        session_id = os.urandom(8)

        # Store pending handshake state
        self._pending_handshakes[addr] = {
            "client_x25519_pub": client_x25519_pub,
            "session_id": session_id,
        }

        # Send SERVER_HELLO: our X25519 pub (32B) + session_id (8B)
        reply_payload = self._x25519.public_key_bytes + session_id
        reply = PacketFrame(
            ptype=PacketType.SERVER_HELLO,
            session_id=session_id,
            seq_num=0,
            payload=reply_payload,
            flags=PacketFlags.HANDSHAKE,
        )
        self._send_frame(reply, addr)
        logger.debug("Sent SERVER_HELLO to %s (session %s)", addr, session_id.hex()[:8])

    async def _handle_client_ack(
        self, frame: PacketFrame, addr: tuple[str, int]
    ) -> None:
        """Process CLIENT_ACK: complete the handshake, create session."""
        pending = self._pending_handshakes.pop(addr, None)
        if not pending:
            logger.warning("Unexpected CLIENT_ACK from %s (no pending handshake)", addr)
            return

        assert self._x25519 is not None
        client_x25519_pub = pending["client_x25519_pub"]
        session_id = pending["session_id"]

        # Derive shared secret via X25519
        x25519_secret = self._x25519.exchange(client_x25519_pub)

        # Use the X25519 secret as master key (in full system, this would be
        # XOR'd with Kyber secret, but we use X25519-only for Windows compat)
        master_key = x25519_secret

        crypto = SessionCrypto(master_key)
        session = UDPSession(
            session_id=session_id,
            remote_addr=addr,
            crypto=crypto,
        )
        self._sessions[addr] = session
        logger.info("Session established with %s (session %s)", addr, session_id.hex()[:8])

    async def _handle_data(
        self, frame: PacketFrame, addr: tuple[str, int]
    ) -> None:
        """Process DATA: decrypt and enqueue for the tunnel layer."""
        session = self._sessions.get(addr)
        if not session:
            logger.warning("DATA from %s but no session", addr)
            return

        # Replay protection
        if session.is_replay(frame.seq_num):
            logger.debug("Replay detected: seq=%d from %s", frame.seq_num, addr)
            return

        try:
            plaintext = session.decrypt_payload(frame.payload)
        except Exception as e:
            logger.warning("Decrypt failed from %s: %s (connection stays alive)", addr, e)
            return

        await self.recv_queue.put((plaintext, addr))

    def _handle_keepalive(
        self, frame: PacketFrame, addr: tuple[str, int]
    ) -> None:
        """Process KEEPALIVE: update last_seen timestamp."""
        session = self._sessions.get(addr)
        if session:
            session.last_seen = time.monotonic()
            session.missed_keepalives = 0
            logger.debug("Keepalive from %s", addr)

    def _handle_fin(self, addr: tuple[str, int]) -> None:
        """Process FIN: remove the session."""
        session = self._sessions.pop(addr, None)
        if session:
            logger.info("Session closed by peer %s", addr)

    async def _keepalive_monitor(self) -> None:
        """Periodically check for missed keepalives and send our own."""
        while self._running:
            await asyncio.sleep(KEEPALIVE_INTERVAL_S)
            now = time.monotonic()
            dead_addrs: list[tuple[str, int]] = []

            for addr, session in list(self._sessions.items()):
                elapsed = now - session.last_seen
                if elapsed > KEEPALIVE_INTERVAL_S:
                    session.missed_keepalives += 1
                    if session.missed_keepalives >= KEEPALIVE_MISS_LIMIT:
                        logger.warning("Client %s timed out (%d missed)", addr, session.missed_keepalives)
                        dead_addrs.append(addr)
                    else:
                        # Send a keepalive to prompt a response
                        frame = PacketFrame(
                            ptype=PacketType.KEEPALIVE,
                            session_id=session.session_id,
                            seq_num=session.next_seq(),
                            flags=PacketFlags.KEEPALIVE,
                        )
                        self._send_frame(frame, addr)

            for addr in dead_addrs:
                self._sessions.pop(addr, None)

    def _send_frame(self, frame: PacketFrame, addr: tuple[str, int]) -> None:
        """Send an encoded frame to the given address."""
        if self._transport:
            self._transport.sendto(frame.encode(), addr)


# ---------------------------------------------------------------------------
# Client Protocol
# ---------------------------------------------------------------------------

class _ClientProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol for the Aegis tunnel client."""

    def __init__(self, client: AegisTunnelClient) -> None:
        self.client = client
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.ensure_future(self.client._handle_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.error("Client UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug("Client connection lost: %s", exc)


class AegisTunnelClient:
    """Asyncio UDP client with X25519 handshake and encrypted data exchange.

    Usage::

        client = AegisTunnelClient("127.0.0.1", 5555)
        await client.connect()
        await client.send_packet(b"hello")
        data = await client.receive_packet()
        await client.disconnect()
    """

    def __init__(self, server_host: str, server_port: int) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.server_addr = (server_host, server_port)

        self._x25519: X25519KeyPair | None = None
        self._session: UDPSession | None = None

        self.recv_queue: asyncio.Queue[bytes] = asyncio.Queue()

        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _ClientProtocol | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._handshake_done: asyncio.Event = asyncio.Event()
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def session(self) -> UDPSession | None:
        return self._session

    async def connect(self, timeout: float = 5.0) -> None:
        """Perform the 3-way handshake with the server.

        Args:
            timeout: Maximum seconds to wait for handshake completion.

        Raises:
            asyncio.TimeoutError: If the handshake doesn't complete in time.
        """
        self._x25519 = X25519KeyPair()
        self._handshake_done.clear()

        loop = asyncio.get_running_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: _ClientProtocol(self),
            remote_addr=self.server_addr,
        )

        # Step 1: Send CLIENT_HELLO with our X25519 public key
        hello = PacketFrame(
            ptype=PacketType.CLIENT_HELLO,
            session_id=b"\x00" * 8,
            seq_num=0,
            payload=self._x25519.public_key_bytes,
            flags=PacketFlags.HANDSHAKE,
        )
        self._send_frame(hello)
        logger.debug("Sent CLIENT_HELLO to %s:%d", self.server_host, self.server_port)

        # Wait for handshake to complete (SERVER_HELLO → CLIENT_ACK)
        await asyncio.wait_for(self._handshake_done.wait(), timeout=timeout)

        self._connected = True
        self._keepalive_task = asyncio.create_task(self._keepalive_sender())
        logger.info("Connected to %s:%d", self.server_host, self.server_port)

    async def disconnect(self) -> None:
        """Send FIN and close the connection."""
        self._connected = False
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            self._keepalive_task = None

        if self._session:
            fin = PacketFrame(
                ptype=PacketType.FIN,
                session_id=self._session.session_id,
                seq_num=self._session.next_seq(),
                flags=PacketFlags.FIN,
            )
            self._send_frame(fin)

        self._session = None
        if self._transport:
            self._transport.close()
            self._transport = None
        self._protocol = None
        logger.info("Disconnected")

    async def send_packet(self, data: bytes) -> None:
        """Encrypt and send a data packet to the server.

        Raises:
            RuntimeError: If not connected.
        """
        if not self._session:
            raise RuntimeError("Not connected — call connect() first")

        encrypted = self._session.encrypt_payload(data)
        frame = PacketFrame(
            ptype=PacketType.DATA,
            session_id=self._session.session_id,
            seq_num=self._session.next_seq(),
            payload=encrypted,
            flags=PacketFlags.DATA,
        )
        self._send_frame(frame)

    async def receive_packet(self, timeout: float = 5.0) -> bytes:
        """Wait for and return the next decrypted data packet.

        Raises:
            asyncio.TimeoutError: If no packet arrives within timeout.
        """
        return await asyncio.wait_for(self.recv_queue.get(), timeout=timeout)

    async def _handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        """Route incoming datagrams from the server."""
        try:
            frame = PacketFrame.decode(data)
        except ValueError as e:
            logger.warning("Invalid packet from server: %s", e)
            return

        if frame.ptype == PacketType.SERVER_HELLO:
            await self._handle_server_hello(frame)
        elif frame.ptype == PacketType.DATA:
            await self._handle_data(frame)
        elif frame.ptype == PacketType.KEEPALIVE:
            self._handle_keepalive(frame)
        elif frame.ptype == PacketType.FIN:
            self._handle_fin()
        else:
            logger.warning("Unexpected packet type from server: %s", frame.ptype)

    async def _handle_server_hello(self, frame: PacketFrame) -> None:
        """Process SERVER_HELLO: extract server X25519 pub + session_id,
        derive shared secret, send CLIENT_ACK."""
        if len(frame.payload) < 40:  # 32 (X25519 pub) + 8 (session_id)
            logger.warning("SERVER_HELLO payload too short")
            return

        server_x25519_pub = frame.payload[:32]
        session_id = frame.payload[32:40]

        assert self._x25519 is not None
        x25519_secret = self._x25519.exchange(server_x25519_pub)

        # Use X25519 secret as master key
        master_key = x25519_secret
        crypto = SessionCrypto(master_key)

        self._session = UDPSession(
            session_id=session_id,
            remote_addr=self.server_addr,
            crypto=crypto,
        )

        # Step 3: Send CLIENT_ACK
        ack = PacketFrame(
            ptype=PacketType.CLIENT_ACK,
            session_id=session_id,
            seq_num=0,
            payload=b"ACK",
            flags=PacketFlags.HANDSHAKE,
        )
        self._send_frame(ack)
        self._handshake_done.set()
        logger.debug("Sent CLIENT_ACK (session %s)", session_id.hex()[:8])

    async def _handle_data(self, frame: PacketFrame) -> None:
        """Process DATA: decrypt and enqueue."""
        if not self._session:
            return

        if self._session.is_replay(frame.seq_num):
            logger.debug("Replay detected: seq=%d", frame.seq_num)
            return

        try:
            plaintext = self._session.decrypt_payload(frame.payload)
        except Exception as e:
            logger.warning("Decrypt failed from server: %s (connection stays alive)", e)
            return

        await self.recv_queue.put(plaintext)

    def _handle_keepalive(self, frame: PacketFrame) -> None:
        """Process KEEPALIVE from server."""
        if self._session:
            self._session.last_seen = time.monotonic()
            self._session.missed_keepalives = 0

    def _handle_fin(self) -> None:
        """Process FIN from server."""
        logger.info("Server sent FIN — disconnecting")
        self._connected = False
        self._session = None

    async def _keepalive_sender(self) -> None:
        """Periodically send KEEPALIVE packets to the server."""
        while self._connected and self._session:
            await asyncio.sleep(KEEPALIVE_INTERVAL_S)
            if self._session and self._connected:
                frame = PacketFrame(
                    ptype=PacketType.KEEPALIVE,
                    session_id=self._session.session_id,
                    seq_num=self._session.next_seq(),
                    flags=PacketFlags.KEEPALIVE,
                )
                self._send_frame(frame)
                logger.debug("Sent keepalive")

    def _send_frame(self, frame: PacketFrame) -> None:
        """Send an encoded frame to the server."""
        if self._transport:
            self._transport.sendto(frame.encode())
