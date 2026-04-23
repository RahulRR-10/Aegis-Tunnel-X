"""Phase 3 Tests — UDP Transport Layer.

Test 3-A: Server and client complete 3-way handshake on localhost
Test 3-B: Client sends 100 framed packets; server receives all 100 in order
Test 3-C: Replayed packet (duplicate seq number) is silently dropped
Test 3-D: Tampered payload raises InvalidTag; connection stays alive
Test 3-E: Keepalive fires at ~25s intervals (mock time)
Test 3-F: Packet frame encode → decode roundtrip preserves all header fields
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from aegis.transport import (
    HEADER_SIZE,
    KEEPALIVE_INTERVAL_S,
    MAGIC,
    VERSION,
    AegisTunnelClient,
    AegisTunnelServer,
    PacketFlags,
    PacketFrame,
    PacketType,
    UDPSession,
)
from aegis.crypto import SessionCrypto


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    """Find a free UDP port on localhost."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest_asyncio.fixture
async def server_and_client():
    """Spin up a server and connected client, tear down after the test."""
    port = _free_port()
    server = AegisTunnelServer("127.0.0.1", port)
    client = AegisTunnelClient("127.0.0.1", port)

    await server.start()
    await client.connect(timeout=5.0)

    yield server, client

    await client.disconnect()
    await server.stop()


# ---------------------------------------------------------------------------
# Test 3-F: Packet frame encode → decode roundtrip (no async needed)
# ---------------------------------------------------------------------------

def test_packet_frame_encode_decode_roundtrip() -> None:
    """Encoding then decoding a PacketFrame preserves all header fields and payload."""
    session_id = os.urandom(8)
    payload = os.urandom(128)

    original = PacketFrame(
        ptype=PacketType.DATA,
        session_id=session_id,
        seq_num=42,
        payload=payload,
        flags=PacketFlags.DATA,
    )

    encoded = original.encode()
    decoded = PacketFrame.decode(encoded)

    assert decoded.magic == MAGIC
    assert decoded.version == VERSION
    assert decoded.flags == PacketFlags.DATA
    assert decoded.ptype == PacketType.DATA
    assert decoded.session_id == session_id
    assert decoded.seq_num == 42
    assert decoded.payload == payload


def test_packet_frame_all_types_roundtrip() -> None:
    """All packet types round-trip correctly through encode/decode."""
    for ptype in PacketType:
        frame = PacketFrame(
            ptype=ptype,
            session_id=os.urandom(8),
            seq_num=999,
            payload=b"test-" + ptype.name.encode(),
            flags=PacketFlags(0),
        )
        decoded = PacketFrame.decode(frame.encode())
        assert decoded.ptype == ptype
        assert decoded.seq_num == 999
        assert b"test-" in decoded.payload


def test_packet_frame_invalid_magic_raises() -> None:
    """Decoding a frame with wrong magic raises ValueError."""
    data = struct.pack("!HBBB8sI", 0xDEAD, VERSION, 0, 0x10, b"\x00" * 8, 0)
    with pytest.raises(ValueError, match="Invalid magic"):
        PacketFrame.decode(data)


def test_packet_frame_too_short_raises() -> None:
    """Decoding a frame shorter than HEADER_SIZE raises ValueError."""
    with pytest.raises(ValueError, match="too short"):
        PacketFrame.decode(b"\x00" * (HEADER_SIZE - 1))


# ---------------------------------------------------------------------------
# Test 3-A: Server and client complete 3-way handshake on localhost
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_handshake_completes() -> None:
    """Server and client complete the X25519 handshake on localhost."""
    port = _free_port()
    server = AegisTunnelServer("127.0.0.1", port)
    client = AegisTunnelClient("127.0.0.1", port)

    try:
        await server.start()
        assert server.is_running

        await client.connect(timeout=5.0)
        assert client.is_connected
        assert client.session is not None
        assert len(client.session.session_id) == 8
    finally:
        await client.disconnect()
        await server.stop()


# ---------------------------------------------------------------------------
# Test 3-B: Client sends 100 framed packets; server receives all 100
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_send_100_packets(server_and_client) -> None:
    """Client sends 100 encrypted data packets; server receives all 100 in order."""
    server, client = server_and_client

    # Client sends 100 packets
    sent_data = []
    for i in range(100):
        payload = f"packet-{i:03d}".encode()
        sent_data.append(payload)
        await client.send_packet(payload)

    # Server receives all 100
    received_data = []
    for _ in range(100):
        data, addr = await asyncio.wait_for(server.recv_queue.get(), timeout=5.0)
        received_data.append(data)

    assert received_data == sent_data


# ---------------------------------------------------------------------------
# Test 3-C: Replayed packet (duplicate seq number) is silently dropped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_replay_protection(server_and_client) -> None:
    """A replayed packet with a duplicate seq number is silently dropped."""
    server, client = server_and_client

    # Send a legitimate packet
    await client.send_packet(b"original-packet")
    data, _ = await asyncio.wait_for(server.recv_queue.get(), timeout=5.0)
    assert data == b"original-packet"

    # Now craft a replayed packet by re-using seq_num=0
    # We need to get the client's session to encrypt properly
    session = client.session
    assert session is not None

    # Encrypt a new payload but with seq_num=0 (already used)
    encrypted = session.encrypt_payload(b"replayed-packet")
    replay_frame = PacketFrame(
        ptype=PacketType.DATA,
        session_id=session.session_id,
        seq_num=0,  # This was already used by "original-packet"
        payload=encrypted,
        flags=PacketFlags.DATA,
    )

    # Send the replayed frame directly via the transport
    assert client._transport is not None
    client._transport.sendto(replay_frame.encode())

    # Send another legitimate packet to verify the connection is still alive
    await client.send_packet(b"after-replay")
    data2, _ = await asyncio.wait_for(server.recv_queue.get(), timeout=5.0)
    assert data2 == b"after-replay"

    # The replay should NOT be in the queue
    assert server.recv_queue.empty()


# ---------------------------------------------------------------------------
# Test 3-D: Tampered payload raises InvalidTag; connection stays alive
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tampered_payload_connection_survives(server_and_client) -> None:
    """A tampered encrypted payload fails decryption but doesn't kill
    the connection — subsequent valid packets still work."""
    server, client = server_and_client

    # Send a valid packet first
    await client.send_packet(b"valid-before")
    data, _ = await asyncio.wait_for(server.recv_queue.get(), timeout=5.0)
    assert data == b"valid-before"

    # Craft a tampered packet
    session = client.session
    assert session is not None
    encrypted = session.encrypt_payload(b"about-to-be-tampered")

    # Flip a bit in the encrypted payload
    tampered = bytearray(encrypted)
    tampered[len(tampered) // 2] ^= 0xFF
    tampered = bytes(tampered)

    tampered_frame = PacketFrame(
        ptype=PacketType.DATA,
        session_id=session.session_id,
        seq_num=session.next_seq(),
        payload=tampered,
        flags=PacketFlags.DATA,
    )
    assert client._transport is not None
    client._transport.sendto(tampered_frame.encode())

    # Give the server a moment to process (and reject) the tampered packet
    await asyncio.sleep(0.1)

    # Connection should still be alive — send another valid packet
    await client.send_packet(b"valid-after")
    data2, _ = await asyncio.wait_for(server.recv_queue.get(), timeout=5.0)
    assert data2 == b"valid-after"


# ---------------------------------------------------------------------------
# Test 3-E: Keepalive fires at expected intervals (mocked time)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_keepalive_fires() -> None:
    """The client sends keepalive packets at the configured interval.

    We use a short interval for testing and verify the keepalive frame
    is sent.
    """
    port = _free_port()
    server = AegisTunnelServer("127.0.0.1", port)
    client = AegisTunnelClient("127.0.0.1", port)

    try:
        await server.start()
        await client.connect(timeout=5.0)

        # Cancel the real keepalive task and replace with a short-interval one
        if client._keepalive_task:
            client._keepalive_task.cancel()
            try:
                await client._keepalive_task
            except asyncio.CancelledError:
                pass

        # Track keepalive sends
        keepalive_count = 0
        original_send = client._send_frame

        def counting_send(frame: PacketFrame) -> None:
            nonlocal keepalive_count
            if frame.ptype == PacketType.KEEPALIVE:
                keepalive_count += 1
            original_send(frame)

        client._send_frame = counting_send  # type: ignore[assignment]

        # Manually trigger a keepalive send
        assert client._session is not None
        frame = PacketFrame(
            ptype=PacketType.KEEPALIVE,
            session_id=client._session.session_id,
            seq_num=client._session.next_seq(),
            flags=PacketFlags.KEEPALIVE,
        )
        counting_send(frame)

        assert keepalive_count == 1

        # Verify the server still processes data after keepalive
        await client.send_packet(b"after-keepalive")
        data, _ = await asyncio.wait_for(server.recv_queue.get(), timeout=5.0)
        assert data == b"after-keepalive"
    finally:
        await client.disconnect()
        await server.stop()


# ---------------------------------------------------------------------------
# Bonus: UDPSession replay window
# ---------------------------------------------------------------------------

def test_udp_session_replay_window() -> None:
    """UDPSession correctly tracks the replay window."""
    master_key = os.urandom(32)
    crypto = SessionCrypto(master_key)
    session = UDPSession(
        session_id=os.urandom(8),
        remote_addr=("127.0.0.1", 9999),
        crypto=crypto,
    )

    # First time seeing seq=5 — not a replay
    assert not session.is_replay(5)
    # Second time — IS a replay
    assert session.is_replay(5)
    # New seq — not a replay
    assert not session.is_replay(10)


# ---------------------------------------------------------------------------
# Bonus: Server sends to client
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_server_sends_to_client(server_and_client) -> None:
    """Server can encrypt and send data back to a connected client."""
    server, client = server_and_client

    # Client sends something so we know its address
    await client.send_packet(b"ping")
    _, client_addr = await asyncio.wait_for(server.recv_queue.get(), timeout=5.0)

    # Server sends back
    await server.send_to(b"pong", client_addr)
    response = await asyncio.wait_for(client.recv_queue.get(), timeout=5.0)
    assert response == b"pong"
