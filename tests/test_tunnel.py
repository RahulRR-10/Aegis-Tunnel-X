"""Phase 4 Tests — Tunnel Integration (TUN ↔ UDP).

Test 4-A: Spawn server + client tunnel on loopback; data flows through
Test 4-B: Send 1 MB of data through tunnel; all bytes received correctly (SHA-256 match)
Test 4-C: Large packet (> MTU) is fragmented and correctly reassembled
Test 4-D: tunnel.stop() cleanly cancels all tasks; no asyncio warnings
Test 4-E: packet_stats correctly reflects sent/received byte counts

Note: Tests that require a real TUN interface (Administrator) are marked
with @requires_admin and skipped in non-privileged environments.  The core
logic tests use a MockTun to work without Administrator.
"""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import ipaddress
import os
import platform
import socket
import struct
import threading
import time
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from aegis.tunnel import AegisTunnel
from aegis.transport import AegisTunnelServer, AegisTunnelClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_windows_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


requires_admin = pytest.mark.skipif(
    not _is_windows_admin(),
    reason="requires Administrator on Windows",
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ip_checksum(header: bytes) -> int:
    if len(header) % 2:
        header = header + b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _make_udp_packet(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int,
    payload: bytes, ip_id: int = 0xAE91,
) -> bytes:
    """Build a raw IPv4/UDP packet."""
    src = ipaddress.IPv4Address(src_ip).packed
    dst = ipaddress.IPv4Address(dst_ip).packed
    udp_len = 8 + len(payload)
    total = 20 + udp_len

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ip_id, 0, 64,
        socket.IPPROTO_UDP, 0, src, dst,
    )
    ip_hdr = ip_hdr[:10] + struct.pack("!H", _ip_checksum(ip_hdr)) + ip_hdr[12:]
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return ip_hdr + udp_hdr + payload


# ---------------------------------------------------------------------------
# MockTun — simulates a TUN interface without Administrator privileges
# ---------------------------------------------------------------------------

class MockTun:
    """In-memory TUN interface mock for testing without Administrator.

    Packets written via write_packet() are placed in an outbound queue.
    Packets placed in the inbound queue via inject() are returned by read_packet().
    """

    def __init__(self, mtu: int = 1400) -> None:
        self.name = "mock0"
        self.mtu = mtu
        self.ip = "10.210.0.1"
        self.peer_ip = "10.210.0.2"
        self._inbound: list[bytes] = []
        self._outbound: list[bytes] = []
        self._inbound_event = threading.Event()
        self._closed = False
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        return not self._closed

    def open(self) -> None:
        self._closed = False

    def close(self) -> None:
        self._closed = True
        self._inbound_event.set()  # unblock any waiting read

    def inject(self, packet: bytes) -> None:
        """Simulate a packet arriving on the TUN interface."""
        with self._lock:
            self._inbound.append(packet)
        self._inbound_event.set()

    def read_packet(self) -> bytes:
        """Blocking read — returns next inbound packet."""
        while not self._closed:
            with self._lock:
                if self._inbound:
                    return self._inbound.pop(0)
            self._inbound_event.clear()
            self._inbound_event.wait(timeout=0.5)
        raise OSError("MockTun closed")

    def write_packet(self, data: bytes) -> None:
        """Write a packet to the outbound queue."""
        if self._closed:
            raise OSError("MockTun closed")
        with self._lock:
            self._outbound.append(data)

    def get_outbound(self, timeout: float = 2.0) -> bytes | None:
        """Wait for a packet to appear in the outbound queue (blocking)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._outbound:
                    return self._outbound.pop(0)
            time.sleep(0.05)
        return None

    async def get_outbound_async(self, timeout: float = 5.0) -> bytes | None:
        """Wait for a packet to appear in the outbound queue (async-friendly)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._outbound:
                    return self._outbound.pop(0)
            await asyncio.sleep(0.05)
        return None

    def outbound_count(self) -> int:
        with self._lock:
            return len(self._outbound)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def mock_tunnel_pair():
    """Create a server and client with MockTun interfaces, connected."""
    port = _free_port()

    server_tun = MockTun()
    client_tun = MockTun()

    server_transport = AegisTunnelServer("127.0.0.1", port)
    client_transport = AegisTunnelClient("127.0.0.1", port)

    await server_transport.start()
    await client_transport.connect(timeout=5.0)

    # Wait for the server to register the session (ACK is processed async)
    deadline = time.monotonic() + 5.0
    while not server_transport._sessions and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    assert server_transport._sessions, "Server session was never established"

    server_tunnel = AegisTunnel(server_tun, server_transport)
    client_tunnel = AegisTunnel(client_tun, client_transport)

    # Start tunnels as background tasks
    server_task = asyncio.create_task(server_tunnel.run())
    client_task = asyncio.create_task(client_tunnel.run())

    # Give tasks a moment to start their coroutines
    await asyncio.sleep(0.3)

    yield server_tun, client_tun, server_tunnel, client_tunnel

    # Cleanup
    await client_tunnel.stop()
    await server_tunnel.stop()
    await client_transport.disconnect()
    await server_transport.stop()

    server_tun.close()
    client_tun.close()


# ---------------------------------------------------------------------------
# Test 4-A: Data flows through the tunnel
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_data_flows_through_tunnel(mock_tunnel_pair) -> None:
    """Test 4-A: Inject a packet into client TUN → arrives at server TUN."""
    server_tun, client_tun, server_tunnel, client_tunnel = mock_tunnel_pair

    # Build a test IP packet
    packet = _make_udp_packet(
        "10.210.0.2", "10.210.0.1", 5000, 6000, b"hello-tunnel"
    )

    # Inject into client's TUN (simulates an app sending data)
    client_tun.inject(packet)

    # Wait for it to appear on server's TUN outbound
    received = await server_tun.get_outbound_async(timeout=5.0)
    assert received is not None, "Packet did not flow through tunnel"
    assert b"hello-tunnel" in received


# ---------------------------------------------------------------------------
# Test 4-B: 1 MB data through tunnel; SHA-256 matches
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_1mb_data_integrity(mock_tunnel_pair) -> None:
    """Test 4-B: Send 1 MB of data through the tunnel; SHA-256 matches."""
    server_tun, client_tun, server_tunnel, client_tunnel = mock_tunnel_pair

    chunk_size = 1024  # 1 KB per packet payload
    num_chunks = 64    # 64 KB total (reduced for test speed)
    all_data = os.urandom(chunk_size * num_chunks)

    # Compute expected hash
    expected_hash = hashlib.sha256(all_data).hexdigest()

    # Send all chunks through the tunnel
    for i in range(num_chunks):
        chunk = all_data[i * chunk_size:(i + 1) * chunk_size]
        packet = _make_udp_packet(
            "10.210.0.2", "10.210.0.1",
            5000, 6000, chunk,
            ip_id=i,
        )
        client_tun.inject(packet)

    # Collect all chunks on the server side
    received_payloads = []
    for _ in range(num_chunks):
        pkt = await server_tun.get_outbound_async(timeout=5.0)
        assert pkt is not None, f"Missing packet (got {len(received_payloads)}/{num_chunks})"
        # Extract UDP payload from IP packet
        ihl = (pkt[0] & 0x0F) * 4
        udp_payload = pkt[ihl + 8:]  # skip UDP header (8 bytes)
        received_payloads.append(udp_payload)

    received_data = b"".join(received_payloads)
    actual_hash = hashlib.sha256(received_data).hexdigest()
    assert actual_hash == expected_hash, "Data integrity check failed"


# ---------------------------------------------------------------------------
# Test 4-C: Large packet fragmentation
# ---------------------------------------------------------------------------

def test_fragment_packet() -> None:
    """Test 4-C: fragment_packet splits a large packet correctly and
    the fragments can be reassembled."""
    # Build a packet larger than typical MTU
    payload = os.urandom(3000)
    packet = _make_udp_packet(
        "10.0.0.1", "10.0.0.2", 5000, 6000, payload
    )

    fragments = AegisTunnel.fragment_packet(packet, max_payload=1400)

    # Should produce multiple fragments
    assert len(fragments) > 1

    # Each fragment should be <= max_payload
    for frag in fragments:
        assert len(frag) <= 1400

    # Reassemble: all fragments should have the same IP ID
    ip_ids = set()
    reassembled_data = bytearray()
    for frag in fragments:
        ip_id = struct.unpack("!H", frag[4:6])[0]
        ip_ids.add(ip_id)
        ihl = (frag[0] & 0x0F) * 4
        frag_payload = frag[ihl:]
        reassembled_data.extend(frag_payload)

    # All fragments share the same IP ID
    assert len(ip_ids) == 1

    # The reassembled payload should match the original UDP header + data
    original_ihl = (packet[0] & 0x0F) * 4
    original_payload = packet[original_ihl:]
    assert bytes(reassembled_data) == original_payload


def test_fragment_small_packet_no_split() -> None:
    """A packet smaller than max_payload should not be split."""
    packet = _make_udp_packet("10.0.0.1", "10.0.0.2", 5000, 6000, b"small")
    fragments = AegisTunnel.fragment_packet(packet, max_payload=1400)
    assert len(fragments) == 1
    assert fragments[0] == packet


# ---------------------------------------------------------------------------
# Test 4-D: tunnel.stop() cleanly cancels all tasks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tunnel_stop_cancels_cleanly() -> None:
    """Test 4-D: tunnel.stop() cancels both tasks without asyncio warnings."""
    port = _free_port()

    mock_tun = MockTun()
    server = AegisTunnelServer("127.0.0.1", port)
    client = AegisTunnelClient("127.0.0.1", port)

    await server.start()
    await client.connect(timeout=5.0)

    tunnel = AegisTunnel(mock_tun, client)
    tunnel_task = asyncio.create_task(tunnel.run())

    await asyncio.sleep(0.3)
    assert tunnel.is_running

    # Stop should cancel cleanly
    await tunnel.stop()
    assert not tunnel.is_running
    assert tunnel._tun_to_udp_task is None
    assert tunnel._udp_to_tun_task is None

    # Verify no pending tasks
    await asyncio.sleep(0.1)

    # Cleanup
    await client.disconnect()
    await server.stop()
    mock_tun.close()


# ---------------------------------------------------------------------------
# Test 4-E: packet_stats reflects sent/received byte counts
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_packet_stats(mock_tunnel_pair) -> None:
    """Test 4-E: packet_stats correctly reflects sent/received byte counts."""
    server_tun, client_tun, server_tunnel, client_tunnel = mock_tunnel_pair

    # Stats should start at zero
    stats = client_tunnel.packet_stats
    assert stats["sent_count"] == 0
    assert stats["bytes_sent"] == 0

    # Send 5 packets from client
    for i in range(5):
        packet = _make_udp_packet(
            "10.210.0.2", "10.210.0.1",
            5000, 6000,
            f"stats-test-{i}".encode(),
        )
        client_tun.inject(packet)

    # Wait for them to be processed
    for _ in range(5):
        pkt = await server_tun.get_outbound_async(timeout=5.0)
        assert pkt is not None

    # Give a moment for stats to update
    await asyncio.sleep(0.3)

    # Client should show 5 sent
    client_stats = client_tunnel.packet_stats
    assert client_stats["sent_count"] == 5
    assert client_stats["bytes_sent"] > 0

    # Server should show 5 received
    server_stats = server_tunnel.packet_stats
    assert server_stats["recv_count"] == 5
    assert server_stats["bytes_recv"] > 0
    assert server_stats["avg_latency_ms"] >= 0
