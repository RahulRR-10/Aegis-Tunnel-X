"""Phase 4 — Tunnel Integration (TUN ↔ UDP).

Glues the TUN interface (Phase 1) to the UDP transport (Phase 3),
creating a full bidirectional IP-packet tunnel:

  TUN read → [morphic transform] → encrypt → UDP send
  UDP recv → decrypt → [morphic detransform] → TUN write

Blocking WinTUN reads/writes are offloaded to a thread executor via
``loop.run_in_executor()`` so they don't block the asyncio event loop.

Classes:
  AegisTunnel — main tunnel orchestrator with packet_stats metrics
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Any

from aegis.tun import TunInterface
from aegis.transport import AegisTunnelServer, AegisTunnelClient

__all__ = ["AegisTunnel"]

logger = logging.getLogger("aegis.tunnel")

# IP header constants
_IP_HEADER_MIN = 20
_IP_ID_OFFSET = 4         # offset of Identification field in IPv4 header
_IP_FLAGS_OFFSET = 6      # offset of Flags+FragmentOffset
_IP_TOTAL_LEN_OFFSET = 2  # offset of Total Length


class AegisTunnel:
    """Bidirectional TUN ↔ UDP tunnel.

    Reads raw IP packets from the TUN interface, encrypts them via the
    transport layer, and sends them over UDP.  Incoming encrypted UDP
    packets are decrypted and injected back into the TUN.

    Args:
        tun:       An open ``TunInterface``.
        transport: An ``AegisTunnelServer`` or ``AegisTunnelClient``.
        morphic:   Optional morphic engine (Phase 5); ``None`` = passthrough.
        feedback:  Optional feedback loop (Phase 6); ``None`` = passthrough.

    Usage::

        tunnel = AegisTunnel(tun, client)
        await tunnel.run()      # blocks until stop() is called
    """

    def __init__(
        self,
        tun: TunInterface,
        transport: AegisTunnelServer | AegisTunnelClient,
        morphic: Any = None,    # Phase 5 — MorphicEngine; None = passthrough
        feedback: Any = None,   # Phase 6 — FeedbackLoop; None = passthrough
    ) -> None:
        self._tun = tun
        self._transport = transport
        self._morphic = morphic
        self._feedback = feedback

        # Metrics
        self._sent_count: int = 0
        self._recv_count: int = 0
        self._bytes_sent: int = 0
        self._bytes_recv: int = 0
        self._latency_samples: list[float] = []

        # Task handles
        self._tun_to_udp_task: asyncio.Task[None] | None = None
        self._udp_to_tun_task: asyncio.Task[None] | None = None
        self._running = False

        # Fragment reassembly buffer: (ip_id) -> list of (offset, data) pairs
        self._frag_buffer: dict[int, list[tuple[int, bytes]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """True if the tunnel tasks are active."""
        return self._running

    @property
    def packet_stats(self) -> dict[str, Any]:
        """Return live tunnel metrics.

        Returns:
            dict with keys: sent_count, recv_count, bytes_sent,
            bytes_recv, avg_latency_ms
        """
        avg_latency = 0.0
        if self._latency_samples:
            avg_latency = (
                sum(self._latency_samples) / len(self._latency_samples)
            )
        return {
            "sent_count": self._sent_count,
            "recv_count": self._recv_count,
            "bytes_sent": self._bytes_sent,
            "bytes_recv": self._bytes_recv,
            "avg_latency_ms": round(avg_latency, 3),
        }

    async def run(self) -> None:
        """Start the bidirectional tunnel and block until ``stop()`` is called.

        Spawns two concurrent tasks:
          - ``_tun_to_udp``: TUN → encrypt → UDP
          - ``_udp_to_tun``: UDP → decrypt → TUN
        """
        self._running = True

        self._tun_to_udp_task = asyncio.create_task(
            self._tun_to_udp(), name="tun_to_udp"
        )
        self._udp_to_tun_task = asyncio.create_task(
            self._udp_to_tun(), name="udp_to_tun"
        )

        logger.info("Tunnel started")

        try:
            await asyncio.gather(
                self._tun_to_udp_task,
                self._udp_to_tun_task,
            )
        except asyncio.CancelledError:
            logger.debug("Tunnel tasks cancelled")

    async def stop(self) -> None:
        """Cleanly cancel both tunnel tasks."""
        self._running = False

        tasks: list[asyncio.Task[None]] = []
        if self._tun_to_udp_task:
            self._tun_to_udp_task.cancel()
            tasks.append(self._tun_to_udp_task)
        if self._udp_to_tun_task:
            self._udp_to_tun_task.cancel()
            tasks.append(self._udp_to_tun_task)

        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass

        self._tun_to_udp_task = None
        self._udp_to_tun_task = None
        logger.info("Tunnel stopped")

    # ------------------------------------------------------------------
    # TUN → UDP path
    # ------------------------------------------------------------------

    async def _tun_to_udp(self) -> None:
        """Read packets from TUN, optionally transform them, then send via UDP."""
        loop = asyncio.get_running_loop()

        while self._running:
            try:
                # Blocking TUN read offloaded to thread executor
                packet = await loop.run_in_executor(
                    None, self._tun.read_packet
                )
            except OSError as e:
                if not self._running:
                    break
                logger.error("TUN read error: %s", e)
                continue
            except asyncio.CancelledError:
                break

            if not packet:
                continue

            send_ts = time.monotonic()
            size = len(packet)

            logger.debug(
                "TUN→UDP: %d bytes, IP ver=%d",
                size,
                (packet[0] >> 4) if packet else 0,
            )

            try:
                # Send via the transport layer
                if isinstance(self._transport, AegisTunnelClient):
                    await self._transport.send_packet(packet)
                elif isinstance(self._transport, AegisTunnelServer):
                    # Server sends to all connected clients
                    for addr in list(self._transport._sessions.keys()):
                        await self._transport.send_to(packet, addr)

                self._sent_count += 1
                self._bytes_sent += size

            except Exception as e:
                logger.error("UDP send error: %s", e)

    # ------------------------------------------------------------------
    # UDP → TUN path
    # ------------------------------------------------------------------

    async def _udp_to_tun(self) -> None:
        """Receive packets from UDP, optionally detransform, inject into TUN."""
        loop = asyncio.get_running_loop()

        while self._running:
            try:
                if isinstance(self._transport, AegisTunnelClient):
                    packet = await asyncio.wait_for(
                        self._transport.receive_packet(),
                        timeout=1.0,
                    )
                elif isinstance(self._transport, AegisTunnelServer):
                    packet, addr = await asyncio.wait_for(
                        self._transport.recv_queue.get(),
                        timeout=1.0,
                    )
                else:
                    await asyncio.sleep(0.1)
                    continue
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            if not packet:
                continue

            recv_ts = time.monotonic()
            size = len(packet)

            logger.debug(
                "UDP→TUN: %d bytes, IP ver=%d",
                size,
                (packet[0] >> 4) if packet else 0,
            )

            try:
                # Blocking TUN write offloaded to thread executor
                await loop.run_in_executor(
                    None, self._tun.write_packet, packet
                )

                self._recv_count += 1
                self._bytes_recv += size

                # Track latency (rough, from recv to TUN write)
                latency_ms = (time.monotonic() - recv_ts) * 1000
                self._latency_samples.append(latency_ms)
                # Keep only last 100 samples
                if len(self._latency_samples) > 100:
                    self._latency_samples = self._latency_samples[-100:]

            except Exception as e:
                logger.error("TUN write error: %s", e)

    # ------------------------------------------------------------------
    # IP Fragmentation helpers (used in Phase 5+ when morphic changes sizes)
    # ------------------------------------------------------------------

    @staticmethod
    def fragment_packet(
        packet: bytes, max_payload: int
    ) -> list[bytes]:
        """Fragment an IP packet into pieces no larger than max_payload.

        Args:
            packet:      Raw IPv4 packet.
            max_payload: Maximum size for each fragment.

        Returns:
            List of IPv4 packet fragments. If the packet is already small
            enough, returns ``[packet]``.
        """
        if len(packet) <= max_payload:
            return [packet]

        if len(packet) < _IP_HEADER_MIN:
            return [packet]

        ihl = (packet[0] & 0x0F) * 4
        ip_header = bytearray(packet[:ihl])
        ip_payload = packet[ihl:]

        ip_id = struct.unpack("!H", packet[_IP_ID_OFFSET:_IP_ID_OFFSET + 2])[0]

        # Fragment payload at 8-byte boundaries
        frag_data_size = ((max_payload - ihl) // 8) * 8
        if frag_data_size <= 0:
            return [packet]

        fragments: list[bytes] = []
        offset = 0

        while offset < len(ip_payload):
            chunk = ip_payload[offset:offset + frag_data_size]
            is_last = (offset + frag_data_size) >= len(ip_payload)

            frag_header = bytearray(ip_header)

            # Set total length
            total = ihl + len(chunk)
            struct.pack_into("!H", frag_header, _IP_TOTAL_LEN_OFFSET, total)

            # Set fragment offset (in 8-byte units) and MF flag
            frag_offset_units = offset // 8
            flags_frag = frag_offset_units & 0x1FFF
            if not is_last:
                flags_frag |= 0x2000  # More Fragments
            struct.pack_into("!H", frag_header, _IP_FLAGS_OFFSET, flags_frag)

            # Recalculate IP header checksum
            frag_header[10] = 0
            frag_header[11] = 0
            cksum = AegisTunnel._ip_checksum(bytes(frag_header))
            struct.pack_into("!H", frag_header, 10, cksum)

            fragments.append(bytes(frag_header) + chunk)
            offset += frag_data_size

        return fragments

    @staticmethod
    def _ip_checksum(header: bytes) -> int:
        """Compute the IP header checksum."""
        if len(header) % 2:
            header = header + b"\x00"
        total = 0
        for i in range(0, len(header), 2):
            total += (header[i] << 8) + header[i + 1]
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF
