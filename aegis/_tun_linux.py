"""Phase 1 — Linux /dev/net/tun interface for raw IP packet capture and injection.

Uses fcntl ioctl to create a TUN device and the ``ip`` command to configure
addressing. Requires root privileges and a kernel with TUN/TAP support.

This module is only imported on Linux (see aegis/tun.py dispatcher).
"""

from __future__ import annotations

import fcntl
import ipaddress
import os
import platform
import struct
import subprocess
from pathlib import Path


# ---------------------------------------------------------------------------
# Linux TUN constants
# ---------------------------------------------------------------------------

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TunInterfaceError(RuntimeError):
    """Raised when a Linux TUN device cannot be created or configured."""


# ---------------------------------------------------------------------------
# TunInterface — Linux backend
# ---------------------------------------------------------------------------

class TunInterface:
    """Linux /dev/net/tun interface for raw IP packet capture and injection.

    Requires root privileges and ``/dev/net/tun`` to be available.

    Usage::

        with TunInterface(name="aegis0", mtu=1400) as tun:
            tun.set_address("10.10.0.1", "10.10.0.2")
            tun.open()
            packet = tun.read_packet()
            tun.write_packet(packet)
    """

    def __init__(self, name: str = "aegis0", mtu: int = 1400) -> None:
        if not name:
            raise ValueError("TUN interface name cannot be empty")
        if mtu <= 0:
            raise ValueError("MTU must be greater than zero")

        self.name: str = name
        self.mtu: int = mtu
        self.ip: str = "10.10.0.1"
        self.peer_ip: str = "10.10.0.2"
        self.netmask: str = "255.255.255.0"
        self._fd: int | None = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_open(self) -> bool:
        """Return True if the TUN file descriptor is active."""
        return self._fd is not None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Create the TUN device, set IP/netmask, and bring it UP."""
        if self._fd is not None:
            return

        self._ensure_linux_tun_available()

        fd = os.open("/dev/net/tun", os.O_RDWR)
        try:
            ifr = struct.pack(
                "16sH",
                self.name.encode("utf-8")[:15],
                IFF_TUN | IFF_NO_PI,
            )
            result = fcntl.ioctl(fd, TUNSETIFF, ifr)
            actual_name = result[:16].split(b"\x00", 1)[0].decode("utf-8")
            if actual_name:
                self.name = actual_name
            self._fd = fd
            self._configure_interface()
        except Exception:
            os.close(fd)
            self._fd = None
            raise

    def close(self) -> None:
        """Bring the interface down and close the file descriptor."""
        if self._fd is None:
            return

        try:
            self._run_ip("link", "set", "dev", self.name, "down")
        except Exception:
            pass

        os.close(self._fd)
        self._fd = None

    # ------------------------------------------------------------------
    # Packet I/O
    # ------------------------------------------------------------------

    def read_packet(self) -> bytes:
        """Blocking read of one raw IP packet from the TUN device."""
        fd = self._require_open()
        return os.read(fd, self.mtu + 4)

    def write_packet(self, data: bytes) -> None:
        """Inject a raw IP packet into the TUN device."""
        fd = self._require_open()

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        if not data:
            raise ValueError("cannot write an empty packet")

        view = memoryview(data)
        written_total = 0
        while written_total < len(view):
            written_total += os.write(fd, view[written_total:])

    # ------------------------------------------------------------------
    # Address configuration
    # ------------------------------------------------------------------

    def set_address(
        self,
        ip: str,
        peer_ip: str,
        netmask: str = "255.255.255.0",
    ) -> None:
        """Set or update the TUN device's IP address, peer IP, and netmask."""
        ipaddress.ip_address(ip)
        ipaddress.ip_address(peer_ip)
        ipaddress.IPv4Network(f"0.0.0.0/{netmask}")

        self.ip = ip
        self.peer_ip = peer_ip
        self.netmask = netmask

        if self._fd is not None:
            self._configure_interface()

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def fileno(self) -> int:
        """Return the underlying file descriptor (for select/poll)."""
        return self._require_open()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> TunInterface:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_open(self) -> int:
        """Raise if the device is not open; otherwise return the fd."""
        if self._fd is None:
            raise TunInterfaceError("TUN interface is not open")
        return self._fd

    def _ensure_linux_tun_available(self) -> None:
        """Check that we're on Linux, have /dev/net/tun, and are root."""
        if platform.system() != "Linux":
            raise TunInterfaceError(
                "Linux TUN implementation can run only on Linux"
            )
        if not Path("/dev/net/tun").exists():
            raise TunInterfaceError("/dev/net/tun is not available")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError(
                "root privileges are required to create a TUN device"
            )

    def _configure_interface(self) -> None:
        """Set MTU, assign IP address, and bring the interface up."""
        prefix_len = ipaddress.IPv4Network(
            f"0.0.0.0/{self.netmask}"
        ).prefixlen
        self._run_ip("link", "set", "dev", self.name, "mtu", str(self.mtu))
        self._run_ip(
            "addr", "replace",
            f"{self.ip}/{prefix_len}",
            "peer", self.peer_ip,
            "dev", self.name,
        )
        self._run_ip("link", "set", "dev", self.name, "up")

    def _run_ip(self, *args: str) -> None:
        """Execute an ``ip`` command, raising TunInterfaceError on failure."""
        try:
            subprocess.run(
                ["ip", *args],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise TunInterfaceError(
                "the Linux 'ip' command is required"
            ) from exc
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.strip() or exc.stdout.strip()
            raise TunInterfaceError(
                f"ip {' '.join(args)} failed: {detail}"
            ) from exc
