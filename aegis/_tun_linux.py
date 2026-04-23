from __future__ import annotations

import fcntl
import ipaddress
import os
import platform
import struct
import subprocess
from pathlib import Path


TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class TunInterfaceError(RuntimeError):
    """Raised when a Linux TUN device cannot be created or configured."""


class TunInterface:
    """Linux /dev/net/tun interface for raw IP packet capture and injection."""

    def __init__(self, name: str = "aegis0", mtu: int = 1400):
        if not name:
            raise ValueError("TUN interface name cannot be empty")
        if mtu <= 0:
            raise ValueError("MTU must be greater than zero")

        self.name = name
        self.mtu = mtu
        self.ip = "10.10.0.1"
        self.peer_ip = "10.10.0.2"
        self.netmask = "255.255.255.0"
        self._fd: int | None = None

    @property
    def is_open(self) -> bool:
        return self._fd is not None

    def open(self) -> None:
        if self._fd is not None:
            return

        self._ensure_linux_tun_available()
        fd = os.open("/dev/net/tun", os.O_RDWR)
        try:
            ifr = struct.pack("16sH", self.name.encode("utf-8")[:15], IFF_TUN | IFF_NO_PI)
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
        if self._fd is None:
            return

        try:
            self._run_ip("link", "set", "dev", self.name, "down")
        except Exception:
            pass

        os.close(self._fd)
        self._fd = None

    def read_packet(self) -> bytes:
        fd = self._require_open()
        return os.read(fd, self.mtu + 4)

    def write_packet(self, data: bytes) -> None:
        fd = self._require_open()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        if not data:
            raise ValueError("cannot write an empty packet")

        view = memoryview(data)
        written_total = 0
        while written_total < len(view):
            written_total += os.write(fd, view[written_total:])

    def set_address(
        self,
        ip: str,
        peer_ip: str,
        netmask: str = "255.255.255.0",
    ) -> None:
        ipaddress.ip_address(ip)
        ipaddress.ip_address(peer_ip)
        ipaddress.IPv4Network(f"0.0.0.0/{netmask}")

        self.ip = ip
        self.peer_ip = peer_ip
        self.netmask = netmask

        if self._fd is not None:
            self._configure_interface()

    def fileno(self) -> int:
        return self._require_open()

    def __enter__(self) -> TunInterface:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def _require_open(self) -> int:
        if self._fd is None:
            raise TunInterfaceError("TUN interface is not open")
        return self._fd

    def _ensure_linux_tun_available(self) -> None:
        if platform.system() != "Linux":
            raise TunInterfaceError("Linux TUN implementation can run only on Linux")
        if not Path("/dev/net/tun").exists():
            raise TunInterfaceError("/dev/net/tun is not available")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError("root privileges are required to create a TUN device")

    def _configure_interface(self) -> None:
        prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{self.netmask}").prefixlen
        self._run_ip("link", "set", "dev", self.name, "mtu", str(self.mtu))
        self._run_ip(
            "addr",
            "replace",
            f"{self.ip}/{prefix_len}",
            "peer",
            self.peer_ip,
            "dev",
            self.name,
        )
        self._run_ip("link", "set", "dev", self.name, "up")

    def _run_ip(self, *args: str) -> None:
        try:
            subprocess.run(
                ["ip", *args],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise TunInterfaceError("the Linux 'ip' command is required") from exc
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.strip() or exc.stdout.strip()
            raise TunInterfaceError(f"ip {' '.join(args)} failed: {detail}") from exc
