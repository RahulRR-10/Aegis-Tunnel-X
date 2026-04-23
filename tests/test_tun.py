from __future__ import annotations

import pytest
import ctypes
import ipaddress
import os
import platform
from pathlib import Path
import queue
import socket
import struct
import subprocess
import threading
import time


from aegis.tun import TunInterface


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _is_windows_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _skip_reason() -> str | None:
    system = platform.system()
    if system == "Windows":
        if not _is_windows_admin():
            return "requires Administrator on Windows"
        if not (PROJECT_ROOT / "wintun.dll").exists():
            return "requires wintun.dll in the project root"
        return None

    if system == "Linux":
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return "requires root on Linux"
        if not Path("/dev/net/tun").exists():
            return "requires /dev/net/tun on Linux"
        return None

    return "requires Windows WinTUN or Linux /dev/net/tun"


pytestmark = pytest.mark.skipif(_skip_reason() is not None, reason=_skip_reason() or "")


def _wait_for(predicate, timeout_s: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _udp_ipv4_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    src = ipaddress.IPv4Address(src_ip).packed
    dst = ipaddress.IPv4Address(dst_ip).packed
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0xAE91,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        src,
        dst,
    )
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    return ip_header + udp_header + payload


def _read_packet_with_timeout(tun: TunInterface, timeout_s: float = 2.0) -> bytes:
    packets: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=1)

    def read_once() -> None:
        try:
            packets.put(tun.read_packet())
        except BaseException as exc:
            packets.put(exc)

    thread = threading.Thread(target=read_once, daemon=True)
    thread.start()
    try:
        result = packets.get(timeout=timeout_s)
    except queue.Empty:
        pytest.fail("timed out waiting for packet from TUN")

    if isinstance(result, BaseException):
        raise result
    return result


def _interface_exists(name: str) -> bool:
    if platform.system() == "Windows":
        result = subprocess.run(
            ["netsh", "interface", "show", "interface", f"name={name}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.returncode == 0
    return Path(f"/sys/class/net/{name}").exists()


def _read_mtu(name: str) -> int:
    if platform.system() == "Windows":
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for line in result.stdout.splitlines():
            if line.rstrip().endswith(name):
                return int(line.split()[0])
        pytest.fail(f"could not find MTU for {name}")

    return int(Path(f"/sys/class/net/{name}/mtu").read_text(encoding="utf-8").strip())


@pytest.fixture
def tun() -> TunInterface:
    iface_name = os.environ.get("AEGIS_TEST_IFACE", "aegis0")
    interface = TunInterface(name=iface_name, mtu=1400)
    interface.set_address("10.210.0.1", "10.210.0.2")
    try:
        yield interface
    finally:
        interface.close()


def test_tun_device_opens_without_error(tun: TunInterface) -> None:
    tun.open()

    assert tun.is_open
    assert _interface_exists(tun.name)


def test_injects_and_captures_raw_ip_packets(tun: TunInterface) -> None:
    tun.open()

    # On Windows, the netsh-assigned IP may not be immediately bindable.
    # Retry until the OS finishes registering the address.
    payload = b"phase-1-inject"
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.settimeout(2.0)
    deadline = time.monotonic() + 5.0
    while True:
        try:
            recv_sock.bind((tun.ip, 54321))
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
    try:
        packet = _udp_ipv4_packet(tun.peer_ip, tun.ip, 42000, 54321, payload)
        tun.write_packet(packet)

        received, remote = recv_sock.recvfrom(2048)
        assert received == payload
        assert remote[0] == tun.peer_ip
    finally:
        recv_sock.close()

    capture_payload = b"phase-1-capture"
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        send_sock.sendto(capture_payload, (tun.peer_ip, 54322))

        # Windows TUN adapters may emit background IPv6 traffic (e.g.
        # neighbor discovery).  Keep reading until we find our IPv4 packet.
        captured: bytes | None = None
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            pkt = _read_packet_with_timeout(tun, timeout_s=2.0)
            if pkt[0] >> 4 == 4 and capture_payload in pkt:
                captured = pkt
                break
    finally:
        send_sock.close()

    assert captured is not None, "never received our IPv4 UDP packet from TUN"
    assert captured[0] >> 4 == 4
    assert captured[9] == socket.IPPROTO_UDP
    assert capture_payload in captured


def test_mtu_is_set(tun: TunInterface) -> None:
    tun.open()

    assert _read_mtu(tun.name) == tun.mtu


def test_close_tears_down_cleanly(tun: TunInterface) -> None:
    tun.open()
    assert tun.is_open

    name = tun.name
    tun.close()

    assert not tun.is_open
    if platform.system() == "Linux":
        assert _wait_for(lambda: not Path(f"/sys/class/net/{name}").exists())
