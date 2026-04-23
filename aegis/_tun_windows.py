from __future__ import annotations

import ctypes
import ipaddress
import subprocess
import threading
import uuid
from pathlib import Path


WINTUN_DLL = Path(__file__).parent.parent / "wintun.dll"
WINTUN_MIN_RING_CAPACITY = 0x20000
WINTUN_MAX_RING_CAPACITY = 0x4000000
WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF
ERROR_NO_MORE_ITEMS = 259
WAIT_OBJECT_0 = 0x00000000
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class TunInterfaceError(RuntimeError):
    """Raised when a WinTUN adapter cannot be created or configured."""


class TunInterface:
    """
    Windows WinTUN-based virtual network interface.

    Requires wintun.dll in the project root and Administrator privileges.
    """

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
        self._adapter: int | None = None
        self._session: int | None = None
        self._wintun: ctypes.WinDLL | None = None
        self._recv_event: int | None = None
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        return self._adapter is not None and self._session is not None

    def open(self) -> None:
        if self.is_open:
            return
        if not WINTUN_DLL.exists():
            raise FileNotFoundError(
                f"wintun.dll not found at {WINTUN_DLL}. "
                "Download from https://www.wintun.net and place it in the project root."
            )

        self._wintun = ctypes.WinDLL(str(WINTUN_DLL), use_last_error=True)
        self._configure_wintun_api()

        guid = self._make_guid()
        self._adapter = self._wintun.WintunCreateAdapter(
            ctypes.c_wchar_p(self.name),
            ctypes.c_wchar_p("Aegis"),
            ctypes.byref(guid),
        )
        if not self._adapter:
            raise self._win_error("WintunCreateAdapter failed")

        try:
            self._session = self._wintun.WintunStartSession(self._adapter, 0x200000)
            if not self._session:
                raise self._win_error("WintunStartSession failed")

            self._recv_event = self._wintun.WintunGetReadWaitEvent(self._session)
            if not self._recv_event:
                raise self._win_error("WintunGetReadWaitEvent failed")

            self._configure_ip()
        except Exception:
            self.close()
            raise

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

        if self.is_open:
            self._configure_ip()

    def read_packet(self) -> bytes:
        self._require_open()
        assert self._wintun is not None
        assert self._session is not None
        assert self._recv_event is not None

        kernel32 = ctypes.windll.kernel32
        kernel32.WaitForSingleObject.restype = ctypes.c_ulong
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]

        while True:
            size = ctypes.c_ulong(0)
            packet = self._wintun.WintunReceivePacket(
                self._session,
                ctypes.byref(size),
            )
            if packet:
                try:
                    return ctypes.string_at(packet, size.value)
                finally:
                    self._wintun.WintunReleaseReceivePacket(self._session, packet)

            error = ctypes.get_last_error()
            if error != ERROR_NO_MORE_ITEMS:
                raise self._win_error("WintunReceivePacket failed", error)

            wait_result = kernel32.WaitForSingleObject(self._recv_event, INFINITE)
            if wait_result == WAIT_FAILED:
                raise self._win_error("WaitForSingleObject failed")
            if wait_result != WAIT_OBJECT_0:
                raise TunInterfaceError(f"unexpected WinTUN wait result: {wait_result}")

    def write_packet(self, data: bytes) -> None:
        self._require_open()
        assert self._wintun is not None
        assert self._session is not None

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        if not data:
            raise ValueError("cannot write an empty packet")
        if len(data) > WINTUN_MAX_IP_PACKET_SIZE:
            raise ValueError("packet exceeds WinTUN maximum IP packet size")

        with self._lock:
            packet = self._wintun.WintunAllocateSendPacket(self._session, len(data))
            if not packet:
                raise self._win_error("WintunAllocateSendPacket failed")
            ctypes.memmove(packet, bytes(data), len(data))
            self._wintun.WintunSendPacket(self._session, packet)

    def close(self) -> None:
        if self._wintun is None:
            self._adapter = None
            self._session = None
            self._recv_event = None
            return

        with self._lock:
            if self._session:
                self._wintun.WintunEndSession(self._session)
                self._session = None
            if self._adapter:
                self._wintun.WintunCloseAdapter(self._adapter)
                self._adapter = None
            self._recv_event = None
            self._wintun = None

    def __enter__(self) -> TunInterface:
        self.open()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def _require_open(self) -> None:
        if not self.is_open:
            raise TunInterfaceError("TUN interface is not open")

    def _configure_wintun_api(self) -> None:
        assert self._wintun is not None
        wintun = self._wintun

        wintun.WintunCreateAdapter.restype = ctypes.c_void_p
        wintun.WintunCreateAdapter.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
        ]
        wintun.WintunCloseAdapter.restype = None
        wintun.WintunCloseAdapter.argtypes = [ctypes.c_void_p]

        wintun.WintunStartSession.restype = ctypes.c_void_p
        wintun.WintunStartSession.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        wintun.WintunEndSession.restype = None
        wintun.WintunEndSession.argtypes = [ctypes.c_void_p]

        wintun.WintunReceivePacket.restype = ctypes.c_void_p
        wintun.WintunReceivePacket.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        wintun.WintunReleaseReceivePacket.restype = None
        wintun.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        wintun.WintunAllocateSendPacket.restype = ctypes.c_void_p
        wintun.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        wintun.WintunSendPacket.restype = None
        wintun.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        wintun.WintunGetReadWaitEvent.restype = ctypes.c_void_p
        wintun.WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]

    def _configure_ip(self) -> None:
        self._run_netsh(
            "interface",
            "ip",
            "set",
            "address",
            f"name={self.name}",
            "static",
            self.ip,
            self.netmask,
        )
        self._run_netsh(
            "interface",
            "ipv4",
            "set",
            "subinterface",
            self.name,
            f"mtu={self.mtu}",
            "store=active",
        )

    def _run_netsh(self, *args: str) -> None:
        try:
            subprocess.run(
                ["netsh", *args],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.strip() or exc.stdout.strip()
            raise TunInterfaceError(f"netsh {' '.join(args)} failed: {detail}") from exc

    def _make_guid(self) -> GUID:
        namespace = uuid.UUID("12345678-1234-5678-1234-567812345678")
        adapter_id = uuid.uuid5(namespace, self.name)
        guid = GUID()
        guid.Data1 = adapter_id.time_low
        guid.Data2 = adapter_id.time_mid
        guid.Data3 = adapter_id.time_hi_version
        guid.Data4 = (ctypes.c_ubyte * 8)(*adapter_id.bytes[8:])
        return guid

    def _win_error(self, message: str, error: int | None = None) -> OSError:
        code = ctypes.get_last_error() if error is None else error
        return OSError(code, f"{message}: {ctypes.FormatError(code)}")
