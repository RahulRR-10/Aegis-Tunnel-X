"""Phase 1 — TUN interface platform dispatcher.

Imports the correct TunInterface implementation based on the current OS:
  - Windows: WinTUN via ctypes (_tun_windows.py)
  - Linux:   /dev/net/tun via fcntl (_tun_linux.py)
"""

import platform

if platform.system() == "Windows":
    from aegis._tun_windows import TunInterface, TunInterfaceError
else:
    from aegis._tun_linux import TunInterface, TunInterfaceError

__all__ = ["TunInterface", "TunInterfaceError"]
