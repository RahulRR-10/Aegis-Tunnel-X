import platform

if platform.system() == "Windows":
    from aegis._tun_windows import TunInterface, TunInterfaceError
else:
    from aegis._tun_linux import TunInterface, TunInterfaceError

__all__ = ["TunInterface", "TunInterfaceError"]
