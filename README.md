# Aegis-Tunnel X

Aegis-Tunnel X is a phase-built Python 3.11 tunnel project. Phase 1 establishes
the repository scaffold and a Linux TUN interface wrapper.

## Phase 1

Phase 1 provides:

- `aegis.tun.TunInterface`
- dependency metadata
- root-gated TUN tests in `tests/test_tun.py`

On Windows, Phase 1 uses WinTUN through `ctypes`; `wintun.dll` must be in the
project root and the terminal must run as Administrator. On Linux, Phase 1 uses
`/dev/net/tun` directly and must run as root.

```bash
python -m pytest tests/test_tun.py -v
```
