# Aegis-Tunnel X

Aegis-Tunnel X is a post-quantum encrypted UDP tunnel with morphic traffic
shaping, designed to defeat Deep Packet Inspection (DPI) and traffic
fingerprinting.

## Features

- **Post-Quantum Key Exchange:** Hybrid Kyber-768 + X25519 handshake
- **Per-Packet Encryption:** AES-256-GCM AEAD with HKDF-derived keys
- **Morphic Traffic Shaping:** Continuously transforms packet sizes and timing
  to mimic real traffic profiles (web browsing, video streaming, gaming)
- **Detection Feedback Loop:** Real-time statistical analysis that auto-tunes
  the morphic engine to minimize detectability
- **Cross-Platform:** Native support for Windows (WinTUN) and Linux (/dev/net/tun)

## Platform Support

| Platform | TUN Backend | Privilege Required |
|----------|-------------|--------------------|
| Windows 10/11 | WinTUN via `ctypes` | Administrator |
| Linux (Ubuntu 22.04+) | `/dev/net/tun` via `fcntl` | root |

## Quick Start (Windows)

### Prerequisites

- Python 3.11+
- `wintun.dll` in the project root ([download](https://www.wintun.net))
- Administrator PowerShell

### Install

```powershell
pip install -r requirements.txt
```

### Run Tests (Phase 1)

```powershell
# Run as Administrator
python -m pytest tests/test_tun.py -v
```

## Project Structure

```
aegis-tunnel-x/
├── aegis/
│   ├── __init__.py
│   ├── tun.py              # Platform dispatcher
│   ├── _tun_windows.py     # WinTUN ctypes adapter
│   ├── _tun_linux.py       # Linux /dev/net/tun adapter
│   ├── crypto.py           # Phase 2 — AES-256-GCM + Kyber
│   ├── transport.py        # Phase 3 — UDP framing & sessions
│   ├── tunnel.py           # Phase 4 — TUN ↔ UDP glue
│   ├── morphic.py          # Phase 5 — morphic engine
│   ├── feedback.py         # Phase 6 — detection feedback loop
│   ├── cli.py              # Phase 7 — CLI entry point
│   └── config.py           # Phase 7 — config loader
├── tests/
├── profiles/               # Traffic shaping profiles (JSON)
├── demo/                   # End-to-end demo configs
├── wintun.dll              # WinTUN driver (Windows only)
├── requirements.txt
├── setup.py
└── README.md
```

## Build Phases

| Phase | Module | Status |
|-------|--------|--------|
| 1 | TUN Interface | ✅ Complete |
| 2 | Encryption Engine | ✅ Complete |
| 3 | UDP Transport | ✅ Complete |
| 4 | Tunnel Integration | ✅ Complete |
| 5 | Morphic Engine | ✅ Complete |
| 6 | Feedback Loop | ✅ Complete |
| 7 | CLI & Config | ⬜ Pending |
| 8 | Demo & E2E | ⬜ Pending |
