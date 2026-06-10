# Aegis-Tunnel X — Post-Quantum Encrypted VPN Tunnel with DPI Evasion

Aegis-Tunnel X is a research-grade, post-quantum secure VPN tunnel that combines **CRYSTALS-Kyber512** key encapsulation, **AES-256-GCM** symmetric encryption, and a **Morphic Engine** that uses entropy-based packet padding to evade Deep Packet Inspection (DPI). It includes a real-time web dashboard with live entropy monitoring, packet visualisation, telemetry logging, and a cryptographic playground.

---

## Features

- **Post-Quantum Handshake** — CRYSTALS-Kyber512 KEM (via liboqs) establishes a shared session key resistant to quantum-computer attacks.
- **AES-256-GCM Encryption** — All tunnel payloads encrypted with authenticated encryption.
- **Morphic Engine** — Injects structured low-entropy padding into each packet to pull composite Shannon entropy below the ~7.9 DPI detection threshold, making encrypted traffic appear as ordinary data.
- **Traffic-Analysis Countermeasures**
  - Randomised padding (60–180 bytes per packet)
  - Randomised jitter delay (10–50 ms per packet)
  - Variable packet sizes defeat length-based fingerprinting
- **Real-Time Dashboard** — Flask/Socket.IO web UI with:
  - Entropy Monitor (live line chart with DPI danger zone)
  - Morphing Visualizer (stacked bar chart — payload vs padding)
  - Live Telemetry Log (per-packet lifecycle stream)
  - System Stats (aggregate metrics — throughput, avg entropy, total padding, avg jitter)
  - Crypto Playground (interactive encryption pipeline — plaintext → header → AES-256 → morphing → wire packet, with hex dumps, entropy bars, and DPI evasion scores)
- **Encrypted Chat Relay** — Type messages in the dashboard that get sent through the full tunnel pipeline (client encrypts → morphs → UDP → server decrypts → echoes back to dashboard).
- **Tunnel Start/Stop Control** — Toggle the continuous packet loop from the dashboard without restarting the client.
- **Morphic Engine Toggle** — Enable/disable the engine mid-session to compare DPI evasion effectiveness.
- **One-Click Launchers** — `run.bat` and `run.ps1` start all three components (dashboard, server, client) in separate windows.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        AEGIS-TUNNEL X                             │
│                                                                   │
│  ┌──────────┐      PQC Handshake (TCP 9000)      ┌──────────┐   │
│  │          │  ──── CRYSTALS-Kyber512 KEM ────→  │          │   │
│  │  CLIENT  │      Session Key Established        │  SERVER  │   │
│  │          │  ──── Encrypted UDP (9001) ──────→  │          │   │
│  │          │      AES-256-GCM + Morphic          │          │   │
│  │          │  ──── Encrypted Chat (9002) ──────→  │          │   │
│  └────┬─────┘                                     └────┬─────┘   │
│       │                                                │         │
│       │  HTTP REST + Socket.IO                         │         │
│       │                                                │         │
│       └──────────────────┬─────────────────────────────┘         │
│                          │                                       │
│                   ┌──────▼──────┐                                │
│                   │  DASHBOARD  │  Flask/SocketIO Web UI         │
│                   │  :5000      │  Real-time stats, controls     │
│                   └─────────────┘                                │
└──────────────────────────────────────────────────────────────────┘
```

### Component Communication

| Path | Protocol | Port | Purpose |
|---|---|---|---|
| Client ↔ Server | TCP | 9000 | Post-quantum handshake (Kyber512 KEM) |
| Client → Server | UDP | 9001 | Encrypted tunnel data (AES-256-GCM + morphing) |
| Client → Server | UDP | 9002 | Encrypted chat relay messages |
| Dashboard ↔ Client | HTTP | 5000 | Stats push, tunnel state, chat outbox polling |
| Dashboard → Server | HTTP | 5000 | Chat received push-back to dashboard |

---

## Project Structure

```
Aegis-Tunnel X/
├── client.py              # Tunnel client — handshake, packet loop, stats push
├── server.py              # Tunnel server — accept handshake, decrypt, log
├── crypto.py              # AES-256-GCM encrypt/decrypt helpers
├── morphic.py             # Shannon entropy meter + packet morphing engine
├── run.bat                # Windows batch launcher (3 windows)
├── run.ps1                # PowerShell launcher (3 windows)
├── oqs.dll                # Bundled liboqs native library (Windows)
├── dashboard/
│   ├── app.py             # Flask + Socket.IO web application
│   ├── static/
│   │   └── main.js        # Dashboard frontend — charts, router, crypto playground
│   └── templates/
│       └── index.html     # Dashboard HTML — 5-page SPA, dark theme, info cards
└── shared/
    ├── config.py          # Network constants (IP, ports)
    └── chat.py            # Chat message binary protocol (pack/unpack)
```

---

## Installation

### Prerequisites

- **Python 3.11+** (launchers point to Python 3.11; 3.12 also compatible)
- **pip packages:**

```bash
pip install cryptography flask flask-socketio
```

### liboqs / oqs-python

The project bundles `oqs.dll` for Windows. If it fails to load or you are on another OS, install liboqs-python:

```bash
pip install liboqs-python
```

> **Note:** The bundled `oqs.dll` is loaded from the project root via `os.add_dll_directory`. The import in `client.py` and `server.py` includes a fallback error message.

### Quick Start

**Option 1 — Launcher scripts:**

```bash
# PowerShell
.\run.ps1

# Command Prompt
run.bat
```

**Option 2 — Manual (three terminals):**

```bash
# Terminal 1: Dashboard
python dashboard/app.py

# Terminal 2: Server
python server.py

# Terminal 3: Client
python client.py
```

Then open **http://127.0.0.1:5000** in a browser.

---

## Dashboard Pages

### 1. Entropy Monitor
Live line chart of packet Shannon entropy with a red dashed line at **7.9** (the DPI danger threshold). When the Morphic Engine is on, entropy values drop below this line.

### 2. Morphing Visualizer
Stacked bar chart showing the composition of each outgoing packet — green for the AES-256 ciphertext payload, orange for the structured padding injected by the Morphic Engine.

### 3. Live Telemetry Log
Per-packet lifecycle stream:
- **MORPH lines** (green) — original size, padding added, entropy before→after, jitter delay
- **WARN lines** (red) — raw ciphertext sent without morphing (engine off)

### 4. System Stats
Aggregate counters across the session:
- Packets Sent
- Average Raw Entropy
- Average Morphed Entropy
- Total Padding Bytes
- Average Jitter (ms)
- Engine Status (ON/OFF)

### 5. Crypto Playground
Interactive 5-stage encryption pipeline visualiser. Type any message and click "ANALYZE & SEND":

1. **Plaintext Input** — raw UTF-8 bytes with hex dump and ASCII view
2. **Packet Header** — message-type byte (0x01) + length prefix
3. **AES-256-GCM Encryption** — nonce, ciphertext hex dump, entropy bar
4. **Morphic Engine Padding** — structured 0xAB 0xCD 0x00 0xFF padding with before/after entropy comparison
5. **Final Wire Packet** — combined packet with length prefix, DPI evasion score, and overhead percentage

Messages are also relayed through the real tunnel and echoed back upon decryption.

### Global Controls (top bar)

| Control | Action |
|---|---|
| **START/STOP TUNNEL** | Toggles the continuous packet loop in `client.py` |
| **MORPHIC ENGINE ON/OFF** | Enables/disables the Morphic Engine mid-session |
| Status Dot | Green pulsing = tunnel active, Red static = tunnel stopped |
| Session Key | Displays first 8 hex chars of the Kyber512-derived session key |

---

## Cryptographic Details

### Post-Quantum Key Exchange (CRYSTALS-Kyber512)

- **Algorithm:** CRYSTALS-Kyber (Module-LWE) at the 512-bit security level
- **Library:** liboqs via the `oqs` Python bindings
- **Flow:**
  1. Server generates a Kyber512 keypair and sends the public key to the client over TCP (port 9000)
  2. Client encapsulates a shared secret using the public key and sends back the ciphertext
  3. Server decapsulates the ciphertext to recover the same shared secret
  4. The resulting 32-byte shared secret is used directly as the AES-256 key

### Symmetric Encryption (AES-256-GCM)

- **Algorithm:** AES-256 in Galois/Counter Mode (authenticated encryption)
- **Nonce:** 12 random bytes per packet
- **Tag:** 16-byte authentication tag appended by AESGCM
- **Wire format:** `[12-byte nonce][ciphertext + tag]`

---

## Morphic Engine

The Morphic Engine is the core DPI evasion mechanism. It operates on each outgoing packet:

### How It Works

1. **Entropy Measurement** — Compute the Shannon entropy of the AES-256 ciphertext (typically ~7.99 bits/byte)
2. **Padding Injection** — Append 60–180 bytes of a repeating low-entropy pattern (`0xAB 0xCD 0x00 0xFF`)
3. **Entropy Reduction** — The structured padding dilutes the composite entropy below 7.9, below the threshold at which many DPI engines flag traffic as encrypted
4. **Jitter Injection** — Add a random 10–50 ms delay to defeat timing-correlation attacks
5. **Variable Sizing** — Randomised padding size hides the true payload length, defeating packet-size fingerprinting

### Shannon Entropy

```
H(X) = -Σ p(xᵢ) · log₂ p(xᵢ)
```

Where p(xᵢ) is the probability of byte value xᵢ in the packet. A perfectly random 256-byte payload has entropy ≈ 8.0. The repeating pattern `0xAB 0xCD 0x00 0xFF` has entropy ≈ 2.0, so adding it to near-8.0 ciphertext pulls the composite entropy down.

### DPI Threshold

Many DPI systems flag traffic with entropy > 7.9 as encrypted/protocol-obfuscated. The Morphic Engine keeps composite entropy safely below this line.

---

## Chat Relay Protocol

Defined in `shared/chat.py`:

```
Wire format:
┌─────────┬──────────────┬──────────────────┐
│ 1 byte  │  2 bytes     │  Variable        │
│ Type    │ Payload Len  │  UTF-8 Text      │
│ 0x01    │  big-endian  │  max 4096 bytes  │
└─────────┴──────────────┴──────────────────┘
```

**Flow:** Dashboard → `/chat/send` → chat_outbox (Queue) → client polls outbox → encrypts → morphs → UDP 9002 → server decrypts → POST `/chat/received` → Socket.IO broadcast to dashboard.

---

## Configuration

`shared/config.py`:

| Constant | Value | Description |
|---|---|---|
| `SERVER_IP` | `127.0.0.1` | Bind/connect address |
| `HANDSHAKE_PORT` | `9000` | TCP Kyber512 handshake |
| `DATA_PORT` | `9001` | UDP encrypted data |
| `CHAT_PORT` | `9002` | UDP encrypted chat |
| `VIRTUAL_CLIENT_IP` | `10.0.0.2` | Virtual internal IP |
| `VIRTUAL_SERVER_IP` | `10.0.0.1` | Virtual internal IP |

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_BASE_URL` | `http://127.0.0.1:5000` | Dashboard API endpoint |
| `MORPHIC_ENGINE_ON` | `true` | Default engine state |
| `PACKET_INTERVAL_MS` | `400` | Delay between test packets |

---

## Dependencies

| Library | Purpose | Required By |
|---|---|---|
| `oqs` (liboqs-python) | CRYSTALS-Kyber512 KEM | client.py, server.py |
| `cryptography` | AES-256-GCM via `AESGCM` | crypto.py |
| `flask` | Web framework | dashboard/app.py |
| `flask-socketio` | Real-time WebSocket bridge | dashboard/app.py |
| `chart.js` (CDN) | Client-side line/bar charts | index.html |
| `socket.io` (CDN) | Client-side WebSocket | main.js |

`oqs.dll` (binaries for Windows, bundled at project root) is required for the `oqs` Python bindings to load.

---

## Development

### Components at a Glance

| File | Lines | Responsibility |
|---|---|---|
| `client.py` | 191 | PQC handshake, continuous UDP packet loop, engine/tunnel state polling, chat outbox relay |
| `server.py` | 146 | PQC handshake acceptor, UDP listener, chat listener, decryption + logging |
| `crypto.py` | 27 | AES-256-GCM encrypt/decrypt wrappers with key validation |
| `morphic.py` | 52 | Shannon entropy calculation, padding injection, jitter |
| `dashboard/app.py` | 207 | Flask routes, Socket.IO events, fake-packet simulator, chat queue |
| `dashboard/static/main.js` | 658 | Hash-router SPA, Chart.js charts, Socket.IO handlers, crypto pipeline UI |
| `dashboard/templates/index.html` | 874 | Full-page dark-theme HTML with inline CSS |
| `shared/config.py` | 6 | Port/IP constants |
| `shared/chat.py` | 30 | Chat binary protocol (pack/unpack) |

---

## License

MIT — see [LICENSE](LICENSE) (if present) or the repository root.
