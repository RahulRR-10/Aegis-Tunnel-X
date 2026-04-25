# Aegis-Tunnel X — Frontend Demo Implementation Plan

> **Stack:** React 18 + Vite · Tailwind CSS · Recharts · FastAPI (WebSocket + REST bridge) · Python `asyncio`  
> **Aesthetic:** Industrial dark — monospace terminals, neon accent lines, raw signal-monitor energy  
> **Approach:** A thin FastAPI server (`aegis/api.py`) exposes all backend state over WebSocket + REST. The React frontend reads from it. No rewrites to existing backend modules.

---

## Repo Additions (never restructures existing layout)

```
aegis-tunnel-x/
├── aegis/
│   └── api.py              ← NEW: FastAPI bridge (Phase F1)
├── frontend/
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   ├── src/
│   │   ├── main.jsx
│   │   ├── App.jsx
│   │   ├── hooks/
│   │   │   └── useAegisSocket.js   ← shared WebSocket hook
│   │   ├── components/
│   │   │   ├── Shell/              ← Phase F1
│   │   │   ├── CryptoPanel/        ← Phase F2
│   │   │   ├── TransportPanel/     ← Phase F3
│   │   │   ├── TunnelPanel/        ← Phase F4
│   │   │   ├── MorphicPanel/       ← Phase F5
│   │   │   ├── FeedbackPanel/      ← Phase F6
│   │   │   ├── ConfigPanel/        ← Phase F7
│   │   │   └── DemoCenter/         ← Phase F8
│   │   └── lib/
│   │       └── format.js           ← byte/time formatters
│   └── public/
└── demo/
    └── run_demo_with_ui.ps1        ← Phase F8: updated demo script
```

---

## Phase F0 — Backend API Bridge (`aegis/api.py`)

**Goal:** Add a non-invasive FastAPI server that exposes all existing backend state via REST + WebSocket without touching any Phase 1–8 modules.

### F0.1 — Dependencies

Add to `requirements.txt`:
```
fastapi>=0.111
uvicorn[standard]>=0.29
websockets>=12.0
```

### F0.2 — API Surface

**REST Endpoints**

| Method | Path | Returns | Backed By |
|--------|------|---------|-----------|
| `GET` | `/api/status` | Session ID, uptime, mode, connection info | `tunnel.packet_stats` |
| `GET` | `/api/crypto` | Algorithm names, handshake status, key fingerprints | `SessionCrypto` metadata |
| `GET` | `/api/transport` | Seq counter, recv_window size, keepalive timer | `UDPSession` fields |
| `GET` | `/api/tunnel` | TX/RX bytes, packet counts, avg latency, TUN IP/peer | `tunnel.packet_stats` + `TunInterface` |
| `GET` | `/api/morphic` | Active profile name, current distribution params | `morphic.current_profile` |
| `GET` | `/api/feedback` | Detection score, all 5 metrics, history (last 100) | `feedback.history` + `analyzer.detection_score()` |
| `GET` | `/api/config` | Rendered server/client config (secrets redacted) | `config.py` loader output |
| `POST` | `/api/profile/{name}` | Switches morphic profile | `morphic.switch_profile()` |
| `POST` | `/api/demo/start` | Starts demo subprocess sequence | Wraps `run_demo.ps1` steps |
| `POST` | `/api/demo/stop` | Kills demo processes | `subprocess.terminate()` |
| `GET` | `/api/demo/status` | Demo step progress, E2E test results | Internal state |

**WebSocket: `/ws/metrics`**

Pushes a JSON frame every **500 ms**:
```json
{
  "ts": 1714000000.123,
  "bytes_tx": 2400000,
  "bytes_rx": 2100000,
  "pkts_tx": 1204,
  "pkts_rx": 1198,
  "latency_ms": 4.2,
  "detection_score": 0.12,
  "metrics": {
    "entropy": 7.94,
    "ipd_cv": 0.81,
    "size_chi2_p": 0.43,
    "burstiness": 1.12,
    "periodicity": 0.09
  },
  "profile": "web_browsing",
  "seq_counter": 4821,
  "handshake_done": true
}
```

### F0.3 — Running the API

```powershell
# In Administrator PowerShell, alongside the tunnel:
uvicorn aegis.api:app --host 127.0.0.1 --port 8765 --reload
```

The API shares the running `AegisTunnel` instance via a module-level singleton in `api.py`. No state duplication.

### F0 Exit Criteria
- `GET /api/status` returns valid JSON while tunnel runs
- WebSocket client receives frames at ~2 Hz
- All endpoints return `503` gracefully if tunnel is not running

---

## Phase F1 — Project Setup & Application Shell

**Goal:** Bootstrapped React app, design system, WebSocket hook, and the persistent shell layout that all panels live inside.

### F1.1 — Bootstrap

```bash
cd frontend
npm create vite@latest . -- --template react
npm install recharts tailwindcss @tailwindcss/vite lucide-react
```

`vite.config.js` proxy — avoids CORS during dev:
```js
server: {
  proxy: {
    '/api': 'http://localhost:8765',
    '/ws':  { target: 'ws://localhost:8765', ws: true }
  }
}
```

### F1.2 — Design System (CSS variables in `index.css`)

```css
:root {
  --bg-void:    #080c10;
  --bg-panel:   #0d1117;
  --bg-card:    #141b24;
  --border:     #1e2d3d;
  --accent-green:  #00ff88;
  --accent-cyan:   #00cfff;
  --accent-red:    #ff4444;
  --accent-amber:  #ffaa00;
  --text-primary:  #c9d1d9;
  --text-dim:      #6e7f8f;
  --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
  --font-display: 'Space Mono', monospace;
}
```

Font imports (Google Fonts CDN):
- `JetBrains Mono` — body / data readouts
- `Space Mono` — panel headers and labels

### F1.3 — `useAegisSocket` Hook

`src/hooks/useAegisSocket.js` — shared, re-exported by every panel:
- Connects to `ws://localhost:8765/ws/metrics`
- Exposes `{ data, connected, error }`
- Auto-reconnects with exponential backoff (1s → 2s → 4s → max 30s)
- Parses incoming JSON frames and stores last N=300 frames in a ring buffer for charts

### F1.4 — Shell Layout (`src/components/Shell/`)

```
┌─────────────────────────────────────────────────────────────┐
│  AEGIS-TUNNEL X  ·  session: a3f2…b901  ·  uptime: 00:04:23 │  ← TopBar
├──────┬──────────────────────────────────────────────────────┤
│ NAV  │                                                      │
│ [●]  │                  ACTIVE PANEL                        │
│ Cryp │                                                      │
│ Trsp │                                                      │
│ Tunl │                                                      │
│ Mrph │                                                      │
│ Fbck │                                                      │
│ Conf │                                                      │
│ Demo │                                                      │
└──────┴──────────────────────────────────────────────────────┘
```

**TopBar** — always visible:
- Left: `AEGIS-TUNNEL X` wordmark
- Centre: session ID (truncated, copy-on-click), mode badge (`SERVER` / `CLIENT`), uptime counter
- Right: WebSocket connection dot (green=live, amber=reconnecting, red=dead), detection score badge (colour-coded)

**Sidebar** — 8 nav icons with labels. Active item highlighted with `--accent-green` left border. Each icon derived from `lucide-react`.

**StatusBar** — bottom 1-line strip: bytes TX/RX, packets TX/RX, latency, profile name.

### F1 Exit Criteria
- App renders with TopBar + Sidebar + StatusBar on `npm run dev`
- WebSocket dot goes green when `aegis/api.py` is running
- Navigation switches between panel placeholders

---

## Phase F2 — Crypto & Handshake Panel

**Covers backend Phase 2:** `aegis/crypto.py` — Kyber-768 + X25519 hybrid key exchange, AES-256-GCM.

### F2.1 — Layout

```
┌─────────────────────────────────────────────────────────────┐
│  ENCRYPTION ENGINE                                          │
├────────────────────────┬────────────────────────────────────┤
│  KEY EXCHANGE          │  SESSION CRYPTO                    │
│  ┌──────────────────┐  │  Algorithm:  AES-256-GCM           │
│  │ CLIENT  →  SERVER│  │  Key size:   256 bit               │
│  │  Kyber-768 KEM   │  │  Nonce:      Counter-XOR           │
│  │  X25519 ECDH     │  │  AAD:        session_id bound      │
│  │  HKDF-SHA256     │  │                                    │
│  └──────────────────┘  │  Nonce counter:  ████████ 4821     │
│  Status: ✓ COMPLETE    │                                    │
│  Time:   38 ms         │  FINGERPRINTS                      │
│                        │  Kyber pub:  ae3f…19c2             │
│                        │  X25519 pub: 7b2a…d401             │
└────────────────────────┴────────────────────────────────────┘
│  HANDSHAKE TIMELINE                                         │
│  CLIENT_HELLO ──────────────────────────────────> 0 ms     │
│               <────────────────────── SERVER_HELLO 22 ms   │
│  CLIENT_ACK  ──────────────────────────────────> 38 ms     │
└─────────────────────────────────────────────────────────────┘
```

### F2.2 — Components

**`KeyExchangeDiagram`** — SVG ladder diagram of the 3-step handshake. Each arrow animates in sequence (CSS `stroke-dashoffset` animation) once `handshake_done` flips `true`. Labels show: algorithm name, bytes exchanged, cumulative ms.

**`AlgoCard`** — shows algorithm name, key size, security level. Three cards: Kyber-768 KEM, X25519 ECDH, AES-256-GCM.

**`NonceCounter`** — live nonce counter (from `seq_counter` in WebSocket), displayed as hex with a progress bar filling towards `2^32` (shows nonce exhaustion distance).

**`FingerprintRow`** — first 4 and last 4 bytes of each public key in monospace, with a copy button.

### F2.3 — Data Source
- `GET /api/crypto` on mount — handshake timing, algorithm names, key fingerprints
- WebSocket `seq_counter` — live nonce counter

### F2 Exit Criteria
- Handshake ladder diagram animates correctly when tunnel is live
- Nonce counter increments in real time

---

## Phase F3 — Transport Layer Panel

**Covers backend Phase 3:** `aegis/transport.py` — UDP framing, sequence numbers, replay protection, keepalive.

### F3.1 — Layout

```
┌─────────────────────────────────────────────────────────────┐
│  UDP TRANSPORT                                              │
├───────────────────────┬─────────────────────────────────────┤
│  SESSION              │  PACKET FRAME INSPECTOR             │
│  ID:  a3f2…b901       │  Magic:    0xAE91  ✓               │
│  Seq: 4821            │  Version:  0x01    ✓               │
│  Remote: 127.0.0.1:   │  Type:     DATA (0x03)             │
│          5555         │  Flags:    DATA                     │
│                       │  Session:  a3f2…b901               │
│  REPLAY WINDOW        │  Seq:      4821                    │
│  [■■■■■■■■░░] 54/64   │  Length:   1400 B                  │
│                       │                                    │
├───────────────────────┴─────────────────────────────────────┤
│  KEEPALIVE TIMER                                            │
│  Next KA in: ████████████████░░░░░░░░  18.4 s / 25 s       │
│  Missed: 0 / 3                                             │
└─────────────────────────────────────────────────────────────┘
```

### F3.2 — Components

**`ReplayWindowBar`** — a 64-slot bit-array visualised as small coloured squares. Green = seen, black = empty slot. Shows how full the replay protection window is.

**`PacketFrameInspector`** — renders the last received packet frame header decoded field-by-field (matching the Phase 3 wire format). Each field labelled, hex value shown, validity icon (✓/✗).

**`KeepaliveTimer`** — countdown bar, resets to 25 s each time a keepalive is sent. Turns amber below 5 s. Shows missed-keepalive count.

**`SeqCounter`** — large monospace number, flashes briefly on increment.

### F3.3 — Data Source
- WebSocket `seq_counter` — live
- `GET /api/transport` — replay window fill level, remote addr, keepalive state

### F3 Exit Criteria
- Replay window updates as traffic flows
- Keepalive timer resets visibly every ~25 s

---

## Phase F4 — Tunnel & Packet Flow Panel

**Covers backend Phase 4:** `aegis/tunnel.py` — TUN ↔ UDP bidirectional glue, fragmentation/reassembly, packet stats.

### F4.1 — Layout

```
┌─────────────────────────────────────────────────────────────┐
│  TUNNEL INTERFACE                                           │
├──────────────────────────┬──────────────────────────────────┤
│  TUN DEVICE              │  LIVE PACKET FLOW               │
│  Name:   aegis_cli       │                                 │
│  IP:     10.10.0.2       │  APP ──encrypt──► UDP ──► PEER  │
│  Peer:   10.10.0.1       │  APP ◄─decrypt── UDP ◄── PEER  │
│  MTU:    1400 B          │                                 │
│  State:  ● UP            │  TX: ████████░░  2.3 MB         │
│                          │  RX: ██████░░░░  2.1 MB         │
├──────────────────────────┴──────────────────────────────────┤
│  THROUGHPUT (last 60 s)                                     │
│  [Area chart — TX kB/s in green, RX kB/s in cyan]          │
├─────────────────────────────────────────────────────────────┤
│  LATENCY (last 60 s)                                        │
│  [Line chart — avg_latency_ms, rolling 10-pkt average]      │
└─────────────────────────────────────────────────────────────┘
│  Pkts TX: 1204    Pkts RX: 1198    Avg RTT: 4.2 ms         │
└─────────────────────────────────────────────────────────────┘
```

### F4.2 — Components

**`TunDeviceCard`** — static info (name, IP, peer IP, MTU) from `/api/tunnel`. State badge (`UP` / `DOWN`) with a green pulse animation when `UP`.

**`PacketFlowDiagram`** — simple SVG: APP box → encrypt label → UDP box → PEER box, with animated particle dots travelling along the arrows proportional to TX/RX rate.

**`ThroughputChart`** — Recharts `AreaChart` with two series (TX, RX) drawn from the 300-frame ring buffer. X-axis = last 60 seconds. Fills are semi-transparent green / cyan.

**`LatencyChart`** — Recharts `LineChart`, `avg_latency_ms` over time. Reference line at 10 ms. Turns red if latency spikes above 50 ms.

**`StatsFooter`** — four monospace readouts: pkts TX, pkts RX, bytes TX, bytes RX (human-formatted: `2.3 MB`).

### F4.3 — Data Source
- WebSocket frames — `bytes_tx`, `bytes_rx`, `pkts_tx`, `pkts_rx`, `latency_ms`
- `GET /api/tunnel` on mount — TUN device metadata

### F4 Exit Criteria
- Throughput chart scrolls in real time during demo traffic
- Latency chart shows sub-10 ms on loopback

---

## Phase F5 — Morphic Engine Control Panel

**Covers backend Phase 5:** `aegis/morphic.py` + `profiles/*.json` — traffic obfuscation, padding, jitter, burst scheduling, hot-swap profiles.

### F5.1 — Layout

```
┌─────────────────────────────────────────────────────────────┐
│  MORPHIC ENGINE                         Profile: web_browsing│
├────────────────────────────────┬────────────────────────────┤
│  PROFILE SWITCHER              │  ACTIVE PARAMETERS         │
│  ○ web_browsing    ← active    │  Size dist:  bimodal       │
│  ○ video_streaming             │  Peaks:      64 / 1400 B   │
│  ○ gaming                      │  IPD type:   pareto        │
│                                │  α = 1.2  min=0.5ms        │
│  [SWITCH] ← hot-swap button    │  Burst size: 3–15 pkts     │
│                                │  Pause:      50–300 ms     │
├────────────────────────────────┴────────────────────────────┤
│  PACKET SIZE DISTRIBUTION (live, last 500 packets)          │
│  [Bar chart: observed vs target distribution overlay]        │
├─────────────────────────────────────────────────────────────┤
│  INTER-PACKET DELAY HISTOGRAM (live, last 500 packets)      │
│  [Bar chart: log-scale X, observed IPDs in ms]              │
└─────────────────────────────────────────────────────────────┘
```

### F5.2 — Components

**`ProfileSwitcher`** — three radio-style cards (one per profile). Selecting a different profile and clicking `SWITCH` calls `POST /api/profile/{name}`. During the switch, the card shows a brief `SWITCHING…` animation. After success, the active badge moves.

**`ProfileParamsCard`** — displays the JSON profile fields parsed into human-readable labels. Updates when active profile changes.

**`SizeDistributionChart`** — Recharts `BarChart`. Two bar series:
- **Observed**: bucket counts of actual packet sizes from last 500 packets (from WebSocket ring buffer)
- **Target**: expected distribution derived from active profile params  
Visually shows how well the morphic engine is hitting its target. Bars are grouped side-by-side.

**`IPDHistogramChart`** — Recharts `BarChart` of observed inter-packet delays in log-spaced bins (0.5–500 ms). Reference line shows profile's expected median.

**`BurstIndicator`** — small animated squares that light up when a burst fires, dims during inter-burst pause. Gives an at-a-glance sense of burstiness.

### F5.3 — Data Source
- `GET /api/morphic` — active profile name + params
- WebSocket ring buffer — derive size/IPD histograms client-side from consecutive frames
- `POST /api/profile/{name}` — profile switch action

### F5 Exit Criteria
- Profile switch reflected in params card within 1 s
- Size distribution chart shows bimodal peaks for `web_browsing`, flat for `video_streaming`

---

## Phase F6 — Detection Feedback Dashboard

**Covers backend Phase 6:** `aegis/feedback.py` — `TrafficAnalyzer` + `FeedbackLoop`, the 5-metric composite detection score.

### F6.1 — Layout

```
┌─────────────────────────────────────────────────────────────┐
│  DETECTION FEEDBACK LOOP                                    │
├──────────────────┬──────────────────────────────────────────┤
│  DETECTION SCORE │  METRIC BREAKDOWN                        │
│                  │                                          │
│      0.12        │  Entropy       7.94  ████████░░  ✓      │
│   ████████░░░░   │  IPD-CV        0.81  ███████░░░  ✓      │
│      GOOD        │  Size χ² p     0.43  ████░░░░░░  ✓      │
│                  │  Burstiness    1.12  █████████░  ✓      │
│  Threshold: 0.25 │  Periodicity   0.09  █░░░░░░░░░  ✓      │
│  Adaptations: 3  │                                          │
├──────────────────┴──────────────────────────────────────────┤
│  SCORE HISTORY (last 100 checks, 2 s interval = ~3.3 min)  │
│  [Line chart — score over time, 0.25 threshold red line]   │
├─────────────────────────────────────────────────────────────┤
│  ADAPTATION LOG                                             │
│  [00:02:14]  score=0.31  action: widen jitter range        │
│  [00:01:52]  score=0.28  action: nudge size peaks -5%      │
│  [00:01:10]  score=0.19  action: none                      │
└─────────────────────────────────────────────────────────────┘
```

### F6.2 — Components

**`DetectionScoreGauge`** — large central readout. Colour-coded by threshold:
- `< 0.15` → `--accent-green` — **GOOD**
- `0.15–0.25` → `--accent-amber` — **WATCH**
- `> 0.25` → `--accent-red` — **ADAPTING**

A semi-circular SVG arc gauge fills proportionally. Pulses red when the feedback loop fires an adaptation.

**`MetricRow`** — one row per metric. Shows: metric name, raw value, a mini progress bar colour-coded to deviation from target, and a ✓/✗ icon.

**`ScoreHistoryChart`** — Recharts `LineChart` of `detection_score` over last 100 feedback cycles. A red dashed `ReferenceLine` at `y=0.25`. When score crosses above the line, the chart area above it fills red.

**`AdaptationLog`** — scrollable monospace log of `feedback.history` entries. Each entry shows timestamp, score, and the action string. Newest at top. New entries flash briefly on arrival.

### F6.3 — Data Source
- WebSocket `detection_score` + `metrics` — live
- `GET /api/feedback` on mount — full history + all metric values

### F6 Exit Criteria
- Score gauge animates between green → amber → red during demo
- History chart shows convergence below 0.25 after ~20 s (matches Phase 6 exit criterion)
- Adaptation log populates when `_adapt()` fires

---

## Phase F7 — Configuration & Key Management Panel

**Covers backend Phase 7:** `aegis/cli.py` + `aegis/config.py` — config schema, `aegis keygen`, CLI commands.

### F7.1 — Layout

```
┌─────────────────────────────────────────────────────────────┐
│  CONFIGURATION & KEYS                                       │
├──────────────────────────┬──────────────────────────────────┤
│  ACTIVE CONFIG           │  KEY MANAGEMENT                 │
│  Mode:    CLIENT         │  Key dir: .\demo\keys\client    │
│  Connect: 127.0.0.1:5555 │                                 │
│  TUN IP:  10.10.0.2      │  kyber_priv.bin   ████ (exists) │
│  Peer IP: 10.10.0.1      │  kyber_pub.bin    ████ (exists) │
│  MTU:     1400           │  x25519_priv.bin  ████ (exists) │
│  Profile: web_browsing   │  x25519_pub.bin   ████ (exists) │
│  Feedback: enabled       │                                 │
│  Threshold: 0.25         │  [REGENERATE KEYS]              │
│  Log: .\demo\client.log  │                                 │
├──────────────────────────┴──────────────────────────────────┘
│  RAW CONFIG (YAML, read-only)                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  mode: client                                        │  │
│  │  connect:                                            │  │
│  │    host: 127.0.0.1                                   │  │
│  │    port: 5555                                        │  │
│  │  ...                                                 │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### F7.2 — Components

**`ConfigSummaryCard`** — structured display of parsed config fields. All values are read-only. Sensitive fields (key paths) shown with a folder icon.

**`KeyFileStatusGrid`** — shows the 4 expected key files for the active role. Each cell: filename, existence indicator (green fill = present, red = missing), file size if present. `REGENERATE KEYS` button calls `POST /api/keygen` which shells out to `aegis keygen`.

**`RawConfigViewer`** — syntax-highlighted YAML in a scrollable monospace box. Uses CSS `color` rules to highlight keys/values. Secrets (`key_dir` contents) shown as `[REDACTED]`.

**`LogLevelBadge`** — shows current log level (`INFO`, `DEBUG`) with colour badge; links to log file path.

### F7.3 — Data Source
- `GET /api/config` — full parsed config + key file status
- `POST /api/keygen` — triggers key generation

### F7 Exit Criteria
- Config card reflects correct mode (SERVER vs CLIENT) based on what tunnel is running
- Key regeneration shows new fingerprints in F2 Crypto panel immediately

---

## Phase F8 — Demo Control Center

**Covers backend Phase 8:** `demo/run_demo.ps1` + `tests/test_e2e.py` — one-command demo, E2E tests.

### F8.1 — Layout

```
┌─────────────────────────────────────────────────────────────┐
│  DEMO CONTROL CENTER                                        │
├──────────────────────────────────┬──────────────────────────┤
│  DEMO SEQUENCE                   │  E2E TEST RUNNER         │
│                                  │                          │
│  ① Key generation    ✓ done      │  E2E-1  Handshake  ✓    │
│  ② Start server      ✓ done      │  E2E-2  10MB xfer  ✓    │
│  ③ Start client      ✓ done      │  E2E-3  Score<0.3  ✓    │
│  ④ Await handshake   ✓ done      │  E2E-4  Hot-swap   ✓    │
│  ⑤ Send test traffic ● active    │  E2E-5  Reconnect  …    │
│  ⑥ Bulk 10MB xfer    ○ pending   │  E2E-6  Replay     ○    │
│  ⑦ Switch profile    ○ pending   │                          │
│  ⑧ Print status      ○ pending   │  [RUN ALL TESTS]         │
│                                  │                          │
│  [▶ START DEMO]  [■ STOP]        │  Results: 4/6 passed     │
└──────────────────────────────────┴──────────────────────────┘
│  DEMO OUTPUT (live stdout from run_demo.ps1)                │
│  > Waiting for tunnel handshake...                          │
│  > Sending test traffic...                                  │
│  > ...                                                      │
└─────────────────────────────────────────────────────────────┘
```

### F8.2 — Components

**`DemoSequenceList`** — 8-step checklist mirroring `run_demo.ps1`. States: `○ pending`, `● active` (pulsing dot), `✓ done`, `✗ failed`. Steps are driven by SSE events from `/api/demo/status`.

**`DemoControls`** — `START DEMO` button (calls `POST /api/demo/start`), `STOP` button (calls `POST /api/demo/stop`). Start button disabled while demo is running. During run, button label shows `RUNNING…` with a spinner.

**`E2ETestRunner`** — 6 test rows (E2E-1 through E2E-6). Each row: test name, short description, status badge. `RUN ALL TESTS` button calls `POST /api/demo/run_tests`. Results stream in via WebSocket. Pass = green ✓, Fail = red ✗, Running = amber spinner.

**`DemoOutputTerminal`** — scrollable monospace terminal box streaming live stdout from the demo subprocess. Auto-scrolls to bottom. Max 500 lines retained. Lines prefixed with `>` in dim green.

### F8.3 — `demo/run_demo_with_ui.ps1`

Updated demo script that additionally starts the FastAPI bridge and opens the browser:

```powershell
#Requires -RunAsAdministrator
# Start API bridge
$api = Start-Process python -ArgumentList "-m uvicorn aegis.api:app --host 127.0.0.1 --port 8765" -PassThru -NoNewWindow
Start-Sleep -Seconds 2
# Open browser
Start-Process "http://localhost:5173"
# Run original demo steps via API-driven sequence
# (original run_demo.ps1 steps are now callable via POST /api/demo/start)
```

### F8 Exit Criteria
- Clicking `START DEMO` drives all 8 steps to ✓ done
- All 6 E2E tests show ✓ in the runner
- Demo terminal shows live PowerShell output

---

## Frontend Phase Summary

| Phase | Panel | Backend Coverage | Key Visuals |
|-------|-------|-----------------|-------------|
| F0 | API Bridge | All phases | FastAPI + WebSocket |
| F1 | Shell | Global | TopBar, sidebar nav, status bar |
| F2 | Crypto | Phase 2 | Handshake ladder, nonce counter |
| F3 | Transport | Phase 3 | Replay window, frame inspector, KA timer |
| F4 | Tunnel | Phase 4 | Throughput + latency charts, flow diagram |
| F5 | Morphic | Phase 5 | Profile switcher, size/IPD histograms |
| F6 | Feedback | Phase 6 | Score gauge, 5-metric rows, history chart |
| F7 | Config | Phase 7 | Config card, key file grid, YAML viewer |
| F8 | Demo Center | Phase 8 | Step checklist, E2E runner, live terminal |

**Implement phases in order: F0 → F1 → F4 → F6 → F5 → F2 → F3 → F7 → F8.**  
(F4 and F6 are the most demo-impactful panels; build them early.)

---

## Global Frontend Constraints

1. **No mock data in production mode.** If the WebSocket is disconnected, panels show a `⚠ TUNNEL NOT RUNNING` overlay rather than fake values.
2. **All charts use the 300-frame ring buffer** from `useAegisSocket` — no separate fetch on each render.
3. **Secrets never rendered in full** — key file contents, nonce bytes, session IDs are always truncated to first 4 + last 4 bytes with `…` in the middle.
4. **Profile switch is the only write action in F2–F7.** All other panels are read-only.
5. **No external CDN dependencies** — all packages installed via npm. Works offline after `npm install`.
6. **Accessible colour contrast** — all text meets WCAG AA against `--bg-panel`. Colour alone is never the only indicator of state (always paired with a label or icon).
7. **Responsive down to 1280 × 800** — minimum resolution for demo laptop. No horizontal scroll.
