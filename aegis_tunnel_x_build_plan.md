# Aegis-Tunnel X — Phase-by-Phase Build Plan

> **Stack:** Python 3.11+ · `liboqs-python` (CRYSTALS-Kyber) · `cryptography` (AES-256-GCM) · WinTUN (`ctypes`) · `asyncio` UDP · Rich (terminal UI)  
> **Platform:** Windows 10/11 — Administrator required for TUN interface (WinTUN via `wintun.dll`)  
> **Repo layout is established in Phase 1 and never restructured.**

---

## Repository Layout (established in Phase 1)

```
aegis-tunnel-x/
├── aegis/
│   ├── __init__.py
│   ├── tun.py              # Phase 1 — platform dispatcher
│   ├── _tun_windows.py     # Phase 1 — WinTUN ctypes adapter
│   ├── _tun_linux.py       # Phase 1 — Linux /dev/net/tun adapter
│   ├── crypto.py           # Phase 2 — AES-256-GCM + Kyber
│   ├── transport.py        # Phase 3 — UDP framing & sessions
│   ├── tunnel.py           # Phase 4 — TUN ↔ UDP glue
│   ├── morphic.py          # Phase 5 — morphic engine
│   ├── feedback.py         # Phase 6 — detection feedback loop
│   ├── cli.py              # Phase 7 — CLI entry point
│   └── config.py           # Phase 7 — config loader
├── tests/
│   ├── test_tun.py
│   ├── test_crypto.py
│   ├── test_transport.py
│   ├── test_tunnel.py
│   ├── test_morphic.py
│   ├── test_feedback.py
│   └── test_e2e.py
├── profiles/               # Phase 5 — traffic profiles (JSON)
│   ├── web_browsing.json
│   ├── video_streaming.json
│   └── gaming.json
├── demo/
│   ├── run_demo.ps1        # Phase 8 — PowerShell demo script
│   ├── server.conf
│   └── client.conf
├── wintun.dll              # WinTUN driver (required on Windows)
├── requirements.txt
├── setup.py
└── README.md
```

---

## Phase 1 — Project Scaffold & TUN Interface ✅ COMPLETED

**Goal:** Bootable project; virtual network interface that captures and injects raw IP packets.  
**Status:** ✅ Completed using WinTUN via `ctypes` on Windows.

### 1.1 — Dependency Setup

**`requirements.txt`**
```
cryptography>=42.0
liboqs-python>=0.10.0
pyyaml>=6.0
rich>=13.0
pytest
pytest-asyncio>=0.23
```

**Install commands the agent must run (PowerShell as Administrator):**
```powershell
pip install -r requirements.txt
```

**Prerequisites:**
- `wintun.dll` must be in the project root (download from https://www.wintun.net)
- Terminal must run as **Administrator**
- `liboqs` must be installed via `pip install liboqs-python` (ships pre-built wheels for Windows)

### 1.2 — TUN Interface Module (`aegis/tun.py`)

Implement the `TunInterface` class with:

```python
class TunInterface:
    def __init__(self, name: str = "aegis0", mtu: int = 1500)
    def open(self) -> None          # Creates TUN device, sets IP/netmask, brings it UP
    def close(self) -> None
    def read_packet(self) -> bytes  # Blocking read of one IP packet from TUN
    def write_packet(self, data: bytes) -> None  # Inject packet into TUN
    def set_address(self, ip: str, peer_ip: str, netmask: str = "255.255.255.0") -> None
```

**Implementation notes (Windows / WinTUN):**
- Load `wintun.dll` via `ctypes.WinDLL` and configure all API function signatures
- Create adapter with `WintunCreateAdapter`, start session with `WintunStartSession`
- Use `WintunReceivePacket` / `WintunAllocateSendPacket` + `WintunSendPacket` for I/O
- Use `WintunGetReadWaitEvent` + `WaitForSingleObject` for blocking reads
- Configure IP via `netsh interface ip set address` and MTU via `netsh interface ipv4 set subinterface`
- WinTUN delivers raw IP frames directly (no TUN header to strip)

### 1.3 — Phase 1 Tests (`tests/test_tun.py`)

```
Test 1-A: TUN device opens without error (requires Administrator; skip if not admin)
Test 1-B: Write a crafted IP packet → read it back via socket bound to TUN IP
Test 1-C: MTU is correctly set (read via netsh interface ipv4 show subinterfaces)
Test 1-D: close() tears down cleanly; adapter is removed
```

### Phase 1 Exit Criteria
- `pytest tests/test_tun.py` passes (Administrator PowerShell)
- Manual: `netsh interface ip show addresses name=aegis0` shows correct IP after `TunInterface.open()`

---

## Phase 2 — Encryption Engine

**Goal:** Hybrid post-quantum key exchange (Kyber-768 + X25519) and per-packet AES-256-GCM AEAD encryption.

### 2.1 — Key Exchange Design

```
Handshake (one-time, per session):
  Server generates: Kyber-768 keypair + X25519 keypair
  Server → Client: kyber_pub, x25519_pub

  Client generates: Kyber-768 ciphertext (encapsulate) + X25519 keypair
  Client → Server: kyber_ciphertext, client_x25519_pub
  Client derives:   kyber_shared_secret XOR x25519_shared_secret → master_key

  Server decapsulates kyber_ciphertext → kyber_shared_secret
  Server computes x25519 DH → x25519_shared_secret
  Server derives:   same master_key

  Both sides: master_key → HKDF-SHA256 → (aes_key 32B, nonce_base 12B)
```

### 2.2 — Crypto Module (`aegis/crypto.py`)

```python
class KyberKeyPair:
    def __init__(self): ...           # generates Kyber-768 keypair via liboqs
    public_key: bytes
    def decapsulate(self, ciphertext: bytes) -> bytes  # → shared_secret

def kyber_encapsulate(server_public_key: bytes) -> tuple[bytes, bytes]:
    # returns (ciphertext, shared_secret)

class SessionCrypto:
    def __init__(self, master_key: bytes): ...
    # Derives aes_key and per-message nonces via HKDF + counter

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        # Returns: nonce(12B) || ciphertext || tag(16B)

    def decrypt(self, ciphertext_blob: bytes, aad: bytes = b"") -> bytes:
        # Raises InvalidTag on tamper; strips nonce prefix

    def derive_session_keys(
        master_key: bytes,
        salt: bytes,
        info: bytes = b"aegis-tunnel-x-v1"
    ) -> tuple[bytes, bytes]:   # (aes_key, nonce_base)
```

**Implementation notes:**
- Use `oqs.KeyEncapsulation("Kyber768")` for PQ operations (`liboqs-python` ships pre-built Windows wheels)
- Use `cryptography.hazmat.primitives.ciphers.aead.AESGCM` for AES-256-GCM
- Use `cryptography.hazmat.primitives.asymmetric.x25519` for X25519 DH
- Nonces: `nonce_base XOR counter.to_bytes(12, 'big')` — never reuse
- AAD must include session_id to prevent cross-session replay
- Use `hmac.compare_digest` for constant-time secret comparison (never `==`)

### 2.3 — Phase 2 Tests (`tests/test_crypto.py`)

```
Test 2-A: Kyber keypair generates; encapsulate + decapsulate → same shared secret
Test 2-B: SessionCrypto.encrypt → SessionCrypto.decrypt roundtrip (256 random payloads)
Test 2-C: Bit-flip in ciphertext raises cryptography.exceptions.InvalidTag
Test 2-D: Nonce counter increments per call; two encryptions of identical plaintext produce different ciphertexts
Test 2-E: Full hybrid handshake simulation → both sides derive identical master_key
Test 2-F: AAD mismatch raises InvalidTag
```

### Phase 2 Exit Criteria
- `pytest tests/test_crypto.py -v` — all 6 tests pass
- Encrypt 1 MB of data; measure throughput (must be > 50 MB/s on modern hardware)

---

## Phase 3 — UDP Transport Layer

**Goal:** Reliable-ish, framed UDP session with handshake, sequence numbers, and packet loss detection.

### 3.1 — Packet Frame Format

```
 0               1               2               3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Magic(2B)  |  Version(1B)  |   Flags (1B)  |  Type  (1B)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Session ID (8B)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Sequence Number (4B)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Payload Length (2B)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Encrypted Payload (variable)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Magic:   0xAE91 (Aegis magic bytes)
Version: 0x01
Flags:   bit0=HANDSHAKE, bit1=DATA, bit2=KEEPALIVE, bit3=FIN
Type:    0x01=CLIENT_HELLO, 0x02=SERVER_HELLO, 0x03=DATA, 0x04=KEEPALIVE
```

### 3.2 — Transport Module (`aegis/transport.py`)

```python
class UDPSession:
    session_id: bytes           # 8 random bytes
    remote_addr: tuple
    crypto: SessionCrypto
    seq_counter: int
    recv_window: deque          # last 64 seq numbers seen (replay protection)

class AegisTunnelServer:
    def __init__(self, host: str, port: int, private_key: KyberKeyPair)
    async def start(self) -> None
    async def stop(self) -> None
    # Emits received plaintext packets via asyncio.Queue → tunnel.py consumes

class AegisTunnelClient:
    def __init__(self, server_host: str, server_port: int)
    async def connect(self) -> None          # performs handshake
    async def send_packet(self, data: bytes) -> None
    async def receive_packet(self) -> bytes
    async def disconnect(self) -> None
```

**Implementation notes:**
- Use `asyncio.DatagramProtocol` / `asyncio.DatagramTransport` (works natively on Windows)
- On Windows, `asyncio` uses `ProactorEventLoop` by default in Python 3.11+; UDP sockets work via `loop.create_datagram_endpoint()`
- Handshake is 3-way: CLIENT_HELLO (kyber_ciphertext + x25519_pub) → SERVER_HELLO (kyber_pub + x25519_pub + session_id) → CLIENT_ACK
- Keepalive: send every 25 seconds; disconnect after 3 missed keepalives
- Replay protection: reject packets with seq numbers already in recv_window

### 3.3 — Phase 3 Tests (`tests/test_transport.py`)

```
Test 3-A: Server and client complete 3-way handshake on localhost
Test 3-B: Client sends 100 framed packets; server receives all 100 in order
Test 3-C: Replayed packet (duplicate seq number) is silently dropped
Test 3-D: Tampered payload raises InvalidTag; connection stays alive
Test 3-E: Keepalive fires at ~25s intervals (mock time)
Test 3-F: Packet frame encode → decode roundtrip preserves all header fields
```

### Phase 3 Exit Criteria
- `pytest tests/test_transport.py -v` — all 6 tests pass
- `netstat -a -p UDP` shows UDP socket listening during test

---

## Phase 4 — Tunnel Integration (TUN ↔ UDP)

**Goal:** Full bidirectional IP packet tunnel — packets from TUN get encrypted and sent over UDP; received UDP packets get decrypted and injected into TUN.

### 4.1 — Tunnel Module (`aegis/tunnel.py`)

```python
class AegisTunnel:
    def __init__(
        self,
        tun: TunInterface,
        transport: AegisTunnelServer | AegisTunnelClient,
        morphic: MorphicEngine = None,   # injected in Phase 5; None = passthrough
        feedback: FeedbackLoop = None,   # injected in Phase 6; None = passthrough
    )

    async def run(self) -> None:
        # Runs two concurrent coroutines:
        #   _tun_to_udp(): read TUN → (morphic.transform if set) → transport.send
        #   _udp_to_tun(): transport.receive → (morphic.detransform if set) → write TUN

    async def stop(self) -> None

    # Metrics exposed for feedback loop:
    @property
    def packet_stats(self) -> dict:
        # returns {sent_count, recv_count, bytes_sent, bytes_recv, avg_latency_ms}
```

**Implementation notes:**
- `_tun_to_udp` and `_udp_to_tun` run as `asyncio.create_task()`
- TUN reads are blocking (WinTUN `WaitForSingleObject`); wrap in `loop.run_in_executor(None, tun.read_packet)` to avoid blocking the event loop
- TUN writes are also wrapped in executor: `loop.run_in_executor(None, tun.write_packet, data)`
- Fragment IP packets larger than (MTU - header_overhead) before encrypting
- Reassemble fragments before TUN inject (use IP ID + frag_offset)
- Log every packet at DEBUG level: direction, size, seq_num

### 4.2 — Phase 4 Tests (`tests/test_tunnel.py`)

```
Test 4-A: Spawn server + client tunnel on loopback; ping client-side TUN IP from server-side TUN → ICMP reply received (requires root)
Test 4-B: Send 1 MB of data through tunnel; all bytes received correctly (SHA-256 both ends match)
Test 4-C: Large packet (> MTU) is fragmented and correctly reassembled
Test 4-D: tunnel.stop() cleanly cancels all tasks; no asyncio warnings
Test 4-E: packet_stats correctly reflects sent/received byte counts
```

### Phase 4 Exit Criteria
- `pytest tests/test_tunnel.py -v` — all 5 tests pass
- Manual demo: `Invoke-WebRequest http://10.10.0.2/` through the tunnel returns a response
- Note: TUN tests require Administrator PowerShell; use `pytest.mark.skipif` for non-admin environments

---

## Phase 5 — Morphic Engine

**Goal:** Continuously transform outgoing packets to statistically mimic real traffic profiles, defeating DPI and traffic fingerprinting.

### 5.1 — Traffic Profiles (`profiles/*.json`)

Each profile defines:
```json
{
  "name": "web_browsing",
  "packet_size_distribution": {
    "type": "bimodal",
    "peaks": [64, 1400],
    "weights": [0.3, 0.7],
    "std_dev": [20, 100]
  },
  "inter_packet_delay_ms": {
    "type": "pareto",
    "alpha": 1.2,
    "min_ms": 0.5,
    "max_ms": 500
  },
  "burst_profile": {
    "burst_size_range": [3, 15],
    "burst_pause_ms_range": [50, 300]
  }
}
```

Provide three profiles: `web_browsing.json`, `video_streaming.json`, `gaming.json`.

### 5.2 — Morphic Engine Module (`aegis/morphic.py`)

```python
class MorphicEngine:
    def __init__(self, profile_name: str = "web_browsing", max_queue_ms: int = 50)

    def load_profile(self, profile_name: str) -> None
    def switch_profile(self, profile_name: str) -> None  # hot-swap; thread-safe

    async def transform(self, packet: bytes) -> list[bytes]:
        # Applies:
        # 1. Padding: pad packet to next target_size drawn from profile distribution
        # 2. Fragmentation: split if padded size > morphic_mtu
        # 3. Jitter: await asyncio.sleep(delay drawn from profile IPD distribution)
        # Returns list of transformed frames (may be 1 or multiple)

    def detransform(self, frame: bytes) -> bytes | None:
        # Strip padding (reads original_length header prepended during transform)
        # Returns original plaintext or None if frame is a padding-only dummy

    async def run_burst_scheduler(self, packet_queue: asyncio.Queue) -> None:
        # Groups packets into bursts per profile; emits them with inter-burst pauses

    @property
    def current_profile(self) -> dict
```

**Implementation notes:**
- Prepend a 2-byte `original_length` field BEFORE encryption (inside plaintext) so detransform knows how much to strip
- Padding bytes must be cryptographically random (use `os.urandom`)
- Jitter is additive, not replacing the natural send time
- `burst_scheduler` accumulates packets in a window then sends as a burst
- Profile switch must not drop in-flight packets

### 5.3 — Phase 5 Tests (`tests/test_morphic.py`)

```
Test 5-A: transform(b"hello") → frame where len(frame) matches profile size distribution (run 1000 samples; Kolmogorov-Smirnov test against expected distribution, p > 0.05)
Test 5-B: detransform(transform(payload)[0]) == payload for all payload sizes 1..1400
Test 5-C: IPD samples from transform calls match profile inter-packet delay distribution (1000 samples, KS test)
Test 5-D: switch_profile("video_streaming") mid-run; next 100 packets use new distribution
Test 5-E: Padding bytes are random (chi-squared uniformity test on byte values)
Test 5-F: Large packet → multiple fragments → all detransform back to original when reassembled
```

### Phase 5 Exit Criteria
- `pytest tests/test_morphic.py -v` — all 6 tests pass
- Wireshark capture of morphic-transformed traffic: packet size histogram visually matches web_browsing profile

---

## Phase 6 — Detection Feedback Loop

**Goal:** Continuously measure the statistical detectability of outgoing traffic and automatically tune morphic parameters to minimize the detection probability score.

### 6.1 — Detectability Metrics

The feedback engine computes these metrics on a rolling window of the last N=200 packets:

| Metric | Method | Target |
|--------|--------|--------|
| Shannon entropy of payload bytes | `H = -Σ p_i log2(p_i)` | > 7.5 bits (high entropy = looks encrypted = bad; but tunnel traffic should look like TLS which is also high entropy, so we compare against reference profile entropy) |
| Inter-packet delay variance | Coefficient of variation | Match profile CV ± 0.15 |
| Packet size chi-squared | χ² vs profile distribution | p-value > 0.10 |
| Burstiness index | Fano factor of packet counts per 100ms bin | Match profile ± 20% |
| Periodic pattern score | Autocorrelation of IPDs at lag 1..10 | < 0.15 (no strong periodicity) |

**Composite detection probability score (0.0–1.0):**
```
score = weighted_average(normalized_metric_deviations)
# 0.0 = perfectly mimicking profile; 1.0 = trivially detectable
```

### 6.2 — Feedback Module (`aegis/feedback.py`)

```python
class TrafficAnalyzer:
    def __init__(self, window_size: int = 200)
    def record_packet(self, size: int, timestamp_ns: int, payload_sample: bytes) -> None
    def compute_entropy(self) -> float
    def compute_ipd_cv(self) -> float
    def compute_size_chi2(self, reference_profile: dict) -> float   # returns p-value
    def compute_burstiness(self) -> float
    def compute_periodicity_score(self) -> float
    def detection_score(self, reference_profile: dict) -> float     # 0.0–1.0

class FeedbackLoop:
    def __init__(
        self,
        analyzer: TrafficAnalyzer,
        morphic: MorphicEngine,
        check_interval_s: float = 2.0,
        score_threshold: float = 0.25,  # trigger adaptation above this
    )

    async def run(self) -> None:
        # Every check_interval_s:
        #   1. Get detection_score from analyzer
        #   2. If score > score_threshold: call _adapt()
        #   3. Log score + action taken

    def _adapt(self, score: float, metrics: dict) -> None:
        # Strategy:
        #   if entropy_deviation high: increase padding randomness
        #   if IPD_cv mismatch: widen jitter range
        #   if size_chi2 fails: nudge size distribution peaks ±5%
        #   if periodicity_score high: add random dummy packets
        # Applies changes via morphic.update_params(delta_dict)

    @property
    def history(self) -> list[dict]:   # last 100 {timestamp, score, action} records
```

### 6.3 — Phase 6 Tests (`tests/test_feedback.py`)

```
Test 6-A: TrafficAnalyzer.compute_entropy returns 7.99 ± 0.01 for uniform random bytes
Test 6-B: compute_size_chi2 returns p > 0.5 when fed packets sampled from the exact reference profile
Test 6-C: compute_size_chi2 returns p < 0.01 for obviously wrong distribution (all 100-byte packets vs bimodal profile)
Test 6-D: FeedbackLoop._adapt is triggered when detection_score > threshold (mock morphic; verify update_params called)
Test 6-E: After 3 adaptation cycles fed with periodic traffic, periodicity_score decreases (convergence test)
Test 6-F: history log correctly records each check cycle's score and action string
```

### Phase 6 Exit Criteria
- `pytest tests/test_feedback.py -v` — all 6 tests pass
- Run a 60-second simulated traffic stream; detection_score graph shows convergence below 0.25 within 20 seconds

---

## Phase 7 — CLI & Configuration

**Goal:** Production-grade CLI so the demo runs with a single command on each side.

### 7.1 — Config Schema (`aegis/config.py`)

```yaml
# server.conf / client.conf (YAML)
mode: server          # or client
listen:
  host: 0.0.0.0
  port: 5555
connect:              # client only
  host: 192.168.1.10
  port: 5555
tun:
  name: aegis0
  ip: 10.10.0.1       # server: .1, client: .2
  peer_ip: 10.10.0.2
  mtu: 1400
crypto:
  key_dir: ~\.aegis\keys     # Windows user profile path
morphic:
  profile: web_browsing
  max_queue_ms: 50
feedback:
  enabled: true
  check_interval_s: 2.0
  score_threshold: 0.25
logging:
  level: INFO
  file: ~\.aegis\aegis.log   # Windows-friendly log path
```

**Implementation notes:**
- Config paths use `pathlib.Path.home()` to resolve `~` cross-platform
- `key_dir` default is `%USERPROFILE%\.aegis\keys`
- Log directory is auto-created via `Path.mkdir(parents=True, exist_ok=True)`

### 7.2 — CLI Entry Point (`aegis/cli.py`)

```
aegis server --config server.conf
aegis client --config client.conf
aegis keygen --output ~\.aegis\keys   # generate Kyber + X25519 keypair, save to dir
aegis status                           # show live metrics (Rich live table)
aegis profile list                     # list available morphic profiles
aegis profile set <name>               # hot-swap morphic profile
```

**`aegis status` live dashboard (Rich):**
```
╔══════════════════ AEGIS-TUNNEL X ══════════════════╗
║  Session: a3f2...b901     Uptime: 00:04:23          ║
║  Detection Score: ░░░░░░░░░░ 0.12  [GOOD]           ║
║  Profile: web_browsing      Pkts TX/RX: 1204 / 1198 ║
║  Bytes TX: 2.3 MB           Bytes RX: 2.1 MB        ║
║  Avg Latency: 4.2 ms        PQ Handshake: ✓ Kyber768║
╚════════════════════════════════════════════════════╝
```

### 7.3 — Phase 7 Tests

```
Test 7-A: `aegis keygen` creates kyber_priv.bin, kyber_pub.bin, x25519_priv.bin, x25519_pub.bin in key_dir
Test 7-B: Config loader correctly parses both server.conf and client.conf; raises ValueError on missing required fields
Test 7-C: Config loader resolves `~` to `%USERPROFILE%` and creates key_dir if it doesn't exist
Test 7-D: `aegis server --config server.conf` starts without error; Ctrl-C triggers clean shutdown
Test 7-E: `aegis profile set video_streaming` while running changes morphic profile (integration test)
```

### Phase 7 Exit Criteria
- `pytest tests/test_cli.py -v` — all 5 tests pass
- `aegis status` renders correctly in a 120×30 Windows Terminal window

---

## Phase 8 — Demo Integration & End-to-End Test

**Goal:** One-command demo that shows the full system working on Windows, with a visible detection score graph and profile switching.

### 8.1 — Demo Setup (Native Windows, Two Processes)

Instead of Docker, the demo runs server and client as **two separate processes on the same Windows machine**, each with its own WinTUN adapter and config.

**`demo/server.conf`**
```yaml
mode: server
listen:
  host: 127.0.0.1
  port: 5555
tun:
  name: aegis_srv
  ip: 10.10.0.1
  peer_ip: 10.10.0.2
  mtu: 1400
crypto:
  key_dir: .\demo\keys\server
morphic:
  profile: web_browsing
feedback:
  enabled: true
logging:
  level: INFO
  file: .\demo\server.log
```

**`demo/client.conf`**
```yaml
mode: client
connect:
  host: 127.0.0.1
  port: 5555
tun:
  name: aegis_cli
  ip: 10.10.0.2
  peer_ip: 10.10.0.1
  mtu: 1400
crypto:
  key_dir: .\demo\keys\client
morphic:
  profile: web_browsing
feedback:
  enabled: true
logging:
  level: INFO
  file: .\demo\client.log
```

### 8.2 — Demo Script (`demo/run_demo.ps1`)

```powershell
#Requires -RunAsAdministrator
# Aegis-Tunnel X — Windows Native Demo

# 1. Generate keys for server and client
aegis keygen --output .\demo\keys\server
aegis keygen --output .\demo\keys\client
# Copy server public keys to client dir and vice versa
Copy-Item .\demo\keys\server\kyber_pub.bin  .\demo\keys\client\server_kyber_pub.bin
Copy-Item .\demo\keys\server\x25519_pub.bin .\demo\keys\client\server_x25519_pub.bin

# 2. Start server in background
$server = Start-Process python -ArgumentList "-m aegis server --config .\demo\server.conf" -PassThru -NoNewWindow
Start-Sleep -Seconds 2

# 3. Start client in background
$client = Start-Process python -ArgumentList "-m aegis client --config .\demo\client.conf" -PassThru -NoNewWindow
Start-Sleep -Seconds 3

# 4. Wait for handshake
Write-Host "Waiting for tunnel handshake..."
Start-Sleep -Seconds 5

# 5. Generate test traffic through the tunnel
Write-Host "Sending test traffic..."
for ($i = 0; $i -lt 10; $i++) {
    Test-Connection -ComputerName 10.10.0.1 -Count 1 -Quiet | Out-Null
}

# 6. Generate bulk transfer (10 MB via UDP socket)
$data = [byte[]]::new(10MB)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($data)
$udpClient = New-Object System.Net.Sockets.UdpClient
for ($i = 0; $i -lt 10; $i++) {
    $chunk = $data[($i * 1MB)..(($i + 1) * 1MB - 1)]
    $udpClient.Send($chunk, $chunk.Length, "10.10.0.1", 9999) | Out-Null
}
$udpClient.Close()

# 7. Switch profile
aegis profile set video_streaming
Start-Sleep -Seconds 5

# 8. Print detection score
aegis status

# 9. Cleanup
Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
Write-Host "Demo complete."
```

### 8.3 — End-to-End Tests (`tests/test_e2e.py`)

```
Test E2E-1: Full handshake completes in < 500ms on loopback
Test E2E-2: 10 MB data transfer through tunnel; SHA-256 hash matches both ends
Test E2E-3: Detection score < 0.30 after 30s of web_browsing profile traffic
Test E2E-4: Profile hot-swap (web_browsing → video_streaming) does not drop packets
Test E2E-5: Restart client (simulates reconnect); new handshake succeeds; tunnel resumes
Test E2E-6: Inject a forged/replayed packet into the UDP stream; server silently drops it; no crash
```

**Implementation notes for Windows E2E tests:**
- Tests spawn server and client as `subprocess.Popen` processes on the same machine
- Each uses a unique WinTUN adapter name (`aegis_e2e_srv`, `aegis_e2e_cli`) to avoid collisions
- Tests must run as Administrator; skip gracefully with `pytest.mark.skipif` otherwise
- Cleanup in `finally` blocks must call `process.terminate()` to release WinTUN adapters
- Use `asyncio.wait_for(coro, timeout=...)` for timeout-bounded handshake checks

### Phase 8 Exit Criteria
- `pytest tests/test_e2e.py -v` — all 6 tests pass (Administrator PowerShell)
- `.\demo\run_demo.ps1` completes without errors
- `aegis status` shows detection score < 0.25 throughout the demo run

---

## Agent Execution Order

| Phase | Module | Tests to Pass Before Next Phase |
|-------|--------|--------------------------------|
| 1 ✅ | `tun.py` + `_tun_windows.py` | `test_tun.py` — 4 tests |
| 2 | `crypto.py` | `test_crypto.py` — 6 tests |
| 3 | `transport.py` | `test_transport.py` — 6 tests |
| 4 | `tunnel.py` | `test_tunnel.py` — 5 tests |
| 5 | `morphic.py` + `profiles/` | `test_morphic.py` — 6 tests |
| 6 | `feedback.py` | `test_feedback.py` — 6 tests |
| 7 | `cli.py` + `config.py` | `test_cli.py` — 5 tests |
| 8 | `demo/` + `setup.py` | `test_e2e.py` — 6 tests |

**Total: 44 tests across 8 phases. All must pass before demo.**

---

## Global Constraints for the Agent

1. **Never restructure the repo** after Phase 1 scaffold is laid.
2. **Never import between phases out of order** — e.g., `tunnel.py` may import `morphic.py` with a `None` guard, but `morphic.py` must not import `tunnel.py`.
3. **Administrator is required** for TUN tests. The agent must either run PowerShell as Administrator or skip TUN-dependent tests gracefully with `pytest.mark.skipif(not _is_windows_admin(), reason="requires Administrator")`.
4. **`liboqs-python` must be installed** before Phase 2. If `import oqs` fails, the agent must `pip install liboqs-python` before proceeding. Pre-built Windows wheels are available.
5. **All crypto operations use constant-time primitives** — no `==` comparison on secrets; use `hmac.compare_digest`.
6. **No plaintext secrets on disk** — key files are binary, not PEM/hex strings.
7. **Detection score history must be serializable to JSON** for the demo dashboard.
8. **All paths must use `pathlib.Path`** for cross-platform compatibility; never hardcode `/` separators.
9. **WinTUN adapters must be cleaned up** in all error paths — use context managers or `try/finally` blocks to call `WintunCloseAdapter`.
10. **asyncio on Windows**: TUN blocking reads must be offloaded to a thread executor via `loop.run_in_executor()` to avoid blocking the event loop.
11. **No WSL, VirtualBox, or Docker** — everything runs natively on Windows.
12. **Firewall**: The agent should document that Windows Firewall may need an inbound UDP rule for port 5555 (`netsh advfirewall firewall add rule name="Aegis" dir=in action=allow protocol=UDP localport=5555`).
