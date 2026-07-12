import math
import os
import random
import sys
import threading
import time
from collections import Counter
from queue import Queue
from pathlib import Path

# Ensure the project root is on sys.path (so benchmark/ is importable)
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from flask import Flask, jsonify, render_template, request, Response
from flask_socketio import SocketIO

from benchmark.config import BenchmarkConfig
from benchmark.engine import BenchmarkEngine
from benchmark.metrics import BenchmarkResult, ComparisonResult
from benchmark.report import ReportGenerator

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
engine_state = {"on": True}

# tunnel_state controls the continuous background packet loop in client.py
tunnel_state: dict = {
    "running": False,
}

chat_outbox: Queue = Queue(maxsize=100)
chat_message_counter: int = 0
chat_lock: threading.Lock = threading.Lock()


# ---------------------------------------------------------------------------
# Simulated packet generation (mirrors morphic.py / crypto.py logic so the
# dashboard can run standalone without the external client.py process)
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return round(
        -sum((c / total) * math.log2(c / total) for c in counts.values()), 4
    )


def _make_fake_packet(engine_on: bool, seq: int) -> dict:
    """Return a stats dict identical in shape to what client.py pushes."""
    payload_size = random.randint(64, 192)
    payload = os.urandom(payload_size)
    raw_entropy = _shannon_entropy(payload)

    if not engine_on:
        return {
            "original_size": payload_size,
            "padding_size": 0,
            "final_size": payload_size,
            "raw_entropy": raw_entropy,
            "final_entropy": raw_entropy,
            "jitter_ms": 0,
            "engine_on": False,
            "session_key_prefix": f"{seq:08x}",
        }

    padding_size = random.randint(60, 180)
    pattern = bytes([0xAB, 0xCD, 0x00, 0xFF])
    padding = (pattern * (padding_size // len(pattern) + 1))[:padding_size]
    morphed = payload + padding
    final_entropy = _shannon_entropy(morphed)
    jitter_ms = random.randint(10, 50)

    return {
        "original_size": payload_size,
        "padding_size": padding_size,
        "final_size": len(morphed),
        "raw_entropy": raw_entropy,
        "final_entropy": final_entropy,
        "jitter_ms": jitter_ms,
        "engine_on": True,
        "session_key_prefix": f"{seq:08x}",
    }





# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index() -> str:
    return render_template("index.html")


# -- Morphic Engine toggle ---------------------------------------------------

@app.route("/toggle", methods=["POST"])
def toggle():
    engine_state["on"] = not engine_state["on"]
    payload = {"engine_on": engine_state["on"]}
    socketio.emit("engine_state", payload)
    return jsonify(payload)


@app.route("/engine", methods=["GET"])
def engine():
    return jsonify({"engine_on": engine_state["on"]})


@app.route("/stats", methods=["POST"])
def stats():
    """Receive a packet stats push from client.py and broadcast it."""
    data = request.get_json(silent=True) or {}

    # If client.py is driving, respect the tunnel running flag.
    # Only forward the event if the tunnel is supposed to be running.
    if not tunnel_state["running"]:
        return jsonify({"ok": True, "dropped": True})

    if "engine_on" in data:
        engine_state["on"] = bool(data["engine_on"])
    else:
        data["engine_on"] = engine_state["on"]

    socketio.emit("packet_event", data)
    return jsonify({"ok": True})


# -- Tunnel Start / Stop -----------------------------------------------------

@app.route("/tunnel", methods=["GET"])
def tunnel_status():
    return jsonify({"tunnel_running": tunnel_state["running"]})


@app.route("/tunnel/start", methods=["POST"])
def tunnel_start():
    tunnel_state["running"] = True
    payload = {"tunnel_running": True}
    socketio.emit("tunnel_state", payload)
    return jsonify(payload)


@app.route("/tunnel/stop", methods=["POST"])
def tunnel_stop():
    tunnel_state["running"] = False
    payload = {"tunnel_running": False}
    socketio.emit("tunnel_state", payload)
    return jsonify(payload)


# -- Chat Relay --------------------------------------------------------------

@app.route("/chat/send", methods=["POST"])
def chat_send():
    global chat_message_counter
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"ok": False, "error": "Empty message"}), 400

    with chat_lock:
        chat_message_counter += 1
        msg_id = chat_message_counter

    try:
        chat_outbox.put_nowait({"id": msg_id, "text": text})
    except Exception:
        return jsonify({"ok": False, "error": "Outbox full"}), 429

    return jsonify({"ok": True, "id": msg_id})


@app.route("/chat/outbox", methods=["GET"])
def chat_outbox_endpoint():
    messages = []
    while not chat_outbox.empty():
        try:
            messages.append(chat_outbox.get_nowait()["text"])
        except Exception:
            break
    return jsonify({"messages": messages})


@app.route("/chat/received", methods=["POST"])
def chat_received():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    socketio.emit("chat_message", {"text": text, "tunnel_verified": True})
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Benchmark state
# ---------------------------------------------------------------------------
benchmark_state = {
    "running": False,
    "progress": 0,
    "phase": "idle",
    "result_on": None,
    "result_off": None,
    "comparison": None,
    "latest_event": {},
}

benchmark_lock: threading.Lock = threading.Lock()
benchmark_thread: threading.Thread = None


# ---------------------------------------------------------------------------
# Benchmark routes
# ---------------------------------------------------------------------------

@app.route("/benchmark/start", methods=["POST"])
def benchmark_start():
    global benchmark_thread
    data = request.get_json(silent=True) or {}
    count = int(data.get("packet_count", 200))
    engine_only = data.get("engine_only", "off").lower()

    with benchmark_lock:
        if benchmark_state["running"]:
            return jsonify({"ok": False, "error": "Benchmark already running"}), 409
        benchmark_state["running"] = True
        benchmark_state["progress"] = 0
        benchmark_state["phase"] = "initializing"
        benchmark_state["result_on"] = None
        benchmark_state["result_off"] = None
        benchmark_state["comparison"] = None
        benchmark_state["latest_event"] = {}

    cfg_on = BenchmarkConfig(packet_count=count, engine_on=True)
    cfg_off = BenchmarkConfig(packet_count=count, engine_on=False)

    def _progress_cb(data):
        with benchmark_lock:
            benchmark_state["phase"] = data["phase"]
            benchmark_state["progress"] = data["percent"]
            benchmark_state["latest_event"] = data.get("data", {})
        try:
            with app.app_context():
                socketio.emit("benchmark_progress", {
                    "phase": data["phase"],
                    "percent": data["percent"],
                    "data": data.get("data", {}),
                })
        except Exception:
            pass

    def _emit_done(data):
        with benchmark_lock:
            benchmark_state["phase"] = "complete"
            benchmark_state["progress"] = 100
            benchmark_state["running"] = False
            if data.get("result_on"):
                benchmark_state["result_on"] = data["result_on"]
            if data.get("result_off"):
                benchmark_state["result_off"] = data["result_off"]
            if data.get("comparison"):
                benchmark_state["comparison"] = data["comparison"]
        try:
            with app.app_context():
                socketio.emit("benchmark_progress", {
                    "phase": "complete",
                    "percent": 100,
                    "data": {},
                })
                socketio.emit("benchmark_done", {
                    "mode": data["mode"],
                    "result": data["result"],
                })
        except Exception:
            pass

    def _run_bench():
        engine = BenchmarkEngine(session_key=os.urandom(32))
        engine.on_progress(_progress_cb)

        try:
            if engine_only == "off":
                result_off = engine.run_test(cfg_off)
                _emit_done({
                    "mode": "off",
                    "result": result_off.summary_dict(),
                    "result_off": result_off,
                })
            elif engine_only == "on":
                result_on = engine.run_test(cfg_on)
                _emit_done({
                    "mode": "on",
                    "result": result_on.summary_dict(),
                    "result_on": result_on,
                })
            else:
                comparison = engine.run_comparison(cfg_on)
                _emit_done({
                    "mode": "comparison",
                    "result": comparison.summary_dict(),
                    "comparison": comparison,
                })
        except Exception as exc:
            with benchmark_lock:
                benchmark_state["phase"] = f"error: {exc}"
                benchmark_state["running"] = False
            try:
                with app.app_context():
                    socketio.emit("benchmark_progress", {
                        "phase": f"error: {exc}",
                        "percent": 100,
                        "data": {},
                    })
            except Exception:
                pass

    benchmark_thread = threading.Thread(target=_run_bench, daemon=True)
    benchmark_thread.start()

    return jsonify({"ok": True})


@app.route("/benchmark/abort", methods=["POST"])
def benchmark_abort():
    with benchmark_lock:
        benchmark_state["running"] = False
        benchmark_state["phase"] = "aborted"
    return jsonify({"ok": True})


@app.route("/benchmark/status", methods=["GET"])
def benchmark_status():
    with benchmark_lock:
        return jsonify({
            "running": benchmark_state["running"],
            "phase": benchmark_state["phase"],
            "progress": benchmark_state["progress"],
            "latest_event": benchmark_state["latest_event"],
        })


@app.route("/benchmark/results", methods=["GET"])
def benchmark_results():
    with benchmark_lock:
        comp = benchmark_state.get("comparison")
        if comp:
            return jsonify({"mode": "comparison", "result": comp.summary_dict()})
        on_res = benchmark_state.get("result_on")
        if on_res:
            return jsonify({"mode": "on", "result": on_res.summary_dict()})
        off_res = benchmark_state.get("result_off")
        if off_res:
            return jsonify({"mode": "off", "result": off_res.summary_dict()})
        return jsonify({"mode": "none", "result": None})


@app.route("/benchmark/report", methods=["GET"])
def benchmark_report():
    """Generate an HTML report card and return it."""
    with benchmark_lock:
        comp = benchmark_state.get("comparison")
        on_res = benchmark_state.get("result_on")
        off_res = benchmark_state.get("result_off")

    if comp:
        html = ReportGenerator.generate(comp.on, comp)
    elif on_res:
        html = ReportGenerator.generate(on_res)
    elif off_res:
        html = ReportGenerator.generate(off_res)
    else:
        return jsonify({"ok": False, "error": "No results available"}), 404

    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": "attachment; filename=aegis_benchmark_report.html"})


# ---------------------------------------------------------------------------
# Post-Quantum Key Exchange Demo (PQKE)
# ---------------------------------------------------------------------------

try:
    from oqs import oqs as _oqs
    _OQS_AVAILABLE = True
except BaseException:
    _OQS_AVAILABLE = False

_KYBER = "Kyber512"
_KYBER_SIZES = {
    "public_key": 800,
    "secret_key": 1632,
    "ciphertext": 768,
    "shared_secret": 32,
}


def _pqke_generate():
    try:
        if _OQS_AVAILABLE:
            kem = _oqs.KeyEncapsulation(_KYBER)
            pub = kem.generate_keypair()
            sec = kem.export_secret_key()
            kem.free()
            return pub.hex(), sec.hex(), True
    except Exception:
        pass
    pub = os.urandom(_KYBER_SIZES["public_key"])
    sec = os.urandom(_KYBER_SIZES["secret_key"])
    return pub.hex(), sec.hex(), False


def _pqke_encapsulate(server_pub_hex: str):
    try:
        if _OQS_AVAILABLE:
            pub = bytes.fromhex(server_pub_hex)
            kem = _oqs.KeyEncapsulation(_KYBER)
            ct, ss = kem.encap_secret(pub)
            kem.free()
            return ct.hex(), ss.hex(), True
    except Exception:
        pass
    ct = os.urandom(_KYBER_SIZES["ciphertext"])
    ss = os.urandom(_KYBER_SIZES["shared_secret"])
    return ct.hex(), ss.hex(), False


def _pqke_decapsulate(ciphertext_hex: str, secret_key_hex: str):
    try:
        if _OQS_AVAILABLE:
            ct = bytes.fromhex(ciphertext_hex)
            sec = bytes.fromhex(secret_key_hex)
            kem = _oqs.KeyEncapsulation(_KYBER)
            kem.set_secret_key(sec)
            ss = kem.decap_secret(ct)
            kem.free()
            return ss.hex(), True
    except Exception:
        pass
    ss = os.urandom(_KYBER_SIZES["shared_secret"])
    return ss.hex(), False


@app.route("/pqke/status", methods=["GET"])
def pqke_status():
    return jsonify({
        "oqs_available": _OQS_AVAILABLE,
        "kyber_variant": _KYBER,
        "key_sizes": _KYBER_SIZES,
    })


@app.route("/pqke/generate", methods=["POST"])
def pqke_generate():
    pub_hex, sec_hex, real = _pqke_generate()
    return jsonify({
        "public_key_hex": pub_hex,
        "secret_key_hex": sec_hex,
        "real_oqs": real,
    })


@app.route("/pqke/encapsulate", methods=["POST"])
def pqke_encapsulate():
    data = request.get_json(silent=True) or {}
    server_pub_hex = data.get("server_public_key_hex", "")
    if len(server_pub_hex) != _KYBER_SIZES["public_key"] * 2:
        return jsonify({"error": "Invalid public key length"}), 400
    ct_hex, ss_hex, real = _pqke_encapsulate(server_pub_hex)
    return jsonify({
        "ciphertext_hex": ct_hex,
        "shared_secret_hex": ss_hex,
        "real_oqs": real,
    })


@app.route("/pqke/decapsulate", methods=["POST"])
def pqke_decapsulate():
    data = request.get_json(silent=True) or {}
    ct_hex = data.get("ciphertext_hex", "")
    sec_hex = data.get("server_secret_key_hex", "")
    if len(ct_hex) != _KYBER_SIZES["ciphertext"] * 2:
        return jsonify({"error": "Invalid ciphertext length"}), 400
    if len(sec_hex) != _KYBER_SIZES["secret_key"] * 2:
        return jsonify({"error": "Invalid secret key length"}), 400
    ss_hex, real = _pqke_decapsulate(ct_hex, sec_hex)
    return jsonify({
        "shared_secret_hex": ss_hex,
        "real_oqs": real,
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("[DASHBOARD] Running at http://127.0.0.1:5000")
    try:
        socketio.run(
            app,
            host="127.0.0.1",
            port=5000,
            debug=False,
            allow_unsafe_werkzeug=True,
        )
    except KeyboardInterrupt:
        print("\n[DASHBOARD] Stopped by user.")
