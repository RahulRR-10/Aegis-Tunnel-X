import math
import os
import random
import threading
import time
from collections import Counter
from queue import Queue

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

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
