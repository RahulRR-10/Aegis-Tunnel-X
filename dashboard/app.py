from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

engine_state = {"on": True}


@app.route("/")
def index() -> str:
	return render_template("index.html")


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
	data = request.get_json(silent=True) or {}

	if "engine_on" in data:
		engine_state["on"] = bool(data["engine_on"])
	else:
		data["engine_on"] = engine_state["on"]

	socketio.emit("packet_event", data)
	return jsonify({"ok": True})


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
