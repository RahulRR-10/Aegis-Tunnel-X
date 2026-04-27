// ===========================================================================
// Aegis-Tunnel X — Dashboard JS  (Multi-Page + Tunnel Controls)
// ===========================================================================

const socket    = io();
const MAX_POINTS = 40;

// ---------------------------------------------------------------------------
// Hash router — four pages: entropy | morphing | telemetry | stats
// ---------------------------------------------------------------------------
const VALID_PAGES = ["entropy", "morphing", "telemetry", "stats"];

function navigateTo(page) {
	if (!VALID_PAGES.includes(page)) page = "entropy";

	history.replaceState(null, "", `#${page}`);

	document.querySelectorAll(".page").forEach((el) => {
		el.classList.toggle("active", el.dataset.page === page);
	});

	document.querySelectorAll(".nav-item").forEach((el) => {
		el.classList.toggle("active", el.dataset.page === page);
	});

	// Resize charts when switching to their page (fixes canvas sizing)
	requestAnimationFrame(() => {
		if (page === "entropy" && entropyChart) entropyChart.resize();
		if (page === "morphing" && morphChart)  morphChart.resize();
	});
}

function getCurrentPage() {
	const hash = window.location.hash.replace("#", "");
	return VALID_PAGES.includes(hash) ? hash : "entropy";
}

// Sidebar click handlers
document.querySelectorAll(".nav-item").forEach((item) => {
	item.addEventListener("click", (e) => {
		e.preventDefault();
		navigateTo(item.dataset.page);
	});
});

// Browser back/forward support
window.addEventListener("hashchange", () => navigateTo(getCurrentPage()));

// ---------------------------------------------------------------------------
// DOM references
// ---------------------------------------------------------------------------
const statEls = {
	packets:    document.getElementById("s-packets"),
	raw:        document.getElementById("s-raw"),
	morphed:    document.getElementById("s-morphed"),
	padding:    document.getElementById("s-padding"),
	jitter:     document.getElementById("s-jitter"),
	engine:     document.getElementById("s-engine"),
	sessionKey: document.getElementById("session-key-value"),
};

const logEl      = document.getElementById("log-output");
const toggleBtn  = document.getElementById("toggle-btn");
const tunnelBtn  = document.getElementById("tunnel-btn");
const tunnelPill = document.getElementById("tunnel-pill");
const statusDot  = document.getElementById("status-dot");

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let packetCount   = 0;
let totalPadding  = 0;
let rawSum        = 0;
let morphedSum    = 0;
let jitterSum     = 0;
let engineOn      = true;
let tunnelRunning = false;

// ---------------------------------------------------------------------------
// Chart helpers
// ---------------------------------------------------------------------------
function trimSeries(chartData) {
	while (chartData.labels.length > MAX_POINTS) {
		chartData.labels.shift();
		for (const ds of chartData.datasets) ds.data.shift();
	}
}

// ---------------------------------------------------------------------------
// Entropy Chart
// ---------------------------------------------------------------------------
const entropyData = {
	labels: [],
	datasets: [{
		label: "Packet Entropy",
		data: [],
		borderColor: "#00ff88",
		backgroundColor: "rgba(0, 255, 136, 0.08)",
		borderWidth: 2,
		tension: 0.25,
		fill: true,
		pointRadius: 0,
	}],
};

const entropyChart = new Chart(document.getElementById("entropyChart").getContext("2d"), {
	type: "line",
	data: entropyData,
	options: {
		animation: false,
		maintainAspectRatio: false,
		scales: {
			y: {
				min: 3,
				max: 8.2,
				grid:  { color: "rgba(0, 255, 136, 0.12)" },
				ticks: { color: "#75d4ac", font: { family: "JetBrains Mono", size: 10 } },
			},
			x: { display: false },
		},
		plugins: { legend: { display: false } },
	},
	plugins: [{
		id: "thresholdLine",
		afterDraw(chart) {
			const { ctx, chartArea, scales } = chart;
			const y = scales.y.getPixelForValue(7.9);
			ctx.save();
			ctx.strokeStyle = "rgba(255, 77, 79, 0.7)";
			ctx.setLineDash([6, 4]);
			ctx.beginPath();
			ctx.moveTo(chartArea.left, y);
			ctx.lineTo(chartArea.right, y);
			ctx.stroke();
			ctx.fillStyle = "rgba(255, 77, 79, 0.95)";
			ctx.font = "10px JetBrains Mono";
			ctx.fillText("DPI danger zone 7.9", chartArea.left + 4, y - 5);
			ctx.restore();
		},
	}],
});

// ---------------------------------------------------------------------------
// Morph / Stacked Bar Chart
// ---------------------------------------------------------------------------
const morphData = {
	labels: [],
	datasets: [
		{
			label: "Encrypted Payload",
			data: [],
			backgroundColor: "rgba(0, 255, 136, 0.5)",
		},
		{
			label: "Padding",
			data: [],
			backgroundColor: "rgba(255, 159, 26, 0.75)",
		},
	],
};

const morphChart = new Chart(document.getElementById("morphChart").getContext("2d"), {
	type: "bar",
	data: morphData,
	options: {
		animation: false,
		maintainAspectRatio: false,
		scales: {
			x: { stacked: true, display: false },
			y: {
				stacked: true,
				grid:  { color: "rgba(0, 255, 136, 0.12)" },
				ticks: { color: "#75d4ac", font: { family: "JetBrains Mono", size: 10 } },
			},
		},
		plugins: {
			legend: {
				labels: { color: "#9dfccf", font: { family: "JetBrains Mono", size: 10 } },
			},
		},
	},
});

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
function formatBytes(value) {
	if (value < 1024)           return `${value} B`;
	if (value < 1024 * 1024)   return `${(value / 1024).toFixed(1)} KB`;
	return `${(value / (1024 * 1024)).toFixed(2)} MB`;
}

// ---------------------------------------------------------------------------
// UI state setters
// ---------------------------------------------------------------------------
function setEngineUI(on) {
	engineOn = on;
	statEls.engine.textContent = on ? "ON" : "OFF";
	toggleBtn.textContent = on ? "MORPHIC ENGINE: ON" : "MORPHIC ENGINE: OFF";
	toggleBtn.classList.toggle("on", on);
}

function setTunnelUI(running) {
	tunnelRunning = running;
	if (running) {
		tunnelBtn.textContent = "⏹ STOP TUNNEL";
		tunnelBtn.classList.add("running");
		tunnelPill.textContent = "▶ TUNNEL ACTIVE";
		tunnelPill.classList.remove("stopped");
		statusDot.classList.remove("stopped");
	} else {
		tunnelBtn.textContent = "▶ START TUNNEL";
		tunnelBtn.classList.remove("running");
		tunnelPill.textContent = "⏹ TUNNEL STOPPED";
		tunnelPill.classList.add("stopped");
		statusDot.classList.add("stopped");
		addPausedNotice();
	}
}

// ---------------------------------------------------------------------------
// Log helpers
// ---------------------------------------------------------------------------
function addLogLine(data) {
	const row = document.createElement("div");
	const now = new Date().toTimeString().slice(0, 8);
	if (data.engine_on) {
		row.textContent =
			`[${now}] MORPH | ${data.original_size}b -> +${data.padding_size || 0}b pad | ` +
			`entropy ${data.raw_entropy}->${data.final_entropy} | jitter ${data.jitter_ms || 0}ms`;
	} else {
		row.className = "warn";
		row.textContent =
			`[${now}] WARN  | ${data.original_size}b | entropy ${data.raw_entropy} | ENGINE OFF`;
	}
	_appendLogRow(row);
}

function addPausedNotice() {
	const row = document.createElement("div");
	const now = new Date().toTimeString().slice(0, 8);
	row.className = "paused-notice";
	row.textContent = `[${now}] ──── TUNNEL PAUSED ────`;
	_appendLogRow(row);
}

function _appendLogRow(row) {
	logEl.appendChild(row);
	logEl.scrollTop = logEl.scrollHeight;
	if (logEl.children.length > 250) logEl.removeChild(logEl.firstChild);
}

// ---------------------------------------------------------------------------
// Socket.IO event handlers
// ---------------------------------------------------------------------------
socket.on("packet_event", (data) => {
	packetCount  += 1;
	totalPadding += data.padding_size  || 0;
	rawSum       += data.raw_entropy   || 0;
	morphedSum   += data.final_entropy || 0;
	jitterSum    += data.jitter_ms     || 0;

	const label = `#${packetCount}`;

	entropyData.labels.push(label);
	entropyData.datasets[0].data.push(data.final_entropy || 0);
	trimSeries(entropyData);
	entropyChart.update();

	morphData.labels.push(label);
	morphData.datasets[0].data.push(data.original_size || 0);
	morphData.datasets[1].data.push(data.padding_size  || 0);
	trimSeries(morphData);
	morphChart.update();

	statEls.packets.textContent = packetCount.toLocaleString();
	statEls.raw.textContent     = (rawSum     / packetCount).toFixed(4);
	statEls.morphed.textContent = (morphedSum / packetCount).toFixed(4);
	statEls.padding.textContent = formatBytes(totalPadding);
	statEls.jitter.textContent  = `${Math.round(jitterSum / packetCount)} ms`;
	setEngineUI(Boolean(data.engine_on));

	if (data.session_key_prefix) {
		statEls.sessionKey.textContent = `${data.session_key_prefix}...`;
	}

	addLogLine(data);
});

socket.on("engine_state", (data) => {
	if (Object.prototype.hasOwnProperty.call(data, "engine_on")) {
		setEngineUI(Boolean(data.engine_on));
	}
});

socket.on("tunnel_state", (data) => {
	if (Object.prototype.hasOwnProperty.call(data, "tunnel_running")) {
		setTunnelUI(Boolean(data.tunnel_running));
	}
});

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------
async function refreshEngineState() {
	try {
		const res = await fetch("/engine", { method: "GET" });
		if (!res.ok) return;
		setEngineUI(Boolean((await res.json()).engine_on));
	} catch (_) {}
}

async function refreshTunnelState() {
	try {
		const res = await fetch("/tunnel", { method: "GET" });
		if (!res.ok) return;
		setTunnelUI(Boolean((await res.json()).tunnel_running));
	} catch (_) {}
}

async function toggleEngine() {
	try {
		const res = await fetch("/toggle", { method: "POST" });
		if (!res.ok) return;
		setEngineUI(Boolean((await res.json()).engine_on));
	} catch (_) {}
}

async function toggleTunnel() {
	const nextRunning = !tunnelRunning;
	setTunnelUI(nextRunning);

	const endpoint = nextRunning ? "/tunnel/start" : "/tunnel/stop";
	try {
		const res = await fetch(endpoint, { method: "POST" });
		if (!res.ok) { setTunnelUI(!nextRunning); return; }
		setTunnelUI(Boolean((await res.json()).tunnel_running));
	} catch (_) {
		setTunnelUI(!nextRunning);
	}
}

// ---------------------------------------------------------------------------
// Expose globals & bootstrap
// ---------------------------------------------------------------------------
window.toggleEngine = toggleEngine;
window.toggleTunnel = toggleTunnel;

refreshEngineState();
refreshTunnelState();

// Boot the router
navigateTo(getCurrentPage());
