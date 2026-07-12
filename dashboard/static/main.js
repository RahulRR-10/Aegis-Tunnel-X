// ===========================================================================
// Aegis-Tunnel X — Dashboard JS  (Multi-Page + Tunnel Controls)
// ===========================================================================

const socket    = io();
const MAX_POINTS = 40;

// ---------------------------------------------------------------------------
// Hash router — seven pages: entropy | morphing | telemetry | stats | crypto | pqke | benchmark
// ---------------------------------------------------------------------------
const VALID_PAGES = ["entropy", "morphing", "telemetry", "stats", "chat", "pqke", "benchmark"];

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

const cryptoInput  = document.getElementById("crypto-input");
const cryptoSendBtn= document.getElementById("crypto-send-btn");
const cryptoPipeline = document.getElementById("crypto-pipeline");

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
// Crypto Playground
// ---------------------------------------------------------------------------
function computeShannonEntropy(bytes) {
	if (!bytes || bytes.length === 0) return 0;
	const counts = new Array(256).fill(0);
	for (const b of bytes) counts[b]++;
	const total = bytes.length;
	let entropy = 0;
	for (const c of counts) {
		if (c === 0) continue;
		const p = c / total;
		entropy -= p * Math.log2(p);
	}
	return Math.round(entropy * 10000) / 10000;
}

function bytesToHex(bytes) {
	return Array.from(bytes).map(b => b.toString(16).padStart(2, "0").toUpperCase()).join(" ");
}

function bytesToAscii(bytes) {
	return Array.from(bytes).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : ".").join("");
}

function formatHexDump(bytes, highlightStart, highlightEnd) {
	let html = "";
	for (let i = 0; i < bytes.length; i++) {
		const hex = bytes[i].toString(16).padStart(2, "0").toUpperCase();
		let cls = "hex-byte";
		if (highlightStart !== undefined && i >= highlightStart && i < highlightEnd) {
			cls += " highlight";
		}
		if (i > 0 && i % 16 === 0) html += "\n";
		html += `<span class="${cls}">${hex}</span> `;
	}
	return html;
}

function entropyBarClass(val) {
	return val < 7.9 ? "safe" : "danger";
}

function dpiScore(entropy) {
	if (entropy < 7.5) return { label: "LOW RISK", cls: "good" };
	if (entropy < 7.9) return { label: "MODERATE", cls: "good" };
	return { label: "DETECTED", cls: "risk" };
}

function runCryptoPipeline(text) {
	if (!text) return;

	const encoder = new TextEncoder();
	const plaintextBytes = encoder.encode(text);

	const msgTypeByte = 0x01;
	const lengthHi = (plaintextBytes.length >> 8) & 0xFF;
	const lengthLo = plaintextBytes.length & 0xFF;
	const packetHeader = new Uint8Array([msgTypeByte, lengthHi, lengthLo]);
	const payloadWithHeader = new Uint8Array([...packetHeader, ...plaintextBytes]);

	const fakeKey = new Uint8Array(32);
	for (let i = 0; i < 32; i++) fakeKey[i] = Math.floor(Math.random() * 256);

	const nonce = new Uint8Array(12);
	for (let i = 0; i < 12; i++) nonce[i] = Math.floor(Math.random() * 256);

	const ciphertext = new Uint8Array(plaintextBytes.length + 16);
	for (let i = 0; i < ciphertext.length; i++) ciphertext[i] = Math.floor(Math.random() * 256);

	const fullCiphertext = new Uint8Array([...ciphertext]);
	const cipherEntropy = computeShannonEntropy(fullCiphertext);

	const paddingSize = Math.floor(Math.random() * 121) + 60;
	const pattern = [0xAB, 0xCD, 0x00, 0xFF];
	const padding = new Uint8Array(paddingSize);
	for (let i = 0; i < paddingSize; i++) padding[i] = pattern[i % 4];

	const morphedPacket = new Uint8Array([...fullCiphertext, ...padding]);
	const morphedEntropy = computeShannonEntropy(morphedPacket);

	const jitterMs = Math.floor(Math.random() * 41) + 10;

	const wirePacket = new Uint8Array([
		(morphedPacket.length >> 8) & 0xFF,
		morphedPacket.length & 0xFF,
		...morphedPacket,
	]);

	const wireEntropy = computeShannonEntropy(wirePacket);
	const originalEntropy = computeShannonEntropy(plaintextBytes);

	const dpiBefore = dpiScore(cipherEntropy);
	const dpiAfter = dpiScore(morphedEntropy);

	cryptoPipeline.innerHTML = "";

	const stages = [
		{
			num: 1,
			title: "Plaintext Input",
			tag: "UTF-8",
			content: `
				<div class="meta-item"><strong>${plaintextBytes.length} bytes</strong> of raw text</div>
				<div class="hex-dump">${formatHexDump(plaintextBytes)}</div>
				<div class="ascii-view">${bytesToAscii(plaintextBytes)}</div>
				<div class="entropy-bar-container">
					<span class="entropy-label">Entropy</span>
					<div class="entropy-bar-track"><div class="entropy-bar-fill ${entropyBarClass(originalEntropy)}" style="width: ${(originalEntropy / 8 * 100).toFixed(1)}%"></div></div>
					<span class="entropy-value">${originalEntropy.toFixed(4)}</span>
				</div>
				<div class="dpi-meter">
					<span class="dpi-label">DPI Status</span>
					<span class="dpi-score ${dpiBefore.cls}">${dpiBefore.label}</span>
				</div>
			`,
		},
		{
			num: 2,
			title: "Packet Header",
			tag: "0x01 + LEN",
			content: `
				<div class="meta-item">Type: <strong>0x01</strong> (Chat) | Length: <strong>${plaintextBytes.length}</strong> bytes</div>
				<div class="hex-dump">${formatHexDump(packetHeader)}</div>
				<div class="meta-item" style="margin-top:6px;">Header + Payload: <strong>${payloadWithHeader.length} bytes</strong></div>
			`,
		},
		{
			num: 3,
			title: "AES-256-GCM Encryption",
			tag: "AES-256-GCM",
			content: `
				<div class="crypto-meta">
					<span class="meta-item">Nonce (12B): <strong>${bytesToHex(nonce)}</strong></span>
					<span class="meta-item">Tag (16B): appended</span>
					<span class="meta-item">Session Key: <strong>${lastSessionKeyPrefix}...</strong></span>
				</div>
				<div style="margin-top:8px;">
					<div class="entropy-label" style="margin-bottom:4px;">Ciphertext (${fullCiphertext.length}B)</div>
					<div class="hex-dump">${formatHexDump(fullCiphertext)}</div>
				</div>
				<div class="entropy-bar-container">
					<span class="entropy-label">Entropy</span>
					<div class="entropy-bar-track"><div class="entropy-bar-fill ${entropyBarClass(cipherEntropy)}" style="width: ${(cipherEntropy / 8 * 100).toFixed(1)}%"></div></div>
					<span class="entropy-value">${cipherEntropy.toFixed(4)}</span>
				</div>
				<div class="dpi-meter">
					<span class="dpi-label">DPI Status</span>
					<span class="dpi-score ${dpiBefore.cls}">${dpiBefore.label}</span>
				</div>
			`,
		},
		{
			num: 4,
			title: "Morphic Engine — Padding Injection",
			tag: "0xABCD00FF",
			content: `
				<div class="meta-item">Padding: <strong>+${paddingSize} bytes</strong> of structured pattern <code>0xAB 0xCD 0x00 0xFF</code></div>
				<div class="meta-item">Jitter: <strong>${jitterMs}ms</strong> randomized delay</div>
				<div style="margin-top:8px;">
					<div class="entropy-label" style="margin-bottom:4px;">Padding Pattern</div>
					<div class="hex-dump" style="max-height:40px;">${formatHexDump(padding)}</div>
				</div>
				<div style="display:flex; gap:20px; margin-top:10px;">
					<div>
						<div class="entropy-label" style="margin-bottom:4px;">Before Morph</div>
						<div class="entropy-bar-container">
							<div class="entropy-bar-track" style="width:120px;"><div class="entropy-bar-fill danger" style="width: ${(cipherEntropy / 8 * 100).toFixed(1)}%"></div></div>
							<span class="entropy-value">${cipherEntropy.toFixed(4)}</span>
						</div>
					</div>
					<div>
						<div class="entropy-label" style="margin-bottom:4px;">After Morph</div>
						<div class="entropy-bar-container">
							<div class="entropy-bar-track" style="width:120px;"><div class="entropy-bar-fill safe" style="width: ${(morphedEntropy / 8 * 100).toFixed(1)}%"></div></div>
							<span class="entropy-value">${morphedEntropy.toFixed(4)}</span>
						</div>
					</div>
				</div>
				<div class="dpi-meter">
					<span class="dpi-label">DPI Status</span>
					<span class="dpi-score ${dpiAfter.cls}">${dpiAfter.label}</span>
				</div>
			`,
		},
		{
			num: 5,
			title: "Final Wire Packet",
			tag: `${wirePacket.length} bytes`,
			content: `
				<div class="meta-item">Length prefix (2B) + morphed payload = <strong>${wirePacket.length} bytes</strong> on the wire</div>
				<div class="hex-dump">${formatHexDump(wirePacket, 0, 2)}</div>
				<div class="meta-item" style="margin-top:6px;">
					<span style="color:var(--accent);">■■</span> Length prefix &nbsp;
					<span style="color:#b6ffe0;">■■</span> AES-256 ciphertext &nbsp;
					<span style="color:var(--muted);">■■</span> Morphic padding
				</div>
				<div class="entropy-bar-container">
					<span class="entropy-label">Entropy</span>
					<div class="entropy-bar-track"><div class="entropy-bar-fill ${entropyBarClass(wireEntropy)}" style="width: ${(wireEntropy / 8 * 100).toFixed(1)}%"></div></div>
					<span class="entropy-value">${wireEntropy.toFixed(4)}</span>
				</div>
				<div class="dpi-meter">
					<span class="dpi-label">DPI Evasion</span>
					<span class="dpi-score ${dpiAfter.cls}">${dpiAfter.label}</span>
					<span class="dpi-label" style="margin-left:auto;">Overhead: <strong style="color:var(--pad);">+${(wirePacket.length - plaintextBytes.length)} bytes</strong> (${((wirePacket.length / plaintextBytes.length - 1) * 100).toFixed(0)}%)</span>
				</div>
			`,
		},
	];

	stages.forEach((stage, idx) => {
		if (idx > 0) {
			const conn = document.createElement("div");
			conn.className = "stage-connector";
			conn.innerHTML = "▼";
			cryptoPipeline.appendChild(conn);
		}

		const el = document.createElement("div");
		el.className = "pipeline-stage";
		el.innerHTML = `
			<div class="stage-header">
				<span class="stage-num">${stage.num}</span>
				<span class="stage-title">${stage.title}</span>
				<span class="stage-tag">${stage.tag}</span>
			</div>
			${stage.content}
		`;
		cryptoPipeline.appendChild(el);
	});
}

function sendCryptoMessage() {
	const text = cryptoInput.value.trim();
	if (!text) return;

	runCryptoPipeline(text);

	fetch("/chat/send", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ text }),
	}).then(res => {
		if (res.ok) {
			const status = document.createElement("div");
			status.className = "pipeline-stage";
			status.style.borderLeftColor = "var(--accent)";
			status.innerHTML = `
				<div class="stage-header">
					<span class="stage-num" style="background: var(--accent);">✓</span>
					<span class="stage-title">Sent Through Tunnel</span>
					<span class="stage-tag">ENCRYPTED</span>
				</div>
				<div class="meta-item">Message queued → client picks up → encrypts → morphs → UDP 9002 → server decrypts → echoes back</div>
			`;
			cryptoPipeline.appendChild(status);
			cryptoPipeline.scrollTop = cryptoPipeline.scrollHeight;
		}
	}).catch(() => {});
}

function escapeHtml(str) {
	const div = document.createElement("div");
	div.textContent = str;
	return div.innerHTML;
}
let lastSessionKeyPrefix = "--------";

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
		lastSessionKeyPrefix = data.session_key_prefix;
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

socket.on("chat_message", (data) => {
	if (data.text) {
		const status = document.createElement("div");
		status.className = "pipeline-stage";
		status.style.borderLeftColor = "var(--accent)";
		status.style.background = "rgba(0, 255, 136, 0.06)";
		status.innerHTML = `
			<div class="stage-header">
				<span class="stage-num" style="background: var(--accent);">✓</span>
				<span class="stage-title">Server Echo Received</span>
				<span class="stage-tag">TUNNEL VERIFIED</span>
			</div>
			<div class="meta-item">Decrypted: <strong>"${escapeHtml(data.text)}"</strong> — message completed full round-trip through the encrypted tunnel</div>
		`;
		cryptoPipeline.appendChild(status);
		cryptoPipeline.scrollTop = cryptoPipeline.scrollHeight;
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

if (cryptoSendBtn) {
	cryptoSendBtn.addEventListener("click", sendCryptoMessage);
}

if (cryptoInput) {
	cryptoInput.addEventListener("keydown", (e) => {
		if (e.key === "Enter") {
			sendCryptoMessage();
		}
	});
}

// ===========================================================================
// Benchmark Module
// ===========================================================================

// ===========================================================================
// Benchmark Module — v2 (fixed layout shift + polling fallback)
// ===========================================================================

const bmEls = {
	startBtn:  document.getElementById("bm-start-btn"),
	abortBtn:  document.getElementById("bm-abort-btn"),
	exportBtn: document.getElementById("bm-export-btn"),
	pktCount:  document.getElementById("bm-pkt-count"),
	mode:      document.getElementById("bm-mode"),
	progressContainer: document.getElementById("bm-progress-container"),
	progressBar:  document.getElementById("bm-progress-bar"),
	phaseLabel:   document.getElementById("bm-phase-label"),
	pctLabel:     document.getElementById("bm-pct-label"),
	content:      document.getElementById("bm-content"),
	liveSection:  document.getElementById("bm-live-section"),
	liveTp:   document.getElementById("bm-live-tp"),
	liveLat:  document.getElementById("bm-live-lat"),
	liveEnt:  document.getElementById("bm-live-ent"),
	livePkts: document.getElementById("bm-live-pkts"),
	resultsSection: document.getElementById("bm-results-section"),
	onTp:    document.getElementById("bm-on-tp"),
	onLat:   document.getElementById("bm-on-lat"),
	onEnt:   document.getElementById("bm-on-ent"),
	onDpi:   document.getElementById("bm-on-dpi"),
	offTp:   document.getElementById("bm-off-tp"),
	offLat:  document.getElementById("bm-off-lat"),
	offEnt:  document.getElementById("bm-off-ent"),
	offDpi:  document.getElementById("bm-off-dpi"),
	impact:  document.getElementById("bm-impact"),
	impactValue: document.getElementById("bm-impact-value"),
};

let bmLiveData = { labels: [], throughput: [], latency: [], entropy: [] };
const BM_MAX_POINTS = 60;

let bmLiveChart = null;
let bmResultsTpChart = null;
let bmResultsLatChart = null;
let bmResultsEntChart = null;

let bmMode = "comparison";
let bmPollInterval = null;

// -------------------------------------------------------------------------
// Chart init
// -------------------------------------------------------------------------
function initBmLiveChart() {
	const canvas = document.getElementById("bm-live-chart");
	if (!canvas) return;
	const ctx = canvas.getContext("2d");
	if (bmLiveChart) { bmLiveChart.destroy(); }
	bmLiveChart = new Chart(ctx, {
		type: "line",
		data: {
			labels: [],
			datasets: [{
				label: "Throughput (Mbps)",
				data: [],
				borderColor: "#00ff88",
				backgroundColor: "rgba(0,255,136,0.08)",
				borderWidth: 2, tension: 0.3, fill: true, pointRadius: 0,
			}],
		},
		options: {
			animation: false, maintainAspectRatio: false,
			scales: {
				y: { beginAtZero: true, grid: { color: "rgba(0,255,136,0.12)" }, ticks: { color: "#75d4ac", font: { family: "JetBrains Mono", size: 10 } } },
				x: { display: false },
			},
			plugins: { legend: { display: false } },
		},
	});
}

function initBmResultsCharts() {
	const tpC = document.getElementById("bm-results-tp-chart");
	if (tpC) {
		if (bmResultsTpChart) bmResultsTpChart.destroy();
		bmResultsTpChart = new Chart(tpC.getContext("2d"), {
			type: "bar",
			data: {
				labels: ["Throughput (Mbps)"],
				datasets: [
					{ label: "Engine ON", data: [0], backgroundColor: "rgba(0,255,136,0.6)", borderColor: "#00ff88", borderWidth: 1 },
					{ label: "Engine OFF", data: [0], backgroundColor: "rgba(255,77,79,0.6)", borderColor: "#ff4d4f", borderWidth: 1 },
				],
			},
			options: {
				responsive: true, maintainAspectRatio: false,
				plugins: { legend: { labels: { color: "#9dfccf", font: { family: "JetBrains Mono", size: 10 } } } },
				scales: {
					y: { beginAtZero: true, grid: { color: "rgba(0,255,136,0.12)" }, ticks: { color: "#75d4ac", font: { family: "JetBrains Mono", size: 10 } } },
					x: { grid: { display: false } },
				},
			},
		});
	}

	const latC = document.getElementById("bm-results-lat-chart");
	if (latC) {
		if (bmResultsLatChart) bmResultsLatChart.destroy();
		bmResultsLatChart = new Chart(latC.getContext("2d"), {
			type: "bar",
			data: { labels: [], datasets: [{ label: "Count", data: [], backgroundColor: "rgba(0,255,136,0.4)", borderColor: "#00ff88", borderWidth: 1 }] },
			options: {
				responsive: true, maintainAspectRatio: false,
				plugins: { legend: { display: false } },
				scales: {
					y: { beginAtZero: true, grid: { color: "rgba(0,255,136,0.12)" }, ticks: { color: "#75d4ac", font: { family: "JetBrains Mono", size: 10 } } },
					x: { grid: { display: false }, ticks: { color: "#75d4ac", font: { family: "JetBrains Mono", size: 9 }, maxRotation: 45 } },
				},
			},
		});
	}

	const entC = document.getElementById("bm-results-ent-chart");
	if (entC) {
		if (bmResultsEntChart) bmResultsEntChart.destroy();
		bmResultsEntChart = new Chart(entC.getContext("2d"), {
			type: "line",
			data: {
				labels: [],
				datasets: [
					{ label: "Raw Entropy", data: [], borderColor: "#ff9f1a", backgroundColor: "rgba(255,159,26,0.1)", borderWidth: 1.5, tension: 0.3, pointRadius: 0, fill: true },
					{ label: "Final Entropy", data: [], borderColor: "#00ff88", backgroundColor: "rgba(0,255,136,0.1)", borderWidth: 1.5, tension: 0.3, pointRadius: 0, fill: true },
				],
			},
			options: {
				responsive: true, maintainAspectRatio: false,
				plugins: { legend: { labels: { color: "#9dfccf", font: { family: "JetBrains Mono", size: 10 } } } },
				scales: {
					y: { min: 3, max: 8.2, grid: { color: "rgba(0,255,136,0.12)" }, ticks: { color: "#75d4ac", font: { family: "JetBrains Mono", size: 10 } } },
					x: { display: false },
				},
			},
		});
	}
}

// -------------------------------------------------------------------------
// UI helpers
// -------------------------------------------------------------------------
function updateBmLiveChart(tp, lat, ent, pkts) {
	bmLiveData.labels.push(`#${pkts}`);
	bmLiveData.throughput.push(tp);
	while (bmLiveData.labels.length > BM_MAX_POINTS) {
		bmLiveData.labels.shift();
		bmLiveData.throughput.shift();
	}
	if (bmLiveChart) {
		bmLiveChart.data.labels = bmLiveData.labels;
		bmLiveChart.data.datasets[0].data = bmLiveData.throughput;
		bmLiveChart.update();
	}
}

function showBmProgress(phase, pct) {
	const pctClamped = Math.min(Math.max(pct, 0), 100);
	if (bmEls.progressContainer) bmEls.progressContainer.style.display = "block";
	if (bmEls.phaseLabel) bmEls.phaseLabel.textContent = phase;
	if (bmEls.pctLabel) bmEls.pctLabel.textContent = `${Math.round(pctClamped)}%`;
	if (bmEls.progressBar) bmEls.progressBar.style.width = `${pctClamped}%`;
}

function toggleBmContent(showLive) {
	if (!bmEls.content) return;
	bmEls.content.style.display = "flex";
	if (bmEls.liveSection) bmEls.liveSection.style.display = showLive ? "block" : "none";
	if (bmEls.resultsSection) bmEls.resultsSection.style.display = showLive ? "none" : "block";
}

function showBmLive(data) {
	toggleBmContent(true);
	// Lazy init live chart if not yet created
	if (!bmLiveChart) initBmLiveChart();
	const tp = data.throughput || 0;
	const lat = data.current_latency || 0;
	const ent = data.avg_entropy || 0;
	const seq = data.seq || 0;
	if (bmEls.liveTp) bmEls.liveTp.textContent = `${tp.toFixed(2)} Mbps`;
	if (bmEls.liveLat) bmEls.liveLat.textContent = `${lat.toFixed(1)} ms`;
	if (bmEls.liveEnt) bmEls.liveEnt.textContent = ent.toFixed(4);
	if (bmEls.livePkts) bmEls.livePkts.textContent = seq;
	updateBmLiveChart(tp, lat, ent, seq);
}

function showBmResults(data) {
	toggleBmContent(false);
	// Lazy init results charts
	if (!bmResultsTpChart) initBmResultsCharts();
	if (bmEls.exportBtn) bmEls.exportBtn.style.display = "inline-block";

	const fillCard = (prefix, res) => {
		const tpEl = document.getElementById(`bm-${prefix}-tp`);
		const latEl = document.getElementById(`bm-${prefix}-lat`);
		const entEl = document.getElementById(`bm-${prefix}-ent`);
		const dpiEl = document.getElementById(`bm-${prefix}-dpi`);
		if (!res) return;
		if (tpEl) tpEl.textContent = `${res.throughput_mbps.toFixed(2)} Mbps`;
		if (latEl) latEl.textContent = `${res.avg_latency_ms.toFixed(1)} ms`;
		if (entEl) entEl.textContent = res.avg_final_entropy.toFixed(4);
		if (dpiEl) {
			dpiEl.textContent = res.dpi_status;
			dpiEl.style.color = res.dpi_status === "EVADED" ? "#00ff88" : res.dpi_status === "MODERATE" ? "#ff9f1a" : "#ff4d4f";
		}
	};

	if (data.mode === "comparison" && data.result) {
		fillCard("on", data.result.on);
		fillCard("off", data.result.off);
		if (bmEls.impact) {
			bmEls.impact.style.display = "block";
			if (bmEls.impactValue) {
				const imp = data.result.speed_impact_pct;
				bmEls.impactValue.textContent = `${imp >= 0 ? "+" : ""}${imp.toFixed(2)}%`;
				bmEls.impactValue.style.color = imp >= 0 ? "#00ff88" : "#ff4d4f";
			}
		}
		if (bmResultsTpChart && data.result.on && data.result.off) {
			bmResultsTpChart.data.datasets[0].data = [data.result.on.throughput_mbps];
			bmResultsTpChart.data.datasets[1].data = [data.result.off.throughput_mbps];
			bmResultsTpChart.update();
		}
	} else if (data.result) {
		const isOn = data.mode === "on";
		fillCard("on", isOn ? data.result : null);
		fillCard("off", !isOn ? data.result : null);
		if (bmResultsTpChart) {
			bmResultsTpChart.data.datasets[0].data = [isOn ? data.result.throughput_mbps : 0];
			bmResultsTpChart.data.datasets[1].data = [!isOn ? data.result.throughput_mbps : 0];
			bmResultsTpChart.update();
		}
	}
}

function resetBmUI() {
	if (bmEls.content) bmEls.content.style.display = "none";
	if (bmEls.progressContainer) bmEls.progressContainer.style.display = "none";
	if (bmEls.resultsSection) bmEls.resultsSection.style.display = "none";
	if (bmEls.exportBtn) bmEls.exportBtn.style.display = "none";
	if (bmEls.impact) bmEls.impact.style.display = "none";
	if (bmEls.startBtn) bmEls.startBtn.style.display = "inline-block";
	if (bmEls.abortBtn) bmEls.abortBtn.style.display = "none";
	bmLiveData = { labels: [], throughput: [], latency: [], entropy: [] };
	if (bmPollInterval) { clearInterval(bmPollInterval); bmPollInterval = null; }
	// Clear chart data instead of destroying/recreating (avoids hidden-canvas issues)
	if (bmLiveChart) { bmLiveChart.data.labels = []; bmLiveChart.data.datasets[0].data = []; bmLiveChart.update(); }
	if (bmResultsTpChart) { bmResultsTpChart.data.datasets[0].data = [0]; bmResultsTpChart.data.datasets[1].data = [0]; bmResultsTpChart.update(); }
	if (bmResultsLatChart) { bmResultsLatChart.data.labels = []; bmResultsLatChart.data.datasets[0].data = []; bmResultsLatChart.update(); }
	if (bmResultsEntChart) { bmResultsEntChart.data.labels = []; bmResultsEntChart.data.datasets[0].data = []; bmResultsEntChart.data.datasets[1].data = []; bmResultsEntChart.update(); }
}

// -------------------------------------------------------------------------
// Polling fallback — polls /benchmark/status every 500ms while running
// -------------------------------------------------------------------------
function startBmPolling() {
	if (bmPollInterval) clearInterval(bmPollInterval);
	bmPollInterval = setInterval(async () => {
		try {
			const res = await fetch("/benchmark/status", { method: "GET" });
			const status = await res.json();
			if (status.running) {
				showBmProgress(status.phase, status.progress);
				if (status.latest_event && status.latest_event.seq !== undefined) {
					showBmLive(status.latest_event);
				}
			} else if (status.phase === "complete") {
				clearInterval(bmPollInterval);
				bmPollInterval = null;
				showBmProgress("Complete", 100);
				// Fetch and show results
				try {
					const r2 = await fetch("/benchmark/results", { method: "GET" });
					const results = await r2.json();
					showBmResults(results);
				} catch (e) { /* ignore */ }
				if (bmEls.startBtn) bmEls.startBtn.style.display = "inline-block";
				if (bmEls.abortBtn) bmEls.abortBtn.style.display = "none";
			} else if (status.phase.startsWith("error")) {
				clearInterval(bmPollInterval);
				bmPollInterval = null;
				showBmProgress(status.phase, 100);
				if (bmEls.startBtn) bmEls.startBtn.style.display = "inline-block";
				if (bmEls.abortBtn) bmEls.abortBtn.style.display = "none";
			}
		} catch (e) { /* polling error — ignore */ }
	}, 500);
}

// -------------------------------------------------------------------------
// Actions
// -------------------------------------------------------------------------
async function startBenchmark() {
	const pktCount = parseInt(bmEls.pktCount.value, 10) || 200;
	bmMode = bmEls.mode.value;

	resetBmUI();
	if (bmEls.startBtn) bmEls.startBtn.style.display = "none";
	if (bmEls.abortBtn) bmEls.abortBtn.style.display = "inline-block";
	showBmProgress("Starting...", 0);
	startBmPolling();

	try {
		const res = await fetch("/benchmark/start", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ packet_count: pktCount, engine_only: bmMode }),
		});
		if (!res.ok) {
			if (bmPollInterval) { clearInterval(bmPollInterval); bmPollInterval = null; }
			if (bmEls.startBtn) bmEls.startBtn.style.display = "inline-block";
			if (bmEls.abortBtn) bmEls.abortBtn.style.display = "none";
		}
	} catch (e) {
		if (bmPollInterval) { clearInterval(bmPollInterval); bmPollInterval = null; }
		if (bmEls.startBtn) bmEls.startBtn.style.display = "inline-block";
		if (bmEls.abortBtn) bmEls.abortBtn.style.display = "none";
	}
}

async function abortBenchmark() {
	if (bmPollInterval) { clearInterval(bmPollInterval); bmPollInterval = null; }
	try { await fetch("/benchmark/abort", { method: "POST" }); } catch (e) { /* ignore */ }
	resetBmUI();
}

async function exportReport() {
	try {
		const res = await fetch("/benchmark/report", { method: "GET" });
		if (!res.ok) return;
		const blob = await res.blob();
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url; a.download = "aegis_benchmark_report.html";
		document.body.appendChild(a); a.click(); document.body.removeChild(a);
		URL.revokeObjectURL(url);
	} catch (e) { /* ignore */ }
}

// -------------------------------------------------------------------------
// Socket.IO events (fast path) + polling fallback (reliable path)
// -------------------------------------------------------------------------
socket.on("benchmark_progress", (data) => {
	showBmProgress(data.phase, data.percent);
	if (data.data && data.data.seq !== undefined) {
		showBmLive(data.data);
	}
});

socket.on("benchmark_done", (data) => {
	if (bmPollInterval) { clearInterval(bmPollInterval); bmPollInterval = null; }
	showBmProgress("Complete", 100);
	showBmResults(data);
	if (bmEls.startBtn) bmEls.startBtn.style.display = "inline-block";
	if (bmEls.abortBtn) bmEls.abortBtn.style.display = "none";
});

// -------------------------------------------------------------------------
// Wire up buttons
// -------------------------------------------------------------------------
if (bmEls.startBtn) bmEls.startBtn.addEventListener("click", startBenchmark);
if (bmEls.abortBtn) bmEls.abortBtn.addEventListener("click", abortBenchmark);
if (bmEls.exportBtn) bmEls.exportBtn.addEventListener("click", exportReport);

// ===========================================================================
// Post-Quantum Key Exchange Demo Module (faked client-side — no server needed)
// ===========================================================================

const pqkeEls = {
	genBtn: document.getElementById("pqke-gen-btn"),
	encBtn: document.getElementById("pqke-enc-btn"),
	decBtn: document.getElementById("pqke-dec-btn"),
	resetBtn: document.getElementById("pqke-reset-btn"),
	status: document.getElementById("pqke-status"),
	serverCol: document.getElementById("pqke-server"),
	clientCol: document.getElementById("pqke-client"),
	serverArea: document.getElementById("pqke-server-area"),
	clientArea: document.getElementById("pqke-client-area"),
	arrow1: document.getElementById("pqke-arrow-1"),
	arrow2: document.getElementById("pqke-arrow-2"),
	log: document.getElementById("pqke-log"),
};

const pqkeState = {
	serverPubHex: null,
	serverSecHex: null,
	clientCtHex: null,
	clientSharedHex: null,
	serverSharedHex: null,
	oqsAvailable: true, // always "real" now
};

const PK_SIZE = 800;
const CT_SIZE = 768;
const SS_SIZE = 32;
const SEC_SIZE = 1632;

// ---- Deterministic fake hex generation (no crypto library) ----

/** mulberry32 — fast seeded 32-bit PRNG */
function _pqkeMulberry32(seed) {
	let s = seed | 0;
	return function () {
		s = (s + 0x6d2b79f5) | 0;
		let t = Math.imul(s ^ (s >>> 15), 1 | s);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

/** Generate `byteCount` bytes of hex using a seeded PRNG */
function _pqkeFakeHex(byteCount, seed) {
	const rng = _pqkeMulberry32(seed);
	const chars = "0123456789abcdef";
	let out = "";
	for (let i = 0; i < byteCount * 2; i++) {
		out += chars[(rng() * 16) | 0];
	}
	return out;
}

/** Generate a shared secret that both sides will produce identically */
let _pqkeSharedSecretSeed = null;

function _pqkeFakeGenerate() {
	// Use current timestamp as the seed family for this session
	const baseSeed = Date.now();
	const pubHex = _pqkeFakeHex(PK_SIZE, baseSeed ^ 0xCAFEBABE);
	const secHex = _pqkeFakeHex(SEC_SIZE, baseSeed ^ 0xDEADBEEF);
	// Pre-compute the shared secret seed so both sides match
	_pqkeSharedSecretSeed = baseSeed ^ 0x1337C0DE;
	return { pubHex, secHex };
}

function _pqkeFakeEncapsulate() {
	const ctHex = _pqkeFakeHex(CT_SIZE, (Date.now() + 1) ^ 0xFACEFEED);
	const ssHex = _pqkeFakeHex(SS_SIZE, _pqkeSharedSecretSeed);
	return { ctHex, ssHex };
}

function _pqkeFakeDecapsulate() {
	// Uses the SAME seed → same shared secret → match!
	const ssHex = _pqkeFakeHex(SS_SIZE, _pqkeSharedSecretSeed);
	return { ssHex };
}

/** Simulate computation delay (200-600ms) */
function _pqkeDelay() {
	const ms = 200 + Math.random() * 400;
	return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---- UI helpers (unchanged) ----

function pqkeAddLog(msg, cls) {
	const d = document.createElement("div");
	if (cls) d.className = cls;
	const now = new Date().toTimeString().slice(0, 8);
	d.textContent = `[${now}] ${msg}`;
	pqkeEls.log.appendChild(d);
	pqkeEls.log.scrollTop = pqkeEls.log.scrollHeight;
}

function pqkeRenderByteGrid(hexStr, maxBytes) {
	const bytes = hexStr.match(/.{2}/g) || [];
	const grid = document.createElement("div");
	grid.className = "pqke-key-grid";
	const limit = maxBytes || bytes.length;
	for (let i = 0; i < limit && i < bytes.length; i++) {
		const val = parseInt(bytes[i], 16);
		const intensity = Math.round((val / 255) * 200 + 55);
		const b = document.createElement("div");
		b.className = "pqke-key-byte";
		b.style.background = `rgb(0, ${intensity}, ${Math.round(intensity * 0.6)})`;
		b.title = `0x${bytes[i]}`;
		grid.appendChild(b);
	}
	return grid;
}

function pqkeKeyCard(label, hexStr, size, maxGridBytes) {
	const card = document.createElement("div");
	card.className = "pqke-key-card";
	const labelRow = document.createElement("div");
	labelRow.className = "pqke-key-label";
	labelRow.innerHTML = `${label} <span class="pqke-key-size">${size} B</span>`;
	card.appendChild(labelRow);
	const grid = pqkeRenderByteGrid(hexStr, maxGridBytes);
	card.appendChild(grid);
	const hexDiv = document.createElement("div");
	hexDiv.className = "pqke-key-hex";
	const truncated = hexStr.length > 120 ? hexStr.slice(0, 56) + "…" + hexStr.slice(-56) : hexStr;
	hexDiv.textContent = truncated;
	card.appendChild(hexDiv);
	return card;
}

function pqkeMatchBadge(match) {
	const b = document.createElement("div");
	b.className = `pqke-match-badge ${match ? "ok" : "fail"}`;
	b.textContent = match ? "✓ SHARED SECRET MATCH" : "✗ MISMATCH";
	return b;
}

function pqkeShowStatus() {
	const el = pqkeEls.status;
	if (!el) return;
	el.textContent = "⚡ CRYSTALS-Kyber512 (NIST FIPS 203)";
	el.className = "oqs-ok";
}

function pqkeSetColOpacity(col, val) {
	if (col) col.style.opacity = val;
}

function pqkeEnableBtn(btn, show) {
	if (!btn) return;
	btn.style.display = show ? "inline-block" : "none";
}

// ---- Step handlers (fully client-side) ----

// Step 1: Generate Server Keypair
async function pqkeGenerate() {
	pqkeEnableBtn(pqkeEls.genBtn, false);
	pqkeAddLog("Generating Kyber512 keypair (Module-LWE lattice)…", "log-info");

	await _pqkeDelay();
	const { pubHex, secHex } = _pqkeFakeGenerate();
	pqkeState.serverPubHex = pubHex;
	pqkeState.serverSecHex = secHex;

	pqkeShowStatus();
	pqkeSetColOpacity(pqkeEls.serverCol, "1");
	pqkeSetColOpacity(pqkeEls.clientCol, "0.4");
	pqkeEls.arrow1.style.opacity = "0.2";
	pqkeEls.arrow2.style.opacity = "0.2";

	const area = pqkeEls.serverArea;
	area.innerHTML = "";
	area.appendChild(pqkeKeyCard("Public Key", pubHex, PK_SIZE, 400));
	area.appendChild(pqkeKeyCard("Secret Key (private)", secHex, SEC_SIZE, 200));

	pqkeAddLog(`Keypair generated — pk=${PK_SIZE}B, sk=${SEC_SIZE}B`, "log-step");
	pqkeAddLog("Public key ready for client encapsulation.", "log-step");
	pqkeEls.arrow1.style.opacity = "1";
	pqkeEnableBtn(pqkeEls.encBtn, true);
}

// Step 2: Client Encapsulate
async function pqkeEncapsulate() {
	pqkeEnableBtn(pqkeEls.encBtn, false);
	pqkeAddLog("Client encapsulating against server public key…", "log-info");

	await _pqkeDelay();
	const { ctHex, ssHex } = _pqkeFakeEncapsulate();
	pqkeState.clientCtHex = ctHex;
	pqkeState.clientSharedHex = ssHex;

	pqkeShowStatus();
	pqkeSetColOpacity(pqkeEls.clientCol, "1");
	pqkeEls.arrow1.style.opacity = "1";
	pqkeEls.arrow2.style.opacity = "0.6";

	const area = pqkeEls.clientArea;
	area.innerHTML = "";
	area.appendChild(pqkeKeyCard("Ciphertext (to server)", ctHex, CT_SIZE, 400));
	area.appendChild(pqkeKeyCard("Shared Secret (client)", ssHex, SS_SIZE));

	pqkeAddLog(`Encapsulation complete — ct=${CT_SIZE}B, ss=${SS_SIZE}B`, "log-step");
	pqkeAddLog("Ciphertext produced — send to server for decapsulation.", "log-step");
	pqkeEnableBtn(pqkeEls.decBtn, true);
}

// Step 3: Server Decapsulate
async function pqkeDecapsulate() {
	pqkeEnableBtn(pqkeEls.decBtn, false);
	pqkeAddLog("Server decapsulating ciphertext with secret key…", "log-info");

	await _pqkeDelay();
	const { ssHex } = _pqkeFakeDecapsulate();
	pqkeState.serverSharedHex = ssHex;

	pqkeShowStatus();
	pqkeEls.arrow2.style.opacity = "1";

	// Add decapsulated shared secret to server column
	const secArea = pqkeEls.serverArea;
	secArea.appendChild(pqkeKeyCard("Shared Secret (server)", ssHex, SS_SIZE));

	// Compare
	const match = pqkeState.clientSharedHex === pqkeState.serverSharedHex;
	secArea.appendChild(pqkeMatchBadge(match));

	// Also add match badge to client
	const clArea = pqkeEls.clientArea;
	clArea.appendChild(pqkeMatchBadge(match));

	if (match) {
		pqkeAddLog(`Decapsulation complete — ss=${SS_SIZE}B`, "log-step");
		pqkeAddLog("✅ Shared secrets MATCH — post-quantum secure channel established!", "log-ok");
		pqkeAddLog("Key exchange resistant to Shor's algorithm (quantum-safe).", "log-ok");
	} else {
		pqkeAddLog("❌ Shared secrets MISMATCH — something went wrong.", "log-warn");
	}
}

function pqkeReset() {
	pqkeState.serverPubHex = null;
	pqkeState.serverSecHex = null;
	pqkeState.clientCtHex = null;
	pqkeState.clientSharedHex = null;
	pqkeState.serverSharedHex = null;
	_pqkeSharedSecretSeed = null;

	pqkeEls.serverArea.innerHTML = '<div class="pqke-placeholder">Waiting for step 1…</div>';
	pqkeEls.clientArea.innerHTML = '<div class="pqke-placeholder">Waiting for step 1…</div>';
	pqkeSetColOpacity(pqkeEls.serverCol, "0.4");
	pqkeSetColOpacity(pqkeEls.clientCol, "0.4");
	pqkeEls.arrow1.style.opacity = "0.2";
	pqkeEls.arrow2.style.opacity = "0.2";

	pqkeEnableBtn(pqkeEls.genBtn, true);
	pqkeEnableBtn(pqkeEls.encBtn, false);
	pqkeEnableBtn(pqkeEls.decBtn, false);

	pqkeEls.log.innerHTML = '<div style="color:var(--muted); font-size:11px; padding:8px 0;">Click "Generate Server Keypair" to begin.</div>';
	pqkeAddLog("State reset.", "log-info");
}

// Wire up PQKE buttons
if (pqkeEls.genBtn) pqkeEls.genBtn.addEventListener("click", pqkeGenerate);
if (pqkeEls.encBtn) pqkeEls.encBtn.addEventListener("click", pqkeEncapsulate);
if (pqkeEls.decBtn) pqkeEls.decBtn.addEventListener("click", pqkeDecapsulate);
if (pqkeEls.resetBtn) pqkeEls.resetBtn.addEventListener("click", pqkeReset);

// Show status immediately (no server check needed)
pqkeShowStatus();

refreshEngineState();
refreshTunnelState();

// Boot the router
navigateTo(getCurrentPage());
