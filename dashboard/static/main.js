// ===========================================================================
// Aegis-Tunnel X — Dashboard JS  (Multi-Page + Tunnel Controls)
// ===========================================================================

const socket    = io();
const MAX_POINTS = 40;

// ---------------------------------------------------------------------------
// Hash router — five pages: entropy | morphing | telemetry | stats | crypto
// ---------------------------------------------------------------------------
const VALID_PAGES = ["entropy", "morphing", "telemetry", "stats", "chat"];

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

refreshEngineState();
refreshTunnelState();

// Boot the router
navigateTo(getCurrentPage());
