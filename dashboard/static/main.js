const socket = io();
const MAX_POINTS = 40;

const statEls = {
	packets: document.getElementById("s-packets"),
	raw: document.getElementById("s-raw"),
	morphed: document.getElementById("s-morphed"),
	padding: document.getElementById("s-padding"),
	jitter: document.getElementById("s-jitter"),
	engine: document.getElementById("s-engine"),
	sessionKey: document.getElementById("session-key-value"),
};

const logEl = document.getElementById("log-output");
const toggleBtn = document.getElementById("toggle-btn");

let packetCount = 0;
let totalPadding = 0;
let rawSum = 0;
let morphedSum = 0;
let jitterSum = 0;
let engineOn = true;

function trimSeries(chartData) {
	while (chartData.labels.length > MAX_POINTS) {
		chartData.labels.shift();
		for (const ds of chartData.datasets) {
			ds.data.shift();
		}
	}
}

const entropyData = {
	labels: [],
	datasets: [
		{
			label: "Packet Entropy",
			data: [],
			borderColor: "#00ff88",
			backgroundColor: "rgba(0, 255, 136, 0.08)",
			borderWidth: 2,
			tension: 0.25,
			fill: true,
			pointRadius: 0,
		},
	],
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
				grid: { color: "rgba(0, 255, 136, 0.12)" },
				ticks: { color: "#75d4ac", font: { family: "JetBrains Mono", size: 10 } },
			},
			x: { display: false },
		},
		plugins: {
			legend: { display: false },
		},
	},
	plugins: [
		{
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
		},
	],
});

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
			x: {
				stacked: true,
				display: false,
			},
			y: {
				stacked: true,
				grid: { color: "rgba(0, 255, 136, 0.12)" },
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

function formatBytes(value) {
	if (value < 1024) {
		return `${value} B`;
	}
	if (value < 1024 * 1024) {
		return `${(value / 1024).toFixed(1)} KB`;
	}
	return `${(value / (1024 * 1024)).toFixed(2)} MB`;
}

function setEngineUI(on) {
	engineOn = on;
	statEls.engine.textContent = on ? "ON" : "OFF";
	toggleBtn.textContent = on ? "MORPHIC ENGINE: ON" : "MORPHIC ENGINE: OFF";
	toggleBtn.classList.toggle("on", on);
}

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

	logEl.appendChild(row);
	logEl.scrollTop = logEl.scrollHeight;
	if (logEl.children.length > 250) {
		logEl.removeChild(logEl.firstChild);
	}
}

socket.on("packet_event", (data) => {
	packetCount += 1;
	totalPadding += data.padding_size || 0;
	rawSum += data.raw_entropy || 0;
	morphedSum += data.final_entropy || 0;
	jitterSum += data.jitter_ms || 0;

	const label = `#${packetCount}`;

	entropyData.labels.push(label);
	entropyData.datasets[0].data.push(data.final_entropy || 0);
	trimSeries(entropyData);
	entropyChart.update();

	morphData.labels.push(label);
	morphData.datasets[0].data.push(data.original_size || 0);
	morphData.datasets[1].data.push(data.padding_size || 0);
	trimSeries(morphData);
	morphChart.update();

	statEls.packets.textContent = packetCount.toLocaleString();
	statEls.raw.textContent = (rawSum / packetCount).toFixed(4);
	statEls.morphed.textContent = (morphedSum / packetCount).toFixed(4);
	statEls.padding.textContent = formatBytes(totalPadding);
	statEls.jitter.textContent = `${Math.round(jitterSum / packetCount)} ms`;
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

async function refreshEngineState() {
	try {
		const response = await fetch("/engine", { method: "GET" });
		if (!response.ok) {
			return;
		}
		const payload = await response.json();
		setEngineUI(Boolean(payload.engine_on));
	} catch (_err) {
		// Dashboard remains usable even if the state endpoint is unavailable.
	}
}

async function toggleEngine() {
	try {
		const response = await fetch("/toggle", { method: "POST" });
		if (!response.ok) {
			return;
		}
		const payload = await response.json();
		setEngineUI(Boolean(payload.engine_on));
	} catch (_err) {
		// Do not throw in UI callbacks.
	}
}

window.toggleEngine = toggleEngine;
refreshEngineState();
