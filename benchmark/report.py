import base64
import json
import os
import statistics
from typing import Optional

from benchmark.metrics import BenchmarkResult, ComparisonResult

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Aegis-Tunnel X — Benchmark Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  background:#0a0e0c; color:#b6ffe0; font-family:'JetBrains Mono','Consolas',monospace;
  padding:30px; max-width:1100px; margin:auto;
}}
h1 {{ color:#00ff88; font-size:20px; letter-spacing:3px; text-transform:uppercase; margin-bottom:4px; }}
h2 {{ color:#b6ffe0; font-size:14px; letter-spacing:2px; text-transform:uppercase; margin:24px 0 12px;
      border-bottom:1px solid rgba(0,255,136,0.15); padding-bottom:6px; }}
.subtitle {{ color:#5ea882; font-size:10px; margin-bottom:20px; letter-spacing:1.5px; }}
.summary-grid {{
  display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:20px;
}}
.summary-card {{
  background:rgba(0,255,136,0.04); border:1px solid rgba(0,255,136,0.15); border-radius:8px;
  padding:16px; border-left:3px solid #00ff88;
}}
.summary-card.danger {{ border-left-color:#ff4d4f; }}
.summary-card.warn {{ border-left-color:#ff9f1a; }}
.card-label {{ font-size:9px; color:#5ea882; letter-spacing:1.8px; text-transform:uppercase; }}
.card-value {{ font-size:28px; font-weight:700; color:#00ff88; margin:4px 0; }}
.card-value.danger {{ color:#ff4d4f; }}
.card-value.warn {{ color:#ff9f1a; }}
.card-sub {{ font-size:10px; color:#5ea882; }}
.chart-container {{ background:rgba(0,255,136,0.02); border:1px solid rgba(0,255,136,0.1); border-radius:8px; padding:14px; margin-bottom:16px; }}
.chart-container canvas {{ height:220px !important; }}
.comparison-row {{
  display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px;
}}
.comp-card {{
  border-radius:8px; padding:14px; border:1px solid rgba(0,255,136,0.12);
}}
.comp-card.on {{ background:rgba(0,255,136,0.06); }}
.comp-card.off {{ background:rgba(255,77,79,0.06); border-color:rgba(255,77,79,0.2); }}
.comp-header {{ font-size:10px; letter-spacing:2px; text-transform:uppercase; margin-bottom:8px; }}
.comp-stat {{ display:flex; justify-content:space-between; padding:4px 0; font-size:11px; }}
.comp-stat .label {{ color:#5ea882; }}
.comp-stat .value {{ color:#b6ffe0; font-weight:600; }}
.score-meter {{
  width:100%; height:12px; background:rgba(0,255,136,0.08); border-radius:6px; overflow:hidden; margin:8px 0;
}}
.score-fill {{ height:100%; border-radius:6px; transition:width 0.5s ease; }}
.score-fill.safe {{ background:linear-gradient(90deg,#00ff88,#00cc6a); }}
.score-fill.warn {{ background:linear-gradient(90deg,#ff9f1a,#ffb84d); }}
.score-fill.danger {{ background:linear-gradient(90deg,#ff4d4f,#ff7875); }}
.footer {{ margin-top:30px; padding-top:16px; border-top:1px solid rgba(0,255,136,0.1); font-size:9px; color:#5ea882; text-align:center; letter-spacing:1px; }}
table {{ width:100%; border-collapse:collapse; font-size:11px; }}
td, th {{ padding:6px 10px; border-bottom:1px solid rgba(0,255,136,0.06); text-align:left; }}
th {{ color:#5ea882; font-size:9px; letter-spacing:1.5px; text-transform:uppercase; }}
td {{ color:#b6ffe0; }}
.tag {{
  display:inline-block; padding:2px 8px; border-radius:3px; font-size:9px; font-weight:700; letter-spacing:1px;
}}
.tag.evaded {{ background:rgba(0,255,136,0.12); color:#00ff88; border:1px solid #00ff88; }}
.tag.detected {{ background:rgba(255,77,79,0.12); color:#ff4d4f; border:1px solid #ff4d4f; }}
.tag.moderate {{ background:rgba(255,159,26,0.12); color:#ff9f1a; border:1px solid #ff9f1a; }}
</style>
</head>
<body>

<h1>⏱ AEGIS-TUNNEL X — BENCHMARK REPORT</h1>
<div class="subtitle">Generated {date} • {packet_count} packets • {mode_label}</div>

<div class="summary-grid">
  <div class="summary-card">
    <div class="card-label">Throughput</div>
    <div class="card-value">{throughput}</div>
    <div class="card-sub">with Morphic Engine</div>
  </div>
  <div class="summary-card {dpi_card_class}">
    <div class="card-label">DPI Evasion Status</div>
    <div class="card-value {dpi_value_class}">{dpi_status}</div>
    <div class="card-sub">Score: {dpi_score}</div>
  </div>
  <div class="summary-card">
    <div class="card-label">Avg Latency</div>
    <div class="card-value">{latency}</div>
    <div class="card-sub">P95: {p95_latency} • Jitter: {jitter}</div>
  </div>
  <div class="summary-card">
    <div class="card-label">Entropy Reduction</div>
    <div class="card-value">{entropy_reduction}</div>
    <div class="card-sub">{raw_entropy} → {final_entropy} (raw → morphed)</div>
  </div>
</div>

{overhead_html}

<h2>Engine Comparison: ON vs OFF</h2>
<div class="comparison-row">
  <div class="comp-card on">
    <div class="comp-header" style="color:#00ff88;">🟢 Morphic Engine ON</div>
    <div class="comp-stat"><span class="label">Throughput</span><span class="value">{on_throughput}</span></div>
    <div class="comp-stat"><span class="label">Avg Latency</span><span class="value">{on_latency}</span></div>
    <div class="comp-stat"><span class="label">Avg Entropy</span><span class="value">{on_entropy}</span></div>
    <div class="comp-stat"><span class="label">DPI Status</span><span class="value">{on_dpi}</span></div>
  </div>
  <div class="comp-card off">
    <div class="comp-header" style="color:#ff4d4f;">🔴 Morphic Engine OFF</div>
    <div class="comp-stat"><span class="label">Throughput</span><span class="value">{off_throughput}</span></div>
    <div class="comp-stat"><span class="label">Avg Latency</span><span class="value">{off_latency}</span></div>
    <div class="comp-stat"><span class="label">Avg Entropy</span><span class="value">{off_entropy}</span></div>
    <div class="comp-stat"><span class="label">DPI Status</span><span class="value">{off_dpi}</span></div>
  </div>
</div>

{h2_comparison_highlight}

<div class="chart-container">
  <h2>Throughput Comparison</h2>
  <canvas id="throughputChart"></canvas>
</div>

<div class="chart-container">
  <h2>Latency Distribution</h2>
  <canvas id="latencyChart"></canvas>
</div>

<div class="chart-container">
  <h2>Entropy Over Time</h2>
  <canvas id="entropyChart"></canvas>
</div>

<h2>Per-Packet Details (first 50 samples)</h2>
<div style="max-height:300px; overflow-y:auto; border:1px solid rgba(0,255,136,0.08); border-radius:6px;">
<table>
<tr><th>#</th><th>Size (B)</th><th>Padding</th><th>Entropy</th><th>Latency (ms)</th><th>Sent</th></tr>
{table_rows}
</table>
</div>

<div class="footer">
  Aegis-Tunnel X — Post-Quantum VPN Tunnel • AES-256-GCM • CRYSTALS-Kyber512 • Morphic Engine
</div>

<script>
const throughputData = {throughput_chart_json};
const latencyData = {latency_chart_json};
const entropyData = {entropy_chart_json};

new Chart(document.getElementById('throughputChart'), {{
  type: 'bar', data: {{
    labels: throughputData.labels,
    datasets: [
      {{ label: 'Engine ON', data: throughputData.on_values, backgroundColor: 'rgba(0,255,136,0.6)', borderColor: '#00ff88', borderWidth: 1 }},
      {{ label: 'Engine OFF', data: throughputData.off_values, backgroundColor: 'rgba(255,77,79,0.6)', borderColor: '#ff4d4f', borderWidth: 1 }}
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ labels: {{ color: '#b6ffe0', font: {{ family: 'JetBrains Mono', size: 10 }} }} }} }},
    scales: {{
      y: {{ beginAtZero: true, grid: {{ color: 'rgba(0,255,136,0.1)' }}, ticks: {{ color: '#5ea882', font: {{ family: 'JetBrains Mono', size: 10 }} }} }},
      x: {{ grid: {{ display: false }}, ticks: {{ color: '#5ea882', font: {{ family: 'JetBrains Mono', size: 9 }} }} }}
    }}
  }}
}});

new Chart(document.getElementById('latencyChart'), {{
  type: 'bar', data: {{
    labels: latencyData.labels,
    datasets: [{{
      label: 'Count',
      data: latencyData.values,
      backgroundColor: 'rgba(0,255,136,0.4)',
      borderColor: '#00ff88',
      borderWidth: 1
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ beginAtZero: true, grid: {{ color: 'rgba(0,255,136,0.1)' }}, ticks: {{ color: '#5ea882', font: {{ family: 'JetBrains Mono', size: 10 }} }} }},
      x: {{ grid: {{ display: false }}, ticks: {{ color: '#5ea882', font: {{ family: 'JetBrains Mono', size: 9 }}, maxRotation: 45 }} }}
    }}
  }}
}});

new Chart(document.getElementById('entropyChart'), {{
  type: 'line', data: {{
    labels: entropyData.labels,
    datasets: [
      {{ label: 'Raw Entropy', data: entropyData.raw_values, borderColor: '#ff9f1a', backgroundColor: 'rgba(255,159,26,0.1)', borderWidth: 1.5, tension: 0.3, pointRadius: 0, fill: true }},
      {{ label: 'Final Entropy', data: entropyData.final_values, borderColor: '#00ff88', backgroundColor: 'rgba(0,255,136,0.1)', borderWidth: 1.5, tension: 0.3, pointRadius: 0, fill: true }}
    ]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{
      legend: {{ labels: {{ color: '#b6ffe0', font: {{ family: 'JetBrains Mono', size: 10 }} }} }}
    }},
    scales: {{
      y: {{ min: 3, max: 8.2, grid: {{ color: 'rgba(0,255,136,0.1)' }}, ticks: {{ color: '#5ea882', font: {{ family: 'JetBrains Mono', size: 10 }} }} }},
      x: {{ display: false }}
    }}
  }}
}});
</script>
</body>
</html>
"""


class ReportGenerator:
    @staticmethod
    def generate(result: BenchmarkResult, comparison: Optional[ComparisonResult] = None) -> str:
        now = __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        samples = result.samples or []
        comparison = comparison or ComparisonResult(on=result, off=None)

        on_result = comparison.on or result
        off_result = comparison.off

        tp = on_result.throughput_mbps
        tp_label = f"{tp:.2f} Mbps" if tp < 1000 else f"{tp / 1000:.2f} Gbps"

        dpi_tag = on_result.dpi_status
        dpi_card_cls = "danger" if dpi_tag == "DETECTED" else "warn" if dpi_tag == "MODERATE" else ""
        dpi_val_cls = "danger" if dpi_tag == "DETECTED" else "warn" if dpi_tag == "MODERATE" else ""

        mode_label = "Morphic Engine ON" if result.engine_on else "Morphic Engine OFF"

        overhead_html = ""
        if on_result.overhead_pct > 0:
            overhead_html = f"""
<div class="summary-grid">
  <div class="summary-card">
    <div class="card-label">Total Data Sent</div>
    <div class="card-value">{_fmt_bytes(on_result.total_data_sent_bytes)}</div>
    <div class="card-sub">{on_result.packet_count} packets</div>
  </div>
  <div class="summary-card warn">
    <div class="card-label">Overhead (Padding)</div>
    <div class="card-value warn">{on_result.overhead_pct}%</div>
    <div class="card-sub">{_fmt_bytes(on_result.total_padding_bytes)} total padding</div>
  </div>
</div>"""

        # Comparison highlight
        h2_comp = ""
        if off_result:
            h2_comp = f"""
<div style="background:rgba(0,255,136,0.04);border:1px solid rgba(0,255,136,0.15);border-radius:8px;padding:14px;margin-bottom:16px;">
  <div style="font-size:10px;color:#5ea882;letter-spacing:1.5px;text-transform:uppercase;">Speed Impact</div>
  <div style="font-size:22px;font-weight:700;color:#00ff88;">{comparison.speed_impact_pct:+.2f}%</div>
  <div style="font-size:10px;color:#5ea882;">Throughput change with engine ON vs OFF</div>
</div>"""

        # Latency distribution histogram bins
        off_samples = off_result.samples if off_result and hasattr(off_result, 'samples') else []
        latency_bins = _bin_latencies(
            [s["total_time_ms"] for s in samples] +
            ([s["total_time_ms"] for s in off_samples] if off_samples else [])
        )

        # Table rows
        table_rows = ""
        for s in samples[:50]:
            cls = ""
            sent_mark = "✓" if s.get("sent_ok") else "✗"
            table_rows += f"<tr><td>{s['seq']}</td><td>{s['wire_size']}</td><td>+{s['padding_size']}B</td><td>{s['final_entropy']}</td><td>{s['total_time_ms']}</td><td style='color:#00ff88'>{sent_mark}</td></tr>\n"

        tp_chart = _throughput_chart_data(on_result, off_result)
        lat_chart = _latency_chart_data(on_result, off_result)
        ent_chart = _entropy_chart_data(on_result, off_result)

        return REPORT_TEMPLATE.format(
            date=now,
            packet_count=result.packet_count,
            mode_label=mode_label,
            throughput=tp_label,
            dpi_card_class=dpi_card_cls,
            dpi_value_class=dpi_val_cls,
            dpi_status=dpi_tag,
            dpi_score=f"{on_result.dpi_evasion_score:.3f}",
            latency=f"{on_result.avg_latency_ms:.1f} ms",
            p95_latency=f"{on_result.p95_latency_ms:.1f} ms",
            jitter=f"{on_result.jitter_ms:.1f} ms",
            entropy_reduction=f"{on_result.entropy_reduction_pct:.1f}%",
            raw_entropy=f"{on_result.avg_raw_entropy:.4f}",
            final_entropy=f"{on_result.avg_final_entropy:.4f}",
            overhead_html=overhead_html,
            on_throughput=comparison.throughput_comparison()["on_label"],
            on_latency=f"{on_result.avg_latency_ms:.1f} ms",
            on_entropy=f"{on_result.avg_final_entropy:.4f}",
            on_dpi=on_result.dpi_status,
            off_throughput=comparison.throughput_comparison()["off_label"],
            off_latency=f"{off_result.avg_latency_ms:.1f} ms" if off_result else "N/A",
            off_entropy=f"{off_result.avg_final_entropy:.4f}" if off_result else "N/A",
            off_dpi=off_result.dpi_status if off_result else "N/A",
            h2_comparison_highlight=h2_comp,
            table_rows=table_rows,
            throughput_chart_json=json.dumps(tp_chart),
            latency_chart_json=json.dumps(lat_chart),
            entropy_chart_json=json.dumps(ent_chart),
        )


def _fmt_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    else:
        return f"{b / (1024 * 1024):.2f} MB"


def _bin_latencies(all_latencies):
    if not all_latencies:
        return {"labels": [], "values": []}
    max_lat = max(all_latencies)
    bin_count = max(10, min(20, len(all_latencies) // 5))
    bin_size = max(max_lat / bin_count, 0.1)
    bins = [0] * bin_count
    labels = []
    for v in all_latencies:
        idx = min(int(v / bin_size), bin_count - 1)
        bins[idx] += 1
    for i in range(bin_count):
        lo = round(i * bin_size, 1)
        hi = round((i + 1) * bin_size, 1)
        labels.append(f"{lo}-{hi}")
    return {"labels": labels, "values": bins}


def _throughput_chart_data(on_res, off_res=None):
    labels = ["Throughput (Mbps)"]
    on_val = on_res.throughput_mbps if on_res else 0
    off_val = off_res.throughput_mbps if off_res else 0
    return {"labels": labels, "on_values": [round(on_val, 2)], "off_values": [round(off_val, 2)]}


def _latency_chart_data(on_res, off_res=None):
    all_lat = []
    if on_res and hasattr(on_res, 'samples') and on_res.samples:
        all_lat.extend([s["total_time_ms"] for s in on_res.samples])
    if off_res and hasattr(off_res, 'samples') and off_res.samples:
        all_lat.extend([s["total_time_ms"] for s in off_res.samples])

    if not all_lat:
        return {"labels": [], "values": []}

    max_lat = max(all_lat) or 1
    bin_count = 15
    bin_size = max_lat / bin_count
    bins = [0] * bin_count
    labels = []
    for v in all_lat:
        idx = min(int(v / bin_size), bin_count - 1)
        bins[idx] += 1
    for i in range(bin_count):
        lo = round(i * bin_size, 1)
        hi = round((i + 1) * bin_size, 1)
        labels.append(f"{lo}")
    return {"labels": labels, "values": bins}


def _entropy_chart_data(on_res, off_res=None):
    labels = []
    raw_values = []
    final_values = []

    on_samp = on_res.samples if on_res and hasattr(on_res, 'samples') else []
    off_samp = off_res.samples if off_res and hasattr(off_res, 'samples') else []
    samples = on_samp + off_samp
    samples_sorted = sorted(samples, key=lambda s: s["seq"])
    for s in samples_sorted:
        labels.append(f"#{s['seq']}")
        raw_values.append(s["raw_entropy"])
        final_values.append(s["final_entropy"])
    return {"labels": labels, "raw_values": raw_values, "final_values": final_values}
