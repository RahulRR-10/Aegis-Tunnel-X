import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  CheckCircle2,
  Network,
  Server,
  ShieldAlert,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import {
  formatBytes,
  formatInteger,
  formatLatency,
} from '../../lib/format.js';

const FALLBACK_TUNNEL = {
  tun: {
    name: 'N/A',
    ip: 'N/A',
    peer_ip: 'N/A',
    mtu: 1400,
    state: 'DOWN',
  },
  bytes_tx: 0,
  bytes_rx: 0,
  pkts_tx: 0,
  pkts_rx: 0,
  avg_latency_ms: 0,
};

function asTunnelPayload(payload) {
  return {
    ...FALLBACK_TUNNEL,
    ...payload,
    tun: {
      ...FALLBACK_TUNNEL.tun,
      ...(payload?.tun || {}),
    },
  };
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function positiveDelta(current, previous, key) {
  return Math.max(0, Number(current?.[key] || 0) - Number(previous?.[key] || 0));
}

function buildChartData(history) {
  if (history.length === 0) {
    return [];
  }

  const newestTs = Number(history[history.length - 1]?.ts) || Date.now() / 1000;
  return history
    .map((frame, index) => {
      const previous = history[index - 1] || frame;
      const dt = Math.max(0.5, Number(frame.ts || 0) - Number(previous.ts || 0));
      const txDelta = positiveDelta(frame, previous, 'bytes_tx');
      const rxDelta = positiveDelta(frame, previous, 'bytes_rx');
      const secondsAgo = Math.max(0, newestTs - Number(frame.ts || newestTs));

      return {
        ts: frame.ts,
        label: `-${secondsAgo.toFixed(0)}s`,
        tx_kbps: Number(((txDelta / dt) / 1024).toFixed(2)),
        rx_kbps: Number(((rxDelta / dt) / 1024).toFixed(2)),
        latency_ms: Number(frame.latency_ms || 0),
      };
    })
    .filter((point) => newestTs - Number(point.ts || newestTs) <= 60);
}

function getLiveRates(chartData) {
  if (chartData.length === 0) {
    return { tx: 0, rx: 0 };
  }

  const recent = chartData.slice(-6);
  const tx = recent.reduce((sum, item) => sum + item.tx_kbps, 0) / recent.length;
  const rx = recent.reduce((sum, item) => sum + item.rx_kbps, 0) / recent.length;
  return { tx, rx };
}

function SectionHeader({ title, children }) {
  return (
    <div className="tunnel-section-header">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

function TunDeviceCard({ tunnel }) {
  const tun = tunnel.tun || FALLBACK_TUNNEL.tun;
  const up = String(tun.state).toUpperCase() === 'UP';

  const rows = [
    ['Name', tun.name],
    ['IP', tun.ip],
    ['Peer', tun.peer_ip],
    ['MTU', `${formatInteger(tun.mtu)} B`],
  ];

  return (
    <div className="tunnel-card tun-device-card">
      <SectionHeader title="TUN Device">
        <span className={`tun-state ${up ? 'is-up' : 'is-down'}`}>
          {up ? <CheckCircle2 aria-hidden="true" size={15} /> : <ShieldAlert aria-hidden="true" size={15} />}
          {up ? 'UP' : 'DOWN'}
        </span>
      </SectionHeader>

      <div className="tun-device-icon">
        <Server aria-hidden="true" size={34} />
      </div>

      <dl className="tun-readouts">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value || 'N/A'}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function PacketFlowDiagram({ rates, stats }) {
  const txActive = rates.tx > 0.05;
  const rxActive = rates.rx > 0.05;
  const txDuration = `${clamp(3.6 - rates.tx / 12, 0.85, 3.6).toFixed(2)}s`;
  const rxDuration = `${clamp(3.6 - rates.rx / 12, 0.85, 3.6).toFixed(2)}s`;

  return (
    <div className="tunnel-card packet-flow-card">
      <SectionHeader title="Live Packet Flow">
        <Network aria-hidden="true" size={18} />
      </SectionHeader>

      <div className="packet-flow-scene">
        <svg viewBox="0 0 760 260" role="img" aria-label="TUN to UDP packet flow diagram">
          <defs>
            <marker id="flow-arrow" markerHeight="8" markerWidth="8" orient="auto" refX="8" refY="4">
              <path d="M0,0 L8,4 L0,8 Z" />
            </marker>
          </defs>

          <rect className="flow-node" height="58" rx="8" width="126" x="34" y="64" />
          <rect className="flow-node" height="58" rx="8" width="126" x="318" y="64" />
          <rect className="flow-node" height="58" rx="8" width="126" x="600" y="64" />
          <rect className="flow-node" height="58" rx="8" width="126" x="34" y="158" />
          <rect className="flow-node" height="58" rx="8" width="126" x="318" y="158" />
          <rect className="flow-node" height="58" rx="8" width="126" x="600" y="158" />

          <text className="flow-node-label" x="97" y="99">APP</text>
          <text className="flow-node-label" x="381" y="99">ENCRYPT</text>
          <text className="flow-node-label" x="663" y="99">PEER</text>
          <text className="flow-node-label" x="97" y="193">APP</text>
          <text className="flow-node-label" x="381" y="193">DECRYPT</text>
          <text className="flow-node-label" x="663" y="193">PEER</text>

          <path className="flow-path tx" d="M160 93 H318 M444 93 H600" markerEnd="url(#flow-arrow)" />
          <path className="flow-path rx" d="M600 187 H444 M318 187 H160" markerEnd="url(#flow-arrow)" />

          <text className="flow-path-label" x="215" y="79">TUN to UDP</text>
          <text className="flow-path-label" x="468" y="173">UDP to TUN</text>

          {txActive && (
            <>
              <circle className="flow-particle tx" r="5">
                <animateMotion dur={txDuration} path="M160 93 H600" repeatCount="indefinite" />
              </circle>
              <circle className="flow-particle tx tx-delay" r="4">
                <animateMotion begin="0.42s" dur={txDuration} path="M160 93 H600" repeatCount="indefinite" />
              </circle>
            </>
          )}

          {rxActive && (
            <>
              <circle className="flow-particle rx" r="5">
                <animateMotion dur={rxDuration} path="M600 187 H160" repeatCount="indefinite" />
              </circle>
              <circle className="flow-particle rx rx-delay" r="4">
                <animateMotion begin="0.42s" dur={rxDuration} path="M600 187 H160" repeatCount="indefinite" />
              </circle>
            </>
          )}
        </svg>
      </div>

      <div className="flow-rate-strip">
        <span><ArrowUpRight aria-hidden="true" size={15} /> TX {formatBytes(stats.bytes_tx)}</span>
        <span><ArrowDownLeft aria-hidden="true" size={15} /> RX {formatBytes(stats.bytes_rx)}</span>
      </div>
    </div>
  );
}

function EmptyChartState() {
  return <div className="chart-empty-state">waiting for ring buffer</div>;
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) {
    return null;
  }

  return (
    <div className="chart-tooltip">
      <strong>{label}</strong>
      {payload.map((item) => (
        <span key={item.dataKey} style={{ color: item.color }}>
          {item.name}: {Number(item.value).toFixed(2)}
        </span>
      ))}
    </div>
  );
}

function ThroughputChart({ data }) {
  return (
    <div className="tunnel-card chart-card">
      <SectionHeader title="Throughput">
        <span>last 60 s</span>
      </SectionHeader>
      <div className="chart-shell">
        {data.length < 2 ? (
          <EmptyChartState />
        ) : (
          <ResponsiveContainer height="100%" width="100%">
            <AreaChart data={data} margin={{ bottom: 4, left: -18, right: 8, top: 8 }}>
              <defs>
                <linearGradient id="txFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#00ff88" stopOpacity={0.36} />
                  <stop offset="95%" stopColor="#00ff88" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="rxFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#00cfff" stopOpacity={0.34} />
                  <stop offset="95%" stopColor="#00cfff" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(110, 127, 143, 0.16)" vertical={false} />
              <XAxis dataKey="label" minTickGap={24} stroke="#6e7f8f" tick={{ fontSize: 11 }} />
              <YAxis stroke="#6e7f8f" tick={{ fontSize: 11 }} />
              <Tooltip content={<ChartTooltip />} />
              <Area dataKey="tx_kbps" fill="url(#txFill)" name="TX KB/s" stroke="#00ff88" strokeWidth={2} type="monotone" />
              <Area dataKey="rx_kbps" fill="url(#rxFill)" name="RX KB/s" stroke="#00cfff" strokeWidth={2} type="monotone" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

function LatencyChart({ data }) {
  const hasSpike = data.some((point) => point.latency_ms > 50);

  return (
    <div className="tunnel-card chart-card">
      <SectionHeader title="Latency">
        <span className={hasSpike ? 'latency-chip is-spiking' : 'latency-chip'}>
          {hasSpike ? 'spike' : 'stable'}
        </span>
      </SectionHeader>
      <div className="chart-shell">
        {data.length < 2 ? (
          <EmptyChartState />
        ) : (
          <ResponsiveContainer height="100%" width="100%">
            <LineChart data={data} margin={{ bottom: 4, left: -18, right: 8, top: 8 }}>
              <CartesianGrid stroke="rgba(110, 127, 143, 0.16)" vertical={false} />
              <XAxis dataKey="label" minTickGap={24} stroke="#6e7f8f" tick={{ fontSize: 11 }} />
              <YAxis stroke="#6e7f8f" tick={{ fontSize: 11 }} />
              <Tooltip content={<ChartTooltip />} />
              <ReferenceLine stroke="#ffaa00" strokeDasharray="4 4" y={10} />
              <ReferenceLine stroke="#ff4444" strokeDasharray="4 4" y={50} />
              <Line
                dataKey="latency_ms"
                dot={false}
                name="Latency ms"
                stroke={hasSpike ? '#ff4444' : '#00cfff'}
                strokeWidth={2}
                type="monotone"
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

function StatsFooter({ stats }) {
  const items = [
    ['Pkts TX', formatInteger(stats.pkts_tx)],
    ['Pkts RX', formatInteger(stats.pkts_rx)],
    ['Bytes TX', formatBytes(stats.bytes_tx)],
    ['Bytes RX', formatBytes(stats.bytes_rx)],
    ['Avg RTT', formatLatency(stats.avg_latency_ms)],
  ];

  return (
    <div className="tunnel-stats-footer">
      {items.map(([label, value]) => (
        <span key={label}>{label}: <strong>{value}</strong></span>
      ))}
    </div>
  );
}

export function TunnelPanel({ panel, socket }) {
  const Icon = panel.icon;
  const [tunnel, setTunnel] = useState(FALLBACK_TUNNEL);
  const [apiState, setApiState] = useState({ loading: true, error: null });

  useEffect(() => {
    let cancelled = false;

    async function loadTunnel() {
      try {
        const response = await fetch('/api/tunnel');
        if (!response.ok) {
          throw new Error(`status ${response.status}`);
        }
        const payload = await response.json();
        if (!cancelled) {
          setTunnel(asTunnelPayload(payload));
          setApiState({ loading: false, error: null });
        }
      } catch (error) {
        if (!cancelled) {
          setTunnel(FALLBACK_TUNNEL);
          setApiState({ loading: false, error: error.message });
        }
      }
    }

    loadTunnel();
    const interval = window.setInterval(loadTunnel, 1500);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const chartData = useMemo(() => buildChartData(socket.history), [socket.history]);
  const rates = useMemo(() => getLiveRates(chartData), [chartData]);
  const latest = socket.data || {};
  const stats = {
    bytes_tx: latest.bytes_tx ?? tunnel.bytes_tx,
    bytes_rx: latest.bytes_rx ?? tunnel.bytes_rx,
    pkts_tx: latest.pkts_tx ?? tunnel.pkts_tx,
    pkts_rx: latest.pkts_rx ?? tunnel.pkts_rx,
    avg_latency_ms: latest.latency_ms ?? tunnel.avg_latency_ms,
  };
  const apiLabel = apiState.loading ? 'loading' : apiState.error ? 'offline' : 'live';

  return (
    <section className="active-panel tunnel-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">{panel.title}</h1>
        </div>
        <div className="panel-heading-cluster">
          <span className="tunnel-api-state">
            <Activity aria-hidden="true" size={15} />
            {apiLabel}
          </span>
          <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
        </div>
      </div>

      <div className="tunnel-layout">
        <TunDeviceCard tunnel={tunnel} />
        <PacketFlowDiagram rates={rates} stats={stats} />
        <ThroughputChart data={chartData} />
        <LatencyChart data={chartData} />
        <StatsFooter stats={stats} />
      </div>
    </section>
  );
}
