import { useEffect, useMemo, useState } from 'react';
import {
  CheckCircle2,
  Clock3,
  RadioTower,
  ShieldCheck,
  ShieldX,
  TimerReset,
} from 'lucide-react';

import { formatBytes, formatInteger } from '../../lib/format.js';

const HEADER_BYTES = 17;
const MAGIC = '0xAE91';
const VERSION = '0x01';
const DATA_TYPE = 'DATA (0x10)';
const DATA_FLAGS = 'DATA (0x02)';
const KEEPALIVE_INTERVAL = 25;
const MISS_LIMIT = 3;

const FALLBACK_TRANSPORT = {
  seq_counter: 0,
  recv_window_fill: 0,
  recv_window_size: 64,
  keepalive_interval_s: KEEPALIVE_INTERVAL,
  keepalive_timer_remaining_s: null,
  missed_keepalives: 0,
  remote_addr: '',
  session_id: 'N/A',
};

function asTransportPayload(payload) {
  return {
    ...FALLBACK_TRANSPORT,
    ...payload,
  };
}

function toHex32(value) {
  const number = Math.max(0, Number(value) || 0);
  return `0x${number.toString(16).toUpperCase().padStart(8, '0')}`;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function getLastPacketDelta(history) {
  for (let index = history.length - 1; index > 0; index -= 1) {
    const current = history[index];
    const previous = history[index - 1];
    const rxDelta = Number(current.pkts_rx || 0) - Number(previous.pkts_rx || 0);
    const txDelta = Number(current.pkts_tx || 0) - Number(previous.pkts_tx || 0);

    if (rxDelta > 0) {
      return {
        direction: 'RX',
        packets: rxDelta,
        bytes: Math.max(0, Number(current.bytes_rx || 0) - Number(previous.bytes_rx || 0)),
      };
    }

    if (txDelta > 0) {
      return {
        direction: 'TX',
        packets: txDelta,
        bytes: Math.max(0, Number(current.bytes_tx || 0) - Number(previous.bytes_tx || 0)),
      };
    }
  }

  return {
    direction: 'IDLE',
    packets: 0,
    bytes: 0,
  };
}

function SectionHeader({ title, children }) {
  return (
    <div className="transport-section-header">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

function SeqCounter({ value }) {
  const [flash, setFlash] = useState(false);

  useEffect(() => {
    setFlash(true);
    const timer = window.setTimeout(() => setFlash(false), 260);
    return () => window.clearTimeout(timer);
  }, [value]);

  return (
    <div className={`seq-counter ${flash ? 'is-flashing' : ''}`}>
      <span>Sequence</span>
      <strong>{formatInteger(value)}</strong>
      <code>{toHex32(value)}</code>
    </div>
  );
}

function ReplayWindowBar({ fill, size }) {
  const windowSize = Math.max(1, Number(size) || 64);
  const fillCount = clamp(Number(fill) || 0, 0, windowSize);
  const percent = (fillCount / windowSize) * 100;
  const slots = Array.from({ length: windowSize }, (_, index) => {
    const seen = index >= windowSize - fillCount;
    return (
      <span
        aria-hidden="true"
        className={seen ? 'is-seen' : ''}
        key={index}
      />
    );
  });

  return (
    <div className="replay-window">
      <div className="replay-window-meta">
        <span>Replay Window</span>
        <strong>{fillCount}/{windowSize}</strong>
      </div>
      <div
        aria-label={`Replay window ${percent.toFixed(0)} percent filled`}
        className="replay-slots"
      >
        {slots}
      </div>
    </div>
  );
}

function PacketField({ label, value, valid = true }) {
  const ValidIcon = valid ? CheckCircle2 : ShieldX;

  return (
    <div className={`packet-field ${valid ? 'is-valid' : 'is-invalid'}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <ValidIcon aria-label={valid ? 'valid' : 'invalid'} size={15} />
    </div>
  );
}

function PacketFrameInspector({ transport, socket }) {
  const lastPacket = getLastPacketDelta(socket.history);
  const handshakeDone = Boolean(socket.data?.handshake_done);
  const seq = socket.data?.seq_counter ?? transport.seq_counter;
  const payloadBytes = Math.max(0, lastPacket.bytes - HEADER_BYTES);
  const frameActive = handshakeDone || lastPacket.packets > 0;

  const fields = [
    ['Magic', MAGIC, true],
    ['Version', VERSION, true],
    ['Type', frameActive ? DATA_TYPE : 'WAIT', frameActive],
    ['Flags', frameActive ? DATA_FLAGS : 'NONE', frameActive],
    ['Session', transport.session_id || 'N/A', transport.session_id !== 'N/A'],
    ['Seq', formatInteger(seq), frameActive],
    ['Payload', lastPacket.packets > 0 ? formatBytes(payloadBytes) : '--', lastPacket.packets > 0],
    ['Direction', lastPacket.direction, lastPacket.direction !== 'IDLE'],
  ];

  return (
    <div className="packet-inspector">
      {fields.map(([label, value, valid]) => (
        <PacketField key={label} label={label} valid={valid} value={value} />
      ))}
    </div>
  );
}

function KeepaliveTimer({ transport }) {
  const interval = Number(transport.keepalive_interval_s) || KEEPALIVE_INTERVAL;
  const remainingValue = Number(transport.keepalive_timer_remaining_s);
  const hasRemaining = Number.isFinite(remainingValue);
  const remaining = hasRemaining ? clamp(remainingValue, 0, interval) : null;
  const progress = remaining === null ? 0 : (remaining / interval) * 100;
  const urgent = remaining !== null && remaining <= 5;
  const missed = Number(transport.missed_keepalives) || 0;

  return (
    <div className="keepalive-timer">
      <div className="keepalive-topline">
        <div>
          <span>Next KA in</span>
          <strong>{remaining === null ? '--' : `${remaining.toFixed(1)} s`}</strong>
        </div>
        <span className={urgent ? 'timer-badge is-urgent' : 'timer-badge'}>
          {interval.toFixed(0)} s interval
        </span>
      </div>
      <div className="keepalive-meter" aria-label="Keepalive countdown">
        <span
          className={urgent ? 'is-urgent' : ''}
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="keepalive-footer">
        <span>Missed: {missed} / {MISS_LIMIT}</span>
        <span>{missed > 0 ? 'WATCH' : 'OK'}</span>
      </div>
    </div>
  );
}

function SessionCard({ transport, socket }) {
  const seq = socket.data?.seq_counter ?? transport.seq_counter;

  return (
    <div className="transport-card session-card">
      <SectionHeader title="Session">
        <ShieldCheck aria-hidden="true" size={18} />
      </SectionHeader>
      <div className="session-readouts">
        <div>
          <span>ID</span>
          <strong>{transport.session_id || 'N/A'}</strong>
        </div>
        <div>
          <span>Remote</span>
          <strong>{transport.remote_addr || 'N/A'}</strong>
        </div>
      </div>
      <SeqCounter value={seq} />
      <ReplayWindowBar
        fill={transport.recv_window_fill}
        size={transport.recv_window_size}
      />
    </div>
  );
}

export function TransportPanel({ panel, socket }) {
  const Icon = panel.icon;
  const [transport, setTransport] = useState(FALLBACK_TRANSPORT);
  const [apiState, setApiState] = useState({ loading: true, error: null });

  useEffect(() => {
    let cancelled = false;

    async function loadTransport() {
      try {
        const response = await fetch('/api/transport');
        if (!response.ok) {
          throw new Error(`status ${response.status}`);
        }
        const payload = await response.json();
        if (!cancelled) {
          setTransport(asTransportPayload(payload));
          setApiState({ loading: false, error: null });
        }
      } catch (error) {
        if (!cancelled) {
          setTransport(FALLBACK_TRANSPORT);
          setApiState({ loading: false, error: error.message });
        }
      }
    }

    loadTransport();
    const interval = window.setInterval(loadTransport, 1000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const apiLabel = apiState.loading ? 'loading' : apiState.error ? 'offline' : 'live';

  const frameStats = useMemo(() => getLastPacketDelta(socket.history), [socket.history]);

  return (
    <section className="active-panel transport-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">{panel.title}</h1>
        </div>
        <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
      </div>

      <div className="transport-layout">
        <div className="transport-left">
          <SessionCard socket={socket} transport={transport} />
        </div>

        <div className="transport-card transport-frame-card">
          <SectionHeader title="Packet Frame Inspector">
            <span className="transport-api-state">
              <RadioTower aria-hidden="true" size={15} />
              {apiLabel}
            </span>
          </SectionHeader>
          <PacketFrameInspector socket={socket} transport={transport} />
          <div className="wire-format-strip">
            <span>Header {HEADER_BYTES} B</span>
            <span>Last {frameStats.direction}</span>
            <span>{frameStats.packets > 0 ? formatBytes(frameStats.bytes) : 'no packet delta'}</span>
          </div>
        </div>

        <div className="transport-card keepalive-card">
          <SectionHeader title="Keepalive Timer">
            <Clock3 aria-hidden="true" size={18} />
          </SectionHeader>
          <KeepaliveTimer transport={transport} />
        </div>

        <div className="transport-card wire-card">
          <SectionHeader title="Wire Constants">
            <TimerReset aria-hidden="true" size={18} />
          </SectionHeader>
          <div className="wire-constant-grid">
            <div>
              <span>Magic</span>
              <strong>{MAGIC}</strong>
            </div>
            <div>
              <span>Version</span>
              <strong>{VERSION}</strong>
            </div>
            <div>
              <span>Header</span>
              <strong>{HEADER_BYTES} B</strong>
            </div>
            <div>
              <span>Replay</span>
              <strong>{transport.recv_window_size || 64} slots</strong>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
