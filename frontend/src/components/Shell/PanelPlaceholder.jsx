import {
  formatBytes,
  formatInteger,
  formatLatency,
  formatScore,
} from '../../lib/format.js';

function readout(value, formatter = (item) => item ?? '--') {
  if (value === undefined || value === null || value === '') {
    return '--';
  }
  return formatter(value);
}

export function PanelPlaceholder({ panel, socket, status }) {
  const Icon = panel.icon;
  const frame = socket.data;
  const statusData = status.data;
  const bufferDepth = `${socket.history.length}/300`;
  const handshake = frame?.handshake_done || statusData?.handshake_done;

  const signalTiles = [
    ['phase', panel.phase],
    ['socket', socket.status.toUpperCase()],
    ['buffer', bufferDepth],
    ['handshake', handshake ? 'DONE' : 'WAIT'],
    ['mode', statusData?.mode ? String(statusData.mode).toUpperCase() : 'N/A'],
    ['profile', frame?.profile || 'N/A'],
  ];

  return (
    <section className="active-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">{panel.title}</h1>
        </div>
        <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
      </div>

      <div className="panel-placeholder-body">
        <div className="signal-grid" aria-label="Panel state">
          {signalTiles.map(([label, value]) => (
            <div className="signal-tile" key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>

        <div className="terminal-pane" aria-label="Live frame readouts">
          <div className="terminal-title">METRICS FRAME</div>
          <dl className="readout-grid">
            <div>
              <dt>bytes_tx</dt>
              <dd>{readout(frame?.bytes_tx, formatBytes)}</dd>
            </div>
            <div>
              <dt>bytes_rx</dt>
              <dd>{readout(frame?.bytes_rx, formatBytes)}</dd>
            </div>
            <div>
              <dt>pkts_tx</dt>
              <dd>{readout(frame?.pkts_tx, formatInteger)}</dd>
            </div>
            <div>
              <dt>pkts_rx</dt>
              <dd>{readout(frame?.pkts_rx, formatInteger)}</dd>
            </div>
            <div>
              <dt>latency_ms</dt>
              <dd>{readout(frame?.latency_ms, formatLatency)}</dd>
            </div>
            <div>
              <dt>detection_score</dt>
              <dd>{readout(frame?.detection_score, formatScore)}</dd>
            </div>
            <div>
              <dt>seq_counter</dt>
              <dd>{readout(frame?.seq_counter, formatInteger)}</dd>
            </div>
            <div>
              <dt>status_api</dt>
              <dd>{status.error ? '503' : 'OK'}</dd>
            </div>
          </dl>
        </div>
      </div>
    </section>
  );
}
