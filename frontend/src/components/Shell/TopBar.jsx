import { Clipboard, Radio, RefreshCw, WifiOff } from 'lucide-react';

import {
  formatDuration,
  formatScore,
  getScoreState,
  truncateToken,
} from '../../lib/format.js';

function getConnectionMeta(socket) {
  if (socket.connected) {
    return {
      className: 'is-live',
      label: 'LIVE',
      icon: Radio,
    };
  }

  if (socket.status === 'dead') {
    return {
      className: 'is-dead',
      label: 'DEAD',
      icon: WifiOff,
    };
  }

  return {
    className: 'is-reconnecting',
    label: 'RECONNECTING',
    icon: RefreshCw,
  };
}

export function TopBar({ socket, status }) {
  const statusData = status.data;
  const sessionId = truncateToken(statusData?.session_id);
  const mode = statusData?.mode ? String(statusData.mode).toUpperCase() : 'STANDBY';
  const uptime = formatDuration(statusData?.uptime_s);
  const scoreState = getScoreState(socket.data?.detection_score);
  const connection = getConnectionMeta(socket);
  const ConnectionIcon = connection.icon;

  async function copySessionId() {
    if (!statusData?.session_id || statusData.session_id === 'N/A') {
      return;
    }

    await navigator.clipboard?.writeText(statusData.session_id);
  }

  return (
    <header className="top-bar">
      <div className="top-brand" aria-label="Aegis-Tunnel X">
        <span className="brand-mark">AX</span>
        <span className="brand-name">AEGIS-TUNNEL X</span>
      </div>

      <div className="top-session">
        <button
          className="session-chip"
          disabled={!statusData?.session_id || statusData.session_id === 'N/A'}
          onClick={copySessionId}
          title="Copy session ID"
          type="button"
        >
          <Clipboard aria-hidden="true" size={14} />
          <span>session: {sessionId}</span>
        </button>
        <span className="mode-badge">{mode}</span>
        <span className="uptime-counter">uptime: {uptime}</span>
      </div>

      <div className="top-health">
        <span className={`connection-state ${connection.className}`}>
          <ConnectionIcon aria-hidden="true" size={15} />
          {connection.label}
        </span>
        <span className={`score-badge score-${scoreState}`}>
          score {formatScore(socket.data?.detection_score)}
        </span>
      </div>
    </header>
  );
}
