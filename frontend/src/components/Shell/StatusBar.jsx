import {
  formatBytes,
  formatInteger,
  formatLatency,
} from '../../lib/format.js';

function pickMetric(socketData, statusData, key) {
  if (socketData && socketData[key] !== undefined) {
    return socketData[key];
  }
  return statusData?.[key];
}

export function StatusBar({ socket, status }) {
  const frame = socket.data;
  const statusData = status.data;
  const profile = frame?.profile || 'N/A';

  return (
    <footer className="status-bar">
      <span>TX {formatBytes(pickMetric(frame, statusData, 'bytes_tx'))}</span>
      <span>RX {formatBytes(pickMetric(frame, statusData, 'bytes_rx'))}</span>
      <span>PKTS TX {formatInteger(pickMetric(frame, statusData, 'pkts_tx'))}</span>
      <span>PKTS RX {formatInteger(pickMetric(frame, statusData, 'pkts_rx'))}</span>
      <span>LAT {formatLatency(pickMetric(frame, statusData, 'latency_ms') ?? statusData?.avg_latency_ms)}</span>
      <span>PROFILE {profile}</span>
    </footer>
  );
}
