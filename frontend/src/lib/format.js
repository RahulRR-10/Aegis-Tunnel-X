export function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes)) {
    return '--';
  }

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unitIndex = 0;
  let size = Math.max(0, bytes);

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  const precision = unitIndex === 0 || size >= 100 ? 0 : 1;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

export function formatInteger(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return '--';
  }
  return new Intl.NumberFormat('en-US').format(Math.trunc(number));
}

export function formatLatency(value) {
  const latency = Number(value);
  if (!Number.isFinite(latency)) {
    return '--';
  }
  return `${latency.toFixed(latency >= 10 ? 0 : 1)} ms`;
}

export function formatDuration(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value)) {
    return '--:--:--';
  }

  const total = Math.max(0, Math.floor(value));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;

  return [hours, minutes, secs]
    .map((part) => String(part).padStart(2, '0'))
    .join(':');
}

export function formatScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) {
    return '--';
  }
  return score.toFixed(2);
}

export function getScoreState(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) {
    return 'unknown';
  }
  if (score < 0.15) {
    return 'good';
  }
  if (score <= 0.25) {
    return 'watch';
  }
  return 'adapting';
}

export function truncateToken(value, head = 4, tail = 4) {
  if (!value || value === 'N/A') {
    return 'N/A';
  }

  const token = String(value);
  if (token.includes('...')) {
    return token;
  }

  if (token.length <= head + tail + 3) {
    return token;
  }

  return `${token.slice(0, head)}...${token.slice(-tail)}`;
}
