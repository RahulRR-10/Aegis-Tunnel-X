import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  CircleAlert,
  FileCode2,
  FolderKey,
  Loader2,
  RefreshCw,
  ShieldX,
} from 'lucide-react';

import { formatBytes } from '../../lib/format.js';

function SectionHeader({ title, children }) {
  return (
    <div className="config-section-header">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

function toScalar(value) {
  if (value === null || value === undefined) return 'N/A';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  return String(value);
}

function endpointLabel(config, mode) {
  if (mode === 'client') {
    const host = config?.connect?.host || 'N/A';
    const port = config?.connect?.port;
    return port !== undefined ? `${host}:${port}` : host;
  }

  const host = config?.listen?.host || 'N/A';
  const port = config?.listen?.port;
  return port !== undefined ? `${host}:${port}` : host;
}

function appendYaml(lines, value, indent = 0) {
  const pad = ' '.repeat(indent);

  if (Array.isArray(value)) {
    if (value.length === 0) {
      lines.push(`${pad}[]`);
      return;
    }

    value.forEach((item) => {
      if (item && typeof item === 'object') {
        lines.push(`${pad}-`);
        appendYaml(lines, item, indent + 2);
      } else {
        lines.push(`${pad}- ${toScalar(item)}`);
      }
    });
    return;
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length === 0) {
      lines.push(`${pad}{}`);
      return;
    }

    entries.forEach(([key, item]) => {
      if (item && typeof item === 'object') {
        lines.push(`${pad}${key}:`);
        appendYaml(lines, item, indent + 2);
      } else {
        lines.push(`${pad}${key}: ${toScalar(item)}`);
      }
    });
    return;
  }

  lines.push(`${pad}${toScalar(value)}`);
}

function toYamlString(value) {
  if (!value || typeof value !== 'object') {
    return '# no configuration loaded';
  }
  const lines = [];
  appendYaml(lines, value, 0);
  return lines.join('\n');
}

function normalizeConfigPayload(payload) {
  if (!payload) return null;
  if (payload.config) return payload;

  if (Array.isArray(payload.configs) && payload.configs.length > 0) {
    const selected = payload.configs[0] || {};
    return {
      live: false,
      mode: selected.config?.mode || 'unknown',
      config_file: selected.file || 'unknown',
      config: selected.config || {},
      key_dir: 'N/A',
      key_files: selected.key_files || [],
      available_configs: payload.configs.map((entry) => ({
        config_file: entry.file || 'unknown',
        mode: entry.config?.mode || 'unknown',
      })),
    };
  }

  return null;
}

function summaryRows(payload) {
  const config = payload?.config || {};
  const mode = String(config.mode || payload?.mode || 'N/A').toLowerCase();
  const tun = config.tun || {};
  const morphic = config.morphic || {};
  const feedback = config.feedback || {};
  const loggingCfg = config.logging || {};

  return [
    ['Mode', mode.toUpperCase()],
    [mode === 'client' ? 'Connect' : 'Listen', endpointLabel(config, mode)],
    ['Tun IP', toScalar(tun.ip)],
    ['Peer IP', toScalar(tun.peer_ip)],
    ['MTU', toScalar(tun.mtu)],
    ['Profile', toScalar(morphic.profile)],
    ['Feedback', feedback.enabled ? 'enabled' : 'disabled'],
    ['Threshold', toScalar(feedback.score_threshold)],
    ['Log', toScalar(loggingCfg.file)],
  ];
}

function logLevelClass(level) {
  const upper = String(level || '').toUpperCase();
  if (upper === 'DEBUG') return 'is-debug';
  if (upper === 'INFO') return 'is-info';
  if (upper === 'WARNING' || upper === 'WARN') return 'is-warn';
  return 'is-other';
}

function ConfigSummaryCard({ payload }) {
  const rows = useMemo(() => summaryRows(payload), [payload]);
  const sourceFile = payload?.config_file || 'N/A';
  const logLevel = String(payload?.config?.logging?.level || 'N/A').toUpperCase();
  const available = payload?.available_configs || [];

  return (
    <div className="config-card config-summary-card">
      <SectionHeader title="Active Config">
        <span className="config-source-chip">{sourceFile}</span>
      </SectionHeader>

      <dl className="config-summary-grid">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd title={String(value)}>{String(value)}</dd>
          </div>
        ))}
      </dl>

      <div className="config-log-row">
        <span>Log Level</span>
        <span className={`log-level-badge ${logLevelClass(logLevel)}`}>{logLevel}</span>
      </div>

      {available.length > 1 && (
        <div className="config-available-modes">
          {available.map((entry) => (
            <span key={`${entry.config_file}-${entry.mode}`}>
              {String(entry.mode || 'unknown').toUpperCase()} / {entry.config_file}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function KeyFileStatusGrid({ keyDir, files, onRegenerate, running, resultMessage }) {
  return (
    <div className="config-card key-status-card">
      <SectionHeader title="Key Management">
        <FolderKey aria-hidden="true" size={18} />
      </SectionHeader>

      <div className="key-dir-row" title={String(keyDir || 'N/A')}>
        <span>Key dir</span>
        <strong>{keyDir || 'N/A'}</strong>
      </div>

      <div className="key-grid">
        {files.length === 0 ? (
          <div className="key-grid-empty">No key files discovered</div>
        ) : (
          files.map((file) => {
            const exists = Boolean(file.exists);
            return (
              <div
                key={file.name}
                className={`key-file-cell ${exists ? 'is-present' : 'is-missing'}`}
              >
                <span className="key-file-name" title={file.name}>{file.name}</span>
                <span className="key-file-size">
                  {exists ? formatBytes(file.size_bytes || 0) : 'missing'}
                </span>
                <span className="key-file-state">
                  {exists ? (
                    <>
                      <CheckCircle2 aria-hidden="true" size={14} />
                      exists
                    </>
                  ) : (
                    <>
                      <ShieldX aria-hidden="true" size={14} />
                      missing
                    </>
                  )}
                </span>
              </div>
            );
          })
        )}
      </div>

      <button
        className={`keygen-button ${running ? 'is-running' : ''}`}
        disabled={running}
        onClick={onRegenerate}
        type="button"
      >
        {running ? (
          <>
            <Loader2 aria-hidden="true" className="spin-icon" size={16} />
            REGENERATING...
          </>
        ) : (
          <>
            <RefreshCw aria-hidden="true" size={16} />
            REGENERATE KEYS
          </>
        )}
      </button>

      {resultMessage && <div className="keygen-result">{resultMessage}</div>}
    </div>
  );
}

function RawConfigViewer({ config }) {
  const raw = useMemo(() => toYamlString(config), [config]);

  return (
    <div className="config-card raw-config-card">
      <SectionHeader title="Raw Config (YAML)">
        <FileCode2 aria-hidden="true" size={18} />
      </SectionHeader>

      <div className="raw-config-shell">
        <pre>{raw}</pre>
      </div>
    </div>
  );
}

export function ConfigPanel({ panel }) {
  const Icon = panel.icon;
  const [payload, setPayload] = useState(null);
  const [apiState, setApiState] = useState({ loading: true, error: null });
  const [keygen, setKeygen] = useState({ running: false, message: '' });

  const loadConfig = useCallback(async () => {
    try {
      const response = await fetch('/api/config');
      if (!response.ok) {
        throw new Error(`status ${response.status}`);
      }

      const next = normalizeConfigPayload(await response.json());
      if (!next) {
        throw new Error('invalid payload');
      }

      setPayload(next);
      setApiState({ loading: false, error: null });
    } catch (error) {
      setApiState({ loading: false, error: error.message });
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      if (cancelled) return;
      await loadConfig();
    }

    load();
    const interval = window.setInterval(load, 3000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [loadConfig]);

  const handleRegenerate = useCallback(async () => {
    setKeygen({ running: true, message: '' });

    try {
      const response = await fetch('/api/keygen', { method: 'POST' });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(body.detail || `status ${response.status}`);
      }

      const count = Array.isArray(body.key_files) ? body.key_files.length : 0;
      setKeygen({
        running: false,
        message: `Key generation complete (${count} files checked).`,
      });
      await loadConfig();
    } catch (error) {
      setKeygen({ running: false, message: `Key generation failed: ${error.message}` });
    }
  }, [loadConfig]);

  const apiLabel = apiState.loading
    ? 'loading'
    : apiState.error
      ? 'offline'
      : 'live';

  const keyFiles = payload?.key_files || [];
  const keyDir = payload?.key_dir || 'N/A';

  return (
    <section className="active-panel config-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">{panel.title}</h1>
        </div>
        <div className="panel-heading-cluster">
          <span className="config-api-state">
            <Activity aria-hidden="true" size={15} />
            {apiLabel}
          </span>
          <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
        </div>
      </div>

      <div className="config-layout">
        <ConfigSummaryCard payload={payload} />
        <KeyFileStatusGrid
          files={keyFiles}
          keyDir={keyDir}
          onRegenerate={handleRegenerate}
          resultMessage={keygen.message}
          running={keygen.running}
        />
        <RawConfigViewer config={payload?.config || {}} />
      </div>

      {apiState.error && (
        <div className="config-api-error" role="status">
          <CircleAlert aria-hidden="true" size={15} />
          Unable to load config endpoint: {apiState.error}
        </div>
      )}
    </section>
  );
}
