import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Beaker,
  CheckCircle2,
  Circle,
  Loader2,
  Play,
  RefreshCw,
  SlidersHorizontal,
  Square,
} from 'lucide-react';

import { formatBytes, formatLatency, formatScore } from '../../lib/format.js';

const PROFILE_OPTIONS = ['web_browsing', 'video_streaming', 'gaming'];

function stateClass(isOnline) {
  return isOnline ? 'is-online' : 'is-offline';
}

function statusText(isOnline) {
  return isOnline ? 'online' : 'offline';
}

function ActionButton({ busy, children, className, disabled, onClick }) {
  return (
    <button
      className={`overview-btn ${className || ''}`.trim()}
      disabled={disabled || busy}
      onClick={onClick}
      type="button"
    >
      {busy ? <Loader2 aria-hidden="true" className="spin-icon" size={15} /> : null}
      {children}
    </button>
  );
}

function StatTiles({ socket, status }) {
  const frame = socket.data || {};
  const api = status.data || {};

  const items = [
    ['Tunnel', socket.connected ? 'LIVE' : 'DOWN'],
    ['Mode', String(api.mode || 'N/A').toUpperCase()],
    ['Profile', frame.profile || 'N/A'],
    ['Detection', formatScore(frame.detection_score || 0)],
    ['TX', formatBytes(frame.bytes_tx || 0)],
    ['RX', formatBytes(frame.bytes_rx || 0)],
    ['Pkts TX', String(frame.pkts_tx || 0)],
    ['Pkts RX', String(frame.pkts_rx || 0)],
    ['Latency', formatLatency(frame.latency_ms || api.avg_latency_ms || 0)],
  ];

  return (
    <div className="overview-tile-grid">
      {items.map(([label, value]) => (
        <div className="overview-tile" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function PageGuide({ socket, demoStatus, testStatus }) {
  const checklist = [
    {
      page: 'Crypto',
      expected: 'Handshake flips to complete and nonce counter increments with traffic.',
      ok: Boolean(socket.data?.handshake_done),
    },
    {
      page: 'Transport',
      expected: 'Sequence counter and frame inspector update continuously.',
      ok: Number(socket.data?.seq_counter || 0) > 0,
    },
    {
      page: 'Tunnel',
      expected: 'Throughput and latency charts animate from live tunnel metrics.',
      ok: Number(socket.data?.pkts_tx || 0) + Number(socket.data?.pkts_rx || 0) > 0,
    },
    {
      page: 'Morphic',
      expected: 'Profile switching changes active profile and chart distributions.',
      ok: Boolean(socket.data?.profile),
    },
    {
      page: 'Feedback',
      expected: 'Detection score updates and adaptation history fills over time.',
      ok: Number(socket.data?.detection_score || 0) >= 0,
    },
    {
      page: 'Config',
      expected: 'Config snapshot loads and key files show presence/size.',
      ok: true,
    },
    {
      page: 'Demo',
      expected: 'Sequence/test logs stream while status transitions idle to running to done.',
      ok: demoStatus === 'running' || testStatus === 'running' || demoStatus === 'done' || testStatus === 'done',
    },
  ];

  return (
    <div className="overview-card overview-guide-card">
      <div className="overview-card-head">
        <h2>Page-by-Page Verification</h2>
      </div>
      <div className="overview-checklist">
        {checklist.map((item) => (
          <div className="overview-check-item" key={item.page}>
            <span className="overview-check-icon">
              {item.ok ? <CheckCircle2 aria-hidden="true" size={14} /> : <Circle aria-hidden="true" size={14} />}
            </span>
            <span className="overview-check-page">{item.page}</span>
            <span className="overview-check-text">{item.expected}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function OverviewPanel({ panel, socket, status }) {
  const Icon = panel.icon;
  const [morphic, setMorphic] = useState(null);
  const [demo, setDemo] = useState({ status: 'idle' });
  const [tests, setTests] = useState({ status: 'idle' });

  const [busy, setBusy] = useState({
    startDemo: false,
    stopDemo: false,
    runTests: false,
    switchProfile: false,
    keygen: false,
  });

  const [selectedProfile, setSelectedProfile] = useState('web_browsing');
  const [actionMessage, setActionMessage] = useState('');

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const [morphicRes, demoRes, testRes] = await Promise.all([
          fetch('/api/morphic'),
          fetch('/api/demo/status'),
          fetch('/api/demo/test_status'),
        ]);

        if (morphicRes.ok) {
          const morphicBody = await morphicRes.json();
          if (!cancelled) {
            setMorphic(morphicBody);
            if (morphicBody.profile) {
              setSelectedProfile(morphicBody.profile);
            }
          }
        }

        if (demoRes.ok) {
          const demoBody = await demoRes.json();
          if (!cancelled) {
            setDemo(demoBody);
          }
        }

        if (testRes.ok) {
          const testBody = await testRes.json();
          if (!cancelled) {
            setTests(testBody);
          }
        }
      } catch {
        // Keep panel responsive even when API is down.
      }
    }

    poll();
    const interval = window.setInterval(poll, 1500);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const profiles = useMemo(() => {
    const remote = morphic?.available_profiles || [];
    return remote.length > 0 ? remote : PROFILE_OPTIONS;
  }, [morphic]);

  async function runAction(key, fn) {
    setBusy((prev) => ({ ...prev, [key]: true }));
    setActionMessage('');
    try {
      await fn();
    } catch (error) {
      setActionMessage(error.message || 'Action failed');
    } finally {
      setBusy((prev) => ({ ...prev, [key]: false }));
    }
  }

  async function postJson(url) {
    const res = await fetch(url, { method: 'POST' });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(body.detail || `status ${res.status}`);
    }
    return body;
  }

  const apiOnline = !status.error;
  const wsOnline = socket.connected;

  return (
    <section className="active-panel overview-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">Live Operations Console</h1>
        </div>
        <div className="panel-heading-cluster">
          <span className={`overview-state ${stateClass(wsOnline)}`}>
            <Activity aria-hidden="true" size={14} /> WS {statusText(wsOnline)}
          </span>
          <span className={`overview-state ${stateClass(apiOnline)}`}>
            <Activity aria-hidden="true" size={14} /> API {statusText(apiOnline)}
          </span>
          <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
        </div>
      </div>

      <div className="overview-layout">
        <div className="overview-card">
          <div className="overview-card-head">
            <h2>Control Center</h2>
          </div>
          <div className="overview-actions">
            <ActionButton
              busy={busy.startDemo}
              className="is-primary"
              onClick={() => runAction('startDemo', async () => {
                await postJson('/api/demo/start');
                setActionMessage('Demo started. Check Demo page for step logs.');
              })}
            >
              <Play aria-hidden="true" size={15} /> Start Demo
            </ActionButton>

            <ActionButton
              busy={busy.stopDemo}
              className="is-danger"
              onClick={() => runAction('stopDemo', async () => {
                await postJson('/api/demo/stop');
                setActionMessage('Demo stopped.');
              })}
            >
              <Square aria-hidden="true" size={15} /> Stop Demo
            </ActionButton>

            <ActionButton
              busy={busy.runTests}
              className="is-outline"
              onClick={() => runAction('runTests', async () => {
                await postJson('/api/demo/run_tests');
                setActionMessage('E2E tests started.');
              })}
            >
              <Beaker aria-hidden="true" size={15} /> Run E2E Tests
            </ActionButton>

            <ActionButton
              busy={busy.keygen}
              className="is-outline"
              onClick={() => runAction('keygen', async () => {
                await postJson('/api/keygen');
                setActionMessage('Key generation complete.');
              })}
            >
              <RefreshCw aria-hidden="true" size={15} /> Regenerate Keys
            </ActionButton>
          </div>

          <div className="overview-profile-row">
            <label htmlFor="overview-profile">Morphic Profile</label>
            <select
              id="overview-profile"
              onChange={(event) => setSelectedProfile(event.target.value)}
              value={selectedProfile}
            >
              {profiles.map((name) => (
                <option key={name} value={name}>{name}</option>
              ))}
            </select>
            <ActionButton
              busy={busy.switchProfile}
              className="is-outline"
              onClick={() => runAction('switchProfile', async () => {
                await postJson(`/api/profile/${encodeURIComponent(selectedProfile)}`);
                setActionMessage(`Switched profile to ${selectedProfile}.`);
              })}
            >
              <SlidersHorizontal aria-hidden="true" size={15} /> Apply
            </ActionButton>
          </div>

          <div className="overview-live-status">
            <span>Demo: <strong>{String(demo.status || 'idle').toUpperCase()}</strong></span>
            <span>Tests: <strong>{String(tests.status || 'idle').toUpperCase()}</strong></span>
            <span>Active Profile: <strong>{morphic?.profile || socket.data?.profile || 'N/A'}</strong></span>
          </div>

          {actionMessage ? <div className="overview-action-message">{actionMessage}</div> : null}
        </div>

        <StatTiles socket={socket} status={status} />
        <PageGuide socket={socket} demoStatus={demo.status} testStatus={tests.status} />
      </div>
    </section>
  );
}
