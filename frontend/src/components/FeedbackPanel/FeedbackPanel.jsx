import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleAlert,
  Clock,
  Eye,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { formatScore, getScoreState } from '../../lib/format.js';

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

const METRIC_META = [
  { key: 'entropy',    label: 'Entropy',      ideal: '~8.0 bits', max: 8.0  },
  { key: 'ipd_cv',     label: 'IPD-CV',       ideal: 'profile α', max: 3.0  },
  { key: 'size_chi2_p',label: 'Size χ² p',    ideal: '>0.05',     max: 1.0  },
  { key: 'burstiness', label: 'Burstiness',   ideal: '~2.0',      max: 5.0  },
  { key: 'periodicity',label: 'Periodicity',  ideal: '<0.15',     max: 1.0  },
];

function scoreColor(score) {
  const state = getScoreState(score);
  if (state === 'good') return 'var(--accent-green)';
  if (state === 'watch') return 'var(--accent-amber)';
  return 'var(--accent-red)';
}

function scoreLabel(score) {
  const state = getScoreState(score);
  if (state === 'good') return 'GOOD';
  if (state === 'watch') return 'WATCH';
  return 'ADAPTING';
}

function SectionHeader({ title, children }) {
  return (
    <div className="feedback-section-header">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <strong>{label}</strong>
      {payload.map((item) => (
        <span key={item.dataKey} style={{ color: item.color }}>
          {item.name}: {Number(item.value).toFixed(4)}
        </span>
      ))}
    </div>
  );
}

function formatTimestamp(ts) {
  if (!ts) return '--:--:--';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString('en-GB', { hour12: false });
}

/* ------------------------------------------------------------------ */
/*  DetectionScoreGauge                                                */
/* ------------------------------------------------------------------ */

function DetectionScoreGauge({ score, threshold, adaptationCount }) {
  const radius = 68;
  const stroke = 10;
  const cx = 80;
  const cy = 80;
  const startAngle = 225;
  const endAngle = -45;
  const totalAngle = startAngle - endAngle;

  const clampedScore = Math.max(0, Math.min(score, 1));
  const sweepAngle = totalAngle * clampedScore;

  function arcPath(angleDeg) {
    const rad = (angleDeg * Math.PI) / 180;
    return {
      x: cx + radius * Math.cos(rad),
      y: cy - radius * Math.sin(rad),
    };
  }

  const bgStart = arcPath(startAngle);
  const bgEnd = arcPath(endAngle);
  const valEnd = arcPath(startAngle - sweepAngle);
  const largeArc = sweepAngle > 180 ? 1 : 0;
  const bgLargeArc = totalAngle > 180 ? 1 : 0;

  const color = scoreColor(score);
  const label = scoreLabel(score);

  return (
    <div className="feedback-card gauge-card">
      <SectionHeader title="Detection Score">
        <Eye aria-hidden="true" size={18} />
      </SectionHeader>

      <div className="gauge-wrap">
        <svg viewBox="0 0 160 120" className="gauge-svg" aria-label={`Detection score ${formatScore(score)}`}>
          {/* Background arc */}
          <path
            d={`M ${bgStart.x} ${bgStart.y} A ${radius} ${radius} 0 ${bgLargeArc} 0 ${bgEnd.x} ${bgEnd.y}`}
            fill="none"
            stroke="rgba(110, 127, 143, 0.2)"
            strokeLinecap="round"
            strokeWidth={stroke}
          />
          {/* Value arc */}
          {clampedScore > 0.005 && (
            <path
              d={`M ${bgStart.x} ${bgStart.y} A ${radius} ${radius} 0 ${largeArc} 0 ${valEnd.x} ${valEnd.y}`}
              fill="none"
              stroke={color}
              strokeLinecap="round"
              strokeWidth={stroke}
              style={{
                filter: `drop-shadow(0 0 6px ${color})`,
                transition: 'stroke 300ms ease',
              }}
            />
          )}
          {/* Threshold marker */}
          {(() => {
            const th = arcPath(startAngle - totalAngle * threshold);
            return <circle cx={th.x} cy={th.y} r={3} fill="var(--accent-red)" />;
          })()}
        </svg>

        <div className="gauge-readout">
          <strong style={{ color }}>{formatScore(score)}</strong>
          <span className={`gauge-label gauge-${getScoreState(score)}`}>{label}</span>
        </div>
      </div>

      <dl className="gauge-meta">
        <div>
          <dt>Threshold</dt>
          <dd>{threshold}</dd>
        </div>
        <div>
          <dt>Adaptations</dt>
          <dd>{adaptationCount}</dd>
        </div>
      </dl>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  MetricBreakdown                                                    */
/* ------------------------------------------------------------------ */

function MetricRow({ label, value, max, ideal, score }) {
  const fill = Math.min((value || 0) / max, 1) * 100;
  const ok = score < 0.25;

  return (
    <div className="metric-row">
      <span className="metric-name">{label}</span>
      <strong className="metric-value">{Number(value || 0).toFixed(2)}</strong>
      <div className="metric-bar-track">
        <div
          className={`metric-bar-fill ${ok ? 'is-ok' : 'is-warn'}`}
          style={{ width: `${fill}%` }}
        />
      </div>
      <span className="metric-ideal">{ideal}</span>
      {ok ? (
        <CheckCircle2 aria-hidden="true" className="metric-icon is-ok" size={15} />
      ) : (
        <AlertTriangle aria-hidden="true" className="metric-icon is-warn" size={15} />
      )}
    </div>
  );
}

function MetricBreakdown({ metrics, score }) {
  return (
    <div className="feedback-card metrics-card">
      <SectionHeader title="Metric Breakdown">
        <Activity aria-hidden="true" size={18} />
      </SectionHeader>

      <div className="metric-stack">
        {METRIC_META.map((m) => (
          <MetricRow
            key={m.key}
            ideal={m.ideal}
            label={m.label}
            max={m.max}
            score={score}
            value={metrics[m.key]}
          />
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  ScoreHistoryChart                                                  */
/* ------------------------------------------------------------------ */

function buildScoreHistory(history) {
  if (!history || history.length === 0) return [];
  const newest = history[history.length - 1]?.timestamp || 0;
  return history.map((entry) => {
    const ago = Math.max(0, newest - (entry.timestamp || 0));
    return {
      label: `-${ago.toFixed(0)}s`,
      score: entry.score || 0,
      ts: entry.timestamp || 0,
    };
  });
}

function ScoreHistoryChart({ data, threshold }) {
  return (
    <div className="feedback-card chart-card feedback-chart-card">
      <SectionHeader title="Score History">
        <span className="feedback-chart-badge">last 100 checks</span>
      </SectionHeader>
      <div className="chart-shell">
        {data.length < 2 ? (
          <div className="chart-empty-state">waiting for feedback cycles</div>
        ) : (
          <ResponsiveContainer height="100%" width="100%">
            <ComposedChart data={data} margin={{ bottom: 4, left: -18, right: 8, top: 8 }}>
              <defs>
                <linearGradient id="scoreFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#00ff88" stopOpacity={0.32} />
                  <stop offset="95%" stopColor="#00ff88" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="scoreDangerFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#ff4444" stopOpacity={0.24} />
                  <stop offset="95%" stopColor="#ff4444" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(110, 127, 143, 0.16)" vertical={false} />
              <XAxis dataKey="label" minTickGap={24} stroke="#6e7f8f" tick={{ fontSize: 11 }} />
              <YAxis domain={[0, 0.6]} stroke="#6e7f8f" tick={{ fontSize: 11 }} />
              <Tooltip content={<ChartTooltip />} />
              <ReferenceLine
                label={{ fill: '#ff4444', fontSize: 11, position: 'right', value: 'threshold' }}
                stroke="#ff4444"
                strokeDasharray="4 4"
                y={threshold}
              />
              <Area
                dataKey="score"
                fill="url(#scoreFill)"
                name="Score"
                stroke="none"
                type="monotone"
              />
              <Line
                dataKey="score"
                dot={false}
                name="Score"
                stroke="#00ff88"
                strokeWidth={2}
                type="monotone"
              />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  AdaptationLog                                                      */
/* ------------------------------------------------------------------ */

function AdaptationLog({ history }) {
  // Show most recent first, only entries with actions
  const entries = useMemo(() => {
    if (!history || history.length === 0) return [];
    return [...history].reverse().slice(0, 50);
  }, [history]);

  return (
    <div className="feedback-card log-card">
      <SectionHeader title="Adaptation Log">
        <span className="feedback-chart-badge">{entries.length} entries</span>
      </SectionHeader>

      <div className="adaptation-log-scroll">
        {entries.length === 0 ? (
          <div className="log-empty">No feedback cycles recorded yet</div>
        ) : (
          entries.map((entry, idx) => {
            const isAction = entry.action && entry.action !== 'none';
            const scoreState = getScoreState(entry.score);
            return (
              <div
                key={entry.timestamp || idx}
                className={`log-entry${idx === 0 ? ' is-newest' : ''}${isAction ? ' has-action' : ''}`}
              >
                <span className="log-time">
                  <Clock aria-hidden="true" size={12} />
                  {formatTimestamp(entry.timestamp)}
                </span>
                <span className={`log-score score-${scoreState}`}>
                  {formatScore(entry.score)}
                </span>
                <span className="log-action">
                  {isAction ? (
                    <>
                      <CircleAlert aria-hidden="true" size={12} />
                      {entry.action}
                    </>
                  ) : (
                    <>
                      <ShieldCheck aria-hidden="true" size={12} />
                      none
                    </>
                  )}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  FeedbackPanel (main export)                                        */
/* ------------------------------------------------------------------ */

export function FeedbackPanel({ panel, socket }) {
  const Icon = panel.icon;
  const [feedback, setFeedback] = useState(null);
  const [apiState, setApiState] = useState({ loading: true, error: null });

  // Fetch /api/feedback on mount and periodically
  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const res = await fetch('/api/feedback');
        if (!res.ok) throw new Error(`status ${res.status}`);
        const payload = await res.json();
        if (!cancelled) {
          setFeedback(payload);
          setApiState({ loading: false, error: null });
        }
      } catch (err) {
        if (!cancelled) {
          setApiState({ loading: false, error: err.message });
        }
      }
    }

    load();
    const interval = window.setInterval(load, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  // Prefer live WebSocket data, fall back to API
  const liveScore = socket.data?.detection_score ?? feedback?.detection_score ?? 0;
  const liveMetrics = socket.data?.metrics || feedback?.metrics || {};
  const threshold = feedback?.threshold ?? 0.25;
  const adaptationCount = feedback?.adaptation_count ?? 0;
  const history = feedback?.history || [];

  const chartData = useMemo(() => buildScoreHistory(history), [history]);

  const apiLabel = apiState.loading
    ? 'loading'
    : apiState.error
      ? 'offline'
      : 'live';

  return (
    <section className="active-panel feedback-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">{panel.title}</h1>
        </div>
        <div className="panel-heading-cluster">
          <span className="feedback-api-state">
            <Activity aria-hidden="true" size={15} />
            {apiLabel}
          </span>
          <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
        </div>
      </div>

      <div className="feedback-layout">
        <DetectionScoreGauge
          adaptationCount={adaptationCount}
          score={liveScore}
          threshold={threshold}
        />
        <MetricBreakdown
          metrics={liveMetrics}
          score={liveScore}
        />
        <ScoreHistoryChart
          data={chartData}
          threshold={threshold}
        />
        <AdaptationLog history={history} />
      </div>
    </section>
  );
}
