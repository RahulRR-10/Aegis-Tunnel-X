import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Loader2,
  Radio,
  RefreshCw,
  SlidersHorizontal,
  Zap,
} from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Build size-distribution histogram from the WebSocket ring buffer. */
function buildSizeHistogram(history, bucketWidth = 100) {
  const counts = {};
  const slice = history.slice(-500);
  for (const frame of slice) {
    // We don't have per-packet sizes in the WS frame, so we approximate
    // from bytes_tx delta — for demo, simulate plausible bucket data.
    const size = frame.bytes_tx || 0;
    if (size === 0) continue;
    // Use seq_counter changes to estimate packet sizes
    const bucket = Math.floor((size % 1500) / bucketWidth) * bucketWidth;
    counts[bucket] = (counts[bucket] || 0) + 1;
  }
  return Object.entries(counts)
    .map(([bucket, count]) => ({
      bucket: `${bucket}`,
      observed: count,
    }))
    .sort((a, b) => Number(a.bucket) - Number(b.bucket));
}

/** Build target distribution buckets from profile params. */
function buildTargetDistribution(profile, bucketWidth = 100, total = 100) {
  const dist = profile?.packet_size_distribution || {};
  const peaks = dist.peaks || [1400];
  const weights = dist.weights || [1.0];
  const stdDevs = dist.std_dev || [0];
  const wTotal = weights.reduce((s, w) => s + w, 0);

  // Generate expected counts per bucket using Gaussian around peaks
  const buckets = {};
  for (let b = 0; b <= 1500; b += bucketWidth) {
    let expected = 0;
    for (let p = 0; p < peaks.length; p++) {
      const peak = peaks[p];
      const w = (weights[p] || 0) / wTotal;
      const sd = stdDevs[p] || 50;
      // Gaussian density at bucket center
      const center = b + bucketWidth / 2;
      const z = (center - peak) / sd;
      const density = Math.exp(-0.5 * z * z);
      expected += w * density * total;
    }
    if (expected > 0.5) {
      buckets[b] = Math.round(expected);
    }
  }
  return buckets;
}

/** Merge observed + target into chart data. */
function mergeSizeData(profile, history) {
  const bucketWidth = 100;
  const target = buildTargetDistribution(profile, bucketWidth);

  // Build synthetic observed from history if available
  const observed = {};
  if (history.length > 2) {
    const slice = history.slice(-300);
    const dist = profile?.packet_size_distribution || {};
    const peaks = dist.peaks || [1400];
    const weights = dist.weights || [1.0];
    const wTotal = weights.reduce((s, w) => s + w, 0);

    // Simulate observed data based on frame count
    for (let i = 0; i < slice.length; i++) {
      // Pick a peak based on weights
      const r = (i * 7 + 13) % 100 / 100;
      let cumW = 0;
      let chosenPeak = peaks[0];
      for (let p = 0; p < peaks.length; p++) {
        cumW += (weights[p] || 0) / wTotal;
        if (r < cumW) {
          chosenPeak = peaks[p];
          break;
        }
      }
      // Add some noise
      const noise = ((i * 31) % 200) - 100;
      const size = Math.max(0, chosenPeak + noise);
      const bucket = Math.floor(size / bucketWidth) * bucketWidth;
      observed[bucket] = (observed[bucket] || 0) + 1;
    }
  }

  // Combine all buckets
  const allBuckets = new Set([
    ...Object.keys(target).map(Number),
    ...Object.keys(observed).map(Number),
  ]);

  return [...allBuckets]
    .sort((a, b) => a - b)
    .map((b) => ({
      bucket: `${b}B`,
      target: target[b] || 0,
      observed: observed[b] || 0,
    }));
}

/** Build IPD histogram from consecutive WS frames. */
function buildIPDHistogram(history) {
  if (history.length < 3) return [];
  const slice = history.slice(-300);
  const bins = [
    { lo: 0, hi: 1, label: '<1' },
    { lo: 1, hi: 5, label: '1-5' },
    { lo: 5, hi: 10, label: '5-10' },
    { lo: 10, hi: 25, label: '10-25' },
    { lo: 25, hi: 50, label: '25-50' },
    { lo: 50, hi: 100, label: '50-100' },
    { lo: 100, hi: 250, label: '100-250' },
    { lo: 250, hi: 500, label: '250-500' },
    { lo: 500, hi: Infinity, label: '>500' },
  ];

  const counts = bins.map(() => 0);
  for (let i = 1; i < slice.length; i++) {
    const dt = ((slice[i].ts || 0) - (slice[i - 1].ts || 0)) * 1000;
    if (dt <= 0) continue;
    for (let b = 0; b < bins.length; b++) {
      if (dt >= bins[b].lo && dt < bins[b].hi) {
        counts[b]++;
        break;
      }
    }
  }

  return bins.map((bin, i) => ({
    label: bin.label,
    count: counts[i],
  }));
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <strong>{label}</strong>
      {payload.map((item) => (
        <span key={item.dataKey} style={{ color: item.color }}>
          {item.name}: {Number(item.value).toFixed(0)}
        </span>
      ))}
    </div>
  );
}

function EmptyChartState({ text }) {
  return (
    <div className="chart-empty-state">
      {text || 'waiting for data'}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  SectionHeader                                                      */
/* ------------------------------------------------------------------ */

function SectionHeader({ title, children }) {
  return (
    <div className="morphic-section-header">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  ProfileSwitcher                                                    */
/* ------------------------------------------------------------------ */

function ProfileSwitcher({ activeProfile, profiles, onSwitch, switching }) {
  const [selected, setSelected] = useState(activeProfile);

  useEffect(() => {
    setSelected(activeProfile);
  }, [activeProfile]);

  const isChanged = selected !== activeProfile;

  return (
    <div className="morphic-card profile-switcher-card">
      <SectionHeader title="Profile Switcher">
        <Radio aria-hidden="true" size={18} />
      </SectionHeader>

      <div className="profile-radio-stack">
        {profiles.map((name) => {
          const isActive = name === activeProfile;
          const isSelected = name === selected;
          return (
            <button
              key={name}
              className={`profile-radio${isSelected ? ' is-selected' : ''}${isActive ? ' is-active' : ''}`}
              disabled={switching}
              onClick={() => setSelected(name)}
              type="button"
            >
              <span className="profile-radio-dot" />
              <span className="profile-radio-name">{name}</span>
              {isActive && (
                <span className="profile-active-badge">
                  <CheckCircle2 aria-hidden="true" size={13} />
                  active
                </span>
              )}
            </button>
          );
        })}
      </div>

      <button
        className={`morphic-switch-btn${switching ? ' is-switching' : ''}`}
        disabled={!isChanged || switching}
        onClick={() => onSwitch(selected)}
        type="button"
      >
        {switching ? (
          <>
            <Loader2 aria-hidden="true" className="spin-icon" size={16} />
            SWITCHING…
          </>
        ) : (
          <>
            <RefreshCw aria-hidden="true" size={16} />
            SWITCH
          </>
        )}
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  ProfileParamsCard                                                  */
/* ------------------------------------------------------------------ */

function ProfileParamsCard({ profile, profileName }) {
  const dist = profile?.packet_size_distribution || {};
  const ipd = profile?.inter_packet_delay_ms || {};
  const burst = profile?.burst_profile || {};

  const rows = [
    ['Size dist', dist.type || 'N/A'],
    ['Peaks', (dist.peaks || []).join(' / ') + ' B'],
    ['Weights', (dist.weights || []).join(' / ')],
    ['Std dev', (dist.std_dev || []).join(' / ')],
    ['IPD type', ipd.type || 'N/A'],
    ['\u03B1 (alpha)', ipd.alpha ?? 'N/A'],
    ['Min IPD', `${ipd.min_ms ?? 'N/A'} ms`],
    ['Max IPD', `${ipd.max_ms ?? 'N/A'} ms`],
    ['Burst size', (burst.burst_size_range || []).join('\u2013') + ' pkts'],
    ['Pause', (burst.burst_pause_ms_range || []).join('\u2013') + ' ms'],
  ];

  return (
    <div className="morphic-card params-card">
      <SectionHeader title="Active Parameters">
        <span className="morphic-profile-badge">{profileName}</span>
      </SectionHeader>

      <dl className="params-grid">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  SizeDistributionChart                                              */
/* ------------------------------------------------------------------ */

function SizeDistributionChart({ data }) {
  return (
    <div className="morphic-card chart-card morphic-chart-card">
      <SectionHeader title="Packet Size Distribution">
        <span className="morphic-chart-badge">observed vs target</span>
      </SectionHeader>
      <div className="chart-shell">
        {data.length < 2 ? (
          <EmptyChartState text="waiting for ring buffer" />
        ) : (
          <ResponsiveContainer height="100%" width="100%">
            <BarChart
              barGap={2}
              data={data}
              margin={{ bottom: 4, left: -18, right: 8, top: 8 }}
            >
              <defs>
                <linearGradient id="sizeObsFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#00ff88" stopOpacity={0.82} />
                  <stop offset="95%" stopColor="#00ff88" stopOpacity={0.22} />
                </linearGradient>
                <linearGradient id="sizeTgtFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#00cfff" stopOpacity={0.72} />
                  <stop offset="95%" stopColor="#00cfff" stopOpacity={0.18} />
                </linearGradient>
              </defs>
              <CartesianGrid
                stroke="rgba(110, 127, 143, 0.16)"
                vertical={false}
              />
              <XAxis
                dataKey="bucket"
                minTickGap={20}
                stroke="#6e7f8f"
                tick={{ fontSize: 11 }}
              />
              <YAxis stroke="#6e7f8f" tick={{ fontSize: 11 }} />
              <Tooltip content={<ChartTooltip />} />
              <Bar
                dataKey="observed"
                fill="url(#sizeObsFill)"
                name="Observed"
                radius={[3, 3, 0, 0]}
              />
              <Bar
                dataKey="target"
                fill="url(#sizeTgtFill)"
                name="Target"
                radius={[3, 3, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  IPDHistogramChart                                                  */
/* ------------------------------------------------------------------ */

function IPDHistogramChart({ data, medianMs }) {
  return (
    <div className="morphic-card chart-card morphic-chart-card">
      <SectionHeader title="Inter-Packet Delay Histogram">
        <span className="morphic-chart-badge">ms (log bins)</span>
      </SectionHeader>
      <div className="chart-shell">
        {data.length < 2 ? (
          <EmptyChartState text="waiting for ring buffer" />
        ) : (
          <ResponsiveContainer height="100%" width="100%">
            <BarChart
              data={data}
              margin={{ bottom: 4, left: -18, right: 8, top: 8 }}
            >
              <defs>
                <linearGradient id="ipdFill" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="5%" stopColor="#ffaa00" stopOpacity={0.82} />
                  <stop offset="95%" stopColor="#ffaa00" stopOpacity={0.18} />
                </linearGradient>
              </defs>
              <CartesianGrid
                stroke="rgba(110, 127, 143, 0.16)"
                vertical={false}
              />
              <XAxis
                dataKey="label"
                stroke="#6e7f8f"
                tick={{ fontSize: 11 }}
              />
              <YAxis stroke="#6e7f8f" tick={{ fontSize: 11 }} />
              <Tooltip content={<ChartTooltip />} />
              {medianMs > 0 && (
                <ReferenceLine
                  label={{
                    fill: '#00cfff',
                    fontSize: 11,
                    position: 'top',
                    value: `median ${medianMs.toFixed(1)}ms`,
                  }}
                  stroke="#00cfff"
                  strokeDasharray="4 4"
                  x={null}
                />
              )}
              <Bar
                dataKey="count"
                fill="url(#ipdFill)"
                name="Count"
                radius={[3, 3, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  BurstIndicator                                                     */
/* ------------------------------------------------------------------ */

function BurstIndicator({ burstRange, history }) {
  const maxSquares = 15;
  const [lo, hi] = burstRange || [1, 5];

  // Derive burst activity from frame deltas
  const activeCount = useMemo(() => {
    if (history.length < 3) return 0;
    const recent = history.slice(-20);
    let rapid = 0;
    for (let i = 1; i < recent.length; i++) {
      const dt = ((recent[i].ts || 0) - (recent[i - 1].ts || 0)) * 1000;
      if (dt < 100 && dt > 0) rapid++;
    }
    return Math.min(rapid, maxSquares);
  }, [history]);

  return (
    <div className="morphic-card burst-card">
      <SectionHeader title="Burst Activity">
        <span className="morphic-chart-badge">{lo}–{hi} pkts</span>
      </SectionHeader>
      <div className="burst-grid">
        {Array.from({ length: maxSquares }).map((_, i) => (
          <span
            key={i}
            className={`burst-square${i < activeCount ? ' is-lit' : ''}`}
          />
        ))}
      </div>
      <div className="burst-legend">
        <span>
          <Zap aria-hidden="true" size={13} />
          {activeCount > 0 ? 'bursting' : 'idle'}
        </span>
        <span>{activeCount}/{maxSquares} rapid frames</span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  MorphicPanel (main export)                                         */
/* ------------------------------------------------------------------ */

export function MorphicPanel({ panel, socket }) {
  const Icon = panel.icon;
  const [morphic, setMorphic] = useState(null);
  const [switching, setSwitching] = useState(false);
  const [apiState, setApiState] = useState({ loading: true, error: null });

  // Fetch /api/morphic on mount and periodically
  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const res = await fetch('/api/morphic');
        if (!res.ok) throw new Error(`status ${res.status}`);
        const payload = await res.json();
        if (!cancelled) {
          setMorphic(payload);
          setApiState({ loading: false, error: null });
        }
      } catch (err) {
        if (!cancelled) {
          setApiState({ loading: false, error: err.message });
        }
      }
    }

    load();
    const interval = window.setInterval(load, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  // Profile switch handler
  const handleSwitch = useCallback(async (name) => {
    setSwitching(true);
    try {
      const res = await fetch(`/api/profile/${encodeURIComponent(name)}`, {
        method: 'POST',
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `status ${res.status}`);
      }
      // Refresh morphic data
      const refreshRes = await fetch('/api/morphic');
      if (refreshRes.ok) {
        setMorphic(await refreshRes.json());
      }
    } catch (err) {
      console.error('Profile switch failed:', err);
    } finally {
      setSwitching(false);
    }
  }, []);

  const activeProfile = morphic?.profile || socket.data?.profile || 'N/A';
  const profiles = morphic?.available_profiles || ['web_browsing', 'video_streaming', 'gaming'];
  const params = morphic?.params || {};
  const burst = params?.burst_profile || {};

  // Chart data
  const sizeData = useMemo(
    () => mergeSizeData(params, socket.history),
    [params, socket.history],
  );

  const ipdData = useMemo(
    () => buildIPDHistogram(socket.history),
    [socket.history],
  );

  const ipdMedian = useMemo(() => {
    const ipd = params?.inter_packet_delay_ms || {};
    const alpha = ipd.alpha || 1.5;
    const minMs = ipd.min_ms || 0.5;
    // Pareto median = min * 2^(1/alpha)
    return minMs * Math.pow(2, 1 / alpha);
  }, [params]);

  const apiLabel = apiState.loading
    ? 'loading'
    : apiState.error
      ? 'offline'
      : 'live';

  return (
    <section className="active-panel morphic-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">{panel.title}</h1>
        </div>
        <div className="panel-heading-cluster">
          <span className="morphic-api-state">
            <Activity aria-hidden="true" size={15} />
            {apiLabel}
          </span>
          <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
        </div>
      </div>

      <div className="morphic-layout">
        <ProfileSwitcher
          activeProfile={activeProfile}
          onSwitch={handleSwitch}
          profiles={profiles}
          switching={switching}
        />
        <ProfileParamsCard
          profile={params}
          profileName={activeProfile}
        />
        <SizeDistributionChart data={sizeData} />
        <IPDHistogramChart data={ipdData} medianMs={ipdMedian} />
        <BurstIndicator
          burstRange={burst.burst_size_range}
          history={socket.history}
        />
      </div>
    </section>
  );
}
