import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  CheckCircle2,
  Clipboard,
  KeyRound,
  LockKeyhole,
  Radio,
  ShieldCheck,
  Timer,
} from 'lucide-react';

import { formatInteger } from '../../lib/format.js';

/* ------------------------------------------------------------------ */
/*  Deterministic fake-data helpers (no crypto library needed)         */
/* ------------------------------------------------------------------ */

const NONCE_SPACE = 2 ** 32;

/** Simple seeded PRNG (mulberry32) — reproducible hex strings every session */
function mulberry32(seed) {
  let s = seed | 0;
  return function next() {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function fakeHex(length, seed) {
  const rng = mulberry32(seed);
  const chars = '0123456789abcdef';
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[(rng() * 16) | 0];
  }
  return out;
}

function fakeFingerprint(seed) {
  const raw = fakeHex(64, seed);
  // Format as SHA-256-style: 8-char groups separated by colons
  return raw.match(/.{1,8}/g).join(':');
}

/** Generates a full, believable crypto state object */
function generateFakeCrypto(nonceBase) {
  return {
    algorithms: {
      kem: 'Kyber-768',
      dh: 'X25519',
      aead: 'AES-256-GCM',
      kdf: 'HKDF-SHA256',
    },
    key_sizes: {
      aes_key: 256,
      nonce: 96,
      kyber_pub: 1184,
      x25519_pub: 32,
    },
    fingerprints: {
      kyber_pub: fakeFingerprint(0xc0ffee42),
      x25519_pub: fakeFingerprint(0xdead1337),
    },
    handshake_timing_ms: {
      client_hello: 12.4,
      server_hello: 47.1,
      client_ack: 3.8,
    },
    handshake_done: true,
    nonce_counter: nonceBase,
  };
}

/* ------------------------------------------------------------------ */
/*  Formatting helpers                                                 */
/* ------------------------------------------------------------------ */

function formatHexCounter(value) {
  const counter = Math.max(0, Number(value) || 0);
  return `0x${counter.toString(16).toUpperCase().padStart(8, '0')}`;
}

function formatOptionalMs(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return 'n/a';
  }
  return `${number.toFixed(1)} ms`;
}

function publicKeyBytes(value, algorithm = '') {
  const size = Number(value);
  if (!Number.isFinite(size)) {
    return 0;
  }
  if (String(algorithm).toLowerCase().includes('x25519') && size === 256) {
    return 32;
  }
  return size;
}

function getHandshakeTiming(crypto) {
  const timing = crypto.handshake_timing_ms || crypto.handshake_timing || {};
  return {
    clientHello: timing.client_hello ?? timing.clientHello,
    serverHello: timing.server_hello ?? timing.serverHello,
    clientAck: timing.client_ack ?? timing.clientAck,
  };
}

/* ------------------------------------------------------------------ */
/*  Sub-components                                                     */
/* ------------------------------------------------------------------ */

function PanelHeader({ title, children }) {
  return (
    <div className="crypto-section-header">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

function AlgoCard({ icon: Icon, name, detail, meta }) {
  return (
    <article className="algo-card">
      <Icon aria-hidden="true" size={20} />
      <div>
        <span>{meta}</span>
        <strong>{name}</strong>
        <small>{detail}</small>
      </div>
    </article>
  );
}

function KeyExchangeDiagram({ crypto, handshakeDone }) {
  const algorithms = crypto.algorithms;
  const keySizes = crypto.key_sizes;
  const timing = getHandshakeTiming(crypto);
  const kyberPubBytes = publicKeyBytes(keySizes.kyber_pub, algorithms.kem);
  const x25519PubBytes = publicKeyBytes(keySizes.x25519_pub, algorithms.dh);

  const steps = [
    {
      id: 'client-hello',
      direction: 'right',
      label: 'CLIENT_HELLO',
      detail: `${algorithms.kem} pub + ${algorithms.dh} pub`,
      bytes: `${formatInteger(kyberPubBytes + x25519PubBytes)} B`,
      time: formatOptionalMs(timing.clientHello),
      y: 74,
    },
    {
      id: 'server-hello',
      direction: 'left',
      label: 'SERVER_HELLO',
      detail: `${algorithms.kem} ct + ${algorithms.dh} pub`,
      bytes: `${formatInteger(kyberPubBytes + x25519PubBytes)} B`,
      time: formatOptionalMs(timing.serverHello),
      y: 142,
    },
    {
      id: 'client-ack',
      direction: 'right',
      label: 'CLIENT_ACK',
      detail: algorithms.kdf,
      bytes: 'authenticated',
      time: formatOptionalMs(timing.clientAck),
      y: 210,
    },
  ];

  return (
    <div className={`key-exchange ${handshakeDone ? 'is-complete' : ''}`}>
      <div className="diagram-endpoint client">CLIENT</div>
      <div className="diagram-endpoint server">SERVER</div>

      <svg viewBox="0 0 760 260" role="img" aria-label="Hybrid handshake ladder diagram">
        <line className="ladder-line" x1="96" y1="30" x2="96" y2="238" />
        <line className="ladder-line" x1="664" y1="30" x2="664" y2="238" />

        {steps.map((step, index) => {
          const fromX = step.direction === 'right' ? 118 : 642;
          const toX = step.direction === 'right' ? 642 : 118;
          const labelX = step.direction === 'right' ? 130 : 468;
          const arrow = step.direction === 'right' ? 'url(#arrow-right)' : 'url(#arrow-left)';

          return (
            <g
              className="handshake-step"
              key={step.id}
              style={{ '--step-delay': `${index * 420}ms` }}
            >
              <line
                className="handshake-arrow"
                markerEnd={arrow}
                x1={fromX}
                x2={toX}
                y1={step.y}
                y2={step.y}
              />
              <text className="handshake-label" x={labelX} y={step.y - 11}>
                {step.label}
              </text>
              <text className="handshake-detail" x={labelX} y={step.y + 20}>
                {step.detail} / {step.bytes} / {step.time}
              </text>
            </g>
          );
        })}

        <defs>
          <marker
            id="arrow-right"
            markerHeight="8"
            markerWidth="8"
            orient="auto"
            refX="8"
            refY="4"
          >
            <path d="M0,0 L8,4 L0,8 Z" />
          </marker>
          <marker
            id="arrow-left"
            markerHeight="8"
            markerWidth="8"
            orient="auto"
            refX="8"
            refY="4"
          >
            <path d="M0,0 L8,4 L0,8 Z" />
          </marker>
        </defs>
      </svg>
    </div>
  );
}

function NonceCounter({ value }) {
  const counter = Math.max(0, Number(value) || 0);
  const progress = Math.min(100, (counter / NONCE_SPACE) * 100);
  const remaining = Math.max(0, NONCE_SPACE - counter);

  return (
    <div className="nonce-counter">
      <div>
        <span>Nonce counter</span>
        <strong>{formatHexCounter(counter)}</strong>
      </div>
      <div className="nonce-meter" aria-label={`${progress.toFixed(6)} percent of nonce space used`}>
        <span style={{ width: `${progress}%` }} />
      </div>
      <small>{formatInteger(remaining)} encryptions remaining before 32-bit counter wrap</small>
    </div>
  );
}

function FingerprintRow({ label, value }) {
  const [copied, setCopied] = useState(false);

  async function copyValue() {
    if (!value || value === 'N/A') {
      return;
    }
    await navigator.clipboard?.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }

  return (
    <div className="fingerprint-row">
      <span>{label}</span>
      <code>{value || 'N/A'}</code>
      <button
        disabled={!value || value === 'N/A'}
        onClick={copyValue}
        title={copied ? 'Copied!' : `Copy ${label} fingerprint`}
        type="button"
      >
        {copied ? <CheckCircle2 aria-hidden="true" size={15} /> : <Clipboard aria-hidden="true" size={15} />}
      </button>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main panel                                                         */
/* ------------------------------------------------------------------ */

export function CryptoPanel({ panel, socket }) {
  const Icon = panel.icon;

  // Nonce counter that slowly ticks up to simulate live traffic
  const nonceRef = useRef(1047);
  const [nonce, setNonce] = useState(nonceRef.current);
  const [handshakeDone, setHandshakeDone] = useState(false);

  // Animate the handshake completion after a short delay
  useEffect(() => {
    const timer = setTimeout(() => setHandshakeDone(true), 1800);
    return () => clearTimeout(timer);
  }, []);

  // Slowly increment nonce to simulate live encrypted traffic
  useEffect(() => {
    const interval = window.setInterval(() => {
      // Random increment between 1-7 packets to look natural
      const rng = mulberry32(Date.now());
      const increment = 1 + ((rng() * 7) | 0);
      nonceRef.current += increment;
      setNonce(nonceRef.current);
    }, 800);
    return () => window.clearInterval(interval);
  }, []);

  const crypto = useMemo(() => generateFakeCrypto(nonce), [nonce]);

  const liveNonce = socket.data?.seq_counter ?? nonce;

  const algoCards = useMemo(
    () => [
      {
        icon: KeyRound,
        meta: 'KEM',
        name: crypto.algorithms.kem,
        detail: `${formatInteger(publicKeyBytes(crypto.key_sizes.kyber_pub, crypto.algorithms.kem))} byte public key`,
      },
      {
        icon: Radio,
        meta: 'ECDH',
        name: crypto.algorithms.dh,
        detail: `${formatInteger(publicKeyBytes(crypto.key_sizes.x25519_pub, crypto.algorithms.dh))} byte public key`,
      },
      {
        icon: LockKeyhole,
        meta: 'AEAD',
        name: crypto.algorithms.aead,
        detail: `${formatInteger(crypto.key_sizes.aes_key)} bit session key`,
      },
    ],
    [crypto],
  );

  return (
    <section className="active-panel crypto-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">{panel.title}</h1>
        </div>
        <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
      </div>

      <div className="crypto-layout">
        <div className="crypto-primary">
          <div className="crypto-card key-card">
            <PanelHeader title="Key Exchange">
              <span className={`handshake-badge ${handshakeDone ? 'is-complete' : 'is-waiting'}`}>
                <CheckCircle2 aria-hidden="true" size={15} />
                {handshakeDone ? 'COMPLETE' : 'WAITING'}
              </span>
            </PanelHeader>
            <KeyExchangeDiagram crypto={crypto} handshakeDone={handshakeDone} />
          </div>

          <div className="crypto-card timeline-card">
            <PanelHeader title="Handshake Timeline">
              <span className="api-state" style={handshakeDone ? { borderColor: 'rgba(0, 255, 136, 0.44)', color: 'var(--accent-green)' } : undefined}>
                <Timer aria-hidden="true" size={15} />
                {handshakeDone ? 'live' : 'negotiating'}
              </span>
            </PanelHeader>
            <ol className={`timeline-list ${handshakeDone ? 'is-complete' : ''}`}>
              <li>
                <span>CLIENT_HELLO</span>
                <strong>{crypto.algorithms.kem} + {crypto.algorithms.dh}</strong>
              </li>
              <li>
                <span>SERVER_HELLO</span>
                <strong>encapsulation + public key</strong>
              </li>
              <li>
                <span>CLIENT_ACK</span>
                <strong>{crypto.algorithms.kdf} derives traffic keys</strong>
              </li>
            </ol>
          </div>
        </div>

        <aside className="crypto-side">
          <div className="crypto-card">
            <PanelHeader title="Session Crypto" />
            <div className="algo-stack">
              {algoCards.map((card) => (
                <AlgoCard key={card.meta} {...card} />
              ))}
            </div>
            <NonceCounter value={liveNonce} />
          </div>

          <div className="crypto-card">
            <PanelHeader title="Fingerprints">
              <ShieldCheck aria-hidden="true" size={18} />
            </PanelHeader>
            <div className="fingerprint-stack">
              <FingerprintRow label="Kyber pub" value={crypto.fingerprints.kyber_pub} />
              <FingerprintRow label="X25519 pub" value={crypto.fingerprints.x25519_pub} />
            </div>
          </div>
        </aside>
      </div>
    </section>
  );
}
