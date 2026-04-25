import { useEffect, useState, useRef } from 'react';
import {
  Play,
  Square,
  CheckCircle2,
  Circle,
  CircleDot,
  XCircle,
  Terminal,
  Beaker,
  Activity,
  ListTodo
} from 'lucide-react';

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function getStatusIcon(status) {
  switch (status) {
    case 'done':
    case 'passed':
      return <CheckCircle2 size={16} className="status-icon is-done" aria-label="Completed" />;
    case 'active':
    case 'running':
      return <CircleDot size={16} className="status-icon is-active" aria-label="Active" />;
    case 'failed':
      return <XCircle size={16} className="status-icon is-failed" aria-label="Failed" />;
    default:
      return <Circle size={16} className="status-icon is-pending" aria-label="Pending" />;
  }
}

function SectionHeader({ title, children }) {
  return (
    <div className="demo-section-header">
      <h2>{title}</h2>
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  DemoSequenceList                                                   */
/* ------------------------------------------------------------------ */

function DemoSequenceList({ steps, status, onStart, onStop }) {
  const isRunning = status === 'running';

  return (
    <div className="demo-card demo-sequence-card">
      <SectionHeader title="Demo Sequence">
        <ListTodo size={18} aria-hidden="true" />
      </SectionHeader>

      <div className="demo-steps-list">
        {steps.map((step, idx) => (
          <div key={idx} className={`demo-step-row is-${step.status}`}>
            <span className="step-num">{(idx + 1).toString().padStart(2, '0')}</span>
            <span className="step-name">{step.name}</span>
            {getStatusIcon(step.status)}
          </div>
        ))}
      </div>

      <div className="demo-controls">
        <button
          className="demo-btn primary"
          onClick={onStart}
          disabled={isRunning}
        >
          <Play size={16} />
          {isRunning ? 'RUNNING…' : 'START DEMO'}
        </button>
        <button
          className="demo-btn danger"
          onClick={onStop}
          disabled={!isRunning}
        >
          <Square size={16} />
          STOP
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  E2ETestRunner                                                      */
/* ------------------------------------------------------------------ */

function E2ETestRunner({ tests, status, onRunTests }) {
  const isRunning = status === 'running';
  const passedCount = tests.filter((t) => t.status === 'passed').length;

  return (
    <div className="demo-card demo-tests-card">
      <SectionHeader title="E2E Test Runner">
        <Beaker size={18} aria-hidden="true" />
      </SectionHeader>

      <div className="demo-tests-list">
        {tests.map((test, idx) => (
          <div key={idx} className={`demo-test-row is-${test.status}`}>
            <span className="test-name">{test.name}</span>
            {getStatusIcon(test.status)}
          </div>
        ))}
      </div>

      <div className="demo-test-controls">
        <button
          className="demo-btn outline"
          onClick={onRunTests}
          disabled={isRunning}
        >
          <Play size={16} />
          RUN ALL TESTS
        </button>
        <span className="demo-test-results">
          Results: {passedCount}/{tests.length} passed
        </span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  DemoOutputTerminal                                                 */
/* ------------------------------------------------------------------ */

function DemoOutputTerminal({ lines }) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="demo-card demo-terminal-card">
      <SectionHeader title="Demo Output">
        <Terminal size={18} aria-hidden="true" />
      </SectionHeader>

      <div className="terminal-scroll" ref={scrollRef}>
        {lines.length === 0 ? (
          <div className="terminal-empty">Waiting for output...</div>
        ) : (
          lines.map((line, idx) => (
            <div key={idx} className="terminal-line">
              <span className="terminal-prefix">&gt; </span>
              {line}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  DemoPanel (main export)                                            */
/* ------------------------------------------------------------------ */

export function DemoPanel({ panel, socket, status }) {
  const Icon = panel.icon;
  const [demoState, setDemoState] = useState({ status: 'idle', steps: [], output_lines: [] });
  const [testState, setTestState] = useState({ status: 'idle', tests: [], output_lines: [] });
  const [apiOk, setApiOk] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const [demoRes, testRes] = await Promise.all([
          fetch('/api/demo/status'),
          fetch('/api/demo/test_status')
        ]);
        
        if (!demoRes.ok || !testRes.ok) throw new Error('API Error');

        const demoData = await demoRes.json();
        const testData = await testRes.json();

        if (!cancelled) {
          setDemoState(demoData);
          setTestState(testData);
          setApiOk(true);
        }
      } catch (err) {
        if (!cancelled) setApiOk(false);
      }
    }

    poll();
    const interval = window.setInterval(poll, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  async function handleStartDemo() {
    try {
      await fetch('/api/demo/start', { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
  }

  async function handleStopDemo() {
    try {
      await fetch('/api/demo/stop', { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
  }

  async function handleRunTests() {
    try {
      await fetch('/api/demo/run_tests', { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
  }

  // Combine lines for terminal, or prefer demo lines if demo is running
  const terminalLines = demoState.status === 'running' 
    ? demoState.output_lines 
    : testState.status === 'running' 
      ? testState.output_lines 
      : demoState.output_lines.length > 0 
        ? demoState.output_lines 
        : testState.output_lines;

  return (
    <section className="active-panel demo-panel" aria-labelledby="panel-title">
      <div className="panel-heading">
        <div>
          <span className="panel-kicker">{panel.phase}</span>
          <h1 id="panel-title">{panel.title}</h1>
        </div>
        <div className="panel-heading-cluster">
          <span className="feedback-api-state" style={{ borderColor: apiOk ? '' : 'rgba(255, 68, 68, 0.5)', color: apiOk ? '' : 'var(--accent-red)' }}>
            <Activity aria-hidden="true" size={15} />
            {apiOk ? 'live' : 'offline'}
          </span>
          <Icon aria-hidden="true" size={30} strokeWidth={1.6} />
        </div>
      </div>

      <div className="demo-layout">
        <DemoSequenceList 
          steps={demoState.steps || []} 
          status={demoState.status} 
          onStart={handleStartDemo} 
          onStop={handleStopDemo} 
        />
        <E2ETestRunner 
          tests={testState.tests || []} 
          status={testState.status} 
          onRunTests={handleRunTests} 
        />
        <DemoOutputTerminal lines={terminalLines} />
      </div>
    </section>
  );
}
