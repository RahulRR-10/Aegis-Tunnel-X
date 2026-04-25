import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  FileCog,
  KeyRound,
  MonitorPlay,
  Network,
  RadioTower,
  ShieldCheck,
  SlidersHorizontal,
} from 'lucide-react';

import { Shell } from './components/Shell/Shell.jsx';
import { useAegisSocket } from './hooks/useAegisSocket.js';

const PANELS = [
  {
    id: 'crypto',
    shortLabel: 'Cryp',
    title: 'Encryption Engine',
    phase: 'F2',
    icon: KeyRound,
  },
  {
    id: 'transport',
    shortLabel: 'Trsp',
    title: 'UDP Transport',
    phase: 'F3',
    icon: RadioTower,
  },
  {
    id: 'tunnel',
    shortLabel: 'Tunl',
    title: 'Tunnel Interface',
    phase: 'F4',
    icon: Network,
  },
  {
    id: 'morphic',
    shortLabel: 'Mrph',
    title: 'Morphic Engine',
    phase: 'F5',
    icon: SlidersHorizontal,
  },
  {
    id: 'feedback',
    shortLabel: 'Fbck',
    title: 'Detection Feedback',
    phase: 'F6',
    icon: Activity,
  },
  {
    id: 'config',
    shortLabel: 'Conf',
    title: 'Configuration & Keys',
    phase: 'F7',
    icon: FileCog,
  },
  {
    id: 'demo',
    shortLabel: 'Demo',
    title: 'Demo Control Center',
    phase: 'F8',
    icon: MonitorPlay,
  },
  {
    id: 'overview',
    shortLabel: 'Ops',
    title: 'Operations Overview',
    phase: 'F1',
    icon: ShieldCheck,
  },
];

export default function App() {
  const socket = useAegisSocket();
  const [activePanelId, setActivePanelId] = useState('overview');
  const [status, setStatus] = useState({ data: null, error: null });

  useEffect(() => {
    let cancelled = false;

    async function loadStatus() {
      try {
        const response = await fetch('/api/status');
        if (!response.ok) {
          throw new Error(`status ${response.status}`);
        }

        const payload = await response.json();
        if (!cancelled) {
          setStatus({ data: payload, error: null });
        }
      } catch (statusError) {
        if (!cancelled) {
          setStatus({ data: null, error: statusError.message });
        }
      }
    }

    loadStatus();
    const interval = window.setInterval(loadStatus, 1000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  const activePanel = useMemo(
    () => PANELS.find((panel) => panel.id === activePanelId) || PANELS[0],
    [activePanelId],
  );

  return (
    <Shell
      activePanel={activePanel}
      activePanelId={activePanelId}
      onSelectPanel={setActivePanelId}
      panels={PANELS}
      socket={socket}
      status={status}
    />
  );
}
