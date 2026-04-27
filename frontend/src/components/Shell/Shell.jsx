import { ShieldAlert } from 'lucide-react';

import { ConfigPanel } from '../ConfigPanel/ConfigPanel.jsx';
import { CryptoPanel } from '../CryptoPanel/CryptoPanel.jsx';
import { DemoPanel } from '../DemoPanel/DemoPanel.jsx';
import { FeedbackPanel } from '../FeedbackPanel/FeedbackPanel.jsx';
import { MorphicPanel } from '../MorphicPanel/MorphicPanel.jsx';
import { OverviewPanel } from '../OverviewPanel/OverviewPanel.jsx';
import { TunnelPanel } from '../TunnelPanel/TunnelPanel.jsx';
import { TransportPanel } from '../TransportPanel/TransportPanel.jsx';
import { PanelPlaceholder } from './PanelPlaceholder.jsx';
import { Sidebar } from './Sidebar.jsx';
import { StatusBar } from './StatusBar.jsx';
import { TopBar } from './TopBar.jsx';

export function Shell({
  activePanel,
  activePanelId,
  onSelectPanel,
  panels,
  socket,
  status,
}) {
  return (
    <div className="aegis-shell">
      <TopBar socket={socket} status={status} />

      <div className="shell-body">
        <Sidebar
          activePanelId={activePanelId}
          onSelectPanel={onSelectPanel}
          panels={panels}
        />

        <main className="shell-main">
          {activePanel.id === 'crypto' ? (
            <CryptoPanel panel={activePanel} socket={socket} status={status} />
          ) : activePanel.id === 'transport' ? (
            <TransportPanel panel={activePanel} socket={socket} status={status} />
          ) : activePanel.id === 'tunnel' ? (
            <TunnelPanel panel={activePanel} socket={socket} status={status} />
          ) : activePanel.id === 'morphic' ? (
            <MorphicPanel panel={activePanel} socket={socket} status={status} />
          ) : activePanel.id === 'feedback' ? (
            <FeedbackPanel panel={activePanel} socket={socket} status={status} />
          ) : activePanel.id === 'demo' ? (
            <DemoPanel panel={activePanel} socket={socket} status={status} />
          ) : activePanel.id === 'config' ? (
            <ConfigPanel panel={activePanel} socket={socket} status={status} />
          ) : activePanel.id === 'overview' ? (
            <OverviewPanel panel={activePanel} socket={socket} status={status} />
          ) : (
            <PanelPlaceholder
              panel={activePanel}
              socket={socket}
              status={status}
            />
          )}

          {!socket.connected && (
            <div className="tunnel-overlay" role="status" aria-live="polite">
              <div className="overlay-box">
                <ShieldAlert aria-hidden="true" size={28} />
                <div>
                  <strong>TUNNEL NOT RUNNING</strong>
                  <span>{socket.error || 'Waiting for metrics stream'}</span>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      <StatusBar socket={socket} status={status} />
    </div>
  );
}
