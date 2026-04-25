export function Sidebar({ activePanelId, onSelectPanel, panels }) {
  return (
    <nav className="sidebar" aria-label="Aegis panels">
      <span className="sidebar-label">NAV</span>
      <div className="nav-stack">
        {panels.map((panel) => {
          const Icon = panel.icon;
          const active = panel.id === activePanelId;

          return (
            <button
              aria-current={active ? 'page' : undefined}
              className={`nav-item ${active ? 'is-active' : ''}`}
              key={panel.id}
              onClick={() => onSelectPanel(panel.id)}
              title={panel.title}
              type="button"
            >
              <Icon aria-hidden="true" size={19} strokeWidth={1.9} />
              <span>{panel.shortLabel}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
