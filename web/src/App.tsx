import { API_BASE } from "./api";
import { HealthPanel } from "./components/HealthPanel";

export function App() {
  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <div className="topbar__inner">
          <a className="brand" href="/">
            <img className="brand__mark" src="/favicon.svg" alt="" width="28" height="28" />
            <span className="brand__name">Vanguard Nexus</span>
          </a>
          <span className="topbar__api" title="API base path">
            API <code>{API_BASE}</code>
          </span>
        </div>
      </header>

      <main id="main" className="main" tabIndex={-1}>
        <div className="main__intro">
          <h1>Overview</h1>
          <p>Status of this Vanguard Nexus server and the database it depends on.</p>
        </div>
        <HealthPanel />
      </main>
    </div>
  );
}
