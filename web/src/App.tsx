import { useQuery } from "@tanstack/react-query";
import { API_BASE, isUnauthorized, meQueryOptions } from "./api";
import { HealthPanel } from "./components/HealthPanel";
import { ProjectsPanel } from "./components/ProjectsPanel";
import { SignInPanel } from "./components/SignInPanel";
import { UserMenu } from "./components/UserMenu";

export function App() {
  const me = useQuery(meQueryOptions);

  let content;
  if (me.data) {
    content = <ProjectsPanel isAdmin={me.data.installation_roles.includes("admin")} />;
  } else if (isUnauthorized(me.error)) {
    content = <SignInPanel error={me.error} search={window.location.search} />;
  } else if (me.error) {
    content = (
      <p className="notice" role="alert">
        Your session could not be checked. {me.error.message}
      </p>
    );
  } else {
    content = <p className="muted">Checking your session…</p>;
  }

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
          {me.data ? (
            <UserMenu me={me.data} />
          ) : (
            <span className="topbar__api" title="API base path">
              API <code>{API_BASE}</code>
            </span>
          )}
        </div>
      </header>

      <main id="main" className="main" tabIndex={-1}>
        <div className="main__intro">
          <h1>Overview</h1>
          <p>Your projects and the status of this Vanguard Nexus server.</p>
        </div>
        <div className="stack">
          {content}
          <HealthPanel />
        </div>
      </main>
    </div>
  );
}
