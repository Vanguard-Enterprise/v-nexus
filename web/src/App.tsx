import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import { BrowserRouter, Link, useLocation } from "react-router";
import { API_BASE, isUnauthorized, meQueryOptions } from "./api";
import { MeContext } from "./auth/me";
import { HealthPanel } from "./components/HealthPanel";
import { SignInPanel } from "./components/SignInPanel";
import { UserMenu } from "./components/UserMenu";
import { AppRoutes } from "./routes";

export function App() {
  return (
    <BrowserRouter>
      <Shell />
    </BrowserRouter>
  );
}

function Shell() {
  const me = useQuery(meQueryOptions);
  const location = useLocation();
  const main = useRef<HTMLElement>(null);
  const firstPath = useRef(location.pathname);

  // After client-side navigation, move focus to the new page so screen readers announce it.
  useEffect(() => {
    if (location.pathname === firstPath.current) return;
    firstPath.current = location.pathname;
    main.current?.focus();
  }, [location.pathname]);

  let content;
  if (me.data) {
    content = (
      <MeContext value={me.data}>
        <AppRoutes />
      </MeContext>
    );
  } else if (isUnauthorized(me.error)) {
    content = (
      <SignedOut>
        <SignInPanel error={me.error} location={location} />
      </SignedOut>
    );
  } else if (me.error) {
    content = (
      <SignedOut>
        <p className="notice" role="alert">
          Your session could not be checked. {me.error.message}
        </p>
      </SignedOut>
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
          <Link className="brand" to="/">
            <img className="brand__mark" src="/favicon.svg" alt="" width="28" height="28" />
            <span className="brand__name">Vanguard Nexus</span>
          </Link>
          {me.data ? (
            <UserMenu me={me.data} />
          ) : (
            <span className="topbar__api" title="API base path">
              API <code>{API_BASE}</code>
            </span>
          )}
        </div>
      </header>

      <main id="main" className="main" tabIndex={-1} ref={main}>
        {content}
      </main>
    </div>
  );
}

function SignedOut({ children }: { children: ReactNode }) {
  return (
    <>
      <div className="page-head">
        <h1>Vanguard Nexus</h1>
        <p className="page-head__lede">Sign in to see your projects and clusters.</p>
      </div>
      <div className="stack">
        {children}
        <HealthPanel />
      </div>
    </>
  );
}
