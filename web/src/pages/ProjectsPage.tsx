import { HealthPanel } from "../components/HealthPanel";
import { ProjectsPanel } from "../components/ProjectsPanel";
import { useMe } from "../auth/me";
import { useDocumentTitle } from "../lib/title";

export function ProjectsPage() {
  const me = useMe();
  useDocumentTitle("Projects");
  return (
    <>
      <div className="page-head">
        <h1>Projects</h1>
        <p className="page-head__lede">Open a project to see its clusters and their inventory.</p>
      </div>
      <div className="stack">
        <ProjectsPanel isAdmin={me.installation_roles.includes("admin")} />
        <HealthPanel />
      </div>
    </>
  );
}
