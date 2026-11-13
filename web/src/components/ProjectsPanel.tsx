import { useQuery } from "@tanstack/react-query";
import { projectsQueryOptions } from "../api";
import type { Project } from "../api";

function accessLabel(project: Project): string {
  if (project.role === "operator") return "Operator";
  if (project.role === "viewer") return "Viewer";
  return "Admin";
}

export function ProjectsPanel({ isAdmin }: { isAdmin: boolean }) {
  const { data, error, isPending } = useQuery(projectsQueryOptions);

  return (
    <section className="panel" aria-labelledby="projects-heading" aria-busy={isPending}>
      <header className="panel__header">
        <h2 id="projects-heading">Projects</h2>
      </header>
      <div className="panel__body">
        {isPending && <p className="muted">Loading projects…</p>}
        {error && (
          <p role="alert">
            Projects could not be loaded. {error.message}
          </p>
        )}
        {data?.length === 0 && (
          <p className="muted">
            {isAdmin
              ? "No projects yet. Create one through the API with POST /api/v1/projects."
              : "You have no projects yet. An installation admin can grant you access."}
          </p>
        )}
        {data && data.length > 0 && (
          <ul className="project-list">
            {data.map((project) => (
              <li key={project.id}>
                <span className="project-list__name">{project.name}</span>
                <code className="project-list__slug">{project.slug}</code>
                <span className="badge">{accessLabel(project)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
