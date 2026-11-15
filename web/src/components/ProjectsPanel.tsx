import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { projectsQueryOptions } from "../api";
import { accessLabel, projectPath } from "../lib/labels";
import { ErrorState } from "./ErrorState";

export function ProjectsPanel({ isAdmin }: { isAdmin: boolean }) {
  const { data, error, isPending, refetch } = useQuery(projectsQueryOptions);

  return (
    <section className="panel" aria-labelledby="projects-heading" aria-busy={isPending}>
      <header className="panel__header">
        <h2 id="projects-heading">Your projects</h2>
      </header>
      <div className="panel__body">
        {isPending && <p className="muted">Loading projects…</p>}
        {error && <ErrorState error={error} subject="Projects" onRetry={() => void refetch()} />}
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
                <Link className="project-list__name" to={projectPath(project.slug)}>
                  {project.name}
                </Link>
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
