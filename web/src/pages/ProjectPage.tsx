import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useParams } from "react-router";
import { projectQueryOptions } from "../api";
import { useCanManageAgents } from "../auth/me";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { ClustersPanel } from "../components/ClustersPanel";
import { EnrollmentTokensPanel } from "../components/EnrollmentTokensPanel";
import { ErrorState } from "../components/ErrorState";
import { MembersPanel } from "../components/MembersPanel";
import { RegisterCluster } from "../components/RegisterCluster";
import { accessLabel } from "../lib/labels";
import { useDocumentTitle } from "../lib/title";

export function ProjectPage() {
  const slug = useParams().slug ?? "";
  const project = useQuery(projectQueryOptions(slug));
  const canManageAgents = useCanManageAgents();
  const [registering, setRegistering] = useState(false);
  useDocumentTitle(project.data?.name ?? slug);

  if (project.error) {
    return (
      <>
        <Breadcrumbs items={[{ label: "Projects", to: "/" }, { label: slug }]} />
        <div className="page-head">
          <h1>Project {slug}</h1>
        </div>
        <ErrorState error={project.error} subject={`Project ${slug}`} onRetry={() => void project.refetch()} />
      </>
    );
  }

  return (
    <>
      <Breadcrumbs items={[{ label: "Projects", to: "/" }, { label: project.data?.name ?? slug }]} />
      <div className="page-head">
        <h1>{project.data?.name ?? <span className="placeholder placeholder--title" />}</h1>
        <p className="page-head__meta">
          <code>{slug}</code>
          {project.data && <span className="badge">{accessLabel(project.data)}</span>}
        </p>
      </div>
      <div className="stack">
        {registering && canManageAgents && (
          <RegisterCluster
            slug={slug}
            onClose={() => {
              setRegistering(false);
            }}
          />
        )}
        <ClustersPanel
          slug={slug}
          canRegister={canManageAgents}
          registering={registering}
          onRegister={() => {
            setRegistering(true);
          }}
        />
        {canManageAgents && <EnrollmentTokensPanel slug={slug} />}
        <MembersPanel slug={slug} />
      </div>
    </>
  );
}
