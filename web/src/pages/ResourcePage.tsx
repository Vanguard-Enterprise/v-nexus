import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router";
import { clusterQueryOptions, isCollection, projectQueryOptions, resourceQueryOptions } from "../api";
import type { ResourceDetail, ResourceSummary } from "../api";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { CopyButton } from "../components/CopyButton";
import { ErrorState } from "../components/ErrorState";
import { Missing } from "../components/Missing";
import { StatusBadge } from "../components/StatusBadge";
import { Timestamp } from "../components/Timestamp";
import { clusterPath, collectionLabel, projectPath } from "../lib/labels";
import { useDocumentTitle } from "../lib/title";

export function ResourcePage() {
  const params = useParams();
  const slug = params.slug ?? "";
  const clusterId = params.clusterId ?? "";
  const resourceId = params.resourceId ?? "";
  const project = useQuery(projectQueryOptions(slug));
  const cluster = useQuery(clusterQueryOptions(slug, clusterId));
  const resource = useQuery(resourceQueryOptions(slug, clusterId, resourceId));
  const data = resource.data;
  useDocumentTitle(data?.name ?? "Resource", cluster.data?.display_name);

  const collectionLink = data && isCollection(data.collection) ? `?collection=${encodeURIComponent(data.collection)}` : "";
  const crumbs = [
    { label: "Projects", to: "/" },
    { label: project.data?.name ?? slug, to: projectPath(slug) },
    { label: cluster.data?.display_name ?? "Cluster", to: `${clusterPath(slug, clusterId)}${collectionLink}` },
    { label: data ? `${data.kind} ${data.name}` : "Resource" },
  ];

  if (!data) {
    return (
      <>
        <Breadcrumbs items={crumbs} />
        <div className="page-head">
          <h1>{resource.error ? "Resource" : <span className="placeholder placeholder--title" />}</h1>
        </div>
        {resource.error ? (
          <ErrorState error={resource.error} subject="This resource" onRetry={() => void resource.refetch()} />
        ) : (
          <p className="muted">Loading resource…</p>
        )}
      </>
    );
  }

  const json = JSON.stringify(data.object, null, 2);
  return (
    <>
      <Breadcrumbs items={crumbs} />
      <div className="page-head">
        <h1 className="mono page-head__resource">{data.name}</h1>
        <p className="page-head__meta">
          <span className="badge">{data.kind}</span>
          {data.namespace !== null && (
            <span>
              in namespace <code>{data.namespace}</code>
            </span>
          )}
          {data.state === "deleted" && <StatusBadge tone="down">Deleted</StatusBadge>}
        </p>
      </div>
      <div className="stack">
        {data.state === "deleted" && (
          <div className="callout" data-tone="degraded" role="status">
            <p>
              This resource was deleted from the cluster
              {data.deleted_at && (
                <>
                  {" "}
                  <Timestamp value={data.deleted_at} />
                </>
              )}
              . Vanguard Nexus keeps its last known state.
            </p>
          </div>
        )}
        {cluster.data?.inventory.stale && (
          <p className="callout" data-tone="degraded" role="status">
            The cluster is disconnected. This is the resource as last reported by the agent.
          </p>
        )}
        <section className="panel" aria-labelledby="metadata-heading">
          <header className="panel__header">
            <h2 id="metadata-heading">Details</h2>
          </header>
          <div className="panel__body">
            <dl className="facts facts--plain">
              <Fact term="Collection">
                <Link to={`${clusterPath(slug, clusterId)}${collectionLink}`}>{collectionLabel(data.collection)}</Link>
              </Fact>
              <Fact term="UID" mono>
                {data.uid}
              </Fact>
              <Fact term="Resource version" mono>
                {data.resource_version}
              </Fact>
              <Fact term="First observed">
                <Timestamp value={data.first_observed_at} />
              </Fact>
              <Fact term="Last observed">
                <Timestamp value={data.last_observed_at} />
              </Fact>
              <SummaryFacts summary={data.summary} />
            </dl>
          </div>
        </section>
        <ObjectPanel resource={data} json={json} />
      </div>
    </>
  );
}

function Fact({ term, children, mono, wide }: { term: string; children: ReactNode; mono?: boolean; wide?: boolean }) {
  return (
    <div className={wide ? "facts__wide" : undefined}>
      <dt>{term}</dt>
      <dd className={mono ? "mono" : undefined}>{children}</dd>
    </div>
  );
}

function value(v: string | number | boolean | null): ReactNode {
  if (v === null) return <Missing label="Unknown" />;
  if (typeof v === "boolean") return v ? "Yes" : "No";
  return String(v);
}

function joined(values: string[] | null): ReactNode {
  return values && values.length > 0 ? values.join(", ") : <Missing />;
}

function SummaryFacts({ summary }: { summary: ResourceSummary }) {
  switch (summary.collection) {
    case "v1/nodes": {
      const s = summary.value;
      return (
        <>
          <Fact term="Ready">{value(s.ready)}</Fact>
          <Fact term="Roles">{joined(s.roles)}</Fact>
          <Fact term="Kubelet version" mono>
            {value(s.kubelet_version)}
          </Fact>
          <Fact term="Internal IP" mono>
            {value(s.internal_ip)}
          </Fact>
          <Fact term="CPU" mono>
            {value(s.cpu)}
          </Fact>
          <Fact term="Memory" mono>
            {value(s.memory)}
          </Fact>
          <Fact term="OS image">{value(s.os_image)}</Fact>
        </>
      );
    }
    case "v1/namespaces":
      return <Fact term="Phase">{value(summary.value.phase)}</Fact>;
    case "apps/v1/deployments":
    case "apps/v1/statefulsets":
      return (
        <>
          <Fact term="Ready replicas">
            {value(summary.value.ready_replicas)} of {value(summary.value.replicas)}
          </Fact>
          <Fact term="Images" mono wide>
            {joined(summary.value.images)}
          </Fact>
        </>
      );
    case "apps/v1/daemonsets":
      return (
        <>
          <Fact term="Ready">
            {value(summary.value.ready)} of {value(summary.value.desired)}
          </Fact>
          <Fact term="Images" mono wide>
            {joined(summary.value.images)}
          </Fact>
        </>
      );
    case "other":
      return null;
  }
}

function ObjectPanel({ resource, json }: { resource: ResourceDetail; json: string }) {
  return (
    <section className="panel" aria-labelledby="object-heading">
      <header className="panel__header panel__header--split">
        <h2 id="object-heading">Object</h2>
        <CopyButton text={json} label={`${resource.kind} ${resource.name} as JSON`} caption="Copy JSON" />
      </header>
      <p className="panel__message muted">The sanitized Kubernetes object, as last reported by the agent.</p>
      <pre className="json" tabIndex={0} aria-label={`${resource.kind} ${resource.name} as JSON`}>
        <code>{json}</code>
      </pre>
    </section>
  );
}
