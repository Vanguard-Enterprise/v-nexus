import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import {
  COLLECTIONS,
  agentsQueryOptions,
  clusterQueryOptions,
  clustersQueryOptions,
  isCollection,
  projectQueryOptions,
  revokeAgent,
} from "../api";
import type { Cluster, Collection, CollectionStatus } from "../api";
import { useCanManageAgents } from "../auth/me";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { ConfirmAction } from "../components/ConfirmAction";
import { ErrorState } from "../components/ErrorState";
import { Missing } from "../components/Missing";
import { ResourceBrowser } from "../components/ResourceBrowser";
import type { ResourceFilters } from "../components/ResourceBrowser";
import { StatusBadge } from "../components/StatusBadge";
import { Timestamp } from "../components/Timestamp";
import { isMissing } from "../lib/errors";
import { formatDateTime } from "../lib/format";
import { COLLECTION_STATE, CONNECTION, collectionLabel, projectPath } from "../lib/labels";
import { useDocumentTitle } from "../lib/title";

/** URL search parameters of the cluster page. */
const PARAM = { collection: "collection", namespace: "namespace", search: "search", deleted: "deleted" } as const;

function readFilters(params: URLSearchParams): ResourceFilters {
  const collection = params.get(PARAM.collection);
  return {
    collection: isCollection(collection) ? collection : COLLECTIONS[0],
    namespace: params.get(PARAM.namespace) ?? "",
    search: params.get(PARAM.search) ?? "",
    includeDeleted: params.get(PARAM.deleted) === "1",
  };
}

/** Search string for a collection tab. Keeps the other filters so switching back restores them. */
function collectionSearch(params: URLSearchParams, collection: Collection): string {
  const next = new URLSearchParams(params);
  next.set(PARAM.collection, collection);
  return `?${next.toString()}`;
}

export function ClusterPage() {
  const params = useParams();
  const slug = params.slug ?? "";
  const clusterId = params.clusterId ?? "";
  const project = useQuery(projectQueryOptions(slug));
  const cluster = useQuery(clusterQueryOptions(slug, clusterId));
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = readFilters(searchParams);
  useDocumentTitle(cluster.data?.display_name ?? "Cluster", project.data?.name);

  const onFilterChange = useCallback(
    (changes: Partial<Omit<ResourceFilters, "collection">>) => {
      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current);
          const set = (key: string, value: string) => {
            if (value === "") next.delete(key);
            else next.set(key, value);
          };
          if (changes.namespace !== undefined) set(PARAM.namespace, changes.namespace);
          if (changes.search !== undefined) set(PARAM.search, changes.search);
          if (changes.includeDeleted !== undefined) set(PARAM.deleted, changes.includeDeleted ? "1" : "");
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  const projectName = project.data?.name ?? slug;
  const crumbs = [
    { label: "Projects", to: "/" },
    { label: projectName, to: projectPath(slug) },
    { label: cluster.data?.display_name ?? "Cluster" },
  ];

  if (!cluster.data) {
    return (
      <>
        <Breadcrumbs items={crumbs} />
        <div className="page-head">
          <h1>{cluster.error ? "Cluster" : <span className="placeholder placeholder--title" />}</h1>
        </div>
        {cluster.error ? (
          <ErrorState error={cluster.error} subject="This cluster" onRetry={() => void cluster.refetch()} />
        ) : (
          <p className="muted">Loading cluster…</p>
        )}
      </>
    );
  }

  const data = cluster.data;
  return (
    <>
      <Breadcrumbs items={crumbs} />
      <ClusterHeader cluster={data} />
      <div className="stack">
        {cluster.error && !isMissing(cluster.error) && (
          <p className="callout" data-tone="degraded" role="alert">
            The cluster status could not be refreshed. {cluster.error.message} Showing the status received at{" "}
            {formatDateTime(new Date(cluster.dataUpdatedAt).toISOString())}.
          </p>
        )}
        <StaleBanner cluster={data} />

        <section className="panel" aria-labelledby="inventory-heading">
          <header className="panel__header">
            <h2 id="inventory-heading">Inventory</h2>
          </header>
          <CollectionNav cluster={data} selected={filters.collection} params={searchParams} />
          <CollectionStatusLine status={data.collections.find((c) => c.collection === filters.collection)} />
          <ResourceBrowser slug={slug} clusterId={clusterId} filters={filters} onChange={onFilterChange} />
        </section>

        <AgentPanel slug={slug} cluster={data} />
      </div>
    </>
  );
}

function ClusterHeader({ cluster }: { cluster: Cluster }) {
  const connection = CONNECTION[cluster.connection.state];
  return (
    <div className="cluster-head" data-tone={connection.tone}>
      <div className="cluster-head__title">
        <h1>{cluster.display_name}</h1>
        <StatusBadge tone={connection.tone}>{connection.label}</StatusBadge>
      </div>
      <dl className="facts">
        <div>
          <dt>{cluster.connection.state === "connected" ? "Connected since" : "Last seen"}</dt>
          <dd>
            <Timestamp
              value={
                cluster.connection.state === "connected"
                  ? cluster.connection.connected_since
                  : cluster.connection.last_seen_at
              }
            />
          </dd>
        </div>
        <div>
          <dt>Kubernetes</dt>
          <dd className="mono">{cluster.connection.kubernetes_version ?? <Missing label="Unknown" />}</dd>
        </div>
        <div>
          <dt>Agent</dt>
          <dd>
            <AgentSummary cluster={cluster} />
          </dd>
        </div>
        <div>
          <dt>Last inventory</dt>
          <dd>
            <Timestamp value={cluster.inventory.last_observed_at} fallback="None yet" />
          </dd>
        </div>
        <div>
          <dt>Registered</dt>
          <dd>
            <Timestamp value={cluster.created_at} />
          </dd>
        </div>
      </dl>
    </div>
  );
}

function AgentSummary({ cluster }: { cluster: Cluster }) {
  if (!cluster.agent) return <span className="muted">Not enrolled</span>;
  if (cluster.agent.status === "revoked") return <StatusBadge tone="down">Revoked</StatusBadge>;
  return (
    <>
      <StatusBadge tone="ok">Active</StatusBadge> <span className="mono">{cluster.agent.agent_version}</span>
    </>
  );
}

/** Explains that the inventory shown is not live whenever the cluster is not connected. */
export function StaleBanner({ cluster }: { cluster: Cluster }) {
  if (!cluster.inventory.stale) return null;
  const revoked = cluster.agent?.status === "revoked";
  const lastObserved = cluster.inventory.last_observed_at;

  if (cluster.connection.state === "never_connected" && lastObserved === null) {
    return (
      <div className="callout" data-tone="pending" role="status">
        <p className="callout__title">Waiting for the agent</p>
        <p>
          This cluster has not connected yet. Its inventory appears here once the agent is installed and connects.
        </p>
      </div>
    );
  }

  return (
    <div className="callout callout--stale" data-tone="degraded" role="status">
      <p className="callout__title">
        {lastObserved === null
          ? "This cluster is disconnected. No inventory has been received yet."
          : `Showing the last inventory received at ${formatDateTime(lastObserved)}.`}
      </p>
      <p>
        {revoked
          ? "The cluster's agent was revoked, so it will not reconnect. Enroll a new agent to resume updates."
          : "The cluster is disconnected, so resources may have changed since then. The inventory updates when the agent reconnects."}
      </p>
    </div>
  );
}

function CollectionNav({
  cluster,
  selected,
  params,
}: {
  cluster: Cluster;
  selected: Collection;
  params: URLSearchParams;
}) {
  return (
    <nav className="collections" aria-label="Collections">
      <ul>
        {COLLECTIONS.map((collection) => {
          const status = cluster.collections.find((c) => c.collection === collection);
          const state = status ? COLLECTION_STATE[status.state] : COLLECTION_STATE.never_synced;
          const count = status?.resource_count ?? cluster.inventory.counts[collection];
          const current = collection === selected;
          return (
            <li key={collection}>
              <Link
                to={{ search: collectionSearch(params, collection) }}
                className="collections__link"
                aria-current={current ? "page" : undefined}
                replace
              >
                <span className="collections__dot" data-tone={state.tone} aria-hidden="true" />
                <span>{collectionLabel(collection)}</span>
                <span className="collections__count">{count ?? 0}</span>
                {status?.state === "error" && <span className="visually-hidden">, collection error</span>}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

function CollectionStatusLine({ status }: { status: CollectionStatus | undefined }) {
  if (!status) {
    return <p className="collection-status muted">This collection has not been reported by the agent.</p>;
  }
  const state = COLLECTION_STATE[status.state];
  return (
    <div className="collection-status">
      <p>
        <StatusBadge tone={state.tone}>{state.label}</StatusBadge>{" "}
        <span className="muted">
          {status.last_snapshot_completed_at === null ? (
            "No complete snapshot yet."
          ) : (
            <>
              Last full snapshot <Timestamp value={status.last_snapshot_completed_at} />.
            </>
          )}
        </span>
      </p>
      {status.error && (
        <div className="callout" data-tone="down" role="alert">
          <p className="callout__title">
            The agent could not read this collection: <code>{status.error.reason}</code>
          </p>
          <p>{status.error.message}</p>
          <p className="muted">
            Reported <Timestamp value={status.error.observed_at} />. The resources below are from the last successful
            read.
          </p>
        </div>
      )}
    </div>
  );
}

function AgentPanel({ slug, cluster }: { slug: string; cluster: Cluster }) {
  const canManage = useCanManageAgents();
  const queryClient = useQueryClient();
  const agents = useQuery({ ...agentsQueryOptions(slug), enabled: cluster.agent !== null });
  const agent = agents.data?.find((a) => a.id === cluster.agent?.id);
  const revoke = useMutation({
    mutationFn: (agentId: string) => revokeAgent(slug, agentId),
    onSettled: () =>
      Promise.all([
        queryClient.invalidateQueries({ queryKey: clustersQueryOptions(slug).queryKey }),
        queryClient.invalidateQueries({ queryKey: agentsQueryOptions(slug).queryKey }),
      ]),
  });

  return (
    <section className="panel" aria-labelledby="agent-heading">
      <header className="panel__header">
        <h2 id="agent-heading">Agent</h2>
      </header>
      <div className="panel__body">
        {cluster.agent === null ? (
          <p className="muted">No agent is enrolled for this cluster.</p>
        ) : (
          <>
            <dl className="facts facts--plain">
              <div>
                <dt>Status</dt>
                <dd>
                  <AgentSummary cluster={cluster} />
                </dd>
              </div>
              <div>
                <dt>Enrolled</dt>
                <dd>{agent ? <Timestamp value={agent.enrolled_at} /> : <Missing label="Unknown" />}</dd>
              </div>
              {agent?.revoked_at && (
                <div>
                  <dt>{agent.revocation_reason === "replaced" ? "Replaced" : "Revoked"}</dt>
                  <dd>
                    <Timestamp value={agent.revoked_at} />
                  </dd>
                </div>
              )}
              <div>
                <dt>Key ID</dt>
                <dd className="mono truncate" title={agent?.key_id}>
                  {agent?.key_id ?? <Missing label="Unknown" />}
                </dd>
              </div>
              <div>
                <dt>Agent ID</dt>
                <dd className="mono truncate" title={cluster.agent.id}>
                  {cluster.agent.id}
                </dd>
              </div>
            </dl>
            {canManage && cluster.agent.status === "active" && (
              <ConfirmAction
                label="Revoke agent"
                description={`Revoke the agent for ${cluster.display_name}? It is disconnected at once and cannot reconnect. The cluster and its last inventory stay in Vanguard Nexus.`}
                pending={revoke.isPending}
                error={revoke.error}
                onConfirm={() => {
                  if (cluster.agent) revoke.mutate(cluster.agent.id);
                }}
                onCancel={revoke.reset}
              />
            )}
          </>
        )}
      </div>
    </section>
  );
}
