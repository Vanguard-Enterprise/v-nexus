import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { clustersQueryOptions } from "../api";
import type { Cluster } from "../api";
import { CONNECTION, clusterCounts, clusterPath } from "../lib/labels";
import { ErrorState } from "./ErrorState";
import { Missing } from "./Missing";
import { StatusBadge } from "./StatusBadge";
import { Timestamp } from "./Timestamp";

interface ClustersPanelProps {
  slug: string;
  canRegister: boolean;
  /** The register form is open, so the register buttons are hidden. */
  registering: boolean;
  onRegister: () => void;
}

export function ClustersPanel({ slug, canRegister, registering, onRegister }: ClustersPanelProps) {
  const { data, error, isPending, refetch } = useQuery(clustersQueryOptions(slug));

  return (
    <section className="panel" aria-labelledby="clusters-heading" aria-busy={isPending}>
      <header className="panel__header panel__header--split">
        <h2 id="clusters-heading">Clusters</h2>
        {canRegister && !registering && data && data.length > 0 && (
          <button type="button" className="button button--primary" onClick={onRegister}>
            Register cluster
          </button>
        )}
      </header>

      {isPending && <p className="panel__message muted">Loading clusters…</p>}
      {error && !data && (
        <div className="panel__message">
          <ErrorState error={error} subject="Clusters" onRetry={() => void refetch()} />
        </div>
      )}
      {data?.length === 0 && (
        <div className="empty">
          <p className="empty__title">No clusters yet</p>
          {canRegister ? (
            <>
              <p className="muted">
                Register a cluster to create an enrollment token, then install the agent in the cluster. Its nodes,
                namespaces, and workloads appear here once the agent connects.
              </p>
              {!registering && (
                <button type="button" className="button button--primary" onClick={onRegister}>
                  Register cluster
                </button>
              )}
            </>
          ) : (
            <p className="muted">An installation admin can register a cluster in this project.</p>
          )}
        </div>
      )}
      {data && data.length > 0 && <ClustersTable slug={slug} clusters={data} />}
    </section>
  );
}

function ClustersTable({ slug, clusters }: { slug: string; clusters: Cluster[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th scope="col">Cluster</th>
            <th scope="col">Connection</th>
            <th scope="col">Inventory</th>
            <th scope="col">Kubernetes</th>
            <th scope="col">Last seen</th>
            <th scope="col" className="num">
              Nodes
            </th>
            <th scope="col" className="num">
              Namespaces
            </th>
            <th scope="col" className="num">
              Workloads
            </th>
          </tr>
        </thead>
        <tbody>
          {clusters.map((cluster) => {
            const connection = CONNECTION[cluster.connection.state];
            const counts = clusterCounts(cluster);
            return (
              <tr key={cluster.id}>
                <th scope="row">
                  <Link className="table__primary" to={clusterPath(slug, cluster.id)}>
                    {cluster.display_name}
                  </Link>
                </th>
                <td>
                  <StatusBadge tone={connection.tone}>{connection.label}</StatusBadge>
                </td>
                <td>
                  <InventoryFreshness cluster={cluster} />
                </td>
                <td className="mono">{cluster.connection.kubernetes_version ?? <Missing label="Unknown" />}</td>
                <td>
                  <Timestamp value={cluster.connection.last_seen_at} />
                </td>
                <Count value={counts.nodes} />
                <Count value={counts.namespaces} />
                <Count value={counts.workloads} />
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** The stale indicator: live while connected, otherwise how old the last inventory is. */
export function InventoryFreshness({ cluster }: { cluster: Cluster }) {
  const { stale, last_observed_at } = cluster.inventory;
  if (!stale) return <span>Live</span>;
  if (last_observed_at === null) return <span className="muted">None yet</span>;
  return (
    <span className="stale-tag">
      Stale, from <Timestamp value={last_observed_at} />
    </span>
  );
}

function Count({ value }: { value: number | null }) {
  return <td className="num">{value ?? <Missing />}</td>;
}
