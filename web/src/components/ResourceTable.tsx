import type { ReactNode } from "react";
import { Link } from "react-router";
import { isNamespaced } from "../api";
import type {
  Collection,
  DaemonSetSummary,
  NamespaceSummary,
  NodeSummary,
  ReplicatedSummary,
  Resource,
} from "../api";
import { resourcePath } from "../lib/labels";
import { Missing } from "./Missing";
import { StatusBadge } from "./StatusBadge";
import { Timestamp } from "./Timestamp";

interface Column {
  header: string;
  numeric?: boolean;
  cell: (resource: Resource) => ReactNode;
}

function node(r: Resource): NodeSummary | null {
  return r.summary.collection === "v1/nodes" ? r.summary.value : null;
}

function namespaceSummary(r: Resource): NamespaceSummary | null {
  return r.summary.collection === "v1/namespaces" ? r.summary.value : null;
}

function replicated(r: Resource): ReplicatedSummary | null {
  return r.summary.collection === "apps/v1/deployments" || r.summary.collection === "apps/v1/statefulsets"
    ? r.summary.value
    : null;
}

function daemonSet(r: Resource): DaemonSetSummary | null {
  return r.summary.collection === "apps/v1/daemonsets" ? r.summary.value : null;
}

function text(value: string | null | undefined, mono = false): ReactNode {
  if (value === null || value === undefined || value === "") return <Missing />;
  return mono ? <span className="mono">{value}</span> : value;
}

function list(values: string[] | null | undefined, mono = false): ReactNode {
  if (!values || values.length === 0) return <Missing />;
  return (
    <ul className={`cell-list${mono ? " mono" : ""}`}>
      {values.map((value) => (
        <li key={value}>{value}</li>
      ))}
    </ul>
  );
}

/** "2 of 3" readiness, flagged when fewer are ready than wanted. */
function readiness(ready: number | null | undefined, wanted: number | null | undefined): ReactNode {
  if (ready === null || ready === undefined || wanted === null || wanted === undefined) return <Missing />;
  const short = ready < wanted;
  return (
    <span className="readiness" data-short={short} title={`${String(ready)} of ${String(wanted)} ready`}>
      {ready}/{wanted}
    </span>
  );
}

function nodeReady(ready: boolean | null | undefined): ReactNode {
  if (ready === null || ready === undefined) return <StatusBadge tone="pending">Unknown</StatusBadge>;
  return ready ? <StatusBadge tone="ok">Ready</StatusBadge> : <StatusBadge tone="down">Not ready</StatusBadge>;
}

/** The kind-specific summary columns for a collection. */
function summaryColumns(collection: Collection): Column[] {
  switch (collection) {
    case "v1/nodes":
      return [
        { header: "Status", cell: (r) => nodeReady(node(r)?.ready) },
        { header: "Roles", cell: (r) => list(node(r)?.roles) },
        { header: "Version", cell: (r) => text(node(r)?.kubelet_version, true) },
        { header: "Internal IP", cell: (r) => text(node(r)?.internal_ip, true) },
        { header: "CPU", numeric: true, cell: (r) => text(node(r)?.cpu, true) },
        { header: "Memory", numeric: true, cell: (r) => text(node(r)?.memory, true) },
        { header: "OS image", cell: (r) => text(node(r)?.os_image) },
      ];
    case "v1/namespaces":
      return [{ header: "Phase", cell: (r) => text(namespaceSummary(r)?.phase) }];
    case "apps/v1/deployments":
    case "apps/v1/statefulsets":
      return [
        { header: "Ready", numeric: true, cell: (r) => readiness(replicated(r)?.ready_replicas, replicated(r)?.replicas) },
        { header: "Images", cell: (r) => list(replicated(r)?.images, true) },
      ];
    case "apps/v1/daemonsets":
      return [
        { header: "Ready", numeric: true, cell: (r) => readiness(daemonSet(r)?.ready, daemonSet(r)?.desired) },
        { header: "Images", cell: (r) => list(daemonSet(r)?.images, true) },
      ];
  }
}

interface ResourceTableProps {
  slug: string;
  clusterId: string;
  collection: Collection;
  resources: Resource[];
  caption: string;
}

export function ResourceTable({ slug, clusterId, collection, resources, caption }: ResourceTableProps) {
  const columns = summaryColumns(collection);
  const namespaced = isNamespaced(collection);

  return (
    <div className="table-wrap">
      <table className="table table--dense">
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            {namespaced && <th scope="col">Namespace</th>}
            {columns.map((column) => (
              <th key={column.header} scope="col" className={column.numeric ? "num" : undefined}>
                {column.header}
              </th>
            ))}
            <th scope="col">Last observed</th>
          </tr>
        </thead>
        <tbody>
          {resources.map((resource) => (
            <tr key={resource.id} data-deleted={resource.state === "deleted"}>
              <th scope="row">
                <Link className="table__primary mono" to={resourcePath(slug, clusterId, resource.id)}>
                  {resource.name}
                </Link>
                {resource.state === "deleted" && (
                  <span className="tag tag--deleted">
                    Deleted {resource.deleted_at && <Timestamp value={resource.deleted_at} />}
                  </span>
                )}
              </th>
              {namespaced && <td className="mono">{resource.namespace ?? <Missing />}</td>}
              {columns.map((column) => (
                <td key={column.header} className={column.numeric ? "num" : undefined}>
                  {column.cell(resource)}
                </td>
              ))}
              <td>
                <Timestamp value={resource.last_observed_at} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
