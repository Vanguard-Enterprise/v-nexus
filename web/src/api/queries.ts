import { keepPreviousData, queryOptions } from "@tanstack/react-query";
import { fetchAgents } from "./agents";
import { fetchMe } from "./auth";
import { fetchCluster, fetchClusters, fetchResource, fetchResources } from "./clusters";
import type { ResourceQuery } from "./clusters";
import { fetchEnrollmentTokens } from "./enrollment";
import { fetchHealth } from "./health";
import { fetchMembers, fetchProject, fetchProjects } from "./projects";

/** How often the health panel polls the server. */
export const HEALTH_REFETCH_INTERVAL_MS = 15_000;

/** How often cluster connection and inventory status is polled. */
export const CLUSTER_REFETCH_INTERVAL_MS = 10_000;

export const healthQueryOptions = queryOptions({
  queryKey: ["health"],
  queryFn: ({ signal }) => fetchHealth(signal),
  refetchInterval: HEALTH_REFETCH_INTERVAL_MS,
});

export const meQueryOptions = queryOptions({
  queryKey: ["auth", "me"],
  queryFn: ({ signal }) => fetchMe(signal),
  staleTime: 60_000,
});

export const projectsQueryOptions = queryOptions({
  queryKey: ["projects"],
  queryFn: ({ signal }) => fetchProjects(signal),
});

/* Keys under ["project", slug] so a project's queries can be invalidated together. */

export function projectQueryOptions(slug: string) {
  return queryOptions({
    queryKey: ["project", slug],
    queryFn: ({ signal }) => fetchProject(slug, signal),
  });
}

export function membersQueryOptions(slug: string) {
  return queryOptions({
    queryKey: ["project", slug, "members"],
    queryFn: ({ signal }) => fetchMembers(slug, signal),
  });
}

export function clustersQueryOptions(slug: string) {
  return queryOptions({
    queryKey: ["project", slug, "clusters"],
    queryFn: ({ signal }) => fetchClusters(slug, signal),
    refetchInterval: CLUSTER_REFETCH_INTERVAL_MS,
  });
}

export function clusterQueryOptions(slug: string, clusterId: string) {
  return queryOptions({
    queryKey: ["project", slug, "clusters", clusterId],
    queryFn: ({ signal }) => fetchCluster(slug, clusterId, signal),
    refetchInterval: CLUSTER_REFETCH_INTERVAL_MS,
  });
}

export function resourcesQueryOptions(slug: string, clusterId: string, query: ResourceQuery) {
  return queryOptions({
    queryKey: ["project", slug, "clusters", clusterId, "resources", query],
    queryFn: ({ signal }) => fetchResources(slug, clusterId, query, signal),
    // Keep the current page on screen while the next one loads.
    placeholderData: keepPreviousData,
  });
}

export function resourceQueryOptions(slug: string, clusterId: string, resourceId: string) {
  return queryOptions({
    queryKey: ["project", slug, "clusters", clusterId, "resource", resourceId],
    queryFn: ({ signal }) => fetchResource(slug, clusterId, resourceId, signal),
  });
}

export function enrollmentTokensQueryOptions(slug: string) {
  return queryOptions({
    queryKey: ["project", slug, "enrollment-tokens"],
    queryFn: ({ signal }) => fetchEnrollmentTokens(slug, signal),
  });
}

export function agentsQueryOptions(slug: string) {
  return queryOptions({
    queryKey: ["project", slug, "agents"],
    queryFn: ({ signal }) => fetchAgents(slug, signal),
  });
}
