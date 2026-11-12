import { queryOptions } from "@tanstack/react-query";
import { fetchMe } from "./auth";
import { fetchHealth } from "./health";
import { fetchProjects } from "./projects";

/** How often the health panel polls the server. */
export const HEALTH_REFETCH_INTERVAL_MS = 15_000;

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
