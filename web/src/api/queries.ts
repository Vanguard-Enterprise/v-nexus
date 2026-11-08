import { queryOptions } from "@tanstack/react-query";
import { fetchHealth } from "./health";

/** How often the health panel polls the server. */
export const HEALTH_REFETCH_INTERVAL_MS = 15_000;

export const healthQueryOptions = queryOptions({
  queryKey: ["health"],
  queryFn: ({ signal }) => fetchHealth(signal),
  refetchInterval: HEALTH_REFETCH_INTERVAL_MS,
});
