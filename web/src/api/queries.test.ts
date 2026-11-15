import { describe, expect, it } from "vitest";
import {
  CLUSTER_REFETCH_INTERVAL_MS,
  clusterQueryOptions,
  resourceQueryOptions,
  resourcesQueryOptions,
} from "./queries";

describe("inventory query options", () => {
  // Inventory arrives and changes while a cluster page stays open, so resource lists and
  // details must refresh on their own, not only when the cluster status does.
  it("polls resource lists and details at the cluster status rate", () => {
    expect(clusterQueryOptions("prod", "c1").refetchInterval).toBe(CLUSTER_REFETCH_INTERVAL_MS);
    expect(
      resourcesQueryOptions("prod", "c1", { collection: "v1/nodes" }).refetchInterval,
    ).toBe(CLUSTER_REFETCH_INTERVAL_MS);
    expect(resourceQueryOptions("prod", "c1", "r1").refetchInterval).toBe(
      CLUSTER_REFETCH_INTERVAL_MS,
    );
  });
});
