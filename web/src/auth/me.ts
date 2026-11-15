import { createContext, useContext } from "react";
import type { Me } from "../api";

/** The signed-in user. Pages render only inside a provider, after `/auth/me` answered. */
export const MeContext = createContext<Me | null>(null);

export function useMe(): Me {
  const me = useContext(MeContext);
  if (!me) throw new Error("useMe needs a signed-in user");
  return me;
}

/**
 * Whether the user may register clusters, manage enrollment tokens, and revoke agents.
 * The server reserves this (`ManageAgents`) for installation admins in the first release.
 */
export function useCanManageAgents(): boolean {
  return useMe().installation_roles.includes("admin");
}
