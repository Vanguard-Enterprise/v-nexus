import { useMutation } from "@tanstack/react-query";
import { logout, userLabel } from "../api";
import type { Me } from "../api";
import { SIGNED_OUT_PARAM, navigation } from "../auth/session";

export function UserMenu({ me }: { me: Me }) {
  const signOut = useMutation({
    mutationFn: logout,
    onSuccess: () => {
      navigation.assign(`/?${SIGNED_OUT_PARAM}=1`);
    },
  });
  const isAdmin = me.installation_roles.includes("admin");

  return (
    <div className="user-menu">
      <span className="user-menu__name" title={me.user.email ?? me.user.subject}>
        {userLabel(me.user)}
      </span>
      {isAdmin && <span className="badge">Admin</span>}
      <button
        type="button"
        className="button"
        disabled={signOut.isPending}
        onClick={() => {
          signOut.mutate();
        }}
      >
        {signOut.isPending ? "Signing out…" : "Sign out"}
      </button>
      {signOut.isError && (
        <span className="user-menu__error" role="alert">
          Sign-out failed. Try again.
        </span>
      )}
    </div>
  );
}
