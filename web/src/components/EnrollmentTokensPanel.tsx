import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { enrollmentTokensQueryOptions, revokeEnrollmentToken } from "../api";
import type { EnrollmentToken } from "../api";
import { TOKEN_STATUS } from "../lib/labels";
import { ConfirmAction } from "./ConfirmAction";
import { ErrorState } from "./ErrorState";
import { StatusBadge } from "./StatusBadge";
import { Timestamp } from "./Timestamp";

/** Enrollment tokens of a project, newest first, with revoke for unused ones. Admins only. */
export function EnrollmentTokensPanel({ slug }: { slug: string }) {
  const { data, error, isPending, refetch } = useQuery(enrollmentTokensQueryOptions(slug));

  return (
    <section className="panel" aria-labelledby="tokens-heading" aria-busy={isPending}>
      <header className="panel__header">
        <h2 id="tokens-heading">Enrollment tokens</h2>
      </header>
      {isPending && <p className="panel__message muted">Loading enrollment tokens…</p>}
      {error && (
        <div className="panel__message">
          <ErrorState error={error} subject="Enrollment tokens" onRetry={() => void refetch()} />
        </div>
      )}
      {data?.length === 0 && (
        <p className="panel__message muted">No enrollment tokens yet. Registering a cluster creates one.</p>
      )}
      {data && data.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">For</th>
                <th scope="col">Status</th>
                <th scope="col">Created</th>
                <th scope="col">Expires</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.map((token) => (
                <TokenRow key={token.id} slug={slug} token={token} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function targetLabel(token: EnrollmentToken): string {
  return token.target.type === "new_cluster"
    ? token.target.display_name
    : `Replacement agent for source ${token.target.source_id}`;
}

function TokenRow({ slug, token }: { slug: string; token: EnrollmentToken }) {
  const queryClient = useQueryClient();
  const revoke = useMutation({
    mutationFn: () => revokeEnrollmentToken(slug, token.id),
    onSettled: () => queryClient.invalidateQueries({ queryKey: enrollmentTokensQueryOptions(slug).queryKey }),
  });
  const status = TOKEN_STATUS[token.status];
  const label = targetLabel(token);

  return (
    <tr>
      <th scope="row">{label}</th>
      <td>
        <StatusBadge tone={status.tone}>{status.label}</StatusBadge>
        {token.status === "used" && token.used_at && (
          <span className="table__sub">
            <Timestamp value={token.used_at} />
          </span>
        )}
      </td>
      <td>
        <Timestamp value={token.created_at} />
      </td>
      <td>
        <Timestamp value={token.expires_at} />
      </td>
      <td className="actions">
        {token.status === "active" && (
          <ConfirmAction
            small
            label="Revoke token"
            description={`Revoke the token for ${label}? An agent that has not enrolled yet can no longer use it.`}
            pending={revoke.isPending}
            error={revoke.error}
            onConfirm={() => {
              revoke.mutate();
            }}
            onCancel={revoke.reset}
          />
        )}
      </td>
    </tr>
  );
}
