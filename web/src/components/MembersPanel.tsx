import { useQuery } from "@tanstack/react-query";
import { membersQueryOptions, userLabel } from "../api";
import { ErrorState } from "./ErrorState";
import { Timestamp } from "./Timestamp";

const ROLE_LABEL = { viewer: "Viewer", operator: "Operator" } as const;

export function MembersPanel({ slug }: { slug: string }) {
  const { data, error, isPending, refetch } = useQuery(membersQueryOptions(slug));

  return (
    <section className="panel" aria-labelledby="members-heading" aria-busy={isPending}>
      <header className="panel__header">
        <h2 id="members-heading">Members</h2>
      </header>
      {isPending && <p className="panel__message muted">Loading members…</p>}
      {error && (
        <div className="panel__message">
          <ErrorState error={error} subject="Members" onRetry={() => void refetch()} />
        </div>
      )}
      {data?.length === 0 && (
        <p className="panel__message muted">
          No members yet. Installation admins have access to every project without a role.
        </p>
      )}
      {data && data.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Email</th>
                <th scope="col">Role</th>
                <th scope="col">Since</th>
              </tr>
            </thead>
            <tbody>
              {data.map((member) => (
                <tr key={member.user.id}>
                  <th scope="row">{userLabel(member.user)}</th>
                  <td>{member.user.email ?? <span className="muted">None</span>}</td>
                  <td>
                    <span className="badge">{ROLE_LABEL[member.role]}</span>
                  </td>
                  <td>
                    <Timestamp value={member.granted_at} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
