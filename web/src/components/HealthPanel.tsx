import { useQuery } from "@tanstack/react-query";
import { ApiError, HEALTH_REFETCH_INTERVAL_MS, healthQueryOptions } from "../api";
import type { HealthResponse } from "../api";

type Tone = "pending" | "ok" | "degraded" | "down";

const timeFormat = new Intl.DateTimeFormat(undefined, { timeStyle: "medium" });

function describeError(error: Error): { title: string; detail: string } {
  if (error instanceof ApiError) {
    switch (error.kind) {
      case "network":
        return {
          title: "Server unreachable",
          detail: "The browser could not connect to the Vanguard Nexus server. Check that vn-server is running.",
        };
      case "unavailable":
        return {
          title: "Server unreachable",
          detail: `${error.message} Check that vn-server is running.`,
        };
      case "http":
        return { title: "Health check failed", detail: error.message };
      case "parse":
        return {
          title: "Unexpected health response",
          detail: `${error.message} The UI and server versions may not match.`,
        };
    }
  }
  return { title: "Health check failed", detail: error.message };
}

function summary(health: HealthResponse): { tone: Tone; title: string; detail: string } {
  if (health.status === "ok") {
    return {
      tone: "ok",
      title: "Operational",
      detail: "The server is running and connected to its database.",
    };
  }
  return {
    tone: "degraded",
    title: "Degraded",
    detail:
      health.database === "unavailable"
        ? "The server is running but cannot reach its database. Stored data is unavailable until the connection returns."
        : "The server reports reduced service.",
  };
}

const DATABASE_LABEL: Record<HealthResponse["database"], string> = {
  ok: "Connected",
  unavailable: "Unavailable",
};

const STATUS_LABEL: Record<HealthResponse["status"], string> = {
  ok: "Operational",
  degraded: "Degraded",
};

export function HealthPanel() {
  const { data, error, isPending, isFetching, dataUpdatedAt, refetch } = useQuery(healthQueryOptions);

  const intervalSeconds = Math.round(HEALTH_REFETCH_INTERVAL_MS / 1000);

  let tone: Tone;
  let title: string;
  let detail: string;
  if (data) {
    ({ tone, title, detail } = summary(data));
  } else if (error) {
    tone = "down";
    ({ title, detail } = describeError(error));
  } else {
    tone = "pending";
    title = "Checking";
    detail = "Contacting the server.";
  }

  const staleError = data && error ? describeError(error) : undefined;

  return (
    <section className="health" data-tone={tone} aria-labelledby="health-heading" aria-busy={isPending}>
      <header className="health__header">
        <h2 id="health-heading">Server health</h2>
        <button
          type="button"
          className="button"
          onClick={() => void refetch({ cancelRefetch: false })}
        >
          Check now
        </button>
      </header>

      <div className="health__signal" role={tone === "down" ? "alert" : "status"}>
        <span className="health__indicator" aria-hidden="true" data-active={isFetching} />
        <div>
          <p className="health__title">{title}</p>
          <p className="health__detail">{detail}</p>
        </div>
      </div>

      {staleError && (
        <p className="health__stale" role="alert">
          <strong>{staleError.title}.</strong> Showing the last result, from{" "}
          {timeFormat.format(dataUpdatedAt)}.
        </p>
      )}

      <dl className="health__facts">
        <div>
          <dt>Overall status</dt>
          <dd>{data ? STATUS_LABEL[data.status] : <Placeholder pending={isPending} />}</dd>
        </div>
        <div>
          <dt>Server version</dt>
          <dd className="health__version">{data ? data.version : <Placeholder pending={isPending} />}</dd>
        </div>
        <div>
          <dt>Database</dt>
          <dd data-database={data?.database}>
            {data ? DATABASE_LABEL[data.database] : <Placeholder pending={isPending} />}
          </dd>
        </div>
      </dl>

      <p className="health__meta">
        {data ? <>Last checked at {timeFormat.format(dataUpdatedAt)}. </> : null}
        Refreshes every {intervalSeconds} seconds.
      </p>
    </section>
  );
}

function Placeholder({ pending }: { pending: boolean }) {
  return pending ? (
    <span className="placeholder">
      <span className="visually-hidden">Loading</span>
    </span>
  ) : (
    <span className="health__unknown">Unknown</span>
  );
}
