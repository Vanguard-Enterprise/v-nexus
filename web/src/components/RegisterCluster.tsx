import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState } from "react";
import type { RefObject } from "react";
import {
  DEFAULT_ENROLLMENT_TOKEN_MINUTES,
  createEnrollmentToken,
  enrollmentTokensQueryOptions,
  installCommands,
} from "../api";
import { formatDateTime } from "../lib/format";
import { CopyButton } from "./CopyButton";

const EXPIRY_OPTIONS: { minutes: number; label: string }[] = [
  { minutes: 15, label: "15 minutes" },
  { minutes: 60, label: "1 hour" },
  { minutes: 4 * 60, label: "4 hours" },
  { minutes: 12 * 60, label: "12 hours" },
  { minutes: 24 * 60, label: "24 hours" },
];

const MAX_NAME_CHARS = 200;

/** A freshly created token. Held only in this component's state, never in the query cache. */
interface Issued {
  clusterName: string;
  secret: string;
  expiresAt: string;
}

interface RegisterClusterProps {
  slug: string;
  onClose: () => void;
  /** URL agents use to reach this server. Defaults to the page's origin. */
  serverUrl?: string;
}

/**
 * Registers a cluster: creates a single-use enrollment token for a new cluster, then
 * shows the token once together with the commands that install the agent.
 */
export function RegisterCluster({ slug, onClose, serverUrl = window.location.origin }: RegisterClusterProps) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [minutes, setMinutes] = useState(DEFAULT_ENROLLMENT_TOKEN_MINUTES);
  const [issued, setIssued] = useState<Issued | null>(null);
  const nameId = useId();
  const expiryId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);

  const create = useMutation({
    // Keep the secret out of the mutation cache: it goes straight into local state and
    // the mutation itself resolves nothing.
    mutationFn: async () => {
      const created = await createEnrollmentToken(slug, {
        target: { type: "new_cluster", display_name: name.trim() },
        expiresInMinutes: minutes,
      });
      setIssued({
        clusterName: created.token.target.type === "new_cluster" ? created.token.target.display_name : name.trim(),
        secret: created.secret,
        expiresAt: created.token.expires_at,
      });
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: enrollmentTokensQueryOptions(slug).queryKey }),
  });

  // Move focus to the token so keyboard and screen reader users land on it.
  useEffect(() => {
    if (issued) headingRef.current?.focus();
  }, [issued]);

  if (issued) {
    return <IssuedToken issued={issued} serverUrl={serverUrl} headingRef={headingRef} onDone={onClose} />;
  }

  const trimmed = name.trim();
  return (
    <section className="panel" aria-labelledby={`${nameId}-heading`}>
      <header className="panel__header">
        <h2 id={`${nameId}-heading`}>Register a cluster</h2>
      </header>
      <form
        className="panel__body form"
        onSubmit={(event) => {
          event.preventDefault();
          if (trimmed !== "" && !create.isPending) create.mutate();
        }}
      >
        <p className="muted form__intro">
          Registering creates a single-use enrollment token. The agent uses it once to enroll, and the cluster appears
          in this project when the agent connects.
        </p>
        <div className="field">
          <label htmlFor={nameId}>Cluster name</label>
          <input
            id={nameId}
            className="input"
            value={name}
            required
            maxLength={MAX_NAME_CHARS}
            autoComplete="off"
            placeholder="prod-east"
            onChange={(event) => {
              setName(event.target.value);
            }}
          />
          <p className="field__hint">Shown in VN only. It does not need to match the cluster's own name.</p>
        </div>
        <div className="field">
          <label htmlFor={expiryId}>Token expires after</label>
          <select
            id={expiryId}
            className="input"
            value={minutes}
            onChange={(event) => {
              setMinutes(Number(event.target.value));
            }}
          >
            {EXPIRY_OPTIONS.map((option) => (
              <option key={option.minutes} value={option.minutes}>
                {option.label}
              </option>
            ))}
          </select>
          <p className="field__hint">Install the agent before then. An unused token can be revoked at any time.</p>
        </div>
        {create.error && (
          <p className="callout" data-tone="down" role="alert">
            The token could not be created. {create.error.message}
          </p>
        )}
        <div className="form__actions">
          <button type="submit" className="button button--primary" disabled={trimmed === "" || create.isPending}>
            {create.isPending ? "Creating token…" : "Create enrollment token"}
          </button>
          <button type="button" className="button" onClick={onClose} disabled={create.isPending}>
            Cancel
          </button>
        </div>
      </form>
    </section>
  );
}

interface IssuedTokenProps {
  issued: Issued;
  serverUrl: string;
  headingRef: RefObject<HTMLHeadingElement | null>;
  onDone: () => void;
}

const STEPS = [
  "Create the agent's namespace.",
  "Store this server's URL and the enrollment token in a Secret.",
  "Apply the agent manifest. The agent enrolls, then connects.",
];

function IssuedToken({ issued, serverUrl, headingRef, onDone }: IssuedTokenProps) {
  const commands = installCommands(serverUrl, issued.secret);
  const headingId = useId();

  return (
    <section className="panel panel--accent" aria-labelledby={headingId}>
      <header className="panel__header">
        <h2 id={headingId} ref={headingRef} tabIndex={-1}>
          Install the agent on {issued.clusterName}
        </h2>
      </header>
      <div className="panel__body">
        <div className="callout" data-tone="degraded" role="note">
          <p className="callout__title">Copy the enrollment token now. It is shown only once.</p>
          <p>
            Vanguard Nexus keeps only a hash of it, so it cannot be shown again after you leave this page. If you lose
            it, revoke it below and register the cluster again.
          </p>
        </div>

        <div className="secret">
          <p className="secret__label" id={`${headingId}-token`}>
            Enrollment token
          </p>
          <div className="secret__row">
            <code className="secret__value" aria-labelledby={`${headingId}-token`}>
              {issued.secret}
            </code>
            <CopyButton text={issued.secret} label="enrollment token" />
          </div>
          <p className="field__hint">
            Single use. Expires at {formatDateTime(issued.expiresAt)}.
          </p>
        </div>

        <ol className="steps">
          {commands.map((command, index) => (
            <li key={command}>
              <p>{STEPS[index]}</p>
              <div className="command">
                <pre>
                  <code>{command}</code>
                </pre>
                <CopyButton text={command} label={`command ${String(index + 1)}`} />
              </div>
            </li>
          ))}
        </ol>

        <div className="form__actions">
          <CopyButton text={commands.join("\n")} label="all commands" caption="Copy all commands" />
          <button type="button" className="button button--primary" onClick={onDone}>
            Done, I have copied the token
          </button>
        </div>
        <p className="muted">
          The cluster appears under Clusters, marked connected, once the agent is running. Commands use{" "}
          <code>{serverUrl}</code> as the server URL; the cluster must be able to reach it.
        </p>
      </div>
    </section>
  );
}
