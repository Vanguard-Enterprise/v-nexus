import { ApiError } from "../api";

interface ErrorStateProps {
  error: Error;
  /** What failed to load, in sentence form, such as "This cluster". */
  subject: string;
  onRetry?: () => void;
}

function describe(error: Error, subject: string): { title: string; detail: string; retry: boolean } {
  if (error instanceof ApiError && error.kind === "http") {
    if (error.status === 404) {
      return {
        title: "Not found",
        detail: `${subject} does not exist, or you do not have access to it.`,
        retry: false,
      };
    }
    if (error.status === 403) {
      return { title: "No access", detail: error.message, retry: false };
    }
  }
  if (error instanceof ApiError && error.kind === "parse") {
    return {
      title: `${subject} could not be loaded`,
      detail: `${error.message} The UI and server versions may not match.`,
      retry: true,
    };
  }
  return { title: `${subject} could not be loaded`, detail: error.message, retry: true };
}

/** Explains a failed query, with 403 and 404 answers worded for people rather than HTTP. */
export function ErrorState({ error, subject, onRetry }: ErrorStateProps) {
  const { title, detail, retry } = describe(error, subject);
  return (
    <div className="callout" data-tone="down" role="alert">
      <p className="callout__title">{title}</p>
      <p>{detail}</p>
      {retry && onRetry && (
        <button type="button" className="button button--small" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

