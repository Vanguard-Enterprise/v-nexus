import { formatDateTime, formatRelative } from "../lib/format";
import { useNow } from "../lib/now";

/** A relative time ("3 minutes ago") with the exact local time on hover. */
export function Timestamp({ value, fallback = "Never" }: { value: string | null; fallback?: string }) {
  const now = useNow();
  if (value === null) return <span className="muted">{fallback}</span>;
  return (
    <time dateTime={value} title={formatDateTime(value)}>
      {formatRelative(value, now)}
    </time>
  );
}
