import type { ReactNode } from "react";

export type Tone = "ok" | "degraded" | "down" | "pending";

/** A status word with a colored dot. The word carries the meaning; color only reinforces it. */
export function StatusBadge({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
  return (
    <span className="status" data-tone={tone} title={title}>
      <span className="status__dot" aria-hidden="true" />
      {children}
    </span>
  );
}
