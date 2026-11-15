import { useSyncExternalStore } from "react";

/** How often relative times ("3 minutes ago") refresh. */
const TICK_MS = 30_000;

const listeners = new Set<() => void>();
let now = Date.now();
let timer: ReturnType<typeof setInterval> | undefined;

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  if (timer === undefined) {
    now = Date.now();
    timer = setInterval(() => {
      now = Date.now();
      for (const notify of listeners) notify();
    }, TICK_MS);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && timer !== undefined) {
      clearInterval(timer);
      timer = undefined;
    }
  };
}

/** The current time, shared by every subscriber and refreshed on one timer. */
export function useNow(): number {
  return useSyncExternalStore(subscribe, () => now);
}
