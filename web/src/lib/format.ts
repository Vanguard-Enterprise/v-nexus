const dateTimeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
const relativeFormat = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** A timestamp as local date and time, such as "Nov 15, 2026, 10:42:07 AM". */
export function formatDateTime(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : dateTimeFormat.format(date);
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
];

/** How long ago (or ahead) a timestamp is, such as "3 minutes ago" or "in 1 hour". */
export function formatRelative(timestamp: string, now: number = Date.now()): string {
  const time = new Date(timestamp).getTime();
  if (Number.isNaN(time)) return timestamp;
  const seconds = Math.round((time - now) / 1000);
  if (Math.abs(seconds) < 45) return seconds <= 0 ? "just now" : "in a few seconds";
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) return relativeFormat.format(Math.round(seconds / size), unit);
  }
  return relativeFormat.format(Math.round(seconds / 60), "minute");
}
