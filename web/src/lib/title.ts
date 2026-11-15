import { useEffect } from "react";

/** Sets the browser tab title for the current page. */
export function useDocumentTitle(...parts: (string | undefined)[]): void {
  const title = [...parts.filter((part) => part !== undefined && part !== ""), "Vanguard Nexus"].join(" | ");
  useEffect(() => {
    document.title = title;
  }, [title]);
}
