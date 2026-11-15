import { useEffect, useState } from "react";
import { copyText } from "../lib/clipboard";

type CopyState = "idle" | "copied" | "failed";

interface CopyButtonProps {
  text: string;
  /** Names what is copied, for screen readers, such as "enrollment token". */
  label: string;
  /** Visible button text. Defaults to "Copy". */
  caption?: string;
}

export function CopyButton({ text, label, caption = "Copy" }: CopyButtonProps) {
  const [state, setState] = useState<CopyState>("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => {
      setState("idle");
    }, 2_500);
    return () => {
      clearTimeout(timer);
    };
  }, [state]);

  return (
    <span className="copy">
      <button
        type="button"
        className="button button--small"
        aria-label={caption === "Copy" ? `Copy ${label}` : undefined}
        onClick={() => {
          void copyText(text).then((ok) => {
            setState(ok ? "copied" : "failed");
          });
        }}
      >
        {state === "copied" ? "Copied" : caption}
      </button>
      <span className="copy__status" role="status">
        {state === "copied" && <span className="visually-hidden">Copied {label}.</span>}
        {state === "failed" && "Copy failed. Select the text and copy it yourself."}
      </span>
    </span>
  );
}
