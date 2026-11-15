import { useId, useState } from "react";
import type { ReactNode } from "react";

interface ConfirmActionProps {
  /** Label of the button that starts the action, such as "Revoke agent". */
  label: string;
  /** What will happen, shown before the user confirms. */
  description: ReactNode;
  pending: boolean;
  error: Error | null;
  onConfirm: () => void;
  /** Called when the user backs out, so callers can clear an earlier error. */
  onCancel?: () => void;
  small?: boolean;
}

/** A destructive action that asks for confirmation in place before it runs. */
export function ConfirmAction({ label, description, pending, error, onConfirm, onCancel, small }: ConfirmActionProps) {
  const [confirming, setConfirming] = useState(false);
  const descriptionId = useId();
  const size = small ? " button--small" : "";

  if (!confirming) {
    return (
      <button
        type="button"
        className={`button button--danger-quiet${size}`}
        onClick={() => {
          setConfirming(true);
        }}
      >
        {label}
      </button>
    );
  }

  const cancel = () => {
    setConfirming(false);
    onCancel?.();
  };

  return (
    <div
      className="confirm"
      role="group"
      aria-label={`Confirm: ${label}`}
      aria-describedby={descriptionId}
      onKeyDown={(event) => {
        if (event.key === "Escape" && !pending) cancel();
      }}
    >
      <p id={descriptionId} className="confirm__text">
        {description}
      </p>
      <div className="confirm__actions">
        <button
          type="button"
          className={`button button--danger${size}`}
          disabled={pending}
          // Moving focus here makes the confirmation reachable at once by keyboard.
          autoFocus
          onClick={onConfirm}
        >
          {pending ? "Working…" : label}
        </button>
        <button type="button" className={`button${size}`} disabled={pending} onClick={cancel}>
          Cancel
        </button>
      </div>
      {error && (
        <p className="confirm__error" role="alert">
          {error.message}
        </p>
      )}
    </div>
  );
}
