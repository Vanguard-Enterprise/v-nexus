/** A placeholder for an empty table cell: a dash on screen, a word for screen readers. */
export function Missing({ label = "None" }: { label?: string }) {
  return (
    <span className="missing">
      <span aria-hidden="true">–</span>
      <span className="visually-hidden">{label}</span>
    </span>
  );
}
