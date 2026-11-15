/**
 * Copies text to the clipboard. The Clipboard API needs a secure context, and VN is often
 * opened over plain HTTP on a private network, so fall back to a hidden text area and the
 * legacy copy command. Resolves whether the copy worked.
 */
export async function copyText(text: string): Promise<boolean> {
  // `navigator.clipboard` is typed as always present but is missing outside secure contexts.
  if (window.isSecureContext && "clipboard" in navigator) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through to the legacy path, for example when permission is denied.
    }
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  try {
    // execCommand is deprecated but remains the only option outside secure contexts.
    // eslint-disable-next-line @typescript-eslint/no-deprecated
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    area.remove();
  }
}
