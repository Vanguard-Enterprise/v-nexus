import { isUnauthorized, loginUrl } from "../api";

/** Query parameter the server sets when a sign-in fails: `denied`, `expired`, or `failed`. */
export const LOGIN_ERROR_PARAM = "login_error";
/** Query parameter the UI sets after signing out. */
export const SIGNED_OUT_PARAM = "signed_out";

/** Page navigation, kept behind an object so tests can observe it. */
export const navigation = {
  assign(url: string): void {
    window.location.assign(url);
  },
};

interface PageLocation {
  pathname: string;
  search: string;
}

/**
 * Whether a 401 should send the browser to sign-in automatically. Not after a failed
 * sign-in (that would loop) or a deliberate sign-out (the provider would sign the user
 * straight back in), and not when the server has no sign-in configured.
 */
export function shouldRedirectToLogin(error: unknown, location: PageLocation): boolean {
  if (!isUnauthorized(error) || error.code === "auth_not_configured") return false;
  const params = new URLSearchParams(location.search);
  return !params.has(LOGIN_ERROR_PARAM) && !params.has(SIGNED_OUT_PARAM);
}

/** The current page without the sign-in status parameters, to return to after sign-in. */
export function returnPath(location: PageLocation): string {
  const params = new URLSearchParams(location.search);
  params.delete(LOGIN_ERROR_PARAM);
  params.delete(SIGNED_OUT_PARAM);
  const query = params.toString();
  return query === "" ? location.pathname : `${location.pathname}?${query}`;
}

/** Global query and mutation error handler: an expired or missing session starts sign-in. */
export function handleUnauthorized(error: unknown, location: PageLocation = window.location): void {
  if (shouldRedirectToLogin(error, location)) {
    navigation.assign(loginUrl(returnPath(location)));
  }
}
