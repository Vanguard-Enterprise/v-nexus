import { loginUrl } from "../api";
import type { ApiError } from "../api";
import { LOGIN_ERROR_PARAM, SIGNED_OUT_PARAM } from "../auth/session";

const FAILED_MESSAGE =
  "Sign-in failed. Try again, and contact an administrator if it keeps failing.";

// A Map, so codes such as `__proto__` from the URL cannot reach Object.prototype.
const LOGIN_ERRORS = new Map<string, string>([
  ["denied", "Sign-in was cancelled or refused by the identity provider."],
  ["expired", "That sign-in expired or was started in another browser. Try again."],
  ["failed", FAILED_MESSAGE],
]);

export function SignInPanel({ error, search }: { error: ApiError; search: string }) {
  const params = new URLSearchParams(search);
  const loginError = params.get(LOGIN_ERROR_PARAM);
  const notConfigured = error.code === "auth_not_configured";

  let detail: string;
  if (notConfigured) {
    detail = "Sign-in is not configured on this server. Add an auth section to its config file.";
  } else if (loginError !== null) {
    detail = LOGIN_ERRORS.get(loginError) ?? FAILED_MESSAGE;
  } else if (params.has(SIGNED_OUT_PARAM)) {
    detail = "You have signed out.";
  } else {
    detail = "Sign in with your organization account to continue.";
  }

  return (
    <section className="panel" aria-labelledby="signin-heading">
      <header className="panel__header">
        <h2 id="signin-heading">Sign in</h2>
      </header>
      <div className="panel__body">
        <p role={loginError !== null ? "alert" : undefined}>{detail}</p>
        {!notConfigured && (
          <a className="button button--primary" href={loginUrl("/")}>
            Sign in
          </a>
        )}
      </div>
    </section>
  );
}
