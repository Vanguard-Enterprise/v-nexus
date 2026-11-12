import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api";
import { handleUnauthorized, navigation, returnPath, shouldRedirectToLogin } from "./session";

const unauthorized = new ApiError("http", "Sign in to continue.", { status: 401, code: "unauthorized" });
const at = (pathname: string, search = "") => ({ pathname, search });

describe("shouldRedirectToLogin", () => {
  it("redirects on a 401", () => {
    expect(shouldRedirectToLogin(unauthorized, at("/"))).toBe(true);
  });

  it("does not redirect for other errors", () => {
    expect(shouldRedirectToLogin(new ApiError("http", "no", { status: 403 }), at("/"))).toBe(false);
    expect(shouldRedirectToLogin(new ApiError("network", "down"), at("/"))).toBe(false);
  });

  it("does not loop after a failed sign-in or undo a sign-out", () => {
    expect(shouldRedirectToLogin(unauthorized, at("/", "?login_error=failed"))).toBe(false);
    expect(shouldRedirectToLogin(unauthorized, at("/", "?signed_out=1"))).toBe(false);
  });

  it("does not redirect when the server has no sign-in configured", () => {
    const error = new ApiError("http", "x", { status: 401, code: "auth_not_configured" });
    expect(shouldRedirectToLogin(error, at("/"))).toBe(false);
  });
});

describe("returnPath", () => {
  it("keeps the page and drops sign-in status parameters", () => {
    expect(returnPath(at("/projects", "?tab=all&login_error=x&signed_out=1"))).toBe(
      "/projects?tab=all",
    );
    expect(returnPath(at("/projects"))).toBe("/projects");
  });
});

describe("handleUnauthorized", () => {
  it("starts sign-in and returns to the current page", () => {
    const assign = vi.spyOn(navigation, "assign").mockImplementation(() => undefined);
    handleUnauthorized(unauthorized, at("/projects", "?tab=all"));
    expect(assign).toHaveBeenCalledWith("/api/v1/auth/login?return_to=%2Fprojects%3Ftab%3Dall");
  });

  it("ignores errors that are not 401", () => {
    const assign = vi.spyOn(navigation, "assign").mockImplementation(() => undefined);
    handleUnauthorized(new ApiError("http", "x", { status: 500 }), at("/"));
    expect(assign).not.toHaveBeenCalled();
  });
});
