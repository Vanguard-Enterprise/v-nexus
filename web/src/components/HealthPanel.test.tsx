import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { HealthPanel } from "./HealthPanel";
import { jsonResponse, mockFetch, renderWithQuery } from "../test/utils";

function fact(label: string): HTMLElement {
  const term = screen.getByText(label, { selector: "dt" });
  const row = term.parentElement;
  if (!row) throw new Error(`No row for ${label}`);
  return within(row).getByRole("definition");
}

describe("HealthPanel", () => {
  it("shows a loading state before the first response", () => {
    mockFetch(() => new Promise<Response>(() => undefined));
    renderWithQuery(<HealthPanel />);

    expect(screen.getByRole("region", { name: "Server health" })).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("status")).toHaveTextContent("Checking");
  });

  it("renders a healthy server", async () => {
    const fetchMock = mockFetch(() =>
      Promise.resolve(jsonResponse({ status: "ok", version: "0.1.0", database: "ok" })),
    );
    renderWithQuery(<HealthPanel />);

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Operational");
    });
    expect(fact("Overall status")).toHaveTextContent("Operational");
    expect(fact("Server version")).toHaveTextContent("0.1.0");
    expect(fact("Database")).toHaveTextContent("Connected");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/health", expect.anything());
  });

  it("renders a degraded state when the server returns 503 with JSON", async () => {
    mockFetch(() =>
      Promise.resolve(
        jsonResponse({ status: "degraded", version: "0.1.0", database: "unavailable" }, 503),
      ),
    );
    renderWithQuery(<HealthPanel />);

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Degraded");
    });
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("cannot reach its database");
    expect(fact("Overall status")).toHaveTextContent("Degraded");
    expect(fact("Server version")).toHaveTextContent("0.1.0");
    expect(fact("Database")).toHaveTextContent("Unavailable");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("renders an error when the server cannot be reached", async () => {
    mockFetch(() => Promise.reject(new TypeError("Failed to fetch")));
    renderWithQuery(<HealthPanel />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Server unreachable");
    expect(fact("Server version")).toHaveTextContent("Unknown");
    expect(fact("Database")).toHaveTextContent("Unknown");
  });
});
