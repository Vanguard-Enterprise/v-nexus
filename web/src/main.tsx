import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { isUnauthorized } from "./api";
import { handleUnauthorized } from "./auth/session";
import "./styles.css";

const queryClient = new QueryClient({
  // Any 401 means the session is missing or over, wherever it happens.
  queryCache: new QueryCache({
    onError: (error) => {
      handleUnauthorized(error);
    },
  }),
  mutationCache: new MutationCache({
    onError: (error) => {
      handleUnauthorized(error);
    },
  }),
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      // Retrying will not make a missing session appear.
      retry: (failureCount, error) => !isUnauthorized(error) && failureCount < 1,
    },
  },
});

const root = document.getElementById("root");
if (!root) {
  throw new Error("Missing #root element in index.html");
}

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
