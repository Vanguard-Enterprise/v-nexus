import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useState } from "react";
import { isNamespaced, namespaceNamesQueryOptions, resourcesQueryOptions } from "../api";
import type { Collection } from "../api";
import { collectionLabel, collectionNoun } from "../lib/labels";
import { ErrorState } from "./ErrorState";
import { ResourceTable } from "./ResourceTable";

/** Resources per page. */
export const RESOURCE_PAGE_SIZE = 100;

/** Delay between the last keystroke in the name search and the request. */
export const SEARCH_DEBOUNCE_MS = 300;

export interface ResourceFilters {
  collection: Collection;
  namespace: string;
  search: string;
  includeDeleted: boolean;
}

interface ResourceBrowserProps {
  slug: string;
  clusterId: string;
  filters: ResourceFilters;
  onChange: (changes: Partial<Omit<ResourceFilters, "collection">>) => void;
}

/** Filters, table, and pagination for one collection of a cluster. */
export function ResourceBrowser({ slug, clusterId, filters, onChange }: ResourceBrowserProps) {
  const namespaced = isNamespaced(filters.collection);
  // Pagination restarts whenever a filter changes, so key the pages on the filters.
  const pageKey = JSON.stringify([filters.collection, namespaced ? filters.namespace : "", filters.search, filters.includeDeleted]);

  return (
    <div className="browser">
      <FilterBar slug={slug} clusterId={clusterId} filters={filters} namespaced={namespaced} onChange={onChange} />
      <ResourcePages key={pageKey} slug={slug} clusterId={clusterId} filters={filters} namespaced={namespaced} />
    </div>
  );
}

interface FilterBarProps {
  slug: string;
  clusterId: string;
  filters: ResourceFilters;
  namespaced: boolean;
  onChange: ResourceBrowserProps["onChange"];
}

function FilterBar({ slug, clusterId, filters, namespaced, onChange }: FilterBarProps) {
  const searchId = useId();
  const namespaceId = useId();
  const deletedId = useId();

  // The search box updates at once; the URL (and the request) follow after a pause.
  const [text, setText] = useState(filters.search);
  const [lastSearch, setLastSearch] = useState(filters.search);
  if (filters.search !== lastSearch) {
    // The URL changed elsewhere, for example with the back button.
    setLastSearch(filters.search);
    setText(filters.search);
  }
  useEffect(() => {
    const next = text.trim();
    if (next === filters.search) return;
    const timer = setTimeout(() => {
      onChange({ search: next });
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [text, filters.search, onChange]);

  const namespaces = useQuery({ ...namespaceNamesQueryOptions(slug, clusterId), enabled: namespaced });
  const namespaceNames = [...(namespaces.data ?? [])];
  if (filters.namespace !== "" && !namespaceNames.includes(filters.namespace)) {
    namespaceNames.unshift(filters.namespace);
  }

  return (
    <div className="filters" role="search" aria-label={`Filter ${collectionLabel(filters.collection)}`}>
      <div className="field field--inline">
        <label htmlFor={searchId}>Name</label>
        <input
          id={searchId}
          className="input"
          type="search"
          value={text}
          placeholder="Search by name"
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => {
            setText(event.target.value);
          }}
        />
      </div>
      {namespaced && (
        <div className="field field--inline">
          <label htmlFor={namespaceId}>Namespace</label>
          <select
            id={namespaceId}
            className="input"
            value={filters.namespace}
            onChange={(event) => {
              onChange({ namespace: event.target.value });
            }}
          >
            <option value="">All namespaces</option>
            {namespaceNames.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>
      )}
      <div className="field field--check">
        <input
          id={deletedId}
          type="checkbox"
          checked={filters.includeDeleted}
          onChange={(event) => {
            onChange({ includeDeleted: event.target.checked });
          }}
        />
        <label htmlFor={deletedId}>Include deleted</label>
      </div>
    </div>
  );
}

interface ResourcePagesProps {
  slug: string;
  clusterId: string;
  filters: ResourceFilters;
  namespaced: boolean;
}

function ResourcePages({ slug, clusterId, filters, namespaced }: ResourcePagesProps) {
  // Cursors of the pages visited so far. The first page has none.
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined]);
  const cursor = cursors[cursors.length - 1];
  const page = cursors.length;

  const query = useQuery(
    resourcesQueryOptions(slug, clusterId, {
      collection: filters.collection,
      namespace: namespaced && filters.namespace !== "" ? filters.namespace : undefined,
      search: filters.search === "" ? undefined : filters.search,
      includeDeleted: filters.includeDeleted,
      limit: RESOURCE_PAGE_SIZE,
      cursor,
    }),
  );
  const { data, error, isPending, isPlaceholderData, isFetching, refetch } = query;
  const label = collectionLabel(filters.collection);
  const noun = collectionNoun(filters.collection);
  const filtered = filters.search !== "" || (namespaced && filters.namespace !== "");
  const nextCursor = isPlaceholderData ? null : (data?.next_cursor ?? null);

  return (
    <div className="pages" aria-busy={isFetching}>
      {isPending && <p className="panel__message muted">Loading {noun}…</p>}
      {error && (
        <div className="panel__message">
          <ErrorState error={error} subject={label} onRetry={() => void refetch()} />
        </div>
      )}
      {data?.resources.length === 0 && (
        <p className="panel__message muted">
          {filtered
            ? `No ${noun} match these filters.`
            : page > 1
              ? "No more resources."
              : `No ${noun} in the inventory.`}
        </p>
      )}
      {data && data.resources.length > 0 && (
        <ResourceTable
          slug={slug}
          clusterId={clusterId}
          collection={filters.collection}
          resources={data.resources}
          caption={`${label}, ${isPlaceholderData ? "loading " : ""}page ${String(page)}`}
        />
      )}
      {(page > 1 || nextCursor !== null) && (
        <nav className="pager" aria-label={`${label} pages`}>
          <button
            type="button"
            className="button button--small"
            disabled={page === 1}
            onClick={() => {
              setCursors((stack) => stack.slice(0, -1));
            }}
          >
            Previous
          </button>
          <span className="pager__page" aria-live="polite">
            {isPlaceholderData ? `Loading page ${String(page)}…` : `Page ${String(page)}`}
          </span>
          <button
            type="button"
            className="button button--small"
            disabled={nextCursor === null}
            onClick={() => {
              if (nextCursor !== null) setCursors((stack) => [...stack, nextCursor]);
            }}
          >
            Next
          </button>
        </nav>
      )}
    </div>
  );
}
