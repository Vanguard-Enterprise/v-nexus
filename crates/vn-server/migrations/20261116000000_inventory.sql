-- Cluster inventory: the latest observed state of each Kubernetes resource, and the
-- synchronization state of each collection of each source.

-- One row per resource, identified by its cluster and UID. A replacement with the same
-- name has a new UID and gets its own row. Rows are never deleted by synchronization:
-- a deletion leaves a tombstone (`deleted_at`) that keeps the last known state.
CREATE TABLE inventory_resources (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id uuid NOT NULL,
    -- The source that wrote the row. Only its own snapshots infer the row's deletion.
    source_id uuid NOT NULL,
    collection text COLLATE "C" NOT NULL CHECK (length(collection) BETWEEN 1 AND 128),
    uid text NOT NULL CHECK (length(uid) BETWEEN 1 AND 128),
    -- Empty for cluster-scoped resources, so ordering and cursors need no null handling.
    -- Kubernetes namespace names are never empty.
    namespace text COLLATE "C" NOT NULL CHECK (length(namespace) <= 253),
    name text COLLATE "C" NOT NULL CHECK (length(name) BETWEEN 1 AND 253),
    resource_version text NOT NULL CHECK (length(resource_version) <= 128),
    -- The sanitized object. Null when the object was truncated, or for a tombstone of a
    -- resource whose content was never received.
    object jsonb CHECK (object IS NULL OR jsonb_typeof(object) = 'object'),
    truncated boolean NOT NULL DEFAULT false,
    -- Order key of the latest accepted observation: (sync epoch, message seq).
    order_epoch bigint NOT NULL CHECK (order_epoch >= 1),
    order_seq bigint NOT NULL CHECK (order_seq >= 1),
    -- Server receive times. `last_observed_at` advances with every accepted
    -- observation, even one with unchanged content.
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    -- The agent's own observation time, for display only.
    agent_observed_at timestamptz,
    deleted_at timestamptz,
    -- Set when a completed snapshot with a narrower scope no longer covers the
    -- resource: it is no longer collected, which is not the same as deleted. Version 1
    -- agents only send whole-cluster scopes, so this stays null for now.
    uncollected_at timestamptz,
    FOREIGN KEY (cluster_id, source_id) REFERENCES sources (cluster_id, id) ON DELETE CASCADE,
    UNIQUE (cluster_id, uid)
);

-- The resources API: filters by collection and namespace, ordered by collection,
-- namespace, name, and ID (the keyset cursor).
CREATE INDEX inventory_resources_listing_idx
    ON inventory_resources (cluster_id, collection, namespace, name, id);
-- Deletion inference at the end of a snapshot, and counts of present resources.
CREATE INDEX inventory_resources_present_idx
    ON inventory_resources (source_id, collection, namespace) WHERE deleted_at IS NULL;

-- Synchronization state per source and collection.
CREATE TABLE inventory_collections (
    source_id uuid NOT NULL REFERENCES sources (id) ON DELETE CASCADE,
    collection text COLLATE "C" NOT NULL CHECK (length(collection) BETWEEN 1 AND 128),
    -- The snapshot in progress, if any, and the epoch of the connection it started on.
    -- It is only in progress while that connection is the source's open connection.
    open_snapshot_id uuid,
    open_snapshot_epoch bigint,
    open_snapshot_started_at timestamptz,
    -- The last completed snapshot: its scope (null namespace for all namespaces), when
    -- it completed, how many items it listed, and its list resource version if known.
    snapshot_scope_namespace text,
    snapshot_completed_at timestamptz,
    snapshot_item_count bigint,
    snapshot_resource_version text,
    -- The last collection error since the last completed snapshot or watch event.
    error_reason text CHECK (length(error_reason) BETWEEN 1 AND 64),
    error_message text CHECK (length(error_message) <= 1024),
    error_observed_at timestamptz,
    -- Server receive time of the latest accepted observation in the collection.
    last_observed_at timestamptz,
    -- Upserts that brought back a tombstoned UID: a deletion that was wrong.
    tombstone_reversals bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (source_id, collection),
    CHECK ((open_snapshot_id IS NULL) = (open_snapshot_epoch IS NULL)),
    CHECK ((error_reason IS NULL) = (error_observed_at IS NULL))
);
