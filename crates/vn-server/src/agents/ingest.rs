//! Inventory ingest: snapshots and observations from one agent connection.
//!
//! The rules are in `docs/agent-protocol.md` (Snapshots, Observations, Duplicate
//! delivery). In short:
//!
//! - Every ingest transaction first applies the epoch fence (the source's current sync
//!   epoch, read `FOR SHARE`, must be this connection's) and checks that the agent is
//!   still active, locking the source row before the agent row like connection open.
//! - Each resource (cluster and UID) stores the order key `(sync_epoch, seq)` of the
//!   latest accepted observation. An observation with a key that is not greater is
//!   ignored. An accepted upsert always advances the key and the last-observed time,
//!   and replaces the content only when it passes the resource version rule.
//! - Only a `snapshot_end` that matches a snapshot started on this connection, with the
//!   item count the server received, infers deletions: resources of the collection and
//!   scope whose key is older than the `snapshot_start`.
//!
//! Messages are buffered and applied in batches, in order, one transaction per batch.
//! The batch is acknowledged after it commits. Snapshot bookkeeping lives in memory: a
//! failed transaction closes the connection, which discards it.

use std::collections::{HashMap, HashSet};

use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;
use vn_core::agent_protocol::{
    CloseCode, CollectionError, Delete, ErrorMessage, Scope, SnapshotAbort, SnapshotEnd,
    SnapshotStart, Upsert,
};
use vn_core::inventory::{Collection, sanitize_object};

use super::dispatch::{Close, ConnectionContext};

/// Longest accepted UID and resource version.
const MAX_UID_LEN: usize = 128;
const MAX_RESOURCE_VERSION_LEN: usize = 128;
/// Longest Kubernetes object name and namespace name.
const MAX_NAME_LEN: usize = 253;
const MAX_REASON_LEN: usize = 64;
const MAX_ERROR_MESSAGE_LEN: usize = 1024;

/// Error codes the server answers an ignored inventory message with.
pub(crate) const UNSUPPORTED_COLLECTION: &str = "unsupported_collection";
pub(crate) const INVALID_MESSAGE: &str = "invalid_message";

/// An inventory message waiting for its batch.
#[derive(Debug)]
pub(crate) enum InventoryMessage {
    SnapshotStart(SnapshotStart),
    Upsert(Upsert),
    Delete(Delete),
    SnapshotEnd(SnapshotEnd),
    SnapshotAbort(SnapshotAbort),
    CollectionError(CollectionError),
}

/// A snapshot started on this connection that has not ended.
#[derive(Debug, Clone)]
struct OpenSnapshot {
    id: Uuid,
    namespace: Option<String>,
    /// `seq` of the `snapshot_start`: resources with an older key are missing from it.
    start_seq: i64,
    /// Upserts received for it, valid or ignored by the ordering rules.
    received: u64,
}

/// The stored resource an observation is compared with.
#[derive(Debug, sqlx::FromRow)]
struct StoredResource {
    id: Uuid,
    source_id: Uuid,
    collection: String,
    resource_version: String,
    order_epoch: i64,
    order_seq: i64,
    deleted: bool,
}

/// What a batch did, for the caller to answer after the commit.
#[derive(Debug, Default)]
pub(crate) struct BatchOutcome {
    /// Errors to send about messages that were ignored.
    pub(crate) notices: Vec<ErrorMessage>,
}

/// Per-connection ingest state.
#[derive(Debug)]
pub(crate) struct Ingest {
    /// Whether resource versions may be compared: the agent reported Kubernetes 1.35 or
    /// later in `hello`.
    compare_versions: bool,
    open: HashMap<Collection, OpenSnapshot>,
    /// Snapshots of this connection that ended or were abandoned. A repeated
    /// `snapshot_end` for one of them is a no-op.
    finished: HashSet<Uuid>,
    /// Collections whose error this connection reported and no later watch event has
    /// cleared.
    errored: HashSet<Collection>,
}

impl Ingest {
    pub(crate) fn new(ctx: &ConnectionContext) -> Self {
        Self {
            compare_versions: ctx
                .kubernetes_version
                .as_deref()
                .is_some_and(orders_resource_versions),
            open: HashMap::new(),
            finished: HashSet::new(),
            errored: HashSet::new(),
        }
    }

    /// Applies `batch` in one transaction and commits it. Messages arrive in `seq`
    /// order. Returns [`CloseCode::Superseded`] or [`CloseCode::Revoked`] as a close,
    /// with nothing persisted, when the fence or the agent check fails.
    pub(crate) async fn apply(
        &mut self,
        ctx: &ConnectionContext,
        batch: Vec<(u64, InventoryMessage)>,
    ) -> Result<BatchOutcome, Close> {
        let mut tx = ctx.db.begin().await?;
        fence(&mut tx, ctx).await?;
        let mut outcome = BatchOutcome::default();
        let mut observed: HashSet<Collection> = HashSet::new();
        for (seq, message) in batch {
            let seq = i64::try_from(seq).map_err(|_| Close::protocol("seq out of range"))?;
            let result = match message {
                InventoryMessage::SnapshotStart(m) => {
                    self.snapshot_start(&mut tx, ctx, seq, m).await
                }
                InventoryMessage::Upsert(m) => {
                    self.upsert(&mut tx, ctx, seq, m, &mut observed).await
                }
                InventoryMessage::Delete(m) => {
                    self.delete(&mut tx, ctx, seq, m, &mut observed).await
                }
                InventoryMessage::SnapshotEnd(m) => self.snapshot_end(&mut tx, ctx, seq, m).await,
                InventoryMessage::SnapshotAbort(m) => self.snapshot_abort(&mut tx, ctx, m).await,
                InventoryMessage::CollectionError(m) => {
                    self.collection_error(&mut tx, ctx, m).await
                }
            };
            match result {
                Ok(()) => {}
                Err(Rejected::Notice(code, message)) => {
                    tracing::debug!(seq, code, message = %message, "ignored inventory message");
                    outcome.notices.push(ErrorMessage {
                        code: code.to_owned(),
                        message: Some(message),
                        ref_seq: u64::try_from(seq).ok(),
                    });
                }
                Err(Rejected::Close(close)) => return Err(close),
            }
        }
        if !observed.is_empty() {
            let names: Vec<&str> = observed.iter().map(|c| c.as_str()).collect();
            sqlx::query(
                "INSERT INTO inventory_collections (source_id, collection, last_observed_at) \
                 SELECT $1, c, now() FROM unnest($2::text[]) AS c \
                 ON CONFLICT (source_id, collection) \
                 DO UPDATE SET last_observed_at = excluded.last_observed_at",
            )
            .bind(ctx.source_id)
            .bind(&names)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(outcome)
    }

    async fn snapshot_start(
        &mut self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        seq: i64,
        start: SnapshotStart,
    ) -> Result<(), Rejected> {
        let collection = parse_collection(&start.collection)?;
        let namespace = parse_scope(collection, &start.scope)?;
        if self.finished.contains(&start.snapshot_id)
            || self.open.values().any(|s| s.id == start.snapshot_id)
        {
            return Err(Rejected::invalid("the snapshot ID was already used"));
        }
        if let Some(previous) = self.open.remove(&collection) {
            tracing::debug!(
                %collection,
                snapshot_id = %previous.id,
                "a new snapshot replaced one that did not end; no deletions inferred"
            );
            self.finished.insert(previous.id);
        }
        self.open.insert(
            collection,
            OpenSnapshot {
                id: start.snapshot_id,
                namespace,
                start_seq: seq,
                received: 0,
            },
        );
        sqlx::query(
            "INSERT INTO inventory_collections \
                 (source_id, collection, open_snapshot_id, open_snapshot_epoch, \
                  open_snapshot_started_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (source_id, collection) DO UPDATE SET \
                 open_snapshot_id = excluded.open_snapshot_id, \
                 open_snapshot_epoch = excluded.open_snapshot_epoch, \
                 open_snapshot_started_at = excluded.open_snapshot_started_at",
        )
        .bind(ctx.source_id)
        .bind(collection.as_str())
        .bind(start.snapshot_id)
        .bind(ctx.sync_epoch)
        .execute(tx)
        .await?;
        Ok(())
    }

    async fn upsert(
        &mut self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        seq: i64,
        upsert: Upsert,
        observed: &mut HashSet<Collection>,
    ) -> Result<(), Rejected> {
        let collection = parse_collection(&upsert.collection)?;
        let namespace = validate_identity(
            collection,
            &upsert.uid,
            upsert.namespace.as_deref(),
            &upsert.name,
            &upsert.resource_version,
        )?;
        let object = match (upsert.truncated, upsert.object) {
            (true, _) => None,
            (false, Some(mut object)) if object.is_object() => {
                sanitize_object(&mut object);
                Some(object)
            }
            (false, _) => {
                return Err(Rejected::invalid(
                    "an upsert needs an `object`, unless it is `truncated`",
                ));
            }
        };
        // Every upsert of the snapshot counts toward its item count, even one the ordering
        // rules ignore below.
        if let Some(snapshot_id) = upsert.snapshot_id
            && let Some(open) = self.open.get_mut(&collection)
            && open.id == snapshot_id
        {
            open.received += 1;
        }
        let watch_event = upsert.snapshot_id.is_none();

        let Some(stored) = self.stored(tx, ctx, &upsert.uid).await? else {
            let inserted = sqlx::query(
                "INSERT INTO inventory_resources \
                     (cluster_id, source_id, collection, uid, namespace, name, \
                      resource_version, object, truncated, order_epoch, order_seq, \
                      agent_observed_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (cluster_id, uid) DO NOTHING",
            )
            .bind(ctx.cluster_id)
            .bind(ctx.source_id)
            .bind(collection.as_str())
            .bind(&upsert.uid)
            .bind(namespace)
            .bind(&upsert.name)
            .bind(&upsert.resource_version)
            .bind(&object)
            .bind(upsert.truncated)
            .bind(ctx.sync_epoch)
            .bind(seq)
            .bind(upsert.observed_at)
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 1 {
                observed.insert(collection);
                self.watch_event(tx, ctx, collection, watch_event).await?;
            }
            return Ok(());
        };
        if !self.owns(ctx, &stored, collection) || !newer(ctx, seq, &stored) {
            return Ok(());
        }
        observed.insert(collection);
        let replaces_content =
            !self.version_is_older(&upsert.resource_version, &stored.resource_version);
        if !replaces_content {
            // The content is older than what is stored. The resource was still seen.
            sqlx::query(
                "UPDATE inventory_resources \
                 SET order_epoch = $2, order_seq = $3, last_observed_at = now(), \
                     uncollected_at = NULL \
                 WHERE id = $1",
            )
            .bind(stored.id)
            .bind(ctx.sync_epoch)
            .bind(seq)
            .execute(&mut *tx)
            .await?;
        } else {
            if stored.deleted {
                tracing::warn!(
                    %collection,
                    uid = %upsert.uid,
                    namespace,
                    name = %upsert.name,
                    resource_version = %upsert.resource_version,
                    "an upsert brought back a tombstoned resource; its deletion was wrong"
                );
                sqlx::query(
                    "UPDATE inventory_collections \
                     SET tombstone_reversals = tombstone_reversals + 1 \
                     WHERE source_id = $1 AND collection = $2",
                )
                .bind(ctx.source_id)
                .bind(collection.as_str())
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(
                "UPDATE inventory_resources \
                 SET namespace = $2, name = $3, resource_version = $4, object = $5, \
                     truncated = $6, order_epoch = $7, order_seq = $8, \
                     last_observed_at = now(), agent_observed_at = $9, deleted_at = NULL, \
                     uncollected_at = NULL \
                 WHERE id = $1",
            )
            .bind(stored.id)
            .bind(namespace)
            .bind(&upsert.name)
            .bind(&upsert.resource_version)
            .bind(&object)
            .bind(upsert.truncated)
            .bind(ctx.sync_epoch)
            .bind(seq)
            .bind(upsert.observed_at)
            .execute(&mut *tx)
            .await?;
        }
        self.watch_event(tx, ctx, collection, watch_event).await?;
        Ok(())
    }

    async fn delete(
        &mut self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        seq: i64,
        delete: Delete,
        observed: &mut HashSet<Collection>,
    ) -> Result<(), Rejected> {
        let collection = parse_collection(&delete.collection)?;
        let namespace = validate_identity(
            collection,
            &delete.uid,
            delete.namespace.as_deref(),
            &delete.name,
            &delete.resource_version,
        )?;
        let Some(stored) = self.stored(tx, ctx, &delete.uid).await? else {
            // A tombstone for a resource never seen, so a delayed upsert with an older key
            // cannot add it.
            let inserted = sqlx::query(
                "INSERT INTO inventory_resources \
                     (cluster_id, source_id, collection, uid, namespace, name, \
                      resource_version, order_epoch, order_seq, agent_observed_at, deleted_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now()) \
                 ON CONFLICT (cluster_id, uid) DO NOTHING",
            )
            .bind(ctx.cluster_id)
            .bind(ctx.source_id)
            .bind(collection.as_str())
            .bind(&delete.uid)
            .bind(namespace)
            .bind(&delete.name)
            .bind(&delete.resource_version)
            .bind(ctx.sync_epoch)
            .bind(seq)
            .bind(delete.observed_at)
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 1 {
                observed.insert(collection);
                self.watch_event(tx, ctx, collection, true).await?;
            }
            return Ok(());
        };
        if !self.owns(ctx, &stored, collection) || !newer(ctx, seq, &stored) {
            return Ok(());
        }
        observed.insert(collection);
        let resource_version =
            if self.version_is_older(&delete.resource_version, &stored.resource_version) {
                &stored.resource_version
            } else {
                &delete.resource_version
            };
        sqlx::query(
            "UPDATE inventory_resources \
             SET resource_version = $2, order_epoch = $3, order_seq = $4, \
                 last_observed_at = now(), agent_observed_at = $5, \
                 deleted_at = coalesce(deleted_at, now()) \
             WHERE id = $1",
        )
        .bind(stored.id)
        .bind(resource_version)
        .bind(ctx.sync_epoch)
        .bind(seq)
        .bind(delete.observed_at)
        .execute(&mut *tx)
        .await?;
        self.watch_event(tx, ctx, collection, true).await?;
        Ok(())
    }

    async fn snapshot_end(
        &mut self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        seq: i64,
        end: SnapshotEnd,
    ) -> Result<(), Rejected> {
        let Some(collection) = self
            .open
            .iter()
            .find(|(_, s)| s.id == end.snapshot_id)
            .map(|(c, _)| *c)
        else {
            if !self.finished.contains(&end.snapshot_id) {
                tracing::debug!(snapshot_id = %end.snapshot_id, "`snapshot_end` for an unknown snapshot");
            }
            return Ok(());
        };
        let snapshot = self.open.remove(&collection).expect("found above");
        self.finished.insert(snapshot.id);
        if snapshot.received != end.item_count {
            tracing::warn!(
                %collection,
                snapshot_id = %snapshot.id,
                item_count = end.item_count,
                received = snapshot.received,
                "snapshot item count mismatch; no deletions inferred"
            );
            sqlx::query(
                "UPDATE inventory_collections \
                 SET open_snapshot_id = NULL, open_snapshot_epoch = NULL, \
                     open_snapshot_started_at = NULL, error_reason = 'snapshot_incomplete', \
                     error_message = $3, error_observed_at = now() \
                 WHERE source_id = $1 AND collection = $2",
            )
            .bind(ctx.source_id)
            .bind(collection.as_str())
            .bind(format!(
                "The snapshot listed {} items, but the server received {}. No deletions were \
                 inferred from it.",
                end.item_count, snapshot.received
            ))
            .execute(&mut *tx)
            .await?;
            self.errored.insert(collection);
            return Ok(());
        }
        let deleted = sqlx::query(
            "UPDATE inventory_resources \
             SET deleted_at = now(), order_epoch = $3, order_seq = $4 \
             WHERE source_id = $1 AND collection = $2 AND deleted_at IS NULL \
               AND ($5::text IS NULL OR namespace = $5) \
               AND (order_epoch, order_seq) < ($3, $6)",
        )
        .bind(ctx.source_id)
        .bind(collection.as_str())
        .bind(ctx.sync_epoch)
        .bind(seq)
        .bind(&snapshot.namespace)
        .bind(snapshot.start_seq)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if let Some(namespace) = &snapshot.namespace {
            // Open question 9 of the architecture document: resources outside a narrower
            // scope are no longer collected, not deleted.
            sqlx::query(
                "UPDATE inventory_resources SET uncollected_at = now() \
                 WHERE source_id = $1 AND collection = $2 AND deleted_at IS NULL \
                   AND namespace <> $3 AND uncollected_at IS NULL",
            )
            .bind(ctx.source_id)
            .bind(collection.as_str())
            .bind(namespace)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "UPDATE inventory_collections \
             SET open_snapshot_id = NULL, open_snapshot_epoch = NULL, \
                 open_snapshot_started_at = NULL, snapshot_scope_namespace = $3, \
                 snapshot_completed_at = now(), snapshot_item_count = $4, \
                 snapshot_resource_version = $5, error_reason = NULL, error_message = NULL, \
                 error_observed_at = NULL \
             WHERE source_id = $1 AND collection = $2",
        )
        .bind(ctx.source_id)
        .bind(collection.as_str())
        .bind(&snapshot.namespace)
        .bind(i64::try_from(end.item_count).unwrap_or(i64::MAX))
        .bind(
            end.resource_version
                .as_deref()
                .filter(|rv| rv.len() <= MAX_RESOURCE_VERSION_LEN),
        )
        .execute(&mut *tx)
        .await?;
        self.errored.remove(&collection);
        tracing::debug!(%collection, items = end.item_count, deleted, "snapshot completed");
        Ok(())
    }

    async fn snapshot_abort(
        &mut self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        abort: SnapshotAbort,
    ) -> Result<(), Rejected> {
        let Some(collection) = self
            .open
            .iter()
            .find(|(_, s)| s.id == abort.snapshot_id)
            .map(|(c, _)| *c)
        else {
            return Ok(());
        };
        self.open.remove(&collection);
        self.finished.insert(abort.snapshot_id);
        tracing::debug!(
            %collection,
            snapshot_id = %abort.snapshot_id,
            reason = %truncate(&abort.reason, MAX_REASON_LEN),
            "snapshot aborted; no deletions inferred"
        );
        self.clear_open_snapshot(tx, ctx, collection).await
    }

    async fn collection_error(
        &mut self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        error: CollectionError,
    ) -> Result<(), Rejected> {
        let collection = parse_collection(&error.collection)?;
        parse_scope(collection, &error.scope)?;
        let reason = printable(&error.reason, MAX_REASON_LEN);
        if reason.is_empty() {
            return Err(Rejected::invalid("`reason` must not be empty"));
        }
        let message = printable(
            error.message.as_deref().unwrap_or(""),
            MAX_ERROR_MESSAGE_LEN,
        );
        tracing::info!(%collection, reason, message, "the agent reported a collection error");
        if let Some(open) = self.open.remove(&collection) {
            self.finished.insert(open.id);
        }
        sqlx::query(
            "INSERT INTO inventory_collections \
                 (source_id, collection, error_reason, error_message, error_observed_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (source_id, collection) DO UPDATE SET \
                 open_snapshot_id = NULL, open_snapshot_epoch = NULL, \
                 open_snapshot_started_at = NULL, error_reason = excluded.error_reason, \
                 error_message = excluded.error_message, \
                 error_observed_at = excluded.error_observed_at",
        )
        .bind(ctx.source_id)
        .bind(collection.as_str())
        .bind(reason)
        .bind(message)
        .execute(&mut *tx)
        .await?;
        self.errored.insert(collection);
        Ok(())
    }

    async fn clear_open_snapshot(
        &self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        collection: Collection,
    ) -> Result<(), Rejected> {
        sqlx::query(
            "UPDATE inventory_collections \
             SET open_snapshot_id = NULL, open_snapshot_epoch = NULL, \
                 open_snapshot_started_at = NULL \
             WHERE source_id = $1 AND collection = $2",
        )
        .bind(ctx.source_id)
        .bind(collection.as_str())
        .execute(tx)
        .await?;
        Ok(())
    }

    /// A watch event shows the collection's watch works again: it clears an error this
    /// connection reported.
    async fn watch_event(
        &mut self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        collection: Collection,
        watch_event: bool,
    ) -> Result<(), Rejected> {
        if !watch_event || !self.errored.remove(&collection) {
            return Ok(());
        }
        sqlx::query(
            "UPDATE inventory_collections \
             SET error_reason = NULL, error_message = NULL, error_observed_at = NULL \
             WHERE source_id = $1 AND collection = $2",
        )
        .bind(ctx.source_id)
        .bind(collection.as_str())
        .execute(tx)
        .await?;
        Ok(())
    }

    async fn stored(
        &self,
        tx: &mut PgConnection,
        ctx: &ConnectionContext,
        uid: &str,
    ) -> Result<Option<StoredResource>, Rejected> {
        Ok(sqlx::query_as(
            "SELECT id, source_id, collection, resource_version, order_epoch, order_seq, \
                    deleted_at IS NOT NULL AS deleted \
             FROM inventory_resources WHERE cluster_id = $1 AND uid = $2 FOR UPDATE",
        )
        .bind(ctx.cluster_id)
        .bind(uid)
        .fetch_optional(tx)
        .await?)
    }

    /// Whether this connection may change `stored`: it belongs to the same source and
    /// collection. A UID never moves between collections, so a mismatch is an agent bug.
    fn owns(
        &self,
        ctx: &ConnectionContext,
        stored: &StoredResource,
        collection: Collection,
    ) -> bool {
        if stored.source_id != ctx.source_id || stored.collection != collection.as_str() {
            tracing::warn!(
                resource_id = %stored.id,
                stored_collection = %stored.collection,
                %collection,
                "an observation names a UID stored for another source or collection; ignored"
            );
            return false;
        }
        true
    }

    /// The resource version rule: `new` is older than `stored` only when versions may be
    /// compared on this cluster and both are canonical decimals.
    fn version_is_older(&self, new: &str, stored: &str) -> bool {
        self.compare_versions && decimal_less(new, stored)
    }
}

/// Whether the observation `(ctx.sync_epoch, seq)` orders after the stored one.
fn newer(ctx: &ConnectionContext, seq: i64, stored: &StoredResource) -> bool {
    (ctx.sync_epoch, seq) > (stored.order_epoch, stored.order_seq)
}

/// The epoch fence and the agent check, at the start of an ingest transaction. The
/// source row is locked before the agent row, in the same order as connection open and
/// replacement enrollment.
async fn fence(tx: &mut Transaction<'_, Postgres>, ctx: &ConnectionContext) -> Result<(), Close> {
    let epoch: Option<i64> =
        sqlx::query_scalar("SELECT sync_epoch FROM sources WHERE id = $1 FOR SHARE")
            .bind(ctx.source_id)
            .fetch_optional(&mut **tx)
            .await?;
    let revoked: Option<bool> =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM agents WHERE id = $1 FOR SHARE")
            .bind(ctx.agent_id)
            .fetch_optional(&mut **tx)
            .await?;
    match (epoch, revoked) {
        (None, _) | (_, None) | (_, Some(true)) => {
            Err(Close::new(CloseCode::Revoked, "agent revoked"))
        }
        (Some(epoch), Some(false)) if epoch != ctx.sync_epoch => Err(Close::new(
            CloseCode::Superseded,
            "superseded by a newer connection for this source",
        )),
        _ => Ok(()),
    }
}

/// Why a message was not applied.
#[derive(Debug)]
enum Rejected {
    /// Ignore it and answer an `error` with this code.
    Notice(&'static str, String),
    Close(Close),
}

impl Rejected {
    fn invalid(message: impl Into<String>) -> Self {
        Rejected::Notice(INVALID_MESSAGE, message.into())
    }
}

impl From<sqlx::Error> for Rejected {
    fn from(err: sqlx::Error) -> Self {
        Rejected::Close(err.into())
    }
}

fn parse_collection(name: &str) -> Result<Collection, Rejected> {
    Collection::parse(name).ok_or_else(|| {
        Rejected::Notice(
            UNSUPPORTED_COLLECTION,
            format!(
                "the server does not collect `{}`",
                truncate(name, MAX_REASON_LEN)
            ),
        )
    })
}

/// The namespace a scope is limited to, after checking it fits the collection.
fn parse_scope(collection: Collection, scope: &Scope) -> Result<Option<String>, Rejected> {
    match &scope.namespace {
        None => Ok(None),
        Some(_) if !collection.namespaced() => Err(Rejected::invalid(format!(
            "`{collection}` is cluster-scoped, so its scope has no namespace"
        ))),
        Some(namespace) if valid_name(namespace) => Ok(Some(namespace.clone())),
        Some(_) => Err(Rejected::invalid("the scope namespace is not a valid name")),
    }
}

/// Checks an observation's identity fields. Returns the namespace column value (empty
/// for cluster-scoped resources).
fn validate_identity<'a>(
    collection: Collection,
    uid: &str,
    namespace: Option<&'a str>,
    name: &str,
    resource_version: &str,
) -> Result<&'a str, Rejected> {
    if uid.is_empty() || uid.len() > MAX_UID_LEN || !uid.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Rejected::invalid(
            "`uid` must be 1 to 128 printable characters",
        ));
    }
    if !valid_name(name) {
        return Err(Rejected::invalid("`name` is not a valid object name"));
    }
    if resource_version.len() > MAX_RESOURCE_VERSION_LEN {
        return Err(Rejected::invalid("`resource_version` is too long"));
    }
    match (collection.namespaced(), namespace) {
        (true, Some(namespace)) if valid_name(namespace) => Ok(namespace),
        (false, None) => Ok(""),
        (true, _) => Err(Rejected::invalid(format!(
            "`{collection}` objects need a valid `namespace`"
        ))),
        (false, Some(_)) => Err(Rejected::invalid(format!(
            "`{collection}` objects are cluster-scoped and have no `namespace`"
        ))),
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LEN && name.bytes().all(|b| b.is_ascii_graphic())
}

/// Whether a Kubernetes `gitVersion` such as `v1.35.0` or `v1.36.1+k3s1` is 1.35 or
/// later, the first release that guarantees resource versions order within a type.
pub(crate) fn orders_resource_versions(git_version: &str) -> bool {
    let version = git_version.strip_prefix('v').unwrap_or(git_version);
    let mut parts = version.split('.');
    let number = |part: Option<&str>| -> Option<u64> {
        let digits: String = part?.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    match (number(parts.next()), number(parts.next())) {
        (Some(major), Some(minor)) => (major, minor) >= (1, 35),
        _ => false,
    }
}

/// A canonical decimal: digits only, no leading zero.
fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

/// `a < b` numerically, when both are canonical decimals. Otherwise false: the order key
/// alone decides.
pub(crate) fn decimal_less(a: &str, b: &str) -> bool {
    canonical_decimal(a)
        && canonical_decimal(b)
        && (a.len(), a.as_bytes()) < (b.len(), b.as_bytes())
}

/// `value` with control characters replaced, cut to at most `max` bytes.
fn printable(value: &str, max: usize) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    truncate(cleaned.trim(), max).to_owned()
}

fn truncate(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubernetes_versions_that_order_resource_versions() {
        for yes in [
            "v1.35.0",
            "v1.36.1+k3s1",
            "v1.37.0-rc.1",
            "1.35",
            "v2.0.0",
            "v1.35+",
        ] {
            assert!(orders_resource_versions(yes), "{yes}");
        }
        for no in ["v1.34.9", "v1.9.0", "v1", "", "garbage", "v1.x"] {
            assert!(!orders_resource_versions(no), "{no}");
        }
    }

    #[test]
    fn resource_versions_compare_only_as_canonical_decimals() {
        assert!(decimal_less("9", "10"));
        assert!(decimal_less("100", "101"));
        assert!(!decimal_less("10", "10"));
        assert!(!decimal_less("11", "10"));
        assert!(decimal_less("0", "1"));
        assert!(!decimal_less("09", "10"), "a leading zero is not canonical");
        assert!(!decimal_less("", "10"));
        assert!(!decimal_less("abc", "10"));
        assert!(!decimal_less("5", "1a"));
        assert!(decimal_less(
            "99999999999999999999",
            "100000000000000000000"
        ));
    }

    #[test]
    fn identities_are_validated_per_collection() {
        assert_eq!(
            validate_identity(Collection::Nodes, "u", None, "n", "1").unwrap(),
            ""
        );
        assert_eq!(
            validate_identity(Collection::Deployments, "u", Some("ns"), "d", "1").unwrap(),
            "ns"
        );
        assert!(validate_identity(Collection::Deployments, "u", None, "d", "1").is_err());
        assert!(validate_identity(Collection::Nodes, "u", Some("ns"), "n", "1").is_err());
        assert!(validate_identity(Collection::Nodes, "", None, "n", "1").is_err());
        assert!(validate_identity(Collection::Nodes, "u", None, "", "1").is_err());
        assert!(
            parse_scope(
                Collection::Nodes,
                &Scope {
                    namespace: Some("a".into())
                }
            )
            .is_err()
        );
        assert_eq!(
            parse_scope(
                Collection::DaemonSets,
                &Scope {
                    namespace: Some("a".into())
                }
            )
            .unwrap(),
            Some("a".into())
        );
    }

    #[test]
    fn printable_strips_control_characters() {
        assert_eq!(printable(" a\nb\u{7} ", 10), "a b");
        assert_eq!(printable("éé", 3), "é");
    }
}
