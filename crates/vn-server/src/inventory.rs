//! The inventory API: clusters with their connection and collection status, and the
//! resources their agents reported.
//!
//! Any project member (viewer and up) and installation admins may read it. A cluster in
//! another project answers 404, the same as one that does not exist.

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::State;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;
use vn_core::AgentStatus;
use vn_core::inventory::{
    Cluster, ClusterAgent, ClusterConnection, ClusterInventory, ClusterList, Collection,
    CollectionErrorInfo, CollectionState, CollectionStatus, ConnectionState, Resource,
    ResourceDetail, ResourceList, ResourceState, ResourceSummary,
};

use crate::auth::Principal;
use crate::authz::{self, ProjectPermission};
use crate::error::{ApiFailure, ApiPath, ApiQuery};
use crate::router::AppState;

/// A connection whose last-seen time is older than this counts as disconnected, which
/// covers a server process that stopped without recording the close. Connections
/// record their last-seen time every 30 seconds.
const CONNECTION_FRESHNESS_SECONDS: i32 = 90;

/// Default and largest page of the resources endpoint.
const DEFAULT_PAGE: i64 = 100;
const MAX_PAGE: i64 = 500;

/// Longest accepted `search` and `namespace` filters.
const MAX_FILTER_LEN: usize = 253;

#[derive(sqlx::FromRow)]
struct ClusterRow {
    id: Uuid,
    project_id: Uuid,
    display_name: String,
    created_at: DateTime<Utc>,
    source_id: Uuid,
    agent_id: Option<Uuid>,
    agent_active: Option<bool>,
    agent_version: Option<String>,
    connection_epoch: Option<i64>,
    opened_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
    closed_at: Option<DateTime<Utc>>,
    kubernetes_version: Option<String>,
    connected: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct CollectionRow {
    source_id: Uuid,
    collection: String,
    open_snapshot_epoch: Option<i64>,
    snapshot_completed_at: Option<DateTime<Utc>>,
    error_reason: Option<String>,
    error_message: Option<String>,
    error_observed_at: Option<DateTime<Utc>>,
    last_observed_at: Option<DateTime<Utc>>,
}

/// Clusters of `project_id`, or only `cluster_id`, with their status.
async fn load_clusters(
    db: &PgPool,
    project_id: Uuid,
    cluster_id: Option<Uuid>,
) -> Result<Vec<Cluster>, ApiFailure> {
    // A cluster's source is its whole-cluster source; its agent is the active one, or the
    // most recent when all are revoked; its connection is the most recent one. "Most recent"
    // means the highest sync epoch, which is allocated under the source row lock. `opened_at`
    // is the transaction start time, so overlapping opens can record it out of order.
    let rows: Vec<ClusterRow> = sqlx::query_as(
        "SELECT c.id, c.project_id, c.display_name, c.created_at, s.id AS source_id, \
                ag.id AS agent_id, ag.revoked_at IS NULL AS agent_active, ag.agent_version, \
                conn.sync_epoch AS connection_epoch, conn.opened_at, conn.last_seen_at, \
                conn.closed_at, conn.kubernetes_version, \
                (conn.closed_at IS NULL \
                 AND conn.last_seen_at > now() - make_interval(secs => $3)) AS connected \
         FROM clusters c \
         JOIN sources s ON s.cluster_id = c.id AND s.scope = 'cluster' \
         LEFT JOIN LATERAL ( \
             SELECT a.id, a.revoked_at, a.agent_version FROM agents a \
             WHERE a.source_id = s.id \
             ORDER BY a.revoked_at IS NULL DESC, a.enrolled_at DESC LIMIT 1 \
         ) ag ON true \
         LEFT JOIN LATERAL ( \
             SELECT k.sync_epoch, k.opened_at, k.last_seen_at, k.closed_at, \
                    k.kubernetes_version \
             FROM agent_connections k WHERE k.source_id = s.id \
             ORDER BY k.sync_epoch DESC LIMIT 1 \
         ) conn ON true \
         WHERE c.project_id = $1 AND ($2::uuid IS NULL OR c.id = $2) \
         ORDER BY c.display_name, c.id",
    )
    .bind(project_id)
    .bind(cluster_id)
    .bind(f64::from(CONNECTION_FRESHNESS_SECONDS))
    .fetch_all(db)
    .await?;
    let sources: Vec<Uuid> = rows.iter().map(|r| r.source_id).collect();
    let collections: Vec<CollectionRow> = sqlx::query_as(
        "SELECT source_id, collection, open_snapshot_epoch, snapshot_completed_at, \
                error_reason, error_message, error_observed_at, last_observed_at \
         FROM inventory_collections WHERE source_id = ANY($1)",
    )
    .bind(&sources)
    .fetch_all(db)
    .await?;
    let counts: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT source_id, collection, count(*) FROM inventory_resources \
         WHERE source_id = ANY($1) AND deleted_at IS NULL GROUP BY source_id, collection",
    )
    .bind(&sources)
    .fetch_all(db)
    .await?;
    let mut states: HashMap<(Uuid, String), CollectionRow> = collections
        .into_iter()
        .map(|row| ((row.source_id, row.collection.clone()), row))
        .collect();
    let counts: HashMap<(Uuid, String), i64> = counts
        .into_iter()
        .map(|(source, collection, count)| ((source, collection), count))
        .collect();
    Ok(rows
        .into_iter()
        .map(|row| cluster(row, &mut states, &counts))
        .collect())
}

fn cluster(
    row: ClusterRow,
    states: &mut HashMap<(Uuid, String), CollectionRow>,
    counts: &HashMap<(Uuid, String), i64>,
) -> Cluster {
    let connected = row.connected == Some(true);
    let state = match (row.opened_at, connected) {
        (None, _) => ConnectionState::NeverConnected,
        (Some(_), true) => ConnectionState::Connected,
        (Some(_), false) => ConnectionState::Disconnected,
    };
    let open_epoch = connected.then_some(row.connection_epoch).flatten();
    let mut last_observed_at: Option<DateTime<Utc>> = None;
    let mut count_map = BTreeMap::new();
    let collections = Collection::ALL
        .into_iter()
        .map(|collection| {
            let key = (row.source_id, collection.as_str().to_owned());
            let resource_count = counts.get(&key).copied().unwrap_or(0);
            count_map.insert(collection.as_str().to_owned(), resource_count);
            let stored = states.remove(&key);
            let Some(stored) = stored else {
                return CollectionStatus {
                    collection,
                    state: CollectionState::NeverSynced,
                    last_snapshot_completed_at: None,
                    resource_count,
                    error: None,
                };
            };
            last_observed_at = last_observed_at.max(stored.last_observed_at);
            let error = match (stored.error_reason, stored.error_observed_at) {
                (Some(reason), Some(observed_at)) => Some(CollectionErrorInfo {
                    reason,
                    message: stored.error_message.unwrap_or_default(),
                    observed_at,
                }),
                _ => None,
            };
            let state = if error.is_some() {
                CollectionState::Error
            } else if open_epoch.is_some() && stored.open_snapshot_epoch == open_epoch {
                CollectionState::Syncing
            } else if stored.snapshot_completed_at.is_some() {
                CollectionState::Synced
            } else {
                CollectionState::NeverSynced
            };
            CollectionStatus {
                collection,
                state,
                last_snapshot_completed_at: stored.snapshot_completed_at,
                resource_count,
                error,
            }
        })
        .collect();
    let agent = match (row.agent_id, row.agent_active, row.agent_version) {
        (Some(id), Some(active), Some(agent_version)) => Some(ClusterAgent {
            id,
            status: if active {
                AgentStatus::Active
            } else {
                AgentStatus::Revoked
            },
            agent_version,
        }),
        _ => None,
    };
    Cluster {
        id: row.id,
        project_id: row.project_id,
        display_name: row.display_name,
        created_at: row.created_at,
        source_id: row.source_id,
        agent,
        connection: ClusterConnection {
            state,
            connected_since: if connected { row.opened_at } else { None },
            last_seen_at: row.last_seen_at.max(row.closed_at),
            kubernetes_version: row.kubernetes_version,
        },
        inventory: ClusterInventory {
            stale: state != ConnectionState::Connected,
            last_observed_at,
            counts: count_map,
        },
        collections,
    }
}

/// `GET /api/v1/projects/{slug}/clusters` (viewer)
pub(crate) async fn list_clusters(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath(slug): ApiPath<String>,
) -> Result<Json<ClusterList>, ApiFailure> {
    let project =
        authz::authorize_project(&state.db, &principal, &slug, ProjectPermission::View).await?;
    Ok(Json(ClusterList {
        clusters: load_clusters(&state.db, project.id, None).await?,
    }))
}

/// `GET /api/v1/projects/{slug}/clusters/{cluster_id}` (viewer)
pub(crate) async fn show_cluster(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath((slug, cluster_id)): ApiPath<(String, Uuid)>,
) -> Result<Json<Cluster>, ApiFailure> {
    let project =
        authz::authorize_project(&state.db, &principal, &slug, ProjectPermission::View).await?;
    load_clusters(&state.db, project.id, Some(cluster_id))
        .await?
        .pop()
        .map(Json)
        .ok_or_else(|| cluster_not_found(cluster_id))
}

fn cluster_not_found(cluster_id: Uuid) -> ApiFailure {
    ApiFailure::not_found(format!("no cluster {cluster_id} in this project"))
}

/// Checks that `cluster_id` belongs to the project the caller may view.
async fn authorize_cluster(
    state: &AppState,
    principal: &Principal,
    slug: &str,
    cluster_id: Uuid,
) -> Result<(), ApiFailure> {
    let project =
        authz::authorize_project(&state.db, principal, slug, ProjectPermission::View).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM clusters WHERE id = $1 AND project_id = $2)",
    )
    .bind(cluster_id)
    .bind(project.id)
    .fetch_one(&state.db)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(cluster_not_found(cluster_id))
    }
}

/// Query parameters of the resources endpoint.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ResourceQuery {
    collection: Option<String>,
    namespace: Option<String>,
    search: Option<String>,
    include_deleted: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
}

/// Where a page starts: after this resource in listing order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
struct Cursor(String, String, String, Uuid);

impl Cursor {
    fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).expect("cursors serialize"))
    }

    fn decode(value: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

struct Filters {
    collection: Option<Collection>,
    namespace: Option<String>,
    /// An `ILIKE` pattern.
    search: Option<String>,
    include_deleted: bool,
    limit: i64,
    cursor: Option<Cursor>,
}

impl ResourceQuery {
    fn parse(self) -> Result<Filters, ApiFailure> {
        let non_empty = |value: Option<String>| value.filter(|v| !v.is_empty());
        let collection = match non_empty(self.collection) {
            None => None,
            Some(name) => Some(Collection::parse(&name).ok_or_else(|| {
                ApiFailure::invalid(format!(
                    "`collection` must be one of {}",
                    Collection::ALL.map(Collection::as_str).join(", ")
                ))
            })?),
        };
        let namespace = non_empty(self.namespace);
        let search = non_empty(self.search);
        if namespace.as_ref().is_some_and(|v| v.len() > MAX_FILTER_LEN)
            || search.as_ref().is_some_and(|v| v.len() > MAX_FILTER_LEN)
        {
            return Err(ApiFailure::invalid(
                "`namespace` and `search` are at most 253 characters",
            ));
        }
        let include_deleted = match self.include_deleted.as_deref() {
            None | Some("") | Some("false") => false,
            Some("true") => true,
            Some(_) => {
                return Err(ApiFailure::invalid(
                    "`include_deleted` must be true or false",
                ));
            }
        };
        let limit = match non_empty(self.limit) {
            None => DEFAULT_PAGE,
            Some(limit) => limit
                .parse::<i64>()
                .ok()
                .filter(|l| (1..=MAX_PAGE).contains(l))
                .ok_or_else(|| ApiFailure::invalid("`limit` must be from 1 to 500"))?,
        };
        let cursor = match non_empty(self.cursor) {
            None => None,
            Some(cursor) => Some(
                Cursor::decode(&cursor)
                    .ok_or_else(|| ApiFailure::invalid("`cursor` is not a valid cursor"))?,
            ),
        };
        Ok(Filters {
            collection,
            namespace,
            search: search.map(|s| format!("%{}%", escape_like(&s))),
            include_deleted,
            limit,
            cursor,
        })
    }
}

/// Escapes `%`, `_`, and `\` for a `LIKE` pattern with the default escape character.
fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

#[derive(sqlx::FromRow)]
struct ResourceRow {
    id: Uuid,
    collection: String,
    uid: String,
    namespace: String,
    name: String,
    resource_version: String,
    object: Option<Value>,
    truncated: bool,
    first_observed_at: DateTime<Utc>,
    last_observed_at: DateTime<Utc>,
    deleted_at: Option<DateTime<Utc>>,
}

const RESOURCE_COLUMNS: &str = "id, collection, uid, namespace, name, resource_version, \
    object, truncated, first_observed_at, last_observed_at, deleted_at";

impl ResourceRow {
    fn cursor(&self) -> Cursor {
        Cursor(
            self.collection.clone(),
            self.namespace.clone(),
            self.name.clone(),
            self.id,
        )
    }

    /// The resource and its stored object.
    fn into_resource(self) -> Result<(Resource, Option<Value>), ApiFailure> {
        let collection = Collection::parse(&self.collection).ok_or_else(|| {
            ApiFailure::internal(format!(
                "unknown collection `{}` in inventory_resources",
                self.collection
            ))
        })?;
        let resource = Resource {
            id: self.id,
            collection,
            kind: collection.kind().to_owned(),
            uid: self.uid,
            namespace: (!self.namespace.is_empty()).then_some(self.namespace),
            name: self.name,
            resource_version: self.resource_version,
            state: if self.deleted_at.is_some() {
                ResourceState::Deleted
            } else {
                ResourceState::Present
            },
            first_observed_at: self.first_observed_at,
            last_observed_at: self.last_observed_at,
            deleted_at: self.deleted_at,
            truncated: self.truncated,
            summary: ResourceSummary::compute(collection, self.object.as_ref()),
        };
        Ok((resource, self.object))
    }
}

/// `GET /api/v1/projects/{slug}/clusters/{cluster_id}/resources` (viewer)
pub(crate) async fn list_resources(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath((slug, cluster_id)): ApiPath<(String, Uuid)>,
    ApiQuery(query): ApiQuery<ResourceQuery>,
) -> Result<Json<ResourceList>, ApiFailure> {
    let filters = query.parse()?;
    authorize_cluster(&state, &principal, &slug, cluster_id).await?;
    let (after_collection, after_namespace, after_name, after_id) = match filters.cursor {
        Some(Cursor(collection, namespace, name, id)) => {
            (Some(collection), Some(namespace), Some(name), Some(id))
        }
        None => (None, None, None, None),
    };
    let mut rows: Vec<ResourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {RESOURCE_COLUMNS} FROM inventory_resources \
         WHERE cluster_id = $1 \
           AND ($2::text IS NULL OR collection = $2) \
           AND ($3::text IS NULL OR namespace = $3) \
           AND ($4::text IS NULL OR name ILIKE $4) \
           AND ($5 OR deleted_at IS NULL) \
           AND ($6::text IS NULL OR (collection, namespace, name, id) > ($6, $7, $8, $9)) \
         ORDER BY collection, namespace, name, id \
         LIMIT $10"
    )))
    .bind(cluster_id)
    .bind(filters.collection.map(Collection::as_str))
    .bind(filters.namespace)
    .bind(filters.search)
    .bind(filters.include_deleted)
    .bind(after_collection)
    .bind(after_namespace)
    .bind(after_name)
    .bind(after_id)
    .bind(filters.limit + 1)
    .fetch_all(&state.db)
    .await?;
    let more = rows.len() > usize::try_from(filters.limit).unwrap_or(usize::MAX);
    rows.truncate(usize::try_from(filters.limit).unwrap_or(usize::MAX));
    let next_cursor = if more {
        rows.last().map(|row| row.cursor().encode())
    } else {
        None
    };
    let resources = rows
        .into_iter()
        .map(|row| row.into_resource().map(|(resource, _)| resource))
        .collect::<Result<_, _>>()?;
    Ok(Json(ResourceList {
        resources,
        next_cursor,
    }))
}

/// `GET /api/v1/projects/{slug}/clusters/{cluster_id}/resources/{resource_id}` (viewer)
pub(crate) async fn show_resource(
    State(state): State<AppState>,
    principal: Principal,
    ApiPath((slug, cluster_id, resource_id)): ApiPath<(String, Uuid, Uuid)>,
) -> Result<Json<ResourceDetail>, ApiFailure> {
    authorize_cluster(&state, &principal, &slug, cluster_id).await?;
    let row: Option<ResourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {RESOURCE_COLUMNS} FROM inventory_resources WHERE id = $1 AND cluster_id = $2"
    )))
    .bind(resource_id)
    .bind(cluster_id)
    .fetch_optional(&state.db)
    .await?;
    let row =
        row.ok_or_else(|| ApiFailure::not_found(format!("no resource {resource_id} here")))?;
    let (resource, object) = row.into_resource()?;
    let object = object.unwrap_or_else(|| identity_object(&resource));
    Ok(Json(ResourceDetail { resource, object }))
}

/// The identity of a resource whose object was not stored (truncated, or a tombstone of
/// a resource never received).
fn identity_object(resource: &Resource) -> Value {
    let mut metadata = json!({
        "name": resource.name,
        "uid": resource.uid,
        "resourceVersion": resource.resource_version,
    });
    if let Some(namespace) = &resource.namespace {
        metadata["namespace"] = json!(namespace);
    }
    json!({
        "apiVersion": resource.collection.api_version(),
        "kind": resource.kind,
        "metadata": metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_round_trip() {
        let cursor = Cursor(
            "v1/nodes".into(),
            "".into(),
            "n1".into(),
            Uuid::from_u128(5),
        );
        assert_eq!(Cursor::decode(&cursor.encode()), Some(cursor));
        assert_eq!(Cursor::decode("not a cursor"), None);
        assert_eq!(Cursor::decode(&URL_SAFE_NO_PAD.encode(b"[1]")), None);
    }

    #[test]
    fn like_patterns_are_escaped() {
        assert_eq!(escape_like("a_b%c\\d"), "a\\_b\\%c\\\\d");
    }

    #[test]
    fn query_validation() {
        let parse = |q: ResourceQuery| q.parse().map(|f| (f.limit, f.include_deleted));
        assert_eq!(parse(ResourceQuery::default()).unwrap(), (100, false));
        let q = |limit: &str| ResourceQuery {
            limit: Some(limit.into()),
            ..Default::default()
        };
        assert_eq!(parse(q("500")).unwrap().0, 500);
        assert!(parse(q("0")).is_err());
        assert!(parse(q("501")).is_err());
        assert!(parse(q("x")).is_err());
        assert!(
            parse(ResourceQuery {
                collection: Some("v1/secrets".into()),
                ..Default::default()
            })
            .is_err()
        );
        assert!(
            parse(ResourceQuery {
                include_deleted: Some("yes".into()),
                ..Default::default()
            })
            .is_err()
        );
    }
}
