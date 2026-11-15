//! Inventory collection: one `kube-runtime` watcher per collection, mapped to protocol
//! messages as `docs/agent-protocol.md` describes.
//!
//! | Watcher event | Messages |
//! | --- | --- |
//! | `Init` | `snapshot_start` (abandoning an unfinished previous snapshot) |
//! | `InitApply` | `upsert` in the snapshot |
//! | `InitDone` | `snapshot_end` with the item count |
//! | `Apply`, `Delete` | `upsert`, `delete` (watch events, which may coalesce) |
//! | error | `snapshot_abort` for an open snapshot, then `collection_error` |
//!
//! Watchers list with the most recent (quorum read) semantic and retry after errors
//! with the agent's backoff (1 to 60 seconds), which starts over only after a completed
//! listing or a watch event. A relist (for example after an expired resource version)
//! starts a new snapshot. `snapshot_start` is queued when the listing yields its first
//! object or its end, so a listing that fails right away, as a forbidden one does,
//! sends nothing but its `collection_error`, and only once. Errors never infer
//! deletions: the server keeps prior inventory.
//!
//! Collection restarts with every connection: [`Collect::start`] is called after each
//! `welcome`, and the returned tasks stop when the connection ends.

use std::fmt;
use std::pin::pin;

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use k8s_openapi::api::core::v1::{Namespace, Node};
use kube::api::{Api, ApiResource, DynamicObject};
use kube::runtime::watcher::{self, Event, ListSemantic};
use serde_json::Value;
use tokio::task::JoinSet;
use uuid::Uuid;
use vn_core::agent_protocol::{CollectionError, Delete, Scope, SnapshotEnd, SnapshotStart, Upsert};
use vn_core::inventory::{Collection, sanitize_object};

use crate::backoff::Backoff;
use crate::queue::{Outgoing, Queue, SyncQueue};

/// What the connection's `welcome` allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest message the server accepts. Larger objects are sent truncated.
    pub max_message_bytes: usize,
}

/// Starts inventory collection for one connection.
pub trait Collect: Send + Sync {
    /// Starts collecting every collection into `queue`. Dropping the returned set stops
    /// collection.
    fn start(&self, queue: SyncQueue, limits: Limits) -> JoinSet<()>;
}

/// Collects from the Kubernetes API with `kube-runtime` watchers.
pub struct KubeCollector {
    client: kube::Client,
}

impl KubeCollector {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

impl Collect for KubeCollector {
    fn start(&self, queue: SyncQueue, limits: Limits) -> JoinSet<()> {
        let mut tasks = JoinSet::new();
        for collection in Collection::ALL {
            tasks.spawn(watch(
                self.client.clone(),
                collection,
                queue.clone(),
                limits,
            ));
        }
        tasks
    }
}

fn api_resource(collection: Collection) -> ApiResource {
    match collection {
        Collection::Nodes => ApiResource::erase::<Node>(&()),
        Collection::Namespaces => ApiResource::erase::<Namespace>(&()),
        Collection::Deployments => ApiResource::erase::<Deployment>(&()),
        Collection::StatefulSets => ApiResource::erase::<StatefulSet>(&()),
        Collection::DaemonSets => ApiResource::erase::<DaemonSet>(&()),
    }
}

/// Watches `collection` in all namespaces until the task is dropped. Objects are read
/// as dynamic JSON so fields newer than the compiled API types are kept.
async fn watch(client: kube::Client, collection: Collection, queue: SyncQueue, limits: Limits) {
    let resource = api_resource(collection);
    let api: Api<DynamicObject> = Api::all_with(client, &resource);
    let config = watcher::Config::default().list_semantic(ListSemantic::MostRecent);
    let mut events = pin!(watcher::watcher(api, config));
    let mut mapper = Mapper::new(collection, limits);
    // `kube-runtime`'s own backoff starts over at every `Init`, which a failing listing
    // emits before each attempt, so it would retry about once a second.
    let mut backoff = Backoff::default();
    tracing::debug!(%collection, "collecting");
    while let Some(event) = events.next().await {
        let failed = event.is_err();
        if matches!(
            event,
            Ok(Event::InitDone | Event::Apply(_) | Event::Delete(_))
        ) {
            backoff.reset();
        }
        let observed = match event {
            Ok(Event::Init) => Observed::Init,
            Ok(Event::InitApply(object)) => Observed::InitApply(to_json(object)),
            Ok(Event::InitDone) => Observed::InitDone,
            Ok(Event::Apply(object)) => Observed::Apply(to_json(object)),
            Ok(Event::Delete(object)) => Observed::Delete(to_json(object)),
            Err(err) => match Failure::classify(&err) {
                Some(failure) => {
                    tracing::warn!(%collection, reason = failure.reason, message = %failure.message, "collection failed; retrying");
                    Observed::Error(failure)
                }
                None => {
                    tracing::debug!(%collection, error = %err, "watch interrupted; the watcher recovers");
                    tokio::time::sleep(backoff.next_delay()).await;
                    continue;
                }
            },
        };
        queue.update(|q| mapper.on(observed, q, Utc::now()));
        if failed {
            tokio::time::sleep(backoff.next_delay()).await;
        }
    }
}

fn to_json(object: DynamicObject) -> Value {
    serde_json::to_value(object).unwrap_or(Value::Null)
}

/// A watcher event with its object as JSON.
#[derive(Debug, Clone, PartialEq)]
pub enum Observed {
    Init,
    InitApply(Value),
    InitDone,
    Apply(Value),
    Delete(Value),
    Error(Failure),
}

/// A failure to report as `collection_error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub reason: &'static str,
    pub message: String,
}

impl Failure {
    /// The failure to report for a watcher error, or `None` for errors the watcher
    /// recovers from without a gap that matters: an expired resource version (410)
    /// makes it relist, which starts a new snapshot, and a dropped watch stream is
    /// resumed from its resource version. Failures to list, and permission or
    /// missing-resource failures to start a watch, are reported.
    pub fn classify(err: &watcher::Error) -> Option<Self> {
        use watcher::Error as E;
        let api_status = |err: &kube::Error| match err {
            kube::Error::Api(status) => Some((status.code, status.message.clone())),
            _ => None,
        };
        let (status, message, default) = match err {
            E::InitialListFailed(err) => (
                api_status(err),
                err.to_string(),
                Some(CollectionError::LIST_FAILED),
            ),
            E::WatchStartFailed(err) => (api_status(err), err.to_string(), None),
            E::WatchError(status) => (
                Some((status.code, status.message.clone())),
                status.message.clone(),
                None,
            ),
            E::WatchFailed(_) => return None,
            E::NoResourceVersion => (None, err.to_string(), Some(CollectionError::LIST_FAILED)),
        };
        let (reason, message) = match status {
            Some((403, text)) => (CollectionError::FORBIDDEN, text),
            Some((404, text)) => (CollectionError::NOT_FOUND, text),
            Some((410, _)) => return None,
            Some((_, text)) if default.is_some() => (default?, text),
            _ => (default?, message),
        };
        Some(Self { reason, message })
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason, self.message)
    }
}

/// Maps one collection's watcher events to queued messages.
#[derive(Debug)]
pub struct Mapper {
    collection: Collection,
    limits: Limits,
    /// The snapshot being listed.
    snapshot: Option<Listing>,
    /// The failure reported last, until an event shows the collection works again.
    reported: Option<Failure>,
}

impl Mapper {
    pub fn new(collection: Collection, limits: Limits) -> Self {
        Self {
            collection,
            limits,
            snapshot: None,
            reported: None,
        }
    }

    /// Queues the messages for `event`, observed at `now`.
    pub fn on(&mut self, event: Observed, queue: &mut Queue, now: DateTime<Utc>) {
        let collection = self.collection;
        match event {
            Observed::Init => {
                if self.snapshot.take().is_some_and(|s| s.started) {
                    queue.abandon(collection, "relisted");
                }
                self.snapshot = Some(Listing {
                    id: random_uuid(),
                    count: 0,
                    started: false,
                });
            }
            Observed::InitApply(object) => {
                let Some(id) = self.start(queue) else {
                    // Not in a snapshot: report it like a watch event.
                    return self.on(Observed::Apply(object), queue, now);
                };
                if let Some((_, upsert)) = self.upsert(object, Some(id), now) {
                    if let Some(listing) = self.snapshot.as_mut() {
                        listing.count += 1;
                    }
                    queue.snapshot_message(collection, id, upsert, false);
                }
            }
            Observed::InitDone => {
                if self.start(queue).is_none() {
                    return;
                }
                let Some(listing) = self.snapshot.take() else {
                    return;
                };
                self.reported = None;
                let end = Outgoing::new(&SnapshotEnd {
                    snapshot_id: listing.id,
                    item_count: listing.count,
                    resource_version: None,
                });
                queue.snapshot_message(collection, listing.id, end, true);
            }
            Observed::Apply(object) => {
                self.reported = None;
                if let Some((uid, upsert)) = self.upsert(object, None, now) {
                    queue.watch_event(collection, &uid, upsert);
                }
            }
            Observed::Delete(object) => {
                self.reported = None;
                if let Some((uid, delete)) = self.delete(&object, now) {
                    queue.watch_event(collection, &uid, delete);
                }
            }
            Observed::Error(failure) => {
                if self.snapshot.take().is_some_and(|s| s.started) {
                    queue.abandon(collection, failure.reason);
                }
                if self.reported.as_ref() == Some(&failure) {
                    return;
                }
                let error = Outgoing::new(&CollectionError {
                    collection: collection.as_str().to_owned(),
                    scope: Scope::ALL,
                    reason: failure.reason.to_owned(),
                    message: Some(failure.message.clone()),
                });
                queue.collection_message(collection, error);
                self.reported = Some(failure);
            }
        }
    }

    /// Queues `snapshot_start` for the listing in progress, if not yet done, and returns
    /// its ID. `None` when no listing is in progress.
    fn start(&mut self, queue: &mut Queue) -> Option<Uuid> {
        let collection = self.collection;
        let listing = self.snapshot.as_mut()?;
        if !listing.started {
            listing.started = true;
            let start = Outgoing::new(&SnapshotStart {
                snapshot_id: listing.id,
                collection: collection.as_str().to_owned(),
                scope: Scope::ALL,
            });
            queue.begin_snapshot(collection, listing.id, start);
        }
        Some(listing.id)
    }

    /// The sanitized `upsert` for `object`, without its body when it would exceed the
    /// message limit. `None` (with a warning) when the object lacks its identity.
    fn upsert(
        &self,
        mut object: Value,
        snapshot_id: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Option<(String, Outgoing)> {
        if let Some(root) = object.as_object_mut() {
            let api_version = self.collection.api_version();
            root.insert("apiVersion".into(), api_version.into());
            root.insert("kind".into(), self.collection.kind().into());
        }
        sanitize_object(&mut object);
        let identity = self.identity(&object)?;
        let mut upsert = Upsert {
            snapshot_id,
            collection: self.collection.as_str().to_owned(),
            uid: identity.uid.clone(),
            namespace: identity.namespace,
            name: identity.name,
            resource_version: identity.resource_version,
            observed_at: now,
            object: Some(object),
            truncated: false,
        };
        let mut message = Outgoing::new(&upsert);
        if message.frame_len() > self.limits.max_message_bytes {
            tracing::info!(
                collection = %self.collection,
                namespace = upsert.namespace.as_deref().unwrap_or(""),
                name = %upsert.name,
                bytes = message.frame_len(),
                "object exceeds the message size limit; sending it truncated"
            );
            upsert.object = None;
            upsert.truncated = true;
            message = Outgoing::new(&upsert);
        }
        Some((identity.uid, message))
    }

    fn delete(&self, object: &Value, now: DateTime<Utc>) -> Option<(String, Outgoing)> {
        let identity = self.identity(object)?;
        let delete = Outgoing::new(&Delete {
            collection: self.collection.as_str().to_owned(),
            uid: identity.uid.clone(),
            namespace: identity.namespace,
            name: identity.name,
            resource_version: identity.resource_version,
            observed_at: now,
        });
        Some((identity.uid, delete))
    }

    fn identity(&self, object: &Value) -> Option<Identity> {
        let metadata = object.get("metadata");
        let field = |key: &str| {
            metadata
                .and_then(|m| m.get(key))
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        let (Some(uid), Some(name)) = (field("uid"), field("name")) else {
            tracing::warn!(collection = %self.collection, "an object without a UID or name was skipped");
            return None;
        };
        let namespace = if self.collection.namespaced() {
            Some(field("namespace")?)
        } else {
            None
        };
        Some(Identity {
            uid,
            namespace,
            name,
            resource_version: field("resourceVersion").unwrap_or_default(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct Listing {
    id: Uuid,
    /// Items queued for it.
    count: u64,
    /// Whether its `snapshot_start` was queued.
    started: bool,
}

struct Identity {
    uid: String,
    namespace: Option<String>,
    name: String,
    resource_version: String,
}

fn random_uuid() -> Uuid {
    let mut bytes = [0u8; 16];
    // Snapshot IDs only need to be unique; without randomness fall back to the time.
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = Utc::now().timestamp_nanos_opt().unwrap_or_default();
        bytes[..8].copy_from_slice(&nanos.to_le_bytes());
    }
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const LIMITS: Limits = Limits {
        max_message_bytes: 64 * 1024,
    };

    fn deployment(uid: &str, rv: &str) -> Value {
        json!({
            "metadata": {
                "name": format!("web-{uid}"),
                "namespace": "shop",
                "uid": uid,
                "resourceVersion": rv,
                "managedFields": [{"manager": "kubectl"}],
            },
            "spec": {"template": {"spec": {"containers": [{
                "name": "web",
                "image": "nginx",
                "env": [{"name": "PASSWORD", "value": "hunter2"}],
            }]}}},
        })
    }

    fn drain(queue: &mut Queue) -> Vec<(String, Value)> {
        std::iter::from_fn(|| queue.pop())
            .map(|m| (m.kind.to_owned(), serde_json::from_str(&m.body).unwrap()))
            .collect()
    }

    fn kinds(messages: &[(String, Value)]) -> Vec<&str> {
        messages.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn a_listing_becomes_a_snapshot_and_watch_events_follow() {
        let mut mapper = Mapper::new(Collection::Deployments, LIMITS);
        let mut q = Queue::default();
        let now = Utc::now();
        mapper.on(Observed::Init, &mut q, now);
        mapper.on(Observed::InitApply(deployment("a", "10")), &mut q, now);
        mapper.on(Observed::InitApply(deployment("b", "11")), &mut q, now);
        mapper.on(Observed::InitDone, &mut q, now);
        mapper.on(Observed::Apply(deployment("a", "12")), &mut q, now);
        mapper.on(Observed::Delete(deployment("b", "13")), &mut q, now);
        let sent = drain(&mut q);
        assert_eq!(
            kinds(&sent),
            [
                "snapshot_start",
                "upsert",
                "upsert",
                "snapshot_end",
                "upsert",
                "delete"
            ]
        );
        let snapshot_id = sent[0].1["snapshot_id"].clone();
        assert_eq!(sent[0].1["collection"], "apps/v1/deployments");
        assert_eq!(sent[0].1["scope"], json!({"namespace": null}));
        assert_eq!(sent[1].1["snapshot_id"], snapshot_id);
        assert_eq!(sent[1].1["uid"], "a");
        assert_eq!(sent[1].1["namespace"], "shop");
        assert_eq!(sent[1].1["resource_version"], "10");
        assert_eq!(sent[1].1["object"]["kind"], "Deployment");
        assert_eq!(sent[1].1["object"]["apiVersion"], "apps/v1");
        assert!(
            sent[1].1["object"]["metadata"]
                .get("managedFields")
                .is_none()
        );
        assert_eq!(
            sent[1].1["object"]["spec"]["template"]["spec"]["containers"][0]["env"],
            json!([{"name": "PASSWORD"}])
        );
        assert_eq!(sent[3].1["item_count"], 2);
        assert_eq!(sent[3].1["snapshot_id"], snapshot_id);
        assert!(sent[4].1.get("snapshot_id").is_none());
        assert_eq!(sent[5].1["uid"], "b");
        assert_eq!(sent[5].1["resource_version"], "13");
    }

    #[test]
    fn a_relist_aborts_the_unfinished_snapshot() {
        let mut mapper = Mapper::new(Collection::Nodes, LIMITS);
        let mut q = Queue::default();
        let now = Utc::now();
        let node = json!({"metadata": {"name": "n1", "uid": "u1", "resourceVersion": "1"}});
        mapper.on(Observed::Init, &mut q, now);
        mapper.on(Observed::InitApply(node.clone()), &mut q, now);
        let first = drain(&mut q);
        mapper.on(Observed::Init, &mut q, now);
        mapper.on(Observed::InitApply(node), &mut q, now);
        mapper.on(Observed::InitDone, &mut q, now);
        let second = drain(&mut q);
        assert_eq!(
            kinds(&second),
            ["snapshot_abort", "snapshot_start", "upsert", "snapshot_end"]
        );
        assert_eq!(second[0].1["snapshot_id"], first[0].1["snapshot_id"]);
        assert_ne!(second[1].1["snapshot_id"], first[0].1["snapshot_id"]);
        assert_eq!(second[3].1["item_count"], 1);
        // Cluster-scoped objects have no namespace.
        assert_eq!(second[2].1["namespace"], Value::Null);
    }

    #[test]
    fn errors_abort_the_snapshot_and_are_reported_once() {
        let mut mapper = Mapper::new(Collection::Nodes, LIMITS);
        let mut q = Queue::default();
        let now = Utc::now();
        let forbidden = Failure {
            reason: CollectionError::FORBIDDEN,
            message: "nodes is forbidden".into(),
        };
        mapper.on(Observed::Init, &mut q, now);
        mapper.on(
            Observed::InitApply(json!({"metadata": {"name": "n1", "uid": "u1"}})),
            &mut q,
            now,
        );
        drain(&mut q);
        mapper.on(Observed::Error(forbidden.clone()), &mut q, now);
        // A listing that fails before its first object sends nothing, and the repeated
        // failure is not reported again.
        mapper.on(Observed::Init, &mut q, now);
        mapper.on(Observed::Error(forbidden.clone()), &mut q, now);
        let sent = drain(&mut q);
        assert_eq!(kinds(&sent), ["snapshot_abort", "collection_error"]);
        assert_eq!(sent[0].1["reason"], "forbidden");
        assert_eq!(
            sent[1].1,
            json!({
                "collection": "v1/nodes",
                "scope": {"namespace": null},
                "reason": "forbidden",
                "message": "nodes is forbidden",
            })
        );
        // After a completed snapshot the same failure is reported again.
        mapper.on(Observed::Init, &mut q, now);
        mapper.on(Observed::InitDone, &mut q, now);
        mapper.on(Observed::Error(forbidden), &mut q, now);
        assert_eq!(
            kinds(&drain(&mut q)),
            ["snapshot_start", "snapshot_end", "collection_error"]
        );
    }

    #[test]
    fn oversize_objects_are_sent_truncated() {
        let limits = Limits {
            max_message_bytes: 1024,
        };
        let mut mapper = Mapper::new(Collection::Deployments, limits);
        let mut q = Queue::default();
        let mut big = deployment("a", "1");
        big["metadata"]["labels"] = json!({"padding": "x".repeat(2000)});
        mapper.on(Observed::Apply(big), &mut q, Utc::now());
        let message = q.pop().unwrap();
        assert!(message.frame_len() <= 1024);
        let body: Value = serde_json::from_str(&message.body).unwrap();
        assert_eq!(body["truncated"], true);
        assert_eq!(body["object"], Value::Null);
        assert_eq!(body["uid"], "a");
    }

    #[test]
    fn objects_without_an_identity_are_skipped_and_not_counted() {
        let mut mapper = Mapper::new(Collection::Deployments, LIMITS);
        let mut q = Queue::default();
        let now = Utc::now();
        mapper.on(Observed::Init, &mut q, now);
        mapper.on(
            Observed::InitApply(json!({"metadata": {"name": "x"}})),
            &mut q,
            now,
        );
        mapper.on(
            Observed::InitApply(json!({"metadata": {"name": "x", "uid": "u"}})),
            &mut q,
            now,
        );
        mapper.on(Observed::InitDone, &mut q, now);
        let sent = drain(&mut q);
        assert_eq!(kinds(&sent), ["snapshot_start", "snapshot_end"]);
        assert_eq!(sent[1].1["item_count"], 0);
    }

    #[test]
    fn watcher_errors_are_classified() {
        let status = |code: u16, message: &str| {
            let mut status = kube::core::Status::failure(message, "");
            status.code = code;
            Box::new(status)
        };
        let api = |code, message| kube::Error::Api(status(code, message));
        let classify = |err| Failure::classify(&err);
        assert_eq!(
            classify(watcher::Error::InitialListFailed(api(
                403,
                "nodes is forbidden"
            ))),
            Some(Failure {
                reason: "forbidden",
                message: "nodes is forbidden".into()
            })
        );
        assert_eq!(
            classify(watcher::Error::InitialListFailed(api(500, "boom")))
                .unwrap()
                .reason,
            "list_failed"
        );
        assert_eq!(
            classify(watcher::Error::WatchStartFailed(api(403, "no")))
                .unwrap()
                .reason,
            "forbidden"
        );
        assert_eq!(
            classify(watcher::Error::WatchStartFailed(api(503, "busy"))),
            None
        );
        assert_eq!(
            classify(watcher::Error::WatchError(status(410, "gone"))),
            None
        );
        assert_eq!(
            classify(watcher::Error::NoResourceVersion).unwrap().reason,
            "list_failed"
        );
    }
}
