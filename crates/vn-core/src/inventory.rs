//! Cluster inventory: the collections agents report, object sanitization shared by the
//! agent and the server, and the inventory API types.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

/// A resource type the agent collects. Version 1 of the protocol collects these five,
/// in all namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Collection {
    Nodes,
    Namespaces,
    Deployments,
    StatefulSets,
    DaemonSets,
}

impl Collection {
    /// Every collection, in the order the API lists them.
    pub const ALL: [Collection; 5] = [
        Collection::Nodes,
        Collection::Namespaces,
        Collection::Deployments,
        Collection::StatefulSets,
        Collection::DaemonSets,
    ];

    /// The wire and API name, `<group>/<version>/<plural>` (`v1/<plural>` for the core
    /// group).
    pub const fn as_str(self) -> &'static str {
        match self {
            Collection::Nodes => "v1/nodes",
            Collection::Namespaces => "v1/namespaces",
            Collection::Deployments => "apps/v1/deployments",
            Collection::StatefulSets => "apps/v1/statefulsets",
            Collection::DaemonSets => "apps/v1/daemonsets",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == value)
    }

    /// The Kubernetes kind of the collection's objects.
    pub const fn kind(self) -> &'static str {
        match self {
            Collection::Nodes => "Node",
            Collection::Namespaces => "Namespace",
            Collection::Deployments => "Deployment",
            Collection::StatefulSets => "StatefulSet",
            Collection::DaemonSets => "DaemonSet",
        }
    }

    /// The objects' `apiVersion`.
    pub const fn api_version(self) -> &'static str {
        match self {
            Collection::Nodes | Collection::Namespaces => "v1",
            _ => "apps/v1",
        }
    }

    /// Whether the collection's objects live in a namespace.
    pub const fn namespaced(self) -> bool {
        !matches!(self, Collection::Nodes | Collection::Namespaces)
    }
}

impl fmt::Display for Collection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Collection {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Collection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Collection::parse(&value)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown collection `{value}`")))
    }
}

/// The annotation `kubectl apply` stores the full applied object in. It can hold
/// anything the object held, including environment values, so it is never sent.
pub const LAST_APPLIED_ANNOTATION: &str = "kubectl.kubernetes.io/last-applied-configuration";

/// Removes what must not leave the cluster, and bulky fields no view uses, from a
/// Kubernetes object in JSON form:
///
/// - `metadata.managedFields` and the [`LAST_APPLIED_ANNOTATION`] annotation;
/// - the `value` of every environment variable in a pod template (names and
///   `valueFrom` references stay, so the source of a value is still visible);
/// - `data`, `stringData`, and `binaryData`, which only Secrets and ConfigMaps have and
///   which are never collected;
/// - a node's `status.images`, the list of every image cached on it.
///
/// The agent sanitizes before sending, and the server sanitizes again before storing,
/// so an older or modified agent cannot store excluded fields.
pub fn sanitize_object(object: &mut Value) {
    let Some(root) = object.as_object_mut() else {
        return;
    };
    for key in ["data", "stringData", "binaryData"] {
        root.remove(key);
    }
    if let Some(metadata) = root.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.remove("managedFields");
        if let Some(annotations) = metadata
            .get_mut("annotations")
            .and_then(Value::as_object_mut)
        {
            annotations.remove(LAST_APPLIED_ANNOTATION);
        }
    }
    if root.get("kind").and_then(Value::as_str) == Some("Node")
        && let Some(status) = root.get_mut("status").and_then(Value::as_object_mut)
    {
        status.remove("images");
    }
    if let Some(pod_spec) = root
        .get_mut("spec")
        .and_then(|spec| spec.get_mut("template"))
        .and_then(|template| template.get_mut("spec"))
        .and_then(Value::as_object_mut)
    {
        strip_env_values(pod_spec);
    }
}

fn strip_env_values(pod_spec: &mut Map<String, Value>) {
    for list in ["containers", "initContainers", "ephemeralContainers"] {
        let Some(containers) = pod_spec.get_mut(list).and_then(Value::as_array_mut) else {
            continue;
        };
        for container in containers {
            let Some(env) = container.get_mut("env").and_then(Value::as_array_mut) else {
                continue;
            };
            for var in env {
                if let Some(var) = var.as_object_mut() {
                    var.remove("value");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// `GET /api/v1/projects/{slug}/clusters`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClusterList {
    pub clusters: Vec<Cluster>,
}

/// A registered cluster with its agent, connection, and inventory status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cluster {
    pub id: Uuid,
    pub project_id: Uuid,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    /// The source the cluster's inventory comes from.
    pub source_id: Uuid,
    /// The source's active agent, or its most recent one when all are revoked.
    pub agent: Option<ClusterAgent>,
    pub connection: ClusterConnection,
    pub inventory: ClusterInventory,
    /// One entry per collection, in [`Collection::ALL`] order.
    pub collections: Vec<CollectionStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterAgent {
    pub id: Uuid,
    pub status: crate::AgentStatus,
    pub agent_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Connected,
    Disconnected,
    NeverConnected,
}

/// The agent's connection, from its most recent connection record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterConnection {
    pub state: ConnectionState,
    /// When the open connection was accepted. `null` unless connected.
    pub connected_since: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub kubernetes_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterInventory {
    /// True whenever the connection is not `connected`.
    pub stale: bool,
    /// Server receive time of the latest accepted observation.
    pub last_observed_at: Option<DateTime<Utc>>,
    /// Resources present, by collection name.
    pub counts: std::collections::BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionState {
    /// A snapshot has completed and no error was reported since.
    Synced,
    /// A snapshot is in progress on the open connection.
    Syncing,
    /// The agent reported an error since the last completed snapshot.
    Error,
    NeverSynced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionStatus {
    pub collection: Collection,
    pub state: CollectionState,
    pub last_snapshot_completed_at: Option<DateTime<Utc>>,
    pub resource_count: i64,
    pub error: Option<CollectionErrorInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionErrorInfo {
    /// Machine-readable, such as `forbidden`.
    pub reason: String,
    pub message: String,
    /// Server receive time of the report.
    pub observed_at: DateTime<Utc>,
}

/// `GET /api/v1/projects/{slug}/clusters/{cluster_id}/resources`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceList {
    pub resources: Vec<Resource>,
    /// Pass as `cursor` for the next page. `null` on the last page.
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    Present,
    Deleted,
}

/// One observed Kubernetes resource, identified by its UID within the cluster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub id: Uuid,
    pub collection: Collection,
    pub kind: String,
    pub uid: String,
    pub namespace: Option<String>,
    pub name: String,
    pub resource_version: String,
    pub state: ResourceState,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    /// The object was over the message size limit, so only its identity is stored.
    pub truncated: bool,
    pub summary: ResourceSummary,
}

/// `GET /api/v1/projects/{slug}/clusters/{cluster_id}/resources/{resource_id}`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceDetail {
    #[serde(flatten)]
    pub resource: Resource,
    /// The sanitized object. For a truncated object, only its identity.
    pub object: Value,
}

/// Kind-specific columns computed from the stored object. Any field is `null` when the
/// object does not have it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceSummary {
    Node(NodeSummary),
    Namespace(NamespaceSummary),
    /// Deployments and StatefulSets.
    Replicated(ReplicatedSummary),
    DaemonSet(DaemonSetSummary),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSummary {
    pub ready: Option<bool>,
    pub roles: Option<Vec<String>>,
    pub kubelet_version: Option<String>,
    pub os_image: Option<String>,
    pub internal_ip: Option<String>,
    pub cpu: Option<String>,
    pub memory: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSummary {
    pub phase: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicatedSummary {
    pub replicas: Option<i64>,
    pub ready_replicas: Option<i64>,
    pub images: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSetSummary {
    pub desired: Option<i64>,
    pub ready: Option<i64>,
    pub images: Option<Vec<String>>,
}

/// Node roles from `node-role.kubernetes.io/<role>` labels.
const NODE_ROLE_PREFIX: &str = "node-role.kubernetes.io/";

impl ResourceSummary {
    /// The summary of `object` in `collection`, or of a missing object (all `null`).
    pub fn compute(collection: Collection, object: Option<&Value>) -> Self {
        let empty = Value::Null;
        let object = object.unwrap_or(&empty);
        let present = !object.is_null();
        let at = |path: &[&str]| path.iter().try_fold(object, |v, key| v.get(key));
        let string = |path: &[&str]| at(path).and_then(Value::as_str).map(str::to_owned);
        let int = |path: &[&str]| at(path).and_then(Value::as_i64);
        // Kubernetes omits zero counts from status, so a present object reads 0.
        let count = |path: &[&str]| int(path).or(present.then_some(0));
        match collection {
            Collection::Nodes => {
                let named = |list: &[&str], key: &str, name: &str, field: &str| {
                    at(list)?
                        .as_array()?
                        .iter()
                        .find(|item| item.get(key).and_then(Value::as_str) == Some(name))?
                        .get(field)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                };
                let roles = at(&["metadata", "labels"])
                    .and_then(Value::as_object)
                    .map(|labels| {
                        let mut roles: Vec<String> = labels
                            .keys()
                            .filter_map(|key| key.strip_prefix(NODE_ROLE_PREFIX))
                            .filter(|role| !role.is_empty())
                            .map(str::to_owned)
                            .collect();
                        roles.sort();
                        roles
                    })
                    .or(present.then(Vec::new));
                ResourceSummary::Node(NodeSummary {
                    ready: named(&["status", "conditions"], "type", "Ready", "status")
                        .map(|status| status == "True"),
                    roles,
                    kubelet_version: string(&["status", "nodeInfo", "kubeletVersion"]),
                    os_image: string(&["status", "nodeInfo", "osImage"]),
                    internal_ip: named(&["status", "addresses"], "type", "InternalIP", "address"),
                    cpu: string(&["status", "capacity", "cpu"]),
                    memory: string(&["status", "capacity", "memory"]),
                })
            }
            Collection::Namespaces => ResourceSummary::Namespace(NamespaceSummary {
                phase: string(&["status", "phase"]),
            }),
            Collection::Deployments | Collection::StatefulSets => {
                ResourceSummary::Replicated(ReplicatedSummary {
                    replicas: int(&["spec", "replicas"]),
                    ready_replicas: count(&["status", "readyReplicas"]),
                    images: images(object),
                })
            }
            Collection::DaemonSets => ResourceSummary::DaemonSet(DaemonSetSummary {
                desired: count(&["status", "desiredNumberScheduled"]),
                ready: count(&["status", "numberReady"]),
                images: images(object),
            }),
        }
    }
}

/// Container images of a pod template, in order.
fn images(object: &Value) -> Option<Vec<String>> {
    let containers = object
        .get("spec")?
        .get("template")?
        .get("spec")?
        .get("containers")?
        .as_array()?;
    Some(
        containers
            .iter()
            .filter_map(|c| c.get("image").and_then(Value::as_str))
            .map(str::to_owned)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn collections_round_trip() {
        for collection in Collection::ALL {
            assert_eq!(Collection::parse(collection.as_str()), Some(collection));
            let json = serde_json::to_value(collection).unwrap();
            assert_eq!(
                serde_json::from_value::<Collection>(json).unwrap(),
                collection
            );
        }
        assert_eq!(Collection::parse("v1/secrets"), None);
        assert!(!Collection::Nodes.namespaced());
        assert!(Collection::DaemonSets.namespaced());
    }

    #[test]
    fn sanitizing_removes_excluded_fields() {
        let mut object = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "web",
                "managedFields": [{"manager": "kubectl"}],
                "annotations": {
                    LAST_APPLIED_ANNOTATION: "{\"secret\":true}",
                    "deployment.kubernetes.io/revision": "3",
                },
            },
            "spec": {"template": {"spec": {
                "containers": [{
                    "name": "web",
                    "image": "nginx:1.27",
                    "env": [
                        {"name": "PASSWORD", "value": "hunter2"},
                        {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}},
                    ],
                }],
                "initContainers": [{"name": "init", "env": [{"name": "A", "value": "b"}]}],
            }}},
            "data": {"leak": "yes"},
        });
        sanitize_object(&mut object);
        assert_eq!(
            object,
            json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "web",
                    "annotations": {"deployment.kubernetes.io/revision": "3"},
                },
                "spec": {"template": {"spec": {
                    "containers": [{
                        "name": "web",
                        "image": "nginx:1.27",
                        "env": [
                            {"name": "PASSWORD"},
                            {"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}},
                        ],
                    }],
                    "initContainers": [{"name": "init", "env": [{"name": "A"}]}],
                }}},
            })
        );
        let mut node =
            json!({"kind": "Node", "status": {"images": [{"names": ["a"]}], "phase": "x"}});
        sanitize_object(&mut node);
        assert_eq!(node, json!({"kind": "Node", "status": {"phase": "x"}}));
        let mut not_an_object = json!([1, 2]);
        sanitize_object(&mut not_an_object);
        assert_eq!(not_an_object, json!([1, 2]));
    }

    #[test]
    fn node_summaries() {
        let node = json!({
            "metadata": {"labels": {
                "node-role.kubernetes.io/control-plane": "",
                "node-role.kubernetes.io/": "",
                "kubernetes.io/os": "linux",
            }},
            "status": {
                "conditions": [
                    {"type": "MemoryPressure", "status": "False"},
                    {"type": "Ready", "status": "True"},
                ],
                "nodeInfo": {"kubeletVersion": "v1.37.0", "osImage": "Debian"},
                "addresses": [
                    {"type": "Hostname", "address": "n1"},
                    {"type": "InternalIP", "address": "10.0.0.2"},
                ],
                "capacity": {"cpu": "8", "memory": "16Gi"},
            },
        });
        assert_eq!(
            ResourceSummary::compute(Collection::Nodes, Some(&node)),
            ResourceSummary::Node(NodeSummary {
                ready: Some(true),
                roles: Some(vec!["control-plane".into()]),
                kubelet_version: Some("v1.37.0".into()),
                os_image: Some("Debian".into()),
                internal_ip: Some("10.0.0.2".into()),
                cpu: Some("8".into()),
                memory: Some("16Gi".into()),
            })
        );
        assert_eq!(
            ResourceSummary::compute(Collection::Nodes, None),
            ResourceSummary::Node(NodeSummary::default())
        );
    }

    #[test]
    fn workload_summaries() {
        let deployment = json!({
            "spec": {"replicas": 3, "template": {"spec": {"containers": [
                {"image": "nginx:1.27"}, {"image": "envoy:1"},
            ]}}},
            "status": {"readyReplicas": 2},
        });
        assert_eq!(
            ResourceSummary::compute(Collection::Deployments, Some(&deployment)),
            ResourceSummary::Replicated(ReplicatedSummary {
                replicas: Some(3),
                ready_replicas: Some(2),
                images: Some(vec!["nginx:1.27".into(), "envoy:1".into()]),
            })
        );
        let scaled_down = json!({"spec": {"replicas": 0}, "status": {}});
        assert_eq!(
            ResourceSummary::compute(Collection::StatefulSets, Some(&scaled_down)),
            ResourceSummary::Replicated(ReplicatedSummary {
                replicas: Some(0),
                ready_replicas: Some(0),
                images: None,
            })
        );
        let daemonset = json!({"status": {"desiredNumberScheduled": 3, "numberReady": 1}});
        assert_eq!(
            ResourceSummary::compute(Collection::DaemonSets, Some(&daemonset)),
            ResourceSummary::DaemonSet(DaemonSetSummary {
                desired: Some(3),
                ready: Some(1),
                images: None,
            })
        );
        let namespace = json!({"status": {"phase": "Active"}});
        assert_eq!(
            serde_json::to_value(ResourceSummary::compute(
                Collection::Namespaces,
                Some(&namespace)
            ))
            .unwrap(),
            json!({"phase": "Active"})
        );
    }

    #[test]
    fn summaries_deserialize_to_their_variant() {
        for summary in [
            ResourceSummary::Namespace(NamespaceSummary {
                phase: Some("Active".into()),
            }),
            ResourceSummary::Replicated(ReplicatedSummary::default()),
            ResourceSummary::DaemonSet(DaemonSetSummary::default()),
            ResourceSummary::Node(NodeSummary::default()),
        ] {
            let json = serde_json::to_value(&summary).unwrap();
            assert_eq!(
                serde_json::from_value::<ResourceSummary>(json).unwrap(),
                summary
            );
        }
    }
}
