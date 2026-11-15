//! What the agent reports about its cluster.

use anyhow::Context;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::Api;

/// The cluster facts sent in `hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterInfo {
    /// The UID of the `kube-system` namespace, which identifies the cluster.
    pub fingerprint: String,
    /// The API server's `gitVersion`, such as `v1.35.0`, when it could be read.
    pub kubernetes_version: Option<String>,
}

/// A Kubernetes client from the in-cluster configuration, falling back to a kubeconfig
/// (`KUBECONFIG` or `~/.kube/config`) when running on a development host.
pub async fn client() -> anyhow::Result<kube::Client> {
    // `Config::infer` prefers a kubeconfig. In a pod the service account must win, even
    // if the image happens to contain a kubeconfig.
    let config = match kube::Config::incluster() {
        Ok(config) => config,
        Err(in_cluster) => {
            tracing::debug!(error = %in_cluster, "not in a cluster; using the kubeconfig");
            kube::Config::infer()
                .await
                .context("failed to configure a Kubernetes client (in-cluster or kubeconfig)")?
        }
    };
    kube::Client::try_from(config).context("failed to build the Kubernetes client")
}

/// The cluster fingerprint: the UID of the `kube-system` namespace.
pub async fn fingerprint(client: &kube::Client) -> anyhow::Result<String> {
    let namespace = Api::<Namespace>::all(client.clone())
        .get("kube-system")
        .await
        .context("failed to read the kube-system namespace for the cluster fingerprint")?;
    namespace
        .metadata
        .uid
        .context("the kube-system namespace has no UID")
}

/// The API server version from `/version`, or `None` (with a warning) when it cannot be
/// read: the server then treats resource versions as opaque.
pub async fn kubernetes_version(client: &kube::Client) -> Option<String> {
    match client.apiserver_version().await {
        Ok(info) => Some(info.git_version),
        Err(err) => {
            tracing::warn!(error = %err, "failed to read the Kubernetes API server version");
            None
        }
    }
}

/// Reads [`ClusterInfo`].
pub async fn info(client: &kube::Client) -> anyhow::Result<ClusterInfo> {
    Ok(ClusterInfo {
        fingerprint: fingerprint(client).await?,
        kubernetes_version: kubernetes_version(client).await,
    })
}
