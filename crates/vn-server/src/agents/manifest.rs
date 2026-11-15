//! Agent install manifests, served without a session so `kubectl apply -f <url>` works.

use axum::http::header;
use axum::response::IntoResponse;

/// The Kubernetes install manifest, `deploy/kubernetes/vn-agent.yaml`, embedded at
/// compile time.
pub(crate) const KUBERNETES: &str = include_str!("../../../../deploy/kubernetes/vn-agent.yaml");

/// `GET /api/v1/agent/manifests/kubernetes.yaml` (unauthenticated)
pub(crate) async fn kubernetes() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/yaml")], KUBERNETES)
}
