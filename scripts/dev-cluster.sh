#!/usr/bin/env bash
# Local Kubernetes cluster for developing the Vanguard Nexus agent.
#
# Usage: scripts/dev-cluster.sh up|load|down
#
#   up    create the kind cluster `vn-dev` if it does not exist, build the agent image,
#         and load it into the cluster
#   load  rebuild the agent image, load it again, and restart the agent Deployment if it
#         is installed
#   down  delete the kind cluster
#
# Needs docker, kind (`go install sigs.k8s.io/kind@latest`), and kubectl. Every kubectl
# call uses the `kind-vn-dev` context, so other kube contexts are never touched.
# See docs/development.md, "Run the agent".

set -euo pipefail

CLUSTER=vn-dev
CONTEXT="kind-${CLUSTER}"
IMAGE=ghcr.io/vanguard-enterprise/vn-agent:latest
NAMESPACE=vn-agent

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  sed -n '4,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

need() {
  local tool
  for tool in "$@"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "error: $tool is not installed" >&2
      if [[ $tool == kind ]]; then
        echo "install it with: go install sigs.k8s.io/kind@latest" >&2
      fi
      exit 1
    fi
  done
}

kc() {
  kubectl --context "$CONTEXT" "$@"
}

cluster_exists() {
  kind get clusters 2>/dev/null | grep -qx "$CLUSTER"
}

require_cluster() {
  if ! cluster_exists; then
    echo "error: kind cluster $CLUSTER does not exist; run: $0 up" >&2
    exit 1
  fi
}

build_image() {
  echo "Building $IMAGE"
  docker build --target agent -t "$IMAGE" "$ROOT"
}

load_image() {
  echo "Loading $IMAGE into kind cluster $CLUSTER"
  kind load docker-image "$IMAGE" --name "$CLUSTER"
}

cmd_up() {
  need docker kind kubectl
  if cluster_exists; then
    echo "kind cluster $CLUSTER already exists"
  else
    # kind switches the current kube context to the new cluster. Switch it back, since
    # this script always passes --context and should not change what plain kubectl uses.
    local previous
    previous="$(kubectl config current-context 2>/dev/null || true)"
    kind create cluster --name "$CLUSTER" --wait 120s
    if [[ -n $previous && $previous != "$CONTEXT" ]]; then
      kubectl config use-context "$previous" >/dev/null
    fi
  fi
  build_image
  load_image
  kc cluster-info
  cat <<MSG

Cluster $CLUSTER is ready (kube context $CONTEXT). To install the agent:

  kubectl --context $CONTEXT create namespace $NAMESPACE
  kubectl --context $CONTEXT -n $NAMESPACE create secret generic vn-agent-enrollment \\
    --from-literal=server-url=http://<host address>:8080 --from-literal=token=<token>
  kubectl --context $CONTEXT apply -f $ROOT/deploy/kubernetes/vn-agent.yaml

Use the host's LAN or VPN address (for example its NetBird IP) as the server URL, with
the server bound to 0.0.0.0. See docs/development.md, "Run the agent".
MSG
}

cmd_load() {
  need docker kind kubectl
  require_cluster
  build_image
  load_image
  # --ignore-not-found prints nothing for a missing Deployment, so any other failure
  # (an unreachable cluster, a missing kube context) still stops the script.
  local deployment
  deployment=$(kc -n "$NAMESPACE" get deployment vn-agent --ignore-not-found -o name)
  if [[ -n $deployment ]]; then
    kc -n "$NAMESPACE" rollout restart deployment/vn-agent
    kc -n "$NAMESPACE" rollout status deployment/vn-agent --timeout 120s
  else
    echo "deployment/vn-agent is not installed in namespace $NAMESPACE; nothing to restart"
  fi
}

cmd_down() {
  need kind
  if cluster_exists; then
    kind delete cluster --name "$CLUSTER"
  else
    echo "kind cluster $CLUSTER does not exist"
  fi
}

case "${1:-}" in
  up) cmd_up ;;
  load) cmd_load ;;
  down) cmd_down ;;
  -h | --help | help) usage ;;
  *)
    usage >&2
    exit 2
    ;;
esac
