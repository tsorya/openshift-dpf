#!/bin/bash
# argus-gtc-demo.sh - Deploy/cleanup the Argus GTC demo stack
#
# Prerequisites:
#   KATA_ENABLED=true KATA_SRIOV_PF_INDEX=0
#   make enable-ovn-injector && make enable-kata && make enable-argus
#
# Usage:
#   make deploy-argus-gtc-demo
#   make cleanup-argus-gtc-demo

set -e
set -o pipefail

source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"
source "$(dirname "${BASH_SOURCE[0]}")/cluster.sh"
source "$(dirname "${BASH_SOURCE[0]}")/verify.sh"

DEMO_NAMESPACE="argus-gtc-demo"
DEMO_MANIFESTS_DIR="${MANIFESTS_DIR}/argus-gtc-demo"
GENERATED_DEMO_DIR="${GENERATED_DIR}/argus-gtc-demo"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_SRC_DIR="${REPO_ROOT}/demo/argus-gtc"
MANIFESTS_DIR=${MANIFESTS_DIR:-"${REPO_ROOT}/manifests"}
GENERATED_DIR=${GENERATED_DIR:-"${MANIFESTS_DIR}/generated"}

function kata_worker_role() {
    if oc get mcp worker-dpu &>/dev/null; then
        echo "worker-dpu"
    else
        echo "worker"
    fi
}

function require_demo_prereqs() {
    if [ "${KATA_ENABLED}" != "true" ]; then
        log "ERROR" "KATA_ENABLED must be true for the Argus GTC demo"
        exit 1
    fi
    if [ "${KATA_SRIOV_PF_INDEX}" != "0" ]; then
        log "ERROR" "Argus GTC demo requires KATA_SRIOV_PF_INDEX=0"
        exit 1
    fi
    if ! oc get runtimeclass "${KATA_RUNTIME_CLASS}" &>/dev/null; then
        log "ERROR" "RuntimeClass ${KATA_RUNTIME_CLASS} not found. Run make enable-kata first."
        exit 1
    fi
    if ! ensure_hosted_kubeconfig; then
        log "ERROR" "Hosted cluster kubeconfig is required for Argus status and log collection"
        exit 1
    fi
    if ! KUBECONFIG="${HOSTED_KUBECONFIG}" oc get pods -n dpf-operator-system 2>/dev/null | grep -q doca-argus; then
        log "ERROR" "DOCA Argus pods not found on hosted cluster. Run make enable-argus first."
        exit 1
    fi
}

function remove_argus_log_cleaner() {
    log "INFO" "Removing destructive Argus log-cleaner DaemonSet from hosted cluster"
    KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete daemonset argus-log-cleaner -n dpf-operator-system --ignore-not-found
}

function build_demo_image() {
    local image="${ARGUS_GTC_SERVER_IMAGE}"
    log "INFO" "Building demo server image ${image}"
    if command -v podman &>/dev/null; then
        podman build -t "${image}" "${DEMO_SRC_DIR}"
    elif command -v docker &>/dev/null; then
        docker build -t "${image}" "${DEMO_SRC_DIR}"
    else
        log "ERROR" "podman or docker is required to build ${image}"
        exit 1
    fi
}

function maybe_push_demo_image() {
    local image="${ARGUS_GTC_SERVER_IMAGE}"
    if [ "${ARGUS_GTC_PUSH_IMAGE:-true}" != "true" ]; then
        return 0
    fi
    local registry route_host token dest
    registry=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null || true)
    if [ -z "${registry}" ]; then
        log "WARN" "OpenShift internal registry route not found; ensure ${image} is pullable by the cluster"
        return 0
    fi
    token=$(oc whoami -t)
    dest="${registry}/argus-gtc-demo/argus-gtc:latest"
    log "INFO" "Pushing demo image to ${dest}"
    if command -v podman &>/dev/null; then
        podman tag "${image}" "${dest}"
        podman login "${registry}" -u "$(oc whoami)" -p "${token}" --tls-verify=false
        podman push "${dest}" --tls-verify=false
    else
        docker tag "${image}" "${dest}"
        echo "${token}" | docker login "${registry}" -u "$(oc whoami)" --password-stdin
        docker push "${dest}"
    fi
    export ARGUS_GTC_SERVER_IMAGE="${dest}"
}

function render_demo_manifests() {
    local worker_role ingest_token server_url
    worker_role=$(kata_worker_role)
    ingest_token="${ARGUS_GTC_INGEST_TOKEN:-$(openssl rand -hex 16)}"
    mkdir -p "${GENERATED_DEMO_DIR}"

    for manifest in "${DEMO_MANIFESTS_DIR}"/*.yaml; do
        local base out
        base=$(basename "${manifest}")
        out="${GENERATED_DEMO_DIR}/${base}"
        update_file_multi_replace \
            "${manifest}" "${out}" \
            "<WORKER_ROLE>" "${worker_role}" \
            "<KATA_RUNTIME_CLASS>" "${KATA_RUNTIME_CLASS}" \
            "<ARGUS_GTC_DEMO_IMAGE>" "${ARGUS_GTC_DEMO_IMAGE}" \
            "<ARGUS_GTC_SERVER_IMAGE>" "${ARGUS_GTC_SERVER_IMAGE}" \
            "<ARGUS_GTC_INGEST_TOKEN>" "${ingest_token}" \
            "<ARGUS_GTC_SERVER_URL>" "${server_url:-http://argus-gtc-demo.${DEMO_NAMESPACE}.svc:8080}"
        log "INFO" "Rendered ${out}"
    done
    echo "${ingest_token}" > "${GENERATED_DEMO_DIR}/.ingest-token"
}

function create_hosted_kubeconfig_secret() {
    oc create namespace "${DEMO_NAMESPACE}" --dry-run=client -o yaml | oc apply -f -
    oc -n "${DEMO_NAMESPACE}" create secret generic argus-gtc-hosted-kubeconfig \
        --from-file=kubeconfig="${HOSTED_KUBECONFIG}" \
        --dry-run=client -o yaml | oc apply -f -
}

function wait_for_demo_ready() {
    log "INFO" "Waiting for demo server pod..."
    retry 30 10 oc -n "${DEMO_NAMESPACE}" rollout status deploy/argus-gtc-demo --timeout=120s
    retry 30 10 oc -n "${DEMO_NAMESPACE}" rollout status deploy/invisible-vm --timeout=300s
}

function deploy_argus_gtc_demo() {
    get_kubeconfig
    require_demo_prereqs
    remove_argus_log_cleaner

    if [ "${ARGUS_GTC_BUILD_IMAGE:-true}" = "true" ]; then
        build_demo_image
        maybe_push_demo_image
    fi

    render_demo_manifests
    create_hosted_kubeconfig_secret

    log "INFO" "Applying management-cluster demo manifests"
    apply_manifest "${GENERATED_DEMO_DIR}/00-namespace.yaml" "true"
    apply_manifest "${GENERATED_DEMO_DIR}/01-rbac.yaml" "true"
    apply_manifest "${GENERATED_DEMO_DIR}/02-networkpolicy.yaml" "true"
    apply_manifest "${GENERATED_DEMO_DIR}/03-sink.yaml" "true"
    apply_manifest "${GENERATED_DEMO_DIR}/04-workload.yaml" "true"

    local ingest_token
    ingest_token=$(cat "${GENERATED_DEMO_DIR}/.ingest-token")
    oc -n "${DEMO_NAMESPACE}" create secret generic argus-gtc-ingest-token \
        --from-literal=token="${ingest_token}" \
        --dry-run=client -o yaml | oc apply -f -

    apply_manifest "${GENERATED_DEMO_DIR}/05-demo-server.yaml" "true"

    wait_for_demo_ready

    local route server_url
    route=$(oc -n "${DEMO_NAMESPACE}" get route argus-gtc-demo -o jsonpath='{.spec.host}' 2>/dev/null || true)
    if [ -n "${route}" ]; then
        server_url="https://${route}"
        log "INFO" "Demo UI: https://${route}"
    else
        server_url="http://argus-gtc-demo.${DEMO_NAMESPACE}.svc:8080"
        log "INFO" "Demo UI service: ${server_url}"
    fi

    log "INFO" "Applying hosted-cluster collector (optional ingest forward path)"
    KUBECONFIG="${HOSTED_KUBECONFIG}" oc create namespace "${DEMO_NAMESPACE}" --dry-run=client -o yaml | KUBECONFIG="${HOSTED_KUBECONFIG}" oc apply -f -
    update_file_multi_replace \
        "${DEMO_MANIFESTS_DIR}/06-collector-hosted.yaml" \
        "${GENERATED_DEMO_DIR}/06-collector-hosted.yaml" \
        "<ARGUS_GTC_SERVER_IMAGE>" "${ARGUS_GTC_SERVER_IMAGE}" \
        "<ARGUS_GTC_INGEST_TOKEN>" "${ingest_token}" \
        "<ARGUS_GTC_SERVER_URL>" "${server_url}"
    KUBECONFIG="${HOSTED_KUBECONFIG}" oc apply -f "${GENERATED_DEMO_DIR}/07-collector-rbac-hosted.yaml"
    KUBECONFIG="${HOSTED_KUBECONFIG}" oc apply -f "${GENERATED_DEMO_DIR}/06-collector-hosted.yaml"

    log "INFO" "Argus GTC demo deployed. See docs/argus-gtc-demo-runbook.md"
}

function cleanup_argus_gtc_demo() {
    get_kubeconfig
    log "INFO" "Removing Argus GTC demo resources from management cluster"
    oc delete namespace "${DEMO_NAMESPACE}" --ignore-not-found --wait=false

    if ensure_hosted_kubeconfig; then
        log "INFO" "Removing hosted-cluster collector"
        KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete namespace "${DEMO_NAMESPACE}" --ignore-not-found --wait=false
    fi

    rm -rf "${GENERATED_DEMO_DIR}"
    log "INFO" "Argus GTC demo cleanup complete (Argus and DPU services untouched)"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-deploy}" in
        deploy)
            deploy_argus_gtc_demo
            ;;
        cleanup)
            cleanup_argus_gtc_demo
            ;;
        *)
            log "ERROR" "Unknown command: $1"
            log "ERROR" "Available commands: deploy, cleanup"
            exit 1
            ;;
    esac
fi
