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
        log "ERROR" "RuntimeClass ${KATA_RUNTIME_CLASS} not found (KUBECONFIG=${KUBECONFIG}, context=$(oc config current-context 2>/dev/null || echo unknown))"
        local available
        available=$(oc get runtimeclass -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' 2>/dev/null || true)
        if [ -n "${available}" ]; then
            log "ERROR" "RuntimeClasses on this cluster: ${available}"
        fi
        local cluster_kc="kubeconfig.${CLUSTER_NAME}"
        if [ -f "${cluster_kc}" ] && [ "${KUBECONFIG}" != "${cluster_kc}" ]; then
            if KUBECONFIG="${cluster_kc}" oc get runtimeclass "${KATA_RUNTIME_CLASS}" &>/dev/null; then
                log "ERROR" "${KATA_RUNTIME_CLASS} exists in ${cluster_kc}; .env KUBECONFIG points elsewhere"
                log "ERROR" "Fix .env or run: make KUBECONFIG=${cluster_kc} deploy-argus-gtc-demo"
            fi
        fi
        log "ERROR" "Run make enable-kata on the management cluster, or fix KUBECONFIG in .env"
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
    if [ -z "${ARGUS_GTC_SERVER_IMAGE}" ]; then
        log "ERROR" "ARGUS_GTC_SERVER_IMAGE must be set to your pre-built demo server image in a registry the cluster can pull."
        exit 1
    fi
    if [ -z "${ARGUS_GTC_AGENT_IMAGE}" ]; then
        log "ERROR" "ARGUS_GTC_AGENT_IMAGE must be set to your pre-built NeMo Agent Toolkit image."
        exit 1
    fi
}

function require_agent_network_policy_prereqs() {
    if ! oc get crd adminnetworkpolicies.policy.networking.k8s.io &>/dev/null; then
        log "ERROR" "AdminNetworkPolicy CRD is unavailable; the agent host-access demo requires OpenShift 4.22 OVN-Kubernetes policy support."
        exit 1
    fi
    local network_type
    network_type=$(oc get network.config.openshift.io cluster -o jsonpath='{.status.networkType}' 2>/dev/null || true)
    if [ "${network_type}" != "OVNKubernetes" ]; then
        log "ERROR" "The agent host-access demo requires OVN-Kubernetes; found ${network_type}."
        exit 1
    fi
    if ! oc auth can-i get adminnetworkpolicies.policy.networking.k8s.io | grep -qx yes \
        || ! oc auth can-i create adminnetworkpolicies.policy.networking.k8s.io | grep -qx yes \
        || ! oc auth can-i patch adminnetworkpolicies.policy.networking.k8s.io | grep -qx yes; then
        log "ERROR" "The agent host-access demo requires permission to get/create/patch cluster AdminNetworkPolicy resources."
        exit 1
    fi

    local priority_zero policy
    priority_zero=$(oc get adminnetworkpolicies.policy.networking.k8s.io \
        -o jsonpath='{range .items[?(@.spec.priority==0)]}{.metadata.name}{"\n"}{end}')
    while IFS= read -r policy; do
        if [ -n "${policy}" ] && [ "${policy}" != "argus-gtc-agent-host-access" ]; then
            log "ERROR" "AdminNetworkPolicy ${policy} already uses priority 0; refusing an undefined priority collision. Choose a free ANP priority before deploying the demo."
            exit 1
        fi
    done <<< "${priority_zero}"
}

function wait_for_agent_network_policy_ready() {
    local conditions attempt
    for attempt in $(seq 1 30); do
        conditions=$(oc get adminnetworkpolicy argus-gtc-agent-host-access \
            -o jsonpath='{range .status.conditions[*]}{.status}{" "}{end}' 2>/dev/null || true)
        if [[ -n "${conditions}" && "${conditions}" =~ ^(True[[:space:]]*)+$ ]]; then
            log "INFO" "Agent AdminNetworkPolicy is ready in all reported OVN zones"
            return
        fi
        sleep 2
    done
    log "ERROR" "Agent AdminNetworkPolicy did not become Ready. The agent pod was not deployed; inspect: oc describe adminnetworkpolicy argus-gtc-agent-host-access"
    exit 1
}

function remove_argus_log_cleaner() {
    log "INFO" "Removing destructive Argus log-cleaner DaemonSet from hosted cluster"
    KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete daemonset argus-log-cleaner -n dpf-operator-system --ignore-not-found
}

function remove_legacy_hosted_collector() {
    # Event collection now happens from the demo server through the hosted
    # kubeconfig and pod exec. Remove the old hostPath-based forwarder if a
    # previous deployment left it behind.
    log "INFO" "Removing legacy hosted Argus collector"
    KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete daemonset argus-gtc-collector \
        -n "${DEMO_NAMESPACE}" --ignore-not-found
    KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete serviceaccount argus-gtc-collector \
        -n "${DEMO_NAMESPACE}" --ignore-not-found
}

function agent_canary_egress_to() {
    local worker_role ip
    worker_role=$(kata_worker_role)
    local blocks=""
    while read -r ip; do
        [ -z "${ip}" ] && continue
        [[ "${ip}" == *:* ]] && continue
        blocks="${blocks}        - ipBlock:"$'\n'"            cidr: ${ip}/32"$'\n'
    done < <(oc get nodes -l "node-role.kubernetes.io/${worker_role}" -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
    blocks="${blocks%$'\n'}"
    if [ -z "${blocks}" ]; then
        log "ERROR" "No IPv4 InternalIP found for ${worker_role} nodes; cannot scope agent canary egress"
        exit 1
    fi
    printf '%s' "${blocks}"
}

function render_demo_manifests() {
    local worker_role ingest_token ingest_token_hash server_url agent_token agent_token_hash model_key_hash agent_model_name canary_egress
    worker_role=$(kata_worker_role)
    ingest_token="${ARGUS_GTC_INGEST_TOKEN:-$(openssl rand -hex 16)}"
    ingest_token_hash=$(printf '%s' "${ingest_token}" | sha256sum | awk '{print $1}')
    agent_token="${ARGUS_GTC_AGENT_TOKEN:-$(openssl rand -hex 32)}"
    agent_token_hash=$(printf '%s' "${agent_token}" | sha256sum | awk '{print $1}')
    model_key_hash=$(printf '%s' "${ARGUS_GTC_MODEL_API_KEY:-}" | sha256sum | awk '{print $1}')
    agent_model_name="${ARGUS_GTC_MODEL_NAME:-unconfigured-model}"
    canary_egress=$(agent_canary_egress_to)
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
            "<ARGUS_GTC_AGENT_IMAGE>" "${ARGUS_GTC_AGENT_IMAGE}" \
            "<ARGUS_GTC_INGEST_TOKEN_SHA256>" "${ingest_token_hash}" \
            "<ARGUS_GTC_AGENT_TOKEN_SHA256>" "${agent_token_hash}" \
            "<ARGUS_GTC_MODEL_API_KEY_SHA256>" "${model_key_hash}" \
            "<ARGUS_GTC_MODEL_BASE_URL>" "${ARGUS_GTC_MODEL_BASE_URL:-}" \
            "<ARGUS_GTC_MODEL_NAME>" "${ARGUS_GTC_MODEL_NAME:-}" \
            "<ARGUS_GTC_AGENT_MODEL_NAME>" "${agent_model_name}" \
            "<ARGUS_GTC_SERVER_URL>" "${server_url:-http://argus-gtc-demo.${DEMO_NAMESPACE}.svc:8080}" \
            "<ARGUS_GTC_CANARY_EGRESS_TO>" "${canary_egress}"
        chmod 600 "${out}"
        log "INFO" "Rendered ${out}"
    done
    (umask 077; printf '%s\n' "${ingest_token}" > "${GENERATED_DEMO_DIR}/.ingest-token")
    (umask 077; printf '%s\n' "${agent_token}" > "${GENERATED_DEMO_DIR}/.agent-token")
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
    retry 30 10 oc -n "${DEMO_NAMESPACE}" rollout status deploy/argus-gtc-agent --timeout=300s
    retry 30 10 oc -n "${DEMO_NAMESPACE}" rollout status deploy/argus-gtc-canary --timeout=120s
}

function deploy_argus_gtc_demo() {
    get_kubeconfig
    log "INFO" "Management cluster: KUBECONFIG=${KUBECONFIG} context=$(oc config current-context 2>/dev/null || echo unknown)"
    require_demo_prereqs
    require_agent_network_policy_prereqs
    remove_argus_log_cleaner
    remove_legacy_hosted_collector

    log "INFO" "Using pre-built demo server image ${ARGUS_GTC_SERVER_IMAGE}"
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

    local agent_token
    agent_token=$(<"${GENERATED_DEMO_DIR}/.agent-token")
    oc -n "${DEMO_NAMESPACE}" create secret generic argus-gtc-agent-auth \
        --from-literal=token="${agent_token}" \
        --dry-run=client -o yaml | oc apply -f -
    oc -n "${DEMO_NAMESPACE}" create secret generic argus-gtc-model-auth \
        --from-literal=api-key="${ARGUS_GTC_MODEL_API_KEY:-}" \
        --dry-run=client -o yaml | oc apply -f -

    apply_manifest "${GENERATED_DEMO_DIR}/05-demo-server.yaml" "true"
    apply_manifest "${GENERATED_DEMO_DIR}/09-canary.yaml" "true"
    apply_manifest "${GENERATED_DEMO_DIR}/08-agent-host-access-deny.yaml" "true"
    wait_for_agent_network_policy_ready
    apply_manifest "${GENERATED_DEMO_DIR}/07-agent-networkpolicy.yaml" "true"
    apply_manifest "${GENERATED_DEMO_DIR}/06-agent.yaml" "true"
    oc -n "${DEMO_NAMESPACE}" set image deployment/argus-gtc-demo \
        server="${ARGUS_GTC_SERVER_IMAGE}"
    oc -n "${DEMO_NAMESPACE}" set image deployment/argus-gtc-canary \
        canary="${ARGUS_GTC_SERVER_IMAGE}"

    wait_for_demo_ready

    local route
    route=$(oc -n "${DEMO_NAMESPACE}" get route argus-gtc-demo -o jsonpath='{.spec.host}' 2>/dev/null || true)
    if [ -n "${route}" ]; then
        log "INFO" "Demo UI: https://${route}"
    else
        log "INFO" "Demo UI service: http://argus-gtc-demo.${DEMO_NAMESPACE}.svc:8080"
    fi

    log "INFO" "Argus GTC demo deployed. The server reads Argus reports through the hosted kubeconfig. See docs/argus-gtc-demo-runbook.md"
}

function cleanup_argus_gtc_demo() {
    get_kubeconfig
    log "INFO" "Removing Argus GTC demo resources from management cluster"
    oc delete rolebinding argus-gtc-demo-dpu-read -n dpf-operator-system --ignore-not-found
    oc delete role argus-gtc-demo-dpu-read -n dpf-operator-system --ignore-not-found
    oc delete clusterrolebinding argus-gtc-demo-monitoring-view --ignore-not-found
    oc delete adminnetworkpolicy argus-gtc-agent-host-access --ignore-not-found
    oc delete namespace "${DEMO_NAMESPACE}" --ignore-not-found --wait=false

    if ensure_hosted_kubeconfig; then
        log "INFO" "Removing legacy hosted collector namespace"
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
