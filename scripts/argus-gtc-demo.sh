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
DEMO_KATA_RUNTIME_CLASS=""
DEMO_KATA_NAD_NAME=""
DEMO_MANIFESTS_DIR="${MANIFESTS_DIR}/argus-gtc-demo"
GENERATED_DEMO_DIR="${GENERATED_DIR}/argus-gtc-demo"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFESTS_DIR=${MANIFESTS_DIR:-"${REPO_ROOT}/manifests"}
GENERATED_DIR=${GENERATED_DIR:-"${MANIFESTS_DIR}/generated"}
MANAGEMENT_KUBECONFIG=""
DEMO_KUBECONFIG=""

trap 'rm -f "${GENERATED_DEMO_DIR}/.hosted-kubeconfig" "${GENERATED_DEMO_DIR}/.management-kubeconfig"' EXIT

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
    if ! oc get runtimeclass "${DEMO_KATA_RUNTIME_CLASS}" &>/dev/null; then
        log "ERROR" "Kata RuntimeClass ${DEMO_KATA_RUNTIME_CLASS} not found in the demo target cluster (KUBECONFIG=${KUBECONFIG}, context=$(oc config current-context 2>/dev/null || echo unknown))"
        local available
        available=$(oc get runtimeclass -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' 2>/dev/null || true)
        if [ -n "${available}" ]; then
            log "ERROR" "RuntimeClasses on this cluster: ${available}"
        fi
        log "ERROR" "Configure RuntimeClass ${DEMO_KATA_RUNTIME_CLASS} and the PF0 Kata VF pool on the demo target cluster before deploying the demo"
        exit 1
    fi
    if ! oc get net-attach-def -n "${OVNK_NAMESPACE}" "${DEMO_KATA_NAD_NAME}" &>/dev/null; then
        log "ERROR" "Kata NetworkAttachmentDefinition ${OVNK_NAMESPACE}/${DEMO_KATA_NAD_NAME} is missing in the demo target cluster"
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
    local worker_role ingest_token ingest_token_hash server_url agent_token agent_token_hash model_key_hash agent_model_name canary_egress hosted_kubeconfig_hash management_kubeconfig_hash
    worker_role=$(kata_worker_role)
    ingest_token="${ARGUS_GTC_INGEST_TOKEN:-$(openssl rand -hex 16)}"
    ingest_token_hash=$(printf '%s' "${ingest_token}" | sha256sum | awk '{print $1}')
    agent_token="${ARGUS_GTC_AGENT_TOKEN:-$(openssl rand -hex 32)}"
    agent_token_hash=$(printf '%s' "${agent_token}" | sha256sum | awk '{print $1}')
    model_key_hash=$(printf '%s' "${ARGUS_GTC_MODEL_API_KEY:-}" | sha256sum | awk '{print $1}')
    agent_model_name="${ARGUS_GTC_MODEL_NAME:-unconfigured-model}"
    canary_egress=$(agent_canary_egress_to)
    hosted_kubeconfig_hash=$(sha256sum "${GENERATED_DEMO_DIR}/.hosted-kubeconfig" | awk '{print $1}')
    management_kubeconfig_hash=$(sha256sum "${GENERATED_DEMO_DIR}/.management-kubeconfig" | awk '{print $1}')
    mkdir -p "${GENERATED_DEMO_DIR}"

    for manifest in "${DEMO_MANIFESTS_DIR}"/*.yaml; do
        local base out
        base=$(basename "${manifest}")
        if [ "${base}" = "10-management-rbac.yaml" ] || [ "${base}" = "11-hosted-rbac.yaml" ]; then
            continue
        fi
        out="${GENERATED_DEMO_DIR}/${base}"
        update_file_multi_replace \
            "${manifest}" "${out}" \
            "<WORKER_ROLE>" "${worker_role}" \
            "<ARGUS_GTC_KATA_RUNTIME_CLASS>" "${DEMO_KATA_RUNTIME_CLASS}" \
            "<ARGUS_GTC_DEMO_IMAGE>" "${ARGUS_GTC_DEMO_IMAGE}" \
            "<ARGUS_GTC_SERVER_IMAGE>" "${ARGUS_GTC_SERVER_IMAGE}" \
            "<ARGUS_GTC_AGENT_IMAGE>" "${ARGUS_GTC_AGENT_IMAGE}" \
            "<ARGUS_GTC_INGEST_TOKEN_SHA256>" "${ingest_token_hash}" \
            "<ARGUS_GTC_AGENT_TOKEN_SHA256>" "${agent_token_hash}" \
            "<ARGUS_GTC_MODEL_API_KEY_SHA256>" "${model_key_hash}" \
            "<ARGUS_GTC_HOSTED_KUBECONFIG_SHA256>" "${hosted_kubeconfig_hash}" \
            "<ARGUS_GTC_MANAGEMENT_KUBECONFIG_SHA256>" "${management_kubeconfig_hash}" \
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

function write_scoped_kubeconfig() {
    local source_kubeconfig="$1" namespace="$2" service_account="$3" output_path="$4"
    local token cluster kubeconfig

    token=$(KUBECONFIG="${source_kubeconfig}" oc -n "${namespace}" create token \
        "${service_account}" --duration=24h)
    cluster=$(KUBECONFIG="${source_kubeconfig}" oc config view \
        --raw --minify --flatten -o json | jq -c '.clusters[0].cluster')
    kubeconfig=$(jq -cn \
        --argjson cluster "${cluster}" \
        --rawfile token <(printf '%s' "${token}") \
        '{apiVersion:"v1",kind:"Config",clusters:[{name:"target",cluster:$cluster}],contexts:[{name:"target",context:{cluster:"target",user:"argus-gtc-reader"}}],"current-context":"target",users:[{name:"argus-gtc-reader",user:{token:$token}}]}')
    (umask 077; printf '%s\n' "${kubeconfig}" > "${output_path}")
}

function create_hosted_kubeconfig_secret() {
    local kubeconfig_path="${GENERATED_DEMO_DIR}/.hosted-kubeconfig"
    mkdir -p "${GENERATED_DEMO_DIR}"
    oc create namespace "${DEMO_NAMESPACE}" --dry-run=client -o yaml | oc apply -f -

    log "INFO" "Creating scoped DPU HostedCluster access for Argus pod status and logs"
    KUBECONFIG="${HOSTED_KUBECONFIG}" oc apply -f "${DEMO_MANIFESTS_DIR}/11-hosted-rbac.yaml"
    write_scoped_kubeconfig "${HOSTED_KUBECONFIG}" dpf-operator-system \
        argus-gtc-hosted-reader "${kubeconfig_path}"
    KUBECONFIG="${DEMO_KUBECONFIG}" oc -n "${DEMO_NAMESPACE}" create secret generic \
        argus-gtc-hosted-kubeconfig \
        --from-file=kubeconfig="${kubeconfig_path}" \
        --dry-run=client -o yaml | KUBECONFIG="${DEMO_KUBECONFIG}" oc apply -f -
}

function initialize_demo_kubeconfigs() {
    get_kubeconfig
    MANAGEMENT_KUBECONFIG="$(canonical_path "${KUBECONFIG}")"
    DEMO_KUBECONFIG="$(_strip_surrounding_quotes "${ARGUS_GTC_DEMO_KUBECONFIG:-${MANAGEMENT_KUBECONFIG}}")"
    DEMO_KUBECONFIG="$(canonical_path "${DEMO_KUBECONFIG}")"

    if [ ! -r "${DEMO_KUBECONFIG}" ]; then
        log "ERROR" "Demo target kubeconfig is missing or unreadable: ${DEMO_KUBECONFIG}"
        log "ERROR" "For the tenant target, create the tenant cluster first and check ZT_TENANT_KUBECONFIG=${ZT_TENANT_KUBECONFIG}"
        return 1
    fi
    if [ "${DEMO_KUBECONFIG}" = "$(canonical_path "${HOSTED_KUBECONFIG}")" ]; then
        log "ERROR" "Demo target kubeconfig must not be the DPU hosted-cluster kubeconfig"
        return 1
    fi

    if [ "${DEMO_KUBECONFIG}" = "${MANAGEMENT_KUBECONFIG}" ]; then
        DEMO_KATA_RUNTIME_CLASS="${KATA_RUNTIME_CLASS}"
        DEMO_KATA_NAD_NAME="${KATA_NAD_NAME}"
        log "INFO" "Demo target is the management cluster (${DEMO_KUBECONFIG})"
    else
        DEMO_KATA_RUNTIME_CLASS="${ARGUS_GTC_KATA_RUNTIME_CLASS:-kata}"
        DEMO_KATA_NAD_NAME="${ARGUS_GTC_KATA_NAD_NAME:-dpf-ovn-kubernetes-${DEMO_KATA_RUNTIME_CLASS}}"
        log "INFO" "Demo target is ${DEMO_KUBECONFIG}; management operations remain on ${MANAGEMENT_KUBECONFIG}"
        log "INFO" "Using standard Kata RuntimeClass ${DEMO_KATA_RUNTIME_CLASS} on the demo target"
    fi
}

function create_management_kubeconfig_secret() {
    local kubeconfig_path="${GENERATED_DEMO_DIR}/.management-kubeconfig"

    log "INFO" "Creating read-only management-cluster access for DPU status"
    KUBECONFIG="${MANAGEMENT_KUBECONFIG}" oc apply -f "${DEMO_MANIFESTS_DIR}/10-management-rbac.yaml"
    write_scoped_kubeconfig "${MANAGEMENT_KUBECONFIG}" dpf-operator-system \
        argus-gtc-management-reader "${kubeconfig_path}"
    KUBECONFIG="${DEMO_KUBECONFIG}" oc -n "${DEMO_NAMESPACE}" create secret generic \
        argus-gtc-management-kubeconfig \
        --from-file=kubeconfig="${kubeconfig_path}" \
        --dry-run=client -o yaml | KUBECONFIG="${DEMO_KUBECONFIG}" oc apply -f -
}

function wait_for_demo_ready() {
    log "INFO" "Waiting for demo server pod..."
    retry 30 10 oc -n "${DEMO_NAMESPACE}" rollout status deploy/argus-gtc-demo --timeout=120s
    retry 30 10 oc -n "${DEMO_NAMESPACE}" rollout status deploy/invisible-vm --timeout=300s
    retry 30 10 oc -n "${DEMO_NAMESPACE}" rollout status deploy/argus-gtc-agent --timeout=300s
    retry 30 10 oc -n "${DEMO_NAMESPACE}" rollout status deploy/argus-gtc-canary --timeout=120s
}

function deploy_argus_gtc_demo() {
    initialize_demo_kubeconfigs || exit 1
    if ! ensure_hosted_kubeconfig; then
        log "ERROR" "Hosted cluster kubeconfig is required for Argus status and log collection"
        exit 1
    fi
    export KUBECONFIG="${DEMO_KUBECONFIG}"
    log "INFO" "Demo target context: $(oc config current-context 2>/dev/null || echo unknown)"
    require_demo_prereqs
    require_agent_network_policy_prereqs
    remove_argus_log_cleaner
    remove_legacy_hosted_collector

    log "INFO" "Using pre-built demo server image ${ARGUS_GTC_SERVER_IMAGE}"
    create_hosted_kubeconfig_secret
    create_management_kubeconfig_secret
    render_demo_manifests

    log "INFO" "Applying demo manifests to ${DEMO_KUBECONFIG}"
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

    log "INFO" "Argus GTC demo deployed to ${DEMO_KUBECONFIG}. Argus reports are read through the DPU hosted kubeconfig. See docs/argus-gtc-demo-runbook.md"
}

function cleanup_argus_gtc_demo() {
    initialize_demo_kubeconfigs || exit 1
    if ! ensure_hosted_kubeconfig; then
        log "WARN" "DPU hosted-cluster kubeconfig unavailable; skipping legacy hosted namespace cleanup"
    fi

    export KUBECONFIG="${DEMO_KUBECONFIG}"
    log "INFO" "Removing Argus GTC demo resources from ${DEMO_KUBECONFIG}"
    oc delete clusterrolebinding argus-gtc-demo-monitoring-view --ignore-not-found
    oc delete adminnetworkpolicy argus-gtc-agent-host-access --ignore-not-found
    oc delete namespace "${DEMO_NAMESPACE}" --ignore-not-found --wait=false

    KUBECONFIG="${MANAGEMENT_KUBECONFIG}" oc delete rolebinding argus-gtc-demo-dpu-read \
        -n dpf-operator-system --ignore-not-found
    KUBECONFIG="${MANAGEMENT_KUBECONFIG}" oc delete role argus-gtc-demo-dpu-read \
        -n dpf-operator-system --ignore-not-found
    KUBECONFIG="${MANAGEMENT_KUBECONFIG}" oc delete serviceaccount \
        argus-gtc-management-reader -n dpf-operator-system --ignore-not-found
    if [ -f "${HOSTED_KUBECONFIG}" ] && [ -s "${HOSTED_KUBECONFIG}" ]; then
        KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete rolebinding argus-gtc-hosted-reader \
            -n dpf-operator-system --ignore-not-found
        KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete role argus-gtc-hosted-reader \
            -n dpf-operator-system --ignore-not-found
        KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete serviceaccount \
            argus-gtc-hosted-reader -n dpf-operator-system --ignore-not-found
    fi

    if [ -f "${HOSTED_KUBECONFIG}" ] && [ -s "${HOSTED_KUBECONFIG}" ]; then
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
