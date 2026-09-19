#!/bin/bash
# enable-argus.sh - Install DOCA Argus as a DPUService for Kata VM introspection
#
# Run after make enable-kata with KATA_SRIOV_PF_INDEX=0 (Argus cannot introspect
# PF1 VFs). Kata VF pool and NAD wiring are handled by enable-kata; this script
# only installs Argus (STEPS.md 1-5). Log retention uses native Argus rotation.
#
#   KATA_ENABLED=true KATA_SRIOV_PF_INDEX=0 make enable-ovn-injector
#   make enable-kata
#   ARGUS_REPRESENTOR_ID=<VU> make enable-argus

set -e
set -o pipefail

source "$(dirname "${BASH_SOURCE[0]}")/post-install.sh"
source "$(dirname "${BASH_SOURCE[0]}")/verify.sh"

ARGUS_MANIFESTS_DIR="${MANIFESTS_DIR}/argus"
GENERATED_ARGUS_DIR="${GENERATED_DIR}/argus"
DPF_NAMESPACE="dpf-operator-system"
DPU_DEPLOYMENT_NAME="dpudeployment"

function cluster_has_kata_sriov_pool() {
    local pools
    pools=$(oc get nodesriovdevicepluginconfig "${SRIOV_DP_CONFIG_CR_NAME}" -n dpf-operator-system \
        -o jsonpath='{range .spec.devicePluginResources[*]}{.name}{"\n"}{end}' 2>/dev/null || true)
    grep -Fx "${KATA_SRIOV_DP_CONFIG_NAME}" <<< "${pools}" >/dev/null
}

function require_argus_prereqs() {
    if [ "${KATA_ENABLED}" != "true" ]; then
        log [ERROR] "KATA_ENABLED is not true. Set KATA_ENABLED=true, KATA_SRIOV_PF_INDEX=0, then make enable-ovn-injector and make enable-kata before make enable-argus."
        exit 1
    fi
    if [ "${KATA_SRIOV_PF_INDEX}" != "0" ]; then
        log [ERROR] "Argus cannot introspect Kata VFs on PF1 (KATA_SRIOV_PF_INDEX=${KATA_SRIOV_PF_INDEX})."
        log [ERROR] "Set KATA_SRIOV_PF_INDEX=0 in .env, then re-run make enable-ovn-injector and make enable-kata."
        exit 1
    fi
    if [ -z "${ARGUS_REPRESENTOR_ID}" ]; then
        log [ERROR] "ARGUS_REPRESENTOR_ID is required (DPU VU string for PF0, e.g. MT254360247BMLNXS0D0F0)."
        log [ERROR] "Derive it from the DPU with: lspci -vv | grep -A2 'NVIDIA' (VU / vendor-specific serial)."
        exit 1
    fi
    if ! oc get dpudeployment -n "${DPF_NAMESPACE}" "${DPU_DEPLOYMENT_NAME}" &>/dev/null; then
        log [ERROR] "DPUDeployment ${DPU_DEPLOYMENT_NAME} not found in ${DPF_NAMESPACE}. Deploy DPU services first."
        exit 1
    fi
    if ! oc get runtimeclass "${KATA_RUNTIME_CLASS}" &>/dev/null; then
        log [ERROR] "RuntimeClass ${KATA_RUNTIME_CLASS} not found. Run make enable-kata first."
        exit 1
    fi
    if ! oc get net-attach-def -n "${OVNK_NAMESPACE}" "${KATA_NAD_NAME}" &>/dev/null; then
        log [ERROR] "NetworkAttachmentDefinition ${KATA_NAD_NAME} not found in ${OVNK_NAMESPACE}."
        log [ERROR] "Set KATA_ENABLED=true KATA_SRIOV_PF_INDEX=0 and run make enable-ovn-injector, then make enable-kata."
        exit 1
    fi
    if ! cluster_has_kata_sriov_pool; then
        log [ERROR] "Kata VF pool ${KATA_SRIOV_DP_CONFIG_NAME} not found in NodeSRIOVDevicePluginConfig."
        log [ERROR] "Run make enable-kata with KATA_SRIOV_PF_INDEX=0."
        exit 1
    fi
    local nad_resource
    nad_resource=$(oc get net-attach-def -n "${OVNK_NAMESPACE}" "${KATA_NAD_NAME}" \
        -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/resourceName}' 2>/dev/null || true)
    if [ "${nad_resource}" != "${KATA_INJECTOR_RESOURCE_NAME}" ]; then
        log [ERROR] "NAD ${KATA_NAD_NAME} uses '${nad_resource}', expected '${KATA_INJECTOR_RESOURCE_NAME}'."
        log [ERROR] "Re-run make enable-kata (or make enable-ovn-injector if the NAD was never created for PF0)."
        exit 1
    fi
}

function apply_argus_template() {
    mkdir -p "${GENERATED_ARGUS_DIR}"
    update_file_multi_replace \
        "${ARGUS_MANIFESTS_DIR}/01-servicetemplate.yaml" \
        "${GENERATED_ARGUS_DIR}/01-servicetemplate.yaml" \
        "<ARGUS_HELM_REPO_URL>" "${ARGUS_HELM_REPO_URL}" \
        "<ARGUS_CHART_VERSION>" "${ARGUS_CHART_VERSION}"
    apply_manifest "${GENERATED_ARGUS_DIR}/01-servicetemplate.yaml" "true"
}

function patch_dpudeployment_argus() {
    local patch="${ARGUS_MANIFESTS_DIR}/02-dpudeployment-patch.yaml"
    log [INFO] "Merge-patching DPUDeployment ${DPU_DEPLOYMENT_NAME} to add Argus"
    if ! oc patch dpudeployment "${DPU_DEPLOYMENT_NAME}" -n "${DPF_NAMESPACE}" \
        --type merge --patch-file "${patch}" --dry-run=server >/dev/null; then
        log [ERROR] "Dry-run patch of DPUDeployment ${DPU_DEPLOYMENT_NAME} failed"
        exit 1
    fi
    oc patch dpudeployment "${DPU_DEPLOYMENT_NAME}" -n "${DPF_NAMESPACE}" \
        --type merge --patch-file "${patch}"
}

function apply_argus_configuration() {
    mkdir -p "${GENERATED_ARGUS_DIR}"
    update_file_multi_replace \
        "${ARGUS_MANIFESTS_DIR}/03-configuration.yaml" \
        "${GENERATED_ARGUS_DIR}/03-configuration.yaml" \
        "<ARGUS_DMA_DEVICE_NAME>" "${ARGUS_DMA_DEVICE_NAME}" \
        "<ARGUS_REPRESENTOR_ID>" "${ARGUS_REPRESENTOR_ID}" \
        "<ARGUS_IMAGE>" "${ARGUS_IMAGE}" \
        "<ARGUS_LOG_THRESHOLD_SIZE>" "${ARGUS_LOG_THRESHOLD_SIZE:-50M}" \
        "<ARGUS_LOG_MAX_FILES_COUNT>" "${ARGUS_LOG_MAX_FILES_COUNT:-10}"
    apply_manifest "${GENERATED_ARGUS_DIR}/03-configuration.yaml" "true"
}

function wait_for_argus_pods() {
    local kc="${HOSTED_KUBECONFIG}"
    log [INFO] "Waiting for Argus pods on the hosted cluster (${kc})..."
    local attempts=0
    local max_attempts=60
    while [ $attempts -lt $max_attempts ]; do
        attempts=$((attempts + 1))
        local running total
        total=$(KUBECONFIG="${kc}" oc get pods -n "${DPF_NAMESPACE}" --no-headers 2>/dev/null \
            | grep -c doca-argus || true)
        running=$(KUBECONFIG="${kc}" oc get pods -n "${DPF_NAMESPACE}" --no-headers 2>/dev/null \
            | grep doca-argus | grep -c Running || true)
        total=${total:-0}
        running=${running:-0}
        log [INFO] "Argus pods Running=${running}/${total} (attempt ${attempts}/${max_attempts})"
        if [ "${total}" -gt 0 ] && [ "${running}" = "${total}" ]; then
            KUBECONFIG="${kc}" oc get pods -n "${DPF_NAMESPACE}" | grep doca-argus || true
            log [INFO] "Argus pods are Running on the hosted cluster"
            return 0
        fi
        sleep 10
    done
    log [ERROR] "Argus pods did not become Running after $((max_attempts * 10))s"
    KUBECONFIG="${kc}" oc get pods -n "${DPF_NAMESPACE}" | grep -E 'argus|NAME' || true
    return 1
}

function remove_argus_log_cleaner() {
    if ! ensure_hosted_kubeconfig; then
        return 0
    fi
    if KUBECONFIG="${HOSTED_KUBECONFIG}" oc get daemonset argus-log-cleaner -n "${DPF_NAMESPACE}" &>/dev/null; then
        log [INFO] "Removing legacy Argus log-cleaner DaemonSet (destructive during demos)"
        KUBECONFIG="${HOSTED_KUBECONFIG}" oc delete daemonset argus-log-cleaner -n "${DPF_NAMESPACE}" --ignore-not-found
    fi
}

function enable_argus() {
    get_kubeconfig
    require_argus_prereqs

    log [INFO] "Installing Argus (kata pool ${KATA_SRIOV_DP_CONFIG_NAME} on PF0, representor ${ARGUS_REPRESENTOR_ID})"

    apply_argus_template
    patch_dpudeployment_argus
    apply_argus_configuration

    if ! ensure_hosted_kubeconfig; then
        log [ERROR] "Could not load hosted-cluster kubeconfig (needed for Argus pods and log-cleaner)."
        exit 1
    fi
    wait_for_argus_pods
    remove_argus_log_cleaner

    log [INFO] "Argus installed. Pods run on the hosted cluster; logs are under /var/log/doca_argus_activity_report/"
    log [INFO] "Log retention uses Argus rotation (threshold=${ARGUS_LOG_THRESHOLD_SIZE:-50M}, max_files=${ARGUS_LOG_MAX_FILES_COUNT:-10})"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-enable}" in
        enable)
            enable_argus
            ;;
        *)
            log [ERROR] "Unknown command: $1"
            log [ERROR] "Available commands: enable"
            exit 1
            ;;
    esac
fi
