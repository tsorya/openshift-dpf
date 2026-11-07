#!/usr/bin/env bash
# zt-tenant-cluster.sh — provision a tenant HostedCluster on physical DPU-host servers (Agent + BMH)
#
# Prerequisites: management cluster, DPU HostedCluster from DPF HCP Provisioner (all-zt),
# MCE with HyperShift + Assisted Service, Metal3 watching all namespaces.
#
set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/utils.sh
source "${SCRIPT_DIR}/utils.sh"
# shellcheck source=scripts/tools.sh
source "${SCRIPT_DIR}/tools.sh"

ZT_TENANT_GENERATED_DIR="${GENERATED_DIR:-manifests/generated}/zt-tenant"
SSH_PUBLIC_KEY_FILE="${SSH_PUBLIC_KEY_FILE:-}"
ZT_TENANT_PULL_SECRET_NAME="${ZT_TENANT_PULL_SECRET_NAME:-zt-tenant-pull-secret}"
ZT_TENANT_INFRAENV_NAME="${ZT_TENANT_INFRAENV_NAME:-zt-tenant-infraenv}"

# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

_tenant_require_zero_trust() {
    if [ "${DPF_DEPLOYMENT_MODE:-}" != "zero-trust" ]; then
        log [ERROR] "deploy-zt-tenant-cluster requires DPF_DEPLOYMENT_MODE=zero-trust"
        return 1
    fi
}

_python_cidr_overlap() {
    python3 - "$@" <<'PY'
import ipaddress, sys
def parse(c):
    return ipaddress.ip_network(c, strict=False)
a, b = sys.argv[1], sys.argv[2]
n1, n2 = parse(a), parse(b)
sys.exit(0 if n1.overlaps(n2) else 1)
PY
}

_tenant_cidr_overlaps() {
    local a="$1" b="$2"
    _python_cidr_overlap "$a" "$b"
}

# Returns 0 if CIDR a overlaps any comma-separated entry in list (ignores empty / spaces).
_tenant_any_cidr_in_list_overlaps() {
    local a="$1"
    local list="$2"
    local part
    IFS=',' read -r -a parts <<< "${list}"
    for part in "${parts[@]}"; do
        part="${part// /}"
        [ -n "${part}" ] || continue
        if _tenant_cidr_overlaps "$a" "$part"; then
            return 0
        fi
    done
    return 1
}

validate_zt_tenant_configuration() {
    local host dpu_count machine_default

    _tenant_require_zero_trust || return 1

    if [ "${HYPERSHIFT_INSTALL_METHOD:-}" != "mce" ]; then
        log [ERROR] "deploy-zt-tenant-cluster requires HYPERSHIFT_INSTALL_METHOD=mce (shared MCE HyperShift + Assisted)"
        return 1
    fi

    if [ -z "${ZT_TENANT_CLUSTER_NAME:-}" ] || [ -z "${ZT_TENANT_BASE_DOMAIN:-}" ]; then
        log [ERROR] "ZT_TENANT_CLUSTER_NAME and ZT_TENANT_BASE_DOMAIN are required"
        return 1
    fi

    if [ -z "${ZT_TENANT_CLUSTER_NETWORK_CIDR:-}" ] || [ -z "${ZT_TENANT_SERVICE_NETWORK_CIDR:-}" ]; then
        log [ERROR] "ZT_TENANT_CLUSTER_NETWORK_CIDR and ZT_TENANT_SERVICE_NETWORK_CIDR are required"
        return 1
    fi

    if [ -z "${ZT_TENANT_OCP_RELEASE_IMAGE:-}" ]; then
        log [ERROR] "ZT_TENANT_OCP_RELEASE_IMAGE is required (tenant cluster release image)"
        return 1
    fi

    if [ "$(readlink -m "${KUBECONFIG}")" = "$(readlink -m "${ZT_TENANT_KUBECONFIG}")" ]; then
        log [ERROR] "ZT_TENANT_KUBECONFIG must differ from management KUBECONFIG"
        return 1
    fi

    # Non-overlap with management cluster and DPU hosted cluster networking
    for pair in \
        "${ZT_TENANT_CLUSTER_NETWORK_CIDR}|${FLANNEL_POD_CIDR:-}" \
        "${ZT_TENANT_SERVICE_NETWORK_CIDR}|${SERVICE_CIDR:-}" \
        "${ZT_TENANT_CLUSTER_NETWORK_CIDR}|${POD_CIDR:-}" \
        "${ZT_TENANT_SERVICE_NETWORK_CIDR}|${POD_CIDR:-}" \
        "${ZT_TENANT_CLUSTER_NETWORK_CIDR}|${SERVICE_CIDR:-}" \
        "${ZT_TENANT_SERVICE_NETWORK_CIDR}|${FLANNEL_POD_CIDR:-}"; do
        local a="${pair%%|*}"
        local b="${pair##*|}"
        [ -n "$b" ] || continue
        if _tenant_cidr_overlaps "$a" "$b"; then
            log [ERROR] "Tenant CIDR ${a} overlaps management or DPU hosted network ${b}"
            return 1
        fi
    done

    if [ -n "${DPU_HOST_CIDR:-}" ]; then
        for cidr in "${ZT_TENANT_CLUSTER_NETWORK_CIDR}" "${ZT_TENANT_SERVICE_NETWORK_CIDR}"; do
            if _tenant_any_cidr_in_list_overlaps "${cidr}" "${DPU_HOST_CIDR}"; then
                log [ERROR] "Tenant CIDR ${cidr} overlaps DPU_HOST_CIDR (${DPU_HOST_CIDR})"
                return 1
            fi
        done
    fi

    dpu_count=0
    while IFS= read -r host; do
        dpu_count=$((dpu_count + 1))
    done < <(list_zero_trust_dpu_hosts)

    if [ "${dpu_count}" -lt 1 ]; then
        log [ERROR] "No Zero Trust DPU hosts (WORKER_<N>_DPU_BMC_IPS); cannot derive tenant worker count"
        return 1
    fi

    while IFS= read -r host; do
        for v in "WORKER_${host}_BMC_IP" "WORKER_${host}_BMC_USER" "WORKER_${host}_BMC_PASSWORD" "WORKER_${host}_BOOT_MAC" "WORKER_${host}_ROOT_DEVICE"; do
            if [ -z "${!v:-}" ]; then
                log [ERROR] "Missing ${v} for tenant BareMetalHost (same BMC as DPU host ${host})"
                return 1
            fi
        done
    done < <(list_zero_trust_dpu_hosts)

    if [ "${ZT_TENANT_DEPLOY_AGENT_SERVICE_CONFIG:-false}" = "true" ]; then
        local fs_sc db_sc img_sc
        fs_sc="${ZT_TENANT_AGENT_SERVICE_FILESYSTEM_STORAGE_CLASS:-${ETCD_STORAGE_CLASS:-}}"
        db_sc="${ZT_TENANT_AGENT_SERVICE_DATABASE_STORAGE_CLASS:-${ETCD_STORAGE_CLASS:-}}"
        img_sc="${ZT_TENANT_AGENT_SERVICE_IMAGE_STORAGE_CLASS:-${ETCD_STORAGE_CLASS:-}}"
        for v in ZT_TENANT_RHCOS_ISO_URL ZT_TENANT_RHCOS_ROOTFS_URL ZT_TENANT_RHCOS_VERSION ZT_TENANT_OPENSHIFT_VERSION_MINOR; do
            if [ -z "${!v:-}" ]; then
                log [ERROR] "ZT tenant AgentServiceConfig enabled but ${v} is empty"
                return 1
            fi
        done
        if [ -z "${fs_sc}" ] || [ -z "${db_sc}" ] || [ -z "${img_sc}" ]; then
            log [ERROR] "ZT tenant AgentServiceConfig requires storage classes (set ZT_TENANT_AGENT_SERVICE_*_STORAGE_CLASS or ETCD_STORAGE_CLASS)"
            return 1
        fi
    fi

    machine_default=""
    if [ -n "${API_VIP:-}" ]; then
        machine_default="$(python3 -c "import ipaddress; print(ipaddress.ip_network('${API_VIP}/24', strict=False))" 2>/dev/null || true)"
    fi
    if [ -z "${ZT_TENANT_MACHINE_NETWORK_CIDRS:-}" ]; then
        if [ -n "${machine_default}" ]; then
            log [WARN] "ZT_TENANT_MACHINE_NETWORK_CIDRS unset; assuming ${machine_default} from API_VIP (verify BMC/L2 reachability to the discovery image)"
            export ZT_TENANT_MACHINE_NETWORK_CIDRS="${machine_default}"
        else
            log [ERROR] "Set ZT_TENANT_MACHINE_NETWORK_CIDRS or API_VIP so the tenant HostedCluster machine networks can be validated"
            return 1
        fi
    fi

    if [ -n "${ZT_TENANT_MACHINE_NETWORK_CIDRS:-}" ]; then
        if _tenant_any_cidr_in_list_overlaps "${ZT_TENANT_CLUSTER_NETWORK_CIDR}" "${ZT_TENANT_MACHINE_NETWORK_CIDRS}"; then
            log [ERROR] "ZT_TENANT_CLUSTER_NETWORK_CIDR must not overlap ZT_TENANT_MACHINE_NETWORK_CIDRS (${ZT_TENANT_MACHINE_NETWORK_CIDRS})"
            return 1
        fi
        if _tenant_any_cidr_in_list_overlaps "${ZT_TENANT_SERVICE_NETWORK_CIDR}" "${ZT_TENANT_MACHINE_NETWORK_CIDRS}"; then
            log [ERROR] "ZT_TENANT_SERVICE_NETWORK_CIDR must not overlap ZT_TENANT_MACHINE_NETWORK_CIDRS (${ZT_TENANT_MACHINE_NETWORK_CIDRS})"
            return 1
        fi
    fi

    log [INFO] "Tenant cluster configuration validation passed"
}

# -----------------------------------------------------------------------------
# DPU hosted cluster health (before tenant changes)
# -----------------------------------------------------------------------------

wait_dpfhcp_provisioner_ready() {
    local ns="${CLUSTERS_NAMESPACE:-clusters}"
    local name="${HOSTED_CLUSTER_NAME}"
    log [INFO] "Waiting for DPFHCPProvisioner ${ns}/${name} to report Ready..."
    if ! oc get dpfhcpprovisioner -n "${ns}" "${name}" &>/dev/null; then
        log [ERROR] "DPFHCPProvisioner ${name} not found in ${ns}; run all-zt / deploy-hosted-cluster first"
        return 1
    fi
    if ! retry 60 10 bash -c "oc get dpfhcpprovisioner -n '${ns}' '${name}' -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null | grep -qx True"; then
        log [ERROR] "DPFHCPProvisioner ${name} is not Ready"
        oc get dpfhcpprovisioner -n "${ns}" "${name}" -o yaml || true
        return 1
    fi
    log [INFO] "DPFHCPProvisioner ${name} is Ready"
}

wait_dpu_hosted_cluster_healthy() {
    local ns="${CLUSTERS_NAMESPACE:-clusters}"
    local name="${HOSTED_CLUSTER_NAME}"
    log [INFO] "Checking HostedCluster ${ns}/${name} (DPU) before tenant provisioning..."
    if ! oc get hostedcluster -n "${ns}" "${name}" &>/dev/null; then
        log [ERROR] "HostedCluster ${name} not found in ${ns}"
        return 1
    fi
    if ! retry 30 10 bash -c "oc get hostedcluster -n '${ns}' '${name}' -o jsonpath='{.status.conditions[?(@.type==\"Available\")].status}' 2>/dev/null | grep -qx True"; then
        log [ERROR] "HostedCluster ${name} is not Available; fix the DPU cluster before deploy-zt-tenant-cluster"
        oc get hostedcluster -n "${ns}" "${name}" -o wide || true
        oc describe hostedcluster -n "${ns}" "${name}" | tail -n 40 || true
        return 1
    fi
    log [INFO] "HostedCluster ${name} is Available"
}

# -----------------------------------------------------------------------------
# MCE / Assisted / Metal3
# -----------------------------------------------------------------------------

mce_enable_components() {
    local mce_name="$1"
    shift
    local comp cur_json new_json
    cur_json=$(oc get multiclusterengine "${mce_name}" -o json)
    new_json="${cur_json}"
    if ! echo "${new_json}" | jq -e '.spec.overrides.components' >/dev/null 2>&1; then
        new_json=$(echo "${new_json}" | jq '.spec.overrides.components = []')
    fi
    for comp in "$@"; do
        if echo "${new_json}" | jq -e --arg c "${comp}" '.spec.overrides.components[]? | select(.name==$c)' >/dev/null 2>&1; then
            new_json=$(echo "${new_json}" | jq --arg c "${comp}" '(.spec.overrides.components[] | select(.name==$c) | .enabled) = true')
        else
            new_json=$(echo "${new_json}" | jq --arg c "${comp}" '.spec.overrides.components += [{"name": $c, "enabled": true}]')
        fi
    done
    echo "${new_json}" | oc apply -f -
}

ensure_mce_assisted_and_hypershift() {
    log [INFO] "Ensuring MCE with HyperShift and Assisted Service..."
    install_hypershift_via_mce || return 1

    local mce_name
    mce_name=$(oc get multiclusterengine -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [ -z "${mce_name}" ]; then
        log [ERROR] "No MultiClusterEngine CR found after MCE install"
        return 1
    fi

    log [INFO] "Ensuring MultiClusterEngine ${mce_name} components: assisted-service, hypershift, hypershift-local-hosting"
    mce_enable_components "${mce_name}" assisted-service hypershift hypershift-local-hosting

    if ! retry 90 10 bash -c "oc get multiclusterengine ${mce_name} -o jsonpath='{.status.phase}' | grep -qx Available"; then
        log [ERROR] "MultiClusterEngine ${mce_name} did not reach Available"
        return 1
    fi

    if ! retry 40 10 bash -c 'oc get deployment -n hypershift -l app=operator --no-headers 2>/dev/null | grep -q Running'; then
        log [ERROR] "HyperShift operator deployment not Running in hypershift namespace"
        return 1
    fi
    log [INFO] "MCE HyperShift operator is ready"
}

ensure_hypershift_operator_ready() {
    if ! retry 20 5 bash -c 'oc get deployment -n hypershift -l app=operator --no-headers 2>/dev/null | awk "{print \$2}" | grep -q "1/1\\|2/2"'; then
        log [ERROR] "HyperShift operator deployment not ready"
        oc get deploy -n hypershift || true
        return 1
    fi
}

ensure_agent_service_config() {
    if [ "${ZT_TENANT_DEPLOY_AGENT_SERVICE_CONFIG:-false}" != "true" ]; then
        if ! oc get agentserviceconfig agent -n multicluster-engine &>/dev/null; then
            log [ERROR] "AgentServiceConfig agent not found in multicluster-engine; MCE must provide it or set ZT_TENANT_DEPLOY_AGENT_SERVICE_CONFIG=true"
            return 1
        fi
        log [INFO] "Using MCE AgentServiceConfig (ZT_TENANT_DEPLOY_AGENT_SERVICE_CONFIG=false)"
        return 0
    fi

    if oc get agentserviceconfig agent -n multicluster-engine &>/dev/null; then
        log [INFO] "AgentServiceConfig agent already exists"
        return 0
    fi

    local out="${ZT_TENANT_GENERATED_DIR}/agentserviceconfig.yaml"
    mkdir -p "${ZT_TENANT_GENERATED_DIR}"
    local fs_sc db_sc img_sc
    fs_sc="${ZT_TENANT_AGENT_SERVICE_FILESYSTEM_STORAGE_CLASS:-${ETCD_STORAGE_CLASS:-}}"
    db_sc="${ZT_TENANT_AGENT_SERVICE_DATABASE_STORAGE_CLASS:-${ETCD_STORAGE_CLASS:-}}"
    img_sc="${ZT_TENANT_AGENT_SERVICE_IMAGE_STORAGE_CLASS:-${ETCD_STORAGE_CLASS:-}}"
    process_template \
        "${MANIFESTS_DIR}/zt-tenant/agentserviceconfig-template.yaml" \
        "${out}" \
        "<ZT_TENANT_AGENT_SERVICE_DATABASE_STORAGE_CLASS>" "${db_sc}" \
        "<ZT_TENANT_AGENT_SERVICE_FILESYSTEM_STORAGE_CLASS>" "${fs_sc}" \
        "<ZT_TENANT_AGENT_SERVICE_IMAGE_STORAGE_CLASS>" "${img_sc}" \
        "<ZT_TENANT_OPENSHIFT_VERSION_MINOR>" "${ZT_TENANT_OPENSHIFT_VERSION_MINOR}" \
        "<ZT_TENANT_RHCOS_VERSION>" "${ZT_TENANT_RHCOS_VERSION}" \
        "<ZT_TENANT_RHCOS_ISO_URL>" "${ZT_TENANT_RHCOS_ISO_URL}" \
        "<ZT_TENANT_RHCOS_ROOTFS_URL>" "${ZT_TENANT_RHCOS_ROOTFS_URL}" \
        "<ZT_TENANT_RHCOS_CPU_ARCHITECTURE>" "${ZT_TENANT_RHCOS_CPU_ARCHITECTURE:-x86_64}"

    apply_manifest "${out}" true
    log [INFO] "Waiting for assisted-service pods after AgentServiceConfig..."
    if ! retry 60 10 bash -c 'oc get pods -n multicluster-engine -l app=assisted-service --no-headers 2>/dev/null | grep -q Running'; then
        log [ERROR] "assisted-service did not become Running; check AgentServiceConfig and storage"
        oc get pods -n multicluster-engine | grep assisted || true
        return 1
    fi
}

ensure_metal3_watch_all_namespaces() {
    log [INFO] "Enabling Metal3 Provisioning watchAllNamespaces for tenant BareMetalHosts..."
    if oc get provisioning provisioning-configuration &>/dev/null; then
        oc patch provisioning provisioning-configuration --type=merge -p '{"spec":{"watchAllNamespaces":true}}' || {
            log [ERROR] "Failed to patch provisioning-configuration watchAllNamespaces"
            return 1
        }
    else
        log [ERROR] "Provisioning CR provisioning-configuration not found"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# HostedCluster + NodePool (HyperShift CLI)
# -----------------------------------------------------------------------------

_tenant_ssh_key_path() {
    local key_path="${SSH_PUBLIC_KEY_FILE:-}"
    if [ -z "${key_path}" ] && [ -n "${SSH_KEY:-}" ]; then
        key_path="${SSH_KEY#\~}"
        key_path="${key_path/#\~/${HOME}}"
    fi
    if [ -z "${key_path}" ] || [ ! -f "${key_path}" ]; then
        log [ERROR] "SSH public key not found (set SSH_KEY or SSH_PUBLIC_KEY_FILE to a .pub path)"
        return 1
    fi
    echo "${key_path}"
}

zt_tenant_agent_namespace() {
    echo "${CLUSTERS_NAMESPACE}-${ZT_TENANT_CLUSTER_NAME}"
}

ensure_tenant_namespace() {
    local ns="$1"
    if oc get namespace "${ns}" &>/dev/null; then
        return 0
    fi
    oc create namespace "${ns}"
}

create_tenant_pull_secret() {
    local ns="$1"
    ensure_tenant_namespace "${ns}" || return 1
    oc create secret generic "${ZT_TENANT_PULL_SECRET_NAME}" \
        -n "${ns}" \
        --from-file=".dockerconfigjson=${OPENSHIFT_PULL_SECRET}" \
        --type=kubernetes.io/dockerconfigjson \
        --dry-run=client -o yaml | oc apply -f -
}

create_tenant_hostedcluster_skip_nodepool() {
    local ns="${CLUSTERS_NAMESPACE:-clusters}"
    local agent_ns
    agent_ns="$(zt_tenant_agent_namespace)"
    ensure_hypershift_cli || return 1

    if oc get hostedcluster -n "${ns}" "${ZT_TENANT_CLUSTER_NAME}" &>/dev/null; then
        log [INFO] "HostedCluster ${ZT_TENANT_CLUSTER_NAME} already exists; skipping create"
        return 0
    fi

    local ssh_key machine_cidrs=()
    ssh_key="$(_tenant_ssh_key_path)" || return 1

    IFS=',' read -r -a machine_cidrs <<< "${ZT_TENANT_MACHINE_NETWORK_CIDRS}"
    if [ "${#machine_cidrs[@]}" -eq 0 ]; then
        log [ERROR] "ZT_TENANT_MACHINE_NETWORK_CIDRS is empty"
        return 1
    fi

    local -a mc_flags=()
    for c in "${machine_cidrs[@]}"; do
        mc_flags+=(--machine-cidr "${c}")
    done

    log [INFO] "Creating tenant HostedCluster ${ZT_TENANT_CLUSTER_NAME} (Agent platform, NodePool deferred)..."
    hypershift create cluster agent \
        --name "${ZT_TENANT_CLUSTER_NAME}" \
        --namespace "${ns}" \
        --base-domain "${ZT_TENANT_BASE_DOMAIN}" \
        --pull-secret "${OPENSHIFT_PULL_SECRET}" \
        --ssh-key "${ssh_key}" \
        --release-image "${ZT_TENANT_OCP_RELEASE_IMAGE}" \
        --etcd-storage-class "${ETCD_STORAGE_CLASS}" \
        --network-type OVNKubernetes \
        --cluster-cidr "${ZT_TENANT_CLUSTER_NETWORK_CIDR}" \
        --service-cidr "${ZT_TENANT_SERVICE_NETWORK_CIDR}" \
        "${mc_flags[@]}" \
        --agent-namespace "${agent_ns}" \
        --node-pool-replicas -1 \
        --arch "${ZT_TENANT_RHCOS_CPU_ARCHITECTURE:-x86_64}"

    log [INFO] "Waiting for tenant control plane namespace ${agent_ns}..."
    retry 60 10 oc get namespace "${agent_ns}" &>/dev/null
}

create_tenant_infraenv() {
    local ns
    ns="$(zt_tenant_agent_namespace)"
    local out="${ZT_TENANT_GENERATED_DIR}/infraenv.yaml"
    local ssh_key merge_patch
    ssh_key="$(_tenant_ssh_key_path)" || return 1

    mkdir -p "${ZT_TENANT_GENERATED_DIR}"
    process_template \
        "${MANIFESTS_DIR}/zt-tenant/infraenv-template.yaml" \
        "${out}" \
        "<INFRAENV_NAME>" "${ZT_TENANT_INFRAENV_NAME}" \
        "<ZT_TENANT_AGENT_NAMESPACE>" "${ns}" \
        "<ZT_TENANT_RHCOS_CPU_ARCHITECTURE>" "${ZT_TENANT_RHCOS_CPU_ARCHITECTURE:-x86_64}" \
        "<ZT_TENANT_PULL_SECRET_NAME>" "${ZT_TENANT_PULL_SECRET_NAME}"

    apply_manifest "${out}" true

    merge_patch="$(jq -n --rawfile k "${ssh_key}" '{spec: {sshAuthorizedKey: ($k | rtrimstr("\n"))}}')"
    oc patch infraenv -n "${ns}" "${ZT_TENANT_INFRAENV_NAME}" --type=merge -p "${merge_patch}" || {
        log [ERROR] "Failed to set sshAuthorizedKey on InfraEnv ${ns}/${ZT_TENANT_INFRAENV_NAME}"
        return 1
    }
}

apply_tenant_bmhs() {
    local ns host i name name_var out
    ns="$(zt_tenant_agent_namespace)"
    mkdir -p "${ZT_TENANT_GENERATED_DIR}"

    i=0
    while IFS= read -r host; do
        name_var="WORKER_${host}_NAME"
        name="${!name_var}"
        if [ -z "${name}" ]; then
            name="zt-tenant-worker-${host}"
        fi

        if oc get bmh -n "${ns}" "${name}" &>/dev/null; then
            log [INFO] "BareMetalHost ${ns}/${name} already exists; skipping"
            continue
        fi

        local bmc_ip_var="WORKER_${host}_BMC_IP"
        local bmc_user_var="WORKER_${host}_BMC_USER"
        local bmc_pass_var="WORKER_${host}_BMC_PASSWORD"
        local boot_mac_var="WORKER_${host}_BOOT_MAC"
        local root_dev_var="WORKER_${host}_ROOT_DEVICE"
        local bmc_ip="${!bmc_ip_var}"
        local bmc_user="${!bmc_user_var}"
        local bmc_pass="${!bmc_pass_var}"
        local boot_mac="${!boot_mac_var}"
        local root_dev="${!root_dev_var:-/dev/sda}"

        local bmh_inspection_mode="disabled"
        if [[ "${BMH_ENABLE_INSPECTION}" == "true" ]]; then
            bmh_inspection_mode="agent"
        fi

        process_template \
            "${MANIFESTS_DIR}/zt-tenant/bmc-secret-tenant-template.yaml" \
            "${ZT_TENANT_GENERATED_DIR}/${name}-bmc-secret.yaml" \
            "<WORKER_NAME>" "$name" \
            "<ZT_TENANT_AGENT_NAMESPACE>" "$ns" \
            "<BMC_USER_BASE64>" "$(printf '%s' "$bmc_user" | base64)" \
            "<BMC_PASSWORD_BASE64>" "$(printf '%s' "$bmc_pass" | base64)"

        process_template \
            "${MANIFESTS_DIR}/zt-tenant/bmh-tenant-template.yaml" \
            "${ZT_TENANT_GENERATED_DIR}/${name}-bmh.yaml" \
            "<WORKER_NAME>" "$name" \
            "<ZT_TENANT_AGENT_NAMESPACE>" "$ns" \
            "<INFRAENV_NAME>" "${ZT_TENANT_INFRAENV_NAME}" \
            "<BOOT_MAC>" "$boot_mac" \
            "<BMC_IP>" "$bmc_ip" \
            "<ROOT_DEVICE>" "$root_dev" \
            "<BMH_INSPECTION_MODE>" "$bmh_inspection_mode"

        retry 5 10 apply_manifest "${ZT_TENANT_GENERATED_DIR}/${name}-bmc-secret.yaml" true
        retry 5 10 apply_manifest "${ZT_TENANT_GENERATED_DIR}/${name}-bmh.yaml" true

        i=$((i + 1))
    done < <(list_zero_trust_dpu_hosts)

    log [INFO] "Submitted ${i} BareMetalHost(s) for tenant discovery"
}

wait_for_agents_registered() {
    local ns expected
    ns="$(zt_tenant_agent_namespace)"
    expected="$(list_zero_trust_dpu_hosts | wc -l | tr -d ' ')"
    log [INFO] "Waiting for ${expected} Agent(s) in ${ns} (namespace must exist)..."
    if ! retry 5 5 oc get namespace "${ns}" &>/dev/null; then
        log [ERROR] "Tenant hosted control plane namespace ${ns} missing; HostedCluster not created?"
        return 1
    fi
    if ! retry 120 15 bash -c "oc get agents.agent-install.openshift.io -n '${ns}' --no-headers 2>/dev/null | wc -l | tr -d ' ' | grep -qx ${expected}"; then
        log [ERROR] "Expected ${expected} Agent(s); current:"
        oc get agents.agent-install.openshift.io -n "${ns}" || true
        return 1
    fi
}

label_agents_for_nodepool() {
    local ns a
    ns="$(zt_tenant_agent_namespace)"
    log [INFO] "Labeling Agents with ${ZT_TENANT_AGENT_LABEL_KEY}=${ZT_TENANT_CLUSTER_NAME}..."
    for a in $(oc get agents.agent-install.openshift.io -n "${ns}" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        oc label agent -n "${ns}" "${a}" "${ZT_TENANT_AGENT_LABEL_KEY}=${ZT_TENANT_CLUSTER_NAME}" --overwrite
    done
}

approve_agents_if_needed() {
    local ns a approved
    ns="$(zt_tenant_agent_namespace)"
    for a in $(oc get agents.agent-install.openshift.io -n "${ns}" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        approved=$(oc get agent -n "${ns}" "${a}" -o jsonpath='{.spec.approved}' 2>/dev/null || echo "false")
        if [ "${approved}" != "true" ]; then
            log [INFO] "Approving Agent ${a}"
            oc patch agent -n "${ns}" "${a}" --type=merge -p '{"spec":{"approved":true}}' || true
        fi
    done
}

_tenant_nodepool_agent_spec_ok() {
    local ns="$1" np="$2" want_ns="$3"
    local got_ns got_label
    got_ns=$(oc get nodepool -n "${ns}" "${np}" -o jsonpath='{.spec.platform.agent.agentNamespace}' 2>/dev/null || true)
    got_label=$(oc get nodepool -n "${ns}" "${np}" -o json | jq -r \
        --arg k "${ZT_TENANT_AGENT_LABEL_KEY}" \
        '.spec.platform.agent.agentLabelSelector.matchLabels[$k] // empty' 2>/dev/null || true)
    if [ "${got_ns}" != "${want_ns}" ]; then
        log [ERROR] "NodePool ${np}: expected spec.platform.agent.agentNamespace=${want_ns}, got '${got_ns}'"
        return 1
    fi
    if [ "${got_label}" != "${ZT_TENANT_CLUSTER_NAME}" ]; then
        log [ERROR] "NodePool ${np}: expected agent label ${ZT_TENANT_AGENT_LABEL_KEY}=${ZT_TENANT_CLUSTER_NAME}, got '${got_label}'"
        return 1
    fi
    return 0
}

ensure_tenant_nodepool() {
    local ns="${CLUSTERS_NAMESPACE:-clusters}"
    local replicas agent_ns merge_patch
    agent_ns="$(zt_tenant_agent_namespace)"
    replicas="$(list_zero_trust_dpu_hosts | wc -l | tr -d ' ')"

    ensure_hypershift_cli || return 1

    merge_patch="$(jq -n \
        --arg ns "${agent_ns}" \
        --arg lk "${ZT_TENANT_AGENT_LABEL_KEY}" \
        --arg lv "${ZT_TENANT_CLUSTER_NAME}" \
        --argjson replicas "${replicas}" \
        '{spec: {replicas: $replicas, platform: {agent: {agentNamespace: $ns, agentLabelSelector: {matchLabels: {($lk): $lv}}}}}}')"

    if oc get nodepool -n "${ns}" "${ZT_TENANT_NODEPOOL_NAME}" &>/dev/null; then
        log [INFO] "NodePool ${ZT_TENANT_NODEPOOL_NAME} exists; setting replicas=${replicas}, agentNamespace, and agentLabelSelector"
        oc patch nodepool -n "${ns}" "${ZT_TENANT_NODEPOOL_NAME}" --type=merge -p "${merge_patch}" || {
            log [ERROR] "Failed to patch NodePool ${ZT_TENANT_NODEPOOL_NAME}"
            return 1
        }
    else
        log [INFO] "Creating NodePool ${ZT_TENANT_NODEPOOL_NAME} (replicas=${replicas}, agentNamespace=${agent_ns})..."
        hypershift create nodepool agent \
            --name "${ZT_TENANT_NODEPOOL_NAME}" \
            --namespace "${ns}" \
            --cluster-name "${ZT_TENANT_CLUSTER_NAME}" \
            --replicas "${replicas}" \
            --release-image "${ZT_TENANT_OCP_RELEASE_IMAGE}" \
            --arch "${ZT_TENANT_RHCOS_CPU_ARCHITECTURE:-x86_64}"
        oc patch nodepool -n "${ns}" "${ZT_TENANT_NODEPOOL_NAME}" --type=merge -p "${merge_patch}" || {
            log [ERROR] "Failed to configure NodePool ${ZT_TENANT_NODEPOOL_NAME} (agentNamespace / selector / replicas)"
            return 1
        }
    fi

    _tenant_nodepool_agent_spec_ok "${ns}" "${ZT_TENANT_NODEPOOL_NAME}" "${agent_ns}" || return 1
}

write_tenant_kubeconfig() {
    local ns="${CLUSTERS_NAMESPACE:-clusters}"
    ensure_hypershift_cli || return 1
    log [INFO] "Writing tenant kubeconfig to ${ZT_TENANT_KUBECONFIG}..."
    hypershift create kubeconfig --namespace "${ns}" --name "${ZT_TENANT_CLUSTER_NAME}" > "${ZT_TENANT_KUBECONFIG}"
    chmod 600 "${ZT_TENANT_KUBECONFIG}" || true
}

wait_tenant_workers_ready() {
    local expected kube ready attempt
    expected="$(list_zero_trust_dpu_hosts | wc -l | tr -d ' ')"
    kube="${ZT_TENANT_KUBECONFIG}"
    log [INFO] "Waiting for ${expected} Ready worker node(s) on tenant cluster..."
    for attempt in $(seq 1 120); do
        if oc --kubeconfig="${kube}" get nodes --no-headers &>/dev/null; then
            break
        fi
        sleep 15
    done
    for attempt in $(seq 1 90); do
        ready=$(oc --kubeconfig="${kube}" get nodes -l '!node-role.kubernetes.io/control-plane' -o json 2>/dev/null | \
            jq '[.items[] | select(.status.conditions[] | select(.type=="Ready" and .status=="True"))] | length' || echo 0)
        if [ "${ready}" -ge "${expected}" ]; then
            log [INFO] "Tenant worker nodes Ready: ${ready}/${expected}"
            return 0
        fi
        sleep 20
    done
    log [ERROR] "Tenant workers not Ready (want ${expected})"
    oc --kubeconfig="${kube}" get nodes -o wide 2>/dev/null || true
    return 1
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

deploy_zt_tenant_cluster() {
    get_kubeconfig
    mkdir -p "${ZT_TENANT_GENERATED_DIR}"

    validate_zt_tenant_configuration || return 1
    wait_dpfhcp_provisioner_ready || return 1
    wait_dpu_hosted_cluster_healthy || return 1

    ensure_mce_assisted_and_hypershift || return 1
    ensure_hypershift_operator_ready || return 1
    ensure_agent_service_config || return 1
    ensure_metal3_watch_all_namespaces || return 1

    create_tenant_hostedcluster_skip_nodepool || return 1

    local agent_ns
    agent_ns="$(zt_tenant_agent_namespace)"
    create_tenant_pull_secret "${agent_ns}" || return 1
    create_tenant_infraenv || return 1
    apply_tenant_bmhs || return 1

    wait_for_agents_registered || return 1
    label_agents_for_nodepool || return 1
    approve_agents_if_needed || return 1

    ensure_tenant_nodepool || return 1

    write_tenant_kubeconfig || return 1
    wait_tenant_workers_ready || return 1

    log [INFO] "Tenant HostedCluster ${ZT_TENANT_CLUSTER_NAME} is ready; kubeconfig: ${ZT_TENANT_KUBECONFIG}"
}

main() {
    case "${1:-deploy}" in
        deploy)
            deploy_zt_tenant_cluster
            ;;
        validate)
            validate_zt_tenant_configuration
            ;;
        *)
            log [INFO] "Usage: $0 [deploy|validate]"
            exit 1
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
