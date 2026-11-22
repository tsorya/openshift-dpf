#!/usr/bin/env bash
# enable-kata-tenant.sh — install Kata Containers on a Zero Trust tenant HostedCluster
#
# The tenant HostedCluster has no MachineConfig/MachineConfigPool API, so the
# OpenShift path (OSC + KataConfig, scripts/enable-kata.sh) is unavailable. This
# uses the upstream kata-deploy DaemonSet instead: it writes the kata tree to the
# host filesystem and registers the CRI handler itself. `install` never returns
# by design, so it must run as a DaemonSet and not as a Job.
#
# Usage:
#   scripts/enable-kata-tenant.sh enable    # deploy kata-deploy, fix SELinux, verify
#   scripts/enable-kata-tenant.sh verify    # check RuntimeClasses, labels, SELinux
#
# Runs against ZT_TENANT_KUBECONFIG (default: tenant.kubeconfig).
#
set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/utils.sh
source "${SCRIPT_DIR}/utils.sh"

KATA_TENANT_NAMESPACE="kata-deploy"
KATA_TENANT_VERSION="${ZT_TENANT_KATA_VERSION:-3.32.0}"
KATA_TENANT_RUNTIME_CLASS="${ARGUS_GTC_KATA_RUNTIME_CLASS:-kata}"

tenant_oc() {
    oc --kubeconfig "${ZT_TENANT_KUBECONFIG}" "$@"
}

require_tenant_kubeconfig() {
    if [ ! -f "${ZT_TENANT_KUBECONFIG}" ]; then
        log [ERROR] "Tenant kubeconfig ${ZT_TENANT_KUBECONFIG} not found; deploy the tenant cluster first"
        return 1
    fi
    if ! tenant_oc get nodes &>/dev/null; then
        log [ERROR] "Cannot reach the tenant cluster with ${ZT_TENANT_KUBECONFIG}"
        return 1
    fi
}

tenant_nodes() {
    tenant_oc get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
}

# Run a shell snippet in the host mount namespace of a tenant node. The debug
# pod defaults to the node's own (likely absent) namespace, so pin one that
# always exists.
host_cmd() {
    local node="$1"
    shift
    tenant_oc debug "node/${node}" --to-namespace=default --quiet -- chroot /host bash -c "$*"
}

check_kvm() {
    local node rc=0
    for node in $(tenant_nodes); do
        if host_cmd "${node}" 'test -e /dev/kvm' &>/dev/null; then
            log [INFO] "${node}: /dev/kvm present"
        else
            log [WARN] "${node}: /dev/kvm missing; Kata workloads cannot start on this node"
            rc=1
        fi
    done
    return "${rc}"
}

deploy_kata_deploy() {
    local out="${ZT_TENANT_GENERATED_DIR}/kata-deploy.yaml"
    mkdir -p "${ZT_TENANT_GENERATED_DIR}"

    process_template \
        "${MANIFESTS_DIR}/zt-tenant/kata-deploy-template.yaml" \
        "${out}" \
        "<KATA_VERSION>" "${KATA_TENANT_VERSION}"

    log [INFO] "Applying kata-deploy (kata-containers ${KATA_TENANT_VERSION}) to the tenant cluster..."
    tenant_oc apply -f "${out}"

    log [INFO] "Waiting for the kata-deploy DaemonSet to roll out..."
    if ! tenant_oc rollout status "ds/kata-deploy" -n "${KATA_TENANT_NAMESPACE}" --timeout=10m; then
        log [ERROR] "kata-deploy did not become ready"
        tenant_oc get pods -n "${KATA_TENANT_NAMESPACE}" -o wide || true
        return 1
    fi
}

# SELinux is the gate that actually breaks Kata on RHCOS. The sandbox QEMU runs
# as container_kvm_t:s0:<categories>, and an MCS-categorised domain cannot read
# an uncategorised var_t file. RHCOS models /opt as a symlink to var/opt, so the
# stock fcontext rules for /opt/.../bin never match the canonical path and the
# tree kata-deploy extracts stays var_t: the firmware open then fails with the
# misleading "qemu: could not load PC BIOS 'bios-256k.bin'". Recording the rules
# in the node policy store survives relabel and reboot, but not node re-creation.
relabel_script() {
    cat <<'EOF'
set -e
if command -v semanage >/dev/null 2>&1; then
    for path in /var/opt/kata/bin /var/opt/kata/libexec; do
        semanage fcontext -a -t bin_t "${path}(/.*)?" || \
            semanage fcontext -m -t bin_t "${path}(/.*)?"
    done
    semanage fcontext -a -t container_ro_file_t '/var/opt/kata/share(/.*)?' || \
        semanage fcontext -m -t container_ro_file_t '/var/opt/kata/share(/.*)?'
    restorecon -RF /var/opt/kata
else
    # No policy store CLI on this image: label in place. Works until the next
    # relabel drops the tree back to var_t.
    chcon -R -t bin_t /var/opt/kata/bin /var/opt/kata/libexec
    chcon -R -t container_ro_file_t /var/opt/kata/share
fi
EOF
}

relabel_kata_paths() {
    local node
    for node in $(tenant_nodes); do
        log [INFO] "${node}: labelling /var/opt/kata"
        host_cmd "${node}" "$(relabel_script)" || {
            log [ERROR] "${node}: failed to label the kata tree"
            return 1
        }
    done
}

verify_kata() {
    local node rc=0 labels
    log [INFO] "RuntimeClasses on the tenant cluster:"
    tenant_oc get runtimeclass || rc=1
    log [INFO] "Nodes labelled for Kata:"
    tenant_oc get nodes -L katacontainers.io/kata-runtime || rc=1
    for node in $(tenant_nodes); do
        labels=$(host_cmd "${node}" \
            'ls -Zd /var/opt/kata/bin /var/opt/kata/libexec /var/opt/kata/share' || true)
        log [INFO] "${node} SELinux labels:"$'\n'"${labels}"
        if [ -z "${labels}" ] || echo "${labels}" | grep -q ':var_t:'; then
            log [WARN] "${node}: the kata tree is missing or still var_t; Kata pods will fail there"
            rc=1
        fi
    done
    return "${rc}"
}

enable_kata_tenant() {
    require_tenant_kubeconfig || return 1
    check_kvm || log [WARN] "Continuing without /dev/kvm on every node"
    deploy_kata_deploy || return 1
    relabel_kata_paths || return 1
    verify_kata || return 1
    log [INFO] "Kata is ready on the tenant cluster; use runtimeClassName: ${KATA_TENANT_RUNTIME_CLASS} (kata-qemu is equivalent)"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-enable}" in
    enable) enable_kata_tenant ;;
    verify)
        require_tenant_kubeconfig && verify_kata
        ;;
    *)
        echo "Usage: $0 {enable|verify}" >&2
        exit 1
        ;;
    esac
fi
