"""
Worker node provisioning module for OpenShift DPF.

This module provides functions for provisioning worker nodes via BMO/Redfish,
approving CSRs, and monitoring worker status.
"""

import base64
import time
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

from dpf.cluster import get_kubeconfig
from dpf.k8s import K8sClient, get_k8s_client
from dpf.utils import (
    ensure_directory,
    log_debug,
    log_error,
    log_info,
    log_step,
    log_warning,
    process_template,
)

if TYPE_CHECKING:
    from dpf.config import Config


def provision_all_workers(config: "Config") -> bool:
    """
    Provision all worker nodes via BMO.
    
    Args:
        config: Configuration object
    
    Returns:
        True if provisioning was successful or skipped
    """
    worker_count = getattr(config, 'worker_count', 0)
    if worker_count == 0:
        log_info("WORKER_COUNT=0, skipping worker provisioning")
        return True
    
    # Ensure kubeconfig is available
    kubeconfig = get_kubeconfig(config)
    if not kubeconfig:
        log_error("Failed to get kubeconfig")
        return False
    
    k8s = get_k8s_client(kubeconfig_path=kubeconfig)
    
    # Verify baremetal cluster operator is available
    try:
        co = k8s.get_resource(
            api_version="config.openshift.io/v1",
            kind="ClusterOperator",
            name="baremetal",
        )
        if not co:
            log_error("Baremetal cluster operator not found. This should not happen in OpenShift.")
            return False
    except Exception as e:
        log_error(f"Failed to check baremetal operator: {e}")
        return False
    
    # Apply provisioning CR
    worker_template_dir = Path(config.directories.manifests_dir) / "worker-provisioning"
    worker_generated_dir = Path(config.directories.generated_dir) / "worker-provisioning"
    ensure_directory(str(worker_generated_dir))
    
    provisioning_manifest = worker_template_dir / "provisioning.yaml"
    if provisioning_manifest.exists():
        k8s.apply_manifest_file(str(provisioning_manifest))
    
    log_info(f"Provisioning {worker_count} worker(s)...")
    
    for i in range(1, worker_count + 1):
        # Get worker configuration
        worker_config = _get_worker_config(config, i)
        if not worker_config:
            return False
        
        name = worker_config['name']
        
        # Check if BMH already exists (idempotent)
        existing = k8s.get_resource(
            api_version="metal3.io/v1alpha1",
            kind="BareMetalHost",
            name=name,
            namespace="openshift-machine-api",
        )
        if existing:
            log_info(f"BMH {name} already exists, skipping")
            continue
        
        log_info(f"Creating manifests for {name}...")
        
        # Generate BMC secret
        bmc_secret_template = worker_template_dir / "bmc-secret.yaml"
        bmc_secret_output = worker_generated_dir / f"{name}-bmc-secret.yaml"
        
        process_template(
            str(bmc_secret_template),
            str(bmc_secret_output),
            {
                "<WORKER_NAME>": name,
                "<BMC_USER_BASE64>": base64.b64encode(worker_config['bmc_user'].encode()).decode(),
                "<BMC_PASSWORD_BASE64>": base64.b64encode(worker_config['bmc_password'].encode()).decode(),
            }
        )
        
        # Generate BareMetalHost
        bmh_template = worker_template_dir / "baremetalhost.yaml"
        bmh_output = worker_generated_dir / f"{name}-bmh.yaml"
        
        process_template(
            str(bmh_template),
            str(bmh_output),
            {
                "<WORKER_NAME>": name,
                "<BOOT_MAC>": worker_config['boot_mac'],
                "<BMC_IP>": worker_config['bmc_ip'],
                "<ROOT_DEVICE>": worker_config['root_device'],
            }
        )
        
        # Apply manifests
        k8s.apply_manifest_file(str(bmc_secret_output))
        k8s.apply_manifest_file(str(bmh_output))
        log_info(f"BMH {name} created")
    
    log_info("Worker provisioning initiated")
    return True


def _get_worker_config(config: "Config", index: int) -> Optional[dict]:
    """
    Get worker configuration for a specific worker index.
    
    Args:
        config: Configuration object
        index: Worker index (1-based)
    
    Returns:
        Dictionary with worker configuration or None if invalid
    """
    # Try to get worker config from config object
    workers = getattr(config, 'workers', [])
    
    if workers and index <= len(workers):
        worker = workers[index - 1]
        return {
            'name': worker.get('name'),
            'bmc_ip': worker.get('bmc_ip'),
            'bmc_user': worker.get('bmc_user'),
            'bmc_password': worker.get('bmc_password'),
            'boot_mac': worker.get('boot_mac'),
            'root_device': worker.get('root_device', '/dev/sda'),
        }
    
    # Fall back to environment variables pattern
    import os
    name = os.environ.get(f"WORKER_{index}_NAME")
    if not name:
        log_error(f"WORKER_{index}_NAME not set")
        return None
    
    bmc_ip = os.environ.get(f"WORKER_{index}_BMC_IP")
    bmc_user = os.environ.get(f"WORKER_{index}_BMC_USER")
    bmc_password = os.environ.get(f"WORKER_{index}_BMC_PASSWORD")
    boot_mac = os.environ.get(f"WORKER_{index}_BOOT_MAC")
    root_device = os.environ.get(f"WORKER_{index}_ROOT_DEVICE", "/dev/sda")
    
    # Validate required vars
    if not bmc_ip:
        log_error(f"WORKER_{index}_BMC_IP not set")
        return None
    if not bmc_user:
        log_error(f"WORKER_{index}_BMC_USER not set")
        return None
    if not bmc_password:
        log_error(f"WORKER_{index}_BMC_PASSWORD not set")
        return None
    if not boot_mac:
        log_error(f"WORKER_{index}_BOOT_MAC not set")
        return None
    
    return {
        'name': name,
        'bmc_ip': bmc_ip,
        'bmc_user': bmc_user,
        'bmc_password': bmc_password,
        'boot_mac': boot_mac,
        'root_device': root_device,
    }


def approve_worker_csrs(config: "Config") -> int:
    """
    Approve all pending CSRs for worker nodes.
    
    Args:
        config: Configuration object
    
    Returns:
        Number of CSRs approved
    """
    kubeconfig = get_kubeconfig(config)
    if not kubeconfig:
        log_error("Failed to get kubeconfig")
        return 0
    
    k8s = get_k8s_client(kubeconfig_path=kubeconfig)
    
    approved = 0
    
    try:
        # Get all CSRs
        csrs = k8s.list_resources(
            api_version="certificates.k8s.io/v1",
            kind="CertificateSigningRequest",
        )
        
        for csr in csrs:
            name = csr.get('metadata', {}).get('name', '')
            status = csr.get('status', {})
            
            # Check if pending (no conditions in status)
            if not status.get('conditions'):
                try:
                    # Approve the CSR
                    if _approve_csr(k8s, name):
                        log_info(f"Approved CSR {name}")
                        approved += 1
                except Exception as e:
                    log_debug(f"Failed to approve CSR {name}: {e}")
    
    except Exception as e:
        log_error(f"Failed to list CSRs: {e}")
    
    if approved > 0:
        log_info(f"Approved {approved} CSR(s)")
    
    return approved


def _approve_csr(k8s: K8sClient, csr_name: str) -> bool:
    """
    Approve a specific CSR.
    
    Args:
        k8s: Kubernetes client
        csr_name: Name of the CSR to approve
    
    Returns:
        True if approved successfully
    """
    try:
        # Get the CSR
        csr = k8s.get_resource(
            api_version="certificates.k8s.io/v1",
            kind="CertificateSigningRequest",
            name=csr_name,
        )
        
        if not csr:
            return False
        
        # Add approval condition
        csr['status'] = csr.get('status', {})
        csr['status']['conditions'] = [{
            'type': 'Approved',
            'status': 'True',
            'reason': 'DPFApproved',
            'message': 'Approved by OpenShift DPF worker provisioning',
        }]
        
        # Update the CSR approval
        k8s.patch_resource(
            api_version="certificates.k8s.io/v1",
            kind="CertificateSigningRequest",
            name=csr_name,
            patch={"status": csr['status']},
            patch_type="merge",
            subresource="approval",
        )
        
        return True
    except Exception as e:
        log_debug(f"Error approving CSR {csr_name}: {e}")
        return False


def is_worker_registered(k8s: K8sClient, bmh_name: str) -> bool:
    """
    Check if a worker's BMH is in provisioned state.
    
    Args:
        k8s: Kubernetes client
        bmh_name: Name of the BareMetalHost
    
    Returns:
        True if worker is provisioned
    """
    try:
        bmh = k8s.get_resource(
            api_version="metal3.io/v1alpha1",
            kind="BareMetalHost",
            name=bmh_name,
            namespace="openshift-machine-api",
        )
        
        if bmh:
            state = bmh.get('status', {}).get('provisioning', {}).get('state', '')
            return state == 'provisioned'
    except Exception:
        pass
    
    return False


def wait_and_approve_csrs(config: "Config", timeout: int = 600) -> bool:
    """
    Wait for workers to register and approve their CSRs.
    
    Args:
        config: Configuration object
        timeout: Timeout in seconds (default: 600)
    
    Returns:
        True if all workers registered
    """
    kubeconfig = get_kubeconfig(config)
    if not kubeconfig:
        log_error("Failed to get kubeconfig")
        return False
    
    k8s = get_k8s_client(kubeconfig_path=kubeconfig)
    
    worker_count = getattr(config, 'worker_count', 0)
    if worker_count == 0:
        return True
    
    # Get worker names
    worker_names = []
    for i in range(1, worker_count + 1):
        worker_config = _get_worker_config(config, i)
        if worker_config:
            worker_names.append(worker_config['name'])
    
    # Check if all workers already registered
    ready = sum(1 for name in worker_names if is_worker_registered(k8s, name))
    if ready >= worker_count:
        log_info(f"All {worker_count} workers already registered, skipping CSR wait")
        return True
    
    log_info(f"Waiting for CSRs (timeout: {timeout}s)...")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        approve_worker_csrs(config)
        
        # Check if all workers registered
        ready = sum(1 for name in worker_names if is_worker_registered(k8s, name))
        
        if ready >= worker_count:
            log_info(f"All {worker_count} workers registered")
            return True
        
        time.sleep(30)
    
    log_warning("Timeout - some workers may need manual CSR approval")
    return False


def display_worker_status(config: "Config") -> None:
    """
    Display worker status information.
    
    Args:
        config: Configuration object
    """
    kubeconfig = get_kubeconfig(config)
    if not kubeconfig:
        log_error("Failed to get kubeconfig")
        return
    
    k8s = get_k8s_client(kubeconfig_path=kubeconfig)
    
    print("=== Worker Status ===")
    
    # Get BMHs
    try:
        bmhs = k8s.list_resources(
            api_version="metal3.io/v1alpha1",
            kind="BareMetalHost",
            namespace="openshift-machine-api",
        )
        
        if bmhs:
            print(f"{'NAME':<30} {'STATE':<15} {'PROVISIONING':<15}")
            print("-" * 60)
            for bmh in bmhs:
                name = bmh.get('metadata', {}).get('name', '')
                state = bmh.get('status', {}).get('provisioning', {}).get('state', 'unknown')
                online = "Yes" if bmh.get('status', {}).get('poweredOn') else "No"
                print(f"{name:<30} {state:<15} {online:<15}")
        else:
            print("No BareMetalHosts found")
    except Exception as e:
        print(f"Error listing BMHs: {e}")
    
    print("")
    print("=== Nodes ===")
    
    # Get nodes
    try:
        nodes = k8s.list_resources(
            api_version="v1",
            kind="Node",
        )
        
        if nodes:
            print(f"{'NAME':<40} {'STATUS':<15} {'ROLES':<20}")
            print("-" * 75)
            for node in nodes:
                name = node.get('metadata', {}).get('name', '')
                labels = node.get('metadata', {}).get('labels', {})
                roles = []
                for label in labels:
                    if label.startswith('node-role.kubernetes.io/'):
                        roles.append(label.split('/')[-1])
                
                conditions = node.get('status', {}).get('conditions', [])
                ready = "Ready" if any(
                    c.get('type') == 'Ready' and c.get('status') == 'True'
                    for c in conditions
                ) else "NotReady"
                
                print(f"{name:<40} {ready:<15} {','.join(roles) or 'none':<20}")
        else:
            print("No nodes found")
    except Exception as e:
        print(f"Error listing nodes: {e}")


def display_manual_csr_instructions() -> None:
    """Display instructions for manual CSR approval."""
    print("")
    print("To approve CSRs manually:")
    print("  oc get csr | grep Pending")
    print("  oc adm certificate approve <csr-name>")
    print("Or: dpf worker approve-csrs")

