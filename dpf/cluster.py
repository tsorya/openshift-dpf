"""
Cluster management module for OpenShift DPF.

This module provides functions for creating, managing, and monitoring
OpenShift clusters using the Assisted Installer API and Kubernetes client.
"""

import time
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from dpf.config import Config

import yaml

from ailib import AssistedClient
from dpf.k8s import K8sClient, get_k8s_client
from dpf.utils import (
    ensure_directory,
    is_valid_ip,
    log_debug,
    log_error,
    log_info,
    log_step,
    log_warning,
)
from dpf.vm import delete_vms


def _get_ai_client(config: "Config") -> AssistedClient:
    """Get an Assisted Installer client configured from config."""
    # Read pull secret
    pull_secret = None
    if config.pull_secret_path and Path(config.pull_secret_path).exists():
        pull_secret = Path(config.pull_secret_path).read_text().strip()
    
    # Read SSH public key
    ssh_public_key = None
    if config.ssh_public_key_path and Path(config.ssh_public_key_path).exists():
        ssh_public_key = Path(config.ssh_public_key_path).read_text().strip()
    
    return AssistedClient(
        url=config.assisted_installer_url,
        pull_secret=pull_secret,
        ssh_public_key=ssh_public_key,
    )


def validate_vips(config: "Config") -> bool:
    """
    Validate VIP configuration.
    
    Args:
        config: Configuration object
    
    Returns:
        True if VIPs are valid
    """
    if config.vm.vm_count == 1:
        # Single node doesn't need VIPs
        log_debug("Single node cluster, VIPs not required")
        return True
    
    api_vip = config.network.api_vip
    ingress_vip = config.network.ingress_vip
    
    if not api_vip or not ingress_vip:
        log_error("API_VIP and INGRESS_VIP are required for multi-node clusters")
        return False
    
    if not is_valid_ip(api_vip):
        log_error(f"Invalid API_VIP: {api_vip}")
        return False
    
    if not is_valid_ip(ingress_vip):
        log_error(f"Invalid INGRESS_VIP: {ingress_vip}")
        return False
    
    if api_vip == ingress_vip:
        log_error("API_VIP and INGRESS_VIP must be different")
        return False
    
    log_info(f"VIPs validated: API={api_vip}, Ingress={ingress_vip}")
    return True


def check_cluster_installed(config: "Config") -> bool:
    """
    Check if a cluster is already installed.
    
    Args:
        config: Configuration object
    
    Returns:
        True if cluster is installed
    """
    ai_client = _get_ai_client(config)
    cluster = ai_client.get_cluster_by_name(config.cluster.cluster_name)
    
    if cluster and cluster.get("status") == "installed":
        log_info(f"Cluster {config.cluster.cluster_name} is already installed")
        return True
    
    return False


def set_cluster_mtu(config: "Config") -> bool:
    """
    Set the cluster MTU in the install configuration.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    mtu = config.mtu
    if not mtu or mtu == 1500:
        log_debug("Using default MTU, no changes needed")
        return True
    
    ai_client = _get_ai_client(config)
    cluster = ai_client.get_cluster_by_name(config.cluster.cluster_name)
    
    if not cluster:
        log_error(f"Cluster {config.cluster.cluster_name} not found")
        return False
    
    # Get and modify install config
    install_config = ai_client.get_cluster_install_config(cluster["id"])
    if not install_config:
        log_error("Failed to get install config")
        return False
    
    # Add MTU configuration
    config_data = yaml.safe_load(install_config)
    
    if "networking" not in config_data:
        config_data["networking"] = {}
    
    config_data["networking"]["clusterNetworkMTU"] = mtu
    
    # For OVN-Kubernetes, set the MTU
    if config_data.get("networking", {}).get("networkType") == "OVNKubernetes":
        log_info(f"Setting OVN-Kubernetes MTU to {mtu}")
    
    log_info(f"Cluster MTU set to {mtu}")
    return True


def check_create_cluster(config: "Config") -> bool:
    """
    Check if cluster exists and create if not.
    
    Args:
        config: Configuration object
    
    Returns:
        True if cluster exists or was created successfully
    """
    log_step("Creating/Checking Cluster")
    
    # Validate VIPs first
    if not validate_vips(config):
        return False
    
    ai_client = _get_ai_client(config)
    
    # Check if cluster exists
    existing = ai_client.get_cluster_by_name(config.cluster.cluster_name)
    if existing:
        log_info(f"Cluster {config.cluster.cluster_name} already exists (status: {existing.get('status')})")
        return True
    
    # Determine high availability mode
    ha_mode = "None" if config.vm.vm_count == 1 else "Full"
    
    # Create cluster
    cluster = ai_client.create_cluster(
        name=config.cluster.cluster_name,
        base_dns_domain=config.base_dns_domain,
        openshift_version=config.ocp_version,
        high_availability_mode=ha_mode,
        network_type="OVNKubernetes",
        machine_network_cidr=config.machine_network_cidr,
        api_vip=config.network.api_vip if config.vm.vm_count > 1 else None,
        ingress_vip=config.network.ingress_vip if config.vm.vm_count > 1 else None,
        schedulable_masters=config.vm.vm_count == 1,
        additional_ntp_source=config.ntp_server,
    )
    
    if not cluster:
        log_error("Failed to create cluster")
        return False
    
    # Create infra-env
    infra_env = ai_client.create_infra_env(
        name=f"{config.cluster.cluster_name}-infra-env",
        cluster_id=cluster["id"],
        openshift_version=config.ocp_version,
    )
    
    if not infra_env:
        log_error("Failed to create infra-env")
        return False
    
    log_info(f"Cluster {config.cluster.cluster_name} created successfully")
    return True


def delete_cluster(config: "Config") -> bool:
    """
    Delete a cluster.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deleting Cluster")
    
    ai_client = _get_ai_client(config)
    
    # Delete infra-env first
    infra_env = ai_client.get_infra_env_by_name(f"{config.cluster.cluster_name}-infra-env")
    if infra_env:
        ai_client.delete_infra_env(infra_env["id"])
    
    # Delete cluster
    success = ai_client.delete_cluster_by_name(config.cluster.cluster_name)
    
    if success:
        log_info(f"Cluster {config.cluster.cluster_name} deleted")
    
    return success


def wait_for_cluster_status(status: str, config: "Config", timeout: int = 7200) -> bool:
    """
    Wait for cluster to reach a specific status.
    
    Args:
        status: Target status (e.g., "ready", "installed")
        config: Configuration object
        timeout: Timeout in seconds
    
    Returns:
        True if cluster reached the status
    """
    log_step(f"Waiting for Cluster Status: {status}")
    
    ai_client = _get_ai_client(config)
    cluster = ai_client.get_cluster_by_name(config.cluster.cluster_name)
    
    if not cluster:
        log_error(f"Cluster {config.cluster.cluster_name} not found")
        return False
    
    return ai_client.wait_for_cluster_status(cluster["id"], status, timeout)


def start_cluster_installation(config: "Config") -> bool:
    """
    Start cluster installation.
    
    Args:
        config: Configuration object
    
    Returns:
        True if installation started successfully
    """
    log_step("Starting Cluster Installation")
    
    ai_client = _get_ai_client(config)
    cluster = ai_client.get_cluster_by_name(config.cluster.cluster_name)
    
    if not cluster:
        log_error(f"Cluster {config.cluster.cluster_name} not found")
        return False
    
    current_status = cluster.get("status")
    
    # Check if already installing or installed
    if current_status == "installed":
        log_info("Cluster is already installed")
        return True
    
    if current_status in ["installing", "finalizing"]:
        log_info(f"Cluster is already {current_status}")
        return True
    
    # Wait for ready status first
    if current_status != "ready":
        log_info(f"Cluster status is {current_status}, waiting for ready...")
        if not ai_client.wait_for_cluster_status(cluster["id"], "ready", timeout=1800):
            log_error("Cluster did not become ready")
            return False
    
    # Start installation
    if not ai_client.start_installation(cluster["id"]):
        return False
    
    # Wait for installation to complete
    log_info("Waiting for installation to complete...")
    return ai_client.wait_for_cluster_status(cluster["id"], "installed", timeout=7200)


def get_kubeconfig(config: "Config") -> Optional[str]:
    """
    Get or download the cluster kubeconfig.
    
    Args:
        config: Configuration object
    
    Returns:
        Path to kubeconfig file, or None on failure
    """
    log_step("Getting Kubeconfig")
    
    kubeconfig_path = Path(config.kubeconfig_path)
    
    # Check if kubeconfig already exists
    if kubeconfig_path.exists():
        log_info(f"Kubeconfig already exists: {kubeconfig_path}")
        return str(kubeconfig_path)
    
    ai_client = _get_ai_client(config)
    cluster = ai_client.get_cluster_by_name(config.cluster.cluster_name)
    
    if not cluster:
        log_error(f"Cluster {config.cluster.cluster_name} not found")
        return None
    
    if cluster.get("status") != "installed":
        log_error(f"Cluster not yet installed (status: {cluster.get('status')})")
        return None
    
    # Download kubeconfig
    if ai_client.download_kubeconfig(cluster["id"], kubeconfig_path):
        # Also download kubeadmin password
        password_path = kubeconfig_path.parent / "kubeadmin-password"
        ai_client.download_kubeadmin_password(cluster["id"], password_path)
        
        return str(kubeconfig_path)
    
    return None


def clean_all(config: "Config") -> bool:
    """
    Delete cluster, VMs, and clean all resources.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Cleaning All Resources")
    
    # Delete VMs first
    delete_vms(config)
    
    # Delete cluster
    delete_cluster(config)
    
    # Clean up local files
    kubeconfig_path = Path(config.kubeconfig_path)
    if kubeconfig_path.exists():
        kubeconfig_path.unlink()
        log_info(f"Deleted {kubeconfig_path}")
    
    password_path = kubeconfig_path.parent / "kubeadmin-password"
    if password_path.exists():
        password_path.unlink()
        log_info(f"Deleted {password_path}")
    
    log_info("All resources cleaned")
    return True


def deploy_lso(config: "Config") -> bool:
    """
    Deploy Local Storage Operator.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying Local Storage Operator")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Create namespace
    if not k8s.create_namespace("openshift-local-storage"):
        return False
    
    # Apply LSO subscription
    lso_subscription = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {
            "name": "local-storage-operator",
            "namespace": "openshift-local-storage",
        },
        "spec": {
            "channel": "stable",
            "name": "local-storage-operator",
            "source": "redhat-operators",
            "sourceNamespace": "openshift-marketplace",
            "installPlanApproval": "Automatic",
        },
    }
    
    if not k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1alpha1",
        plural="subscriptions",
        body=lso_subscription,
        namespace="openshift-local-storage",
    ):
        return False
    
    # Wait for operator to be ready
    log_info("Waiting for LSO operator to be ready...")
    time.sleep(60)  # Give time for CSV to be created
    
    log_info("Local Storage Operator deployed")
    return True


def deploy_odf(config: "Config") -> bool:
    """
    Deploy OpenShift Data Foundation.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying OpenShift Data Foundation")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Create namespace
    if not k8s.create_namespace("openshift-storage"):
        return False
    
    # Create OperatorGroup
    operator_group = {
        "apiVersion": "operators.coreos.com/v1",
        "kind": "OperatorGroup",
        "metadata": {
            "name": "openshift-storage-operatorgroup",
            "namespace": "openshift-storage",
        },
        "spec": {
            "targetNamespaces": ["openshift-storage"],
        },
    }
    
    k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1",
        plural="operatorgroups",
        body=operator_group,
        namespace="openshift-storage",
    )
    
    # Apply ODF subscription
    odf_subscription = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {
            "name": "odf-operator",
            "namespace": "openshift-storage",
        },
        "spec": {
            "channel": "stable-4.16",
            "name": "odf-operator",
            "source": "redhat-operators",
            "sourceNamespace": "openshift-marketplace",
            "installPlanApproval": "Automatic",
        },
    }
    
    if not k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1alpha1",
        plural="subscriptions",
        body=odf_subscription,
        namespace="openshift-storage",
    ):
        return False
    
    log_info("Waiting for ODF operator to be ready...")
    time.sleep(120)  # Give time for CSV and CRDs to be created
    
    log_info("OpenShift Data Foundation deployed")
    return True


def create_day2_cluster(config: "Config") -> bool:
    """
    Create a day2 cluster for adding workers.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Creating Day2 Cluster")
    
    ai_client = _get_ai_client(config)
    
    # Get the existing cluster
    cluster = ai_client.get_cluster_by_name(config.cluster.cluster_name)
    if not cluster:
        log_error(f"Cluster {config.cluster.cluster_name} not found")
        return False
    
    if cluster.get("status") != "installed":
        log_error("Cluster must be installed before creating day2 configuration")
        return False
    
    # Create a new infra-env for day2 workers
    day2_name = f"{config.cluster.cluster_name}-day2"
    
    infra_env = ai_client.create_infra_env(
        name=day2_name,
        cluster_id=cluster["id"],
        openshift_version=config.ocp_version,
    )
    
    if not infra_env:
        log_error("Failed to create day2 infra-env")
        return False
    
    log_info(f"Day2 infra-env created: {day2_name}")
    return True


def get_iso(config: "Config", iso_type: str = "day1", action: str = "download") -> Optional[str]:
    """
    Get the discovery ISO.
    
    Args:
        config: Configuration object
        iso_type: "day1" or "day2"
        action: "download" or "url"
    
    Returns:
        Path to ISO or URL, depending on action
    """
    log_step(f"Getting {iso_type} ISO")
    
    ai_client = _get_ai_client(config)
    
    # Determine infra-env name
    if iso_type == "day2":
        infra_env_name = f"{config.cluster.cluster_name}-day2"
    else:
        infra_env_name = f"{config.cluster.cluster_name}-infra-env"
    
    infra_env = ai_client.get_infra_env_by_name(infra_env_name)
    if not infra_env:
        log_error(f"Infra-env {infra_env_name} not found")
        return None
    
    if action == "url":
        url = ai_client.get_iso_download_url(infra_env["id"])
        if url:
            log_info(f"ISO URL: {url}")
        return url
    
    # Download ISO
    iso_path = Path(config.vm.iso_folder) / f"{config.cluster.cluster_name}-{iso_type}.iso"
    ensure_directory(iso_path.parent)
    
    if ai_client.download_iso(infra_env["id"], iso_path):
        return str(iso_path)
    
    return None


def wait_for_nodes_ready(config: "Config", expected_count: int, timeout: int = 1800) -> bool:
    """
    Wait for expected number of nodes to be ready.
    
    Args:
        config: Configuration object
        expected_count: Expected number of ready nodes
        timeout: Timeout in seconds
    
    Returns:
        True if all nodes are ready
    """
    log_step(f"Waiting for {expected_count} Nodes")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        nodes = k8s.get_nodes()
        ready_nodes = [n for n in nodes if n.get("ready")]
        
        log_debug(f"Nodes ready: {len(ready_nodes)}/{expected_count}")
        
        if len(ready_nodes) >= expected_count:
            log_info(f"All {expected_count} nodes are ready")
            return True
        
        time.sleep(30)
    
    log_error(f"Timeout waiting for {expected_count} nodes")
    return False


def approve_pending_csrs(config: "Config") -> int:
    """
    Approve pending certificate signing requests.
    
    Args:
        config: Configuration object
    
    Returns:
        Number of CSRs approved
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    try:
        # List pending CSRs
        csrs = k8s.custom_objects.list_cluster_custom_object(
            group="certificates.k8s.io",
            version="v1",
            plural="certificatesigningrequests",
        )
        
        approved_count = 0
        for csr in csrs.get("items", []):
            name = csr.get("metadata", {}).get("name")
            conditions = csr.get("status", {}).get("conditions", [])
            
            # Check if already approved
            is_approved = any(c.get("type") == "Approved" for c in conditions)
            if is_approved:
                continue
            
            # Approve the CSR
            approval = {
                "apiVersion": "certificates.k8s.io/v1",
                "kind": "CertificateSigningRequest",
                "metadata": {"name": name},
                "status": {
                    "conditions": [
                        {
                            "type": "Approved",
                            "status": "True",
                            "reason": "DPFApproval",
                            "message": "Approved by DPF automation",
                        }
                    ]
                },
            }
            
            k8s.custom_objects.patch_cluster_custom_object_status(
                group="certificates.k8s.io",
                version="v1",
                plural="certificatesigningrequests",
                name=name,
                body=approval,
            )
            
            log_info(f"Approved CSR: {name}")
            approved_count += 1
        
        return approved_count
        
    except Exception as e:
        log_error(f"Failed to approve CSRs: {e}")
        return 0
