"""
Post-installation module for OpenShift DPF.

This module provides functions for post-installation configuration
including BFB, HBN OVN, DPU services, and DPUDeployment using
the Kubernetes Python client.
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from dpf.k8s import K8sClient, get_k8s_client
from dpf.utils import (
    log_info,
    log_error,
    log_warning,
    log_debug,
    log_step,
    file_exists,
    read_file,
    write_file,
    ensure_directory,
    load_yaml,
    save_yaml,
    copy_file,
    copy_directory,
)


def update_bfb_manifest(config: Any) -> bool:
    """
    Update BFB manifest with configuration values.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_info("Updating BFB manifest")
    
    output_dir = Path(config.output_dir) / "post-install"
    ensure_directory(output_dir)
    
    # Create BFB manifest
    bfb_manifest = {
        "apiVersion": "svc.dpu.nvidia.com/v1alpha1",
        "kind": "BFB",
        "metadata": {
            "name": config.bfb_name,
            "namespace": config.dpf_namespace,
        },
        "spec": {
            "url": config.bfb_url,
        },
    }
    
    output_path = output_dir / "bfb.yaml"
    save_yaml(output_path, bfb_manifest)
    
    log_debug(f"BFB manifest saved to {output_path}")
    return True


def update_hbn_ovn_manifests(config: Any) -> bool:
    """
    Update HBN OVN manifests with configuration values.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_info("Updating HBN OVN manifests")
    
    output_dir = Path(config.output_dir) / "post-install"
    ensure_directory(output_dir)
    
    # HBN OVN image manifest
    hbn_ovn_image = {
        "apiVersion": "svc.dpu.nvidia.com/v1alpha1",
        "kind": "DPUServiceImage",
        "metadata": {
            "name": "hbn-ovn-image",
            "namespace": config.dpf_namespace,
        },
        "spec": {
            "image": config.hbn_ovn_image,
            "version": config.hbn_ovn_version,
        },
    }
    
    output_path = output_dir / "hbn-ovn-image.yaml"
    save_yaml(output_path, hbn_ovn_image)
    
    # HBN OVN service chain
    hbn_service_chain = {
        "apiVersion": "svc.dpu.nvidia.com/v1alpha1",
        "kind": "DPUServiceChain",
        "metadata": {
            "name": "hbn-service-chain",
            "namespace": config.dpf_namespace,
        },
        "spec": {
            "template": {
                "spec": {
                    "switches": [
                        {
                            "ports": [
                                {"serviceInterface": {"matchLabels": {"svc.dpu.nvidia.com/interface": "p0-hbn"}}},
                                {"serviceInterface": {"matchLabels": {"svc.dpu.nvidia.com/interface": "pf0hpf-hbn"}}},
                            ],
                        },
                    ],
                },
            },
        },
    }
    
    output_path = output_dir / "hbn-service-chain.yaml"
    save_yaml(output_path, hbn_service_chain)
    
    log_debug("HBN OVN manifests saved")
    return True


def update_vf_configuration(config: Any) -> bool:
    """
    Update VF configuration manifest.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_info("Updating VF configuration")
    
    output_dir = Path(config.output_dir) / "post-install"
    ensure_directory(output_dir)
    
    # DPU Service Interface
    service_interface = {
        "apiVersion": "svc.dpu.nvidia.com/v1alpha1",
        "kind": "DPUServiceInterface",
        "metadata": {
            "name": "pf0-vf-config",
            "namespace": config.dpf_namespace,
        },
        "spec": {
            "template": {
                "spec": {
                    "interfaceType": "vf",
                    "vf": {
                        "pfNames": ["p0#0-15"],
                    },
                },
            },
        },
    }
    
    output_path = output_dir / "vf-configuration.yaml"
    save_yaml(output_path, service_interface)
    
    log_debug(f"VF configuration saved to {output_path}")
    return True


def update_service_templates(config: Any) -> bool:
    """
    Update DPU service templates.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_info("Updating service templates")
    
    output_dir = Path(config.output_dir) / "post-install"
    ensure_directory(output_dir)
    
    # HBN Service Template
    hbn_template = {
        "apiVersion": "svc.dpu.nvidia.com/v1alpha1",
        "kind": "DPUServiceTemplate",
        "metadata": {
            "name": "hbn-service-template",
            "namespace": config.dpf_namespace,
        },
        "spec": {
            "deploymentServiceName": "hbn-dpu-service",
            "helmChart": {
                "source": {
                    "repoURL": config.hbn_helm_repo,
                    "path": config.hbn_helm_chart_path,
                    "version": config.hbn_helm_chart_version,
                },
                "values": {
                    "mtu": config.mtu,
                },
            },
        },
    }
    
    save_yaml(output_dir / "hbn-service-template.yaml", hbn_template)
    
    # DTS Service Template
    dts_template = {
        "apiVersion": "svc.dpu.nvidia.com/v1alpha1",
        "kind": "DPUServiceTemplate",
        "metadata": {
            "name": "dts-service-template",
            "namespace": config.dpf_namespace,
        },
        "spec": {
            "deploymentServiceName": "dts-dpu-service",
            "helmChart": {
                "source": {
                    "repoURL": config.dts_helm_repo,
                    "path": config.dts_helm_chart_path,
                    "version": config.dts_helm_chart_version,
                },
            },
        },
    }
    
    save_yaml(output_dir / "dts-service-template.yaml", dts_template)
    
    log_debug("Service templates saved")
    return True


def update_dpu_deployment(config: Any) -> bool:
    """
    Update DPUDeployment manifest.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_info("Updating DPUDeployment")
    
    output_dir = Path(config.output_dir) / "post-install"
    ensure_directory(output_dir)
    
    # DPUDeployment
    dpu_deployment = {
        "apiVersion": "provisioning.dpu.nvidia.com/v1alpha1",
        "kind": "DPUDeployment",
        "metadata": {
            "name": "dpu-deployment",
            "namespace": config.dpf_namespace,
        },
        "spec": {
            "dpus": {
                "bfb": {
                    "name": config.bfb_name,
                },
                "dpuFlavor": "bf3",
            },
            "services": {
                "hbnServiceChain": "hbn-service-chain",
                "serviceChains": [
                    {
                        "name": "hbn-service-chain",
                        "template": "hbn-service-template",
                    },
                ],
            },
        },
    }
    
    save_yaml(output_dir / "dpu-deployment.yaml", dpu_deployment)
    
    log_debug("DPUDeployment manifest saved")
    return True


def prepare_post_installation(config: Any) -> bool:
    """
    Prepare all post-installation manifests.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Preparing Post-Installation Manifests")
    
    steps = [
        ("BFB", lambda: update_bfb_manifest(config)),
        ("HBN OVN", lambda: update_hbn_ovn_manifests(config)),
        ("VF Config", lambda: update_vf_configuration(config)),
        ("Service Templates", lambda: update_service_templates(config)),
        ("DPU Deployment", lambda: update_dpu_deployment(config)),
    ]
    
    for step_name, step_func in steps:
        log_debug(f"Preparing: {step_name}")
        if not step_func():
            log_error(f"Failed to prepare: {step_name}")
            return False
    
    log_info("Post-installation manifests prepared")
    return True


def apply_post_installation(config: Any) -> bool:
    """
    Apply post-installation manifests to the cluster.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Applying Post-Installation Manifests")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    manifests_dir = Path(config.output_dir) / "post-install"
    
    if not manifests_dir.exists():
        log_error(f"Post-install manifests directory not found: {manifests_dir}")
        log_error("Run 'dpf post-install prepare' first")
        return False
    
    # Ensure namespace exists
    if not k8s.create_namespace(config.dpf_namespace):
        return False
    
    # Wait for DPF operator to be ready
    log_info("Waiting for DPF operator webhooks...")
    if not wait_for_dpf_webhooks(k8s, timeout=120):
        log_warning("DPF webhooks may not be ready, continuing...")
    
    # Apply manifests in order
    manifest_order = [
        "bfb.yaml",
        "hbn-ovn-image.yaml",
        "vf-configuration.yaml",
        "hbn-service-chain.yaml",
        "hbn-service-template.yaml",
        "dts-service-template.yaml",
        "dpu-deployment.yaml",
    ]
    
    for manifest_name in manifest_order:
        manifest_path = manifests_dir / manifest_name
        if manifest_path.exists():
            log_info(f"Applying: {manifest_name}")
            if not k8s.apply_yaml_file(manifest_path):
                log_error(f"Failed to apply: {manifest_name}")
                return False
            # Small delay between manifests
            time.sleep(2)
    
    # Also apply any additional manifests
    for manifest_path in sorted(manifests_dir.glob("*.yaml")):
        if manifest_path.name not in manifest_order:
            log_info(f"Applying: {manifest_path.name}")
            k8s.apply_yaml_file(manifest_path)
    
    log_info("Post-installation manifests applied")
    return True


def wait_for_dpf_webhooks(k8s: K8sClient, timeout: int = 120) -> bool:
    """
    Wait for DPF operator webhooks to be ready.
    
    Args:
        k8s: Kubernetes client
        timeout: Timeout in seconds
    
    Returns:
        True if webhooks are ready
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        # Check if webhook deployment is ready
        deployment = k8s.get_deployment(
            "dpf-operator-controller-manager",
            "dpf-operator-system",
        )
        
        if deployment and deployment.get("ready"):
            return True
        
        time.sleep(5)
    
    return False


def redeploy(config: Any) -> bool:
    """
    Redeploy DPU services (delete and recreate).
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Redeploying DPU Services")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Delete DPUDeployment
    log_info("Deleting existing DPUDeployment...")
    k8s.delete_custom_resource(
        group="provisioning.dpu.nvidia.com",
        version="v1alpha1",
        plural="dpudeployments",
        name="dpu-deployment",
        namespace=config.dpf_namespace,
    )
    
    # Wait for deletion
    time.sleep(10)
    
    # Delete service chains
    log_info("Deleting service chains...")
    k8s.delete_custom_resource(
        group="svc.dpu.nvidia.com",
        version="v1alpha1",
        plural="dpuservicechains",
        name="hbn-service-chain",
        namespace=config.dpf_namespace,
    )
    
    # Wait for cleanup
    log_info("Waiting for resources to be cleaned up...")
    time.sleep(30)
    
    # Re-apply manifests
    return apply_post_installation(config)


def get_dpu_status(config: Any) -> List[Dict[str, Any]]:
    """
    Get status of DPUs.
    
    Args:
        config: Configuration object
    
    Returns:
        List of DPU status dictionaries
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    dpus = k8s.list_custom_resources(
        group="provisioning.dpu.nvidia.com",
        version="v1alpha1",
        plural="dpus",
        namespace=config.dpf_namespace,
    )
    
    results = []
    for dpu in dpus:
        metadata = dpu.get("metadata", {})
        status = dpu.get("status", {})
        
        results.append({
            "name": metadata.get("name"),
            "phase": status.get("phase"),
            "conditions": status.get("conditions", []),
        })
    
    return results


def wait_for_dpus_ready(config: Any, timeout: int = 1800) -> bool:
    """
    Wait for DPUs to be ready.
    
    Args:
        config: Configuration object
        timeout: Timeout in seconds
    
    Returns:
        True if all DPUs are ready
    """
    log_step("Waiting for DPUs to be Ready")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        dpus = get_dpu_status(config)
        
        if not dpus:
            log_debug("No DPUs found yet...")
            time.sleep(30)
            continue
        
        all_ready = True
        for dpu in dpus:
            phase = dpu.get("phase")
            if phase != "Ready":
                all_ready = False
                log_debug(f"DPU {dpu['name']} is {phase}")
        
        if all_ready:
            log_info(f"All {len(dpus)} DPUs are ready")
            return True
        
        time.sleep(30)
    
    log_error("Timeout waiting for DPUs to be ready")
    return False


def get_hosted_cluster_kubeconfig(config: Any) -> Optional[str]:
    """
    Get the hosted cluster kubeconfig from secret.
    
    Args:
        config: Configuration object
    
    Returns:
        Kubeconfig content or None
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    hosted_cluster_name = config.hosted_cluster_name
    namespace = f"clusters-{hosted_cluster_name}"
    secret_name = f"{hosted_cluster_name}-admin-kubeconfig"
    
    secret = k8s.get_secret(secret_name, namespace)
    
    if not secret:
        log_error(f"Hosted cluster kubeconfig secret not found")
        return None
    
    return secret.get("data", {}).get("kubeconfig")


def verify_dpu_services(config: Any) -> bool:
    """
    Verify DPU services are running correctly.
    
    Args:
        config: Configuration object
    
    Returns:
        True if services are healthy
    """
    log_step("Verifying DPU Services")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Check DPU service deployments
    services = k8s.list_custom_resources(
        group="svc.dpu.nvidia.com",
        version="v1alpha1",
        plural="dpuservices",
        namespace=config.dpf_namespace,
    )
    
    if not services:
        log_warning("No DPU services found")
        return False
    
    all_healthy = True
    for svc in services:
        name = svc.get("metadata", {}).get("name")
        status = svc.get("status", {})
        phase = status.get("phase", "Unknown")
        
        if phase == "Running":
            log_info(f"  ✓ {name}: {phase}")
        else:
            log_warning(f"  ✗ {name}: {phase}")
            all_healthy = False
    
    return all_healthy
