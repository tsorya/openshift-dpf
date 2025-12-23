"""
Manifest management module for OpenShift DPF.

This module provides functions for preparing and managing
Kubernetes manifests for cluster and DPF installation.
"""

import base64
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from dpf.cluster import check_cluster_installed, get_kubeconfig
from dpf.config import Config, get_config
from dpf.k8s import get_k8s_client
from dpf.tools import ensure_helm_installed
from dpf.utils import (
    copy_directory,
    ensure_directory,
    load_yaml,
    log_debug,
    log_error,
    log_info,
    log_step,
    log_warning,
    process_template,
    read_file,
    run_command,
    save_yaml,
    write_file,
)


def prepare_manifests(manifest_type: str, config: Optional[Config] = None) -> bool:
    """
    Prepare manifests for cluster or DPF installation.

    Args:
        manifest_type: Type of manifests (cluster or dpf)
        config: Configuration object

    Returns:
        True if successful
    """
    if config is None:
        config = get_config()

    log_step(f"Preparing {manifest_type} manifests")

    # Clean and recreate generated directory
    generated_dir = Path(config.directories.generated_dir)
    if generated_dir.exists():
        shutil.rmtree(generated_dir)
    generated_dir.mkdir(parents=True)

    if manifest_type == "cluster":
        return prepare_cluster_manifests(config)
    elif manifest_type == "dpf":
        return prepare_dpf_manifests(config)
    else:
        log_error(f"Unknown manifest type: {manifest_type}")
        log_info("Valid types are: cluster, dpf")
        return False


def prepare_cluster_manifests(config: Config) -> bool:
    """
    Prepare cluster installation manifests.

    Args:
        config: Configuration object

    Returns:
        True if successful
    """
    log_info("Preparing cluster manifests...")

    manifests_dir = Path(config.directories.manifests_dir)
    generated_dir = Path(config.directories.generated_dir)

    # Copy base manifests
    src_dir = manifests_dir / "cluster"
    if src_dir.exists():
        copy_directory(
            src_dir,
            generated_dir / "cluster",
            exclude_patterns=["*.template", "*.example"],
        )

    # Process templates with configuration values
    template_vars = {
        "cluster_name": config.cluster.cluster_name,
        "base_domain": config.cluster.base_domain,
        "api_vip": config.network.api_vip,
        "ingress_vip": config.network.ingress_vip,
        "machine_network_cidr": f"{config.network.api_vip.rsplit('.', 1)[0]}.0/24",
        "pod_cidr": config.network.pod_cidr,
        "service_cidr": config.network.service_cidr,
        "mtu": config.network.nodes_mtu,
    }

    # Process any template files
    for template_file in manifests_dir.glob("**/*.template"):
        output_file = generated_dir / template_file.relative_to(manifests_dir).with_suffix("")
        process_template(template_file, output_file, template_vars)

    log_info("Cluster manifests prepared successfully")
    return True


def prepare_dpf_manifests(config: Config) -> bool:
    """
    Prepare DPF installation manifests.

    Args:
        config: Configuration object

    Returns:
        True if successful
    """
    log_info("Preparing DPF manifests...")

    manifests_dir = Path(config.directories.manifests_dir)
    generated_dir = Path(config.directories.generated_dir)
    dpf_dir = generated_dir / "dpf"
    ensure_directory(dpf_dir)

    # Copy DPF manifests
    src_dir = manifests_dir / "dpf"
    if src_dir.exists():
        copy_directory(
            src_dir,
            dpf_dir,
            exclude_patterns=["*.template", "*.example"],
        )

    # Generate DPF operator subscription
    dpf_subscription = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {
            "name": "dpf-operator",
            "namespace": "dpf-operator-system",
        },
        "spec": {
            "channel": "stable",
            "name": "dpf-operator",
            "source": config.olm.catalog_source_name,
            "sourceNamespace": "openshift-marketplace",
            "installPlanApproval": "Automatic",
        },
    }

    save_yaml(dpf_dir / "dpf-subscription.yaml", dpf_subscription)

    # Generate OVN manifests using Helm if available
    if ensure_helm_installed():
        generate_ovn_manifests(config)

    log_info("DPF manifests prepared successfully")
    return True


def prepare_nfs(config: Optional[Config] = None) -> bool:
    """
    Prepare NFS manifests for storage.

    Args:
        config: Configuration object

    Returns:
        True if successful
    """
    if config is None:
        config = get_config()

    log_step("Preparing NFS manifests")

    generated_dir = Path(config.directories.generated_dir)
    nfs_dir = generated_dir / "nfs"
    ensure_directory(nfs_dir)

    nfs_path = config.nfs.path
    server_ip = config.nfs.server_node_ip

    if server_ip:
        log_info(f"Using external NFS server: {server_ip}:{nfs_path}")
        
        # Create NFS PV manifest
        nfs_pv = {
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": {
                "name": "nfs-pv",
            },
            "spec": {
                "capacity": {"storage": "100Gi"},
                "accessModes": ["ReadWriteMany"],
                "nfs": {
                    "server": server_ip,
                    "path": nfs_path,
                },
                "persistentVolumeReclaimPolicy": "Retain",
            },
        }
        
        save_yaml(nfs_dir / "nfs-pv.yaml", nfs_pv)
    else:
        log_info("Preparing internal NFS deployment")
        
        # Create NFS provisioner deployment
        nfs_provisioner = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "nfs-provisioner",
                "namespace": "nfs-provisioner",
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": "nfs-provisioner"}},
                "template": {
                    "metadata": {"labels": {"app": "nfs-provisioner"}},
                    "spec": {
                        "containers": [
                            {
                                "name": "nfs-provisioner",
                                "image": "registry.k8s.io/sig-storage/nfs-subdir-external-provisioner:v4.0.2",
                                "volumeMounts": [
                                    {"name": "nfs-client-root", "mountPath": "/persistentvolumes"},
                                ],
                                "env": [
                                    {"name": "PROVISIONER_NAME", "value": "nfs-provisioner"},
                                    {"name": "NFS_SERVER", "value": server_ip or "localhost"},
                                    {"name": "NFS_PATH", "value": nfs_path},
                                ],
                            }
                        ],
                        "volumes": [
                            {
                                "name": "nfs-client-root",
                                "nfs": {
                                    "server": server_ip or "localhost",
                                    "path": nfs_path,
                                },
                            }
                        ],
                    },
                },
            },
        }
        
        save_yaml(nfs_dir / "nfs-provisioner.yaml", nfs_provisioner)

    log_info("NFS manifests prepared")
    return True


def generate_ovn_manifests(config: Config) -> bool:
    """
    Generate OVN-Kubernetes manifests using Helm.

    Args:
        config: Configuration object

    Returns:
        True if successful
    """
    log_info("Generating OVN manifests...")

    generated_dir = Path(config.directories.generated_dir)
    ovn_dir = generated_dir / "ovn"
    ensure_directory(ovn_dir)

    helm_chart = config.dpf.ovn_chart_url
    helm_version = config.dpf.ovn_chart_version

    # Run helm template to generate manifests
    result = run_command([
        "helm", "template", "ovn-kubernetes",
        helm_chart,
        "--version", helm_version,
        "--output-dir", str(ovn_dir),
        "--set", f"mtu={config.network.nodes_mtu}",
        "--set", f"namespace={config.dpf.ovnk_namespace}",
    ])

    if not result.success:
        log_warning(f"Failed to generate OVN manifests: {result.stderr}")
        return False

    log_info("OVN manifests generated successfully")
    return True


def deploy_core_operator_sources(config: Optional[Config] = None) -> bool:
    """
    Deploy core operator catalog sources.

    Args:
        config: Configuration object

    Returns:
        True if successful
    """
    if config is None:
        config = get_config()

    log_step("Deploying Core Operator Sources")

    k8s = get_k8s_client(config.cluster.kubeconfig)

    # Create custom catalog source if needed
    if config.olm.use_v419_workaround:
        catalog_source = {
            "apiVersion": "operators.coreos.com/v1alpha1",
            "kind": "CatalogSource",
            "metadata": {
                "name": "redhat-operators-v419",
                "namespace": "openshift-marketplace",
            },
            "spec": {
                "sourceType": "grpc",
                "image": "registry.redhat.io/redhat/redhat-operator-index:v4.19",
                "displayName": "Red Hat Operators (v4.19)",
                "publisher": "Red Hat",
                "updateStrategy": {
                    "registryPoll": {"interval": "10m"},
                },
            },
        }

        if not k8s.create_custom_resource(
            group="operators.coreos.com",
            version="v1alpha1",
            plural="catalogsources",
            body=catalog_source,
            namespace="openshift-marketplace",
        ):
            log_error("Failed to create catalog source")
            return False

    log_info("Core operator sources deployed")
    return True


def update_mtu_in_values_file(values_file: Path, new_mtu: int) -> bool:
    """
    Update MTU value in a Helm values file.

    Args:
        values_file: Path to values file
        new_mtu: New MTU value

    Returns:
        True if successful
    """
    if not values_file.exists():
        log_error(f"Values file not found: {values_file}")
        return False

    content = read_file(values_file)

    # Update or add MTU setting
    if re.search(r"^\s*mtu:", content, re.MULTILINE):
        content = re.sub(r"mtu:.*", f"mtu: {new_mtu}", content)
    else:
        content += f"\nmtu: {new_mtu}\n"

    write_file(values_file, content)
    log_info(f"Updated MTU to {new_mtu} in {values_file}")
    return True


def enable_storage(storage_type: str, config: Config) -> bool:
    """
    Enable storage operator (LVM or ODF).

    Args:
        storage_type: Type of storage (lvm or odf)
        config: Configuration object

    Returns:
        True if successful
    """
    log_info(f"Enabling {storage_type} storage...")

    k8s = get_k8s_client(config.cluster.kubeconfig)

    if storage_type == "lvm":
        namespace = "openshift-lvm-storage"
        operator_name = "lvm-operator"
    elif storage_type == "odf":
        namespace = "openshift-storage"
        operator_name = "odf-operator"
    else:
        log_error(f"Unknown storage type: {storage_type}")
        return False

    # Create namespace
    k8s.create_namespace(namespace)

    # Create operator group
    operator_group = {
        "apiVersion": "operators.coreos.com/v1",
        "kind": "OperatorGroup",
        "metadata": {
            "name": f"{operator_name}-og",
            "namespace": namespace,
        },
        "spec": {
            "targetNamespaces": [namespace],
        },
    }

    k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1",
        plural="operatorgroups",
        body=operator_group,
        namespace=namespace,
    )

    # Create subscription
    subscription = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {
            "name": operator_name,
            "namespace": namespace,
        },
        "spec": {
            "channel": "stable",
            "name": operator_name,
            "source": config.olm.catalog_source_name,
            "sourceNamespace": "openshift-marketplace",
            "installPlanApproval": "Automatic",
        },
    }

    if not k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1alpha1",
        plural="subscriptions",
        body=subscription,
        namespace=namespace,
    ):
        log_error(f"Failed to create {operator_name} subscription")
        return False

    log_info(f"{storage_type} storage enabled")
    return True
