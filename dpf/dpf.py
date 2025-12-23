"""
DPF deployment module for OpenShift DPF.

This module provides functions for deploying the Data Processing Framework
components including NFD, MetalLB, Cert-Manager, Hypershift, and DPF operators
using the Kubernetes Python client.
"""

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from dpf.k8s import get_k8s_client
from dpf.tools import ensure_helm_installed, ensure_hypershift_installed
from dpf.utils import (
    ensure_directory,
    file_exists,
    log_debug,
    log_error,
    log_info,
    log_step,
    log_warning,
    run_command,
)


def deploy_nfd(config: Any) -> bool:
    """
    Deploy Node Feature Discovery operator.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying Node Feature Discovery")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Check if CRD already exists
    if k8s.crd_exists("nodefeaturerules.nfd.openshift.io"):
        log_info("NFD is already installed")
        return True
    
    # Create namespace
    if not k8s.create_namespace("openshift-nfd", labels={"openshift.io/cluster-monitoring": "true"}):
        return False
    
    # Create OperatorGroup
    operator_group = {
        "apiVersion": "operators.coreos.com/v1",
        "kind": "OperatorGroup",
        "metadata": {
            "name": "openshift-nfd",
            "namespace": "openshift-nfd",
        },
        "spec": {
            "targetNamespaces": ["openshift-nfd"],
        },
    }
    
    k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1",
        plural="operatorgroups",
        body=operator_group,
        namespace="openshift-nfd",
    )
    
    # Create Subscription
    subscription = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {
            "name": "nfd",
            "namespace": "openshift-nfd",
        },
        "spec": {
            "channel": "stable",
            "name": "nfd",
            "source": "redhat-operators",
            "sourceNamespace": "openshift-marketplace",
            "installPlanApproval": "Automatic",
        },
    }
    
    if not k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1alpha1",
        plural="subscriptions",
        body=subscription,
        namespace="openshift-nfd",
    ):
        return False
    
    # Wait for CRD to be available
    log_info("Waiting for NFD CRD to be available...")
    if not k8s.wait_for_crd("nodefeaturerules.nfd.openshift.io", timeout=300):
        return False
    
    # Create NFD instance
    time.sleep(10)  # Give operator time to initialize
    
    nfd_instance = {
        "apiVersion": "nfd.openshift.io/v1",
        "kind": "NodeFeatureDiscovery",
        "metadata": {
            "name": "nfd-instance",
            "namespace": "openshift-nfd",
        },
        "spec": {
            "instance": "",
            "operand": {
                "image": "registry.redhat.io/openshift4/ose-node-feature-discovery-rhel9:v4.16",
                "imagePullPolicy": "Always",
            },
            "workerConfig": {
                "configData": "",
            },
        },
    }
    
    k8s.create_custom_resource(
        group="nfd.openshift.io",
        version="v1",
        plural="nodefeaturediscoveries",
        body=nfd_instance,
        namespace="openshift-nfd",
    )
    
    log_info("NFD deployed successfully")
    return True


def deploy_metallb(config: Any) -> bool:
    """
    Deploy MetalLB operator.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying MetalLB")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Check if CRD already exists
    if k8s.crd_exists("metallbs.metallb.io"):
        log_info("MetalLB is already installed")
        return True
    
    # Create namespace
    if not k8s.create_namespace("metallb-system"):
        return False
    
    # Create OperatorGroup
    operator_group = {
        "apiVersion": "operators.coreos.com/v1",
        "kind": "OperatorGroup",
        "metadata": {
            "name": "metallb-operator",
            "namespace": "metallb-system",
        },
        "spec": {},
    }
    
    k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1",
        plural="operatorgroups",
        body=operator_group,
        namespace="metallb-system",
    )
    
    # Create Subscription
    subscription = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {
            "name": "metallb-operator",
            "namespace": "metallb-system",
        },
        "spec": {
            "channel": "stable",
            "name": "metallb-operator",
            "source": "redhat-operators",
            "sourceNamespace": "openshift-marketplace",
            "installPlanApproval": "Automatic",
        },
    }
    
    if not k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1alpha1",
        plural="subscriptions",
        body=subscription,
        namespace="metallb-system",
    ):
        return False
    
    # Wait for CRD
    log_info("Waiting for MetalLB CRD to be available...")
    if not k8s.wait_for_crd("metallbs.metallb.io", timeout=300):
        return False
    
    time.sleep(10)
    
    # Create MetalLB instance
    metallb_instance = {
        "apiVersion": "metallb.io/v1beta1",
        "kind": "MetalLB",
        "metadata": {
            "name": "metallb",
            "namespace": "metallb-system",
        },
        "spec": {},
    }
    
    k8s.create_custom_resource(
        group="metallb.io",
        version="v1beta1",
        plural="metallbs",
        body=metallb_instance,
        namespace="metallb-system",
    )
    
    log_info("MetalLB deployed successfully")
    return True


def deploy_cert_manager(config: Any) -> bool:
    """
    Deploy cert-manager operator.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying Cert-Manager")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Check if CRD already exists
    if k8s.crd_exists("certificates.cert-manager.io"):
        log_info("Cert-Manager is already installed")
        return True
    
    # Create namespace
    if not k8s.create_namespace("cert-manager"):
        return False
    
    # Create OperatorGroup
    operator_group = {
        "apiVersion": "operators.coreos.com/v1",
        "kind": "OperatorGroup",
        "metadata": {
            "name": "cert-manager-operator",
            "namespace": "cert-manager-operator",
        },
        "spec": {
            "targetNamespaces": ["cert-manager-operator"],
            "upgradeStrategy": "Default",
        },
    }
    
    # Create operator namespace first
    k8s.create_namespace("cert-manager-operator")
    
    k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1",
        plural="operatorgroups",
        body=operator_group,
        namespace="cert-manager-operator",
    )
    
    # Create Subscription
    subscription = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {
            "name": "openshift-cert-manager-operator",
            "namespace": "cert-manager-operator",
        },
        "spec": {
            "channel": "stable-v1",
            "name": "openshift-cert-manager-operator",
            "source": "redhat-operators",
            "sourceNamespace": "openshift-marketplace",
            "installPlanApproval": "Automatic",
        },
    }
    
    if not k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1alpha1",
        plural="subscriptions",
        body=subscription,
        namespace="cert-manager-operator",
    ):
        return False
    
    log_info("Waiting for Cert-Manager CRD...")
    if not k8s.wait_for_crd("certificates.cert-manager.io", timeout=300):
        return False
    
    log_info("Cert-Manager deployed successfully")
    return True


def deploy_hypershift(config: Any) -> bool:
    """
    Deploy Hypershift operator.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying Hypershift")
    
    # Check if hypershift binary exists
    if not ensure_hypershift_installed(config):
        log_error("Hypershift binary not available")
        return False
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Check if hypershift namespace exists (already installed)
    if k8s.namespace_exists("hypershift"):
        log_info("Hypershift is already installed")
        return True
    
    # Install hypershift operator using the binary
    # This is one case where we need to use subprocess as there's no
    # Python library equivalent for the hypershift install command
    log_info("Installing Hypershift operator...")
    
    result = run_command([
        "hypershift", "install",
        "--oidc-storage-provider-s3-bucket-name", "",
        "--oidc-storage-provider-s3-credentials", "",
        "--oidc-storage-provider-s3-region", "",
        "--enable-defaulting-webhook", "true",
    ], env={"KUBECONFIG": config.kubeconfig_path})
    
    if not result.success:
        log_error(f"Failed to install Hypershift: {result.stderr}")
        return False
    
    # Wait for hypershift pods to be ready
    log_info("Waiting for Hypershift pods...")
    if not k8s.wait_for_pods_ready("hypershift", timeout=300):
        log_warning("Hypershift pods not fully ready yet, continuing...")
    
    log_info("Hypershift deployed successfully")
    return True


def deploy_hosted_cluster(config: Any) -> bool:
    """
    Deploy a hosted cluster using Hypershift.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying Hosted Cluster")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    hosted_cluster_name = config.hosted_cluster_name
    hosted_cluster_namespace = f"clusters-{hosted_cluster_name}"
    
    # Check if hosted cluster already exists
    existing = k8s.get_custom_resource(
        group="hypershift.openshift.io",
        version="v1beta1",
        plural="hostedclusters",
        name=hosted_cluster_name,
        namespace="clusters",
    )
    
    if existing:
        log_info(f"Hosted cluster {hosted_cluster_name} already exists")
        return True
    
    # Create hosted cluster using hypershift CLI
    # This requires the hypershift binary
    log_info(f"Creating hosted cluster: {hosted_cluster_name}")
    
    pull_secret_path = config.pull_secret_path
    
    result = run_command([
        "hypershift", "create", "cluster", "none",
        "--name", hosted_cluster_name,
        "--release-image", config.hosted_cluster_release_image,
        "--pull-secret", pull_secret_path,
        "--node-pool-replicas", "0",
    ], env={"KUBECONFIG": config.kubeconfig_path})
    
    if not result.success:
        log_error(f"Failed to create hosted cluster: {result.stderr}")
        return False
    
    # Wait for hosted cluster to be available
    log_info("Waiting for hosted cluster to be available...")
    
    start_time = time.time()
    timeout = 1800  # 30 minutes
    
    while time.time() - start_time < timeout:
        hc = k8s.get_custom_resource(
            group="hypershift.openshift.io",
            version="v1beta1",
            plural="hostedclusters",
            name=hosted_cluster_name,
            namespace="clusters",
        )
        
        if hc:
            conditions = hc.get("status", {}).get("conditions", [])
            available = any(
                c.get("type") == "Available" and c.get("status") == "True"
                for c in conditions
            )
            
            if available:
                log_info(f"Hosted cluster {hosted_cluster_name} is available")
                return True
        
        time.sleep(30)
    
    log_error("Timeout waiting for hosted cluster")
    return False


def deploy_argocd(config: Any) -> bool:
    """
    Deploy GitOps/ArgoCD operator.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying GitOps (ArgoCD)")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Check if already installed
    if k8s.namespace_exists("openshift-gitops"):
        log_info("GitOps is already installed")
        return True
    
    # Create Subscription
    subscription = {
        "apiVersion": "operators.coreos.com/v1alpha1",
        "kind": "Subscription",
        "metadata": {
            "name": "openshift-gitops-operator",
            "namespace": "openshift-operators",
        },
        "spec": {
            "channel": "latest",
            "name": "openshift-gitops-operator",
            "source": "redhat-operators",
            "sourceNamespace": "openshift-marketplace",
            "installPlanApproval": "Automatic",
        },
    }
    
    if not k8s.create_custom_resource(
        group="operators.coreos.com",
        version="v1alpha1",
        plural="subscriptions",
        body=subscription,
        namespace="openshift-operators",
    ):
        return False
    
    # Wait for namespace to be created
    log_info("Waiting for GitOps namespace...")
    
    start_time = time.time()
    while time.time() - start_time < 300:
        if k8s.namespace_exists("openshift-gitops"):
            break
        time.sleep(10)
    
    # Wait for pods to be ready
    if not k8s.wait_for_pods_ready("openshift-gitops", label_selector="app.kubernetes.io/name=openshift-gitops-server", timeout=300):
        log_warning("GitOps pods not fully ready yet")
    
    log_info("GitOps deployed successfully")
    return True


def deploy_maintenance_operator(config: Any) -> bool:
    """
    Deploy Maintenance Operator using Helm.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying Maintenance Operator")
    
    if not ensure_helm_installed():
        return False
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Check if already deployed
    if k8s.namespace_exists("maintenance-operator-system"):
        pods = k8s.get_pods("maintenance-operator-system")
        if pods:
            log_info("Maintenance Operator is already deployed")
            return True
    
    # Create namespace
    k8s.create_namespace("maintenance-operator-system")
    
    # Install using Helm
    helm_repo = config.maintenance_operator_helm_repo
    helm_chart = config.maintenance_operator_helm_chart
    
    # Add helm repo
    result = run_command([
        "helm", "repo", "add", "maintenance-operator", helm_repo,
    ], env={"KUBECONFIG": config.kubeconfig_path})
    
    run_command(["helm", "repo", "update"], env={"KUBECONFIG": config.kubeconfig_path})
    
    # Install chart
    result = run_command([
        "helm", "upgrade", "--install",
        "maintenance-operator", helm_chart,
        "--namespace", "maintenance-operator-system",
        "--create-namespace",
    ], env={"KUBECONFIG": config.kubeconfig_path})
    
    if not result.success:
        log_error(f"Failed to install Maintenance Operator: {result.stderr}")
        return False
    
    log_info("Maintenance Operator deployed successfully")
    return True


def apply_scc(config: Any) -> bool:
    """
    Apply SecurityContextConstraints.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Applying SecurityContextConstraints")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # SCC for DPF
    dpf_scc = {
        "apiVersion": "security.openshift.io/v1",
        "kind": "SecurityContextConstraints",
        "metadata": {
            "name": "dpf-scc",
        },
        "allowHostDirVolumePlugin": True,
        "allowHostIPC": True,
        "allowHostNetwork": True,
        "allowHostPID": True,
        "allowHostPorts": True,
        "allowPrivilegedContainer": True,
        "allowedCapabilities": ["*"],
        "fsGroup": {"type": "RunAsAny"},
        "runAsUser": {"type": "RunAsAny"},
        "seLinuxContext": {"type": "RunAsAny"},
        "supplementalGroups": {"type": "RunAsAny"},
        "users": [
            "system:serviceaccount:dpf-operator-system:dpf-operator-controller-manager",
        ],
        "volumes": ["*"],
    }
    
    return k8s.apply_scc("dpf-scc", dpf_scc)


def apply_namespaces(config: Any) -> bool:
    """
    Create required namespaces.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Creating Namespaces")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    namespaces = [
        config.dpf_namespace,
        "dpf-operator-system",
    ]
    
    for ns in namespaces:
        if not k8s.create_namespace(ns):
            return False
    
    return True


def create_ignition_template(config: Any) -> bool:
    """
    Create ignition template for DPU nodes.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Creating Ignition Template")
    
    # This uses the gen_template.py script
    gen_template_path = Path(config.project_root) / "gen_template.py"
    
    if not gen_template_path.exists():
        log_error(f"gen_template.py not found at {gen_template_path}")
        return False
    
    # Build command
    cmd = [
        "python3", str(gen_template_path),
        "--kubeconfig", config.kubeconfig_path,
        "--hosted-cluster-name", config.hosted_cluster_name,
        "--output-dir", str(Path(config.output_dir) / "ignition"),
    ]
    
    if config.mtu == 9000:
        cmd.append("--mtu9000")
    
    result = run_command(cmd)
    
    if not result.success:
        log_error(f"Failed to create ignition template: {result.stderr}")
        return False
    
    log_info("Ignition template created successfully")
    return True


def configure_ovn_ip_forwarding(config: Any) -> bool:
    """
    Configure OVN-Kubernetes IP forwarding.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Configuring OVN-K IP Forwarding")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    # Patch the network operator config
    patch = {
        "spec": {
            "defaultNetwork": {
                "ovnKubernetesConfig": {
                    "gatewayConfig": {
                        "ipForwarding": "Global",
                    },
                },
            },
        },
    }
    
    success = k8s.patch_custom_resource(
        group="operator.openshift.io",
        version="v1",
        plural="networks",
        name="cluster",
        patch=patch,
    )
    
    if success:
        log_info("OVN-K IP forwarding configured")
    
    return success


def apply_dpf(config: Any) -> bool:
    """
    Deploy the complete DPF stack.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Deploying DPF Stack")
    
    steps = [
        ("NFD", lambda: deploy_nfd(config)),
        ("MetalLB", lambda: deploy_metallb(config)),
        ("Cert-Manager", lambda: deploy_cert_manager(config)),
        ("Namespaces", lambda: apply_namespaces(config)),
        ("SCCs", lambda: apply_scc(config)),
        ("OVN-K Config", lambda: configure_ovn_ip_forwarding(config)),
    ]
    
    # Optional steps based on configuration
    if config.deploy_hypershift:
        steps.append(("Hypershift", lambda: deploy_hypershift(config)))
        steps.append(("Hosted Cluster", lambda: deploy_hosted_cluster(config)))
    
    if config.deploy_argocd:
        steps.append(("ArgoCD", lambda: deploy_argocd(config)))
    
    if config.deploy_maintenance_operator:
        steps.append(("Maintenance Operator", lambda: deploy_maintenance_operator(config)))
    
    for step_name, step_func in steps:
        log_info(f"Running: {step_name}")
        try:
            if not step_func():
                log_error(f"Step failed: {step_name}")
                return False
        except Exception as e:
            log_error(f"Step failed: {step_name}: {e}")
            return False
    
    # Apply DPF operator manifests
    if not apply_dpf_manifests(config):
        return False
    
    log_info("DPF stack deployed successfully")
    return True


def apply_dpf_manifests(config: Any) -> bool:
    """
    Apply DPF operator manifests.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Applying DPF Operator Manifests")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    manifests_dir = Path(config.output_dir) / "dpf"
    
    if not manifests_dir.exists():
        log_error(f"DPF manifests directory not found: {manifests_dir}")
        log_error("Run 'dpf manifests prepare-dpf' first")
        return False
    
    # Apply manifests in order
    if not k8s.apply_yaml_directory(manifests_dir, recursive=True):
        return False
    
    # Wait for DPF operator to be ready
    log_info("Waiting for DPF operator...")
    if not k8s.wait_for_pods_ready("dpf-operator-system", timeout=300):
        log_warning("DPF operator pods not fully ready yet")
    
    log_info("DPF manifests applied successfully")
    return True


def copy_hypershift_kubeconfig(config: Any) -> Optional[str]:
    """
    Copy the hosted cluster kubeconfig to a local file.
    
    Args:
        config: Configuration object
    
    Returns:
        Path to the kubeconfig file, or None on failure
    """
    log_step("Getting Hosted Cluster Kubeconfig")
    
    k8s = get_k8s_client(config.kubeconfig_path)
    
    hosted_cluster_name = config.hosted_cluster_name
    namespace = f"clusters-{hosted_cluster_name}"
    secret_name = f"{hosted_cluster_name}-admin-kubeconfig"
    
    # Get the kubeconfig secret
    secret = k8s.get_secret(secret_name, namespace)
    
    if not secret:
        log_error(f"Kubeconfig secret {secret_name} not found in {namespace}")
        return None
    
    kubeconfig_data = secret.get("data", {}).get("kubeconfig")
    if not kubeconfig_data:
        log_error("Kubeconfig data not found in secret")
        return None
    
    # Write to file
    output_path = Path(config.output_dir) / "hosted-cluster-kubeconfig"
    ensure_directory(output_path.parent)
    
    with open(output_path, 'w') as f:
        f.write(kubeconfig_data)
    
    output_path.chmod(0o600)
    
    log_info(f"Hosted cluster kubeconfig saved to: {output_path}")
    return str(output_path)
