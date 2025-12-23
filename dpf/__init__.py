"""
OpenShift DPF (Data Processing Framework) CLI Tool.

This package provides automation for OpenShift DPF cluster deployments,
including cluster management, VM provisioning, DPF operator installation,
and post-installation configuration.

Usage:
    # Import submodules
    from dpf import cluster, vm, network, tools
    
    # Import main classes
    from dpf import DPFConfig, K8sClient
    from ailib import AssistedClient  # Use ailib directly
    
    # Import specific functions
    from dpf.cluster import check_create_cluster, get_kubeconfig
    from dpf.vm import create_vms, delete_vms
    from dpf.k8s import get_k8s_client
"""

__version__ = "1.0.0"
__author__ = "OpenShift DPF Team"

# Submodule names available for import
__all__ = [
    # Version info
    "__version__",
    "__author__",
    # Submodule names (for from dpf import X)
    "cli",
    "cluster",
    "config",
    "dpf",
    "k8s",
    "manifests",
    "network",
    "post_install",
    "sanity_checks",
    "tools",
    "utils",
    "vm",
    # Classes (re-exported for convenience)
    "DPFConfig",
    "K8sClient",
    # Functions (re-exported for convenience)
    "get_config",
    "get_k8s_client",
    "load_config",
]

# Lazy module loading to avoid circular imports and improve startup time
def __getattr__(name: str):
    """Lazy load submodules and provide convenient access to common classes."""
    import importlib
    
    # Submodules that can be imported
    submodules = {
        "cli",
        "cluster",
        "config",
        "dpf",
        "k8s",
        "manifests",
        "network",
        "post_install",
        "sanity_checks",
        "tools",
        "utils",
        "vm",
    }
    
    # Class/function mappings for convenience imports
    class_mappings = {
        "DPFConfig": ("dpf.config", "Config"),
        "K8sClient": ("dpf.k8s", "K8sClient"),
        "load_config": ("dpf.config", "load_config"),
        "get_config": ("dpf.config", "get_config"),
        "get_k8s_client": ("dpf.k8s", "get_k8s_client"),
    }
    
    if name in submodules:
        return importlib.import_module(f"dpf.{name}")
    
    if name in class_mappings:
        module_name, attr_name = class_mappings[name]
        module = importlib.import_module(module_name)
        return getattr(module, attr_name)
    
    raise AttributeError(f"module 'dpf' has no attribute {name!r}")
