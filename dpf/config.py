"""
Configuration management module for OpenShift DPF.

This module handles loading environment variables from .env files
and provides default configuration values.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DirectoryConfig:
    """Directory configuration paths."""
    manifests_dir: str = "manifests"
    generated_dir: str = ""
    post_install_dir: str = ""
    generated_post_install_dir: str = ""
    helm_charts_dir: str = ""

    def __post_init__(self):
        if not self.generated_dir:
            self.generated_dir = f"{self.manifests_dir}/generated"
        if not self.post_install_dir:
            self.post_install_dir = f"{self.manifests_dir}/post-installation"
        if not self.generated_post_install_dir:
            self.generated_post_install_dir = f"{self.generated_dir}/post-install"
        if not self.helm_charts_dir:
            self.helm_charts_dir = f"{self.manifests_dir}/helm-charts-values"


@dataclass
class BFBConfig:
    """BFB (BlueField Boot) configuration."""
    url: str = "http://10.8.2.236/bfb/rhcos_4.19.0-ec.4_installer_2025-04-23_07-48-42.bfb"


@dataclass
class HBNConfig:
    """HBN (Host Based Networking) configuration."""
    ovn_network: str = "10.0.120.0/22"
    helm_repo_url: str = "https://helm.ngc.nvidia.com/nvidia/doca"
    helm_chart_version: str = "1.0.3"
    image_repo: str = "quay.io/eelgaev/doca_hbn"
    image_tag: str = "release-3.1.0.7-doca3.1.0-RHTP"


@dataclass
class DTSConfig:
    """DTS (Data Transfer Service) configuration."""
    helm_repo_url: str = "https://helm.ngc.nvidia.com/nvidia/doca"
    helm_chart_version: str = "1.22.1"


@dataclass
class ClusterConfig:
    """Cluster configuration."""
    cluster_name: str = "doca"
    base_domain: str = "lab.nvidia.com"
    openshift_version: str = "4.14.0"
    kubeconfig: str = ""
    ssh_key: str = ""

    def __post_init__(self):
        if not self.kubeconfig:
            self.kubeconfig = f"./{self.cluster_name}-kubeconfig"
        if not self.ssh_key:
            self.ssh_key = str(Path.home() / ".ssh" / "id_rsa.pub")


@dataclass
class NetworkConfig:
    """Network configuration."""
    pod_cidr: str = "10.128.0.0/14"
    service_cidr: str = "172.30.0.0/16"
    dpu_interface: str = "ens7f0np0"
    api_vip: str = "10.8.2.100"
    ingress_vip: str = "10.8.2.101"
    nodes_mtu: int = 1500
    primary_iface: str = "enp1s0"


@dataclass
class VMConfig:
    """Virtual machine configuration."""
    vm_count: int = 3
    ram: int = 41984
    vcpus: int = 14
    disk_size1: int = 120
    disk_size2: int = 80
    vm_prefix: str = "vm-dpf"
    mac_prefix: str = ""
    disk_path: str = "/var/lib/libvirt/images"
    iso_folder: str = ""
    iso_type: str = "minimal"
    bridge_name: str = "br0"
    skip_bridge_config: bool = False

    def __post_init__(self):
        if not self.iso_folder:
            self.iso_folder = self.disk_path


@dataclass
class DPFConfig:
    """DPF Operator configuration."""
    version: str = "v25.7.1"
    helm_repo_url: str = "https://helm.ngc.nvidia.com/nvidia/doca"
    ovn_chart_url: str = "oci://ghcr.io/mellanox/charts"
    ovn_template_chart_url: str = ""
    ovn_kubernetes_image_repo: str = "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256"
    ovn_kubernetes_image_tag: str = "780d11fac73412276b312b3f7c879b5e63da9687c7c8e79fc142e9c6e2f7c4cf"
    ovn_kubernetes_utils_image_repo: str = ""
    ovn_kubernetes_utils_image_tag: str = ""
    ovn_chart_version: str = ""
    injector_chart_version: str = ""
    ovnk_namespace: str = "openshift-ovn-kubernetes"
    nfd_operand_image: str = "quay.io/itsoiref/nfd:latest"
    num_vfs: int = 46

    def __post_init__(self):
        if not self.ovn_template_chart_url:
            self.ovn_template_chart_url = self.ovn_chart_url
        if not self.ovn_chart_version:
            self.ovn_chart_version = self.version
        if not self.injector_chart_version:
            self.injector_chart_version = self.ovn_chart_version


@dataclass
class GitOpsConfig:
    """GitOps Operator configuration."""
    channel: str = "1.16"
    version: str = "v1.16.3"


@dataclass
class MaintenanceOperatorConfig:
    """Maintenance Operator configuration."""
    version: str = "0.2.0"


@dataclass
class HypershiftConfig:
    """Hypershift configuration."""
    enable_hcp_multus: bool = True
    image: str = "quay.io/hypershift/hypershift-operator:latest"
    hosted_cluster_name: str = "doca"
    clusters_namespace: str = "clusters"
    ocp_release_image: str = "quay.io/openshift-release-dev/ocp-release:4.20.4-x86_64"
    api_ip: str = ""

    @property
    def hosted_control_plane_namespace(self) -> str:
        return f"{self.clusters_namespace}-{self.hosted_cluster_name}"


@dataclass
class NFSConfig:
    """NFS configuration."""
    server_node_ip: str = ""
    path: str = "/"
    export_dir: str = "/nfs/exports"
    export_options: str = "rw,sync,no_root_squash,no_subtree_check"
    allowed_network: str = "*"


@dataclass
class StorageConfig:
    """Storage configuration."""
    etcd_storage_class: str = ""
    bfb_storage_class: str = ""


@dataclass
class WaitConfig:
    """Wait/retry configuration."""
    max_retries: int = 90
    sleep_time: int = 60


@dataclass
class OLMConfig:
    """OLM Catalog Source configuration."""
    catalog_source_name: str = "redhat-operators"
    use_v419_workaround: bool = False


@dataclass
class SanityTestConfig:
    """Sanity test configuration."""
    pods_workload_file: str = "manifests/post-installation-manual/workload.yaml"
    workload_namespace: str = "workload"
    ping_count: int = 20
    ping_hbn_to_hbn_pods: bool = False


@dataclass
class Config:
    """Main configuration class containing all configuration sections."""
    directories: DirectoryConfig = field(default_factory=DirectoryConfig)
    bfb: BFBConfig = field(default_factory=BFBConfig)
    hbn: HBNConfig = field(default_factory=HBNConfig)
    dts: DTSConfig = field(default_factory=DTSConfig)
    cluster: ClusterConfig = field(default_factory=ClusterConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    vm: VMConfig = field(default_factory=VMConfig)
    dpf: DPFConfig = field(default_factory=DPFConfig)
    gitops: GitOpsConfig = field(default_factory=GitOpsConfig)
    maintenance: MaintenanceOperatorConfig = field(default_factory=MaintenanceOperatorConfig)
    hypershift: HypershiftConfig = field(default_factory=HypershiftConfig)
    nfs: NFSConfig = field(default_factory=NFSConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    wait: WaitConfig = field(default_factory=WaitConfig)
    olm: OLMConfig = field(default_factory=OLMConfig)
    sanity: SanityTestConfig = field(default_factory=SanityTestConfig)
    disable_nfd: bool = False
    debug: bool = False
    dpu_host_cidr: str = ""
    cno_hcp_image: str = ""

    @property
    def host_cluster_api(self) -> str:
        """Get the host cluster API endpoint."""
        return f"api.{self.cluster.cluster_name}.{self.cluster.base_domain}"

    @property
    def openshift_pull_secret(self) -> str:
        """Get the OpenShift pull secret path."""
        return os.environ.get("OPENSHIFT_PULL_SECRET", "openshift_pull.json")

    @property
    def dpf_pull_secret(self) -> str:
        """Get the DPF pull secret path."""
        return os.environ.get("DPF_PULL_SECRET", "dpf-pull-secret.yaml")


def load_env_file(env_file: Optional[Path] = None) -> dict[str, str]:
    """
    Load environment variables from a .env file.

    Args:
        env_file: Path to the .env file. If None, searches for .env in the project root.

    Returns:
        Dictionary of environment variables loaded from the file.
    """
    if env_file is None:
        # Find the .env file relative to this module
        module_dir = Path(__file__).parent
        env_file = module_dir.parent / ".env"

    env_vars: dict[str, str] = {}

    if not env_file.exists():
        return env_vars

    with open(env_file, "r") as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Parse key=value
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                # Remove quotes from value
                value = value.strip().strip("'\"")
                env_vars[key] = value

    return env_vars


def load_config(env_file: Optional[Path] = None) -> Config:
    """
    Load configuration from environment variables and .env file.

    Args:
        env_file: Optional path to .env file.

    Returns:
        Fully populated Config object.
    """
    # Load .env file
    env_vars = load_env_file(env_file)

    # Merge with existing environment (existing takes precedence)
    for key, value in env_vars.items():
        if key not in os.environ:
            os.environ[key] = value

    def get_env(key: str, default: str = "") -> str:
        return os.environ.get(key, default)

    def get_env_int(key: str, default: int = 0) -> int:
        val = os.environ.get(key, "")
        return int(val) if val else default

    def get_env_bool(key: str, default: bool = False) -> bool:
        val = os.environ.get(key, "").lower()
        if val in ("true", "1", "yes"):
            return True
        if val in ("false", "0", "no"):
            return False
        return default

    # Determine storage classes based on VM_COUNT
    vm_count = get_env_int("VM_COUNT", 3)
    if vm_count < 2:
        default_etcd_sc = "lvms-vg1"
        default_bfb_sc = "nfs-client"
    else:
        default_etcd_sc = "ocs-storagecluster-ceph-rbd"
        default_bfb_sc = ""

    # Handle OLM workaround
    use_v419_workaround = get_env_bool("USE_V419_WORKAROUND", False)
    catalog_source = "redhat-operators-v419" if use_v419_workaround else "redhat-operators"

    config = Config(
        directories=DirectoryConfig(
            manifests_dir=get_env("MANIFESTS_DIR", "manifests"),
            generated_dir=get_env("GENERATED_DIR", ""),
            helm_charts_dir=get_env("HELM_CHARTS_DIR", ""),
        ),
        bfb=BFBConfig(
            url=get_env("BFB_URL", BFBConfig.url),
        ),
        hbn=HBNConfig(
            ovn_network=get_env("HBN_OVN_NETWORK", HBNConfig.ovn_network),
            helm_repo_url=get_env("HBN_HELM_REPO_URL", HBNConfig.helm_repo_url),
            helm_chart_version=get_env("HBN_HELM_CHART_VERSION", HBNConfig.helm_chart_version),
            image_repo=get_env("HBN_IMAGE_REPO", HBNConfig.image_repo),
            image_tag=get_env("HBN_IMAGE_TAG", HBNConfig.image_tag),
        ),
        dts=DTSConfig(
            helm_repo_url=get_env("DTS_HELM_REPO_URL", DTSConfig.helm_repo_url),
            helm_chart_version=get_env("DTS_HELM_CHART_VERSION", DTSConfig.helm_chart_version),
        ),
        cluster=ClusterConfig(
            cluster_name=get_env("CLUSTER_NAME", "doca"),
            base_domain=get_env("BASE_DOMAIN", "lab.nvidia.com"),
            openshift_version=get_env("OPENSHIFT_VERSION", "4.14.0"),
            kubeconfig=get_env("KUBECONFIG", ""),
            ssh_key=get_env("SSH_KEY", ""),
        ),
        network=NetworkConfig(
            pod_cidr=get_env("POD_CIDR", "10.128.0.0/14"),
            service_cidr=get_env("SERVICE_CIDR", "172.30.0.0/16"),
            dpu_interface=get_env("DPU_INTERFACE", "ens7f0np0"),
            api_vip=get_env("API_VIP", "10.8.2.100"),
            ingress_vip=get_env("INGRESS_VIP", "10.8.2.101"),
            nodes_mtu=get_env_int("NODES_MTU", 1500),
            primary_iface=get_env("PRIMARY_IFACE", "enp1s0"),
        ),
        vm=VMConfig(
            vm_count=vm_count,
            ram=get_env_int("RAM", 41984),
            vcpus=get_env_int("VCPUS", 14),
            disk_size1=get_env_int("DISK_SIZE1", 120),
            disk_size2=get_env_int("DISK_SIZE2", 80),
            vm_prefix=get_env("VM_PREFIX", "vm-dpf"),
            mac_prefix=get_env("MAC_PREFIX", ""),
            disk_path=get_env("DISK_PATH", "/var/lib/libvirt/images"),
            iso_folder=get_env("ISO_FOLDER", ""),
            iso_type=get_env("ISO_TYPE", "minimal"),
            bridge_name=get_env("BRIDGE_NAME", "br0"),
            skip_bridge_config=get_env_bool("SKIP_BRIDGE_CONFIG", False),
        ),
        dpf=DPFConfig(
            version=get_env("DPF_VERSION", "v25.7.1"),
            helm_repo_url=get_env("DPF_HELM_REPO_URL", "https://helm.ngc.nvidia.com/nvidia/doca"),
            ovn_chart_url=get_env("OVN_CHART_URL", "oci://ghcr.io/mellanox/charts"),
            ovn_template_chart_url=get_env("OVN_TEMPLATE_CHART_URL", ""),
            ovn_kubernetes_image_repo=get_env("OVN_KUBERNETES_IMAGE_REPO", "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256"),
            ovn_kubernetes_image_tag=get_env("OVN_KUBERNETES_IMAGE_TAG", "780d11fac73412276b312b3f7c879b5e63da9687c7c8e79fc142e9c6e2f7c4cf"),
            ovn_kubernetes_utils_image_repo=get_env("OVN_KUBERNETES_UTILS_IMAGE_REPO", ""),
            ovn_kubernetes_utils_image_tag=get_env("OVN_KUBERNETES_UTILS_IMAGE_TAG", ""),
            ovn_chart_version=get_env("OVN_CHART_VERSION", ""),
            injector_chart_version=get_env("INJECTOR_CHART_VERSION", ""),
            ovnk_namespace=get_env("OVNK_NAMESPACE", "openshift-ovn-kubernetes"),
            nfd_operand_image=get_env("NFD_OPERAND_IMAGE", "quay.io/itsoiref/nfd:latest"),
            num_vfs=get_env_int("NUM_VFS", 46),
        ),
        gitops=GitOpsConfig(
            channel=get_env("GITOPS_OPERATOR_CHANNEL", "1.16"),
            version=get_env("GITOPS_OPERATOR_VERSION", "v1.16.3"),
        ),
        maintenance=MaintenanceOperatorConfig(
            version=get_env("MAINTENANCE_OPERATOR_VERSION", "0.2.0"),
        ),
        hypershift=HypershiftConfig(
            enable_hcp_multus=get_env_bool("ENABLE_HCP_MULTUS", True),
            image=get_env("HYPERSHIFT_IMAGE", "quay.io/hypershift/hypershift-operator:latest"),
            hosted_cluster_name=get_env("HOSTED_CLUSTER_NAME", "doca"),
            clusters_namespace=get_env("CLUSTERS_NAMESPACE", "clusters"),
            ocp_release_image=get_env("OCP_RELEASE_IMAGE", "quay.io/openshift-release-dev/ocp-release:4.20.4-x86_64"),
            api_ip=get_env("HYPERSHIFT_API_IP", ""),
        ),
        nfs=NFSConfig(
            server_node_ip=get_env("NFS_SERVER_NODE_IP", ""),
            path=get_env("NFS_PATH", "/"),
            export_dir=get_env("NFS_EXPORT_DIR", "/nfs/exports"),
            export_options=get_env("NFS_EXPORT_OPTIONS", NFSConfig.export_options),
            allowed_network=get_env("NFS_ALLOWED_NETWORK", "*"),
        ),
        storage=StorageConfig(
            etcd_storage_class=get_env("ETCD_STORAGE_CLASS", default_etcd_sc),
            bfb_storage_class=get_env("BFB_STORAGE_CLASS", default_bfb_sc),
        ),
        wait=WaitConfig(
            max_retries=get_env_int("MAX_RETRIES", 90),
            sleep_time=get_env_int("SLEEP_TIME", 60),
        ),
        olm=OLMConfig(
            catalog_source_name=get_env("CATALOG_SOURCE_NAME", catalog_source),
            use_v419_workaround=use_v419_workaround,
        ),
        sanity=SanityTestConfig(
            pods_workload_file=get_env("SANITY_TESTS_PODS_WORKLOAD_FILE", SanityTestConfig.pods_workload_file),
            workload_namespace=get_env("SANITY_TESTS_WORKLOAD_NAMESPACE", "workload"),
            ping_count=get_env_int("SANITY_TESTS_PING_COUNT", 20),
            ping_hbn_to_hbn_pods=get_env_bool("SANITY_TESTS_PING_HBN_TO_HBN_PODS", False),
        ),
        disable_nfd=get_env_bool("DISABLE_NFD", False),
        debug=get_env_bool("DEBUG", False),
        dpu_host_cidr=get_env("DPU_HOST_CIDR", ""),
        cno_hcp_image=get_env("CNO_HCP_IMAGE", ""),
    )

    return config


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance, loading it if necessary."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def reload_config(env_file: Optional[Path] = None) -> Config:
    """Reload configuration from environment and .env file."""
    global _config
    _config = load_config(env_file)
    return _config


# Alias for cleaner external imports (from dpf import DPFConfig)
# Note: DPFConfig in this file refers to the DPF operator config dataclass
# The top-level Config class is the complete application config

