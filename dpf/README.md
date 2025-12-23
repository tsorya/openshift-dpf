# OpenShift DPF Python Package

A Python package for deploying and managing OpenShift Data Processing Framework (DPF).

## Installation

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install the package (development mode)
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

## Package Structure

```
dpf/
├── __init__.py          # Package exports
├── cli.py               # CLI entry point (Click)
├── config.py            # Configuration management
├── utils.py             # Common utilities
├── k8s.py               # Kubernetes client wrapper
├── assisted_installer.py # Assisted Installer API client
├── cluster.py           # Cluster management
├── vm.py                # Virtual machine management
├── dpf.py               # DPF deployment operations
├── manifests.py         # Manifest preparation
├── post_install.py      # Post-installation operations
├── network.py           # Network configuration
├── tools.py             # Tool installation
└── sanity_checks.py     # Sanity tests
```

## Usage

### Import Styles

```python
# Import submodules
from dpf import cluster, vm, network, tools

# Import main classes
from dpf import DPFConfig, K8sClient
from ailib import AssistedClient

# Import specific functions
from dpf.cluster import check_create_cluster, get_kubeconfig
from dpf.vm import create_vms, delete_vms
from dpf.k8s import get_k8s_client
from dpf.config import load_config, get_config
```

### Configuration

```python
from dpf import load_config, DPFConfig

# Load from .env file
config = load_config()

# Access configuration
print(config.cluster.cluster_name)
print(config.network.api_vip)
print(config.vm.vm_count)
```

### Kubernetes Operations

```python
from dpf import K8sClient, get_k8s_client

# Get client with default kubeconfig
k8s = get_k8s_client()

# Or specify kubeconfig path
k8s = get_k8s_client("/path/to/kubeconfig")

# Use the client
namespaces = k8s.core_v1.list_namespace()
pods = k8s.get_pods("default")
```

### Cluster Management

```python
from dpf import cluster
from dpf.config import load_config

config = load_config()

# Create cluster
cluster.check_create_cluster(config)

# Start installation
cluster.start_cluster_installation(config)

# Get kubeconfig
kubeconfig_path = cluster.get_kubeconfig(config)
```

### VM Management

```python
from dpf import vm
from dpf.config import load_config

config = load_config()

# Create VMs
vm.create_vms(config)

# Delete VMs
vm.delete_vms(config)

# List VMs
vms = vm.list_vms(prefix="dpf-")
```

## CLI Usage

```bash
# Using the installed command
dpf --help
dpf cluster --help
dpf vm create

# Or run as module
python -m dpf.cli --help
```

### Main Commands

```bash
dpf all              # Run complete installation workflow
dpf sanity-check     # Run sanity checks
dpf verify-files     # Verify required files
```

### Cluster Commands

```bash
dpf cluster create       # Create cluster
dpf cluster delete       # Delete cluster
dpf cluster install      # Start installation
dpf cluster kubeconfig   # Get kubeconfig
dpf cluster clean-all    # Full cleanup
```

### VM Commands

```bash
dpf vm create    # Create VMs
dpf vm delete    # Delete VMs
```

### DPF Deployment

```bash
dpf dpf deploy              # Deploy complete DPF stack
dpf dpf deploy-nfd          # Deploy NFD operator
dpf dpf deploy-metallb      # Deploy MetalLB
dpf dpf deploy-hypershift   # Deploy Hypershift
```

### Post-Installation

```bash
dpf post-install prepare   # Prepare manifests
dpf post-install apply     # Apply manifests
dpf post-install redeploy  # Redeploy services
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy dpf/

# Linting
ruff check dpf/

# Format code
black dpf/
```

## Environment Variables

Create a `.env` file in the project root:

```bash
# Cluster
CLUSTER_NAME=dpf-cluster
BASE_DOMAIN=example.com
OPENSHIFT_VERSION=4.18

# Network
API_VIP=192.168.1.100
INGRESS_VIP=192.168.1.101
NODES_MTU=9000

# VMs
VM_COUNT=3
VM_PREFIX=dpf-master
RAM=32768
VCPUS=16

# See dpf/config.py for all available options
```
