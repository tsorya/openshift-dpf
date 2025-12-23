"""
Tool installation module for OpenShift DPF.

This module provides functions for installing and managing tools
like Helm, Hypershift, and OpenShift CLI.
"""

import os
import platform
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Optional

import requests

from dpf.utils import (
    log_info,
    log_error,
    log_warning,
    log_debug,
    log_step,
    run_command,
    ensure_directory,
    verify_command_exists,
)


# ============================================================================
# Helm Installation
# ============================================================================

HELM_VERSION = "v3.14.0"
HELM_DOWNLOAD_URL = "https://get.helm.sh/helm-{version}-{os}-{arch}.tar.gz"


def get_helm_download_url() -> str:
    """Get the Helm download URL for the current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Map architecture
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = arch_map.get(machine, "amd64")
    
    return HELM_DOWNLOAD_URL.format(
        version=HELM_VERSION,
        os=system,
        arch=arch,
    )


def ensure_helm_installed() -> bool:
    """
    Ensure Helm is installed, installing if necessary.
    
    Returns:
        True if Helm is available
    """
    if verify_command_exists("helm"):
        log_debug("Helm is already installed")
        return True
    
    return install_helm()


def install_helm() -> bool:
    """
    Install Helm CLI.
    
    Returns:
        True if successful
    """
    log_step("Installing Helm")
    
    url = get_helm_download_url()
    install_dir = Path("/usr/local/bin")
    
    log_info(f"Downloading Helm from {url}")
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            archive_path = tmpdir / "helm.tar.gz"
            
            # Download
            response = requests.get(url, stream=True, timeout=300)
            response.raise_for_status()
            
            with open(archive_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract
            with tarfile.open(archive_path) as tar:
                tar.extractall(tmpdir)
            
            # Find helm binary
            system = platform.system().lower()
            machine = platform.machine().lower()
            arch = "amd64" if machine in ["x86_64", "amd64"] else "arm64"
            
            helm_binary = tmpdir / f"{system}-{arch}" / "helm"
            
            if not helm_binary.exists():
                log_error(f"Helm binary not found in archive")
                return False
            
            # Install to system path
            dest_path = install_dir / "helm"
            
            try:
                shutil.copy2(helm_binary, dest_path)
                dest_path.chmod(0o755)
            except PermissionError:
                log_warning(f"Cannot write to {install_dir}, trying local install")
                local_bin = Path.home() / ".local" / "bin"
                ensure_directory(local_bin)
                dest_path = local_bin / "helm"
                shutil.copy2(helm_binary, dest_path)
                dest_path.chmod(0o755)
                log_info(f"Installed Helm to {dest_path}")
                log_warning(f"Add {local_bin} to your PATH")
        
        log_info("Helm installed successfully")
        return True
        
    except requests.RequestException as e:
        log_error(f"Failed to download Helm: {e}")
        return False
    except Exception as e:
        log_error(f"Failed to install Helm: {e}")
        return False


# ============================================================================
# OpenShift CLI Installation
# ============================================================================

OC_DOWNLOAD_URL = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable/openshift-client-{os}-{arch}.tar.gz"


def get_oc_download_url() -> str:
    """Get the OpenShift CLI download URL for the current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    if system == "darwin":
        # macOS
        if machine in ["arm64", "aarch64"]:
            return OC_DOWNLOAD_URL.format(os="mac-arm64", arch="")
        else:
            return OC_DOWNLOAD_URL.format(os="mac", arch="")
    else:
        # Linux
        if machine in ["arm64", "aarch64"]:
            return OC_DOWNLOAD_URL.format(os="linux-arm64", arch="")
        else:
            return OC_DOWNLOAD_URL.format(os="linux", arch="")


def install_oc() -> bool:
    """
    Install OpenShift CLI (oc).
    
    Returns:
        True if successful
    """
    log_step("Installing OpenShift CLI")
    
    if verify_command_exists("oc"):
        log_info("OpenShift CLI is already installed")
        return True
    
    url = get_oc_download_url()
    log_info(f"Downloading oc from {url}")
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            archive_path = tmpdir / "oc.tar.gz"
            
            # Download
            response = requests.get(url, stream=True, timeout=300)
            response.raise_for_status()
            
            with open(archive_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract
            with tarfile.open(archive_path) as tar:
                tar.extractall(tmpdir)
            
            oc_binary = tmpdir / "oc"
            kubectl_binary = tmpdir / "kubectl"
            
            # Install to system path
            install_dir = Path("/usr/local/bin")
            
            try:
                if oc_binary.exists():
                    shutil.copy2(oc_binary, install_dir / "oc")
                    (install_dir / "oc").chmod(0o755)
                
                if kubectl_binary.exists():
                    shutil.copy2(kubectl_binary, install_dir / "kubectl")
                    (install_dir / "kubectl").chmod(0o755)
                    
            except PermissionError:
                log_warning(f"Cannot write to {install_dir}, trying local install")
                local_bin = Path.home() / ".local" / "bin"
                ensure_directory(local_bin)
                
                if oc_binary.exists():
                    shutil.copy2(oc_binary, local_bin / "oc")
                    (local_bin / "oc").chmod(0o755)
                
                if kubectl_binary.exists():
                    shutil.copy2(kubectl_binary, local_bin / "kubectl")
                    (local_bin / "kubectl").chmod(0o755)
                
                log_warning(f"Add {local_bin} to your PATH")
        
        log_info("OpenShift CLI installed successfully")
        return True
        
    except requests.RequestException as e:
        log_error(f"Failed to download oc: {e}")
        return False
    except Exception as e:
        log_error(f"Failed to install oc: {e}")
        return False


# ============================================================================
# Hypershift Installation
# ============================================================================

def ensure_hypershift_installed(config: Any) -> bool:
    """
    Ensure Hypershift CLI is installed.
    
    Args:
        config: Configuration object
    
    Returns:
        True if Hypershift is available
    """
    if verify_command_exists("hypershift"):
        log_debug("Hypershift is already installed")
        return True
    
    return install_hypershift(config)


def install_hypershift(config: Any) -> bool:
    """
    Install Hypershift CLI by building from source.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Installing Hypershift")
    
    # Hypershift is typically built from source
    # Check if Go is installed
    if not verify_command_exists("go"):
        log_error("Go is not installed. Install Go first or download Hypershift binary.")
        return False
    
    log_info("Building Hypershift from source...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Clone hypershift repo
        result = run_command([
            "git", "clone", "--depth", "1",
            "https://github.com/openshift/hypershift.git",
            str(tmpdir / "hypershift"),
        ])
        
        if not result.success:
            log_error(f"Failed to clone hypershift: {result.stderr}")
            return False
        
        # Build
        result = run_command(
            ["make", "hypershift"],
            cwd=tmpdir / "hypershift",
        )
        
        if not result.success:
            log_error(f"Failed to build hypershift: {result.stderr}")
            return False
        
        # Install binary
        binary_path = tmpdir / "hypershift" / "bin" / "hypershift"
        
        if not binary_path.exists():
            log_error("Hypershift binary not found after build")
            return False
        
        install_dir = Path("/usr/local/bin")
        
        try:
            shutil.copy2(binary_path, install_dir / "hypershift")
            (install_dir / "hypershift").chmod(0o755)
        except PermissionError:
            local_bin = Path.home() / ".local" / "bin"
            ensure_directory(local_bin)
            shutil.copy2(binary_path, local_bin / "hypershift")
            (local_bin / "hypershift").chmod(0o755)
            log_warning(f"Installed to {local_bin}, ensure it's in your PATH")
    
    log_info("Hypershift installed successfully")
    return True


# ============================================================================
# Go Installation
# ============================================================================

GO_VERSION = "1.22.0"
GO_DOWNLOAD_URL = "https://go.dev/dl/go{version}.{os}-{arch}.tar.gz"


def get_go_download_url() -> str:
    """Get the Go download URL for the current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    arch = arch_map.get(machine, "amd64")
    
    return GO_DOWNLOAD_URL.format(
        version=GO_VERSION,
        os=system,
        arch=arch,
    )


def install_golang() -> bool:
    """
    Install Go programming language.
    
    Returns:
        True if successful
    """
    log_step("Installing Go")
    
    if verify_command_exists("go"):
        log_info("Go is already installed")
        return True
    
    url = get_go_download_url()
    install_dir = Path("/usr/local")
    
    log_info(f"Downloading Go {GO_VERSION}")
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            archive_path = tmpdir / "go.tar.gz"
            
            # Download
            response = requests.get(url, stream=True, timeout=300)
            response.raise_for_status()
            
            with open(archive_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Remove old Go installation if exists
            go_dir = install_dir / "go"
            if go_dir.exists():
                shutil.rmtree(go_dir)
            
            # Extract
            with tarfile.open(archive_path) as tar:
                tar.extractall(install_dir)
        
        # Create symlinks
        go_bin = install_dir / "go" / "bin"
        
        for binary in ["go", "gofmt"]:
            src = go_bin / binary
            dst = Path("/usr/local/bin") / binary
            
            if dst.exists() or dst.is_symlink():
                dst.unlink()
            
            try:
                dst.symlink_to(src)
            except PermissionError:
                log_warning(f"Cannot create symlink for {binary}")
        
        log_info(f"Go {GO_VERSION} installed successfully")
        log_info("Add /usr/local/go/bin to your PATH if not already present")
        return True
        
    except requests.RequestException as e:
        log_error(f"Failed to download Go: {e}")
        return False
    except Exception as e:
        log_error(f"Failed to install Go: {e}")
        return False


# ============================================================================
# Tool Version Checking
# ============================================================================

def get_tool_version(tool: str) -> Optional[str]:
    """
    Get the version of an installed tool.
    
    Args:
        tool: Tool name
    
    Returns:
        Version string or None
    """
    version_commands = {
        "helm": ["helm", "version", "--short"],
        "oc": ["oc", "version", "--client"],
        "kubectl": ["kubectl", "version", "--client", "--short"],
        "go": ["go", "version"],
        "hypershift": ["hypershift", "version"],
    }
    
    cmd = version_commands.get(tool)
    if not cmd:
        return None
    
    result = run_command(cmd)
    if result.success:
        return result.stdout.strip().split('\n')[0]
    return None


def check_required_tools() -> dict:
    """
    Check if required tools are installed.
    
    Returns:
        Dictionary with tool status
    """
    tools = ["helm", "oc", "kubectl"]
    
    status = {}
    for tool in tools:
        installed = verify_command_exists(tool)
        version = get_tool_version(tool) if installed else None
        status[tool] = {
            "installed": installed,
            "version": version,
        }
    
    return status


def print_tool_status() -> None:
    """Print the status of required tools."""
    log_step("Tool Status")
    
    status = check_required_tools()
    
    for tool, info in status.items():
        if info["installed"]:
            log_info(f"  ✓ {tool}: {info['version']}")
        else:
            log_warning(f"  ✗ {tool}: not installed")
