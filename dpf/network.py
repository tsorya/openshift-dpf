"""
Network configuration module for OpenShift DPF.

This module provides functions for network configuration including
bridge setup, NFS configuration, MTU settings, and /etc/hosts updates.

Note: Some network operations require system-level tools (nmcli, ovs-vsctl)
that don't have pure Python equivalents. In these cases, we use subprocess
with proper error handling.
"""

import os
import re
import shutil
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from dpf.utils import (
    log_info,
    log_error,
    log_warning,
    log_debug,
    log_step,
    run_command,
    CommandResult,
    file_exists,
    read_file,
    write_file,
    ensure_directory,
)


# ============================================================================
# Network Detection and Information
# ============================================================================

def get_default_interface() -> Optional[str]:
    """
    Get the interface with the default route.
    
    Returns:
        Interface name or None
    """
    result = run_command(["ip", "route", "show", "default"])
    if result.success:
        # Parse "default via X.X.X.X dev INTERFACE"
        match = re.search(r"default via .+ dev (\S+)", result.stdout)
        if match:
            return match.group(1)
    return None


def get_interface_ip(interface: str) -> Optional[str]:
    """
    Get the IP address of an interface.
    
    Args:
        interface: Interface name
    
    Returns:
        IP address or None
    """
    result = run_command(["ip", "-4", "addr", "show", interface])
    if result.success:
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    return None


def get_interface_mtu(interface: str) -> Optional[int]:
    """
    Get the MTU of an interface.
    
    Args:
        interface: Interface name
    
    Returns:
        MTU value or None
    """
    result = run_command(["ip", "link", "show", interface])
    if result.success:
        match = re.search(r"mtu (\d+)", result.stdout)
        if match:
            return int(match.group(1))
    return None


def bridge_exists(bridge_name: str) -> bool:
    """
    Check if a bridge exists.
    
    Args:
        bridge_name: Bridge name
    
    Returns:
        True if bridge exists
    """
    result = run_command(["ip", "link", "show", bridge_name])
    return result.success


def get_network_manager_type() -> str:
    """
    Detect the network manager type (NetworkManager or Netplan).
    
    Returns:
        "networkmanager" or "netplan" or "unknown"
    """
    # Check for NetworkManager
    result = run_command(["systemctl", "is-active", "NetworkManager"])
    if result.success and result.stdout.strip() == "active":
        return "networkmanager"
    
    # Check for netplan
    if Path("/etc/netplan").exists():
        return "netplan"
    
    return "unknown"


# ============================================================================
# Bridge Operations (NetworkManager)
# ============================================================================

def create_bridge_networkmanager(
    bridge_name: str,
    interface: str,
    mtu: int = 1500,
) -> bool:
    """
    Create a network bridge using NetworkManager.
    
    Args:
        bridge_name: Name for the bridge
        interface: Interface to add to bridge
        mtu: MTU value
    
    Returns:
        True if successful
    """
    log_info(f"Creating bridge {bridge_name} with interface {interface}")
    
    # Get current interface IP configuration
    current_ip = get_interface_ip(interface)
    
    # Create bridge
    result = run_command([
        "nmcli", "connection", "add",
        "type", "bridge",
        "con-name", bridge_name,
        "ifname", bridge_name,
        "bridge.stp", "no",
        "bridge.forward-delay", "0",
    ])
    
    if not result.success:
        log_error(f"Failed to create bridge: {result.stderr}")
        return False
    
    # Set MTU
    run_command([
        "nmcli", "connection", "modify", bridge_name,
        "802-3-ethernet.mtu", str(mtu),
    ])
    
    # Add interface to bridge
    slave_conn_name = f"{bridge_name}-{interface}"
    result = run_command([
        "nmcli", "connection", "add",
        "type", "bridge-slave",
        "con-name", slave_conn_name,
        "ifname", interface,
        "master", bridge_name,
    ])
    
    if not result.success:
        log_error(f"Failed to add interface to bridge: {result.stderr}")
        return False
    
    # If interface had DHCP, configure bridge for DHCP
    # Otherwise, copy the IP configuration
    if current_ip:
        # Get netmask and gateway
        result = run_command(["ip", "route", "show", "default"])
        gateway = None
        if result.success:
            match = re.search(r"default via (\S+)", result.stdout)
            if match:
                gateway = match.group(1)
        
        run_command([
            "nmcli", "connection", "modify", bridge_name,
            "ipv4.method", "manual",
            "ipv4.addresses", f"{current_ip}/24",
            "ipv4.gateway", gateway or "",
        ])
    else:
        run_command([
            "nmcli", "connection", "modify", bridge_name,
            "ipv4.method", "auto",
        ])
    
    # Bring up the bridge
    run_command(["nmcli", "connection", "up", bridge_name])
    
    log_info(f"Bridge {bridge_name} created successfully")
    return True


def delete_bridge_networkmanager(bridge_name: str) -> bool:
    """
    Delete a network bridge using NetworkManager.
    
    Args:
        bridge_name: Name of the bridge
    
    Returns:
        True if successful
    """
    log_info(f"Deleting bridge {bridge_name}")
    
    # Delete bridge connection
    result = run_command(["nmcli", "connection", "delete", bridge_name])
    if not result.success:
        log_warning(f"Failed to delete bridge connection: {result.stderr}")
    
    # Delete any slave connections
    result = run_command(["nmcli", "connection", "show"])
    if result.success:
        for line in result.stdout.splitlines():
            if bridge_name in line:
                conn_name = line.split()[0]
                run_command(["nmcli", "connection", "delete", conn_name])
    
    return True


# ============================================================================
# Bridge Operations (Netplan)
# ============================================================================

def create_bridge_netplan(
    bridge_name: str,
    interface: str,
    mtu: int = 1500,
) -> bool:
    """
    Create a network bridge using Netplan.
    
    Args:
        bridge_name: Name for the bridge
        interface: Interface to add to bridge
        mtu: MTU value
    
    Returns:
        True if successful
    """
    log_info(f"Creating bridge {bridge_name} with interface {interface} (netplan)")
    
    netplan_config = {
        "network": {
            "version": 2,
            "renderer": "networkd",
            "ethernets": {
                interface: {
                    "mtu": mtu,
                },
            },
            "bridges": {
                bridge_name: {
                    "interfaces": [interface],
                    "mtu": mtu,
                    "dhcp4": True,
                    "parameters": {
                        "stp": False,
                        "forward-delay": 0,
                    },
                },
            },
        },
    }
    
    config_path = Path("/etc/netplan/99-bridge.yaml")
    
    try:
        with open(config_path, 'w') as f:
            yaml.dump(netplan_config, f)
        
        # Apply configuration
        result = run_command(["netplan", "apply"])
        if not result.success:
            log_error(f"Failed to apply netplan: {result.stderr}")
            return False
        
        log_info(f"Bridge {bridge_name} created successfully")
        return True
        
    except Exception as e:
        log_error(f"Failed to create bridge: {e}")
        return False


def delete_bridge_netplan(bridge_name: str) -> bool:
    """
    Delete a network bridge created with Netplan.
    
    Args:
        bridge_name: Name of the bridge
    
    Returns:
        True if successful
    """
    config_path = Path("/etc/netplan/99-bridge.yaml")
    
    if config_path.exists():
        config_path.unlink()
        run_command(["netplan", "apply"])
    
    return True


# ============================================================================
# High-Level Bridge Functions
# ============================================================================

def setup_bridge(config: Any, force: bool = False) -> bool:
    """
    Set up a network bridge for VMs.
    
    Args:
        config: Configuration object
        force: Force creation even if bridge exists
    
    Returns:
        True if successful
    """
    log_step("Setting Up Network Bridge")
    
    bridge_name = config.network_bridge
    mtu = config.mtu
    
    # Check if bridge already exists
    if bridge_exists(bridge_name):
        if not force:
            log_info(f"Bridge {bridge_name} already exists")
            return True
        else:
            log_info(f"Force flag set, recreating bridge {bridge_name}")
            cleanup_bridge(config)
    
    # Get default interface
    interface = get_default_interface()
    if not interface:
        log_error("Could not determine default interface")
        return False
    
    log_info(f"Default interface: {interface}")
    
    # Detect network manager
    nm_type = get_network_manager_type()
    log_info(f"Network manager: {nm_type}")
    
    if nm_type == "networkmanager":
        return create_bridge_networkmanager(bridge_name, interface, mtu)
    elif nm_type == "netplan":
        return create_bridge_netplan(bridge_name, interface, mtu)
    else:
        log_error("Unsupported network manager")
        return False


def cleanup_bridge(config: Any) -> bool:
    """
    Clean up network bridge.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Cleaning Up Network Bridge")
    
    bridge_name = config.network_bridge
    
    nm_type = get_network_manager_type()
    
    if nm_type == "networkmanager":
        return delete_bridge_networkmanager(bridge_name)
    elif nm_type == "netplan":
        return delete_bridge_netplan(bridge_name)
    else:
        log_warning("Unknown network manager, attempting generic cleanup")
        run_command(["ip", "link", "set", bridge_name, "down"])
        run_command(["ip", "link", "delete", bridge_name])
        return True


# ============================================================================
# MTU Configuration
# ============================================================================

def set_interface_mtu(interface: str, mtu: int) -> bool:
    """
    Set the MTU on a network interface using nmstatectl.
    
    Args:
        interface: Interface name
        mtu: MTU value
    
    Returns:
        True if successful
    """
    log_step(f"Setting MTU {mtu} on {interface}")
    
    # Check if nmstatectl is available
    if not shutil.which("nmstatectl"):
        log_warning("nmstatectl not found, using ip command")
        result = run_command(["ip", "link", "set", interface, "mtu", str(mtu)])
        return result.success
    
    # Create NMState configuration
    nmstate_config = {
        "interfaces": [
            {
                "name": interface,
                "type": "ethernet",
                "state": "up",
                "mtu": mtu,
            },
        ],
    }
    
    # Write temporary config file
    config_path = Path("/tmp/nmstate-mtu.yaml")
    with open(config_path, 'w') as f:
        yaml.dump(nmstate_config, f)
    
    # Apply configuration
    result = run_command(["nmstatectl", "apply", str(config_path)])
    
    # Cleanup
    config_path.unlink(missing_ok=True)
    
    if result.success:
        log_info(f"MTU set to {mtu} on {interface}")
    else:
        log_error(f"Failed to set MTU: {result.stderr}")
    
    return result.success


# ============================================================================
# /etc/hosts Updates
# ============================================================================

def update_etc_hosts(config: Any) -> bool:
    """
    Update /etc/hosts with cluster API entries.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Updating /etc/hosts")
    
    cluster_name = config.cluster.cluster_name
    base_domain = config.base_dns_domain
    
    # Determine IP address
    if config.vm.vm_count > 1:
        ip_address = config.network.api_vip
    else:
        # Single node - get VM IP
        # This would need to query libvirt or wait for the VM to get an IP
        ip_address = config.network.api_vip or "127.0.0.1"
    
    if not ip_address:
        log_error("Could not determine API IP address")
        return False
    
    # Build hostname entries
    api_hostname = f"api.{cluster_name}.{base_domain}"
    api_int_hostname = f"api-int.{cluster_name}.{base_domain}"
    apps_hostname = f"*.apps.{cluster_name}.{base_domain}"
    oauth_hostname = f"oauth-openshift.apps.{cluster_name}.{base_domain}"
    console_hostname = f"console-openshift-console.apps.{cluster_name}.{base_domain}"
    
    entries = [
        f"{ip_address} {api_hostname}",
        f"{ip_address} {api_int_hostname}",
        f"{config.network.ingress_vip or ip_address} {apps_hostname.replace('*', 'wildcard')}",
        f"{config.network.ingress_vip or ip_address} {oauth_hostname}",
        f"{config.network.ingress_vip or ip_address} {console_hostname}",
    ]
    
    # Read current /etc/hosts
    hosts_path = Path("/etc/hosts")
    try:
        current_content = hosts_path.read_text()
    except PermissionError:
        log_error("Cannot read /etc/hosts - need root privileges")
        return False
    
    # Remove old entries for this cluster
    lines = current_content.splitlines()
    new_lines = [
        line for line in lines
        if cluster_name not in line and base_domain not in line
    ]
    
    # Add marker and new entries
    new_lines.append(f"\n# OpenShift DPF - {cluster_name}")
    new_lines.extend(entries)
    
    # Write back
    try:
        hosts_path.write_text("\n".join(new_lines) + "\n")
        log_info(f"Updated /etc/hosts with entries for {cluster_name}")
        return True
    except PermissionError:
        log_error("Cannot write /etc/hosts - need root privileges")
        log_info("Add the following entries manually:")
        for entry in entries:
            log_info(f"  {entry}")
        return False


# ============================================================================
# NFS Server Setup
# ============================================================================

def detect_os() -> str:
    """
    Detect the operating system.
    
    Returns:
        "rhel", "ubuntu", or "unknown"
    """
    if Path("/etc/redhat-release").exists():
        return "rhel"
    elif Path("/etc/lsb-release").exists():
        return "ubuntu"
    return "unknown"


def setup_nfs_server(config: Any) -> bool:
    """
    Set up an NFS server.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Setting Up NFS Server")
    
    os_type = detect_os()
    log_info(f"Detected OS: {os_type}")
    
    # Install NFS packages
    if os_type == "rhel":
        result = run_command(["dnf", "install", "-y", "nfs-utils"])
    elif os_type == "ubuntu":
        result = run_command(["apt-get", "install", "-y", "nfs-kernel-server"])
    else:
        log_error("Unsupported OS for NFS setup")
        return False
    
    if not result.success:
        log_error(f"Failed to install NFS packages: {result.stderr}")
        return False
    
    # Create export directory
    nfs_path = Path(config.nfs_path)
    ensure_directory(nfs_path)
    
    # Set permissions
    run_command(["chmod", "777", str(nfs_path)])
    
    # Configure exports
    export_line = f"{nfs_path} *(rw,sync,no_subtree_check,no_root_squash)"
    
    exports_path = Path("/etc/exports")
    current_exports = ""
    if exports_path.exists():
        current_exports = exports_path.read_text()
    
    if str(nfs_path) not in current_exports:
        with open(exports_path, 'a') as f:
            f.write(f"\n{export_line}\n")
        log_info(f"Added NFS export: {nfs_path}")
    
    # Configure firewall
    if os_type == "rhel":
        run_command(["firewall-cmd", "--permanent", "--add-service=nfs"])
        run_command(["firewall-cmd", "--permanent", "--add-service=rpc-bind"])
        run_command(["firewall-cmd", "--permanent", "--add-service=mountd"])
        run_command(["firewall-cmd", "--reload"])
    
    # Enable and start NFS service
    if os_type == "rhel":
        run_command(["systemctl", "enable", "--now", "nfs-server"])
    elif os_type == "ubuntu":
        run_command(["systemctl", "enable", "--now", "nfs-kernel-server"])
    
    # Export filesystems
    run_command(["exportfs", "-rav"])
    
    # Verify
    result = run_command(["exportfs", "-v"])
    if result.success and str(nfs_path) in result.stdout:
        log_info("NFS server configured successfully")
        return True
    else:
        log_error("NFS export verification failed")
        return False


# ============================================================================
# OVS Configuration
# ============================================================================

def configure_ovs_bridges(config: Any) -> bool:
    """
    Configure Open vSwitch bridges for DPF.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step("Configuring OVS Bridges")
    
    # Check if ovs-vsctl is available
    if not shutil.which("ovs-vsctl"):
        log_error("ovs-vsctl not found - OVS not installed")
        return False
    
    # Create br-sfc bridge
    result = run_command(["ovs-vsctl", "--may-exist", "add-br", "br-sfc"])
    if not result.success:
        log_error(f"Failed to create br-sfc: {result.stderr}")
        return False
    
    # Create br-dpu bridge
    result = run_command(["ovs-vsctl", "--may-exist", "add-br", "br-dpu"])
    if not result.success:
        log_error(f"Failed to create br-dpu: {result.stderr}")
        return False
    
    # Create br-ovn bridge
    result = run_command(["ovs-vsctl", "--may-exist", "add-br", "br-ovn"])
    if not result.success:
        log_error(f"Failed to create br-ovn: {result.stderr}")
        return False
    
    # Create patch ports between bridges
    patch_ports = [
        ("br-sfc", "patch-sfc-dpu", "br-dpu", "patch-dpu-sfc"),
        ("br-dpu", "patch-dpu-ovn", "br-ovn", "patch-ovn-dpu"),
    ]
    
    for br1, port1, br2, port2 in patch_ports:
        run_command([
            "ovs-vsctl", "--may-exist", "add-port", br1, port1,
            "--", "set", "Interface", port1, "type=patch",
            f"options:peer={port2}",
        ])
        run_command([
            "ovs-vsctl", "--may-exist", "add-port", br2, port2,
            "--", "set", "Interface", port2, "type=patch",
            f"options:peer={port1}",
        ])
    
    log_info("OVS bridges configured successfully")
    return True


def get_ovs_bridges() -> List[str]:
    """
    Get list of OVS bridges.
    
    Returns:
        List of bridge names
    """
    result = run_command(["ovs-vsctl", "list-br"])
    if result.success:
        return [br.strip() for br in result.stdout.splitlines() if br.strip()]
    return []


def cleanup_ovs_bridges() -> bool:
    """
    Clean up OVS bridges created for DPF.
    
    Returns:
        True if successful
    """
    log_step("Cleaning Up OVS Bridges")
    
    bridges = ["br-sfc", "br-dpu", "br-ovn"]
    
    for bridge in bridges:
        result = run_command(["ovs-vsctl", "--if-exists", "del-br", bridge])
        if result.success:
            log_debug(f"Deleted bridge: {bridge}")
    
    return True
