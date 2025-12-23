"""
Virtual Machine management module for OpenShift DPF.

This module provides functions for creating and managing VMs
using the libvirt Python library instead of virsh subprocess calls.
"""

import os
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import libvirt
    LIBVIRT_AVAILABLE = True
except ImportError:
    LIBVIRT_AVAILABLE = False
    libvirt = None

from dpf.utils import (
    ensure_directory,
    file_exists,
    generate_mac_address,
    log_debug,
    log_error,
    log_info,
    log_step,
    log_warning,
    run_command,
)


class LibvirtConnection:
    """Context manager for libvirt connections."""
    
    def __init__(self, uri: str = "qemu:///system"):
        self.uri = uri
        self.conn = None
    
    def __enter__(self) -> "libvirt.virConnect":
        if not LIBVIRT_AVAILABLE:
            raise RuntimeError("libvirt-python is not installed")
        
        self.conn = libvirt.open(self.uri)
        if self.conn is None:
            raise RuntimeError(f"Failed to connect to {self.uri}")
        return self.conn
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()


def _get_vm_xml(
    name: str,
    ram_mb: int,
    vcpus: int,
    disk_path: str,
    disk_size_gb: int,
    iso_path: str,
    network_bridge: str,
    mac_address: str,
    additional_disks: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Generate VM XML definition.
    
    Args:
        name: VM name
        ram_mb: RAM in megabytes
        vcpus: Number of virtual CPUs
        disk_path: Path to the primary disk image
        disk_size_gb: Size of primary disk in GB
        iso_path: Path to boot ISO
        network_bridge: Bridge network name
        mac_address: MAC address for the network interface
        additional_disks: List of additional disks
    
    Returns:
        XML definition string
    """
    # Convert RAM to KB
    ram_kb = ram_mb * 1024
    
    # Build disk entries
    disk_entries = []
    
    # Primary disk
    disk_entries.append(f"""
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native'/>
      <source file='{disk_path}'/>
      <target dev='vda' bus='virtio'/>
    </disk>""")
    
    # CD-ROM with ISO
    disk_entries.append(f"""
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{iso_path}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
      <boot order='1'/>
    </disk>""")
    
    # Additional disks
    if additional_disks:
        disk_letters = ['b', 'c', 'd', 'e', 'f', 'g', 'h']
        for i, disk in enumerate(additional_disks):
            if i >= len(disk_letters):
                break
            disk_entries.append(f"""
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' io='native'/>
      <source file='{disk["path"]}'/>
      <target dev='vd{disk_letters[i]}' bus='virtio'/>
    </disk>""")
    
    disks_xml = "".join(disk_entries)
    
    xml = f"""<domain type='kvm'>
  <name>{name}</name>
  <memory unit='KiB'>{ram_kb}</memory>
  <currentMemory unit='KiB'>{ram_kb}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='cdrom'/>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    {disks_xml}
    <controller type='usb' index='0' model='qemu-xhci' ports='15'/>
    <controller type='pci' index='0' model='pcie-root'/>
    <controller type='pci' index='1' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='1' port='0x10'/>
    </controller>
    <interface type='bridge'>
      <mac address='{mac_address}'/>
      <source bridge='{network_bridge}'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <input type='tablet' bus='usb'>
      <address type='usb' bus='0' port='1'/>
    </input>
    <input type='mouse' bus='ps2'/>
    <input type='keyboard' bus='ps2'/>
    <graphics type='vnc' port='-1' autoport='yes' listen='0.0.0.0'>
      <listen type='address' address='0.0.0.0'/>
    </graphics>
    <video>
      <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/>
    </video>
    <memballoon model='virtio'/>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>"""
    
    return xml


def _create_disk_image(path: str, size_gb: int) -> bool:
    """
    Create a qcow2 disk image.
    
    Args:
        path: Path for the disk image
        size_gb: Size in gigabytes
    
    Returns:
        True if successful
    """
    ensure_directory(Path(path).parent)
    
    result = run_command([
        "qemu-img", "create",
        "-f", "qcow2",
        path,
        f"{size_gb}G"
    ])
    
    if result.success:
        log_debug(f"Created disk image: {path} ({size_gb}GB)")
        return True
    else:
        log_error(f"Failed to create disk image: {result.stderr}")
        return False


def vm_exists(name: str) -> bool:
    """
    Check if a VM exists.
    
    Args:
        name: VM name
    
    Returns:
        True if VM exists
    """
    if not LIBVIRT_AVAILABLE:
        log_error("libvirt-python is not installed")
        return False
    
    try:
        with LibvirtConnection() as conn:
            try:
                conn.lookupByName(name)
                return True
            except libvirt.libvirtError:
                return False
    except Exception as e:
        log_error(f"Failed to check VM existence: {e}")
        return False


def get_vm_state(name: str) -> Optional[str]:
    """
    Get the state of a VM.
    
    Args:
        name: VM name
    
    Returns:
        State string or None if VM doesn't exist
    """
    if not LIBVIRT_AVAILABLE:
        return None
    
    state_names = {
        libvirt.VIR_DOMAIN_NOSTATE: "nostate",
        libvirt.VIR_DOMAIN_RUNNING: "running",
        libvirt.VIR_DOMAIN_BLOCKED: "blocked",
        libvirt.VIR_DOMAIN_PAUSED: "paused",
        libvirt.VIR_DOMAIN_SHUTDOWN: "shutdown",
        libvirt.VIR_DOMAIN_SHUTOFF: "shutoff",
        libvirt.VIR_DOMAIN_CRASHED: "crashed",
        libvirt.VIR_DOMAIN_PMSUSPENDED: "pmsuspended",
    }
    
    try:
        with LibvirtConnection() as conn:
            dom = conn.lookupByName(name)
            state, _ = dom.state()
            return state_names.get(state, "unknown")
    except libvirt.libvirtError:
        return None
    except Exception as e:
        log_error(f"Failed to get VM state: {e}")
        return None


def create_vm(
    name: str,
    ram_mb: int,
    vcpus: int,
    disk_path: str,
    disk_size_gb: int,
    iso_path: str,
    network_bridge: str,
    mac_address: Optional[str] = None,
    additional_disks: Optional[List[Dict[str, Any]]] = None,
    start: bool = True,
) -> bool:
    """
    Create and optionally start a VM.
    
    Args:
        name: VM name
        ram_mb: RAM in megabytes
        vcpus: Number of virtual CPUs
        disk_path: Path to the primary disk image
        disk_size_gb: Size of primary disk in GB
        iso_path: Path to boot ISO
        network_bridge: Bridge network name
        mac_address: MAC address (generated if not provided)
        additional_disks: List of additional disks
        start: Whether to start the VM after creation
    
    Returns:
        True if successful
    """
    if not LIBVIRT_AVAILABLE:
        log_error("libvirt-python is not installed")
        return False
    
    # Check if VM already exists
    if vm_exists(name):
        log_warning(f"VM {name} already exists")
        return True
    
    # Generate MAC address if not provided
    if not mac_address:
        mac_address = generate_mac_address()
    
    # Create disk image
    if not _create_disk_image(disk_path, disk_size_gb):
        return False
    
    # Create additional disks
    if additional_disks:
        for disk in additional_disks:
            if not _create_disk_image(disk["path"], disk["size_gb"]):
                return False
    
    # Check ISO exists
    if not file_exists(iso_path):
        log_error(f"ISO file not found: {iso_path}")
        return False
    
    # Generate XML
    xml = _get_vm_xml(
        name=name,
        ram_mb=ram_mb,
        vcpus=vcpus,
        disk_path=disk_path,
        disk_size_gb=disk_size_gb,
        iso_path=iso_path,
        network_bridge=network_bridge,
        mac_address=mac_address,
        additional_disks=additional_disks,
    )
    
    try:
        with LibvirtConnection() as conn:
            # Define the VM
            dom = conn.defineXML(xml)
            if dom is None:
                log_error(f"Failed to define VM {name}")
                return False
            
            log_info(f"Defined VM: {name}")
            
            # Start the VM if requested
            if start:
                if dom.create() < 0:
                    log_error(f"Failed to start VM {name}")
                    return False
                log_info(f"Started VM: {name}")
            
            return True
            
    except libvirt.libvirtError as e:
        log_error(f"Libvirt error creating VM {name}: {e}")
        return False
    except Exception as e:
        log_error(f"Error creating VM {name}: {e}")
        return False


def delete_vm(name: str, delete_disks: bool = True) -> bool:
    """
    Delete a VM and optionally its disks.
    
    Args:
        name: VM name
        delete_disks: Whether to delete associated disk images
    
    Returns:
        True if successful
    """
    if not LIBVIRT_AVAILABLE:
        log_error("libvirt-python is not installed")
        return False
    
    if not vm_exists(name):
        log_debug(f"VM {name} does not exist")
        return True
    
    try:
        with LibvirtConnection() as conn:
            dom = conn.lookupByName(name)
            
            # Get disk paths before destroying
            disk_paths = []
            if delete_disks:
                xml = dom.XMLDesc()
                root = ET.fromstring(xml)
                for disk in root.findall(".//disk[@device='disk']/source"):
                    file_path = disk.get("file")
                    if file_path:
                        disk_paths.append(file_path)
            
            # Stop if running
            state, _ = dom.state()
            if state == libvirt.VIR_DOMAIN_RUNNING:
                dom.destroy()
                log_debug(f"Stopped VM: {name}")
            
            # Undefine
            dom.undefine()
            log_info(f"Deleted VM: {name}")
            
            # Delete disks
            if delete_disks:
                for path in disk_paths:
                    try:
                        os.unlink(path)
                        log_debug(f"Deleted disk: {path}")
                    except OSError as e:
                        log_warning(f"Failed to delete disk {path}: {e}")
            
            return True
            
    except libvirt.libvirtError as e:
        log_error(f"Libvirt error deleting VM {name}: {e}")
        return False
    except Exception as e:
        log_error(f"Error deleting VM {name}: {e}")
        return False


def start_vm(name: str) -> bool:
    """
    Start a VM.
    
    Args:
        name: VM name
    
    Returns:
        True if successful
    """
    if not LIBVIRT_AVAILABLE:
        log_error("libvirt-python is not installed")
        return False
    
    try:
        with LibvirtConnection() as conn:
            dom = conn.lookupByName(name)
            
            state, _ = dom.state()
            if state == libvirt.VIR_DOMAIN_RUNNING:
                log_debug(f"VM {name} is already running")
                return True
            
            if dom.create() < 0:
                log_error(f"Failed to start VM {name}")
                return False
            
            log_info(f"Started VM: {name}")
            return True
            
    except libvirt.libvirtError as e:
        log_error(f"Failed to start VM {name}: {e}")
        return False


def stop_vm(name: str, force: bool = False) -> bool:
    """
    Stop a VM.
    
    Args:
        name: VM name
        force: Force shutdown (destroy) instead of graceful shutdown
    
    Returns:
        True if successful
    """
    if not LIBVIRT_AVAILABLE:
        log_error("libvirt-python is not installed")
        return False
    
    try:
        with LibvirtConnection() as conn:
            dom = conn.lookupByName(name)
            
            state, _ = dom.state()
            if state != libvirt.VIR_DOMAIN_RUNNING:
                log_debug(f"VM {name} is not running")
                return True
            
            if force:
                dom.destroy()
            else:
                dom.shutdown()
            
            log_info(f"Stopped VM: {name}")
            return True
            
    except libvirt.libvirtError as e:
        log_error(f"Failed to stop VM {name}: {e}")
        return False


def list_vms(prefix: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List all VMs, optionally filtered by name prefix.
    
    Args:
        prefix: Optional name prefix to filter by
    
    Returns:
        List of VM info dictionaries
    """
    if not LIBVIRT_AVAILABLE:
        log_error("libvirt-python is not installed")
        return []
    
    vms = []
    
    try:
        with LibvirtConnection() as conn:
            for dom in conn.listAllDomains():
                name = dom.name()
                
                if prefix and not name.startswith(prefix):
                    continue
                
                state, _ = dom.state()
                state_names = {
                    libvirt.VIR_DOMAIN_NOSTATE: "nostate",
                    libvirt.VIR_DOMAIN_RUNNING: "running",
                    libvirt.VIR_DOMAIN_BLOCKED: "blocked",
                    libvirt.VIR_DOMAIN_PAUSED: "paused",
                    libvirt.VIR_DOMAIN_SHUTDOWN: "shutdown",
                    libvirt.VIR_DOMAIN_SHUTOFF: "shutoff",
                    libvirt.VIR_DOMAIN_CRASHED: "crashed",
                    libvirt.VIR_DOMAIN_PMSUSPENDED: "pmsuspended",
                }
                
                info = dom.info()
                vms.append({
                    "name": name,
                    "state": state_names.get(state, "unknown"),
                    "memory_kb": info[2],
                    "vcpus": info[3],
                    "uuid": dom.UUIDString(),
                })
        
        return vms
        
    except Exception as e:
        log_error(f"Failed to list VMs: {e}")
        return []


def create_vms(config: Any) -> bool:
    """
    Create VMs for the cluster based on configuration.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step(f"Creating {config.vm.vm_count} VMs")
    
    if not LIBVIRT_AVAILABLE:
        log_error("libvirt-python is not installed. Install with: pip install libvirt-python")
        return False
    
    # Get ISO path
    iso_path = Path(config.vm.iso_folder) / f"{config.cluster.cluster_name}-day1.iso"
    if not iso_path.exists():
        log_error(f"ISO not found: {iso_path}")
        log_error("Run 'dpf cluster download-iso' first")
        return False
    
    # Create each VM
    for i in range(config.vm.vm_count):
        vm_name = f"{config.vm_prefix}-{i}"
        
        # Generate MAC addresses from config or random
        mac_address = None
        if hasattr(config, 'mac_addresses') and i < len(config.mac_addresses):
            mac_address = config.mac_addresses[i]
        
        # Prepare disk paths
        disk_dir = Path(config.vm_disk_dir)
        primary_disk = str(disk_dir / f"{vm_name}.qcow2")
        
        # Additional disks for storage
        additional_disks = []
        if hasattr(config, 'extra_disk_count') and config.extra_disk_count > 0:
            for j in range(config.extra_disk_count):
                additional_disks.append({
                    "path": str(disk_dir / f"{vm_name}-extra{j}.qcow2"),
                    "size_gb": config.extra_disk_size,
                })
        
        success = create_vm(
            name=vm_name,
            ram_mb=config.vm_ram,
            vcpus=config.vm_vcpus,
            disk_path=primary_disk,
            disk_size_gb=config.vm_disk_size,
            iso_path=str(iso_path),
            network_bridge=config.network_bridge,
            mac_address=mac_address,
            additional_disks=additional_disks,
            start=True,
        )
        
        if not success:
            log_error(f"Failed to create VM {vm_name}")
            return False
    
    log_info(f"Created {config.vm.vm_count} VMs")
    return True


def delete_vms(config: Any) -> bool:
    """
    Delete VMs with the configured prefix.
    
    Args:
        config: Configuration object
    
    Returns:
        True if successful
    """
    log_step(f"Deleting VMs with prefix: {config.vm_prefix}")
    
    if not LIBVIRT_AVAILABLE:
        log_warning("libvirt-python is not installed, cannot delete VMs")
        return True
    
    vms = list_vms(prefix=config.vm_prefix)
    
    if not vms:
        log_info("No VMs found to delete")
        return True
    
    success = True
    for vm in vms:
        if not delete_vm(vm["name"], delete_disks=True):
            success = False
    
    if success:
        log_info(f"Deleted {len(vms)} VMs")
    
    return success


def wait_for_vms_running(config: Any, timeout: int = 300) -> bool:
    """
    Wait for all VMs to be running.
    
    Args:
        config: Configuration object
        timeout: Timeout in seconds
    
    Returns:
        True if all VMs are running
    """
    log_step("Waiting for VMs to start")
    
    start_time = time.time()
    expected_count = config.vm.vm_count
    
    while time.time() - start_time < timeout:
        vms = list_vms(prefix=config.vm_prefix)
        running = [vm for vm in vms if vm.get("state") == "running"]
        
        log_debug(f"VMs running: {len(running)}/{expected_count}")
        
        if len(running) >= expected_count:
            log_info(f"All {expected_count} VMs are running")
            return True
        
        time.sleep(10)
    
    log_error(f"Timeout waiting for VMs to start")
    return False
