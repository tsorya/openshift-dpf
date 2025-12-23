"""
Command-line interface for OpenShift DPF.

This module provides the main CLI entry point using Click.
"""

import sys
from pathlib import Path
from typing import Optional

import click

from dpf import __version__
from dpf.cluster import (
    check_create_cluster,
    clean_all,
    create_day2_cluster,
    delete_cluster,
    deploy_lso,
    deploy_odf,
    get_iso,
    get_kubeconfig,
    start_cluster_installation,
    wait_for_cluster_status,
)
from dpf.config import get_config, load_config, reload_config
from dpf.dpf import (
    apply_dpf,
    create_ignition_template,
    deploy_argocd,
    deploy_hypershift,
    deploy_maintenance_operator,
    deploy_metallb,
    deploy_nfd,
)
from dpf.manifests import deploy_core_operator_sources, prepare_manifests, prepare_nfs
from dpf.network import (
    cleanup_bridge,
    set_interface_mtu,
    setup_bridge,
    setup_nfs_server,
    update_etc_hosts,
)
from dpf.post_install import (
    apply_post_installation,
    prepare_post_installation,
    redeploy,
)
from dpf.sanity_checks import run_sanity_checks
from dpf.tools import install_golang, install_helm, install_hypershift, install_oc
from dpf.utils import log_error, log_info, verify_files
from dpf.vm import create_vms, delete_vms


@click.group()
@click.version_option(version=__version__)
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.option("--env-file", type=click.Path(exists=True), help="Path to .env file")
@click.pass_context
def cli(ctx: click.Context, debug: bool, env_file: Optional[str]) -> None:
    """OpenShift DPF - Data Processing Framework deployment tool."""
    ctx.ensure_object(dict)

    # Load configuration
    env_path = Path(env_file) if env_file else None
    config = reload_config(env_path)

    if debug:
        config.debug = True

    ctx.obj["config"] = config


# ============================================================================
# Cluster Management Commands
# ============================================================================

@cli.group()
def cluster() -> None:
    """Cluster management commands."""
    pass


@cluster.command("create")
@click.pass_context
def cluster_create(ctx: click.Context) -> None:
    """Create or check if cluster exists."""
    config = ctx.obj["config"]
    success = check_create_cluster(config)
    sys.exit(0 if success else 1)


@cluster.command("delete")
@click.pass_context
def cluster_delete(ctx: click.Context) -> None:
    """Delete the cluster."""
    config = ctx.obj["config"]
    success = delete_cluster(config)
    sys.exit(0 if success else 1)


@cluster.command("install")
@click.pass_context
def cluster_install(ctx: click.Context) -> None:
    """Start cluster installation."""
    config = ctx.obj["config"]
    success = start_cluster_installation(config)
    sys.exit(0 if success else 1)


@cluster.command("wait")
@click.argument("status")
@click.pass_context
def cluster_wait(ctx: click.Context, status: str) -> None:
    """Wait for cluster to reach a specific status."""
    config = ctx.obj["config"]
    success = wait_for_cluster_status(status, config)
    sys.exit(0 if success else 1)


@cluster.command("kubeconfig")
@click.pass_context
def cluster_kubeconfig(ctx: click.Context) -> None:
    """Get or download cluster kubeconfig."""
    config = ctx.obj["config"]
    try:
        path = get_kubeconfig(config)
        click.echo(f"Kubeconfig: {path}")
        sys.exit(0)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cluster.command("clean-all")
@click.pass_context
def cluster_clean_all(ctx: click.Context) -> None:
    """Delete cluster, VMs, and clean all resources."""
    config = ctx.obj["config"]
    success = clean_all(config)
    sys.exit(0 if success else 1)


@cluster.command("download-iso")
@click.pass_context
def cluster_download_iso(ctx: click.Context) -> None:
    """Download ISO for master nodes."""
    config = ctx.obj["config"]
    get_iso(config, "day1", "download")
    sys.exit(0)


@cluster.command("create-day2")
@click.pass_context
def cluster_create_day2(ctx: click.Context) -> None:
    """Move cluster to day2 mode for adding workers."""
    config = ctx.obj["config"]
    success = create_day2_cluster(config)
    sys.exit(0 if success else 1)


@cluster.command("deploy-lso")
@click.pass_context
def cluster_deploy_lso(ctx: click.Context) -> None:
    """Deploy Local Storage Operator."""
    config = ctx.obj["config"]
    success = deploy_lso(config)
    sys.exit(0 if success else 1)


@cluster.command("deploy-odf")
@click.pass_context
def cluster_deploy_odf(ctx: click.Context) -> None:
    """Deploy OpenShift Data Foundation."""
    config = ctx.obj["config"]
    success = deploy_odf(config)
    sys.exit(0 if success else 1)


# ============================================================================
# VM Management Commands
# ============================================================================

@cli.group()
def vm() -> None:
    """Virtual machine management commands."""
    pass


@vm.command("create")
@click.pass_context
def vm_create(ctx: click.Context) -> None:
    """Create VMs for the cluster."""
    config = ctx.obj["config"]
    success = create_vms(config)
    sys.exit(0 if success else 1)


@vm.command("delete")
@click.pass_context
def vm_delete(ctx: click.Context) -> None:
    """Delete VMs with the configured prefix."""
    config = ctx.obj["config"]
    success = delete_vms(config)
    sys.exit(0 if success else 1)


# ============================================================================
# DPF Deployment Commands
# ============================================================================

@cli.group()
def dpf() -> None:
    """DPF deployment commands."""
    pass


@dpf.command("deploy")
@click.pass_context
def dpf_deploy(ctx: click.Context) -> None:
    """Deploy complete DPF stack."""
    config = ctx.obj["config"]
    success = apply_dpf(config)
    sys.exit(0 if success else 1)


@dpf.command("deploy-nfd")
@click.pass_context
def dpf_deploy_nfd(ctx: click.Context) -> None:
    """Deploy Node Feature Discovery operator."""
    config = ctx.obj["config"]
    success = deploy_nfd(config)
    sys.exit(0 if success else 1)


@dpf.command("deploy-metallb")
@click.pass_context
def dpf_deploy_metallb(ctx: click.Context) -> None:
    """Deploy MetalLB operator."""
    config = ctx.obj["config"]
    success = deploy_metallb(config)
    sys.exit(0 if success else 1)


@dpf.command("deploy-argocd")
@click.pass_context
def dpf_deploy_argocd(ctx: click.Context) -> None:
    """Deploy GitOps/ArgoCD operator."""
    config = ctx.obj["config"]
    success = deploy_argocd(config)
    sys.exit(0 if success else 1)


@dpf.command("deploy-maintenance")
@click.pass_context
def dpf_deploy_maintenance(ctx: click.Context) -> None:
    """Deploy Maintenance Operator."""
    config = ctx.obj["config"]
    success = deploy_maintenance_operator(config)
    sys.exit(0 if success else 1)


@dpf.command("deploy-hypershift")
@click.pass_context
def dpf_deploy_hypershift(ctx: click.Context) -> None:
    """Deploy Hypershift hosted cluster."""
    config = ctx.obj["config"]
    success = deploy_hypershift(config)
    sys.exit(0 if success else 1)


@dpf.command("create-ignition")
@click.pass_context
def dpf_create_ignition(ctx: click.Context) -> None:
    """Create ignition template."""
    config = ctx.obj["config"]
    success = create_ignition_template(config)
    sys.exit(0 if success else 1)


# ============================================================================
# Manifest Commands
# ============================================================================

@cli.group()
def manifests() -> None:
    """Manifest management commands."""
    pass


@manifests.command("prepare-cluster")
@click.pass_context
def manifests_prepare_cluster(ctx: click.Context) -> None:
    """Prepare cluster installation manifests."""
    config = ctx.obj["config"]
    success = prepare_manifests("cluster", config)
    sys.exit(0 if success else 1)


@manifests.command("prepare-dpf")
@click.pass_context
def manifests_prepare_dpf(ctx: click.Context) -> None:
    """Prepare DPF installation manifests."""
    config = ctx.obj["config"]
    success = prepare_manifests("dpf", config)
    sys.exit(0 if success else 1)


@manifests.command("prepare-nfs")
@click.pass_context
def manifests_prepare_nfs(ctx: click.Context) -> None:
    """Prepare NFS manifests."""
    config = ctx.obj["config"]
    success = prepare_nfs(config)
    sys.exit(0 if success else 1)


@manifests.command("deploy-operators")
@click.pass_context
def manifests_deploy_operators(ctx: click.Context) -> None:
    """Deploy core operator sources."""
    config = ctx.obj["config"]
    success = deploy_core_operator_sources(config)
    sys.exit(0 if success else 1)


# ============================================================================
# Post-Installation Commands
# ============================================================================

@cli.group("post-install")
def post_install() -> None:
    """Post-installation commands."""
    pass


@post_install.command("prepare")
@click.pass_context
def post_install_prepare(ctx: click.Context) -> None:
    """Prepare post-installation manifests."""
    config = ctx.obj["config"]
    success = prepare_post_installation(config)
    sys.exit(0 if success else 1)


@post_install.command("apply")
@click.pass_context
def post_install_apply(ctx: click.Context) -> None:
    """Apply post-installation manifests."""
    config = ctx.obj["config"]
    success = apply_post_installation(config)
    sys.exit(0 if success else 1)


@post_install.command("redeploy")
@click.pass_context
def post_install_redeploy(ctx: click.Context) -> None:
    """Redeploy DPU services."""
    config = ctx.obj["config"]
    success = redeploy(config)
    sys.exit(0 if success else 1)


# ============================================================================
# Tools Commands
# ============================================================================

@cli.group()
def tools() -> None:
    """Tool installation commands."""
    pass


@tools.command("install-helm")
def tools_install_helm() -> None:
    """Install Helm."""
    success = install_helm()
    sys.exit(0 if success else 1)


@tools.command("install-hypershift")
@click.pass_context
def tools_install_hypershift(ctx: click.Context) -> None:
    """Install Hypershift binary and operator."""
    config = ctx.obj["config"]
    success = install_hypershift(config)
    sys.exit(0 if success else 1)


@tools.command("install-oc")
def tools_install_oc() -> None:
    """Install OpenShift CLI."""
    success = install_oc()
    sys.exit(0 if success else 1)


@tools.command("install-go")
def tools_install_go() -> None:
    """Install Go."""
    success = install_golang()
    sys.exit(0 if success else 1)


# ============================================================================
# Network Commands
# ============================================================================

@cli.group()
def network() -> None:
    """Network configuration commands."""
    pass


@network.command("setup-bridge")
@click.option("--force", is_flag=True, help="Force bridge creation")
@click.pass_context
def network_setup_bridge(ctx: click.Context, force: bool) -> None:
    """Set up network bridge for VMs."""
    config = ctx.obj["config"]
    success = setup_bridge(config, force)
    sys.exit(0 if success else 1)


@network.command("cleanup-bridge")
@click.pass_context
def network_cleanup_bridge(ctx: click.Context) -> None:
    """Clean up network bridge."""
    config = ctx.obj["config"]
    success = cleanup_bridge(config)
    sys.exit(0 if success else 1)


@network.command("update-hosts")
@click.pass_context
def network_update_hosts(ctx: click.Context) -> None:
    """Update /etc/hosts with cluster entries."""
    config = ctx.obj["config"]
    success = update_etc_hosts(config)
    sys.exit(0 if success else 1)


@network.command("set-mtu")
@click.argument("interface")
@click.option("--mtu", default=9000, help="MTU value (default: 9000)")
def network_set_mtu(interface: str, mtu: int) -> None:
    """Set MTU on a network interface."""
    success = set_interface_mtu(interface, mtu)
    sys.exit(0 if success else 1)


@network.command("setup-nfs")
@click.pass_context
def network_setup_nfs(ctx: click.Context) -> None:
    """Set up NFS server."""
    config = ctx.obj["config"]
    success = setup_nfs_server(config)
    sys.exit(0 if success else 1)


# ============================================================================
# Sanity Check Commands
# ============================================================================

@cli.command("sanity-check")
@click.pass_context
def sanity_check(ctx: click.Context) -> None:
    """Run DPF sanity checks."""
    config = ctx.obj["config"]
    success = run_sanity_checks(config)
    sys.exit(0 if success else 1)


# ============================================================================
# Utility Commands
# ============================================================================

@cli.command("verify-files")
@click.pass_context
def verify_files_cmd(ctx: click.Context) -> None:
    """Verify required files exist."""
    config = ctx.obj["config"]
    success = verify_files(config)
    sys.exit(0 if success else 1)


@cli.command("all")
@click.pass_context
def run_all(ctx: click.Context) -> None:
    """Run complete DPF installation workflow."""
    config = ctx.obj["config"]

    steps = [
        ("Verify files", lambda: verify_files(config)),
        ("Check/create cluster", lambda: check_create_cluster(config)),
        ("Create VMs", lambda: create_vms(config)),
        ("Prepare manifests", lambda: prepare_manifests("cluster", config)),
        ("Install cluster", lambda: start_cluster_installation(config)),
        ("Update /etc/hosts", lambda: update_etc_hosts(config)),
        ("Get kubeconfig", lambda: bool(get_kubeconfig(config))),
        ("Deploy DPF", lambda: apply_dpf(config)),
        ("Prepare DPU files", lambda: prepare_post_installation(config)),
        ("Deploy DPU services", lambda: apply_post_installation(config)),
    ]

    for step_name, step_func in steps:
        log_info(f"Step: {step_name}")
        try:
            if not step_func():
                log_error(f"Step failed: {step_name}")
                sys.exit(1)
        except Exception as e:
            log_error(f"Step failed: {step_name}: {e}")
            sys.exit(1)

    click.echo("")
    click.echo("=" * 80)
    click.echo("✅ DPF Installation Complete!")
    click.echo("=" * 80)
    click.echo("")
    click.echo("Next steps to add worker nodes with DPUs:")
    click.echo("1. Access Assisted Installer UI and download discovery ISO")
    click.echo("2. Boot worker nodes with the discovery ISO")
    click.echo("3. Approve pending certificate signing requests")
    click.echo("4. Wait for nodes to join the cluster")
    click.echo("5. Monitor DPU deployment progress")
    click.echo("")
    click.echo("=" * 80)

    sys.exit(0)


def main() -> None:
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
