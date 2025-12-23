"""
Sanity check module for OpenShift DPF.

This module provides functions for running sanity checks on DPF deployments
using the Kubernetes Python client for all cluster operations.
"""

import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml

from dpf.k8s import K8sClient, get_k8s_client
from dpf.utils import (
    log_debug,
    log_error,
    log_info,
    log_step,
    log_warning,
)


@dataclass
class TestResult:
    """Result of a sanity check test."""
    name: str
    passed: bool
    message: str
    details: Optional[str] = None


@dataclass
class PingResult:
    """Result of a ping test."""
    source: str
    destination: str
    mtu: int
    packets_sent: int
    packets_received: int
    packet_loss: float
    passed: bool


def check_cluster_operators(config: Any) -> TestResult:
    """
    Check that all cluster operators are available.
    
    Args:
        config: Configuration object
    
    Returns:
        TestResult
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    operators = k8s.get_cluster_operators()
    
    if not operators:
        return TestResult(
            name="Cluster Operators",
            passed=False,
            message="Failed to get cluster operators",
        )
    
    degraded = []
    not_available = []
    
    for op in operators:
        name = op.get("name")
        if op.get("degraded"):
            degraded.append(name)
        if not op.get("available"):
            not_available.append(name)
    
    if degraded or not_available:
        details = []
        if degraded:
            details.append(f"Degraded: {', '.join(degraded)}")
        if not_available:
            details.append(f"Not Available: {', '.join(not_available)}")
        
        return TestResult(
            name="Cluster Operators",
            passed=False,
            message="Some operators are not healthy",
            details="; ".join(details),
        )
    
    return TestResult(
        name="Cluster Operators",
        passed=True,
        message=f"All {len(operators)} operators are healthy",
    )


def check_dpf_operator(config: Any) -> TestResult:
    """
    Check that DPF operator is running.
    
    Args:
        config: Configuration object
    
    Returns:
        TestResult
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    pods = k8s.get_pods(
        "dpf-operator-system",
        label_selector="control-plane=controller-manager",
    )
    
    if not pods:
        return TestResult(
            name="DPF Operator",
            passed=False,
            message="DPF operator pod not found",
        )
    
    running_pods = [p for p in pods if p.get("status") == "Running" and p.get("ready")]
    
    if not running_pods:
        return TestResult(
            name="DPF Operator",
            passed=False,
            message="DPF operator pod is not ready",
            details=f"Pod status: {pods[0].get('status')}",
        )
    
    return TestResult(
        name="DPF Operator",
        passed=True,
        message="DPF operator is running",
    )


def check_dpus(config: Any) -> TestResult:
    """
    Check DPU status.
    
    Args:
        config: Configuration object
    
    Returns:
        TestResult
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    dpus = k8s.list_custom_resources(
        group="provisioning.dpu.nvidia.com",
        version="v1alpha1",
        plural="dpus",
        namespace=config.dpf_namespace,
    )
    
    if not dpus:
        return TestResult(
            name="DPUs",
            passed=False,
            message="No DPUs found",
        )
    
    ready_dpus = []
    not_ready = []
    
    for dpu in dpus:
        name = dpu.get("metadata", {}).get("name")
        phase = dpu.get("status", {}).get("phase", "Unknown")
        
        if phase == "Ready":
            ready_dpus.append(name)
        else:
            not_ready.append(f"{name}({phase})")
    
    if not_ready:
        return TestResult(
            name="DPUs",
            passed=False,
            message=f"{len(not_ready)} DPUs not ready",
            details=f"Not ready: {', '.join(not_ready)}",
        )
    
    return TestResult(
        name="DPUs",
        passed=True,
        message=f"All {len(ready_dpus)} DPUs are ready",
    )


def check_dpu_services(config: Any) -> TestResult:
    """
    Check DPU services status.
    
    Args:
        config: Configuration object
    
    Returns:
        TestResult
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    services = k8s.list_custom_resources(
        group="svc.dpu.nvidia.com",
        version="v1alpha1",
        plural="dpuservices",
        namespace=config.dpf_namespace,
    )
    
    if not services:
        return TestResult(
            name="DPU Services",
            passed=False,
            message="No DPU services found",
        )
    
    running = []
    not_running = []
    
    for svc in services:
        name = svc.get("metadata", {}).get("name")
        phase = svc.get("status", {}).get("phase", "Unknown")
        
        if phase == "Running":
            running.append(name)
        else:
            not_running.append(f"{name}({phase})")
    
    if not_running:
        return TestResult(
            name="DPU Services",
            passed=False,
            message=f"{len(not_running)} services not running",
            details=f"Not running: {', '.join(not_running)}",
        )
    
    return TestResult(
        name="DPU Services",
        passed=True,
        message=f"All {len(running)} DPU services are running",
    )


def check_hosted_cluster(config: Any) -> TestResult:
    """
    Check hosted cluster status.
    
    Args:
        config: Configuration object
    
    Returns:
        TestResult
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    hosted_cluster_name = config.hosted_cluster_name
    
    hc = k8s.get_custom_resource(
        group="hypershift.openshift.io",
        version="v1beta1",
        plural="hostedclusters",
        name=hosted_cluster_name,
        namespace="clusters",
    )
    
    if not hc:
        return TestResult(
            name="Hosted Cluster",
            passed=False,
            message=f"Hosted cluster {hosted_cluster_name} not found",
        )
    
    conditions = hc.get("status", {}).get("conditions", [])
    
    available = any(
        c.get("type") == "Available" and c.get("status") == "True"
        for c in conditions
    )
    
    if not available:
        return TestResult(
            name="Hosted Cluster",
            passed=False,
            message="Hosted cluster is not available",
        )
    
    return TestResult(
        name="Hosted Cluster",
        passed=True,
        message=f"Hosted cluster {hosted_cluster_name} is available",
    )


def run_ping_test(
    k8s: K8sClient,
    source_pod: str,
    source_namespace: str,
    dest_ip: str,
    mtu: int = 1490,
    count: int = 5,
    container: Optional[str] = None,
) -> PingResult:
    """
    Run a ping test from a pod.
    
    Args:
        k8s: Kubernetes client
        source_pod: Source pod name
        source_namespace: Source pod namespace
        dest_ip: Destination IP address
        mtu: MTU size for the test
        count: Number of pings
        container: Container name (optional)
    
    Returns:
        PingResult
    """
    # Calculate packet size (MTU - 28 bytes for IP + ICMP headers)
    packet_size = mtu - 28
    
    command = [
        "ping",
        "-c", str(count),
        "-s", str(packet_size),
        "-M", "do",  # Don't fragment
        dest_ip,
    ]
    
    exit_code, stdout, stderr = k8s.exec_in_pod(
        source_pod,
        source_namespace,
        command,
        container,
    )
    
    # Parse ping output
    packets_sent = count
    packets_received = 0
    packet_loss = 100.0
    
    # Look for "X packets transmitted, Y received"
    match = re.search(r"(\d+) packets transmitted, (\d+) received", stdout)
    if match:
        packets_sent = int(match.group(1))
        packets_received = int(match.group(2))
        if packets_sent > 0:
            packet_loss = ((packets_sent - packets_received) / packets_sent) * 100
    
    return PingResult(
        source=f"{source_namespace}/{source_pod}",
        destination=dest_ip,
        mtu=mtu,
        packets_sent=packets_sent,
        packets_received=packets_received,
        packet_loss=packet_loss,
        passed=packets_received > 0,
    )


def deploy_workload_pod(k8s: K8sClient, name: str, namespace: str, node_selector: Optional[Dict[str, str]] = None) -> bool:
    """
    Deploy a workload pod for testing.
    
    Args:
        k8s: Kubernetes client
        name: Pod name
        namespace: Namespace
        node_selector: Optional node selector
    
    Returns:
        True if successful
    """
    # Check if pod already exists
    existing = k8s.get_pod(name, namespace)
    if existing and existing.get("status") == "Running":
        return True
    
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app": "dpf-test"},
        },
        "spec": {
            "containers": [
                {
                    "name": "test",
                    "image": "registry.access.redhat.com/ubi9/ubi-minimal:latest",
                    "command": ["sleep", "infinity"],
                    "securityContext": {
                        "privileged": True,
                    },
                }
            ],
            "restartPolicy": "Never",
        },
    }
    
    if node_selector:
        pod["spec"]["nodeSelector"] = node_selector
    
    # Create namespace if needed
    k8s.create_namespace(namespace)
    
    # Apply the pod
    return k8s.apply_yaml(yaml.dump(pod), namespace)


def cleanup_test_pods(k8s: K8sClient, namespace: str = "dpf-test") -> bool:
    """
    Clean up test pods.
    
    Args:
        k8s: Kubernetes client
        namespace: Test namespace
    
    Returns:
        True if successful
    """
    try:
        k8s.delete_namespace(namespace, wait=False)
        return True
    except Exception as e:
        log_warning(f"Failed to cleanup test namespace: {e}")
        return False


def run_mtu_tests(config: Any) -> List[TestResult]:
    """
    Run MTU ping tests.
    
    Args:
        config: Configuration object
    
    Returns:
        List of TestResults
    """
    log_step("Running MTU Tests")
    
    results = []
    k8s = get_k8s_client(config.kubeconfig_path)
    
    test_namespace = "dpf-test"
    
    # Get worker nodes
    workers = [n for n in k8s.get_nodes() if "worker" in n.get("roles", [])]
    
    if not workers:
        results.append(TestResult(
            name="MTU Tests",
            passed=False,
            message="No worker nodes found",
        ))
        return results
    
    # Deploy test pod on first worker
    worker_node = workers[0]["name"]
    test_pod_name = "mtu-test-pod"
    
    log_info(f"Deploying test pod on {worker_node}...")
    if not deploy_workload_pod(
        k8s,
        test_pod_name,
        test_namespace,
        {"kubernetes.io/hostname": worker_node},
    ):
        results.append(TestResult(
            name="MTU Test Setup",
            passed=False,
            message="Failed to deploy test pod",
        ))
        return results
    
    # Wait for pod to be ready
    if not k8s.wait_for_pods_ready(test_namespace, expected_count=1, timeout=120):
        results.append(TestResult(
            name="MTU Test Setup",
            passed=False,
            message="Test pod not ready",
        ))
        return results
    
    # Get pod IP for tests
    pods = k8s.get_pods(test_namespace)
    if not pods:
        results.append(TestResult(
            name="MTU Tests",
            passed=False,
            message="Test pod not found",
        ))
        return results
    
    pod_ip = pods[0].get("ip")
    
    # MTU tests
    mtu_values = [1490, 8970]
    
    for mtu in mtu_values:
        # Test to pod's own IP (loopback essentially)
        ping_result = run_ping_test(
            k8s,
            test_pod_name,
            test_namespace,
            pod_ip,
            mtu=mtu,
        )
        
        results.append(TestResult(
            name=f"MTU {mtu} Test",
            passed=ping_result.passed,
            message=f"Packet loss: {ping_result.packet_loss:.1f}%",
            details=f"{ping_result.packets_received}/{ping_result.packets_sent} packets received",
        ))
    
    # Cleanup
    cleanup_test_pods(k8s, test_namespace)
    
    return results


def check_node_labels(config: Any) -> TestResult:
    """
    Check that nodes have required labels.
    
    Args:
        config: Configuration object
    
    Returns:
        TestResult
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    nodes = k8s.get_nodes()
    
    # Check for DPU-related labels
    dpu_nodes = [n for n in nodes if "dpu" in str(n.get("labels", {})).lower()]
    
    if not dpu_nodes:
        return TestResult(
            name="Node Labels",
            passed=False,
            message="No nodes with DPU labels found",
        )
    
    return TestResult(
        name="Node Labels",
        passed=True,
        message=f"Found {len(dpu_nodes)} nodes with DPU labels",
    )


def run_sanity_checks(config: Any) -> bool:
    """
    Run all sanity checks.
    
    Args:
        config: Configuration object
    
    Returns:
        True if all checks pass
    """
    log_step("Running DPF Sanity Checks")
    
    all_results: List[TestResult] = []
    
    # Core checks
    checks = [
        ("Cluster Operators", lambda: check_cluster_operators(config)),
        ("DPF Operator", lambda: check_dpf_operator(config)),
        ("DPUs", lambda: check_dpus(config)),
        ("DPU Services", lambda: check_dpu_services(config)),
        ("Node Labels", lambda: check_node_labels(config)),
    ]
    
    # Optional checks based on configuration
    if config.deploy_hypershift:
        checks.append(("Hosted Cluster", lambda: check_hosted_cluster(config)))
    
    for check_name, check_func in checks:
        log_info(f"Running: {check_name}")
        try:
            result = check_func()
            all_results.append(result)
        except Exception as e:
            all_results.append(TestResult(
                name=check_name,
                passed=False,
                message=f"Check failed with error: {e}",
            ))
    
    # MTU tests (if nodes available)
    mtu_results = run_mtu_tests(config)
    all_results.extend(mtu_results)
    
    # Print summary
    print("\n" + "=" * 60)
    print("SANITY CHECK RESULTS")
    print("=" * 60)
    
    passed_count = 0
    failed_count = 0
    
    for result in all_results:
        status = "✓" if result.passed else "✗"
        status_color = "\033[92m" if result.passed else "\033[91m"
        reset_color = "\033[0m"
        
        print(f"{status_color}{status}{reset_color} {result.name}: {result.message}")
        if result.details:
            print(f"    Details: {result.details}")
        
        if result.passed:
            passed_count += 1
        else:
            failed_count += 1
    
    print("=" * 60)
    print(f"TOTAL: {passed_count} passed, {failed_count} failed")
    print("=" * 60 + "\n")
    
    return failed_count == 0


def run_connectivity_test(config: Any, source_ns: str, source_pod: str, dest_ip: str) -> bool:
    """
    Run a connectivity test between pods.
    
    Args:
        config: Configuration object
        source_ns: Source namespace
        source_pod: Source pod name
        dest_ip: Destination IP
    
    Returns:
        True if connectivity test passes
    """
    k8s = get_k8s_client(config.kubeconfig_path)
    
    log_info(f"Testing connectivity from {source_ns}/{source_pod} to {dest_ip}")
    
    result = run_ping_test(k8s, source_pod, source_ns, dest_ip)
    
    if result.passed:
        log_info(f"  ✓ Connectivity OK ({result.packets_received}/{result.packets_sent} packets)")
    else:
        log_error(f"  ✗ Connectivity FAILED ({result.packet_loss:.1f}% loss)")
    
    return result.passed
