"""
Kubernetes client wrapper for OpenShift DPF.

This module provides a unified interface for Kubernetes/OpenShift API operations
using the official kubernetes-client library instead of subprocess calls.
"""

import base64
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import yaml
from kubernetes import client, config, watch
from kubernetes.client.exceptions import ApiException
from kubernetes.dynamic import DynamicClient
from kubernetes.dynamic.exceptions import NotFoundError, ResourceNotFoundError
from kubernetes.stream import stream

from dpf.utils import log_debug, log_error, log_info, log_warning


@dataclass
class K8sClientConfig:
    """Configuration for Kubernetes client."""
    kubeconfig_path: Optional[str] = None
    context: Optional[str] = None
    in_cluster: bool = False


class K8sClient:
    """
    Kubernetes client wrapper providing high-level operations.
    
    Uses the official kubernetes-client library for all API operations,
    eliminating the need for subprocess calls to kubectl/oc.
    """
    
    def __init__(self, config_obj: Optional[K8sClientConfig] = None):
        """Initialize the Kubernetes client."""
        self._api_client: Optional[client.ApiClient] = None
        self._dynamic_client: Optional[DynamicClient] = None
        self._config = config_obj or K8sClientConfig()
        self._loaded = False
        
    def _load_config(self) -> bool:
        """Load Kubernetes configuration."""
        if self._loaded:
            return True
            
        try:
            if self._config.in_cluster:
                config.load_incluster_config()
            else:
                kubeconfig = self._config.kubeconfig_path or os.environ.get(
                    "KUBECONFIG", str(Path.home() / ".kube" / "config")
                )
                if Path(kubeconfig).exists():
                    config.load_kube_config(
                        config_file=kubeconfig,
                        context=self._config.context
                    )
                else:
                    log_warning(f"Kubeconfig not found at {kubeconfig}")
                    return False
                    
            self._api_client = client.ApiClient()
            self._dynamic_client = DynamicClient(self._api_client)
            self._loaded = True
            return True
        except Exception as e:
            log_error(f"Failed to load Kubernetes config: {e}")
            return False
    
    @property
    def core_v1(self) -> client.CoreV1Api:
        """Get CoreV1 API client."""
        self._load_config()
        return client.CoreV1Api(self._api_client)
    
    @property
    def apps_v1(self) -> client.AppsV1Api:
        """Get AppsV1 API client."""
        self._load_config()
        return client.AppsV1Api(self._api_client)
    
    @property
    def custom_objects(self) -> client.CustomObjectsApi:
        """Get CustomObjects API client."""
        self._load_config()
        return client.CustomObjectsApi(self._api_client)
    
    @property
    def dynamic(self) -> DynamicClient:
        """Get dynamic client for arbitrary resources."""
        self._load_config()
        return self._dynamic_client
    
    @property
    def api_extensions(self) -> client.ApiextensionsV1Api:
        """Get API Extensions client for CRDs."""
        self._load_config()
        return client.ApiextensionsV1Api(self._api_client)
    
    @property
    def rbac_v1(self) -> client.RbacAuthorizationV1Api:
        """Get RBAC API client."""
        self._load_config()
        return client.RbacAuthorizationV1Api(self._api_client)
    
    @property
    def batch_v1(self) -> client.BatchV1Api:
        """Get Batch API client."""
        self._load_config()
        return client.BatchV1Api(self._api_client)
    
    @property
    def networking_v1(self) -> client.NetworkingV1Api:
        """Get Networking API client."""
        self._load_config()
        return client.NetworkingV1Api(self._api_client)
    
    # ========================================================================
    # Namespace Operations
    # ========================================================================
    
    def namespace_exists(self, name: str) -> bool:
        """Check if a namespace exists."""
        try:
            self.core_v1.read_namespace(name)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise
    
    def create_namespace(self, name: str, labels: Optional[Dict[str, str]] = None) -> bool:
        """Create a namespace if it doesn't exist."""
        if self.namespace_exists(name):
            log_debug(f"Namespace {name} already exists")
            return True
            
        try:
            ns = client.V1Namespace(
                metadata=client.V1ObjectMeta(name=name, labels=labels)
            )
            self.core_v1.create_namespace(ns)
            log_info(f"Created namespace {name}")
            return True
        except ApiException as e:
            log_error(f"Failed to create namespace {name}: {e}")
            return False
    
    def delete_namespace(self, name: str, wait: bool = False, timeout: int = 300) -> bool:
        """Delete a namespace."""
        try:
            self.core_v1.delete_namespace(name)
            log_info(f"Deleted namespace {name}")
            
            if wait:
                return self.wait_for_namespace_deleted(name, timeout)
            return True
        except ApiException as e:
            if e.status == 404:
                log_debug(f"Namespace {name} already deleted")
                return True
            log_error(f"Failed to delete namespace {name}: {e}")
            return False
    
    def wait_for_namespace_deleted(self, name: str, timeout: int = 300) -> bool:
        """Wait for namespace to be fully deleted."""
        start = time.time()
        while time.time() - start < timeout:
            if not self.namespace_exists(name):
                return True
            time.sleep(5)
        log_error(f"Timeout waiting for namespace {name} to be deleted")
        return False
    
    # ========================================================================
    # Secret Operations
    # ========================================================================
    
    def secret_exists(self, name: str, namespace: str) -> bool:
        """Check if a secret exists."""
        try:
            self.core_v1.read_namespaced_secret(name, namespace)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise
    
    def get_secret(self, name: str, namespace: str) -> Optional[Dict[str, Any]]:
        """Get a secret and decode its data."""
        try:
            secret = self.core_v1.read_namespaced_secret(name, namespace)
            data = {}
            if secret.data:
                for key, value in secret.data.items():
                    try:
                        data[key] = base64.b64decode(value).decode('utf-8')
                    except (UnicodeDecodeError, ValueError):
                        # Keep as base64 for binary data
                        data[key] = value
            return {
                "metadata": {
                    "name": secret.metadata.name,
                    "namespace": secret.metadata.namespace,
                },
                "data": data,
                "type": secret.type,
            }
        except ApiException as e:
            if e.status == 404:
                return None
            raise
    
    def create_secret(
        self,
        name: str,
        namespace: str,
        data: Dict[str, str],
        secret_type: str = "Opaque",
        labels: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Create a secret."""
        try:
            # Encode data to base64
            encoded_data = {
                k: base64.b64encode(v.encode()).decode() 
                for k, v in data.items()
            }
            
            secret = client.V1Secret(
                metadata=client.V1ObjectMeta(name=name, namespace=namespace, labels=labels),
                data=encoded_data,
                type=secret_type,
            )
            self.core_v1.create_namespaced_secret(namespace, secret)
            log_info(f"Created secret {name} in {namespace}")
            return True
        except ApiException as e:
            if e.status == 409:
                log_debug(f"Secret {name} already exists in {namespace}")
                return True
            log_error(f"Failed to create secret {name}: {e}")
            return False
    
    def wait_for_secret_with_data(
        self,
        name: str,
        namespace: str,
        data_key: str,
        timeout: int = 300,
    ) -> bool:
        """Wait for a secret to exist and contain specific data key."""
        start = time.time()
        while time.time() - start < timeout:
            secret = self.get_secret(name, namespace)
            if secret and secret.get("data", {}).get(data_key):
                return True
            time.sleep(5)
        log_error(f"Timeout waiting for secret {name} with key {data_key}")
        return False
    
    # ========================================================================
    # ConfigMap Operations
    # ========================================================================
    
    def configmap_exists(self, name: str, namespace: str) -> bool:
        """Check if a ConfigMap exists."""
        try:
            self.core_v1.read_namespaced_config_map(name, namespace)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise
    
    def get_configmap(self, name: str, namespace: str) -> Optional[Dict[str, Any]]:
        """Get a ConfigMap."""
        try:
            cm = self.core_v1.read_namespaced_config_map(name, namespace)
            return {
                "metadata": {
                    "name": cm.metadata.name,
                    "namespace": cm.metadata.namespace,
                },
                "data": cm.data or {},
            }
        except ApiException as e:
            if e.status == 404:
                return None
            raise
    
    def create_configmap(
        self,
        name: str,
        namespace: str,
        data: Dict[str, str],
        labels: Optional[Dict[str, str]] = None,
    ) -> bool:
        """Create a ConfigMap."""
        try:
            cm = client.V1ConfigMap(
                metadata=client.V1ObjectMeta(name=name, namespace=namespace, labels=labels),
                data=data,
            )
            self.core_v1.create_namespaced_config_map(namespace, cm)
            log_info(f"Created ConfigMap {name} in {namespace}")
            return True
        except ApiException as e:
            if e.status == 409:
                log_debug(f"ConfigMap {name} already exists in {namespace}")
                return True
            log_error(f"Failed to create ConfigMap {name}: {e}")
            return False
    
    def update_configmap(
        self,
        name: str,
        namespace: str,
        data: Dict[str, str],
    ) -> bool:
        """Update a ConfigMap."""
        try:
            cm = self.core_v1.read_namespaced_config_map(name, namespace)
            cm.data = data
            self.core_v1.replace_namespaced_config_map(name, namespace, cm)
            log_info(f"Updated ConfigMap {name} in {namespace}")
            return True
        except ApiException as e:
            log_error(f"Failed to update ConfigMap {name}: {e}")
            return False
    
    # ========================================================================
    # Pod Operations
    # ========================================================================
    
    def get_pods(
        self,
        namespace: str,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get pods in a namespace."""
        try:
            pods = self.core_v1.list_namespaced_pod(
                namespace,
                label_selector=label_selector,
                field_selector=field_selector,
            )
            return [
                {
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "status": pod.status.phase,
                    "node": pod.spec.node_name,
                    "ip": pod.status.pod_ip,
                    "containers": [c.name for c in pod.spec.containers],
                    "ready": all(
                        cs.ready for cs in (pod.status.container_statuses or [])
                    ),
                }
                for pod in pods.items
            ]
        except ApiException as e:
            log_error(f"Failed to list pods in {namespace}: {e}")
            return []
    
    def get_pod(self, name: str, namespace: str) -> Optional[Dict[str, Any]]:
        """Get a specific pod."""
        try:
            pod = self.core_v1.read_namespaced_pod(name, namespace)
            return {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "status": pod.status.phase,
                "node": pod.spec.node_name,
                "ip": pod.status.pod_ip,
                "containers": [c.name for c in pod.spec.containers],
                "ready": all(
                    cs.ready for cs in (pod.status.container_statuses or [])
                ),
            }
        except ApiException as e:
            if e.status == 404:
                return None
            raise
    
    def exec_in_pod(
        self,
        name: str,
        namespace: str,
        command: List[str],
        container: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """Execute a command in a pod and return (exit_code, stdout, stderr)."""
        try:
            kwargs = {
                "name": name,
                "namespace": namespace,
                "command": command,
                "stderr": True,
                "stdin": False,
                "stdout": True,
                "tty": False,
                "_preload_content": False,
            }
            if container:
                kwargs["container"] = container
            
            resp = stream(self.core_v1.connect_get_namespaced_pod_exec, **kwargs)
            
            stdout = ""
            stderr = ""
            while resp.is_open():
                resp.update(timeout=1)
                if resp.peek_stdout():
                    stdout += resp.read_stdout()
                if resp.peek_stderr():
                    stderr += resp.read_stderr()
            
            # Get return code from the response
            resp.close()
            return_code = resp.returncode if hasattr(resp, 'returncode') else 0
            
            return return_code, stdout, stderr
        except ApiException as e:
            return 1, "", str(e)
    
    def wait_for_pods_ready(
        self,
        namespace: str,
        label_selector: Optional[str] = None,
        timeout: int = 300,
        expected_count: int = 1,
    ) -> bool:
        """Wait for pods to be ready."""
        start = time.time()
        while time.time() - start < timeout:
            pods = self.get_pods(namespace, label_selector)
            ready_pods = [p for p in pods if p.get("ready")]
            
            if len(ready_pods) >= expected_count:
                log_info(f"All {expected_count} pods ready in {namespace}")
                return True
            
            log_debug(f"Waiting for pods: {len(ready_pods)}/{expected_count} ready")
            time.sleep(10)
        
        log_error(f"Timeout waiting for pods in {namespace}")
        return False
    
    # ========================================================================
    # Node Operations
    # ========================================================================
    
    def get_nodes(
        self,
        label_selector: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get cluster nodes."""
        try:
            nodes = self.core_v1.list_node(label_selector=label_selector)
            result = []
            for node in nodes.items:
                conditions = {c.type: c.status for c in node.status.conditions}
                result.append({
                    "name": node.metadata.name,
                    "labels": node.metadata.labels or {},
                    "ready": conditions.get("Ready") == "True",
                    "roles": [
                        k.replace("node-role.kubernetes.io/", "")
                        for k in (node.metadata.labels or {}).keys()
                        if k.startswith("node-role.kubernetes.io/")
                    ],
                    "addresses": {
                        addr.type: addr.address
                        for addr in node.status.addresses
                    },
                })
            return result
        except ApiException as e:
            log_error(f"Failed to list nodes: {e}")
            return []
    
    def patch_node(self, name: str, patch: Dict[str, Any]) -> bool:
        """Patch a node."""
        try:
            self.core_v1.patch_node(name, patch)
            log_info(f"Patched node {name}")
            return True
        except ApiException as e:
            log_error(f"Failed to patch node {name}: {e}")
            return False
    
    def label_node(self, name: str, labels: Dict[str, str]) -> bool:
        """Add labels to a node."""
        patch = {"metadata": {"labels": labels}}
        return self.patch_node(name, patch)
    
    # ========================================================================
    # CRD Operations
    # ========================================================================
    
    def crd_exists(self, name: str) -> bool:
        """Check if a CRD exists."""
        try:
            self.api_extensions.read_custom_resource_definition(name)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise
    
    def wait_for_crd(self, name: str, timeout: int = 300) -> bool:
        """Wait for a CRD to be available."""
        start = time.time()
        while time.time() - start < timeout:
            if self.crd_exists(name):
                log_info(f"CRD {name} is available")
                return True
            time.sleep(5)
        log_error(f"Timeout waiting for CRD {name}")
        return False
    
    # ========================================================================
    # Custom Resource Operations
    # ========================================================================
    
    def get_custom_resource(
        self,
        group: str,
        version: str,
        plural: str,
        name: str,
        namespace: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Get a custom resource."""
        try:
            if namespace:
                return self.custom_objects.get_namespaced_custom_object(
                    group, version, namespace, plural, name
                )
            else:
                return self.custom_objects.get_cluster_custom_object(
                    group, version, plural, name
                )
        except ApiException as e:
            if e.status == 404:
                return None
            raise
    
    def create_custom_resource(
        self,
        group: str,
        version: str,
        plural: str,
        body: Dict[str, Any],
        namespace: Optional[str] = None,
    ) -> bool:
        """Create a custom resource."""
        try:
            if namespace:
                self.custom_objects.create_namespaced_custom_object(
                    group, version, namespace, plural, body
                )
            else:
                self.custom_objects.create_cluster_custom_object(
                    group, version, plural, body
                )
            log_info(f"Created {plural}/{body['metadata']['name']}")
            return True
        except ApiException as e:
            if e.status == 409:
                log_debug(f"Resource {plural}/{body['metadata']['name']} already exists")
                return True
            log_error(f"Failed to create custom resource: {e}")
            return False
    
    def patch_custom_resource(
        self,
        group: str,
        version: str,
        plural: str,
        name: str,
        patch: Dict[str, Any],
        namespace: Optional[str] = None,
    ) -> bool:
        """Patch a custom resource."""
        try:
            if namespace:
                self.custom_objects.patch_namespaced_custom_object(
                    group, version, namespace, plural, name, patch
                )
            else:
                self.custom_objects.patch_cluster_custom_object(
                    group, version, plural, name, patch
                )
            log_info(f"Patched {plural}/{name}")
            return True
        except ApiException as e:
            log_error(f"Failed to patch custom resource: {e}")
            return False
    
    def delete_custom_resource(
        self,
        group: str,
        version: str,
        plural: str,
        name: str,
        namespace: Optional[str] = None,
    ) -> bool:
        """Delete a custom resource."""
        try:
            if namespace:
                self.custom_objects.delete_namespaced_custom_object(
                    group, version, namespace, plural, name
                )
            else:
                self.custom_objects.delete_cluster_custom_object(
                    group, version, plural, name
                )
            log_info(f"Deleted {plural}/{name}")
            return True
        except ApiException as e:
            if e.status == 404:
                log_debug(f"Resource {plural}/{name} already deleted")
                return True
            log_error(f"Failed to delete custom resource: {e}")
            return False
    
    def list_custom_resources(
        self,
        group: str,
        version: str,
        plural: str,
        namespace: Optional[str] = None,
        label_selector: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List custom resources."""
        try:
            if namespace:
                result = self.custom_objects.list_namespaced_custom_object(
                    group, version, namespace, plural,
                    label_selector=label_selector,
                )
            else:
                result = self.custom_objects.list_cluster_custom_object(
                    group, version, plural,
                    label_selector=label_selector,
                )
            return result.get("items", [])
        except ApiException as e:
            log_error(f"Failed to list custom resources: {e}")
            return []
    
    # ========================================================================
    # Apply YAML Manifests
    # ========================================================================
    
    def apply_yaml(
        self,
        yaml_content: str,
        namespace: Optional[str] = None,
    ) -> bool:
        """Apply YAML manifest(s) to the cluster."""
        try:
            docs = list(yaml.safe_load_all(yaml_content))
            
            for doc in docs:
                if doc is None:
                    continue
                    
                if not self._apply_resource(doc, namespace):
                    return False
            
            return True
        except Exception as e:
            log_error(f"Failed to apply YAML: {e}")
            return False
    
    def apply_yaml_file(
        self,
        file_path: Union[str, Path],
        namespace: Optional[str] = None,
    ) -> bool:
        """Apply a YAML file to the cluster."""
        path = Path(file_path)
        if not path.exists():
            log_error(f"File not found: {path}")
            return False
        
        with open(path, 'r') as f:
            return self.apply_yaml(f.read(), namespace)
    
    def apply_yaml_directory(
        self,
        directory: Union[str, Path],
        namespace: Optional[str] = None,
        recursive: bool = False,
    ) -> bool:
        """Apply all YAML files in a directory."""
        dir_path = Path(directory)
        if not dir_path.is_dir():
            log_error(f"Directory not found: {dir_path}")
            return False
        
        pattern = "**/*.yaml" if recursive else "*.yaml"
        files = sorted(dir_path.glob(pattern))
        
        # Also include .yml files
        yml_pattern = "**/*.yml" if recursive else "*.yml"
        files.extend(sorted(dir_path.glob(yml_pattern)))
        
        for file_path in files:
            log_info(f"Applying {file_path}")
            if not self.apply_yaml_file(file_path, namespace):
                return False
        
        return True
    
    def _apply_resource(
        self,
        resource: Dict[str, Any],
        default_namespace: Optional[str] = None,
    ) -> bool:
        """Apply a single resource to the cluster."""
        try:
            api_version = resource.get("apiVersion", "")
            kind = resource.get("kind", "")
            metadata = resource.get("metadata", {})
            name = metadata.get("name", "")
            namespace = metadata.get("namespace", default_namespace)
            
            # Get the API resource
            api_resource = self._get_api_resource(api_version, kind)
            if not api_resource:
                log_error(f"Could not find API resource for {api_version}/{kind}")
                return False
            
            # Try to get existing resource
            try:
                if api_resource.namespaced and namespace:
                    existing = api_resource.get(name=name, namespace=namespace)
                else:
                    existing = api_resource.get(name=name)
                
                # Update existing resource
                resource["metadata"]["resourceVersion"] = existing.metadata.resourceVersion
                if api_resource.namespaced and namespace:
                    api_resource.replace(body=resource, name=name, namespace=namespace)
                else:
                    api_resource.replace(body=resource, name=name)
                log_info(f"Updated {kind}/{name}")
                
            except NotFoundError:
                # Create new resource
                if api_resource.namespaced and namespace:
                    api_resource.create(body=resource, namespace=namespace)
                else:
                    api_resource.create(body=resource)
                log_info(f"Created {kind}/{name}")
            
            return True
            
        except Exception as e:
            log_error(f"Failed to apply resource: {e}")
            return False
    
    def _get_api_resource(self, api_version: str, kind: str):
        """Get the dynamic API resource for a given apiVersion and kind."""
        try:
            return self.dynamic.resources.get(api_version=api_version, kind=kind)
        except ResourceNotFoundError:
            return None
    
    # ========================================================================
    # Deployment Operations
    # ========================================================================
    
    def get_deployment(self, name: str, namespace: str) -> Optional[Dict[str, Any]]:
        """Get a deployment."""
        try:
            dep = self.apps_v1.read_namespaced_deployment(name, namespace)
            return {
                "name": dep.metadata.name,
                "namespace": dep.metadata.namespace,
                "replicas": dep.spec.replicas,
                "available_replicas": dep.status.available_replicas or 0,
                "ready_replicas": dep.status.ready_replicas or 0,
                "ready": (dep.status.ready_replicas or 0) >= dep.spec.replicas,
            }
        except ApiException as e:
            if e.status == 404:
                return None
            raise
    
    def wait_for_deployment(
        self,
        name: str,
        namespace: str,
        timeout: int = 300,
    ) -> bool:
        """Wait for a deployment to be ready."""
        start = time.time()
        while time.time() - start < timeout:
            dep = self.get_deployment(name, namespace)
            if dep and dep.get("ready"):
                log_info(f"Deployment {name} is ready")
                return True
            time.sleep(10)
        log_error(f"Timeout waiting for deployment {name}")
        return False
    
    # ========================================================================
    # Service Operations
    # ========================================================================
    
    def get_service(self, name: str, namespace: str) -> Optional[Dict[str, Any]]:
        """Get a service."""
        try:
            svc = self.core_v1.read_namespaced_service(name, namespace)
            return {
                "name": svc.metadata.name,
                "namespace": svc.metadata.namespace,
                "type": svc.spec.type,
                "cluster_ip": svc.spec.cluster_ip,
                "ports": [
                    {"port": p.port, "target_port": p.target_port, "protocol": p.protocol}
                    for p in svc.spec.ports
                ],
            }
        except ApiException as e:
            if e.status == 404:
                return None
            raise
    
    # ========================================================================
    # OpenShift-Specific Operations
    # ========================================================================
    
    def get_cluster_version(self) -> Optional[Dict[str, Any]]:
        """Get the OpenShift cluster version."""
        try:
            cv = self.get_custom_resource(
                group="config.openshift.io",
                version="v1",
                plural="clusterversions",
                name="version",
            )
            if cv:
                return {
                    "version": cv.get("status", {}).get("desired", {}).get("version"),
                    "channel": cv.get("spec", {}).get("channel"),
                    "available": any(
                        c.get("type") == "Available" and c.get("status") == "True"
                        for c in cv.get("status", {}).get("conditions", [])
                    ),
                }
            return None
        except Exception:
            return None
    
    def get_cluster_operators(self) -> List[Dict[str, Any]]:
        """Get OpenShift cluster operators."""
        try:
            operators = self.list_custom_resources(
                group="config.openshift.io",
                version="v1",
                plural="clusteroperators",
            )
            result = []
            for op in operators:
                conditions = {
                    c.get("type"): c.get("status")
                    for c in op.get("status", {}).get("conditions", [])
                }
                result.append({
                    "name": op.get("metadata", {}).get("name"),
                    "available": conditions.get("Available") == "True",
                    "progressing": conditions.get("Progressing") == "True",
                    "degraded": conditions.get("Degraded") == "True",
                })
            return result
        except Exception as e:
            log_error(f"Failed to get cluster operators: {e}")
            return []
    
    def apply_scc(self, name: str, body: Dict[str, Any]) -> bool:
        """Apply a SecurityContextConstraint."""
        return self.create_custom_resource(
            group="security.openshift.io",
            version="v1",
            plural="securitycontextconstraints",
            body=body,
        )


# Global client instance
_client: Optional[K8sClient] = None


def get_k8s_client(kubeconfig: Optional[str] = None) -> K8sClient:
    """Get or create the global Kubernetes client."""
    global _client
    
    if _client is None or kubeconfig:
        config_obj = K8sClientConfig(kubeconfig_path=kubeconfig)
        _client = K8sClient(config_obj)
    
    return _client


def reset_k8s_client() -> None:
    """Reset the global Kubernetes client."""
    global _client
    _client = None

