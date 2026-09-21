from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from .config import Settings
from .models import StatusRibbon

logger = logging.getLogger(__name__)


def _load_config(kubeconfig: str | None = None) -> None:
    if kubeconfig and kubeconfig != "in-cluster":
        config.load_kube_config(config_file=kubeconfig)
        return
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


class K8sAdapter:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        _load_config()
        self.apps = client.AppsV1Api()
        self.core = client.CoreV1Api()
        self.custom = client.CustomObjectsApi()

    def _hosted_api(self) -> client.CustomObjectsApi | None:
        if not self.settings.hosted_kubeconfig:
            return None
        try:
            api_client = config.new_client_from_config(self.settings.hosted_kubeconfig)
            return client.CustomObjectsApi(api_client)
        except Exception:
            logger.exception("failed to load hosted kubeconfig")
            return None

    def _hosted_core(self) -> client.CoreV1Api | None:
        if not self.settings.hosted_kubeconfig:
            return None
        try:
            api_client = config.new_client_from_config(self.settings.hosted_kubeconfig)
            return client.CoreV1Api(api_client)
        except Exception:
            logger.exception("failed to load hosted core api")
            return None

    def get_workload_pod(self) -> dict[str, Any] | None:
        pods = self.core.list_namespaced_pod(
            namespace=self.settings.namespace,
            label_selector=f"app={self.settings.workload_name}",
        ).items
        for pod in pods:
            if pod.status and pod.status.phase != "Succeeded":
                return self._pod_summary(pod)
        return None

    def _pod_summary(self, pod: Any) -> dict[str, Any]:
        annotations = pod.metadata.annotations or {}
        resources = []
        for container in pod.spec.containers:
            if container.resources and container.resources.requests:
                resources.extend(container.resources.requests.keys())
        return {
            "name": pod.metadata.name,
            "uid": pod.metadata.uid,
            "node": pod.spec.node_name,
            "phase": pod.status.phase if pod.status else None,
            "runtime_class": pod.spec.runtime_class_name,
            "ip": pod.status.pod_ip if pod.status else None,
            "ready": all(
                cond.status == "True"
                for cond in (pod.status.conditions or [])
                if cond.type == "Ready"
            )
            if pod.status
            else False,
            "annotations": {
                k: v
                for k, v in annotations.items()
                if "dpu" in k.lower() or "multus" in k.lower() or "ovn" in k.lower()
            },
            "resource_requests": sorted(set(resources)),
            "start_time": pod.status.start_time.isoformat()
            if pod.status and pod.status.start_time
            else None,
        }

    def get_deployment_status(self) -> dict[str, Any]:
        try:
            deploy = self.apps.read_namespaced_deployment(
                name=self.settings.workload_name,
                namespace=self.settings.namespace,
            )
        except ApiException:
            return {"replicas": 0, "ready": 0, "available": 0}
        status = deploy.status
        return {
            "replicas": deploy.spec.replicas,
            "ready": status.ready_replicas or 0 if status else 0,
            "available": status.available_replicas or 0 if status else 0,
        }

    def get_sink_pod_ip(self) -> str | None:
        pods = self.core.list_namespaced_pod(
            namespace=self.settings.namespace,
            label_selector=f"app={self.settings.sink_name}",
        ).items
        for pod in pods:
            if pod.status and pod.status.pod_ip:
                return pod.status.pod_ip
        return None

    def get_dpudeployment_status(self) -> dict[str, Any]:
        try:
            obj = self.custom.get_namespaced_custom_object(
                group="svc.dpu.nvidia.com",
                version="v1alpha1",
                namespace=self.settings.dpf_namespace,
                plural="dpudeployments",
                name=self.settings.dpu_deployment_name,
            )
        except ApiException as exc:
            return {"ready": False, "message": str(exc)}
        conditions = obj.get("status", {}).get("conditions", [])
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
        return {
            "ready": ready,
            "conditions": conditions,
            "services": obj.get("status", {}).get("services", []),
        }

    def get_argus_status(self) -> dict[str, Any]:
        hosted_core = self._hosted_core()
        if not hosted_core:
            return {"ready": False, "running": 0, "total": 0, "message": "hosted kubeconfig unavailable"}
        pods = hosted_core.list_namespaced_pod(namespace=self.settings.dpf_namespace).items
        argus_pods = [p for p in pods if p.metadata.name and "doca-argus" in p.metadata.name]
        running = [
            p
            for p in argus_pods
            if p.status and p.status.phase == "Running"
            and all(c.ready for c in (p.status.container_statuses or []) if c.ready is not None)
        ]
        initialized = False
        for pod in running:
            for condition in pod.status.conditions or []:
                if condition.type == "Ready" and condition.status == "True":
                    initialized = True
        return {
            "ready": bool(running) and initialized,
            "running": len(running),
            "total": len(argus_pods),
            "pods": [p.metadata.name for p in argus_pods],
        }

    def build_status_ribbon(
        self,
        argus_last_event: datetime | None,
        dts_health: str,
    ) -> StatusRibbon:
        deploy = self.get_deployment_status()
        pod = self.get_workload_pod()
        dpu = self.get_dpudeployment_status()
        argus = self.get_argus_status()
        coverage = self.get_argus_coverage()

        cluster = "Ready"
        dpu_state = "Ready" if dpu.get("ready") else "Degraded"
        argus_state = "Ready" if argus.get("ready") else "Pending"
        kata_state = "Absent"
        vf_state = "Unknown"

        if deploy.get("replicas", 0) == 0:
            kata_state = "Contained"
        elif pod and pod.get("ready"):
            kata_state = "Ready" if pod.get("runtime_class") == self.settings.kata_runtime_class else "Running"
            reqs = pod.get("resource_requests") or []
            vf_state = "Allocated" if reqs else "Pending"
        elif deploy.get("replicas", 0) > 0:
            kata_state = "Pending"

        freshness = "No events"
        if argus_last_event:
            age = (datetime.now(timezone.utc) - argus_last_event).total_seconds()
            if age < 30:
                freshness = "Live"
            elif age < 120:
                freshness = f"{int(age)}s ago"
            else:
                freshness = f"{int(age // 60)}m ago"

        return StatusRibbon(
            cluster=cluster,
            dpu=dpu_state,
            argus=argus_state,
            kata_vm=kata_state,
            vf_link=vf_state if dts_health == "Ready" else dts_health,
            argus_freshness=freshness,
            details={
                "deployment": deploy,
                "pod": pod,
                "dpu": dpu,
                "argus": argus,
                "coverage": coverage,
            },
        )

    def scale_workload(self, replicas: int) -> dict[str, Any]:
        body = {"spec": {"replicas": replicas}}
        deploy = self.apps.patch_namespaced_deployment(
            name=self.settings.workload_name,
            namespace=self.settings.namespace,
            body=body,
        )
        return {
            "replicas": deploy.spec.replicas,
            "status": "ok",
        }

    def get_argus_coverage(self) -> dict[str, Any]:
        pod = self.get_workload_pod()
        node = pod.get("node") if pod else None
        demo_workloads: list[dict[str, Any]] = []
        try:
            items = self.core.list_namespaced_pod(namespace=self.settings.namespace).items
            for item in items:
                if not item.status or item.status.phase not in {"Running", "Pending"}:
                    continue
                labels = item.metadata.labels or {}
                app = labels.get("app")
                if app == "argus-gtc-demo":
                    continue
                if node and item.spec.node_name and item.spec.node_name != node:
                    continue
                demo_workloads.append(
                    {
                        "name": item.metadata.name,
                        "app": labels.get("app"),
                        "runtime": item.spec.runtime_class_name or "runc",
                        "node": item.spec.node_name,
                        "phase": item.status.phase,
                    }
                )
        except ApiException:
            logger.debug("failed to list demo pods for coverage", exc_info=True)

        auto_scan = None
        representor_id = None
        dma_device = None
        try:
            obj = self.custom.get_namespaced_custom_object(
                group="svc.dpu.nvidia.com",
                version="v1alpha1",
                namespace=self.settings.dpf_namespace,
                plural="dpuserviceconfigurations",
                name=self.settings.argus_service_name,
            )
            content = (
                obj.get("spec", {})
                .get("serviceConfiguration", {})
                .get("helmChart", {})
                .get("values", {})
                .get("config", {})
                .get("content", {})
                .get("apsh_config", {})
            )
            auto_scan = content.get("auto_scan")
            bm = (content.get("systems") or {}).get("bm") or {}
            representor_id = bm.get("representor_id")
            dma_device = bm.get("dma_device_name")
        except ApiException:
            logger.debug("argus DPUServiceConfiguration not readable", exc_info=True)

        kata_runtime = self.settings.kata_runtime_class
        return {
            "selects_all_cluster_pods": False,
            "scope": "DPU-attached worker via DMA — not a cluster-wide pod watch",
            "worker_node": node,
            "auto_scan": auto_scan,
            "representor_id": representor_id,
            "dma_device": dma_device,
            "kata_runtime_class": kata_runtime,
            "kata_pf0_only": True,
            "guest_agent": False,
            "demo_workloads": demo_workloads,
            "includes": [
                "Every process on the DPU-attached worker, including OpenShift system pods",
                f"Kata VMs whose SR-IOV VF is on PF0 (RuntimeClass {kata_runtime})",
                "runc pods on that same worker (no guest hypervisor)",
            ],
            "excludes": [
                "Pods on other workers / control-plane VMs",
                "Kata VFs on PF1 — Argus cannot introspect them",
                "In-guest agents — none are installed in the Kata VM",
            ],
            "signals": [
                "Process and thread lifecycle (INFO · EVENT)",
                "TCP connections (INFO · EVENT)",
                "File descriptors and mappings (INFO · EVENT)",
                "Native HIGH/ALERT only when Argus emits them — not guaranteed per button",
            ],
        }
