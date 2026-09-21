from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


SCENARIO_LABELS: dict[str, str] = {
    "audit-evasion": "Audit Evasion Attempt (demo correlation)",
    "discovery": "Discovery (demo classification)",
    "reverse-shell": "Reverse Shell Simulation (demo classification)",
    "shell-history": "Shell History Tampering (demo classification)",
    "decoy-modify": "Decoy File Modification (demo classification)",
    "network-burst": "Network Burst (demo classification)",
    "compute-simulation": "Compute Simulation (demo classification)",
}

# Distinctive process names / command fragments Argus may emit for each button.
# Matching is demo-side correlation, not native Argus classification.
# Keep in sync with demo/argus-gtc/static/app.js.
SCENARIO_SIGNATURES: dict[str, tuple[str, ...]] = {
    "audit-evasion": (
        "argus-gtc-audit_evasion",
        "argus-gtc-audit-evasion",
        "argus-demo-before-clear",
    ),
    "discovery": (
        "argus-gtc-discovery",
        "argus-gtc-discovery-uname",
        "argus-gtc-discovery-decoys",
        "uname",
        "decoys",
        "credentials.txt",
        "runbook.txt",
        "ps aux",
    ),
    "reverse-shell": (
        "argus-gtc-reverse_shell",
        "argus-gtc-reverse-shell",
        "/dev/tcp/",
        "bash -i",
    ),
    "shell-history": (
        "argus-gtc-shell_history",
        "argus-gtc-shell-history",
        "histfile",
        "history -c",
    ),
    "decoy-modify": (
        "argus-gtc-decoy_modify",
        "argus-gtc-decoy-modify",
        "tampered-by-demo",
    ),
    "network-burst": (
        "argus-gtc-network_burst",
        "argus-gtc-network-burst",
        " /dev/zero",
        "nc -w",
    ),
    "compute-simulation": (
        "argus-gtc-compute_simulation",
        "argus-gtc-compute-simulation",
        "compute-done",
    ),
}

# Pod name prefixes for the Kata workload and the scenario TCP sink.
DEMO_POD_PREFIXES: tuple[str, ...] = ("invisible-vm", "scenario-sink")
SCENARIO_POD_PREFIXES: dict[str, tuple[str, ...]] = {
    "audit-evasion": ("invisible-vm",),
    "discovery": ("invisible-vm",),
    "compute-simulation": ("invisible-vm",),
    "shell-history": ("invisible-vm",),
    "decoy-modify": ("invisible-vm",),
    "reverse-shell": ("invisible-vm", "scenario-sink"),
    "network-burst": ("invisible-vm", "scenario-sink"),
}

# Exact native activity names emitted by Argus. These are deliberately kept
# separate from demo signatures: an activity only correlates to the currently
# active scenario and never promotes a demo label into an Argus alert.
SCENARIO_NATIVE_ALERTS: dict[str, tuple[str, ...]] = {
    "audit-evasion": (
        "Shell History Disabled",
        "Shell History Cleared",
    ),
    "reverse-shell": ("Reverse Shell Detected",),
}

_HYPERVISOR_RE = re.compile(
    r"(?:^|/)(kata-agent|virtiofsd|qemu-system[^/\s]*|cloud-hypervisor)(?:\s|$)",
    re.IGNORECASE,
)


class NormalizedEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    received_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    message_type: str | None = None
    severity: str | None = None
    occurred_at: str | None = None
    activity_name: str | None = None
    process_name: str | None = None
    process_command: str | None = None
    pod_name: str | None = None
    pod_uid: str | None = None
    container_name: str | None = None
    node_name: str | None = None
    workload_id: str | None = None
    scenario_id: str | None = None
    demo_label: str | None = None
    source_file: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


def _event_signature_text(event: NormalizedEvent) -> str:
    return " ".join(
        part
        for part in (event.process_name, event.process_command, event.activity_name)
        if part
    ).lower()


def is_hypervisor_noise(event: NormalizedEvent) -> bool:
    text = " ".join(
        part for part in (event.process_name, event.process_command) if part
    )
    return bool(_HYPERVISOR_RE.search(text))


def is_demo_workload(
    event: NormalizedEvent, scenario_id: str | None = None
) -> bool:
    if is_hypervisor_noise(event):
        return False
    pod = (event.pod_name or "").lower()
    prefixes = SCENARIO_POD_PREFIXES.get(scenario_id or "", DEMO_POD_PREFIXES)
    if pod:
        return any(pod.startswith(prefix) for prefix in prefixes)
    return False


def classify_scenario(
    event: NormalizedEvent, active_scenario: str | None = None
) -> str | None:
    """Label an event only if it matches a scenario signature or the demo VM.

    A running scenario must never stamp OpenShift system pods (node-resolver,
    MCD, node-exporter). Those share the worker with the Kata guest.
    """
    text = _event_signature_text(event)
    if active_scenario and is_native_high_alert(event):
        expected = SCENARIO_NATIVE_ALERTS.get(active_scenario, ())
        if event.activity_name in expected:
            return active_scenario
    if active_scenario:
        for token in SCENARIO_SIGNATURES.get(active_scenario, ()):
            if token.lower() in text:
                return active_scenario
    for scenario_id, tokens in SCENARIO_SIGNATURES.items():
        if any(token.lower() in text for token in tokens):
            return scenario_id
    if active_scenario and is_demo_workload(event, active_scenario):
        return active_scenario
    return None


def is_native_high_alert(event: NormalizedEvent) -> bool:
    return (
        (event.message_type or "").upper() == "ALERT"
        and (event.severity or "").upper() == "HIGH"
    )


def native_alert_matches_scenario(
    event: NormalizedEvent,
    scenario_id: str,
    scenario_marker: str | None = None,
) -> bool:
    """Return true only for an exact native HIGH alert from the active run."""
    if not is_native_high_alert(event):
        return False
    if event.activity_name not in SCENARIO_NATIVE_ALERTS.get(scenario_id, ()):
        return False

    process_text = " ".join(
        part for part in (event.process_name, event.process_command) if part
    ).lower()
    if scenario_marker and scenario_marker.lower() in process_text:
        return True

    # Argus can omit container context for a valid native activity. In that
    # case the parser's active-scenario correlation plus the post-click event
    # boundary is the available attribution signal.
    if not event.pod_name:
        if event.process_command:
            return False
        if (event.process_name or "").lower().startswith("argus-gtc-"):
            return False
        return event.scenario_id == scenario_id
    return is_demo_workload(event, scenario_id)


class ScenarioRequest(BaseModel):
    scenario_id: str


class NativeAlertResult(BaseModel):
    activity_name: str | None = None
    message_type: str | None = None
    severity: str | None = None
    occurred_at: str | None = None
    process_name: str | None = None
    process_command: str | None = None
    pod_name: str | None = None
    source_file: str | None = None

    @classmethod
    def from_event(cls, event: NormalizedEvent) -> NativeAlertResult:
        return cls(
            activity_name=event.activity_name,
            message_type=event.message_type,
            severity=event.severity,
            occurred_at=event.occurred_at,
            process_name=event.process_name,
            process_command=event.process_command,
            pod_name=event.pod_name,
            source_file=event.source_file,
        )


class ScenarioResult(BaseModel):
    scenario_id: str
    status: Literal["native-alert", "no-native-alert", "started"]
    message: str
    started_at: str
    native_alert: NativeAlertResult | None = None
    scenario_marker: str | None = Field(default=None, exclude=True)


class ContainResult(BaseModel):
    status: str
    message: str
    replicas: int


class StatusRibbon(BaseModel):
    cluster: str
    dpu: str
    argus: str
    kata_vm: str
    vf_link: str
    argus_freshness: str
    details: dict[str, Any] = Field(default_factory=dict)


class DtsMetrics(BaseModel):
    timestamp: str
    link_speed: list[dict[str, Any]] = Field(default_factory=list)
    link_width: list[dict[str, Any]] = Field(default_factory=list)
    rx_packets: list[dict[str, Any]] = Field(default_factory=list)
    tx_packets: list[dict[str, Any]] = Field(default_factory=list)
    rx_errors: list[dict[str, Any]] = Field(default_factory=list)
    tx_drops: list[dict[str, Any]] = Field(default_factory=list)
