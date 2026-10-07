from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal, Mapping
from uuid import uuid4

from pydantic import BaseModel, Field


SCENARIO_LABELS: dict[str, str] = {
    "audit-evasion": "Audit Evasion Attempt (demo correlation)",
    "discovery": "Discovery (demo classification)",
    "exec-memory": "Executable Memory (demo correlation)",
    "phone-home": "Phone Home (demo correlation)",
    "reverse-shell": "Reverse Shell Simulation (demo classification)",
    "shell-history": "Shell History Tampering (demo classification)",
    "decoy-modify": "Decoy File Modification (demo classification)",
    "network-burst": "Network Burst (demo classification)",
    "compute-simulation": "Compute Simulation (demo classification)",
    "agent-baseline": "AI Agent Baseline (demo correlation)",
    "host-access-attempt": "Kata Agent Host-Boundary Attempt (demo correlation)",
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
    "exec-memory": ("argus-gtc-exec_memory", "/scripts/exec-memory.py"),
    "phone-home": ("argus-gtc-phone_home",),
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
    "agent-baseline": (),
    "host-access-attempt": ("check_host_access",),
}

# Pod name prefixes for the Kata workload and the scenario TCP sink.
DEMO_POD_PREFIXES: tuple[str, ...] = (
    "invisible-vm",
    "scenario-sink",
    "argus-gtc-agent",
)
SCENARIO_POD_PREFIXES: dict[str, tuple[str, ...]] = {
    "audit-evasion": ("invisible-vm",),
    "discovery": ("invisible-vm",),
    "exec-memory": ("invisible-vm",),
    "phone-home": ("invisible-vm",),
    "compute-simulation": ("invisible-vm",),
    "shell-history": ("invisible-vm",),
    "decoy-modify": ("invisible-vm",),
    "reverse-shell": ("invisible-vm", "scenario-sink"),
    "network-burst": ("invisible-vm", "scenario-sink"),
    "agent-baseline": ("argus-gtc-agent",),
    "host-access-attempt": ("argus-gtc-agent",),
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

# Expected native Argus event metadata for the two evidence-gated scenes.
SCENARIO_NATIVE_EVENTS: dict[str, tuple[str, str, str]] = {
    "exec-memory": ("New Executable Anonymous Memory Mapped", "EVENT", "WARNING"),
    "phone-home": ("Network Connection Created", "EVENT", "INFO"),
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
    protocol: str | None = None
    connection_state: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    pod_name: str | None = None
    pod_uid: str | None = None
    container_name: str | None = None
    node_name: str | None = None
    workload_id: str | None = None
    scenario_id: str | None = None
    scenario_run_id: str | None = None
    demo_label: str | None = None
    source_file: str | None = None
    evidence_source: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


AGENT_TCP_ACTIVITIES = frozenset(
    {
        "network connection created",
        "network connection terminated",
        "tcp network connection state change",
    }
)


def native_agent_host_attempt_matches(
    event: NormalizedEvent,
    report: Mapping[str, Any],
    pod_name: str | None,
    pod_uid: str | None,
    run_id: str,
) -> bool:
    """Require an Argus TCP event for the socket opened by this Kata agent run."""
    if (event.message_type or "").upper() != "EVENT":
        return False
    if (event.activity_name or "").casefold() not in AGENT_TCP_ACTIVITIES:
        return False
    if event.evidence_source in {"ovn-acl-audit", "demo-correlation"}:
        return False
    if event.scenario_run_id and event.scenario_run_id != run_id:
        return False
    if pod_uid and event.pod_uid and event.pod_uid != pod_uid:
        return False
    if pod_name and event.pod_name and event.pod_name != pod_name:
        return False
    if not (event.process_name or event.process_command):
        return False
    if event.protocol and event.protocol.upper() not in {"TCP", "6"}:
        return False
    source_port = report.get("source_port")
    if not source_port or event.source_port != source_port:
        return False
    return bool(
        event.source_ip == report.get("source_ip")
        and event.destination_ip == report.get("destination_ip")
        and event.destination_port == report.get("destination_port")
    )


def _event_signature_text(event: NormalizedEvent) -> str:
    return " ".join(
        part
        for part in (event.process_name, event.process_command, event.activity_name)
        if part
    ).lower()


def scenario_run_id_from_event(
    event: NormalizedEvent,
    scenario_id: str,
) -> str | None:
    scenario_marker = re.escape(scenario_id.replace("-", "_"))
    match = re.search(
        rf"\bargus-gtc-{scenario_marker}-([0-9a-f]{{12}})\b",
        _event_signature_text(event),
        re.IGNORECASE,
    )
    return match.group(1).lower() if match else None


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
    scenario_run_id: str | None = None,
) -> bool:
    """Return true only for an exact native HIGH alert from the active run."""
    if not is_native_high_alert(event):
        return False
    if event.activity_name not in SCENARIO_NATIVE_ALERTS.get(scenario_id, ()):
        return False

    if (
        scenario_run_id
        and event.scenario_run_id
        and event.scenario_run_id != scenario_run_id
    ):
        return False

    process_text = " ".join(
        part for part in (event.process_name, event.process_command) if part
    ).lower()
    marker_run_id = scenario_run_id_from_event(event, scenario_id)
    if scenario_run_id and marker_run_id and marker_run_id != scenario_run_id:
        return False
    if scenario_run_id and event.scenario_run_id == scenario_run_id:
        return True
    if scenario_marker and scenario_marker.lower() in process_text:
        return True

    if marker_run_id:
        return marker_run_id == scenario_run_id

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


def native_event_matches_scenario(
    event: NormalizedEvent,
    scenario_id: str,
    scenario_marker: str,
    scenario_run_id: str,
    started_at: str,
    target_pod: str,
    target_ip: str | None = None,
    target_port: int | None = None,
) -> bool:
    """Match a fresh raw Argus event to the exact demo workload and action."""
    expected = SCENARIO_NATIVE_EVENTS.get(scenario_id)
    if not expected or (
        event.activity_name,
        (event.message_type or "").upper(),
        (event.severity or "").upper(),
    ) != expected:
        return False
    if event.evidence_source in {"ovn-acl-audit", "demo-correlation", "canary-listener"}:
        return False
    if event.pod_name != target_pod or not target_pod.startswith("invisible-vm"):
        return False
    if event.scenario_run_id and event.scenario_run_id != scenario_run_id:
        return False
    marker_run_id = scenario_run_id_from_event(event, scenario_id)
    if marker_run_id and marker_run_id != scenario_run_id:
        return False

    # A record ingested after the click can still describe an older activity.
    # Require the native event timestamp, not merely its arrival time.
    try:
        occurred = datetime.fromisoformat((event.occurred_at or "").replace("Z", "+00:00"))
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if not occurred.tzinfo or not started.tzinfo or occurred < started:
        return False

    # The raw Argus activity must agree with the normalized record shown in
    # the timeline; a demo-side synthetic label is never native evidence.
    header = event.raw.get("message_header", event.raw)
    if not isinstance(header, dict):
        return False
    activity = header.get("activity_data", event.raw.get("activity_data"))
    if not isinstance(activity, dict):
        return False
    raw_name = str(activity.get("name") or "").replace("_", " ").title()
    if raw_name != expected[0]:
        return False

    if scenario_id == "exec-memory":
        process_text = " ".join(
            part for part in (event.process_name, event.process_command) if part
        )
        return scenario_marker.lower() in process_text.lower()

    return (
        bool(target_ip)
        and bool(target_port)
        and (event.protocol or "").upper() in {"TCP", "6"}
        and event.destination_ip == target_ip
        and event.destination_port == target_port
    )


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


class NativeEventResult(BaseModel):
    activity_name: str | None = None
    message_type: str | None = None
    severity: str | None = None
    occurred_at: str | None = None
    process_name: str | None = None
    process_command: str | None = None
    pod_name: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    source_file: str | None = None

    @classmethod
    def from_event(cls, event: NormalizedEvent) -> NativeEventResult:
        return cls(**event.model_dump(include=set(cls.model_fields)))


class ScenarioResult(BaseModel):
    scenario_id: str
    scenario_run_id: str
    status: Literal[
        "native-alert", "no-native-alert", "native-event", "no-native-event", "started"
    ]
    message: str
    started_at: str
    native_alert: NativeAlertResult | None = None
    native_event: NativeEventResult | None = None
    scenario_marker: str | None = Field(default=None, exclude=True)
    target_pod: str | None = Field(default=None, exclude=True)
    target_ip: str | None = Field(default=None, exclude=True)


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
