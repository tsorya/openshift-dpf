from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


SCENARIO_LABELS: dict[str, str] = {
    "discovery": "Discovery (demo classification)",
    "reverse-shell": "Reverse Shell Simulation (demo classification)",
    "shell-history": "Shell History Tampering (demo classification)",
    "decoy-modify": "Decoy File Modification (demo classification)",
    "network-burst": "Network Burst (demo classification)",
    "compute-simulation": "Compute Simulation (demo classification)",
}


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


class ScenarioRequest(BaseModel):
    scenario_id: str


class ScenarioResult(BaseModel):
    scenario_id: str
    status: str
    message: str
    started_at: str


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
