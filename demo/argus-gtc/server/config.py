from __future__ import annotations

import os
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARGUS_GTC_", extra="ignore")

    role: str = "server"  # server | collector
    namespace: str = "argus-gtc-demo"
    workload_name: str = "invisible-vm"
    sink_name: str = "scenario-sink"
    sink_port: int = 4444
    kata_runtime_class: str = "kata-coldplug"
    dpf_namespace: str = "dpf-operator-system"
    dpu_deployment_name: str = "dpudeployment"
    argus_service_name: str = "argus"

    activity_log_dir: str = "/var/log/doca_argus_activity_report"
    service_log_dir: str = "/var/log/doca_argus"

    collector_url: str = ""
    ingest_token: str = ""

    prometheus_url: str = (
        "https://thanos-querier.openshift-monitoring.svc:9091"
    )
    hosted_kubeconfig: str = ""

    demo_image: str = "quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v1"

    max_events: int = 5000
    max_evidence_events: int = 500
    poll_interval_seconds: float = 1.0

    @property
    def static_dir(self) -> str:
        return os.environ.get("ARGUS_GTC_STATIC_DIR", "/app/static")


@lru_cache
def get_settings() -> Settings:
    return Settings()
