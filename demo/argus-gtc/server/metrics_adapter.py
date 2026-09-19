from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from kubernetes import client, config

from .config import Settings
from .models import DtsMetrics

logger = logging.getLogger(__name__)


class MetricsAdapter:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        self._token = self._read_token()

    def _read_token(self) -> str:
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        try:
            with open(token_path, encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            return ""

    async def _query(self, expr: str) -> list[dict[str, Any]]:
        if not self._token:
            return []
        url = f"{self.settings.prometheus_url}/api/v1/query"
        headers = {"Authorization": f"Bearer {self._token}"}
        params = {"query": expr}
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                response = await client.get(url, headers=headers, params=params)
                response.raise_for_status()
                payload = response.json()
        except Exception:
            logger.debug("prometheus query failed for %s", expr, exc_info=True)
            return []
        data = payload.get("data", {}).get("result", [])
        series: list[dict[str, Any]] = []
        for item in data:
            metric = item.get("metric", {})
            value = item.get("value", [None, None])
            series.append(
                {
                    "labels": metric,
                    "value": float(value[1]) if value[1] is not None else None,
                    "timestamp": value[0],
                }
            )
        return series

    async def get_dts_metrics(self) -> DtsMetrics:
        return DtsMetrics(
            timestamp=datetime.now(timezone.utc).isoformat(),
            link_speed=await self._query("current_link_speed"),
            link_width=await self._query("current_link_width"),
            rx_packets=await self._query("rate(rx_packets[2m])"),
            tx_packets=await self._query("rate(tx_packets[2m])"),
            rx_errors=await self._query("rate(rx_errors[2m])"),
            tx_drops=await self._query("rate(tx_drops[2m])"),
        )

    async def health_summary(self) -> str:
        speed = await self._query("current_link_speed")
        if not speed:
            return "Unknown"
        for item in speed:
            value = item.get("value")
            if value and value > 0:
                return "Ready"
        return "Degraded"
