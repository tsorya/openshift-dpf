from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable

import httpx

from .config import Settings
from .models import NormalizedEvent

logger = logging.getLogger(__name__)


def _dig(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def normalize_argus_message(
    payload: dict[str, Any],
    source_file: str | None = None,
    scenario_id: str | None = None,
) -> NormalizedEvent:
    header = payload.get("message_header", payload)
    activity = header.get("activity_data", payload.get("activity_data", {}))
    workload = header.get("workload_information", payload.get("workload_information", {}))
    container = workload.get("container_context", {}) or {}

    process = activity.get("process", {}) or {}
    if not process and isinstance(activity, dict):
        for key, value in activity.items():
            if key.endswith("process") and isinstance(value, dict):
                process = value
                break

    command = process.get("command_line") or process.get("command") or process.get("name")
    activity_name = activity.get("name")

    return NormalizedEvent(
        message_type=header.get("message_type") or payload.get("message_type"),
        severity=header.get("severity") or payload.get("severity"),
        occurred_at=header.get("occurred_message_time_iso_8601_ns")
        or payload.get("occurred_message_time_iso_8601_ns"),
        activity_name=activity_name,
        process_name=process.get("name") or process.get("process_name"),
        process_command=command,
        pod_name=container.get("pod_name"),
        pod_uid=container.get("pod_uid"),
        container_name=container.get("container_name"),
        workload_id=workload.get("unique_identifier"),
        scenario_id=scenario_id,
        demo_label=None,
        source_file=source_file,
        raw=payload,
    )


class EventStore:
    def __init__(self, max_events: int = 500) -> None:
        self._events: deque[NormalizedEvent] = deque(maxlen=max_events)
        self._subscribers: list[asyncio.Queue[NormalizedEvent]] = []
        self._last_event_at: datetime | None = None
        self._lock = asyncio.Lock()

    @property
    def last_event_at(self) -> datetime | None:
        return self._last_event_at

    def list_events(self, limit: int = 100) -> list[NormalizedEvent]:
        items = list(self._events)
        return items[-limit:]

    async def add(self, event: NormalizedEvent) -> None:
        async with self._lock:
            self._events.append(event)
            self._last_event_at = datetime.now(timezone.utc)
            for queue in list(self._subscribers):
                await queue.put(event)

    def subscribe(self) -> asyncio.Queue[NormalizedEvent]:
        queue: asyncio.Queue[NormalizedEvent] = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[NormalizedEvent]) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)


class ArgusLogTailer:
    def __init__(
        self,
        settings: Settings,
        store: EventStore,
        scenario_lookup: Callable[[], str | None] | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.scenario_lookup = scenario_lookup or (lambda: None)
        self._offsets: dict[str, int] = {}
        self._seen_ids: set[str] = set()

    def _iter_log_dirs(self) -> list[Path]:
        dirs = [Path(self.settings.activity_log_dir)]
        if self.settings.service_log_dir:
            dirs.append(Path(self.settings.service_log_dir))
        return dirs

    def _parse_line(self, line: str, source_file: str) -> NormalizedEvent | None:
        line = line.strip()
        if not line or not line.startswith("{"):
            return None
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return None

        header = payload.get("message_header", payload)
        message_id = header.get("message_id") or payload.get("message_id")
        if message_id and message_id in self._seen_ids:
            return None
        if message_id:
            self._seen_ids.add(message_id)

        scenario_id = self.scenario_lookup()
        event = normalize_argus_message(payload, source_file=source_file, scenario_id=scenario_id)
        if scenario_id:
            from .models import SCENARIO_LABELS

            event.demo_label = SCENARIO_LABELS.get(scenario_id)
        return event

    def _poll_once_sync(self) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for base in self._iter_log_dirs():
            if not base.is_dir():
                continue
            for path in sorted(base.rglob("*.json")) + sorted(base.rglob("*.log")):
                try:
                    stat = path.stat()
                except OSError:
                    continue
                key = str(path)
                offset = self._offsets.get(key, 0)
                if stat.st_size < offset:
                    offset = 0
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as handle:
                        handle.seek(offset)
                        for line in handle:
                            event = self._parse_line(line, source_file=key)
                            if event:
                                events.append(event)
                        self._offsets[key] = handle.tell()
                except OSError as exc:
                    logger.debug("skip %s: %s", path, exc)
        return events

    async def poll_once(self) -> int:
        events = await asyncio.to_thread(self._poll_once_sync)
        for event in events:
            await self.store.add(event)
        return len(events)

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.poll_once()
            except Exception:
                logger.exception("collector poll failed")
            await asyncio.sleep(self.settings.poll_interval_seconds)


class HostedArgusPodTailer:
    """Fallback: read Argus JSON logs via hosted-cluster pod exec."""

    def __init__(
        self,
        settings: Settings,
        store: EventStore,
        scenario_lookup: Callable[[], str | None] | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.scenario_lookup = scenario_lookup or (lambda: None)
        self._offsets: dict[str, int] = {}

    def _hosted_clients(self) -> tuple[Any, Any] | None:
        if not self.settings.hosted_kubeconfig:
            return None
        try:
            from kubernetes import client, config

            api_client = config.new_client_from_config(self.settings.hosted_kubeconfig)
            return client.CoreV1Api(api_client), client
        except Exception:
            logger.debug("hosted kubeconfig unavailable", exc_info=True)
            return None

    def _poll_once_sync(self) -> list[NormalizedEvent]:
        clients = self._hosted_clients()
        if not clients:
            return []
        core, _k8s_client = clients
        from kubernetes.stream import stream

        pods = core.list_namespaced_pod(namespace=self.settings.dpf_namespace).items
        argus_pods = [p for p in pods if p.metadata.name and "doca-argus" in p.metadata.name]
        events: list[NormalizedEvent] = []
        parser = ArgusLogTailer(self.settings, self.store, self.scenario_lookup)
        for pod in argus_pods:
            if not pod.status or pod.status.phase != "Running":
                continue
            pod_key = pod.metadata.name
            cmd = [
                "/bin/sh",
                "-c",
                "find /var/log/doca_argus_activity_report /var/log/doca_argus "
                "-type f \\( -name '*.json' -o -name '*.log' \\) 2>/dev/null | sort",
            ]
            try:
                output = stream(
                    core.connect_get_namespaced_pod_exec,
                    pod.metadata.name,
                    self.settings.dpf_namespace,
                    command=cmd,
                    stderr=True,
                    stdin=False,
                    stdout=True,
                    tty=False,
                )
            except Exception:
                continue
            for path in [line.strip() for line in output.splitlines() if line.strip()]:
                offset = self._offsets.get(f"{pod_key}:{path}", 0)
                tail_cmd = [
                    "/bin/sh",
                    "-c",
                    f"tail -c +{offset + 1} '{path}' 2>/dev/null || true",
                ]
                try:
                    chunk = stream(
                        core.connect_get_namespaced_pod_exec,
                        pod.metadata.name,
                        self.settings.dpf_namespace,
                        command=tail_cmd,
                        stderr=True,
                        stdin=False,
                        stdout=True,
                        tty=False,
                    )
                except Exception:
                    continue
                if not chunk:
                    continue
                self._offsets[f"{pod_key}:{path}"] = offset + len(
                    chunk.encode("utf-8", errors="ignore")
                )
                for line in chunk.splitlines():
                    event = parser._parse_line(line, source_file=f"{pod_key}:{path}")
                    if event:
                        events.append(event)
        return events

    async def poll_once(self) -> int:
        events = await asyncio.to_thread(self._poll_once_sync)
        for event in events:
            await self.store.add(event)
        return len(events)

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.poll_once()
            except Exception:
                logger.exception("hosted pod tailer failed")
            await asyncio.sleep(self.settings.poll_interval_seconds)


class RemoteCollectorClient:
    def __init__(self, settings: Settings, store: EventStore) -> None:
        self.settings = settings
        self.store = store

    async def ingest_events(self, events: list[dict[str, Any]]) -> int:
        added = 0
        for item in events:
            payload = item.get("raw", item)
            event = normalize_argus_message(
                payload,
                source_file=item.get("source_file"),
                scenario_id=item.get("scenario_id"),
            )
            if item.get("demo_label"):
                event.demo_label = item["demo_label"]
            await self.store.add(event)
            added += 1
        return added

    async def forward_loop(self, stop_event: asyncio.Event, tailer: ArgusLogTailer) -> None:
        if not self.settings.collector_url:
            return
        headers = {}
        if self.settings.ingest_token:
            headers["X-Ingest-Token"] = self.settings.ingest_token
        url = self.settings.collector_url.rstrip("/") + "/api/events/ingest"
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            while not stop_event.is_set():
                await tailer.poll_once()
                batch = [event.model_dump() for event in self.store.list_events(50)]
                if batch:
                    try:
                        await client.post(url, json={"events": batch}, headers=headers)
                    except Exception:
                        logger.debug("forward to server failed", exc_info=True)
                await asyncio.sleep(self.settings.poll_interval_seconds)


async def sse_stream(store: EventStore) -> AsyncIterator[dict[str, str]]:
    queue = store.subscribe()
    try:
        for event in store.list_events(25):
            yield {"event": "argus", "data": event.model_dump_json()}
        while True:
            event = await queue.get()
            yield {"event": "argus", "data": event.model_dump_json()}
    finally:
        store.unsubscribe(queue)
