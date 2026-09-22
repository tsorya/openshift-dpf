from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Callable

import httpx

from .config import Settings
from .models import (
    SCENARIO_LABELS,
    NormalizedEvent,
    classify_scenario,
    scenario_run_id_from_event,
)

logger = logging.getLogger(__name__)

INITIAL_TAIL_BYTES = 512 * 1024
MAX_READ_BYTES = 256 * 1024
MAX_LOG_FILES_PER_POLL = 20

ScenarioContext = tuple[str, str]
ScenarioLookup = Callable[[], ScenarioContext | str | None]


def _scenario_context(
    value: ScenarioContext | str | None,
) -> tuple[str | None, str | None]:
    if isinstance(value, tuple):
        return value
    return value, None


def normalize_argus_message(
    payload: dict[str, Any],
    source_file: str | None = None,
    scenario_id: str | None = None,
    scenario_run_id: str | None = None,
) -> NormalizedEvent:
    header = payload.get("message_header", payload)
    activity = header.get("activity_data", payload.get("activity_data", {}))
    workload = header.get("workload_information", payload.get("workload_information", {}))
    container = workload.get("container_context", {}) or {}

    process = (
        activity.get("process_details")
        or activity.get("process")
        or activity.get("parent_process_details")
        or {}
    )
    if not process and isinstance(activity, dict):
        for key, value in activity.items():
            if key.endswith("process") and isinstance(value, dict):
                process = value
                break

    command = (
        process.get("process_command_line_arguments")
        or process.get("command_line")
        or process.get("command")
        or process.get("name")
    )
    activity_name = activity.get("name")
    if activity_name:
        activity_name = activity_name.replace("_", " ").title()

    message_id = header.get("message_id") or payload.get("message_id")
    event_data: dict[str, Any] = {
        "message_type": header.get("message_type") or payload.get("message_type"),
        "severity": header.get("severity") or payload.get("severity"),
        "occurred_at": header.get("occurred_message_time_iso_8601_ns")
        or payload.get("occurred_message_time_iso_8601_ns"),
        "activity_name": activity_name,
        "process_name": process.get("process_name") or process.get("name"),
        "process_command": command,
        "pod_name": container.get("pod_name"),
        "pod_uid": container.get("pod_uid"),
        "container_name": container.get("container_name"),
        "node_name": container.get("node_name") or workload.get("hostname"),
        "workload_id": workload.get("unique_identifier"),
        "scenario_id": scenario_id,
        "scenario_run_id": scenario_run_id,
        "demo_label": None,
        "source_file": source_file,
        "raw": payload,
    }
    if message_id:
        event_data["id"] = str(message_id)
    return NormalizedEvent(**event_data)


class EventStore:
    def __init__(
        self,
        max_events: int = 5000,
        max_evidence_events: int = 500,
    ) -> None:
        self._events: deque[NormalizedEvent] = deque(maxlen=max_events)
        self._event_ids: set[str] = set()
        self._evidence: deque[NormalizedEvent] = deque(maxlen=max_evidence_events)
        self._evidence_ids: set[str] = set()
        self._subscribers: list[asyncio.Queue[NormalizedEvent]] = []
        self._last_event_at: datetime | None = None
        self._evicted_events = 0
        self._evicted_evidence = 0
        self._lock = asyncio.Lock()

    @property
    def last_event_at(self) -> datetime | None:
        return self._last_event_at

    def list_events(self, limit: int = 100) -> list[NormalizedEvent]:
        items = list(self._events)
        return items[-limit:]

    def list_evidence(self, limit: int = 100) -> list[NormalizedEvent]:
        items = list(self._evidence)
        return items[-limit:]

    def stats(self) -> dict[str, Any]:
        oldest = self._events[0].received_at if self._events else None
        newest = self._events[-1].received_at if self._events else None
        return {
            "storage": "memory",
            "buffered": len(self._events),
            "capacity": self._events.maxlen or 0,
            "evidence_buffered": len(self._evidence),
            "evidence_capacity": self._evidence.maxlen or 0,
            "evicted": self._evicted_events,
            "evidence_evicted": self._evicted_evidence,
            "oldest_received_at": oldest,
            "newest_received_at": newest,
        }

    def event_ids(self) -> set[str]:
        return self._event_ids | self._evidence_ids

    @staticmethod
    def _is_evidence(event: NormalizedEvent) -> bool:
        return bool(
            event.scenario_id
            or event.demo_label
            or (event.message_type or "").upper() == "ALERT"
            or (event.severity or "").upper() == "HIGH"
        )

    async def add(self, event: NormalizedEvent) -> bool:
        async with self._lock:
            if event.id in self._event_ids or event.id in self._evidence_ids:
                return False
            if self._events.maxlen and len(self._events) == self._events.maxlen:
                self._event_ids.discard(self._events[0].id)
                self._evicted_events += 1
            self._events.append(event)
            self._event_ids.add(event.id)
            if self._is_evidence(event):
                if (
                    self._evidence.maxlen
                    and len(self._evidence) == self._evidence.maxlen
                ):
                    self._evidence_ids.discard(self._evidence[0].id)
                    self._evicted_evidence += 1
                self._evidence.append(event)
                self._evidence_ids.add(event.id)
            self._last_event_at = datetime.now(timezone.utc)
            for queue in list(self._subscribers):
                await queue.put(event)
            return True

    def subscribe(self) -> asyncio.Queue[NormalizedEvent]:
        queue: asyncio.Queue[NormalizedEvent] = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[NormalizedEvent]) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def wait_for(
        self,
        predicate: Callable[[NormalizedEvent], bool],
        timeout_seconds: float,
        exclude_ids: set[str] | None = None,
        subscription: asyncio.Queue[NormalizedEvent] | None = None,
    ) -> NormalizedEvent | None:
        """Wait for a matching current-or-future event without an ingest race."""
        excluded = exclude_ids or set()
        queue = subscription or self.subscribe()
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        try:
            for event in self.list_events(len(self._events)):
                if event.id not in excluded and predicate(event):
                    return event
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    return None
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    return None
                if event.id not in excluded and predicate(event):
                    return event
        finally:
            self.unsubscribe(queue)


class ArgusLogParser:
    def __init__(self, scenario_lookup: ScenarioLookup | None = None) -> None:
        self.scenario_lookup = scenario_lookup or (lambda: None)
        self._seen_ids: set[str] = set()
        self._remainders: dict[str, str] = {}

    def parse_lines(self, text: str, source_file: str) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for line in text.splitlines():
            event = self._parse_line(line, source_file=source_file)
            if event:
                events.append(event)
        return events

    def parse_chunk(self, text: str, source_file: str) -> list[NormalizedEvent]:
        """Parse complete NDJSON records and retain a split trailing record."""
        combined = self._remainders.pop(source_file, "") + text
        if not combined:
            return []
        lines = combined.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._remainders[source_file] = lines.pop()
        return self.parse_lines("".join(lines), source_file)

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

        event = normalize_argus_message(payload, source_file=source_file)
        active_scenario, active_run_id = _scenario_context(self.scenario_lookup())
        classified = classify_scenario(event, active_scenario)
        if classified:
            event.scenario_id = classified
            if classified == active_scenario:
                marker_run_id = scenario_run_id_from_event(event, classified)
                if marker_run_id in (None, active_run_id):
                    event.scenario_run_id = active_run_id
            event.demo_label = SCENARIO_LABELS.get(classified)
        return event


def _resolve_offset(offsets: dict[str, int], key: str, size: int) -> int:
    offset = offsets.get(key)
    if offset is None:
        offset = max(0, size - INITIAL_TAIL_BYTES)
    if size < offset:
        offset = max(0, size - INITIAL_TAIL_BYTES)
    return offset


class ArgusLogTailer:
    def __init__(
        self,
        settings: Settings,
        store: EventStore,
        scenario_lookup: ScenarioLookup | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.parser = ArgusLogParser(scenario_lookup)
        self._offsets: dict[str, int] = {}

    def _iter_log_dirs(self) -> list[Path]:
        dirs = [Path(self.settings.activity_log_dir)]
        if self.settings.service_log_dir:
            dirs.append(Path(self.settings.service_log_dir))
        return dirs

    def _poll_once_sync(self) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        candidates: list[tuple[float, Path]] = []
        for base in self._iter_log_dirs():
            if not base.is_dir():
                continue
            for path in base.rglob("doca_argus_log*.log"):
                if path.suffix == ".gz" or ".gz" in path.name:
                    continue
                try:
                    candidates.append((path.stat().st_mtime, path))
                except OSError:
                    continue
        candidates.sort(reverse=True)
        for _, path in candidates[:MAX_LOG_FILES_PER_POLL]:
            key = str(path)
            try:
                stat = path.stat()
            except OSError:
                continue
            offset = _resolve_offset(self._offsets, key, stat.st_size)
            read_size = min(MAX_READ_BYTES, max(0, stat.st_size - offset))
            if read_size == 0:
                continue
            try:
                with path.open("rb") as handle:
                    handle.seek(offset)
                    raw_chunk = handle.read(read_size)
                    self._offsets[key] = offset + len(raw_chunk)
            except OSError as exc:
                logger.debug("skip %s: %s", path, exc)
                continue
            chunk = raw_chunk.decode("utf-8", errors="replace")
            events.extend(self.parser.parse_chunk(chunk, source_file=key))
        return events

    async def poll_once(self) -> int:
        events = await asyncio.to_thread(self._poll_once_sync)
        for event in events:
            await self.store.add(event)
        if events:
            logger.info("ingested %d argus events from local logs", len(events))
        return len(events)

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.poll_once()
            except Exception:
                logger.exception("collector poll failed")
            await asyncio.sleep(self.settings.poll_interval_seconds)


class HostedArgusPodTailer:
    """Read Argus NDJSON logs via hosted-cluster pod exec."""

    def __init__(
        self,
        settings: Settings,
        store: EventStore,
        scenario_lookup: ScenarioLookup | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.parser = ArgusLogParser(scenario_lookup)
        self._offsets: dict[str, int] = {}

    def _hosted_clients(self) -> tuple[Any, Any] | None:
        if not self.settings.hosted_kubeconfig:
            return None
        try:
            from kubernetes import client, config

            api_client = config.new_client_from_config(self.settings.hosted_kubeconfig)
            return client.CoreV1Api(api_client), client
        except Exception:
            logger.exception("hosted kubeconfig unavailable")
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
        list_cmd = (
            "find /var/log/doca_argus_activity_report -type f "
            "-name 'doca_argus_log*.log' ! -name '*.gz' -printf '%T@ %s %p\\n' 2>/dev/null "
            "| sort -rn | head -" + str(MAX_LOG_FILES_PER_POLL)
        )
        for pod in argus_pods:
            if not pod.status or pod.status.phase != "Running":
                continue
            pod_key = pod.metadata.name
            try:
                listing = stream(
                    core.connect_get_namespaced_pod_exec,
                    pod.metadata.name,
                    self.settings.dpf_namespace,
                    command=["/bin/sh", "-c", list_cmd],
                    stderr=True,
                    stdin=False,
                    stdout=True,
                    tty=False,
                )
            except Exception:
                logger.exception("failed to list argus logs in %s", pod.metadata.name)
                continue
            for line in listing.splitlines():
                parts = line.strip().split(" ", 2)
                if len(parts) != 3:
                    continue
                try:
                    size = int(parts[1])
                except ValueError:
                    continue
                path = parts[2]
                key = f"{pod_key}:{path}"
                offset = _resolve_offset(self._offsets, key, size)
                read_size = min(MAX_READ_BYTES, max(0, size - offset))
                if read_size == 0:
                    continue
                tail_cmd = (
                    f"tail -c +{offset + 1} '{path}' 2>/dev/null | head -c {read_size}"
                )
                try:
                    chunk = stream(
                        core.connect_get_namespaced_pod_exec,
                        pod.metadata.name,
                        self.settings.dpf_namespace,
                        command=["/bin/sh", "-c", tail_cmd],
                        stderr=True,
                        stdin=False,
                        stdout=True,
                        tty=False,
                    )
                except Exception:
                    continue
                if not chunk:
                    continue
                self._offsets[key] = offset + len(chunk.encode("utf-8", errors="ignore"))
                events.extend(self.parser.parse_chunk(chunk, source_file=key))
        return events

    async def poll_once(self) -> int:
        events = await asyncio.to_thread(self._poll_once_sync)
        for event in events:
            await self.store.add(event)
        if events:
            logger.info("ingested %d argus events from hosted cluster", len(events))
        return len(events)

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.poll_once()
            except Exception:
                logger.exception("hosted pod tailer failed")
            await asyncio.sleep(self.settings.poll_interval_seconds)


class RemoteCollectorClient:
    def __init__(
        self,
        settings: Settings,
        store: EventStore,
        scenario_lookup: ScenarioLookup | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.scenario_lookup = scenario_lookup or (lambda: None)

    async def ingest_events(self, events: list[dict[str, Any]]) -> int:
        added = 0
        for item in events:
            payload = item.get("raw", item)
            event = normalize_argus_message(
                payload,
                source_file=item.get("source_file"),
            )
            active_scenario, active_run_id = _scenario_context(self.scenario_lookup())
            classified = classify_scenario(
                event,
                active_scenario or item.get("scenario_id"),
            )
            if classified:
                event.scenario_id = classified
                item_run_id = item.get("scenario_run_id")
                if classified == active_scenario:
                    marker_run_id = scenario_run_id_from_event(event, classified)
                    if (
                        item_run_id in (None, active_run_id)
                        and marker_run_id in (None, active_run_id)
                    ):
                        event.scenario_run_id = active_run_id
                else:
                    event.scenario_run_id = item_run_id
                event.demo_label = item.get("demo_label") or SCENARIO_LABELS.get(classified)
            if await self.store.add(event):
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
