from __future__ import annotations

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from .collector import (
    ArgusLogTailer,
    EventStore,
    HostedArgusPodTailer,
    RemoteCollectorClient,
    sse_stream,
)
from .config import Settings, get_settings
from .k8s_adapter import K8sAdapter
from .metrics_adapter import MetricsAdapter
from .models import (
    ContainResult,
    NativeAlertResult,
    SCENARIO_LABELS,
    SCENARIO_NATIVE_ALERTS,
    native_alert_matches_scenario,
)
from .scenarios import ALLOWED_SCENARIOS, ScenarioController

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("argus-gtc")

NATIVE_ALERT_TIMEOUT_SECONDS = 45.0


class IngestBody(BaseModel):
    events: list[dict[str, Any]]


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    store: EventStore = app.state.store
    stop_event = asyncio.Event()
    app.state.stop_event = stop_event
    tasks: list[asyncio.Task] = []

    if settings.role == "collector":
        tailer = ArgusLogTailer(
            settings,
            store,
            scenario_lookup=lambda: None,
        )
        forwarder = RemoteCollectorClient(settings, store)
        if settings.collector_url:
            tasks.append(asyncio.create_task(forwarder.forward_loop(stop_event, tailer)))
        else:
            tasks.append(asyncio.create_task(tailer.run(stop_event)))
    else:
        hosted_tailer = HostedArgusPodTailer(
            settings,
            store,
            scenario_lookup=lambda: app.state.scenarios.active_scenario_context,
        )
        tasks.append(asyncio.create_task(hosted_tailer.run(stop_event)))

    app.state.background_tasks = tasks
    try:
        yield
    finally:
        stop_event.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Argus GTC Demo",
        description="Invisible VM, Visible Threat",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.store = EventStore(
        max_events=settings.max_events,
        max_evidence_events=settings.max_evidence_events,
    )
    app.state.k8s = K8sAdapter(settings)
    app.state.metrics = MetricsAdapter(settings)
    app.state.scenarios = ScenarioController(settings)
    app.state.scenario_lock = asyncio.Lock()
    app.state.remote = RemoteCollectorClient(
        settings,
        app.state.store,
        scenario_lookup=lambda: app.state.scenarios.active_scenario_context,
    )

    static_dir = Path(settings.static_dir)
    if static_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=static_dir), name="assets")

    @app.get("/")
    async def index() -> FileResponse:
        index_path = static_dir / "index.html"
        if not index_path.is_file():
            raise HTTPException(status_code=404, detail="UI not found")
        return FileResponse(
            index_path,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "role": settings.role}

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        dts_health = await app.state.metrics.health_summary()
        ribbon = await asyncio.to_thread(
            app.state.k8s.build_status_ribbon,
            app.state.store.last_event_at,
            dts_health,
        )
        return ribbon.model_dump()

    @app.get("/api/events")
    async def events(limit: int = 100, evidence_limit: int = 100) -> dict[str, Any]:
        bounded_limit = max(1, min(limit, settings.max_events))
        bounded_evidence_limit = max(0, min(evidence_limit, settings.max_evidence_events))
        items = app.state.store.list_events(bounded_limit)
        evidence = app.state.store.list_evidence(bounded_evidence_limit)
        return {
            "events": [item.model_dump() for item in items],
            "evidence": [item.model_dump() for item in evidence],
            "retention": app.state.store.stats(),
        }

    @app.get("/api/events/stream")
    async def events_stream():
        return EventSourceResponse(sse_stream(app.state.store))

    @app.post("/api/events/ingest")
    async def ingest(
        body: IngestBody,
        x_ingest_token: str | None = Header(default=None),
    ) -> dict[str, int]:
        if settings.ingest_token and x_ingest_token != settings.ingest_token:
            raise HTTPException(status_code=401, detail="invalid ingest token")
        added = await app.state.remote.ingest_events(body.events)
        return {"ingested": added}

    @app.get("/api/metrics/dts")
    async def dts_metrics() -> dict[str, Any]:
        metrics = await app.state.metrics.get_dts_metrics()
        return metrics.model_dump()

    @app.get("/api/scenarios")
    async def list_scenarios() -> dict[str, Any]:
        return {
            "scenarios": [
                {"id": sid, "label": SCENARIO_LABELS.get(sid, sid)}
                for sid in sorted(ALLOWED_SCENARIOS)
            ]
        }

    @app.post("/api/scenarios/{scenario_id}")
    async def run_scenario(
        scenario_id: str,
        scenario_run_id: str | None = None,
    ) -> dict[str, Any]:
        if scenario_id not in ALLOWED_SCENARIOS:
            raise HTTPException(status_code=400, detail="scenario not allowlisted")
        if scenario_run_id and not re.fullmatch(r"[0-9a-f]{12}", scenario_run_id):
            raise HTTPException(status_code=400, detail="invalid scenario run id")
        if app.state.scenario_lock.locked():
            raise HTTPException(
                status_code=409,
                detail="another scenario is already running",
            )
        async with app.state.scenario_lock:
            baseline_ids = app.state.store.event_ids()
            subscription = (
                app.state.store.subscribe()
                if scenario_id in SCENARIO_NATIVE_ALERTS
                else None
            )
            try:
                try:
                    result = await asyncio.to_thread(
                        app.state.scenarios.run,
                        scenario_id,
                        scenario_run_id,
                    )
                except Exception as exc:
                    raise HTTPException(status_code=500, detail=str(exc)) from exc

                if scenario_id in SCENARIO_NATIVE_ALERTS:
                    native_alert = await app.state.store.wait_for(
                        lambda event: native_alert_matches_scenario(
                            event,
                            scenario_id,
                            result.scenario_marker,
                            result.scenario_run_id,
                        ),
                        timeout_seconds=NATIVE_ALERT_TIMEOUT_SECONDS,
                        exclude_ids=baseline_ids,
                        subscription=subscription,
                    )
                    if native_alert:
                        result.status = "native-alert"
                        result.message = (
                            "Native Argus HIGH observed: "
                            f"{native_alert.activity_name}"
                        )
                        result.native_alert = NativeAlertResult.from_event(native_alert)
                    else:
                        result.status = "no-native-alert"
                        result.message = (
                            "No native alert observed within 45 seconds. "
                            "Underlying INFO/EVENT records remain in the timeline."
                        )
                return result.model_dump()
            finally:
                if subscription is not None:
                    app.state.store.unsubscribe(subscription)

    @app.post("/api/contain")
    async def contain() -> dict[str, Any]:
        result = await asyncio.to_thread(app.state.k8s.scale_workload, 0)
        return ContainResult(
            status="contained",
            message="Demo workload scaled to zero; DPU services unchanged",
            replicas=result["replicas"],
        ).model_dump()

    @app.post("/api/reset")
    async def reset() -> dict[str, Any]:
        result = await asyncio.to_thread(app.state.k8s.scale_workload, 1)
        return {
            "status": "reset",
            "message": "Demo workload restored to one replica",
            "replicas": result["replicas"],
        }

    return app


app = create_app()
