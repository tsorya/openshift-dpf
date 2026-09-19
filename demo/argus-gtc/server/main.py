from __future__ import annotations

import asyncio
import logging
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
from .models import ContainResult, SCENARIO_LABELS
from .scenarios import ALLOWED_SCENARIOS, ScenarioController

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("argus-gtc")


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
        tasks.append(asyncio.create_task(tailer.run(stop_event)))
        if settings.collector_url:
            tasks.append(asyncio.create_task(forwarder.forward_loop(stop_event, tailer)))
    else:
        hosted_tailer = HostedArgusPodTailer(
            settings,
            store,
            scenario_lookup=lambda: app.state.scenarios.active_scenario,
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
    app.state.store = EventStore(max_events=settings.max_events)
    app.state.k8s = K8sAdapter(settings)
    app.state.metrics = MetricsAdapter(settings)
    app.state.scenarios = ScenarioController(settings)
    app.state.remote = RemoteCollectorClient(settings, app.state.store)

    static_dir = Path(settings.static_dir)
    if static_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=static_dir), name="assets")

    @app.get("/")
    async def index() -> FileResponse:
        index_path = static_dir / "index.html"
        if not index_path.is_file():
            raise HTTPException(status_code=404, detail="UI not found")
        return FileResponse(index_path)

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
    async def events(limit: int = 100) -> dict[str, Any]:
        items = app.state.store.list_events(limit)
        return {"events": [item.model_dump() for item in items]}

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
    async def run_scenario(scenario_id: str) -> dict[str, Any]:
        if scenario_id not in ALLOWED_SCENARIOS:
            raise HTTPException(status_code=400, detail="scenario not allowlisted")
        try:
            result = await asyncio.to_thread(app.state.scenarios.run, scenario_id)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return result.model_dump()

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
