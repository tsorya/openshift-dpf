from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from server.collector import EventStore, normalize_argus_message
from server.main import app
from server.models import ScenarioResult, native_event_matches_scenario
from server.scenarios import ALLOWED_SCENARIOS, ScenarioController


RUN_ID = "0123456789ab"
STARTED = "2026-10-07T12:00:00+00:00"
POD = "invisible-vm-6f8d8d94b8-abcd1"
SINK_IP = "10.129.0.31"


def native_event(scenario_id: str):
    memory = scenario_id == "exec-memory"
    payload = {
        "message_header": {
            "message_type": "EVENT",
            "severity": "WARNING" if memory else "INFO",
            "occurred_message_time_iso_8601_ns": "2026-10-07T12:00:01Z",
        },
        "activity_data": {
            "name": (
                "NEW_EXECUTABLE_ANONYMOUS_MEMORY_MAPPED"
                if memory
                else "NETWORK_CONNECTION_CREATED"
            ),
            "process_details": {
                "process_name": "python3" if memory else "bash",
                "process_command_line_arguments": (
                    f"argus-gtc-exec_memory-{RUN_ID} python3 /scripts/exec-memory.py"
                    if memory
                    else f"argus-gtc-phone_home-{RUN_ID} bash -c 'exec 3<>/dev/tcp/{SINK_IP}/4444'"
                ),
            },
            "network_connection_details": {
                "protocol": "TCP",
                "local_address": "10.128.0.42",
                "local_port": 42320,
                "peer_address": SINK_IP,
                "peer_port": 4444,
            },
        },
        "workload_information": {"container_context": {"pod_name": POD}},
    }
    return normalize_argus_message(payload, source_file="doca_argus_log.json.log")


def matches(event, scenario_id: str) -> bool:
    return native_event_matches_scenario(
        event,
        scenario_id,
        f"argus-gtc-{scenario_id.replace('-', '_')}-{RUN_ID}",
        RUN_ID,
        STARTED,
        POD,
        SINK_IP if scenario_id == "phone-home" else None,
        4444,
    )


class NativeScenarioEventTests(unittest.TestCase):
    def test_memory_requires_exact_native_event_pod_run_and_click_time(self):
        self.assertIn("exec-memory", ALLOWED_SCENARIOS)
        event = native_event("exec-memory")
        self.assertTrue(matches(event, "exec-memory"))
        for changed in (
            event.model_copy(update={"activity_name": "Process Created"}),
            event.model_copy(update={"severity": "INFO"}),
            event.model_copy(update={"pod_name": "another-pod"}),
            event.model_copy(update={"scenario_run_id": "aaaaaaaaaaaa"}),
            event.model_copy(update={"occurred_at": "2026-10-07T11:59:59Z"}),
            event.model_copy(update={"occurred_at": None}),
            event.model_copy(update={"process_command": "/scripts/exec-memory.py"}),
            event.model_copy(update={"raw": {}}),
            event.model_copy(update={"evidence_source": "demo-correlation"}),
        ):
            self.assertFalse(matches(changed, "exec-memory"), changed)

        old_marker = event.model_copy(
            update={
                "process_command": "argus-gtc-exec_memory-aaaaaaaaaaaa python3 /scripts/exec-memory.py"
            }
        )
        self.assertFalse(matches(old_marker, "exec-memory"))

    def test_phone_home_requires_sink_tcp_destination_and_current_run(self):
        self.assertIn("phone-home", ALLOWED_SCENARIOS)
        event = native_event("phone-home")
        self.assertTrue(matches(event, "phone-home"))
        self.assertTrue(matches(event.model_copy(update={"protocol": "6"}), "phone-home"))
        for changed in (
            event.model_copy(update={"activity_name": "TCP Network Connection State Change"}),
            event.model_copy(update={"message_type": "ALERT"}),
            event.model_copy(update={"pod_name": "scenario-sink-xyz"}),
            event.model_copy(update={"scenario_run_id": "aaaaaaaaaaaa"}),
            event.model_copy(update={"occurred_at": "2026-10-07T11:59:59Z"}),
            event.model_copy(update={"destination_ip": "10.129.0.32"}),
            event.model_copy(update={"destination_port": 5555}),
            event.model_copy(update={"protocol": "UDP"}),
            event.model_copy(update={"raw": {}}),
        ):
            self.assertFalse(matches(changed, "phone-home"), changed)

    def test_commands_are_bounded_and_phone_home_uses_only_fd_three(self):
        controller = object.__new__(ScenarioController)
        controller.settings = SimpleNamespace(sink_port=4444)
        memory_command = " ".join(
            controller._script_for("exec-memory", "", f"argus-gtc-exec_memory-{RUN_ID}")
        )
        phone_command = " ".join(
            controller._script_for("phone-home", SINK_IP, f"argus-gtc-phone_home-{RUN_ID}")
        )
        self.assertNotIn("timeout", memory_command)
        self.assertIn("python3 /scripts/exec-memory.py", memory_command)
        self.assertIn(f"--scenario-marker argus-gtc-exec_memory-{RUN_ID}", memory_command)
        self.assertIn("/scripts/run-scenario.py phone-home", phone_command)
        self.assertIn(f"argus-gtc-phone_home-{RUN_ID}", phone_command)
        self.assertIn(SINK_IP, phone_command)
        self.assertNotIn("timeout", phone_command)
        self.assertNotIn("bash", phone_command)

    def test_checked_exec_requires_confirmed_zero_status(self):
        class ClosedExec:
            def __init__(self, returncode):
                self.returncode = returncode

            def is_open(self):
                return False

            def close(self):
                pass

        controller = object.__new__(ScenarioController)
        controller.settings = SimpleNamespace(namespace="argus-gtc-demo")
        controller.core = SimpleNamespace(connect_get_namespaced_pod_exec=object())
        for returncode in (None, 7):
            with patch("server.scenarios.stream", return_value=ClosedExec(returncode)):
                with self.assertRaisesRegex(RuntimeError, "did not complete successfully"):
                    controller._exec(["true"], check=True, pod_name=POD)
        with patch("server.scenarios.stream", return_value=ClosedExec(0)):
            self.assertEqual(controller._exec(["true"], check=True, pod_name=POD), "")


class NativeScenarioRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_matching_raw_phone_event_returns_native_summary(self):
        class FakeController:
            settings = SimpleNamespace(sink_port=4444)

            def run(self, scenario_id, scenario_run_id):
                return ScenarioResult(
                    scenario_id=scenario_id,
                    scenario_run_id=scenario_run_id,
                    status="started",
                    message="action completed",
                    started_at=STARTED,
                    scenario_marker=f"argus-gtc-phone_home-{scenario_run_id}",
                    target_pod=POD,
                    target_ip=SINK_IP,
                )

        route = next(
            route for route in app.routes if getattr(route, "path", "") == "/api/scenarios/{scenario_id}"
        )
        original_store = app.state.store
        original_controller = app.state.scenarios
        original_lock = app.state.scenario_lock
        app.state.store = EventStore()
        app.state.scenarios = FakeController()
        app.state.scenario_lock = asyncio.Lock()

        async def publish():
            await asyncio.sleep(0.01)
            await app.state.store.add(native_event("phone-home"))

        try:
            publisher = asyncio.create_task(publish())
            with patch("server.main.NATIVE_EVENT_TIMEOUT_SECONDS", 0.1):
                result = await route.endpoint("phone-home", RUN_ID)
            await publisher
            self.assertEqual(result["status"], "native-event")
            self.assertEqual(result["native_event"]["message_type"], "EVENT")
            self.assertEqual(result["native_event"]["severity"], "INFO")
            self.assertEqual(result["native_event"]["destination_ip"], SINK_IP)
            self.assertEqual(result["native_event"]["destination_port"], 4444)
            self.assertEqual(result["workload_pod"], POD)
            self.assertEqual(result["sink_ip"], SINK_IP)
            self.assertEqual(result["sink_port"], 4444)
        finally:
            app.state.store = original_store
            app.state.scenarios = original_controller
            app.state.scenario_lock = original_lock

    async def test_missing_telemetry_never_reports_native_event(self):
        class FakeController:
            settings = SimpleNamespace(sink_port=4444)

            def run(self, scenario_id, scenario_run_id):
                return ScenarioResult(
                    scenario_id=scenario_id,
                    scenario_run_id=scenario_run_id,
                    status="started",
                    message="action completed",
                    started_at=STARTED,
                    scenario_marker=f"argus-gtc-{scenario_id.replace('-', '_')}-{scenario_run_id}",
                    target_pod=POD,
                    target_ip=SINK_IP,
                )

        route = next(
            route for route in app.routes if getattr(route, "path", "") == "/api/scenarios/{scenario_id}"
        )
        original_store = app.state.store
        original_controller = app.state.scenarios
        original_lock = app.state.scenario_lock
        app.state.store = EventStore()
        app.state.scenarios = FakeController()
        app.state.scenario_lock = asyncio.Lock()
        try:
            with patch("server.main.NATIVE_EVENT_TIMEOUT_SECONDS", 0.01):
                result = await route.endpoint("exec-memory", RUN_ID)
            self.assertEqual(result["status"], "no-native-event")
            self.assertIsNone(result["native_event"])
        finally:
            app.state.store = original_store
            app.state.scenarios = original_controller
            app.state.scenario_lock = original_lock

    async def test_execution_error_is_not_reported_as_missing_telemetry(self):
        class FailingController:
            def run(self, _scenario_id, _scenario_run_id):
                raise RuntimeError("connection refused")

        route = next(
            route for route in app.routes if getattr(route, "path", "") == "/api/scenarios/{scenario_id}"
        )
        original_controller = app.state.scenarios
        original_lock = app.state.scenario_lock
        app.state.scenarios = FailingController()
        app.state.scenario_lock = asyncio.Lock()
        try:
            with self.assertRaises(HTTPException) as caught:
                await route.endpoint("phone-home", RUN_ID)
            self.assertEqual(caught.exception.status_code, 500)
            self.assertIn("connection refused", caught.exception.detail)
        finally:
            app.state.scenarios = original_controller
            app.state.scenario_lock = original_lock
