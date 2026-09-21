from __future__ import annotations

import asyncio
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from server.collector import (
    ArgusLogParser,
    EventStore,
    RemoteCollectorClient,
    normalize_argus_message,
)
from server.models import (
    NormalizedEvent,
    ScenarioResult,
    classify_scenario,
    native_alert_matches_scenario,
)
from server.scenarios import ALLOWED_SCENARIOS, ScenarioController


def shell_history_alert(*, message_type: str = "ALERT", severity: str = "HIGH"):
    return normalize_argus_message(
        {
            "message_header": {
                "message_type": message_type,
                "severity": severity,
                "occurred_message_time_iso_8601_ns": "2026-09-19T12:00:00Z",
            },
            "activity_data": {
                "name": "SHELL_HISTORY_DISABLED",
                "process_details": {
                    "process_name": "bash",
                    "process_command_line_arguments": (
                        "argus-gtc-audit_evasion-test bash --noprofile --norc -i"
                    ),
                },
            },
            "workload_information": {},
        },
        source_file="doca_argus_log.json.log",
    )


class NativeAlertModelTests(unittest.TestCase):
    def test_audit_evasion_is_allowlisted_and_bounded(self):
        self.assertIn("audit-evasion", ALLOWED_SCENARIOS)
        controller = object.__new__(ScenarioController)
        controller.settings = SimpleNamespace(sink_port=4444)

        command_parts, stdin_text = controller._audit_evasion_execution(
            "argus-gtc-audit_evasion-test"
        )
        command = " ".join(command_parts)
        self.assertIn("bash --noprofile --norc -i", command)
        self.assertIn("argus-gtc-audit_evasion-test.history", command)
        self.assertIn('trap \'rm -f -- "$HISTFILE"\' EXIT', command)
        self.assertIn("timeout --foreground -s KILL 32", command)
        self.assertNotIn("<<", command)

        expected_lines = [
            "set -o history",
            "HISTCONTROL=",
            "HISTIGNORE=",
            "history -s argus-demo-before-clear",
            "history -w",
            "sleep 7",
            "history -c",
            "history -w",
            "sleep 7",
            "history -s argus-demo-before-disable",
            "history -w",
            "set +o history",
            "sleep 10",
            "exit",
        ]
        self.assertEqual(stdin_text.splitlines(), expected_lines)

        reverse_shell = " ".join(
            controller._script_for(
                "reverse-shell", "10.0.0.10", "argus-gtc-reverse_shell-test"
            )
        )
        self.assertIn("timeout -s KILL 20", reverse_shell)
        self.assertIn("/dev/tcp/10.0.0.10/4444", reverse_shell)

    def test_audit_evasion_exec_uses_real_pty(self):
        class FakeExecResponse:
            def __init__(self):
                self.open = True
                self.returncode = 0
                self.stdin_writes: list[str] = []
                self.update_timeouts: list[float] = []
                self.closed = False
                self.stdout_pending = False

            def is_open(self):
                return self.open

            def write_stdin(self, data):
                self.stdin_writes.append(data)

            def update(self, timeout):
                self.update_timeouts.append(timeout)
                self.stdout_pending = True
                self.open = False

            def peek_stdout(self):
                return self.stdout_pending

            def read_stdout(self):
                self.stdout_pending = False
                return "audit-evasion-complete\n"

            def peek_stderr(self):
                return False

            def read_stderr(self):
                return ""

            def close(self):
                self.closed = True
                self.open = False

        controller = object.__new__(ScenarioController)
        controller.settings = SimpleNamespace(namespace="argus-gtc-demo")
        controller.core = SimpleNamespace(
            connect_get_namespaced_pod_exec=object()
        )
        controller._workload_pod_name = lambda: "invisible-vm-test"
        response = FakeExecResponse()

        with patch("server.scenarios.stream", return_value=response) as exec_stream:
            output = controller._exec_interactive(
                ["/bin/bash", "-lc", "bounded-command"],
                "history -c\nexit\n",
                38.0,
            )

        self.assertEqual(output, "audit-evasion-complete\n")
        self.assertEqual(response.stdin_writes, ["history -c\nexit\n"])
        self.assertTrue(response.closed)
        self.assertTrue(response.update_timeouts)
        call = exec_stream.call_args
        self.assertEqual(call.args[1:3], ("invisible-vm-test", "argus-gtc-demo"))
        self.assertFalse(call.kwargs["stderr"])
        self.assertTrue(call.kwargs["stdin"])
        self.assertTrue(call.kwargs["tty"])
        self.assertFalse(call.kwargs["_preload_content"])

    def test_audit_evasion_exec_enforces_controller_deadline(self):
        class StuckExecResponse:
            returncode = None

            def __init__(self):
                self.closed = False

            def is_open(self):
                return not self.closed

            def write_stdin(self, _data):
                return None

            def close(self):
                self.closed = True

        controller = object.__new__(ScenarioController)
        controller.settings = SimpleNamespace(namespace="argus-gtc-demo")
        controller.core = SimpleNamespace(
            connect_get_namespaced_pod_exec=object()
        )
        controller._workload_pod_name = lambda: "invisible-vm-test"
        response = StuckExecResponse()

        with patch("server.scenarios.stream", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "controller deadline"):
                controller._exec_interactive(
                    ["/bin/bash", "-lc", "bounded-command"],
                    "exit\n",
                    0.0,
                )
        self.assertTrue(response.closed)

    def test_audit_evasion_run_uses_38_second_controller_deadline(self):
        controller = object.__new__(ScenarioController)
        controller.settings = SimpleNamespace(sink_port=4444)
        controller._active_scenario = None
        controller._last_scenario = None
        controller._last_scenario_until = 0.0
        controller._run_lock = threading.Lock()
        controller._exec_interactive = Mock(return_value="audit-evasion-complete")

        result = controller.run("audit-evasion")

        self.assertEqual(result.status, "started")
        self.assertEqual(controller._exec_interactive.call_args.args[2], 38.0)

    def test_empty_pod_context_matches_only_exact_native_high(self):
        event = shell_history_alert()
        self.assertEqual(event.activity_name, "Shell History Disabled")
        self.assertEqual(classify_scenario(event, "audit-evasion"), "audit-evasion")
        event.scenario_id = "audit-evasion"
        self.assertTrue(
            native_alert_matches_scenario(
                event, "audit-evasion", "argus-gtc-audit_evasion-test"
            )
        )

        self.assertFalse(
            native_alert_matches_scenario(
                shell_history_alert(message_type="EVENT"), "audit-evasion"
            )
        )
        self.assertFalse(
            native_alert_matches_scenario(
                shell_history_alert(severity="INFO"), "audit-evasion"
            )
        )

        medium_memory_alert = NormalizedEvent(
            message_type="ALERT",
            severity="MEDIUM",
            activity_name="Executable Permissions Removed",
            scenario_id="audit-evasion",
        )
        self.assertFalse(
            native_alert_matches_scenario(medium_memory_alert, "audit-evasion")
        )
        unrelated_high_alert = NormalizedEvent(
            message_type="ALERT",
            severity="HIGH",
            activity_name="Reverse Shell Detected",
            scenario_id="audit-evasion",
        )
        self.assertFalse(
            native_alert_matches_scenario(unrelated_high_alert, "audit-evasion")
        )

        cleared = shell_history_alert()
        cleared.activity_name = "Shell History Cleared"
        cleared.scenario_id = "audit-evasion"
        self.assertTrue(
            native_alert_matches_scenario(
                cleared,
                "audit-evasion",
                "argus-gtc-audit_evasion-test",
            )
        )

        unrelated = shell_history_alert()
        unrelated.scenario_id = "audit-evasion"
        unrelated.process_command = "bash -i"
        self.assertFalse(
            native_alert_matches_scenario(unrelated, "audit-evasion", "expected-marker")
        )

        activity_only = shell_history_alert()
        activity_only.scenario_id = "audit-evasion"
        activity_only.process_command = None
        activity_only.process_name = "bash"
        self.assertTrue(
            native_alert_matches_scenario(activity_only, "audit-evasion", "expected-marker")
        )

    def test_split_ndjson_record_is_not_dropped(self):
        parser = ArgusLogParser(lambda: "audit-evasion")
        record = (
            '{"message_header":{"message_id":"one","message_type":"ALERT",'
            '"severity":"HIGH"},"activity_data":{"name":'
            '"SHELL_HISTORY_CLEARED"}}\n'
        )
        self.assertEqual(parser.parse_chunk(record[:40], "argus.log"), [])
        events = parser.parse_chunk(record[40:], "argus.log")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].activity_name, "Shell History Cleared")
        self.assertEqual(events[0].scenario_id, "audit-evasion")

    def test_scenario_marker_is_not_exposed_by_api_model(self):
        result = ScenarioResult(
            scenario_id="audit-evasion",
            status="started",
            message="started",
            started_at="2026-09-19T12:00:00Z",
            scenario_marker="private-correlation-marker",
        ).model_dump()
        self.assertNotIn("scenario_marker", result)
        self.assertIsNone(result["native_alert"])


class EventStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_forwarded_alert_uses_server_active_scenario(self):
        store = EventStore(max_events=10)
        client = RemoteCollectorClient(
            SimpleNamespace(),
            store,
            scenario_lookup=lambda: "audit-evasion",
        )
        payload = shell_history_alert().raw
        ingested = await client.ingest_events([{"raw": payload}])
        self.assertEqual(ingested, 1)
        event = store.list_events()[0]
        self.assertEqual(event.scenario_id, "audit-evasion")
        self.assertTrue(
            native_alert_matches_scenario(
                event,
                "audit-evasion",
                "argus-gtc-audit_evasion-test",
            )
        )

    async def test_pre_run_subscription_keeps_an_evicted_early_alert(self):
        store = EventStore(max_events=2)
        baseline = store.event_ids()
        subscription = store.subscribe()
        alert = NormalizedEvent(
            message_type="ALERT",
            severity="HIGH",
            activity_name="Shell History Cleared",
            scenario_id="audit-evasion",
        )
        await store.add(alert)
        await store.add(NormalizedEvent(activity_name="noise-one"))
        await store.add(NormalizedEvent(activity_name="noise-two"))

        matched = await store.wait_for(
            lambda event: event.id == alert.id,
            timeout_seconds=0.1,
            exclude_ids=baseline,
            subscription=subscription,
        )
        self.assertEqual(matched, alert)

    async def test_wait_for_ignores_baseline_and_observes_future_event(self):
        store = EventStore(max_events=10)
        old_event = NormalizedEvent(
            message_type="ALERT",
            severity="HIGH",
            activity_name="Shell History Disabled",
            scenario_id="audit-evasion",
        )
        await store.add(old_event)
        baseline = store.event_ids()

        waiter = asyncio.create_task(
            store.wait_for(
                lambda event: native_alert_matches_scenario(
                    event, "audit-evasion"
                ),
                timeout_seconds=0.5,
                exclude_ids=baseline,
            )
        )
        await asyncio.sleep(0)
        new_event = old_event.model_copy(update={"id": "new-event"})
        await store.add(new_event)
        self.assertEqual(await waiter, new_event)

    async def test_store_deduplicates_argus_message_ids(self):
        store = EventStore(max_events=10)
        event = shell_history_alert()
        duplicate = shell_history_alert()
        event.id = "stable-message-id"
        duplicate.id = "stable-message-id"
        self.assertTrue(await store.add(event))
        self.assertFalse(await store.add(duplicate))
        self.assertEqual(len(store.list_events()), 1)

    async def test_store_reports_eviction_and_retains_evidence_separately(self):
        store = EventStore(max_events=2, max_evidence_events=2)
        alert = NormalizedEvent(
            id="native-alert",
            message_type="ALERT",
            severity="HIGH",
            activity_name="Shell History Cleared",
            scenario_id="audit-evasion",
        )
        await store.add(alert)
        await store.add(NormalizedEvent(id="noise-one", activity_name="noise-one"))
        await store.add(NormalizedEvent(id="noise-two", activity_name="noise-two"))

        self.assertNotIn(alert, store.list_events(10))
        self.assertIn(alert, store.list_evidence(10))
        self.assertIn("native-alert", store.event_ids())
        self.assertEqual(
            store.stats(),
            {
                "storage": "memory",
                "buffered": 2,
                "capacity": 2,
                "evidence_buffered": 1,
                "evidence_capacity": 2,
                "evicted": 1,
                "evidence_evicted": 0,
                "oldest_received_at": store.list_events(10)[0].received_at,
                "newest_received_at": store.list_events(10)[-1].received_at,
            },
        )


if __name__ == "__main__":
    unittest.main()
