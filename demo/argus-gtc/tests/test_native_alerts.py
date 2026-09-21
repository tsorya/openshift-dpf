from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace

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

        command = " ".join(
            controller._script_for(
                "audit-evasion", "", "argus-gtc-audit_evasion-test"
            )
        )
        self.assertIn("bash --noprofile --norc -i", command)
        self.assertIn("history -s argus-demo-before-clear", command)
        self.assertIn("set +o history", command)
        self.assertIn("history -c", command)
        self.assertIn("history -w", command)
        self.assertIn("sleep 10", command)
        self.assertIn("<<'ARGUS_EVASION'", command)
        self.assertNotIn("bash --noprofile --norc -i -c", command)
        self.assertIn("timeout -s KILL 18", command)

        reverse_shell = " ".join(
            controller._script_for(
                "reverse-shell", "10.0.0.10", "argus-gtc-reverse_shell-test"
            )
        )
        self.assertIn("timeout -s KILL 20", reverse_shell)
        self.assertIn("/dev/tcp/10.0.0.10/4444", reverse_shell)

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
