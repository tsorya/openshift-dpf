# Argus GTC Demo — Presenter Brief

## Audience takeaway

Argus can observe activity inside an isolated workload without a security agent installed in that workload. Argus runs separately on the BlueField DPU. OpenShift supplies workload identity so an operator can understand what ran and choose a response.

The AI application in the second story is itself an agent. That does not mean it is a security agent installed inside its Kata VM.

## Story 1: Workload security

- **Workload:** `invisible-vm` (Kata VM)
- **Observer:** DOCA Argus on the BlueField DPU
- **Response target:** `invisible-vm` only

1. **Environment.** Open the fixed monitoring console and point to activity already visible. “Argus runs on the BlueField DPU and observes activity inside this isolated workload without a security agent installed in the guest.” Read Browser connection, Argus collector, and Latest native event as separate signals.
2. **Discovery.** Select **Discovery** to show its explanation, then click **Run Discovery**. Identify the demo controller marker and related process or file events in the continuing stream. Completion alone does not create an alert.
3. **Reverse shell.** Select **Reverse shell**, explain the controlled demo listener, then click **Run Reverse shell**. Follow the related process and network activity without losing earlier records.
4. **Evidence.** Use the persistent Alerts panel and **Inspect record**. A controller response is not sensor evidence; a process or socket event is not automatically an alert. Say “HIGH alert” only when the matching native Argus record contains `message_type=ALERT` and `severity=HIGH`. If no match arrives, say so while showing the available telemetry.
5. **Respond and recover.** The secondary controls stop and restore only `invisible-vm`. The UI reports Stopping/Restoring until Kubernetes shows pod termination/readiness. Argus health is independent of the workload response.

Choosing another action changes its description only; the last actual run and its evidence keep their identities. The nine action descriptions come from the [scenario catalog](../demo/argus-gtc/server/scenario_catalog.py), which also feeds the UI. The catalog and **More scenarios** cover the extended tour.

## Story 2: AI agent behavior

- **Workload:** `argus-gtc-agent` (a separate Kata VM)
- **Observer:** DOCA Argus on the BlueField DPU
- **Response:** no AI-workload stop control is provided by this demo

Select **AI agent behavior** in the story picker. The stream and persistent Alerts panel now show `argus-gtc-agent`; selection still precedes Run.

1. **Normal request.** Ask for a status summary. No shell-tool call is the expected baseline; shell-specific checks are Not applicable.
2. **Authorized demo shell.** Explicitly ask the AI application to open its bounded demo shell. Its tool connects to the configured `argus-gtc-canary` Service on TCP/31999. The canary sends `id`; that listener output is the evidence that a working shell was confirmed.
3. **Independent observation.** Show the matching native Argus event from `argus-gtc-agent`, if present. Show a HIGH alert only when the native record itself is `ALERT/HIGH`.
4. **Pasted-note example.** Optional. The current workflow instructs the AI application to complete the pasted maintenance note, so describe this as note-driven tool use. A missing tool call does not by itself establish a deliberate refusal. This path does not demonstrate a prompt-injection exploit.
5. **Recap.** State separately whether an authenticated tool report was recorded, whether the canary confirmed `id`, what Argus observed, whether a native alert appeared, and whether OVN recorded a matching deny.

## Evidence language

- A request or completed controller action is not proof that Argus observed it.
- A TCP connection is not proof of a working shell; the canary must record `id` output.
- A matching process/socket event is native Argus visibility, not automatically a native alert.
- A network timeout is not proof of a policy block. Use “OVN recorded a deny” only when matching OVN ACL evidence exists.
- Keep the current workload and run identity visible. Never combine `invisible-vm` evidence with `argus-gtc-agent` evidence.

For setup, configuration, troubleshooting, and raw event criteria, see the [operator runbook](argus-gtc-demo-runbook.md). This brief describes the source-supported workflow; it does not certify the current deployed cluster or live sensor behavior.
