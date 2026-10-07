# Argus GTC Demo — Presenter Brief

## Audience takeaway

Argus can observe activity inside an isolated workload without a security agent installed in that workload. Argus runs separately on the BlueField DPU. OpenShift supplies workload identity so an operator can understand what ran and choose a response.

The AI application in the second story is itself an agent. That does not mean it is a security agent installed inside its Kata VM.

## Story 1: Workload security

- **Workload:** `invisible-vm` (Kata VM)
- **Observer:** DOCA Argus on the BlueField DPU
- **Response target:** `invisible-vm` only

1. **Environment.** “This application runs in an isolated VM. Its security observer runs separately on the BlueField card.” Point out the live workload and observer readiness, then select **Start demo** to move to Normal activity. Start does not run a scenario.
2. **Normal activity.** Select **Run harmless commands** to run bounded discovery in `invisible-vm`. Show the current-run process record if Argus reports one; if none is visible, say so.
3. **Remote shell.** Advance to the next scene, then explicitly start the remote-shell simulation. “This shell runs inside `invisible-vm` and connects only to the controlled demo listener.”
4. **Evidence.** Explain the single pinned Argus record and its workload, time, and severity. A controller response is not sensor evidence; a process or socket event is not automatically an alert. Say “HIGH alert” only when the matching native Argus record contains `message_type=ALERT` and `severity=HIGH`.
5. **Respond and recover.** Stop `invisible-vm`, then restore it. The UI reports Stopping/Restoring until Kubernetes shows pod termination/readiness. Argus health is independent of the workload response.

Scene navigation changes the displayed scene only. Each action is started separately and never repeats when moving backward or forward.

## Story 2: AI agent behavior

- **Workload:** `argus-gtc-agent` (a separate Kata VM)
- **Observer:** DOCA Argus on the BlueField DPU
- **Response:** no AI-workload stop control is provided by this demo

1. **Normal request.** Ask for a status summary. No shell-tool call is the expected baseline; shell-specific checks are Not applicable.
2. **Authorized tool use.** Explicitly ask the AI application to open its bounded demo shell. Its tool connects to the configured `argus-gtc-canary` Service on TCP/31999. The canary sends `id`; that listener output is the evidence that a working shell was confirmed.
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
