# Argus GTC Demo — Agent Handoff Brief

## Objective

Build a polished GTC demonstration titled **“Invisible VM, Visible Threat.”**
The story is that a Kata workload has no in-guest security agent, while a
separate AI agent runs in its own management-cluster pod. The BlueField DPU
observes worker activity out of band through DOCA Argus; OpenShift/DPF provides
workload and policy context.

The demo must be safe, deterministic, repeatable, and visually compelling.
Do not use real malware, internet C2, external scanning, privilege
escalation, or attacks against shared infrastructure.

## Current repository state

- Argus is installed by `scripts/enable-argus.sh` as a DPUService.
- Argus configuration is in `manifests/argus/03-configuration.yaml`.
- Kata SR-IOV VFs must be carved from PF0 for Argus.
- The kata pool is now always regenerated and force-applied from the current
  environment by `scripts/enable-kata.sh`.
- Argus output currently lands on the DPU host under:
  - `/var/log/doca_argus_activity_report/`
  - `/var/log/doca_argus/`
- There is no Argus HTTP API or ServiceMonitor in this repository. The demo
  server reads Argus activity reports by execing into the native `doca-argus`
  pod through the hosted-cluster kubeconfig.
- The current `manifests/argus/04-log-cleaner.yaml` deletes Argus logs every
  five minutes. This must be removed or replaced with bounded retention before
  the demo; it would erase evidence during a presentation.

## Recommended architecture

The demo server is the read-only event reader. It uses the hosted kubeconfig to
list the native `doca-argus` pod, exec `find`/`tail` inside that container, and
parse the documented common fields: `message_type`, `severity`,
`occurred_message_time_iso_8601_ns`, `workload_information`,
`container_context`, and `activity_data`. It publishes normalized events over
SSE for the UI. No hostPath collector DaemonSet is required.
- The prompt-injection demo uses a separate runc pod with NeMo Agent Toolkit.
  Its only tool is a fixed TCP connect to the hosting node's `status.hostIP` on
  TCP/31999; it accepts no model-supplied destination, sends no application
  data, and runs no commands. A scoped AdminNetworkPolicy denies that flow.
- Argus may report process/TCP activity from the agent pod, but it does not
  report OVN policy verdicts. A local ACL watcher forwards the matching OVN
  `verdict=drop` record separately and labels it as OVN evidence.
- The UI can raise a `CORRELATED_ALERT` only when the authenticated agent tool
  report confirms a timed-out connection and the matching OVN ACL drop is
  present. This derived demo alert is not presented as a native Argus alert.

1. **Kubernetes status adapter**
   - Watch DPUDeployment/DPUService readiness.
   - Watch the demo Pod's Kata runtime, DPU connection annotations, node, and
     VF/resource identity.
   - Expose a read-only status endpoint to the UI.

2. **DPU health adapter**
   - Query the existing Thanos/Prometheus DTS metrics for link speed/width,
     packets, bytes, errors, and drops.
   - Keep infrastructure health visible while the workload is contained.

3. **Static UI**
   - Top status ribbon: Cluster, DPU, Argus, Kata VM, VF/link.
   - Center topology: `Pod → Kata VM → VF → BlueField → Argus`.
   - Live event timeline with severity, activity, process, pod, node, and
     scenario label.
   - DTS sparklines for traffic/errors.
   - Allowlisted scenario buttons plus `Contain Workload` and `Restore Workload`;
     the API never accepts arbitrary commands.
   - Separate agent-baseline and prompt-injection buttons; existing Kata
     scenarios remain available.

4. **AI agent simulation**
   - Schedule a new runc pod on the same DPU-attached worker as the Kata
     workload; keep the agent outside the guest.
   - Run NeMo Agent Toolkit's tool-calling agent against an operator-provided
     OpenAI-compatible model endpoint. Keep any model credential in a Secret.
   - Expose exactly one tool, `check_host_access`, with a fixed host IP/port
     configured by the pod. The agent pod's normal egress is limited to the
     demo server and cluster DNS.
   - Use an AdminNetworkPolicy scoped to the agent pod to deny TCP/31999 to
     node peers and enable OVN ACL logging. Preflight the API and priority
     collision before deployment.
   - Correlate Argus records during the run by agent pod and run id. A blocked
     result is confirmed only by the matching OVN ACL `verdict=drop`; a TCP
     timeout alone is not proof.

## Demo flow

### 1. Healthy baseline

- Start a purpose-built, digest-pinned Kata demo image.
- Show the workload Ready, Kata runtime active, PF0 VF allocated, Argus Ready,
  and DPU link/traffic healthy.
- Make the “no agent in the guest” point explicit.

### 2. Safe, bounded scenarios

The scenario controller must accept scenario IDs, never arbitrary shell input.
Each scenario runs only in a dedicated namespace and has a NetworkPolicy that
allows traffic only to a local sink pod.

- **Discovery:** run bounded `id`, `uname`, `ps`, and reads of planted decoy
  files. Use this to populate the process/file timeline with Argus events.
- **Audit evasion attempt:** run interactive Bash history disable/clear actions,
  wait up to 45 seconds, and report success only for native `ALERT/HIGH`
  activity named `Shell History Disabled` or `Shell History Cleared`.
- **Reverse-shell simulation:** create a short-lived connection from the demo
  workload to the dedicated sink pod. Argus 3.5 documents `Reverse Shell
  Detected` as a HIGH alert; do not claim that native alert unless the event
  `message_type`/`severity` show ALERT/HIGH. Live runs here have mostly been
  `INFO · EVENT` (TCP/process).
- **Shell-history tampering:** run the pre-scripted history-disable/clear
  scenario. Argus documents HIGH alerts for those actions; treat them as
  documented capabilities, not guaranteed output of each button click.
- **Decoy modification:** modify a planted file and show file-descriptor
  activity. A content-change alert is optional, not assumed.
- **Optional network burst:** send bounded data only to the sink pod. An
  excessive-data alert is documented, not guaranteed.

Do not claim ATT&CK mappings are native Argus output; apply any demo labels in
the controller and label them as demo-side classifications. The UI demonstrates
Argus visibility and correlation. It must not claim that every scenario
generated a native Argus alert.

### 3. Correlation and containment

- Correlate Argus events with Pod/VF identity and DTS traffic.
- Keep Argus telemetry distinct from OVN ACL policy evidence in the timeline.
- Click `Contain Workload` to scale only the demo Deployment to zero.
- Show the process/event stream stop, the VF return to the pool, and DPU
  services/link health remain green.

## Important implementation constraints

- Preserve Argus event files long enough for UI history and audit review.
  Prefer Argus's native `log_threshold_size` and `log_max_files_count` or
  documented logrotate behavior over recursive deletion.
- Wait for Argus container readiness and successful service/host
  initialization before showing a green status.
- Use a pinned demo image; do not use `latest`.
- Keep all routes private/authenticated for the demo cluster.
- Keep the hosted kubeconfig read-only and limited to listing Argus pods and
  reading their activity reports through `pods/exec`.
- Add a reset action or documented cleanup that removes only demo resources.
- Capture real Argus report samples and measure detection latency before
  finalizing the UI. Do not fabricate event fields or detection semantics.

## Acceptance criteria

- A single command deploys the demo stack and a single command cleans up only
  demo resources.
- The UI shows Kubernetes readiness, Argus freshness, VF identity, and DTS
  health in one view.
- At least two bounded scenarios produce real Argus events visible in the UI.
- Demo classification labels are visibly distinct from native Argus ALERT/HIGH.
- Audit-evasion success requires both raw `message_type=ALERT` and
  `severity=HIGH`; a timeout is shown as `no-native-alert` without synthesis.
- The UI and runbook do not claim every scenario generated a native Argus alert.
- The AI agent is a separate pod; the Kata guest still has no security agent.
- The agent tool accepts no destination from the model and attempts only one
  connection to the configured reserved node port.
- The UI does not present a timeout as proof of an OVN deny or an Argus alert;
  confirmed policy evidence requires a matching OVN ACL drop record.
- Containment scales down only the demo workload and leaves DPU services
  healthy.
- No event deletion occurs during the demo window.
- The implementation includes a short operator runbook and a safety note.

## Authoritative reference

Use the DOCA Argus version matching the deployed image. For the current
`1.5.0-doca3.5.0` image, consult the [DOCA Argus 3.5 Service Guide](https://docs.nvidia.com/doca/sdk/DOCA-Argus-Service-Guide/index.html),
especially the output/logging, message schema, and alerts sections.
