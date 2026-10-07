# Argus GTC Demo — Operator Runbook

**Title:** Invisible VM, Visible Threat

This demo shows activity inside an isolated Kata workload with **no in-guest security agent**. DOCA Argus observes from the BlueField DPU, and OpenShift supplies workload identity so an operator can respond. The AI application is a separate workload in its own Kata VM; it is an application agent, not a security agent installed inside the guest. OVN-Kubernetes policy evidence remains separate from native Argus telemetry.

## Safety note

All scenarios are **bounded and allowlisted**. They do not use malware, internet C2, external scanning, privilege escalation, or attacks against shared infrastructure. The agent’s only extra tool opens one Bash session inside the agent Kata pod to the configured `argus-gtc-canary` Service on TCP/31999 for at most 20 seconds. The current agent manifest uses the canary Service DNS name; the Service also publishes a NodePort. The canary sends `id` and records the output; commands run in the agent workload, not on the host. The tool accepts no model-selected IP, port, or command. The demo UI is an OpenShift Route. The Kata agent Service stays ClusterIP-only so the LLM and shell tool are not on ingress. Scenario labels such as “Discovery” and “Reverse Shell Simulation” are applied by the demo controller for correlation. They are **not** native Argus ATT&CK mappings and do **not** mean Argus raised a HIGH/ALERT. The AI shell action is confirmed only when an authenticated tool report and matching canary `id` output establish the bounded session. Matching native Argus process/socket evidence is a separate observation with its real severity. Treat a native HIGH alert as confirmed only when the same raw event contains both `message_type=ALERT` and `severity=HIGH`. Do not synthesize an Argus alert from the agent response.

## Prerequisites

1. `KATA_ENABLED=true` and `KATA_SRIOV_PF_INDEX=0` (Argus requires PF0 VFs).
   The worker needs two free PF0 Kata VFs: one for `invisible-vm` and one for `argus-gtc-agent`.
2. `make enable-ovn-injector`, `make enable-kata`, `make enable-argus` with `ARGUS_REPRESENTOR_ID` set.
3. `make deploy-observability` recommended for DTS panels (Thanos metrics).
4. Hosted cluster kubeconfig available (`doca.kubeconfig` or secret fetch).

## Build the demo images

The Kata workload and sink use a small UBI9 image because Argus 1.5.0's shell
history collector requires a Bash layout it can introspect. The workload image
also includes Python 3 for the bounded executable-memory scenario. The previous
Alpine netshoot image was visible to Argus at the process level but did not
produce shell-history events. Build and push the workload image for the x86 worker:

```bash
docker build --platform linux/amd64 \
  -t quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v2 \
  -f demo/argus-gtc-workload/Containerfile demo/argus-gtc-workload
docker push quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v2
```

Build and push the demo server from the repository root, then set
`ARGUS_GTC_SERVER_IMAGE` in `.env`:

```bash
docker build --platform linux/amd64 \
  -t quay.io/itsoiref/argus-gtc-demo:v47-memory-phonehome \
  -f demo/argus-gtc/Containerfile demo/argus-gtc
docker push quay.io/itsoiref/argus-gtc-demo:v47-memory-phonehome
```

The server image contains Python 3.11, `requirements.txt`, and the `server/` +
`static/` directories. The audit-evasion implementation uses
`timeout --foreground` so the bounded timeout preserves the interactive PTY.

Build and push the separate NeMo Agent Toolkit pod image:

```bash
docker build --platform linux/amd64 \
  -t quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v14-agent-shell \
  -f demo/argus-gtc-agent/Containerfile demo/argus-gtc-agent
docker push quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v14-agent-shell
```

Configure these values in the generated `.env` before deployment. The model
must expose OpenAI-compatible chat completions and support tool calling. For
direct OpenAI API access, use `https://api.openai.com/v1`, an API model ID, and
an OpenAI API key. The agent pod receives the key from a Kubernetes Secret and
needs outbound TCP/443. The demo shell is allowed only to the worker-host
canary on TCP/31999.

```text
ARGUS_GTC_AGENT_IMAGE=quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v14-agent-shell
ARGUS_GTC_MODEL_BASE_URL=https://api.openai.com/v1
ARGUS_GTC_MODEL_NAME=gpt-6-luna
ARGUS_GTC_MODEL_API_KEY=<OpenAI-API-key>
```

## Deploy

Set the image in `.env` (or export it), then deploy:

```bash
ARGUS_GTC_DEMO_IMAGE=quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v2 \
ARGUS_GTC_SERVER_IMAGE=quay.io/itsoiref/argus-gtc-demo:v47-memory-phonehome \
ARGUS_GTC_AGENT_IMAGE=quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v14-agent-shell \
make deploy-argus-gtc-demo
```

This command:

- Removes the legacy Argus log-cleaner DaemonSet (if present).
- Deploys the Kata workload, scenario sink, NetworkPolicy, and UI on the management cluster.
- Configures the demo server to read native Argus reports from the hosted Argus pod through the hosted kubeconfig.
- Deploys the NeMo Agent Toolkit pod in its own Kata VM on the same worker as `invisible-vm`.
- Deploys an in-cluster canary Service on TCP/31999 (NodePort exists, but the agent configuration uses the canary Service DNS name). Bash still runs inside the agent pod. The UI Route is the public entry; do not create a Route to the agent.
- Applies a cluster-scoped AdminNetworkPolicy selecting only the agent pod. It allows TCP/31999 to nodes (the canary) and denies every other node destination. Deployment requires the AdminNetworkPolicy API, OVN-Kubernetes, cluster-admin permissions, and a free priority 0.
- Allows the agent pod outbound TCP/443 for direct model API calls. The Kubernetes NetworkPolicy destination is any IPv4 address; the OpenAI hostname is selected by `ARGUS_GTC_MODEL_BASE_URL`. Canary egress is scoped to worker InternalIPs on TCP/31999. Do not disable the namespace NetworkPolicy for `invisible-vm`.
- Prints the OpenShift Route URL for the UI.

### Useful variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ARGUS_GTC_DEMO_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v2` | Kata workload + sink image; UBI9/glibc Bash and Python 3 support the scenarios |
| `ARGUS_GTC_SERVER_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:v47-memory-phonehome` | Demo server, UI, and canary image |
| `ARGUS_GTC_AGENT_IMAGE` | `quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v14-agent-shell` | Pre-built NeMo Agent Toolkit image |
| `ARGUS_GTC_MODEL_BASE_URL` | *(empty)* | OpenAI-compatible API base URL; for OpenAI use `https://api.openai.com/v1` |
| `ARGUS_GTC_MODEL_NAME` | `gpt-6-luna` | OpenAI API model ID; must be enabled for your API account |
| `ARGUS_GTC_MODEL_API_KEY` | *(empty)* | Model API key; stored in a Kubernetes Secret and injected into the agent pod |
| `ARGUS_LOG_THRESHOLD_SIZE` | `50M` | Argus native log rotation threshold |
| `ARGUS_LOG_MAX_FILES_COUNT` | `10` | Argus rotated log file cap |

## Demo flow

### Workload security presenter path

The fixed console opens on `invisible-vm`. Native Argus activity and alerts remain visible before, during, and after an action. The descriptions for all nine allowlisted workload actions live in the [scenario catalog](../demo/argus-gtc/server/scenario_catalog.py), which also serves `GET /api/scenarios` for the UI. Use that catalog as the source for the What happens, Why show it, and Watch for copy. **More scenarios** exposes Phone home, Legacy shell-history test, Modify a demo file, Network burst, and Compute activity; **Technical view** has the exact commands and references. Selection only changes the explanation and Run button.

1. **Environment.** Show the activity stream before running anything. Identify the selected workload and say: “Argus runs on the BlueField DPU and observes activity inside this isolated workload without a security agent installed in the guest.” Read Browser, Argus collector, and Latest native event separately. A connected browser and a quiet workload do not prove or disprove source health.
2. **Discovery.** Select **Discovery**, explain the bounded commands, then select **Run Discovery**. The distinct demo controller marker identifies the action start. Related process and file events are highlighted in the continuing native stream; unrelated activity remains visible in scope. Discovery completion alone is not an Argus alert.
3. **Reverse shell.** Select **Reverse shell**, explain the controlled listener, then select **Run Reverse shell**. The latest actual run remains identified even while a different action is selected. Follow process and network records in the stream. Call it a detection only if the matching native `Reverse Shell Detected` record is `ALERT/HIGH`; it then appears in the persistent Alerts panel with its original severity. If none arrives, report the explicit no-matching-alert result.
4. **Inspect evidence.** Use **Inspect record** on the stream row or alert card to show event ID, source timestamp, workload, process, run ID, and original payload. The same native alert appears in both panels. Earlier-run or unassociated records remain labeled honestly; the controller marker is not native telemetry.
5. **Respond and recover.** The secondary stop/restore controls target only `invisible-vm`. The server serializes these actions with scenario/agent runs and waits for observed pod termination or readiness. Argus and DPU health remain separate from workload state.

The stream scope defaults to the selected workload. **All demo workloads** and **Worker telemetry** broaden it without deleting evidence. **Pause** freezes the displayed rows while ingestion continues and shows incoming count; Resume catches up to retained records. A replay gap, eviction, or server restart is shown in the history note. The server and browser buffers are bounded, so inspect older raw records before retention removes them.

### AI agent behavior path

The AI story uses only `argus-gtc-agent`, a separate Kata workload on the management cluster. It is not `invisible-vm`, and the UI does not present the scripted workload's stop control as an AI response. The agent's configured target is the `argus-gtc-canary` Service name on TCP/31999; the listener is a controlled action destination, separate from the DPU observer.

Select **AI agent behavior** in the story picker; the same stream and alerts layout now scopes to `argus-gtc-agent`. Selecting an AI request shows its description without sending it.

1. **Normal request.** Select and run the status-summary baseline. A run with no recorded shell-tool call is the expected baseline. Shell connection, listener, and shell-specific Argus checks are Not applicable.
2. **Authorized demo shell.** Explicitly ask the agent to open one bounded demo shell. Keep the evidence separate: authenticated tool report; canary `id` output; matching native Argus process/socket event; native alert, if any; OVN deny, if any. A connected socket without listener output is not a confirmed working shell.
3. **Independent observation.** Show the matching native Argus record from `argus-gtc-agent`. Only describe a HIGH alert when the record itself contains `message_type=ALERT` and `severity=HIGH`. A timeout alone is not proof of an OVN policy block.
4. **Pasted-note example (optional).** The current workflow explicitly asks the agent to complete actions requested in the pasted maintenance note. Describe this as note-driven tool use, not as a successful prompt-injection test. If no tool call is recorded, show the agent response without claiming a deliberate refusal.
5. **Recap.** State what the agent attempted, what the listener confirmed, what Argus observed, whether Argus raised a native alert, and whether OVN recorded a matching deny. Do not blend this evidence with `invisible-vm`.

For both stories, use the actual workload name and the three separate health signals. “Connected” means the SSE connection is open; “Reading source” means the collector completed a source poll, even if it found no new events; Latest native event uses the source occurrence timestamp. A collector failure is shown separately from a quiet feed.

## Cleanup

```bash
make cleanup-argus-gtc-demo
```

Removes only the demo resources on the management cluster and any legacy
`argus-gtc-demo` namespace left on the hosted cluster. Argus, DPU services,
and Kata infrastructure are untouched. It also deletes only the named
`argus-gtc-agent-host-access` AdminNetworkPolicy.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No Argus events in UI | Argus pods Running on hosted cluster; the demo server's hosted kubeconfig can list/exec into `doca-argus-*`; logs under `/var/log/doca_argus_activity_report/`; log-cleaner absent |
| Argus status Pending | `KUBECONFIG=doca.kubeconfig oc get pods -n dpf-operator-system \| grep argus` |
| DPU status Degraded | Open `/api/status` and inspect `details.dpu`. A `403` means re-apply demo RBAC (`make deploy-argus-gtc-demo`). If `ready: false` with conditions, check `oc get dpudeployment dpudeployment -n dpf-operator-system` |
| Workload Pending | Kata VF pool on PF0; NAD/injector applied |
| UI image pull errors | Ensure `ARGUS_GTC_SERVER_IMAGE` points to a registry the cluster can pull (image pull secret if private) |
| Agent actions disabled | Check `ARGUS_GTC_MODEL_BASE_URL`, `ARGUS_GTC_MODEL_NAME`, and `oc -n argus-gtc-demo rollout status deploy/argus-gtc-agent` |
| Kata agent Pending | Confirm a second PF0 Kata VF is free on the same worker as `invisible-vm`; inspect `oc -n argus-gtc-demo describe pod -l app=argus-gtc-agent` |
| Agent does not call the tool | Use a tool-calling-compatible model and inspect its response. The UI reports no tool call without inferring a deliberate refusal; do not claim an attempted connection. The pasted-note example is note-driven under the current system instructions. |
| Canary has no `uid=` output | Confirm `argus-gtc-canary` is Ready, NodePort 31999 is allocated, and the agent ANP allows TCP/31999 to nodes. Check canary logs. |
| Shell connected but Argus did not show it | Inspect native Argus logs for `TCP Network Connection State Change`, `Network Connection Created`, `Process Created`, or `Reverse Shell Detected` with `argus-gtc-agent-shell-<run-id>` or the agent pod. Check that Argus is scanning the agent's Kata VF on PF0. The UI does not mark this run as Argus observed without a matching native event. |
| Argus report tailing fails | Check the demo server logs and verify the hosted kubeconfig has `get/list` access to Argus pods and `create` access to `pods/exec` in `dpf-operator-system` |
| Executable Memory returns `no-native-event` | Confirm the Python action completed and held the mapping for 45 seconds. Inspect native Argus reports for `New Executable Anonymous Memory Mapped` on `invisible-vm` with the run marker; confirm the live memory collector is enabled. A process event by itself is insufficient. |
| Phone Home returns `no-native-event` | Confirm `scenario-sink` has a Pod IP and the connection reached that IP on TCP/4444. Inspect native Argus reports for `Network Connection Created` from `invisible-vm` with the correct destination; confirm the live network collector is enabled. Other socket events do not satisfy this scene. |
| Audit Evasion returns `no-native-alert` | Confirm the live Argus config has `shell_command.disable_scan=false`, `shell_history_cleared=true`, and `shell_history_disabled=true`; inspect `/var/log/doca_argus/` for profile or collection failures. A correlated `Executable Permissions Removed` MEDIUM alert does not satisfy this scenario. |

## Measuring action timing and detection latency

Before presenting, run two scenarios and note timestamps:

```bash
# wall clock when scenario starts (UI action log)
# compare to occurred_message_time_iso_8601_ns in Argus JSON under:
# hosted node /var/log/doca_argus_activity_report/
```

Do not fabricate Argus fields; use captured samples to tune UI refresh intervals.

## Architecture

```text
Management cluster                Hosted/DPU cluster
─────────────────────            ───────────────────
invisible-vm (Kata) ── VF ──> BlueField DPU <── DMA ── doca-argus pods
argus-gtc-agent (Kata) ── VF ────────┘                    │
       ├── HTTPS/443 ──> OpenAI API                       │
       ├── Bash TCP/31999 ──> canary Service           │
       └── auth/report ──> demo server                    │
argus-gtc-canary Service DNS/ClusterIP :31999 (NodePort also published)
                 ── id/exit ──> agent shell
browser ── Route ──> argus-gtc-demo UI ── /generate ──> agent ClusterIP
(no Route on the agent)
       ↑                    native process/socket <──────┘
```
