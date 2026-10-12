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
docker buildx build --platform linux/amd64 --push \
  -t quay.io/itsoiref/argus-gtc-demo:v64-freeform-agent \
  -f demo/argus-gtc/Containerfile demo/argus-gtc
```

The server image contains Python 3.11, `requirements.txt`, and the `server/` +
`static/` directories. The audit-evasion implementation uses
`timeout --foreground` so the bounded timeout preserves the interactive PTY.

Build and push the separate NeMo Agent Toolkit pod image:

```bash
docker build --platform linux/amd64 \
  -t quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v19-agent-shell \
  -f demo/argus-gtc-agent/Containerfile demo/argus-gtc-agent
docker push quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v19-agent-shell
```

Configure these values in the generated `.env` before deployment. The model
must expose OpenAI-compatible chat completions and support tool calling. For
direct OpenAI API access, use `https://api.openai.com/v1`, an API model ID, and
an OpenAI API key. The agent pod receives the key from a Kubernetes Secret and
needs outbound TCP/443. The demo shell is allowed only to the worker-host
canary on TCP/31999.

```text
ARGUS_GTC_AGENT_IMAGE=quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v19-agent-shell
ARGUS_GTC_MODEL_BASE_URL=https://api.openai.com/v1
ARGUS_GTC_MODEL_NAME=gpt-6-luna
ARGUS_GTC_MODEL_API_KEY=<OpenAI-API-key>
```

The AI agent Run controls require a Ready Kata agent and a model base URL and name on the demo server. An older generated `.env` may omit `ARGUS_GTC_MODEL_NAME`; the deployment script uses the repository default for both server and agent in that case. Supply the model base URL and API key on each deployment.

## Deploy

Set the image in `.env` (or export it), then deploy:

```bash
ARGUS_GTC_DEMO_IMAGE=quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v3-python-scenarios \
ARGUS_GTC_SERVER_IMAGE=quay.io/itsoiref/argus-gtc-demo:v64-freeform-agent@sha256:93a94a79401fa2c02102ecc609cb8571aa94fe3fae895243cd26eb2583bd9074 \
ARGUS_GTC_AGENT_IMAGE=quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v19-agent-shell \
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
| `ARGUS_GTC_DEMO_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v3-python-scenarios` | Kata workload + sink image; UBI9/glibc Bash and Python 3 support the scenarios |
| `ARGUS_GTC_SERVER_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:v64-freeform-agent@sha256:93a94a79401fa2c02102ecc609cb8571aa94fe3fae895243cd26eb2583bd9074` | Demo server, UI, and canary image |
| `ARGUS_GTC_AGENT_IMAGE` | `quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v19-agent-shell` | Pre-built NeMo Agent Toolkit image |
| `ARGUS_GTC_MODEL_BASE_URL` | *(empty)* | OpenAI-compatible API base URL; for OpenAI use `https://api.openai.com/v1` |
| `ARGUS_GTC_MODEL_NAME` | `gpt-6-luna` | OpenAI API model ID; must be enabled for your API account |
| `ARGUS_GTC_MODEL_API_KEY` | *(empty)* | Model API key; stored in a Kubernetes Secret and injected into the agent pod |
| `ARGUS_LOG_THRESHOLD_SIZE` | `50M` | Argus native log rotation threshold |
| `ARGUS_LOG_MAX_FILES_COUNT` | `10` | Argus rotated log file cap |

## Demo flow

### Workload security presenter path

The console opens on `invisible-vm`. The selected scenario shows three action steps, cues for opening Activity, and the Argus result to verify. Activity is collapsed by default; **Show Activity** opens the raw native feed with Scope and Pause controls. Native alerts and the last run's Expected / Observed result remain visible. The descriptions live in the [scenario catalog](../demo/argus-gtc/server/scenario_catalog.py), which serves `GET /api/scenarios`. **Technical view** has exact commands and references. Selecting a scenario changes its guide and Run button but does not start it or replace the last run's result.

1. **Environment.** Identify the selected workload and say: “Argus runs on the BlueField DPU and observes activity inside this isolated workload without a security agent installed in the guest.” The compact Environment panel repeats the six system values from Technical view: Management cluster, DPU, Argus / HyperShift, Kata VM, PF0 VF / Link, and Security feed. **Updates Connected** means only that the browser stream is open. Security feed shows event recency while the collector is reading; it shows Unavailable when the collector fails, even if a recent event remains in memory. Open Activity only when you want to inspect raw records.
2. **Discovery.** Run `uname -a` and `id`, list processes with `ps aux`, and read the planted `/decoys` files. Select **Run Discovery**. The **Discovered inside the VM** card shows the actual command output; it is separate from Argus telemetry. In Activity, look for the corresponding process and file records if Argus reports them. No native alert is required.
3. **Executable memory.** Map writable executable anonymous memory, write inert bytes, and hold the mapping for 15 seconds without executing them. In Activity, look for the marked Python process and the exact memory event. The Expected / Observed card verifies a matching `New Executable Anonymous Memory Mapped` WARNING with writable and executable memory; a process event alone is insufficient.
4. **Reverse shell.** Open a bounded Bash shell whose input and output connect to the in-namespace `scenario-sink`. In Activity, look for the marked shell and its TCP connection. Call it a detection only if the Expected / Observed card verifies `Reverse Shell Detected` as `ALERT/HIGH`. The current sink accepts the connection but does not capture commands, user ID, or whether the shell remains active; do not claim those facts from the demo.
5. **Audit evasion.** Start a disposable interactive shell, clear its harmless history, add a second harmless marker, then disable history recording. The shell remains open for an Argus scan before it exits and deletes the temporary history file. In Activity, inspect the Bash session and native Argus records. The required native result is `Shell History Cleared` or `Shell History Disabled` with `ALERT/HIGH`; ordinary process activity does not prove an evasion alert.
6. **Inspect evidence.** Use **Inspect record** on an alert card or Activity row to show event ID, source timestamp, workload, process, run ID, and original payload. **Find in activity** opens the feed at the corresponding native record. Earlier-run or unassociated records remain labeled honestly; the controller marker is not native telemetry.
7. **Respond and recover.** Open **Technical view → Explore scenarios → OpenShift response** for the stop/restore controls. They target only `invisible-vm`. The server serializes these actions with scenario/agent runs and waits for observed pod termination or readiness. Argus and DPU health remain separate from workload state.

Activity scope defaults to the selected workload, not the selected scenario. Use the run label, process, destination or file path, and the verified result card to distinguish related records; other records in scope are not proof of this run. **All demo workloads** and **Worker telemetry** broaden the feed without deleting evidence. **Pause** freezes displayed rows while ingestion continues and shows incoming count; Resume catches up to retained records. A replay gap, eviction, or server restart is shown in the history note. The server and browser buffers are bounded, so inspect older raw records before retention removes them.

### AI agent behavior path

The AI story uses only `argus-gtc-agent`, a separate Kata workload on the management cluster. It is not `invisible-vm`, and the UI does not present the scripted workload's stop control as an AI response. The agent's configured target is the `argus-gtc-canary` Service name on TCP/31999; the listener is a controlled action destination, separate from the DPU observer.

Open `/agent` directly or choose **AI agent behavior** in the header navigation. This page uses the same collapsible Activity feed and visible Alerts layout scoped to `argus-gtc-agent`. Its five evidence checks summarize the latest run without treating a tool report, listener response, native Argus event, native alert, and OVN deny as interchangeable. Selecting an AI request shows its description without sending it. Use the **Workload security** link to return to `/` and `invisible-vm`.

1. **Talk to agent.** Edit the example question or type your own short message, such as “Who are you, and what are you running?”, then select **Send to agent**. The page shows the message and the Kata agent's actual reply. The agent application runs in a Kata workload and calls the configured model endpoint; the model itself is not presented as running in the pod. No shell action is requested; a run with no recorded shell action is the expected baseline. Listener and shell-specific Argus checks are Not applicable. Each send is a separate request without chat history. The message and reply stay in the sending page session and are excluded from the shared run-state API.
2. **Demo shell request.** Ask the agent to call its fixed demo shell tool. The server checks the agent token and active run ID before allowing it; there is no separate presenter approval step. The tool opens Bash inside the agent's Kata pod to the fixed canary for at most 20 seconds. Keep the evidence separate: authenticated tool report; canary `id` output; matching native Argus process/socket event; native alert, if any; OVN deny, if any. A connected socket without listener output is not a confirmed working shell.
3. **Independent observation.** Show the matching native Argus record from `argus-gtc-agent`. Only describe a HIGH alert when the record itself contains `message_type=ALERT` and `severity=HIGH`. A timeout alone is not proof of an OVN policy block.
4. **Recap.** State what the agent attempted, what the listener confirmed, what Argus observed, whether Argus raised a native alert, and whether OVN recorded a matching deny. Do not blend this evidence with `invisible-vm`.

For both stories, use the actual workload name. The Environment tiles describe the scripted `invisible-vm` system and appear on the Workload security page; the AI agent page uses its separate agent readiness and evidence checks. Management cluster Ready means the demo server's management API status queries succeeded, not that every cluster operator is healthy. Argus / HyperShift Ready refers to the hosted Argus service pods. Security feed recency is not proof of continuous collection, so collector Unavailable overrides it in both the main and Technical views.

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
| Agent does not call the tool | Use a tool-calling-compatible model and inspect its response. The UI reports no tool call without inferring a deliberate refusal; do not claim an attempted connection. |
| Canary has no `uid=` output | Confirm `argus-gtc-canary` is Ready, NodePort 31999 is allocated, and the agent ANP allows TCP/31999 to nodes. Check canary logs. |
| Shell connected but Argus did not show it | Inspect native Argus logs for `TCP Network Connection State Change`, `Network Connection Created`, `Process Created`, or `Reverse Shell Detected` with `argus-gtc-agent-shell-<run-id>` or the agent pod. Check that Argus is scanning the agent's Kata VF on PF0. The UI does not mark this run as Argus observed without a matching native event. |
| Argus report tailing fails | Check the demo server logs and verify the hosted kubeconfig has `get/list` access to Argus pods and `create` access to `pods/exec` in `dpf-operator-system` |
| Executable Memory returns `no-native-event` | Confirm the Python action completed and held the mapping for 15 seconds. The evidence wait ends immediately on a matching record, or after 45 more seconds without one. Inspect native Argus reports for `New Executable Anonymous Memory Mapped` with `EVENT/WARNING` or `ALERT/WARNING`, writable and executable permissions, the target `invisible-vm` pod, and the run marker. Confirm the live memory collector is enabled. A process event or ordinary `r-xp` mapping is insufficient. |
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
