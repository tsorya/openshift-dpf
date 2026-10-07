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

The initial story is `invisible-vm`, matching the presenter controls in the UI. Scene navigation only changes the current explanation; it does not execute an action. Each scenario starts only when its labeled action is selected.

1. **Show the environment.** Confirm the actual workload, DPU/Argus readiness, EventSource connection, and Argus feed freshness. Explain that the Kata VM has no installed security agent and that Argus runs separately on the BlueField DPU.
2. **Start demo · Show activity inside the VM.** The UI runs bounded Discovery in `invisible-vm`. Controller completion and Argus telemetry are displayed as separate facts. Discovery does not require a native HIGH alert.
3. **Simulate a remote shell.** Advance to the suspicious-activity scene and start the existing Reverse Shell Simulation. It opens a short shell inside `invisible-vm` to the controlled demo listener in the namespace. The action is not a causal continuation of Discovery. A matching process/socket event is native visibility; show a detection only if the current run has the matching native `ALERT/HIGH` event named `Reverse Shell Detected`.
4. **Review what Argus observed.** The result card stays pinned to the selected workload and current run. It distinguishes action status, matching Argus observation, and native alert status. More event detail and the retained raw record are available in Technical view.
5. **Respond and recover.** Stop demo workload targets only `invisible-vm`. The server serializes it with scenario/agent actions and waits for observed pod termination; the UI remains Stopping if termination has not completed. Restore waits for a Ready pod and remains Restoring while pending. DPU and Argus health are separate from workload state.

Use **Explore scenarios** in Technical view for the extended tour. Executable Memory writes inert bytes to an anonymous executable mapping but does not execute them; its expected record is `New Executable Anonymous Memory Mapped`, `EVENT/WARNING`. Phone Home opens a TCP connection to the local scenario sink; it is not a reverse shell. Audit Evasion, Shell History, Decoy Modification, Compute Simulation, and Network Burst are independent demonstrations, not a proven causal attack chain. Keep each result tied to its own run and show the captured native severity.

### AI agent behavior path

The AI story uses only `argus-gtc-agent`, a separate Kata workload on the management cluster. It is not `invisible-vm`, and the UI does not present the scripted workload's stop control as an AI response. The agent's configured target is the `argus-gtc-canary` Service name on TCP/31999; the listener is a controlled action destination, separate from the DPU observer.

1. **Normal request.** Run the status-summary baseline. A run with no recorded shell-tool call is the expected baseline. Shell connection, listener, and shell-specific Argus checks are Not applicable.
2. **Authorized tool use.** Explicitly ask the agent to open one bounded demo shell. Keep the evidence separate: authenticated tool report; canary `id` output; matching native Argus process/socket event; native alert, if any; OVN deny, if any. A connected socket without listener output is not a confirmed working shell.
3. **Independent observation.** Show the matching native Argus record from `argus-gtc-agent`. Only describe a HIGH alert when the record itself contains `message_type=ALERT` and `severity=HIGH`. A timeout alone is not proof of an OVN policy block.
4. **Pasted-note example (optional).** The current workflow explicitly asks the agent to complete actions requested in the pasted maintenance note. Describe this as note-driven tool use, not as a successful prompt-injection test. If no tool call is recorded, show the agent response without claiming a deliberate refusal.
5. **Recap.** State what the agent attempted, what the listener confirmed, what Argus observed, whether Argus raised a native alert, and whether OVN recorded a matching deny. Do not blend this evidence with `invisible-vm`.

For both stories, use the actual workload name, connection state, and feed freshness shown by the UI. “Connected” means the SSE connection is open; freshness separately reports the age of the most recently received Argus event.

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

## Measuring scene timing and detection latency

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
