# Argus GTC Demo — Operator Runbook

**Title:** Invisible VM, Visible Threat

This tenant demo runs the Kata workloads and AI agent on the tenant cluster with its existing `kata` RuntimeClass. The demo UI and Argus reader run on the infra/management cluster; DOCA Argus runs on the BlueField DPU HostedCluster. No DPU VF passthrough or in-guest security agent is used. Argus does not introspect processes inside the Kata guests in this mode; the UI shows tenant workload state and DPU-scoped Argus telemetry. OVN-Kubernetes policy evidence remains separate from native Argus telemetry.

## Safety note

All scenarios are **bounded and allowlisted**. They do not use malware, internet C2, external scanning, privilege escalation, or attacks against shared infrastructure. The agent’s only extra tool opens one Bash session inside the agent Kata pod to the configured `argus-gtc-canary` Service on TCP/31999 for at most 20 seconds. The canary sends `id` and records the output; commands run in the agent workload, not on the host. The tool accepts no model-selected IP, port, or command. The UI and the token-protected agent gateway use OpenShift Routes for cross-cluster calls. The NAT `/generate` endpoint is reachable only through that gateway and requires the demo bearer token. Scenario labels such as “Discovery” and “Reverse Shell Simulation” are applied by the demo controller for correlation. They are **not** native Argus ATT&CK mappings and do **not** mean Argus raised a HIGH/ALERT. The AI shell action is confirmed only when an authenticated tool report and matching canary `id` output establish the bounded session. Matching native Argus process/socket evidence is a separate observation with its real severity. Treat a native HIGH alert as confirmed only when the same raw event contains both `message_type=ALERT` and `severity=HIGH`. Do not synthesize an Argus alert from the agent response.

## Prerequisites

1. The tenant cluster already has the standard `kata` RuntimeClass available.
   No Kata installation, PF0 VF pool, or Kata NAD is needed for this no-VF path.
2. The DPUDeployment exists on the management cluster. The combined start
   target enables Argus with its non-Kata configuration; no
   `ARGUS_REPRESENTOR_ID` or Kata VF pool is required. The demo reads Argus
   reports from the DPU HostedCluster.
3. DTS panels query Thanos in the demo server cluster (infra by default). Make
   sure DTS metrics are scraped there; the existing `make deploy-observability`
   target acts on `KUBECONFIG`.
4. For the tenant target, deploy the tenant HostedCluster first and make sure
   `ZT_TENANT_KUBECONFIG` points to its kubeconfig. The default file is
   `tenant.kubeconfig`.
5. DPU hosted-cluster kubeconfig available locally (`doca.kubeconfig` or
   secret fetch). The deploy script uses it to create a namespace-scoped
   24-hour Argus reader token; it does not copy this admin kubeconfig into the
   demo namespace.
6. The infra cluster can reach the tenant Kubernetes API and tenant route, and
   the tenant workload can resolve and reach the infra UI route over HTTPS.

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
  -t quay.io/itsoiref/argus-gtc-demo:v48-infra-ui-tenant-workloads \
  -f demo/argus-gtc/Containerfile demo/argus-gtc
docker push quay.io/itsoiref/argus-gtc-demo:v48-infra-ui-tenant-workloads
```

The server image contains Python 3.11, `requirements.txt`, and the `server/` +
`static/` directories. The audit-evasion implementation uses
`timeout --foreground` so the bounded timeout preserves the interactive PTY.

Build and push the separate NeMo Agent Toolkit pod image:

```bash
docker build --platform linux/amd64 \
  -t quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v20-tenant-gateway \
  -f demo/argus-gtc-agent/Containerfile demo/argus-gtc-agent
docker push quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v20-tenant-gateway
```

Configure these values in the generated `.env` before deployment. The model
must expose OpenAI-compatible chat completions and support tool calling. For
direct OpenAI API access, use `https://api.openai.com/v1`, an API model ID, and
an OpenAI API key. The agent pod receives the key from a Kubernetes Secret and
needs outbound TCP/443. The demo shell is allowed only to the worker-host
canary on TCP/31999.

```text
ARGUS_GTC_AGENT_IMAGE=quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v20-tenant-gateway
ARGUS_GTC_MODEL_BASE_URL=https://api.openai.com/v1
ARGUS_GTC_MODEL_NAME=gpt-6-luna
ARGUS_GTC_MODEL_API_KEY=<OpenAI-API-key>
```

## Deploy

Set the image in `.env` (or export it), then deploy:

```bash
ARGUS_GTC_DEMO_IMAGE=quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v2 \
ARGUS_GTC_SERVER_IMAGE=quay.io/itsoiref/argus-gtc-demo:v48-infra-ui-tenant-workloads \
ARGUS_GTC_AGENT_IMAGE=quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v20-tenant-gateway \
make deploy-argus-gtc-demo
```

That target keeps the single-cluster behavior and deploys the UI and workloads
to `KUBECONFIG`. To start Argus in non-Kata mode and deploy the UI on infra
with Kata workloads on the tenant HostedCluster, run:

```bash
make start-argus-gtc-demo-tenant
```

This command enables or updates Argus on the DPU side, then deploys the UI and
reader on `ARGUS_GTC_DEMO_KUBECONFIG` (defaults to `KUBECONFIG`) and the Kata
workloads on `ZT_TENANT_KUBECONFIG`. It does not run `make enable-kata`, install Kata, or
configure DPU VFs. To redeploy only the demo after Argus is already running,
use `make deploy-argus-gtc-demo-tenant`.

The tenant target creates a namespace on both clusters. The UI Route and demo
server run on infra; the Kata workload, sink, agent, and canary run on the
tenant. The server reads workload state and controls scenarios through a
namespace-scoped tenant token, DPU status through a management token, and Argus
reports through a DPU HostedCluster token. The tokens last 24 hours; re-running
the deploy target refreshes them and restarts the server.

This command:

- Removes the legacy Argus log-cleaner DaemonSet (if present).
- Deploys the UI and Argus reader to the demo server cluster (`KUBECONFIG` by default) and the Kata workload, scenario sink, NetworkPolicies, agent, and canary to the workload cluster. `make deploy-argus-gtc-demo-tenant` selects `ZT_TENANT_KUBECONFIG` for workloads.
- Runs both Kata pods with the target cluster's configured RuntimeClass. Tenant deployments default to standard `kata` without DPU VF passthrough; the demo does not create a RuntimeClass.
- Configures the demo server to read DPU deployment status with a read-only management token and native Argus reports through a scoped DPU HostedCluster token.
- Deploys the NeMo Agent Toolkit pod in its own Kata VM on the same tenant worker as `invisible-vm`.
- Deploys the tenant canary Service on TCP/31999 and a token-protected Route for the agent gateway. The NAT `/generate` endpoint binds to pod-local loopback and is not directly exposed.
- Applies a cluster-scoped AdminNetworkPolicy selecting only the agent pod. It allows TCP/31999 to nodes (the canary), plus HTTPS to the infra UI route, and denies other node destinations. Deployment requires the AdminNetworkPolicy API, OVN-Kubernetes, cluster-admin permissions, and a free priority 0.
- Allows the agent pod outbound TCP/443 for direct model API calls. The Kubernetes NetworkPolicy destination is any IPv4 address; the OpenAI hostname is selected by `ARGUS_GTC_MODEL_BASE_URL`. Canary egress is scoped to worker InternalIPs on TCP/31999. Do not disable the namespace NetworkPolicy for `invisible-vm`.
- Prints the OpenShift Route URL for the UI.

### Useful variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ARGUS_GTC_DEMO_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v2` | Kata workload + sink image; UBI9/glibc Bash and Python 3 support the scenarios |
| `ARGUS_GTC_SERVER_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:v48-infra-ui-tenant-workloads` | Demo server, UI, and canary image |
| `ARGUS_GTC_AGENT_IMAGE` | `quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v20-tenant-gateway` | Pre-built NeMo Agent Toolkit image plus authenticated gateway |
| `ARGUS_GTC_KATA_RUNTIME_CLASS` | `kata` | Existing tenant Kata RuntimeClass; no VF passthrough |
| `ZT_TENANT_KUBECONFIG` | `tenant.kubeconfig` | Tenant cluster kubeconfig selected by `make start-argus-gtc-demo-tenant` |
| `ARGUS_GTC_DEMO_KUBECONFIG` | `KUBECONFIG` | Infra cluster that hosts the UI and Argus reader |
| `ARGUS_GTC_WORKLOAD_KUBECONFIG` | `ARGUS_GTC_DEMO_KUBECONFIG` | Cluster that hosts Kata workloads; the tenant Make target sets this to `ZT_TENANT_KUBECONFIG` |
| `ARGUS_GTC_MODEL_BASE_URL` | *(empty)* | OpenAI-compatible API base URL; for OpenAI use `https://api.openai.com/v1` |
| `ARGUS_GTC_MODEL_NAME` | `gpt-6-luna` | OpenAI API model ID; must be enabled for your API account |
| `ARGUS_GTC_MODEL_API_KEY` | *(empty)* | Model API key; stored in a Kubernetes Secret and injected into the agent pod |
| `ARGUS_LOG_THRESHOLD_SIZE` | `50M` | Argus native log rotation threshold |
| `ARGUS_LOG_MAX_FILES_COUNT` | `10` | Argus rotated log file cap |

## Demo flow

### Workload security presenter path

The fixed console opens on `invisible-vm`. Native Argus activity and alerts remain visible before, during, and after an action. The four presenter workload descriptions live in the [scenario catalog](../demo/argus-gtc/server/scenario_catalog.py), which also serves `GET /api/scenarios` for the UI. Use that catalog as the source for the What happens, Why show it, and Watch for copy. **Technical view** has the exact commands and references. Selection only changes the explanation and Run button.

1. **Environment.** Show the activity stream before running anything. Identify the selected workload and say: “Argus runs on the BlueField DPU and observes activity inside this isolated workload without a security agent installed in the guest.” Read Browser, Argus collector, and Latest native event separately. A connected browser and a quiet workload do not prove or disprove source health.
2. **Discovery.** Select **Discovery**, explain the bounded commands, then select **Run Discovery**. The distinct demo controller marker identifies the action start. Related process and file events are highlighted in the continuing native stream; unrelated activity remains visible in scope. Discovery completion alone is not an Argus alert.
3. **Reverse shell.** Select **Reverse shell**, explain the controlled listener, then select **Run Reverse shell**. The latest actual run remains identified even while a different action is selected. Follow process and network records in the stream. Call it a detection only if the matching native `Reverse Shell Detected` record is `ALERT/HIGH`; it then appears in the persistent Alerts panel with its original severity. If none arrives, report the explicit no-matching-alert result.
4. **Inspect evidence.** Use **Inspect record** on the stream row or alert card to show event ID, source timestamp, workload, process, run ID, and original payload. The same native alert appears in both panels. Earlier-run or unassociated records remain labeled honestly; the controller marker is not native telemetry.
5. **Respond and recover.** The secondary stop/restore controls target only `invisible-vm`. The server serializes these actions with scenario/agent runs and waits for observed pod termination or readiness. Argus and DPU health remain separate from workload state.

The stream scope defaults to the selected workload. **All demo workloads** and **Worker telemetry** broaden it without deleting evidence. **Pause** freezes the displayed rows while ingestion continues and shows incoming count; Resume catches up to retained records. A replay gap, eviction, or server restart is shown in the history note. The server and browser buffers are bounded, so inspect older raw records before retention removes them.

### AI agent behavior path

The AI story uses only `argus-gtc-agent`, a separate Kata workload on the workload cluster (tenant for the tenant target). It is not `invisible-vm`, and the UI does not present the scripted workload's stop control as an AI response. The agent's configured target is the `argus-gtc-canary` Service name on TCP/31999; the listener is a controlled action destination, separate from the DPU observer.

Open `/agent` directly or choose **AI agent behavior** in the header navigation. This page uses the same stream and alerts layout scoped to `argus-gtc-agent`. Its five evidence checks summarize the latest run without treating a tool report, listener response, native Argus event, native alert, and OVN deny as interchangeable. Selecting an AI request shows its description without sending it. Use the **Workload security** link to return to `/` and `invisible-vm`.

1. **Normal request.** Select and run the status-summary baseline. A run with no recorded shell-tool call is the expected baseline. Shell connection, listener, and shell-specific Argus checks are Not applicable.
2. **Authorized demo shell.** Explicitly ask the agent to open one bounded demo shell. Keep the evidence separate: authenticated tool report; canary `id` output; matching native Argus process/socket event; native alert, if any; OVN deny, if any. A connected socket without listener output is not a confirmed working shell.
3. **Independent observation.** Show the matching native Argus record from `argus-gtc-agent`. Only describe a HIGH alert when the record itself contains `message_type=ALERT` and `severity=HIGH`. A timeout alone is not proof of an OVN policy block.
4. **Recap.** State what the agent attempted, what the listener confirmed, what Argus observed, whether Argus raised a native alert, and whether OVN recorded a matching deny. Do not blend this evidence with `invisible-vm`.

For the tenant deployment, run `make watch-argus-gtc-acl-tenant` in a second
terminal to stream the tenant agent's OVN ACL evidence to the infra UI.

For both stories, use the actual workload name and the three separate health signals. “Connected” means the SSE connection is open; “Reading source” means the collector completed a source poll, even if it found no new events; Latest native event uses the source occurrence timestamp. A collector failure is shown separately from a quiet feed.

## Cleanup

```bash
make cleanup-argus-gtc-demo
```

For a tenant deployment, use:

```bash
make cleanup-argus-gtc-demo-tenant
```

Cleanup removes the demo namespaces from the UI and workload clusters, the
scoped reader roles and service accounts from management and the DPU
HostedCluster, and any legacy `argus-gtc-demo` namespace left on the DPU
HostedCluster. Argus, DPU services, and Kata infrastructure are untouched. It
also deletes only the named `argus-gtc-agent-host-access` AdminNetworkPolicy
from the workload cluster.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No Argus events in UI | Argus pods Running on hosted cluster; the demo server's scoped hosted token can list and exec into `doca-argus-*`; logs under `/var/log/doca_argus_activity_report/`; log-cleaner absent |
| Argus status Pending | `KUBECONFIG=doca.kubeconfig oc get pods -n dpf-operator-system \| grep argus` |
| DPU status Degraded | Open `/api/status` and inspect `details.dpu`. Re-run the matching deploy target to refresh management read access. If `ready: false` with conditions, check `oc get dpudeployment dpudeployment -n dpf-operator-system` using the management kubeconfig. |
| Workload Pending | Confirm RuntimeClass `kata` exists and the tenant worker has enough CPU and memory; the tenant no-VF path does not need a VF pool or Kata NAD |
| UI image pull errors | Ensure `ARGUS_GTC_SERVER_IMAGE` points to a registry the cluster can pull (image pull secret if private) |
| Agent actions disabled | Check `ARGUS_GTC_MODEL_BASE_URL`, `ARGUS_GTC_MODEL_NAME`, and `oc -n argus-gtc-demo rollout status deploy/argus-gtc-agent` |
| Kata agent Pending | Both demo pods require placement on one worker; inspect CPU/memory availability and `oc -n argus-gtc-demo describe pod -l app=argus-gtc-agent` |
| Agent does not call the tool | Use a tool-calling-compatible model and inspect its response. The UI reports no tool call without inferring a deliberate refusal; do not claim an attempted connection. |
| Canary has no `uid=` output | Confirm `argus-gtc-canary` is Ready, NodePort 31999 is allocated, and the agent ANP allows TCP/31999 to nodes. Check canary logs. |
| Shell connected but Argus did not show it | Guest process/socket events are not expected in the tenant no-VF mode because Argus cannot introspect inside those Kata guests. The UI does not mark this run as Argus observed without a matching native event. |
| Argus report tailing fails | Check the demo server logs and the `argus-gtc-hosted-reader` Role/RoleBinding in DPU HostedCluster `dpf-operator-system`; re-run the matching deploy target to refresh its token. |
| Executable Memory returns `no-native-event` | Confirm the Python action completed and held the mapping for 45 seconds. Inspect native Argus reports for `New Executable Anonymous Memory Mapped` on `invisible-vm` with the run marker; confirm the live memory collector is enabled. A process event by itself is insufficient. |
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
Infra / management         Tenant HostedCluster          DPU HostedCluster
───────────────────        ────────────────────          ─────────────────
UI Route + demo server     invisible-vm (Kata)           doca-argus pods
scoped management token   argus-gtc-agent (Kata)                  ↑
scoped tenant token        canary Service                       logs
       │                         │                            scoped token
       ├── tenant API ──────────>│
       ├── /generate ── HTTPS Route ──> authenticated agent gateway
       │                         ├── HTTPS/443 ──> OpenAI API
browser ── Route ──> UI          └── TCP/31999 ──> canary Service
       │                                  │
       └── Argus reader ── scoped DPU token ──> DPU HostedCluster

`make deploy-argus-gtc-demo-tenant` keeps the UI and Argus reader on
`ARGUS_GTC_DEMO_KUBECONFIG` (defaults to `KUBECONFIG`) and selects
`ZT_TENANT_KUBECONFIG` for Kata workloads. Argus observations use the DPU
HostedCluster.
```
