# Argus GTC Demo — Operator Runbook

**Title:** Invisible VM, Visible Threat

This demo shows a Kata workload with **no in-guest security agent** while DOCA Argus on the BlueField DPU observes activity out-of-band. An additional AI agent runs in its own runc pod on the same DPU-attached worker. OpenShift DPF supplies Kubernetes workload context (Pod, VF, node); OVN-Kubernetes supplies separate policy-deny evidence.

## Safety note

All scenarios are **bounded and allowlisted**. They do not use malware, internet C2, external scanning, privilege escalation, or attacks against shared infrastructure. The new agent tool makes at most one fixed TCP connect to the local worker's reserved port `31999`; it sends no payload and accepts no model-selected IP, port, or command. Scenario labels such as “Discovery” and “Reverse Shell Simulation” are applied by the demo controller for correlation. They are **not** native Argus ATT&CK mappings and do **not** mean Argus raised a HIGH/ALERT. Argus may show the agent's process/TCP activity as `INFO · EVENT`; it does not emit the OVN policy verdict. The timeline labels an OVN ACL `verdict=drop` separately. Treat a native HIGH alert as confirmed only when the same raw event contains both `message_type=ALERT` and `severity=HIGH`.

## Prerequisites

1. `KATA_ENABLED=true` and `KATA_SRIOV_PF_INDEX=0` (Argus requires PF0 VFs).
2. `make enable-ovn-injector`, `make enable-kata`, `make enable-argus` with `ARGUS_REPRESENTOR_ID` set.
3. `make deploy-observability` recommended for DTS panels (Thanos metrics).
4. Hosted cluster kubeconfig available (`doca.kubeconfig` or secret fetch).

## Build the demo images

The Kata workload and sink use a small UBI9 image because Argus 1.5.0's shell
history collector requires a Bash layout it can introspect. The previous Alpine
netshoot image was visible to Argus at the process level but did not produce
shell-history events. Build and push the workload image for the x86 worker:

```bash
podman build --platform linux/amd64 \
  -t quay.io/<user>/argus-gtc-demo:workload-ubi9-v1 \
  -f demo/argus-gtc-workload/Containerfile demo/argus-gtc-workload
podman push quay.io/<user>/argus-gtc-demo:workload-ubi9-v1
```

Build and push the demo server from the repository root, then set
`ARGUS_GTC_SERVER_IMAGE` in `.env`:

```bash
# example — use your registry and tag
podman build --platform linux/amd64 \
  -t quay.io/<user>/argus-gtc-demo:v1 \
  -f demo/argus-gtc/Containerfile demo/argus-gtc
podman push quay.io/<user>/argus-gtc-demo:v1
```

The server image contains Python 3.11, `requirements.txt`, and the `server/` +
`static/` directories. The audit-evasion implementation uses
`timeout --foreground` so the bounded timeout preserves the interactive PTY.

Build and push the separate NeMo Agent Toolkit pod image:

```bash
podman build --platform linux/amd64 \
  -t quay.io/<user>/argus-gtc-agent:nat-1.8.0-v1 \
  -f demo/argus-gtc-agent/Containerfile demo/argus-gtc-agent
podman push quay.io/<user>/argus-gtc-agent:nat-1.8.0-v1
```

Configure these values in the generated `.env` before deployment. The model
must expose OpenAI-compatible chat completions and support tool calling. The
server pod must be able to reach its base URL; the agent pod itself can reach
only the demo server and cluster DNS.

```text
ARGUS_GTC_AGENT_IMAGE=quay.io/<user>/argus-gtc-agent:nat-1.8.0-v2
ARGUS_GTC_MODEL_BASE_URL=http://<model-host>:8080/v1
ARGUS_GTC_MODEL_NAME=<tool-capable-model-name>
ARGUS_GTC_MODEL_API_KEY=<optional-key>
```

## Deploy

Set the image in `.env` (or export it), then deploy:

```bash
ARGUS_GTC_SERVER_IMAGE=quay.io/<user>/argus-gtc-demo:v1 make deploy-argus-gtc-demo
```

This command:

- Removes the legacy Argus log-cleaner DaemonSet (if present).
- Deploys the Kata workload, scenario sink, NetworkPolicy, and UI on the management cluster.
- Configures the demo server to read native Argus reports from the hosted Argus pod through the hosted kubeconfig.
- Deploys the separate NeMo Agent Toolkit pod on the same worker as `invisible-vm`.
- Applies a cluster-scoped AdminNetworkPolicy selecting only the agent pod and denying its TCP/31999 egress to cluster nodes. Deployment requires the AdminNetworkPolicy API, OVN-Kubernetes, cluster-admin permissions, and a free priority 0.
- Prints the OpenShift Route URL for the UI.

### Useful variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ARGUS_GTC_DEMO_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v1` | Kata workload + sink image; UBI9/glibc Bash is required for native shell-history alerts |
| `ARGUS_GTC_SERVER_IMAGE` | *(required)* | Pre-built demo server image |
| `ARGUS_GTC_AGENT_IMAGE` | `quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v2` | Pre-built NeMo Agent Toolkit image |
| `ARGUS_GTC_MODEL_BASE_URL` | *(empty)* | OpenAI-compatible API base URL, such as `http://model-host:8080/v1` |
| `ARGUS_GTC_MODEL_NAME` | *(empty)* | Tool-calling model name served by the endpoint |
| `ARGUS_GTC_MODEL_API_KEY` | *(empty)* | Optional model API key; stored in a Kubernetes Secret |
| `ARGUS_LOG_THRESHOLD_SIZE` | `50M` | Argus native log rotation threshold |
| `ARGUS_LOG_MAX_FILES_COUNT` | `10` | Argus rotated log file cap |

## Demo flow

1. **Baseline** — Open the Route URL. Confirm ribbon: Cluster, DPU, Argus, Kata VM, VF/link are green. Note “no security agent in the Kata guest”; the AI agent is a separate pod.
2. **Run Discovery** — Bounded recon in the Kata VM. Expect real Argus `INFO · EVENT` process/file activity correlated as Discovery. Do not expect a native HIGH alert.
3. **Audit Evasion Attempt** — Runs a bounded interactive Bash session on a real Kubernetes exec PTY. It establishes a history baseline across one Argus scan, clears history while history remains enabled, then disables history across another scan. After the action finishes, the server waits up to 45 seconds for the native event, so the full request can take about 80 seconds. Pass only when `/api/events` and the timeline show `Shell History Disabled` or `Shell History Cleared` with `message_type=ALERT` and `severity=HIGH`. `no-native-alert` is a valid failed/indeterminate outcome; keep the underlying telemetry for troubleshooting.
4. **Reverse Shell Simulation** — Opens a roughly 20-second `/dev/tcp` connection only to the in-namespace sink pod. This is the secondary native-HIGH path; pass only for raw `ALERT/HIGH` activity named `Reverse Shell Detected`.
5. **Shell History Tampering** — The original non-interactive telemetry/correlation scenario. Do not use its demo label as native-alert proof.
6. **Decoy Modification** — Modifies planted files. File-descriptor events are the typical signal.
7. **Contain Workload** — Scales only `invisible-vm` to zero. Event stream from that VM stops; DPU/Argus remain healthy.
8. **Restore Workload** — Brings the demo Deployment back to one replica.
9. **AI agent baseline** — Click `Run benign baseline`. The NeMo agent should summarize the harmless note without calling its tool.
10. **Start the OVN evidence watcher** in a second terminal before the prompt-injection action:

    ```bash
    ARGUS_GTC_DEMO_URL=https://<demo-route-host> make watch-argus-gtc-acl
    ```

    The helper uses local `oc` credentials to find the agent pod's node, tail that node's OVN ACL log, and post only the matching record to the demo's authenticated ingest route. It does not grant the server pod access to OVN `pods/exec`.

11. **Prompt-injection simulation** — Click `Run prompt-injection simulation`. The untrusted note may cause the agent to select its sole tool. The tool connects once to the agent pod's host IP on TCP/31999 and sends no data. If the model refuses or does not select the tool, the result says so; it does not simulate a successful call. In the timeline, choose `Prompt Injection / Host Access`: any Argus records are labeled as Argus telemetry, and an actual OVN `POLICY · DENY` event is labeled as OVN ACL audit evidence. When the authenticated tool report says the connect timed out and the watcher supplies the matching OVN drop, the UI adds a `CORRELATED_ALERT` derived from those two signals. It is not a native Argus alert. A timeout without the ACL record is not presented as a verified block.

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
| Agent does not call the tool | Use a tool-calling-compatible model and inspect its response. The UI reports a refusal/no tool call; do not claim an attempted connection. |
| Agent timed out but no policy evidence appears | Start `make watch-argus-gtc-acl` before clicking. Check the AdminNetworkPolicy status and OVN ACL audit logging. A timeout alone is inconclusive. |
| Argus report tailing fails | Check the demo server logs and verify the hosted kubeconfig has `get/list` access to Argus pods and `create` access to `pods/exec` in `dpf-operator-system` |
| Audit Evasion returns `no-native-alert` | Confirm the live Argus config has `shell_command.disable_scan=false`, `shell_history_cleared=true`, and `shell_history_disabled=true`; inspect `/var/log/doca_argus/` for profile or collection failures. A correlated `Executable Permissions Removed` MEDIUM alert does not satisfy this scenario. |

## Measuring detection latency

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
       │                            │                         │
       └── same worker ──> Argus activity reports ────────────┤
argus-gtc-agent (runc) ── TCP/31999 ──> node                  │
       │                            │                         │
       │                    AdminNetworkPolicy                │
       │                            │                         │
       └── model proxy <── argus-gtc-demo UI/server <──────────┘
                                ↑
                     local OVN ACL audit watcher
```
