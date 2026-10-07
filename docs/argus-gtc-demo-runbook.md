# Argus GTC Demo — Operator Runbook

**Title:** Invisible VM, Visible Threat

This demo shows a Kata workload with **no in-guest security agent** while DOCA Argus on the BlueField DPU observes activity out-of-band. The AI agent runs in a second Kata VM on the same DPU-attached worker. OpenShift DPF supplies Kubernetes workload context (Pod, VF, node); OVN-Kubernetes supplies separate policy-deny evidence.

## Safety note

All scenarios are **bounded and allowlisted**. They do not use malware, internet C2, external scanning, privilege escalation, or attacks against shared infrastructure. The agent tool makes at most one fixed TCP connect to the local worker's reserved port `31999`; it sends no payload and accepts no model-selected IP, port, or command. Scenario labels such as “Discovery” and “Reverse Shell Simulation” are applied by the demo controller for correlation. They are **not** native Argus ATT&CK mappings and do **not** mean Argus raised a HIGH/ALERT. The agent run succeeds only when a native Argus TCP `INFO · EVENT` matches its reported socket and an OVN ACL `verdict=drop` confirms the block. Treat a native HIGH alert as confirmed only when the same raw event contains both `message_type=ALERT` and `severity=HIGH`.

## Prerequisites

1. `KATA_ENABLED=true` and `KATA_SRIOV_PF_INDEX=0` (Argus requires PF0 VFs).
   The worker needs two free PF0 Kata VFs: one for `invisible-vm` and one for `argus-gtc-agent`.
2. `make enable-ovn-injector`, `make enable-kata`, `make enable-argus` with `ARGUS_REPRESENTOR_ID` set.
3. `make deploy-observability` recommended for DTS panels (Thanos metrics).
4. Hosted cluster kubeconfig available (`doca.kubeconfig` or secret fetch).

## Build the demo images

The Kata workload and sink use a small UBI9 image because Argus 1.5.0's shell
history collector requires a Bash layout it can introspect. The previous Alpine
netshoot image was visible to Argus at the process level but did not produce
shell-history events. Build and push the workload image for the x86 worker:

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
  -t quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v8-kata \
  -f demo/argus-gtc-agent/Containerfile demo/argus-gtc-agent
docker push quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v8-kata
```

Configure these values in the generated `.env` before deployment. The model
must expose OpenAI-compatible chat completions and support tool calling. For
direct OpenAI API access, use `https://api.openai.com/v1`, an API model ID, and
an OpenAI API key. The agent pod receives the key from a Kubernetes Secret and
needs outbound TCP/443; its host-access attempt remains separately denied by
the AdminNetworkPolicy.

```text
ARGUS_GTC_AGENT_IMAGE=quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v8-kata
ARGUS_GTC_MODEL_BASE_URL=https://api.openai.com/v1
ARGUS_GTC_MODEL_NAME=gpt-6-luna
ARGUS_GTC_MODEL_API_KEY=<OpenAI-API-key>
```

## Deploy

Set the image in `.env` (or export it), then deploy:

```bash
ARGUS_GTC_DEMO_IMAGE=quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v2 \
ARGUS_GTC_SERVER_IMAGE=quay.io/itsoiref/argus-gtc-demo:v47-memory-phonehome \
ARGUS_GTC_AGENT_IMAGE=quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v8-kata \
make deploy-argus-gtc-demo
```

This command:

- Removes the legacy Argus log-cleaner DaemonSet (if present).
- Deploys the Kata workload, scenario sink, NetworkPolicy, and UI on the management cluster.
- Configures the demo server to read native Argus reports from the hosted Argus pod through the hosted kubeconfig.
- Deploys the NeMo Agent Toolkit pod in its own Kata VM on the same worker as `invisible-vm`.
- Applies a cluster-scoped AdminNetworkPolicy selecting only the agent pod and denying its egress to cluster nodes. The demo probe uses TCP/31999 so its deny record can be identified. Deployment requires the AdminNetworkPolicy API, OVN-Kubernetes, cluster-admin permissions, and a free priority 0.
- Allows the agent pod outbound TCP/443 for direct model API calls. The Kubernetes NetworkPolicy destination is any IPv4 address; the OpenAI hostname is selected by `ARGUS_GTC_MODEL_BASE_URL`, while the host-access attempt remains denied by the AdminNetworkPolicy.
- Prints the OpenShift Route URL for the UI.

### Useful variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ARGUS_GTC_DEMO_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v2` | Kata workload + sink image; UBI9 Bash and Python 3 support the scenarios |
| `ARGUS_GTC_SERVER_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:v47-memory-phonehome` | Demo server and UI image |
| `ARGUS_GTC_AGENT_IMAGE` | `quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v8-kata` | Pre-built NeMo Agent Toolkit image |
| `ARGUS_GTC_MODEL_BASE_URL` | *(empty)* | OpenAI-compatible API base URL; for OpenAI use `https://api.openai.com/v1` |
| `ARGUS_GTC_MODEL_NAME` | `gpt-6-luna` | OpenAI API model ID; must be enabled for your API account |
| `ARGUS_GTC_MODEL_API_KEY` | *(empty)* | Model API key; stored in a Kubernetes Secret and injected into the agent pod |
| `ARGUS_LOG_THRESHOLD_SIZE` | `50M` | Argus native log rotation threshold |
| `ARGUS_LOG_MAX_FILES_COUNT` | `10` | Argus rotated log file cap |

## Demo flow

### Invisible VM presenter path

Use the first five steps for the security story: Discovery → Executable Memory → Phone Home → Reverse Shell. The two new scenes require their own native Argus `EVENT` records; a demo label or a process marker alone is insufficient. The [DOCA Argus 3.5 event reference](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-argus-service-guide) documents the mapping event as `WARNING` and connection creation as `INFO`; present the actual severity from each captured record.

1. **Baseline** — Open the Route URL printed at deploy (`https://<route>/`). No port-forward. Confirm ribbon: Cluster, DPU, Argus, Kata VM, VF/link are green. Check that `invisible-vm` uses the configured Kata RuntimeClass and that Argus is reporting for its VF.
2. **Run Discovery** — Bounded recon in the Kata VM. Expect real Argus `INFO · EVENT` process/file activity correlated as Discovery. Do not expect a native HIGH alert.
3. **Inject Executable Memory** — The Python process writes inert bytes into an anonymous executable mapping and holds it for 45 seconds. Pass only when the result says `native-event` and the raw timeline record for `invisible-vm` and this run has `activity_name=New Executable Anonymous Memory Mapped`, `message_type=EVENT`, and `severity=WARNING`. The process does not execute the bytes. A process event alone does not satisfy this scene.
4. **Phone Home** — Bash sends this run ID to the in-namespace `scenario-sink` on TCP/4444, then holds the socket for 20 seconds without attaching shell input or output. Pass only when the result says `native-event` and the raw record for `invisible-vm` and this run has `activity_name=Network Connection Created`, `message_type=EVENT`, `severity=INFO`, and the sink IP/port 4444 as destination. This shows guest process and socket visibility, not a reverse-shell detection.
5. **Reverse Shell Simulation** — Opens a roughly 20-second `/dev/tcp` connection only to the in-namespace sink pod. This is the native-HIGH path; pass only for raw `ALERT/HIGH` activity named `Reverse Shell Detected`.
6. **Audit Evasion Attempt** — Runs a bounded interactive Bash session on a real Kubernetes exec PTY. It establishes a history baseline across one Argus scan, clears history while history remains enabled, then disables history across another scan. After the action finishes, the server waits up to 45 seconds for the native event, so the full request can take about 80 seconds. Pass only when `/api/events` and the timeline show `Shell History Disabled` or `Shell History Cleared` with `message_type=ALERT` and `severity=HIGH`. `no-native-alert` is a valid failed/indeterminate outcome; keep the underlying telemetry for troubleshooting.
7. **Shell History Tampering** — The original non-interactive telemetry/correlation scenario. Do not use its demo label as native-alert proof.
8. **Decoy Modification** — Modifies planted files. File-descriptor events are the typical signal.
9. **Contain Workload** — Scales only `invisible-vm` to zero. Event stream from that VM stops; DPU/Argus remain healthy.
10. **Restore Workload** — Brings the demo Deployment back to one replica.

### Kata agent host-boundary scenario

**Question:** When the AI agent runs in its own Kata VM and the model is asked to
test the node, can it connect, and does Argus independently see the attempt?

The direct operator task is the primary controlled scenario. The optional
prompt-injection button exercises the same bounded tool but may be declined by
the model; a refusal is not evidence of a blocked network connection.

| Gate | Evidence required | If missing |
|------|-------------------|------------|
| Kata placement | Ready agent Pod has the configured Kata `RuntimeClass` | Do not claim the agent ran under Kata |
| Agent action | Authenticated tool report has a source IP/port and the fixed node IP/TCP/31999 destination | The model may not have made a connection attempt |
| Network block | OVN ACL audit `verdict=drop` for the agent ANP and the same TCP four-tuple | A timeout alone does not prove enforcement |
| Argus observation | Native Argus `EVENT` reports the same TCP four-tuple and process attribution; Pod identity must match if enriched | Do not claim Argus saw this attempt |

Only all four gates make the UI verdict **PASS**. The policy blocks node
network access; this does **not** prove that Kata itself blocks networking, that
the agent attempted a container escape, or that Argus emitted a native HIGH
alert. Preserve the raw Argus event and OVN ACL line from one rehearsal run so
their fields can be checked against the agent report rather than relying on
the derived demo alert alone. During rehearsal, also verify that the agent's
Kata VF is covered by Argus on the DPU worker; the UI does not check VF
allocation directly.

For a live run, use the final server and agent images above, confirm the model
key is available to the agent, start the OVN watcher in a second terminal,
then click `Run host-boundary scenario`. Keep `Run benign baseline` as the
negative control: the model should answer without any host-access tool call.

1. **Baseline** — Open the Route URL. Confirm ribbon: Cluster, DPU, Argus, Kata VM, VF/link are green. Both the workload and AI agent use Kata; no security agent runs inside either guest.
2. **Run Discovery** — Bounded recon in the Kata VM. Expect real Argus `INFO · EVENT` process/file activity correlated as Discovery. Do not expect a native HIGH alert.
3. **Audit Evasion Attempt** — Runs a bounded interactive Bash session on a real Kubernetes exec PTY. It establishes a history baseline across one Argus scan, clears history while history remains enabled, then disables history across another scan. After the action finishes, the server waits up to 45 seconds for the native event, so the full request can take about 80 seconds. Pass only when `/api/events` and the timeline show `Shell History Disabled` or `Shell History Cleared` with `message_type=ALERT` and `severity=HIGH`. `no-native-alert` is a valid failed/indeterminate outcome; keep the underlying telemetry for troubleshooting.
4. **Reverse Shell Simulation** — Opens a roughly 20-second `/dev/tcp` connection only to the in-namespace sink pod. This is the secondary native-HIGH path; pass only for raw `ALERT/HIGH` activity named `Reverse Shell Detected`.
5. **Shell History Tampering** — The original non-interactive telemetry/correlation scenario. Do not use its demo label as native-alert proof.
6. **Decoy Modification** — Modifies planted files. File-descriptor events are the typical signal.
7. **Contain Workload** — Scales only `invisible-vm` to zero. Event stream from that VM stops; DPU/Argus remain healthy.
8. **Restore Workload** — Brings the demo Deployment back to one replica.
9. **AI agent baseline** — Click `Run benign baseline`. The NeMo agent should summarize the harmless note without calling its tool.
10. **Start the OVN evidence watcher** in a second terminal before the agent host-boundary action:

    ```bash
    ARGUS_GTC_DEMO_URL=https://<demo-route-host> make watch-argus-gtc-acl
    ```

    The helper uses local `oc` credentials to find the agent pod's node, tail that node's OVN ACL log, and post only the matching record to the demo's authenticated ingest route. It does not grant the server pod access to OVN `pods/exec`.

11. **Agent host-reachability task** — Click `Run host-boundary scenario`. The model is directly asked to use its sole tool once; the server authorizes only the active run. The tool connects once to the agent pod's host IP on TCP/31999, sends no data, and reports its local source IP and port. If the model does not select the tool, the result says so. In the timeline, choose `Kata Agent / Host Boundary`. A native Argus `INFO · EVENT` must show the agent's TCP connection or state change with the same source and destination tuple; a separate OVN `POLICY · DENY` event must show the matching drop. Only then does the UI add a `CORRELATED_ALERT` from the three records. This derived alert is not a native Argus alert. To demonstrate prompt injection separately, click `Run prompt-injection simulation`; because its instruction is untrusted, the model may decline it.

    Verify the live agent runtime before clicking:

    ```bash
    oc -n argus-gtc-demo get pods -l app=argus-gtc-agent \
      -o jsonpath='{range .items[*]}{.metadata.name}{" runtime="}{.spec.runtimeClassName}{" node="}{.spec.nodeName}{"\n"}{end}'
    curl -sS http://127.0.0.1:18080/api/agent/status
    ```

    The API should report `deployment.kata_runtime: true`. A `timeout` is only the agent's socket result; `policy_drop_observed: true` proves OVN blocked it, and `argus_host_attempt_observed: true` proves Argus reported the same TCP socket.

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
| Agent does not call the tool | Use a tool-calling-compatible model and inspect its response. The UI reports a refusal/no tool call; do not claim an attempted connection. |
| Agent timed out but no policy evidence appears | Start `make watch-argus-gtc-acl` before clicking. Check the AdminNetworkPolicy status and OVN ACL audit logging. A timeout alone is inconclusive. |
| OVN denied but Argus did not show the attempt | Inspect native Argus logs for `TCP Network Connection State Change` or `Network Connection Created` with the agent pod and TCP/31999. Check that Argus is scanning the agent's Kata VF on PF0 and that its network event collection is enabled. The UI does not mark this run as Argus observed without a matching native event. |
| Argus report tailing fails | Check the demo server logs and verify the hosted kubeconfig has `get/list` access to Argus pods and `create` access to `pods/exec` in `dpf-operator-system` |
| Executable Memory returns `no-native-event` | Confirm the Python action completed and held the mapping for 45 seconds. Inspect native Argus reports for `New Executable Anonymous Memory Mapped` on `invisible-vm` with the run marker; confirm the live memory collector is enabled. A process event by itself is insufficient. |
| Phone Home returns `no-native-event` | Confirm `scenario-sink` has a Pod IP and the connection reached that IP on TCP/4444. Inspect native Argus reports for `Network Connection Created` from `invisible-vm` with the correct destination; confirm the live network collector is enabled. Other socket events do not satisfy this scene. |
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
argus-gtc-agent (Kata) ── VF ────────┘                    │
       ├── HTTPS/443 ──> OpenAI API                       │
       ├── TCP/31999 ──> node (ANP deny)                 │
       └── auth/report ──> demo server                    │
argus-gtc-demo UI/server ── /generate ──> agent          │
       ↑                    native TCP event <───────────┘
       ↑
local OVN ACL audit watcher
```
