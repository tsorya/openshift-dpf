# GTC Argus Agent Demo — Goal and Validation

## What the demo shows

The primary story is a Kata workload with no in-guest security agent. DOCA Argus runs separately on the BlueField DPU and reports observed activity; OpenShift supplies workload identity. The scripted workload is `invisible-vm`.

The separate AI story uses `argus-gtc-agent`, an AI application running in its own Kata VM. “Agent” here means the application, not a security agent installed inside the guest. The authorized tool-use scene asks that application to open a bounded shell to the configured `argus-gtc-canary` Service on TCP/31999. The workflow also has a pasted-note example that currently asks the application to complete the note. Describe it as note-driven tool use, not as a prompt-injection result.

Keep these facts separate in the UI and when presenting:

1. An authenticated tool report establishes that the agent tool reported an attempt.
2. A matching canary response containing `uid=` confirms the bounded shell session.
3. A matching native Argus process/socket event establishes independent visibility.
4. A native alert exists only when the Argus record itself has the required `message_type` and `severity`, including `ALERT/HIGH` for a HIGH claim.
5. OVN policy evidence is separate. A timeout alone does not prove a policy deny.

The two stories use separate workloads and evidence. The scripted workload’s stop/restore action targets `invisible-vm`; the current UI does not claim that this action contains `argus-gtc-agent`.

## Presenter screen

The workload console is at `/`; the AI agent page is at `/agent`. The header links between them, and each URL opens with its own workload scope. Both show continuous native Argus activity and a persistent native Alerts panel. Choose a workload action or AI request to read **What happens**, **Why show it**, and **Watch for**; only its separate **Run** button starts it. The agent page summarizes the latest run across the authenticated tool report, listener proof, Argus observation, native alert, and OVN policy evidence. The last actual run stays identified when a different action is selected. A demo controller action marker is visually separate from native Argus records and excluded from their counts. Browser connection, collector source reads, and the most recent native source timestamp are independent health signals. **Inspect record** opens the original retained payload. The eight presenter workload descriptions are served from the [scenario catalog](demo/argus-gtc/server/scenario_catalog.py).

At presentation time, show activity before running Discovery, then follow related process/file records and a Reverse shell attempt without hiding unrelated activity in the selected scope. State whether Argus produced a matching native alert; a completed action can end with no alert. Stop/restore controls are shown only for `invisible-vm` and wait for observed pod state. The [presenter brief](docs/argus-gtc-demo-agent-brief.md) contains the short spoken path.

## Cluster access

The demo is in the `igal-cno` management cluster, namespace `argus-gtc-demo`. Use the bastion `nvd-srv-45` and its kubeconfig:

```bash
rssh nvd-srv-45.nvidia.eng.rdu2.dc.redhat.com
```

On the bastion:

```bash
KUBECONFIG=/root/jose/openshift-dpf/kubeconfig.igal-cno
oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo get pods -o wide
oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo get deployments
```

The demo API/UI is the OpenShift Route `argus-gtc-demo` (service `argus-gtc-demo:8080`). Open `https://<route-host>/` for workload security or `https://<route-host>/agent` for the AI agent page. Do **not** create a Route to `argus-gtc-agent`: that Service is ClusterIP-only so the unauthenticated NeMo `/generate` API and `open_demo_shell` stay off ingress. The UI server calls the agent over ClusterIP.

```bash
oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo get route argus-gtc-demo
```

A localhost port-forward is only a fallback when the Route certificate is untrusted in an embedded browser. It is not required for the demo.

## Historical cluster snapshot

The notes below are from an earlier read-only check. The check date was not recorded; re-check the cluster before relying on these values. This repository review did not exercise the deployed cluster.


At the last read-only check:

- Agent image: `quay.io/itsoiref/argus-gtc-agent:nat-1.8.0-v13-host-os-reachability`
- Demo server image: `quay.io/itsoiref/argus-gtc-demo:v31-host-os-reachability`
- Agent pod: uses RuntimeClass `kata-coldplug`, on worker `nvd-srv-27`
- Agent and demo server deployments were 1/1 available after recovery.
- `/api/agent/status` reported `model_configured: false`; `ARGUS_GTC_MODEL_BASE_URL` was absent from both deployments. The agent run endpoint therefore cannot call the model until the OpenAI-compatible base URL is configured. Keep the API key in the existing Secret; do not put it in this file or command history.
- A `scenario-sink` pod was listening on TCP/4444, but there was no Service for it. The agent egress NetworkPolicy did not allow TCP/4444. The host-access AdminNetworkPolicy allowed node TCP/6443 and denied other node egress.
- Argus event ingestion was live, but agent-specific native Argus correlation had not yet been demonstrated.

An earlier diagnostic used an oversized event query (`limit=5000`, `evidence_limit=500`) and caused the demo server pod to OOM-restart once. It recovered to 1/1 and ingestion resumed. Keep event queries small; the in-memory event buffer reset on that restart.

## Checks to run

### 1. Confirm the workloads and runtime

```bash
oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo get pods -o wide
oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo get deployments \
  -o custom-columns=NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image,READY:.status.readyReplicas
oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo get pod \
  -l app=argus-gtc-agent \
  -o jsonpath='{range .items[*]}{.metadata.name}{" runtime="}{.spec.runtimeClassName}{" node="}{.spec.nodeName}{"\n"}{end}'
```

### 2. Check agent and Argus readiness

```bash
ROUTE="https://$(oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo get route argus-gtc-demo -o jsonpath='{.spec.host}')"
curl -sS "$ROUTE/api/agent/status"
curl -sS "$ROUTE/api/status"
```

Before running an agent scenario, confirm `ready: true`, the expected Kata runtime, and `model_configured: true`. Configure the OpenAI-compatible base URL on the required deployments; keep credentials in the Kubernetes Secret.

### 3. Run one authorized demo-shell attempt

Use a fresh run ID and save the JSON response. This asks the deployed AI application to use its bounded demo-shell tool. It does not itself prove listener confirmation or Argus detection.

```bash
run_id=$(python3 -c 'import secrets; print(secrets.token_hex(6))')
curl -sS --max-time 180 "$ROUTE/api/agent-runs" \
  -H 'Content-Type: application/json' \
  -d "{\"profile\":\"host-reachability\",\"scenario_run_id\":\"$run_id\"}"
```

Inspect these response fields:

- `status`, `agent_response`, and `tool_result`: did the agent actually call the tool, and what did it attempt?
- `agent_pod`, `agent_pod_uid`, and `agent_runtime_class`: did the activity originate from the expected Kata agent pod?
- `argus_events_observed`, `argus_host_attempt_observed`, and `argus_host_attempt_event`: did native Argus telemetry match it?
- `policy_drop_observed` and `policy_evidence_source`: was there evidence of a network-policy drop?
- `correlated_alert`: did the UI have a native alert to show?

For the authorized shell request, `no-tool-call` means the requested tool action was not recorded; the baseline profile intentionally expects no shell-tool call. `authorization-unavailable` or `model_configured: false` indicate setup problems. None of these outcomes is Argus detection.

### 4. Inspect a small slice of the native event feed

Use the demo API and limit the query. Do not use a large `limit` or `evidence_limit`; the event buffer is in memory and a large response previously OOM-restarted the server.

```bash
curl -sS "$ROUTE/api/events?limit=1&evidence_limit=1"
```

For recent agent logs:

```bash
oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo \
  logs deployment/argus-gtc-agent --since=5m --tail=100
```

### 5. Evidence criteria

Report the outcomes separately:

- An authenticated tool report records the agent tool result and fixed configured destination.
- The canary listener’s matching `uid=` output confirms a working shell. A TCP connection without listener output is not enough.
- A matching native Argus event confirms independent observation. Show its actual activity, type, severity, workload, and run identity.
- A native HIGH alert requires the matching raw record to contain `message_type=ALERT` and `severity=HIGH`. Do not infer it from the agent response or a process/socket event.
- A matching OVN ACL audit record is policy evidence. A timeout alone is inconclusive.

If evidence is missing, keep that fact visible and narrow the claim accordingly.

## Implementation boundary

Keep the target fixed to a demo-owned canary listener, bound the run duration, and scope any network allowance to the agent pod and that listener only. Do not disable the namespace's broad egress policy. Build container images on the laptop and push them to Quay; use the bastion only for cluster access and deployment. Avoid changes to the DPU or hosted cluster for this scenario.

The Reverse Shell Simulation is a separate controller-triggered scenario in `invisible-vm`; it does not prove the AI application initiated an action. Keep its run identity and evidence separate from the `argus-gtc-agent` story.
