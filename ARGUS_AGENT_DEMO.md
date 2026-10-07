# GTC Argus Agent Demo — Goal and Validation

## What the demo should show

An attacker-controlled instruction steers the real NeMo Agent Toolkit agent to initiate a bounded connection from its Kata workload to a controlled in-cluster canary. DOCA Argus, running out of band on the DPU service plane, reports the agent process and its socket activity. The demo UI ties the agent run to the native Argus evidence.

The evidence chain should be visible and independently verifiable:

1. The agent receives the attacker-controlled instruction.
2. The agent makes a tool call from its own Kata pod.
3. The tool produces a real connection attempt to the configured demo target.
4. Argus reports a matching native event for the workload process or socket.
5. The UI shows the run ID, agent pod, connection result, raw Argus event, and alert severity.

The claim is detection and workload visibility. A TCP connection by itself does not prove host command execution, a Kata escape, or containment. If the demo uses an interactive shell channel, any commands run through it execute in the agent workload context.

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

The demo API/UI is the OpenShift Route `argus-gtc-demo` (service `argus-gtc-demo:8080`). Open `https://<route-host>/` in a browser. Do **not** create a Route to `argus-gtc-agent`: that Service is ClusterIP-only so the unauthenticated NeMo `/generate` API and `open_demo_shell` stay off ingress. The UI server calls the agent over ClusterIP.

```bash
oc --kubeconfig="$KUBECONFIG" -n argus-gtc-demo get route argus-gtc-demo
```

A localhost port-forward is only a fallback when the Route certificate is untrusted in an embedded browser. It is not required for the demo.

## Current observed state

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

### 3. Run one host-reachability attempt

Use a fresh run ID and save the JSON response. This asks the deployed agent workflow to run its bounded host-reachability scenario; it does not itself prove Argus detection.

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

Treat `no-tool-call`, `authorization-unavailable`, or `model_configured: false` as an unsuccessful test setup, not as Argus detection.

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

### 5. Success criteria

Call the demo successful only when all of these are true:

- The deployed model-backed agent made the intended tool call from its Kata pod.
- The connection result came from the configured demo target, with the scenario run ID recorded.
- Raw Argus telemetry identifies matching workload process/socket activity.
- The UI shows that native event and its real severity; do not synthesize an Argus alert from the agent response.

If the connection is denied, report the actual policy evidence. If the event feed has no matching native event, the Argus-detection claim has not been validated.

## Implementation boundary

Keep the target fixed to a demo-owned canary listener, bound the run duration, and scope any network allowance to the agent pod and that listener only. Do not disable the namespace's broad egress policy. Build container images on the laptop and push them to Quay; use the bastion only for cluster access and deployment. Avoid changes to the DPU or hosted cluster for this scenario.

The current Reverse Shell Simulation button is a separate controller-triggered scenario in `invisible-vm`; it does not prove the AI agent initiated the action. The requested agent-originated flow must show the agent tool call and the resulting pod process/socket in native Argus telemetry.
