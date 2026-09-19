# Argus GTC Demo — Operator Runbook

**Title:** Invisible VM, Visible Threat

This demo shows a Kata workload with **no in-guest security agent** while DOCA Argus on the BlueField DPU observes activity out-of-band. OpenShift DPF supplies Kubernetes workload context (Pod, VF, node) and DTS link health.

## Safety note

All scenarios are **bounded and allowlisted**. They do not use malware, internet C2, external scanning, privilege escalation, or attacks against shared infrastructure. Scenario labels such as “Discovery” are applied by the demo controller and are **not** native Argus ATT&CK mappings.

## Prerequisites

1. `KATA_ENABLED=true` and `KATA_SRIOV_PF_INDEX=0` (Argus requires PF0 VFs).
2. `make enable-ovn-injector`, `make enable-kata`, `make enable-argus` with `ARGUS_REPRESENTOR_ID` set.
3. `make deploy-observability` recommended for DTS panels (Thanos metrics).
4. Hosted cluster kubeconfig available (`doca.kubeconfig` or secret fetch).

## Deploy

```bash
make deploy-argus-gtc-demo
```

This command:

- Removes the legacy Argus log-cleaner DaemonSet (if present).
- Builds and pushes the demo server image to the cluster integrated registry (override with `ARGUS_GTC_BUILD_IMAGE=false` / `ARGUS_GTC_PUSH_IMAGE=false`).
- Deploys the Kata workload, scenario sink, NetworkPolicy, and UI on the management cluster.
- Deploys a read-only log collector DaemonSet on the hosted cluster.
- Prints the OpenShift Route URL for the UI.

### Useful variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ARGUS_GTC_DEMO_IMAGE` | `nicolaka-netshoot:v0.13` | Digest-pinned Kata workload image |
| `ARGUS_GTC_SERVER_IMAGE` | `argus-gtc-demo:local` | Demo server/collector image |
| `ARGUS_LOG_THRESHOLD_SIZE` | `50M` | Argus native log rotation threshold |
| `ARGUS_LOG_MAX_FILES_COUNT` | `10` | Argus rotated log file cap |

## Demo flow

1. **Baseline** — Open the Route URL. Confirm ribbon: Cluster, DPU, Argus, Kata VM, VF/link are green. Note “no agent in guest.”
2. **Run Discovery** — Populates process/file timeline with real Argus events.
3. **Reverse Shell Simulation** — Short-lived `/dev/tcp` connection to the in-namespace sink pod. Expect Argus `Reverse Shell Detected` (HIGH).
4. **Shell History Tampering** — Triggers `Shell History Disabled` / `Shell History Cleared` alerts.
5. **Decoy Modification** — Modifies planted files; expect file-descriptor content-change alerts.
6. **Contain Workload** — Scales only `invisible-vm` to zero. Event stream stops; DPU/Argus remain healthy.
7. **Restore Workload** — Brings the demo Deployment back to one replica.

## Cleanup

```bash
make cleanup-argus-gtc-demo
```

Removes only `argus-gtc-demo` namespace resources on management and hosted clusters. Argus, DPU services, and Kata infrastructure are untouched.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No Argus events in UI | Argus pods Running on hosted cluster; logs under `/var/log/doca_argus_activity_report/`; log-cleaner absent |
| Argus status Pending | `KUBECONFIG=doca.kubeconfig oc get pods -n dpf-operator-system \| grep argus` |
| Workload Pending | Kata VF pool on PF0; NAD/injector applied |
| UI image pull errors | Set `ARGUS_GTC_SERVER_IMAGE` to a registry the cluster can reach |
| Collector not forwarding | Hosted→management Route reachability; server still tails Argus pods via hosted kubeconfig fallback |

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
invisible-vm (Kata)              doca-argus pods
       │                                │
       └──────── VF / BlueField ────────┘
argus-gtc-demo (UI + scenarios)  argus-gtc-collector (read-only hostPath)
```
