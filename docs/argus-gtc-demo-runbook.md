# Argus GTC Demo — Operator Runbook

**Title:** Invisible VM, Visible Threat

This demo shows a Kata workload with **no in-guest security agent** while DOCA Argus on the BlueField DPU observes activity out-of-band. OpenShift DPF supplies Kubernetes workload context (Pod, VF, node) and DTS link health.

## Safety note

All scenarios are **bounded and allowlisted**. They do not use malware, internet C2, external scanning, privilege escalation, or attacks against shared infrastructure. Scenario labels such as “Discovery” and “Reverse Shell Simulation” are applied by the demo controller for correlation. They are **not** native Argus ATT&CK mappings and do **not** mean Argus raised a HIGH/ALERT. Live feeds in this environment have been mostly `INFO · EVENT` (TCP, files, processes). Treat a native HIGH alert as confirmed only when the same raw event contains both `message_type=ALERT` and `severity=HIGH`.

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

## Deploy

Set the image in `.env` (or export it), then deploy:

```bash
ARGUS_GTC_SERVER_IMAGE=quay.io/<user>/argus-gtc-demo:v1 make deploy-argus-gtc-demo
```

This command:

- Removes the legacy Argus log-cleaner DaemonSet (if present).
- Deploys the Kata workload, scenario sink, NetworkPolicy, and UI on the management cluster.
- Deploys a read-only log collector DaemonSet on the hosted cluster.
- Prints the OpenShift Route URL for the UI.

### Useful variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ARGUS_GTC_DEMO_IMAGE` | `quay.io/itsoiref/argus-gtc-demo:workload-ubi9-v1` | Kata workload + sink image; UBI9/glibc Bash is required for native shell-history alerts |
| `ARGUS_GTC_SERVER_IMAGE` | *(required)* | Pre-built demo server/collector image |
| `ARGUS_LOG_THRESHOLD_SIZE` | `50M` | Argus native log rotation threshold |
| `ARGUS_LOG_MAX_FILES_COUNT` | `10` | Argus rotated log file cap |

## Demo flow

1. **Baseline** — Open the Route URL. Confirm ribbon: Cluster, DPU, Argus, Kata VM, VF/link are green. Note “no agent in guest.”
2. **Run Discovery** — Bounded recon in the Kata VM. Expect real Argus `INFO · EVENT` process/file activity correlated as Discovery. Do not expect a native HIGH alert.
3. **Audit Evasion Attempt** — Runs a bounded interactive Bash session on a real Kubernetes exec PTY. It establishes a history baseline across one Argus scan, clears history while history remains enabled, then disables history across another scan. After the action finishes, the server waits up to 45 seconds for the native event, so the full request can take about 80 seconds. Pass only when `/api/events` and the timeline show `Shell History Disabled` or `Shell History Cleared` with `message_type=ALERT` and `severity=HIGH`. `no-native-alert` is a valid failed/indeterminate outcome; keep the underlying telemetry for troubleshooting.
4. **Reverse Shell Simulation** — Opens a roughly 20-second `/dev/tcp` connection only to the in-namespace sink pod. This is the secondary native-HIGH path; pass only for raw `ALERT/HIGH` activity named `Reverse Shell Detected`.
5. **Shell History Tampering** — The original non-interactive telemetry/correlation scenario. Do not use its demo label as native-alert proof.
6. **Decoy Modification** — Modifies planted files. File-descriptor events are the typical signal.
7. **Contain Workload** — Scales only `invisible-vm` to zero. Event stream from that VM stops; DPU/Argus remain healthy.
8. **Restore Workload** — Brings the demo Deployment back to one replica.

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
| DPU status Degraded | Open `/api/status` and inspect `details.dpu`. A `403` means re-apply demo RBAC (`make deploy-argus-gtc-demo`). If `ready: false` with conditions, check `oc get dpudeployment dpudeployment -n dpf-operator-system` |
| Workload Pending | Kata VF pool on PF0; NAD/injector applied |
| UI image pull errors | Ensure `ARGUS_GTC_SERVER_IMAGE` points to a registry the cluster can pull (image pull secret if private) |
| Collector not forwarding | Hosted→management Route reachability; server still tails Argus pods via hosted kubeconfig fallback |
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
invisible-vm (Kata)              doca-argus pods
       │                                │
       └──────── VF / BlueField ────────┘
argus-gtc-demo (UI + scenarios)  argus-gtc-collector (read-only hostPath)
```
