# Argus GTC Demo — Agent Handoff Brief

## Objective

Build a polished GTC demonstration titled **“Invisible VM, Visible Threat.”**
The story is that a Kata workload has no in-guest security agent, but the
BlueField DPU observes it out-of-band through DOCA Argus and OpenShift/DPF
provides the workload and infrastructure context.

The demo must be safe, deterministic, repeatable, and visually compelling.
Do not use real malware, internet C2, external scanning, privilege
escalation, or attacks against shared infrastructure.

## Current repository state

- Argus is installed by `scripts/enable-argus.sh` as a DPUService.
- Argus configuration is in `manifests/argus/03-configuration.yaml`.
- Kata SR-IOV VFs must be carved from PF0 for Argus.
- The kata pool is now always regenerated and force-applied from the current
  environment by `scripts/enable-kata.sh`.
- Argus output currently lands on the DPU host under:
  - `/var/log/doca_argus_activity_report/`
  - `/var/log/doca_argus/`
- There is currently no Argus HTTP API, ServiceMonitor, event collector, or
  dashboard in this repository.
- The current `manifests/argus/04-log-cleaner.yaml` deletes Argus logs every
  five minutes. This must be removed or replaced with bounded retention before
  the demo; it would erase evidence during a presentation.

## Recommended architecture

Create a small read-only demo stack:

1. **Argus collector**
   - Run on the hosted/DPU cluster with read-only access to Argus report files,
     or consume Argus JSON telemetry through Vector/Fluent Bit.
   - Parse the documented common fields:
     `message_type`, `severity`, `occurred_message_time_iso_8601_ns`,
     `workload_information`, `container_context`, and `activity_data`.
   - Publish normalized events over SSE or WebSocket for the UI.

2. **Kubernetes status adapter**
   - Watch DPUDeployment/DPUService readiness.
   - Watch the demo Pod's Kata runtime, DPU connection annotations, node, and
     VF/resource identity.
   - Expose a read-only status endpoint to the UI.

3. **DPU health adapter**
   - Query the existing Thanos/Prometheus DTS metrics for link speed/width,
     packets, bytes, errors, and drops.
   - Keep infrastructure health visible while the workload is contained.

4. **Static UI**
   - Top status ribbon: Cluster, DPU, Argus, Kata VM, VF/link.
   - Center topology: `Pod → Kata VM → VF → BlueField → Argus`.
   - Live event timeline with severity, activity, process, pod, node, and
     scenario label.
   - DTS sparklines for traffic/errors.
   - Three allowlisted actions only: `Run Discovery`, `Run Compute Simulation`,
     and `Contain Workload`.

## Demo flow

### 1. Healthy baseline

- Start a purpose-built, digest-pinned Kata demo image.
- Show the workload Ready, Kata runtime active, PF0 VF allocated, Argus Ready,
  and DPU link/traffic healthy.
- Make the “no agent in the guest” point explicit.

### 2. Safe, bounded scenarios

The scenario controller must accept scenario IDs, never arbitrary shell input.
Each scenario runs only in a dedicated namespace and has a NetworkPolicy that
allows traffic only to a local sink pod.

- **Discovery:** run bounded `id`, `uname`, `ps`, and reads of planted decoy
  files. Use this to populate the process/file timeline.
- **Reverse-shell simulation:** create a short-lived connection from the demo
  workload to the dedicated sink pod. Argus 3.5 documents `Reverse Shell
  Detected` as a HIGH alert.
- **Shell-history tampering:** run the pre-scripted history-disable/clear
  scenario. Argus documents both as HIGH alerts.
- **Decoy modification:** modify a planted file and show the file-descriptor
  content-change alert.
- **Optional network burst:** send bounded data only to the sink pod to exercise
  the excessive-data alert.

Do not claim ATT&CK mappings are native Argus output; apply any demo labels in
the controller and label them as demo-side classifications.

### 3. Correlation and containment

- Correlate Argus events with Pod/VF identity and DTS traffic.
- Click `Contain Workload` to scale only the demo Deployment to zero.
- Show the process/event stream stop, the VF return to the pool, and DPU
  services/link health remain green.

## Important implementation constraints

- Preserve Argus event files long enough for UI history and audit review.
  Prefer Argus's native `log_threshold_size` and `log_max_files_count` or
  documented logrotate behavior over recursive deletion.
- Wait for Argus container readiness and successful service/host
  initialization before showing a green status.
- Use a pinned demo image; do not use `latest`.
- Keep all routes private/authenticated for the demo cluster.
- Use read-only mounts and least-privilege RBAC for the collector.
- Add a reset action or documented cleanup that removes only demo resources.
- Capture real Argus report samples and measure detection latency before
  finalizing the UI. Do not fabricate event fields or detection semantics.

## Acceptance criteria

- A single command deploys the demo stack and a single command cleans up only
  demo resources.
- The UI shows Kubernetes readiness, Argus freshness, VF identity, and DTS
  health in one view.
- At least two bounded scenarios produce real Argus events visible in the UI.
- Containment scales down only the demo workload and leaves DPU services
  healthy.
- No event deletion occurs during the demo window.
- The implementation includes a short operator runbook and a safety note.

## Authoritative reference

Use the DOCA Argus version matching the deployed image. For the current
`1.5.0-doca3.5.0` image, consult the [DOCA Argus 3.5 Service Guide](https://docs.nvidia.com/doca/sdk/DOCA-Argus-Service-Guide/index.html),
especially the output/logging, message schema, and alerts sections.
