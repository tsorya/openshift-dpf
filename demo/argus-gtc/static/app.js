const timeline = document.getElementById("timeline");
const actionLog = document.getElementById("action-log");
const metricGrid = document.getElementById("metric-grid");
const eventCountEl = document.getElementById("event-count");
const timelineFilter = document.getElementById("timeline-filter");
const severityFilter = document.getElementById("severity-filter");
const messageTypeFilter = document.getElementById("message-type-filter");
const pauseBtn = document.getElementById("pause-timeline");
const timelineState = document.getElementById("timeline-state");
const timelineStory = document.getElementById("timeline-story");
const timelinePin = document.getElementById("timeline-pin");
const eventDialog = document.getElementById("event-dialog");
const eventDialogTitle = document.getElementById("event-dialog-title");
const eventDialogMeta = document.getElementById("event-dialog-meta");
const eventDialogJson = document.getElementById("event-dialog-json");
const eventCopyStatus = document.getElementById("event-copy-status");
const copyEventJsonBtn = document.getElementById("copy-event-json");
let selectedEventJson = "";
let eventDialogTrigger = null;

const MAX_VISIBLE_EVENTS = 120;
const MAX_BUFFERED_EVENTS = 2000;
const MAX_EVIDENCE_EVENTS = 500;
const MAX_QUEUED_EVENTS = 5000;
const MAX_DIALOG_JSON_CHARS = 512 * 1024;
// Full Argus records include workload/network metadata. Keep the initial route
// response small enough for the OpenShift router; the SSE stream continues to
// deliver new records and the server retains the larger history.
const HISTORY_LIMIT = 100;
const HISTORY_EVIDENCE_LIMIT = 100;
const FLUSH_INTERVAL_MS = 400;
const CLICK_WINDOW_MS = 60000;
const CLICK_WINDOW_NOISE = new Set([
  "File Descriptor Open",
  "File Descriptor Close",
  "File Unmapped",
  "Thread Created",
]);

const SCENARIO_SIGNATURES = {
  "audit-evasion": ["argus-gtc-audit_evasion", "argus-gtc-audit-evasion", "argus-demo-before-clear"],
  discovery: ["argus-gtc-discovery", "uname", "decoys", "credentials.txt", "runbook.txt", "ps aux", "argus-gtc-discovery-uname", "argus-gtc-discovery-decoys"],
  "reverse-shell": ["argus-gtc-reverse_shell", "argus-gtc-reverse-shell", "/dev/tcp/", "bash -i"],
  "shell-history": ["argus-gtc-shell_history", "argus-gtc-shell-history", "histfile", "history -c"],
  "decoy-modify": ["argus-gtc-decoy_modify", "argus-gtc-decoy-modify", "tampered-by-demo"],
  "network-burst": ["argus-gtc-network_burst", "argus-gtc-network-burst", "/dev/zero", "nc -w"],
  "compute-simulation": ["argus-gtc-compute_simulation", "argus-gtc-compute-simulation", "compute-done"],
};

const SCENARIO_LABELS = {
  "audit-evasion": "Audit Evasion Attempt (demo correlation)",
  discovery: "Discovery (demo classification)",
  "reverse-shell": "Reverse Shell Simulation (demo classification)",
  "shell-history": "Shell History Tampering (demo classification)",
  "decoy-modify": "Decoy File Modification (demo classification)",
  "network-burst": "Network Burst (demo classification)",
  "compute-simulation": "Compute Simulation (demo classification)",
};

const SCENARIO_POD_PREFIXES = {
  "audit-evasion": ["invisible-vm"],
  discovery: ["invisible-vm"],
  "compute-simulation": ["invisible-vm"],
  "shell-history": ["invisible-vm"],
  "decoy-modify": ["invisible-vm"],
  "reverse-shell": ["invisible-vm", "scenario-sink"],
  "network-burst": ["invisible-vm", "scenario-sink"],
};
const DEMO_POD_PREFIXES = ["invisible-vm", "scenario-sink"];
const SCENARIO_NATIVE_ALERTS = {
  "audit-evasion": ["Shell History Disabled", "Shell History Cleared"],
  "reverse-shell": ["Reverse Shell Detected"],
};

let eventQueue = [];
let allEvents = [];
let evidenceEvents = [];
let knownEventIds = new Set();
let evidenceEventIds = new Set();
let pinnedScenarioEventIds = new Map();
let serverRetention = null;
let droppedQueuedEvents = 0;
let flushTimer = null;
let timelinePaused = false;
let lastClickAt = 0;
let lastClickScenario = null;
let activeScenarioRunId = null;
let scenarioRunBaselineIds = new Set();

function pillClass(value) {
  if (!value) return "";
  const v = String(value).toLowerCase();
  if (["ready", "live", "allocated", "ok", "contained"].includes(v)) return "ok";
  if (["pending", "unknown", "degraded"].includes(v)) return "warn";
  if (["absent", "error", "failed"].includes(v)) return "bad";
  return "";
}

function updateRibbon(status) {
  document.querySelectorAll(".pill").forEach((pill) => {
    const key = pill.dataset.key;
    const value = status[key] || "—";
    pill.querySelector("strong").textContent = value;
    pill.className = `pill ${pillClass(value)}`;
  });

  const pod = status.details?.pod;
  document.getElementById("pod-name").textContent = pod?.name || "—";
  document.getElementById("runtime-class").textContent = pod?.runtime_class || "—";
  document.getElementById("vf-state").textContent = (pod?.resource_requests || []).join(", ") || "—";
  document.getElementById("dpu-node").textContent = pod?.node || "—";
  const argus = status.details?.argus;
  document.getElementById("argus-pods").textContent = argus ? `${argus.running}/${argus.total} ready` : "—";
  updateCoverage(status.details?.coverage);
}

function fillList(id, items) {
  const el = document.getElementById(id);
  if (!el) return;
  el.replaceChildren();
  (items || []).forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    el.appendChild(li);
  });
}

function updateCoverage(coverage) {
  if (!coverage) return;
  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value || "—";
  };
  setText("coverage-scope", coverage.scope);
  setText("coverage-node", coverage.worker_node);
  setText(
    "coverage-scan",
    coverage.auto_scan === true ? "on (host + VMs)" : coverage.auto_scan === false ? "off" : "—"
  );
  setText("coverage-representor", coverage.representor_id);
  const kataBits = [];
  if (coverage.kata_runtime_class) kataBits.push(coverage.kata_runtime_class);
  kataBits.push(coverage.kata_pf0_only ? "PF0 VFs only" : "PF unknown");
  kataBits.push(coverage.guest_agent ? "guest agent" : "no in-guest agent");
  setText("coverage-kata", kataBits.join(" · "));

  const demoItems = (coverage.demo_workloads || []).map((w) => {
    const runtime = w.runtime && w.runtime !== "runc" ? `Kata (${w.runtime})` : "runc";
    return `${w.name} · ${runtime}`;
  });
  fillList(
    "coverage-demo",
    demoItems.length ? demoItems : ["No demo pods on the DPU worker"]
  );
  fillList("coverage-includes", coverage.includes);
  fillList("coverage-excludes", coverage.excludes);
  fillList("coverage-signals", coverage.signals);
}

function eventHaystack(event) {
  return [event.process_name, event.process_command, event.activity_name]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function inClickWindow(event) {
  if (!lastClickAt) return false;
  const stamp = Date.parse(event.received_at || event.occurred_at || "") || 0;
  return stamp >= lastClickAt && Date.now() - lastClickAt <= CLICK_WINDOW_MS;
}

function podMatchesPrefixes(podName, prefixes) {
  const pod = (podName || "").toLowerCase();
  return prefixes.some((prefix) => pod.startsWith(prefix));
}

function isHypervisorNoise(event) {
  const hay = [event.process_name, event.process_command].filter(Boolean).join(" ").toLowerCase();
  return /(?:^|\/)(kata-agent|virtiofsd|qemu-system|cloud-hypervisor)(?:\s|$)/.test(hay);
}

function isDemoWorkload(event, scenarioId) {
  if (isHypervisorNoise(event)) return false;
  const prefixes = scenarioId
    ? SCENARIO_POD_PREFIXES[scenarioId] || DEMO_POD_PREFIXES
    : DEMO_POD_PREFIXES;
  const pod = (event.pod_name || "").toLowerCase();
  const node = (event.node_name || "").toLowerCase();
  return prefixes.some((prefix) => {
    const p = prefix.toLowerCase();
    return pod.startsWith(p) || node.startsWith(p);
  });
}

function matchesSignature(event, scenarioId) {
  const hay = eventHaystack(event);
  const signatures = SCENARIO_SIGNATURES[scenarioId] || [];
  return signatures.some((token) => hay.includes(token.toLowerCase()));
}

function matchesAnySignature(event) {
  return Object.keys(SCENARIO_SIGNATURES).some((id) => matchesSignature(event, id));
}

function isNativeAlert(event) {
  return (event.message_type || "").toUpperCase() === "ALERT";
}

function isNativeHighAlert(event) {
  return isNativeAlert(event) && (event.severity || "").toUpperCase() === "HIGH";
}

function matchesNativeScenario(event, scenarioId) {
  if (!isNativeHighAlert(event)) return false;
  const expected = SCENARIO_NATIVE_ALERTS[scenarioId] || [];
  if (!expected.includes(event.activity_name)) return false;
  if (event.scenario_id === scenarioId) return true;
  return lastClickScenario === scenarioId && inClickWindow(event);
}

function isDemoRelevant(event) {
  if (event.scenario_id || event.demo_label) return true;
  if (!isDemoWorkload(event)) return false;
  if (isNativeAlert(event)) return true;
  if ((event.severity || "").toUpperCase() === "HIGH") return true;
  if (event.demo_label) return true;
  if (matchesAnySignature(event)) return true;
  const name = event.activity_name || "";
  return !CLICK_WINDOW_NOISE.has(name);
}

function matchesScenario(event, scenarioId) {
  if (!scenarioId) return true;
  if (scenarioId === "demo") return isDemoRelevant(event);
  if (
    lastClickScenario === scenarioId &&
    activeScenarioRunId
  ) {
    if (scenarioRunBaselineIds.has(event.id)) return false;
    if (event.scenario_run_id) {
      if (event.scenario_run_id !== activeScenarioRunId) return false;
    } else if (eventTimestamp(event) < lastClickAt - 2000) {
      // Compatibility fallback while an older server is still rolling out.
      return false;
    }
  }
  const expectedNativeAlerts = SCENARIO_NATIVE_ALERTS[scenarioId] || [];
  if (isNativeAlert(event) && expectedNativeAlerts.length) {
    return matchesNativeScenario(event, scenarioId);
  }
  if (matchesNativeScenario(event, scenarioId)) return true;
  if (matchesSignature(event, scenarioId)) return true;

  if (event.scenario_id === scenarioId) return true;
  const labeled = event.demo_label === SCENARIO_LABELS[scenarioId];
  if (labeled && isDemoWorkload(event, scenarioId)) return true;

  const pinned = pinnedScenarioEventIds.get(scenarioId);
  if (pinned?.has(event.id)) return true;

  // After a button click, keep Kata/VF events whose command lines Argus left empty.
  // A pod name is not enough: Argus attributes OpenShift system pods on the same node.
  if (
    lastClickScenario === scenarioId &&
    inClickWindow(event) &&
    isDemoWorkload(event, scenarioId)
  ) {
    const name = event.activity_name || "";
    if (!CLICK_WINDOW_NOISE.has(name)) {
      if (!pinnedScenarioEventIds.has(scenarioId)) {
        pinnedScenarioEventIds.set(scenarioId, new Set());
      }
      pinnedScenarioEventIds.get(scenarioId).add(event.id);
      return true;
    }
  }
  return false;
}

function shouldShowEvent(event) {
  const view = timelineFilter.value;
  let inScope = true;
  if (view === "evidence") inScope = isDemoRelevant(event);
  else if (view === "demo") inScope = isDemoWorkload(event);
  else if (view !== "raw") inScope = matchesScenario(event, view);
  if (!inScope) return false;

  const severity = (event.severity || "").toUpperCase();
  const type = (event.message_type || "").toUpperCase();
  if (severityFilter.value && severity !== severityFilter.value) return false;
  if (messageTypeFilter.value && type !== messageTypeFilter.value) return false;
  return true;
}

function eventTimestamp(event) {
  return Date.parse(event.received_at || event.occurred_at || "") || 0;
}

function isPersistentEvidence(event) {
  return Boolean(
    event.scenario_id ||
    event.demo_label ||
    isNativeAlert(event) ||
    (event.severity || "").toUpperCase() === "HIGH"
  );
}

function rememberEvent(event) {
  if (!event?.id || knownEventIds.has(event.id)) return false;
  knownEventIds.add(event.id);
  allEvents.push(event);
  if (isPersistentEvidence(event) && !evidenceEventIds.has(event.id)) {
    evidenceEventIds.add(event.id);
    evidenceEvents.push(event);
  }
  return true;
}

function trimBuffers() {
  allEvents.sort((a, b) => eventTimestamp(a) - eventTimestamp(b));
  evidenceEvents.sort((a, b) => eventTimestamp(a) - eventTimestamp(b));

  if (allEvents.length > MAX_BUFFERED_EVENTS) {
    const removed = allEvents.splice(0, allEvents.length - MAX_BUFFERED_EVENTS);
    removed.forEach((event) => {
      if (!evidenceEventIds.has(event.id)) knownEventIds.delete(event.id);
    });
  }
  if (evidenceEvents.length > MAX_EVIDENCE_EVENTS) {
    const removed = evidenceEvents.splice(
      0,
      evidenceEvents.length - MAX_EVIDENCE_EVENTS
    );
    removed.forEach((event) => {
      evidenceEventIds.delete(event.id);
      if (!allEvents.some((item) => item.id === event.id)) {
        knownEventIds.delete(event.id);
      }
    });
  }
}

function retainedEvents() {
  const merged = new Map();
  allEvents.forEach((event) => merged.set(event.id, event));
  evidenceEvents.forEach((event) => merged.set(event.id, event));
  return Array.from(merged.values()).sort(
    (a, b) => eventTimestamp(a) - eventTimestamp(b)
  );
}

function createEventElement(event) {
  const el = document.createElement("article");
  const severity = (event.severity || "").toUpperCase();
  const type = (event.message_type || "").toUpperCase();
  const nativeAlert = type === "ALERT";
  const nativeHigh = nativeAlert && severity === "HIGH";
  el.className = `event ${nativeAlert ? "alert" : ""} ${nativeHigh ? "high" : ""}`;
  const origin = nativeHigh
    ? "native Argus ALERT/HIGH"
    : nativeAlert
      ? `native Argus ALERT/${severity || "UNKNOWN"} (not native HIGH)`
      : event.demo_label
      ? "demo classification (not a native alert)"
      : "Argus EVENT";
  const extra = event.demo_label ? ` · ${event.demo_label}` : "";
  const meta = document.createElement("div");
  meta.className = "meta";
  const timestamp = document.createElement("span");
  timestamp.textContent = event.occurred_at || event.received_at || "";
  const classification = document.createElement("span");
  classification.textContent = `${severity || "INFO"} · ${type || "EVENT"}`;
  meta.append(timestamp, classification);

  const title = document.createElement("div");
  title.className = "title";
  title.textContent = event.activity_name || "Activity";
  const process = document.createElement("div");
  process.className = "detail";
  process.textContent = event.process_command || event.process_name || "";
  const context = document.createElement("div");
  context.className = "detail";
  context.textContent = `pod=${event.pod_name || "—"} · node=${event.node_name || "—"} · ${origin}${extra}`;
  const actions = document.createElement("div");
  actions.className = "event-actions";
  const viewButton = document.createElement("button");
  viewButton.type = "button";
  viewButton.className = "event-view-button";
  viewButton.textContent = "View full message";
  viewButton.setAttribute(
    "aria-label",
    `View full message for ${event.activity_name || "Argus activity"}`
  );
  viewButton.addEventListener("click", () => {
    openEventDialog(event, viewButton);
  });
  actions.appendChild(viewButton);
  el.append(meta, title, process, context, actions);
  return el;
}

function openEventDialog(event, trigger) {
  eventDialogTrigger = trigger;
  selectedEventJson = JSON.stringify(event, null, 2);
  eventDialogTitle.textContent = event.activity_name || "Argus Event";
  eventDialogMeta.textContent = [
    event.severity || "INFO",
    event.message_type || "EVENT",
    event.occurred_at || event.received_at || "timestamp unavailable",
    event.id ? `id=${event.id}` : null,
  ].filter(Boolean).join(" · ");
  eventDialogJson.textContent = selectedEventJson.length > MAX_DIALOG_JSON_CHARS
    ? `${selectedEventJson.slice(0, MAX_DIALOG_JSON_CHARS)}\n\n[Display truncated at 512 KiB; Copy JSON retains the complete event.]`
    : selectedEventJson;
  eventCopyStatus.textContent = "";
  eventDialog.showModal();
  document.getElementById("close-event-dialog").focus();
}

document.getElementById("close-event-dialog").addEventListener("click", () => {
  eventDialog.close();
});

eventDialog.addEventListener("click", (event) => {
  if (event.target === eventDialog) eventDialog.close();
});

eventDialog.addEventListener("close", () => {
  if (eventDialogTrigger?.isConnected) eventDialogTrigger.focus();
  eventDialogTrigger = null;
});

copyEventJsonBtn.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(selectedEventJson);
    eventCopyStatus.textContent = "Copied";
  } catch (_error) {
    eventCopyStatus.textContent = "Copy unavailable; select the JSON text manually.";
  }
});

function renderTimeline() {
  const retained = retainedEvents();
  const filtered = retained.filter(shouldShowEvent);
  const visible = filtered.slice(-MAX_VISIBLE_EVENTS).reverse();
  const fragment = document.createDocumentFragment();
  visible.forEach((event) => fragment.appendChild(createEventElement(event)));
  if (!visible.length) {
    const empty = document.createElement("div");
    empty.className = "timeline-empty";
    empty.textContent = "No matching events in retained history.";
    fragment.appendChild(empty);
  }
  timeline.replaceChildren(fragment);
  const capped = filtered.length - visible.length;
  eventCountEl.textContent = `${visible.length} shown · ${filtered.length} matching${capped > 0 ? ` · ${capped} older` : ""}`;
  eventCountEl.title = `${retained.length} browser-retained events`;
  const operationEvents = filtered.filter(
    (event) => (event.message_type || "").toUpperCase() === "EVENT"
  ).length;
  const nativeAlerts = filtered.filter(isNativeAlert).length;
  const nativeHigh = filtered.filter(isNativeHighAlert).length;
  const demoCorrelated = filtered.filter((event) => Boolean(event.demo_label)).length;
  timelineStory.textContent =
    `Current view: ${operationEvents} operation event${operationEvents === 1 ? "" : "s"} observed · ` +
    `${nativeAlerts} native alert${nativeAlerts === 1 ? "" : "s"} triggered · ` +
    `${nativeHigh} native HIGH · ${demoCorrelated} demo-correlated. ` +
    `EVENT means observed activity; ALERT means Argus policy detection.`;

  updateTimelineState();
}

function updateTimelineState() {
  const server = serverRetention
    ? `server ${serverRetention.buffered}/${serverRetention.capacity}`
    : "server loading";
  const evicted = serverRetention?.evicted
    ? ` · ${serverRetention.evicted} raw evicted`
    : "";
  const waiting = timelinePaused && eventQueue.length
    ? ` · ${eventQueue.length} waiting while paused`
    : "";
  const queueDrops = droppedQueuedEvents
    ? ` · ${droppedQueuedEvents} queue-overflow drops`
    : "";
  timelineState.textContent = `${server}${evicted} · browser ${allEvents.length}/${MAX_BUFFERED_EVENTS} raw + ${evidenceEvents.length}/${MAX_EVIDENCE_EVENTS} evidence${waiting}${queueDrops} · memory resets when the demo server restarts`;
}

function flushEventQueue() {
  flushTimer = null;
  if (!eventQueue.length || timelinePaused) return;

  eventQueue.splice(0, 250).forEach(rememberEvent);
  trimBuffers();
  renderTimeline();
  if (eventQueue.length) scheduleFlush();
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(flushEventQueue, FLUSH_INTERVAL_MS);
}

function queueEvent(event) {
  eventQueue.push(event);
  if (eventQueue.length > MAX_QUEUED_EVENTS) {
    const overflow = eventQueue.length - MAX_QUEUED_EVENTS;
    eventQueue.splice(0, overflow);
    droppedQueuedEvents += overflow;
  }
  if (timelinePaused) updateTimelineState();
  else scheduleFlush();
}

function createScenarioRunId() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function setScenarioFilter(scenarioId, scenarioRunId) {
  lastClickScenario = scenarioId;
  lastClickAt = Date.now();
  activeScenarioRunId = scenarioRunId;
  scenarioRunBaselineIds = new Set([
    ...knownEventIds,
    ...eventQueue.map((event) => event?.id).filter(Boolean),
  ]);
  pinnedScenarioEventIds.set(scenarioId, new Set());
  timelineFilter.value = scenarioId;
  timelinePin.hidden = false;
  timelinePin.textContent = `Current run: ${SCENARIO_LABELS[scenarioId] || scenarioId} · ${scenarioRunId} · earlier-run and unrelated alerts hidden`;
  renderTimeline();
}

function sparkline(series) {
  const values = (series || []).map((s) => s.value || 0);
  const max = Math.max(...values, 1);
  return values.slice(-24).map((v) => `<span style="height:${Math.max(8, (v / max) * 100)}%"></span>`).join("");
}

async function parseJsonResponse(res) {
  const body = await res.text();
  let data;
  try {
    data = JSON.parse(body);
  } catch (_parseError) {
    const proxyPage = /<html|<body|503 Service Unavailable|504 Gateway/i.test(body);
    const reason = proxyPage
      ? "the OpenShift Route returned an HTML proxy error page"
      : "the server returned a non-JSON response";
    throw new Error(`HTTP ${res.status} ${res.statusText}: ${reason}`);
  }
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status} ${res.statusText}`);
  return data;
}

async function refreshMetrics() {
  const res = await fetch("/api/metrics/dts");
  const data = await parseJsonResponse(res);
  metricGrid.innerHTML = `
    <div class="metric-card"><h3>Link Speed</h3><div>${(data.link_speed?.[0]?.value ?? "—")} GT/s</div></div>
    <div class="metric-card"><h3>Link Width</h3><div>${(data.link_width?.[0]?.value ?? "—")} lanes</div></div>
    <div class="metric-card"><h3>RX packets/s</h3><div class="spark">${sparkline(data.rx_packets)}</div></div>
    <div class="metric-card"><h3>TX packets/s</h3><div class="spark">${sparkline(data.tx_packets)}</div></div>
    <div class="metric-card"><h3>RX errors/s</h3><div class="spark">${sparkline(data.rx_errors)}</div></div>
    <div class="metric-card"><h3>TX drops/s</h3><div class="spark">${sparkline(data.tx_drops)}</div></div>
  `;
}

async function refreshStatus() {
  const res = await fetch("/api/status");
  const data = await parseJsonResponse(res);
  updateRibbon(data);
}

async function runScenario(id) {
  const scenarioRunId = createScenarioRunId();
  setScenarioFilter(id, scenarioRunId);
  const scenarioButtons = document.querySelectorAll("button[data-scenario]");
  scenarioButtons.forEach((button) => { button.disabled = true; });
  actionLog.className = "result-running";
  actionLog.textContent = SCENARIO_NATIVE_ALERTS[id]
    ? `Running ${id}. Waiting up to 45 seconds for a native Argus ALERT/HIGH.`
    : `Running ${id}. Timeline filtered for correlation. Demo labels are not native Argus alerts.`;
  try {
    const res = await fetch(
      `/api/scenarios/${id}?scenario_run_id=${encodeURIComponent(scenarioRunId)}`,
      { method: "POST" }
    );
    const data = await parseJsonResponse(res);
    if (data.scenario_run_id && data.scenario_run_id !== scenarioRunId) {
      throw new Error("scenario run correlation mismatch");
    }
    actionLog.className = data.status === "native-alert"
      ? "result-success"
      : data.status === "no-native-alert"
        ? "result-failed"
        : "";
    actionLog.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    actionLog.className = "result-failed";
    actionLog.textContent = `Scenario failed: ${error.message}`;
  } finally {
    scenarioButtons.forEach((button) => { button.disabled = false; });
  }
}

document.querySelectorAll("button[data-scenario]").forEach((btn) => {
  btn.addEventListener("click", () => {
    closeScenarioInfo();
    runScenario(btn.dataset.scenario);
  });
});

function closeScenarioInfo(except) {
  document.querySelectorAll(".scenario-info").forEach((panel) => {
    if (panel === except) return;
    panel.hidden = true;
  });
  document.querySelectorAll(".info-sign").forEach((btn) => {
    if (except && btn.getAttribute("aria-controls") === except.id) {
      btn.setAttribute("aria-expanded", String(!except.hidden));
      return;
    }
    btn.setAttribute("aria-expanded", "false");
  });
}

document.querySelectorAll(".info-sign").forEach((btn) => {
  btn.addEventListener("click", (event) => {
    event.stopPropagation();
    const panel = document.getElementById(btn.getAttribute("aria-controls"));
    if (!panel) return;
    const willOpen = panel.hidden;
    closeScenarioInfo(willOpen ? panel : null);
    panel.hidden = !willOpen;
    btn.setAttribute("aria-expanded", String(willOpen));
  });
});

document.addEventListener("click", (event) => {
  if (event.target.closest(".scenario-action")) return;
  closeScenarioInfo();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeScenarioInfo();
});

async function runControlAction(path) {
  try {
    const res = await fetch(path, { method: "POST" });
    actionLog.className = "";
    actionLog.textContent = JSON.stringify(await parseJsonResponse(res), null, 2);
    await refreshStatus();
  } catch (error) {
    actionLog.className = "result-failed";
    actionLog.textContent = `Action failed: ${error.message}`;
  }
}

document.getElementById("contain-btn").addEventListener("click", () => {
  runControlAction("/api/contain");
});

document.getElementById("reset-btn").addEventListener("click", () => {
  runControlAction("/api/reset");
});

pauseBtn.addEventListener("click", () => {
  timelinePaused = !timelinePaused;
  pauseBtn.textContent = timelinePaused ? "Resume" : "Pause";
  pauseBtn.classList.toggle("active", timelinePaused);
  if (!timelinePaused) scheduleFlush();
  renderTimeline();
});

timelineFilter.addEventListener("change", renderTimeline);
severityFilter.addEventListener("change", renderTimeline);
messageTypeFilter.addEventListener("change", renderTimeline);

async function loadTimelineHistory() {
  try {
    const res = await fetch(
      `/api/events?limit=${HISTORY_LIMIT}&evidence_limit=${HISTORY_EVIDENCE_LIMIT}`
    );
    const data = await parseJsonResponse(res);
    serverRetention = data.retention || null;
    [...(data.events || []), ...(data.evidence || [])].forEach(rememberEvent);
    trimBuffers();
    renderTimeline();
  } catch (error) {
    timelineState.textContent = `Could not load retained history: ${error.message}`;
  }
}

function connectStream() {
  const source = new EventSource("/api/events/stream");
  source.addEventListener("argus", (msg) => {
    try {
      queueEvent(JSON.parse(msg.data));
    } catch (e) {
      console.error(e);
    }
  });
  source.onerror = () => {
    source.close();
    setTimeout(connectStream, 3000);
  };
}

refreshStatus();
refreshMetrics();
connectStream();
loadTimelineHistory();
setInterval(refreshStatus, 5000);
setInterval(refreshMetrics, 15000);
