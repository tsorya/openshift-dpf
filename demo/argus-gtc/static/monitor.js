/* Fixed presenter console. Native records come only from the existing Argus history/SSE path. */
(() => {
  "use strict";

  const api = window.argusDemo;
  const byId = (id) => document.getElementById(id);
  const storyPicker = byId("story-select");
  const rawDialog = byId("event-dialog");
  const primaryChoices = byId("monitor-primary-scenarios");
  const runButton = byId("monitor-run-button");
  const stream = byId("monitor-stream");
  const alerts = byId("monitor-alerts");
  const scopePicker = byId("monitor-scope");
  const AI_ACTIONS = [
    {
      id: "baseline", label: "Normal request",
      what: "Ask the AI application to summarize a harmless status note without using the shell tool.",
      why: "Establishes the expected baseline: a completed response with no recorded shell-tool call.",
      watch: "No shell check is expected. Tool, listener, and Argus shell evidence are Not applicable.",
      duration: "The request duration depends on the configured model.",
    },
    {
      id: "host-reachability", label: "Authorized demo shell",
      what: "Explicitly ask the AI application to open its bounded demo shell inside its own Kata VM.",
      why: "Shows an authorized tool action and separates the tool report from independent observation.",
      watch: "The controlled listener must record the identity-command output to prove a working shell. Argus activity and any native alert are separate.",
      duration: "A bounded shell; allow additional time for native Argus evidence.",
    },
  ];

  let workloadCatalog = new Map();
  let catalogError = null;
  let workloadTarget = "invisible-vm";
  let selectedWorkloadAction = "discovery";
  let selectedAgentAction = "baseline";
  let markers = [];
  let localRun = null;
  let paused = false;
  let frozenRecords = null;
  let frozenMarkers = null;
  let frozenRun = null;
  let pauseBaselineIds = null;
  let historyGap = "";
  let knownServerInstance = null;
  let selectedEventId = null;
  let expandedGroups = new Set();
  let renderedFeedKey = "";
  let alertBaselineIds = new Set();
  let alertViewReset = false;
  let alertSelectionAt = 0;
  let renderTimer = null;

  // A modal must remain usable while Technical view is collapsed.
  document.body.appendChild(rawDialog);

  function selectedAction() {
    if (api.story === "agent") return AI_ACTIONS.find((item) => item.id === selectedAgentAction);
    return workloadCatalog.get(selectedWorkloadAction);
  }

  function showStory(story) {
    if (api.story === story) return;
    storyPicker.value = story;
    storyPicker.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function selectAction(story, id) {
    const storyChanged = api.story !== story;
    const currentAction = story === "agent" ? selectedAgentAction : selectedWorkloadAction;
    showStory(story);
    if (story === "agent") selectedAgentAction = id;
    else selectedWorkloadAction = id;
    if (storyChanged || currentAction !== id) resetAlertViewForSelection();
    renderChoices();
    renderConsole();
  }

  function resetAlertViewForSelection() {
    const visibleRecords = paused
      ? (frozenRecords || []).filter(scopedRecord)
      : [...api.events, ...(api.queuedEvents || [])].filter(scopedRecord);
    alertBaselineIds = new Set(visibleRecords
      .filter((event) => (event.message_type || "").toUpperCase() === "ALERT" && !api.isRuntimeNoise(event))
      .map((event) => event.id)
      .filter(Boolean));
    alertSelectionAt = Date.now();
    alertViewReset = true;
    renderedFeedKey = "";
  }

  window.selectMonitorScenario = (id) => {
    if (workloadCatalog.has(id)) selectAction("workload", id);
    byId("monitor-main").scrollIntoView({ block: "start", behavior: "smooth" });
  };
  window.selectMonitorAgent = (id) => {
    if (AI_ACTIONS.some((item) => item.id === id)) selectAction("agent", id);
    byId("monitor-main").scrollIntoView({ block: "start", behavior: "smooth" });
  };

  function choiceButton(item, story) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "monitor-choice";
    button.textContent = item.label;
    button.dataset.actionId = item.id;
    const selected = story === "agent" ? selectedAgentAction : selectedWorkloadAction;
    if (item.id === selected) {
      button.classList.add("selected");
      button.setAttribute("aria-current", "true");
    }
    button.addEventListener("click", () => selectAction(story, item.id));
    return button;
  }

  function renderChoices() {
    primaryChoices.replaceChildren();
    const story = api.story;
    const actions = story === "agent" ? AI_ACTIONS : [...workloadCatalog.values()];
    actions.forEach((item) => primaryChoices.appendChild(choiceButton(item, story)));
  }

  function actionReadiness() {
    if (catalogError && api.story === "workload") return catalogError;
    if (!selectedAction()) return "Loading action descriptions…";
    if (api.actionInProgress || localRun?.pending) return "Another demo action is running.";
    if (api.story === "agent") {
      if (!api.agentReady) return api.agentStatus?.message || "AI application is not ready.";
    } else if (api.status?.kata_vm !== "Ready") {
      return api.status ? `Workload is ${api.status.kata_vm || "unavailable"}; restore it before running.` : "Checking workload readiness…";
    }
    return null;
  }

  function renderDescription() {
    const story = api.story;
    const item = selectedAction();
    byId("monitor-workload").textContent = story === "agent" ? "argus-gtc-agent" : workloadTarget;
    byId("monitor-target").textContent = story === "agent" ? "argus-gtc-agent" : workloadTarget;
    byId("monitor-selection-kind").textContent = story === "agent" ? "Selected AI request" : "Selected scenario";
    byId("monitor-scenario-title").textContent = item?.label || "Scenario catalog unavailable";
    byId("monitor-what").textContent = item?.what || catalogError || "Loading…";
    byId("monitor-why").textContent = item?.why || "";
    byId("monitor-watch").textContent = item?.watch || "";
    byId("monitor-duration").textContent = item?.duration || "";
    runButton.textContent = item ? `Run ${item.label}` : "Run";
    const reason = actionReadiness();
    runButton.disabled = Boolean(reason);
    byId("monitor-readiness").textContent = reason || (
      api.status?.collector?.state === "unavailable"
        ? "Argus collector unavailable; this action may have no observable evidence."
        : "Selection does not start the action."
    );
    const operator = byId("monitor-operator");
    operator.hidden = story === "agent";
    byId("monitor-response-target").textContent = workloadTarget;
    const response = api.responseState;
    byId("monitor-response-state").textContent = response === "Not requested"
      ? api.status?.kata_vm === "Stopped" ? "OpenShift reports the workload stopped." : "No response requested."
      : response + ".";
    byId("monitor-stop-btn").disabled = api.actionInProgress || Boolean(localRun?.pending);
    byId("monitor-restore-btn").disabled = api.actionInProgress || Boolean(localRun?.pending);
  }

  async function loadCatalog() {
    try {
      const response = await fetch("/api/scenarios", { cache: "no-store" });
      if (!response.ok) throw new Error(`Scenario catalog unavailable (HTTP ${response.status})`);
      const data = await response.json();
      if (!Array.isArray(data.scenarios) || !data.scenarios.length) throw new Error("Scenario catalog is empty");
      workloadCatalog = new Map(data.scenarios.map((item) => [item.id, item]));
      workloadTarget = data.target || workloadTarget;
      if (!workloadCatalog.has(selectedWorkloadAction)) selectedWorkloadAction = data.scenarios[0].id;
      document.querySelectorAll(".scenario-action [data-scenario]").forEach((button) => {
        const item = workloadCatalog.get(button.dataset.scenario);
        button.closest(".scenario-action").hidden = !item;
        if (item) button.textContent = `Select ${item.label}`;
      });
      catalogError = null;
    } catch (error) {
      catalogError = error.message;
    }
    renderChoices();
    renderConsole();
  }

  function shortTime(value) {
    const date = new Date(value || "");
    return Number.isNaN(date.getTime())
      ? "time unavailable"
      : new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(date);
  }

  function ageLabel(value) {
    const stamp = Date.parse(value || "");
    if (!stamp) return "No native events yet";
    const seconds = Math.max(0, Math.floor((Date.now() - stamp) / 1000));
    const age = seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m`;
    return seconds < 120 ? `${age} ago` : `No recent events · ${age} ago`;
  }

  function renderHealth() {
    const status = api.status;
    const browser = api.streamState;
    const browserText = browser === "connected" ? "Connected" : browser === "disconnected" ? "Reconnecting" : "Connecting";
    byId("monitor-browser-health").textContent = browserText;
    byId("monitor-browser-health").dataset.state = browser;
    const collector = status?.collector;
    const collectorState = collector?.state || "starting";
    byId("monitor-collector-health").textContent = collectorState === "reading"
      ? "Reading source" : collectorState === "unavailable" ? "Unavailable" : "Checking";
    byId("monitor-collector-health").dataset.state = collectorState;
    byId("monitor-collector-health").title = collector?.last_error || collector?.source || "Collector status unavailable";
    byId("monitor-native-age").textContent = ageLabel(status?.latest_native_occurred_at);
    byId("monitor-native-age").title = status?.latest_native_occurred_at || "No native source timestamp";
    byId("monitor-native-age").dataset.state = status?.latest_native_occurred_at
      ? Date.now() - Date.parse(status.latest_native_occurred_at) < 120000 ? "recent" : "quiet"
      : "quiet";
    const instance = status?.server_instance_id || api.serverInstanceId;
    if (instance && knownServerInstance && instance !== knownServerInstance) {
      historyGap = "Demo server restarted; earlier in-memory history may be unavailable.";
      renderedFeedKey = "";
    }
    if (instance) knownServerInstance = instance;
  }

  function currentRun() {
    const serverRun = api.run;
    if (localRun?.story === api.story) {
      if (serverRun?.runId === localRun.runId && !localRun.pending) localRun = null;
      else return localRun;
    }
    return serverRun || null;
  }

  function displayRun() {
    return paused ? frozenRun : currentRun();
  }

  function runLabel(run) {
    if (!run) return "";
    if (run.story === "agent" || run.kind === "agent") {
      return AI_ACTIONS.find((item) => item.id === run.profile)?.label || "AI request";
    }
    return workloadCatalog.get(run.scenarioId)?.label || run.scenarioId || "Scenario";
  }

  function renderRun() {
    const run = currentRun();
    if (!run) {
      byId("monitor-run-status").textContent = "No action started";
      byId("monitor-run-identity").textContent = "Monitoring continues before and after a run.";
      byId("monitor-run-evidence").textContent = "";
      return;
    }
    const state = run.serverState || {};
    const phase = state.phase || (run.pending ? "action" : run.error ? "failed" : "complete");
    const started = state.started_at || run.startedAt;
    const seconds = started ? Math.max(0, Math.floor((Date.now() - Date.parse(started)) / 1000)) : 0;
    const data = run.data || state.result || {};
    let statusText;
    if (run.lost) statusText = "Run state unavailable after reload";
    else if (phase === "action") statusText = `Running action · ${seconds}s`;
    else if (phase === "observation") statusText = `Waiting for matching Argus evidence · ${seconds}s`;
    else if (phase === "failed" || run.error) statusText = "Action failed";
    else if (data.status === "no-native-alert") statusText = "Completed · no matching native alert in the wait window";
    else if (data.status === "no-native-event") statusText = "Completed · no matching native event in the wait window";
    else if (data.status === "native-alert") statusText = "Completed · matching native alert";
    else if (data.status === "native-event") statusText = "Completed · matching native event";
    else if (data.status === "no-tool-call") statusText = "Completed · no shell tool used (expected baseline)";
    else if (data.working_shell && data.native_argus_alert) statusText = "Completed · shell confirmed; native Argus alert";
    else if (data.working_shell) statusText = "Completed · shell confirmed by demo listener";
    else statusText = "Action completed";
    const identity = `Last run: ${runLabel(run)} · ${run.workload || (run.story === "agent" ? "argus-gtc-agent" : workloadTarget)} · ${shortTime(started)} · run ${run.runId || "unavailable"}`;
    byId("monitor-run-status").textContent = statusText;
    byId("monitor-run-status").dataset.phase = phase;
    byId("monitor-run-identity").textContent = identity;
    const evidenceHint = phase === "failed"
      ? state.message || run.error || "Inspect Technical view for the action error."
      : phase === "complete" && state.observation_status === "not_checked"
        ? "Native telemetry remains visible below; this action has no gated detection result."
        : phase === "complete" && data.status === "no-native-alert"
          ? "Underlying process and network events remain visible."
          : "";
    byId("monitor-run-evidence").textContent = api.story === "workload" && phase !== "failed"
      ? "" : evidenceHint;
    if (run.runId && started && !markers.some((marker) => marker.runId === run.runId)) {
      markers.push({
        runId: run.runId, story: run.story, label: runLabel(run),
        workload: run.workload || (run.story === "agent" ? "argus-gtc-agent" : workloadTarget),
        startedAt: started,
      });
      markers = markers.slice(-20);
    }
  }

  function renderRunComparison() {
    const panel = byId("monitor-run-comparison");
    const run = currentRun();
    panel.hidden = api.story !== "workload" || !run;
    panel.closest(".monitor-console").classList.toggle("has-comparison", !panel.hidden);
    if (panel.hidden) return;

    const scenarioId = run.scenarioId || run.serverState?.scenario_id;
    const catalogItem = workloadCatalog.get(scenarioId);
    const expectationKnown = catalogItem && Object.prototype.hasOwnProperty.call(catalogItem, "expected_native");
    const expected = expectationKnown ? catalogItem.expected_native : undefined;
    const state = run.serverState || {};
    const phase = state.phase || (run.pending ? "action" : run.error ? "failed" : "complete");
    const data = run.data || state.result || {};
    const observedItem = byId("monitor-observed-item");

    byId("monitor-comparison-scenario").textContent = `· ${runLabel(run)}`;
    byId("monitor-comparison-run-id").textContent = run.runId ? `Run ${run.runId}` : "Run ID unavailable";
    if (!expectationKnown) {
      byId("monitor-expected-native").textContent = "Expectation unavailable";
      byId("monitor-expected-detail").textContent = "Scenario catalog has not supplied native evidence criteria.";
    } else if (expected) {
      byId("monitor-expected-native").textContent = expected.activity_names.join(" or ");
      byId("monitor-expected-detail").textContent =
        `${expected.message_type} · ${expected.severity} · ${expected.wait_seconds}-second observation window`;
    } else {
      byId("monitor-expected-native").textContent = "No specific native detection required";
      byId("monitor-expected-detail").textContent = "Routine process and file telemetry may appear in Activity.";
    }

    let observed = "";
    let detail = "";
    let explanation = "";
    let observationState = "pending";
    const verified = data.status === "native-alert" ? data.native_alert
      : data.status === "native-event" ? data.native_event : null;
    const exactMatch = expected && verified &&
      expected.activity_names.includes(verified.activity_name) &&
      expected.message_type === verified.message_type &&
      expected.severity === verified.severity;

    if (run.lost) {
      observed = "Run result unavailable";
      detail = "The server no longer has this run's result.";
      observationState = "unavailable";
    } else if (phase === "failed" || run.error) {
      observed = "No sensor verdict";
      detail = "The action failed before a verified result was returned.";
      explanation = state.message || run.error || "Inspect the action error in the run status above.";
      observationState = "failed";
    } else if (phase === "action") {
      observed = "Action in progress";
      detail = "The evidence check begins after the action completes.";
    } else if (phase === "observation") {
      observed = "Checking Argus records";
      detail = "The server is waiting for evidence from this run.";
    } else if (!expectationKnown) {
      observed = "Result unavailable";
      detail = "The expected native evidence could not be loaded.";
      observationState = "unavailable";
    } else if (!expected) {
      observed = "Native detection not checked";
      detail = "Discovery has no required native alert.";
      explanation = "The action completed. Inspect Activity for ordinary process and file records.";
      observationState = "ungated";
    } else if (exactMatch) {
      observed = verified.activity_name;
      detail = `${verified.message_type} · ${verified.severity} · ${shortTime(verified.occurred_at)} · ` +
        (verified.pod_name ? `pod ${verified.pod_name}` : "pod not supplied in record");
      explanation = "This native record satisfied the server's checks for the last run.";
      observationState = "matched";
    } else if (data.status === "no-native-alert" || data.status === "no-native-event") {
      observed = `No matching record verified within ${expected.wait_seconds} seconds`;
      detail = "The action completed; no record satisfied the expected criteria during the wait window.";
      explanation = "Other Activity records are separate observations. A later record remains visible there without changing this wait-window result.";
      observationState = "unmatched";
    } else {
      observed = "Sensor verdict unavailable";
      detail = "The server did not return a verified native record for this run.";
      observationState = "unavailable";
    }

    observedItem.dataset.state = observationState;
    byId("monitor-observed-native").textContent = observed;
    byId("monitor-observed-detail").textContent = detail;
    const explanationNode = byId("monitor-comparison-explanation");
    explanationNode.textContent = explanation;
    explanationNode.hidden = !explanation;
  }

  function renderAgentChecks() {
    const checks = byId("monitor-agent-checks");
    checks.hidden = api.story !== "agent";
    if (checks.hidden) return;

    const setCheck = (name, value, state = "neutral") => {
      const item = byId(`agent-check-${name}`);
      item.textContent = value;
      item.dataset.state = state;
    };
    const setAll = (value) => {
      ["tool", "listener", "argus", "alert", "ovn"].forEach((name) => setCheck(name, value));
    };
    const run = currentRun();
    if (!run) {
      setAll("No run yet");
      return;
    }
    if (run.lost) {
      setAll("Run state unavailable");
      return;
    }
    const serverState = run.serverState || {};
    const phase = serverState.phase || (run.pending || run.running ? "action" : run.error ? "failed" : "complete");
    const data = run.data || serverState.result || {};
    if (phase === "failed") {
      setAll("Run failed");
      return;
    }
    if (phase !== "complete") {
      setCheck("tool", serverState.action_status === "tool_reported" ? "Report recorded" : "Waiting for report",
        serverState.action_status === "tool_reported" ? "observed" : "neutral");
      ["listener", "argus", "alert", "ovn"].forEach((name) => setCheck(name, "Waiting for result"));
      return;
    }
    if (run.profile === "baseline" && data.status === "no-tool-call") {
      setCheck("tool", "No shell call (expected)", "observed");
      ["listener", "argus", "alert", "ovn"].forEach((name) => setCheck(name, "Not applicable"));
      return;
    }
    setCheck("tool", data.authenticated_tool_report_observed ? "Report recorded" : "No authenticated report",
      data.authenticated_tool_report_observed ? "observed" : "missing");
    setCheck("listener", data.working_shell ? "id output confirmed" : "No shell proof",
      data.working_shell ? "observed" : "missing");
    setCheck("argus", data.argus_host_attempt_observed ? "Matching native event" : "No matching event",
      data.argus_host_attempt_observed ? "observed" : "missing");
    setCheck("alert", data.native_argus_alert ? "Native HIGH alert" : "No matching alert",
      data.native_argus_alert ? "observed" : "neutral");
    setCheck("ovn", data.policy_drop_observed ? "Matching deny" : "No matching deny",
      data.policy_drop_observed ? "observed" : "neutral");
  }

  function nativeRecord(event) {
    const source = event.evidence_source || "";
    return !["ovn-acl-audit", "demo-correlation", "canary-listener"].includes(source) &&
      ["EVENT", "ALERT", "SYSTEM_ACTIVITY"].includes((event.message_type || "").toUpperCase());
  }

  function scopedRecord(event) {
    if (!nativeRecord(event)) return false;
    if (scopePicker.value === "worker") return true;
    const pod = (event.pod_name || "").toLowerCase();
    if (scopePicker.value === "demo") {
      return ["invisible-vm", "scenario-sink", "argus-gtc-agent"].some((name) => pod.startsWith(name));
    }
    const target = api.story === "agent" ? "argus-gtc-agent" : workloadTarget;
    if (pod.startsWith(target.toLowerCase())) return true;
    const run = displayRun();
    return Boolean(run?.runId && event.scenario_run_id === run.runId &&
      (pod.startsWith("scenario-sink") || !pod));
  }

  function sourceTime(event) {
    return Date.parse(event.occurred_at || event.received_at || "") || 0;
  }

  function routineMemoryNoise(event) {
    const process = (event.process_name || "").split(/[\\/]/).pop().toLowerCase();
    return event.activity_name === "Executable Permissions Removed" &&
      (event.severity || "").toUpperCase() === "MEDIUM" &&
      ["bash", "sh", "sleep", "timeout"].includes(process) &&
      (event.pod_name || "").toLowerCase().startsWith("invisible-vm");
  }

  function isLate(event) {
    const occurred = Date.parse(event.occurred_at || "");
    const received = Date.parse(event.received_at || "");
    return Boolean(occurred && received && received - occurred > 30000);
  }

  function fileContext(event) {
    if (!/file/i.test(event.activity_name || "")) return "";
    const queue = [{ value: event.raw, depth: 0 }];
    while (queue.length) {
      const { value, depth } = queue.shift();
      if (!value || typeof value !== "object" || depth > 5) continue;
      for (const [key, part] of Object.entries(value)) {
        if (typeof part === "string" && /(?:file|path|filename)/i.test(key) && part.startsWith("/")) {
          return part;
        }
        if (part && typeof part === "object") queue.push({ value: part, depth: depth + 1 });
      }
    }
    return "";
  }

  function recordExplanation(activity) {
    return {
      "Process Created": "A process started",
      "Process Executed": "A process ran",
      "Network Connection Created": "A connection opened",
      "File Descriptor Open": "A file was opened",
      "New Executable Anonymous Memory Mapped": "Executable memory was mapped",
      "Reverse Shell Detected": "Argus identified a remote shell pattern",
    }[activity] || "";
  }

  function element(tag, className, content) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content != null) node.textContent = content;
    return node;
  }

  function association(event) {
    const run = displayRun();
    const selectedScenarioId = api.story === "agent"
      ? selectedAgentAction === "baseline" ? "agent-baseline" : "host-access-attempt"
      : selectedWorkloadAction;
    const runScenarioId = run?.scenarioId || run?.scenario_id ||
      (run?.profile === "baseline" ? "agent-baseline" : run?.profile ? "host-access-attempt" : null);
    const runActionLabel = run ? runLabel(run) : "previous action";
    if (event.scenario_run_id && (!run?.runId || event.scenario_run_id !== run.runId)) {
      const earlier = markers.find((marker) => marker.runId === event.scenario_run_id);
      return `Earlier run${earlier?.label ? ` · ${earlier.label}` : ` ${event.scenario_run_id}`}`;
    }
    if (event.scenario_run_id && runScenarioId && runScenarioId !== selectedScenarioId) {
      return `Previous action · ${runActionLabel}`;
    }
    if (!event.scenario_run_id) {
      if (event.scenario_id && event.scenario_id !== selectedScenarioId) {
        const previous = api.story === "agent"
          ? event.scenario_id === "agent-baseline" ? "Normal request" : "Authorized demo shell"
          : workloadCatalog.get(event.scenario_id)?.label || event.scenario_id;
        return `Other scenario · ${previous}`;
      }
      const occurred = Date.parse(event.occurred_at || "");
      if (alertSelectionAt && occurred && occurred < alertSelectionAt - 2000) {
        return "Late Argus alert · occurred before this action was selected";
      }
      return "No run association";
    }
    const result = run.data || run.serverState?.result || {};
    const validated = result.native_alert || result.native_event || (
      result.native_argus_alert ? result.argus_host_attempt_event : null
    );
    const sameAlert = validated &&
      validated.activity_name === event.activity_name &&
      validated.occurred_at === event.occurred_at &&
      (!validated.pod_name || validated.pod_name === event.pod_name) &&
      (!validated.message_type || validated.message_type === event.message_type) &&
      (!validated.severity || validated.severity === event.severity);
    return sameAlert
      ? "Current run · verified Argus evidence"
      : "Run window association · not verified";
  }

  function isLowValue(event) {
    return (event.message_type || "").toUpperCase() !== "ALERT" &&
      /^(File Descriptor (Open|Close)|File Unmapped|Thread Created)$/i.test(event.activity_name || "");
  }

  function groupKey(event) {
    return [
      event.pod_name || "", event.process_name || event.process_command || "",
      event.activity_name || "", event.severity || "", event.message_type || "",
      event.scenario_run_id || "",
    ].join("|");
  }

  function groupRecords(records) {
    const groups = [];
    for (const event of records) {
      const previous = groups[groups.length - 1];
      if (previous && isLowValue(event) &&
          groupKey(previous.events[0]) === groupKey(event) &&
          sourceTime(previous.events[0]) - sourceTime(event) <= 5000) {
        previous.events.push(event);
      } else {
        groups.push({ events: [event] });
      }
    }
    return groups;
  }

  function groupAlertRecords(records) {
    const groups = [];
    const repeatedMemoryAlerts = new Map();
    const sorted = [...records].sort((a, b) => sourceTime(b) - sourceTime(a));
    sorted.forEach((event) => {
      if (event.activity_name !== "Executable Permissions Removed") {
        groups.push({ events: [event] });
        return;
      }
      const key = [event.severity || "", event.pod_name || ""].join("|");
      let group = repeatedMemoryAlerts.get(key);
      if (!group) {
        group = { events: [] };
        repeatedMemoryAlerts.set(key, group);
        groups.push(group);
      }
      group.events.push(event);
    });
    return groups;
  }

  function recordButton(event, label = "Inspect record") {
    const button = element("button", "secondary compact monitor-inspect", label);
    button.type = "button";
    button.addEventListener("click", (click) => {
      click.stopPropagation();
      selectedEventId = event.id;
      api.openEventDialog(event, button);
    });
    return button;
  }

  function eventRow(event, compact = false) {
    const row = element("article", "monitor-event");
    row.dataset.eventId = event.id;
    row.tabIndex = -1;
    const type = (event.message_type || "EVENT").toUpperCase();
    const severity = (event.severity || "UNKNOWN").toUpperCase();
    row.dataset.type = type;
    row.dataset.severity = severity;
    if (association(event) === "Current run · verified Argus evidence") row.classList.add("current-run");
    if (event.id === selectedEventId) row.classList.add("selected-record");
    const top = element("div", "monitor-event-top");
    const time = element("time", "", shortTime(event.occurred_at || event.received_at));
    time.dateTime = event.occurred_at || event.received_at || "";
    time.title = event.occurred_at || event.received_at || "";
    top.append(time, element("span", "monitor-type", `${type} · ${severity}`));
    if (isLate(event)) top.append(element("span", "monitor-late", "Arrived late"));
    row.append(top);
    const heading = element("strong", "monitor-event-name", event.activity_name || "Argus activity");
    row.append(heading);
    const explanation = recordExplanation(event.activity_name);
    if (explanation && !compact) row.append(element("span", "monitor-event-explain", explanation));
    const context = [event.pod_name || "Pod unavailable", event.process_name || event.process_command || "Process unavailable"];
    row.append(element("div", "monitor-event-context", context.join(" · ")));
    const destination = event.destination_ip
      ? `Destination ${event.destination_ip}${event.destination_port ? ":" + event.destination_port : ""}`
      : "";
    const file = fileContext(event);
    if (destination || file) row.append(element("div", "monitor-event-detail", destination || `File ${file}`));
    if (!compact) {
      row.append(element("span", "monitor-association", association(event)));
      row.append(recordButton(event));
    } else {
      row.append(recordButton(event, "Inspect"));
    }
    return row;
  }

  function groupedRow(group) {
    if (group.events.length === 1) return eventRow(group.events[0]);
    const newest = group.events[0];
    const oldest = group.events[group.events.length - 1];
    const details = element("details", "monitor-event-group");
    const key = oldest.id;
    details.dataset.eventId = key;
    if (expandedGroups.has(key)) details.open = true;
    const summary = element("summary");
    summary.append(
      element("span", "monitor-group-count", `${group.events.length} records`),
      element("strong", "", newest.activity_name || "Repeated activity"),
      element("span", "", `${shortTime(oldest.occurred_at || oldest.received_at)}–${shortTime(newest.occurred_at || newest.received_at)}`),
      element("small", "", `${newest.pod_name || "Pod unavailable"} · ${newest.process_name || newest.process_command || "Process unavailable"} · ${newest.message_type || "EVENT"} / ${newest.severity || "UNKNOWN"}`)
    );
    details.append(summary);
    const originals = element("div", "monitor-group-originals");
    group.events.forEach((event) => originals.append(eventRow(event, true)));
    details.append(originals);
    details.addEventListener("toggle", () => {
      if (details.open) expandedGroups.add(key);
      else expandedGroups.delete(key);
    });
    return details;
  }

  function markerRow(marker) {
    const row = element("article", "monitor-action-marker");
    row.append(
      element("strong", "", "Demo controller · action started"),
      element("span", "", `${marker.label} · ${marker.workload} · ${shortTime(marker.startedAt)} · run ${marker.runId}`)
    );
    return row;
  }

  function alertCard(event) {
    const card = element("article", "monitor-alert-card");
    card.dataset.eventId = event.id;
    card.dataset.severity = (event.severity || "UNKNOWN").toUpperCase();
    const header = element("div", "monitor-alert-card-head");
    header.append(
      element("span", "monitor-alert-severity", `ALERT · ${event.severity || "UNKNOWN"}`),
      element("time", "", shortTime(event.occurred_at || event.received_at))
    );
    card.append(
      header,
      element("strong", "", event.activity_name || "Native Argus alert"),
      element("span", "monitor-alert-context", `${event.pod_name || "Pod unavailable"} · ${event.process_name || event.process_command || "Process unavailable"}`),
      element("span", "monitor-alert-association", association(event))
    );
    const controls = element("div", "monitor-alert-actions");
    const find = element("button", "secondary compact", "Find in activity");
    find.type = "button";
    find.addEventListener("click", () => {
      selectedEventId = event.id;
      renderedFeedKey = "";
      renderPanels();
      const row = [...stream.querySelectorAll(".monitor-event")].find((item) => item.dataset.eventId === event.id);
      row?.scrollIntoView({ block: "center" });
      row?.focus?.();
    });
    controls.append(find, recordButton(event));
    card.append(controls);
    return card;
  }

  function repeatedAlertGroup(group) {
    const newest = group.events[0];
    const oldest = group.events[group.events.length - 1];
    const details = element("details", "monitor-event-group monitor-alert-repeat-group");
    const summary = element("summary");
    const processNames = [...new Set(group.events.map((event) => event.process_name || event.process_command || "Process unavailable"))];
    const processText = processNames.length > 3
      ? `${processNames.slice(0, 3).join(", ")} +${processNames.length - 3} more`
      : processNames.join(", ");
    summary.append(
      element("span", "monitor-group-count", `${group.events.length} records`),
      element("strong", "", newest.activity_name || "Executable Permissions Removed"),
      element("span", "", `${shortTime(oldest.occurred_at || oldest.received_at)}–${shortTime(newest.occurred_at || newest.received_at)}`),
      element("small", "", `${newest.pod_name || "Pod unavailable"} · ${processText} · expand to inspect every Argus record`)
    );
    const records = element("div", "monitor-group-originals");
    group.events.forEach((event) => records.append(alertCard(event)));
    details.append(summary, records);
    return details;
  }

  function historyText() {
    const retention = api.retention;
    const pieces = [];
    if (historyGap) pieces.push(historyGap);
    if (retention?.evicted) pieces.push(`${retention.evicted} server records evicted`);
    if (retention?.evidence_evicted) pieces.push(`${retention.evidence_evicted} server evidence records evicted`);
    if (api.browserEvictedEvents) pieces.push(`${api.browserEvictedEvents} browser records evicted`);
    if (api.droppedQueuedEvents) pieces.push(`${api.droppedQueuedEvents} queue overflow drops`);
    return pieces.join(" · ");
  }

  function renderPanels() {
    const received = api.events.filter(scopedRecord);
    const records = paused ? (frozenRecords || []).filter(scopedRecord) : received;
    const visibleMarkers = (paused ? frozenMarkers || [] : markers).filter((marker) =>
      scopePicker.value !== "selected" || marker.story === api.story
    );
    const nativeAlerts = records.filter((event) =>
      (event.message_type || "").toUpperCase() === "ALERT" &&
      !api.isRuntimeNoise(event) && !alertBaselineIds.has(event.id)
    );
    const hiddenMemoryNoise = records.filter((event) =>
      (event.message_type || "").toUpperCase() === "ALERT" &&
      routineMemoryNoise(event) && !alertBaselineIds.has(event.id)
    );
    const alertGroups = groupAlertRecords(nativeAlerts);
    byId("monitor-event-count").textContent = `${records.length} native record${records.length === 1 ? "" : "s"} in scope`;
    const alertCount = byId("monitor-alert-count");
    alertCount.textContent = String(alertGroups.length);
    alertCount.title = `${nativeAlerts.length} visible native alert records; ${hiddenMemoryNoise.length} routine workload memory teardown records remain in Activity`;
    alertCount.setAttribute("aria-label", `${alertGroups.length} alert groups containing ${nativeAlerts.length} native alert records`);
    byId("monitor-history-state").textContent = historyText();
    const newlyReceived = pauseBaselineIds
      ? api.events.filter((event) => !pauseBaselineIds.has(event.id)).length : 0;
    byId("monitor-pause-count").textContent = paused
      ? `Paused · ${newlyReceived} new record${newlyReceived === 1 ? "" : "s"} received` : "";
    if (rawDialog.open) return;

    const newestId = records[records.length - 1]?.id || "";
    const feedKey = [
      records.length, newestId, visibleMarkers.length, visibleMarkers.at(-1)?.runId || "",
      selectedEventId || "", scopePicker.value, api.story, displayRun()?.runId || "",
      displayRun()?.serverState?.phase || "", displayRun()?.data?.status || "",
      api.status?.collector?.state || "", paused
    ].join("|");
    if (feedKey === renderedFeedKey) return;
    renderedFeedKey = feedKey;
    const wasAtTop = stream.scrollTop <= 8;
    const anchor = wasAtTop ? null : [...stream.querySelectorAll("[data-event-id]")].find((node) =>
      node.getBoundingClientRect().bottom > stream.getBoundingClientRect().top + 2
    );
    const anchorId = anchor?.dataset.eventId;
    const anchorTop = anchor?.getBoundingClientRect().top;
    const sorted = [...records].sort((a, b) => sourceTime(b) - sourceTime(a));
    const groups = groupRecords(sorted);
    const selected = selectedEventId && records.find((event) => event.id === selectedEventId);
    if (selected && !groups.some((group) => group.events.some((event) => event.id === selected.id))) {
      groups.unshift({ events: [selected] });
    }
    const items = [
      ...groups.map((group) => ({ time: sourceTime(group.events[0]), node: groupedRow(group) })),
      ...visibleMarkers.map((marker) => ({
        time: Date.parse(marker.startedAt) || 0, node: markerRow(marker),
      })),
    ].sort((a, b) => b.time - a.time);
    const fragment = document.createDocumentFragment();
    if (!items.length) {
      fragment.append(element("p", "monitor-empty", api.status?.collector?.state === "reading"
        ? "No native activity for this workload yet. The collector is reading; a quiet workload is normal."
        : "No native activity in this scope. Check collector and source status above."));
    } else {
      items.forEach((item) => fragment.append(item.node));
    }
    stream.replaceChildren(fragment);
    if (wasAtTop) {
      stream.scrollTop = 0;
    } else if (anchorId && anchorTop != null) {
      const replacement = [...stream.querySelectorAll("[data-event-id]")].find((node) => node.dataset.eventId === anchorId);
      if (replacement) stream.scrollTop += replacement.getBoundingClientRect().top - anchorTop;
    }

    const alertFragment = document.createDocumentFragment();
    if (hiddenMemoryNoise.length) {
      alertFragment.append(element(
        "p", "monitor-empty monitor-filter-note",
        `${hiddenMemoryNoise.length} routine memory teardown alert${hiddenMemoryNoise.length === 1 ? " is" : "s are"} hidden from Alerts; raw Argus records remain in Activity.`
      ));
    }
    if (!nativeAlerts.length) {
      alertFragment.append(element("p", "monitor-empty", alertViewReset
        ? "No new relevant native alerts in this view. Earlier records remain in the activity feed."
        : "No relevant native alerts in this view. Monitoring is active; known runtime noise remains in the activity feed."));
    } else {
      alertGroups.forEach((group) => alertFragment.append(
        group.events.length > 1 && group.events[0].activity_name === "Executable Permissions Removed"
          ? repeatedAlertGroup(group) : alertCard(group.events[0])
      ));
    }
    alerts.replaceChildren(alertFragment);
  }

  function renderConsole() {
    renderHealth();
    renderDescription();
    renderRun();
    renderRunComparison();
    renderAgentChecks();
    renderPanels();
  }

  window.renderMonitorConsole = () => {
    if (renderTimer) return;
    renderTimer = setTimeout(() => {
      renderTimer = null;
      renderConsole();
    }, 80);
  };
  window.onMonitorHistoryGap = (gap) => {
    historyGap = "Stream replay gap: " + (gap?.reason || "some records may be unavailable") + ".";
    renderedFeedKey = "";
    window.renderMonitorConsole();
  };

  runButton.addEventListener("click", async () => {
    const item = selectedAction();
    if (!item || actionReadiness()) return;
    const story = api.story;
    const runId = api.createRunId();
    const startedAt = new Date().toISOString();
    localRun = {
      pending: true, runId, startedAt, story, kind: story === "agent" ? "agent" : "scenario",
      scenarioId: story === "agent" ? item.id === "baseline" ? "agent-baseline" : "host-access-attempt" : item.id,
      profile: story === "agent" ? item.id : null,
      workload: story === "agent" ? "argus-gtc-agent" : workloadTarget,
    };
    markers.push({ runId, story, label: item.label, workload: localRun.workload, startedAt });
    markers = markers.slice(-20);
    renderedFeedKey = "";
    renderConsole();
    try {
      if (story === "agent") {
        await api.runAgentProfile(item.id, { scenarioRunId: runId });
      } else {
        await api.runScenario(item.id, { scenarioRunId: runId });
      }
      await api.loadTimelineHistory();
      await api.refreshServerRunState();
    } catch (error) {
      localRun.error = error.message || "Demo action failed";
    } finally {
      localRun.pending = false;
      localRun.lost = api.run?.runId !== runId;
      renderConsole();
    }
  });

  byId("monitor-stop-btn").addEventListener("click", () => {
    if (api.story !== "workload") return;
    const task = api.runControlAction("/api/contain");
    renderConsole();
    task.finally(renderConsole);
  });
  byId("monitor-restore-btn").addEventListener("click", () => {
    if (api.story !== "workload") return;
    const task = api.runControlAction("/api/reset");
    renderConsole();
    task.finally(renderConsole);
  });

  byId("monitor-pause").addEventListener("click", () => {
    paused = !paused;
    if (paused) {
      frozenRecords = api.events;
      frozenMarkers = [...markers];
      frozenRun = currentRun() ? JSON.parse(JSON.stringify(currentRun())) : null;
      pauseBaselineIds = new Set(frozenRecords.map((event) => event.id));
    } else {
      frozenRecords = null;
      frozenMarkers = null;
      frozenRun = null;
      pauseBaselineIds = null;
    }
    byId("monitor-pause").textContent = paused ? "Resume" : "Pause";
    byId("monitor-pause").setAttribute("aria-pressed", String(paused));
    renderedFeedKey = "";
    renderConsole();
  });

  scopePicker.addEventListener("change", () => {
    renderedFeedKey = "";
    renderConsole();
  });
  storyPicker.addEventListener("change", () => {
    scopePicker.value = "selected";
    if (paused) {
      paused = false;
      frozenRecords = null;
      frozenMarkers = null;
      frozenRun = null;
      pauseBaselineIds = null;
      byId("monitor-pause").textContent = "Pause";
      byId("monitor-pause").setAttribute("aria-pressed", "false");
    }
    resetAlertViewForSelection();
    selectedEventId = null;
    renderedFeedKey = "";
    renderChoices();
    renderConsole();
  });
  rawDialog.addEventListener("close", () => {
    renderedFeedKey = "";
    renderConsole();
  });
  setInterval(window.renderMonitorConsole, 5000);
  renderChoices();
  renderConsole();
  loadCatalog();
})();
