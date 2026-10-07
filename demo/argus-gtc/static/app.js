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
const storySelect = document.getElementById("story-select");
const connectionState = document.getElementById("connection-state");
const feedFreshness = document.getElementById("feed-freshness");
const legacyConnectionState = document.getElementById("legacy-connection-state");
const legacyFeedState = document.getElementById("legacy-feed-state");
const guidedActionButton = document.getElementById("guided-action");
const guidedRunState = document.getElementById("run-state");
const guidedEvidenceList = document.getElementById("guided-evidence-list");
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
  "exec-memory": ["argus-gtc-exec_memory"],
  "phone-home": ["argus-gtc-phone_home"],
  "reverse-shell": ["argus-gtc-reverse_shell", "argus-gtc-reverse-shell", "/dev/tcp/", "bash -i"],
  "shell-history": ["argus-gtc-shell_history", "argus-gtc-shell-history", "histfile", "history -c"],
  "decoy-modify": ["argus-gtc-decoy_modify", "argus-gtc-decoy-modify", "tampered-by-demo"],
  "network-burst": ["argus-gtc-network_burst", "argus-gtc-network-burst", "/dev/zero", "nc -w"],
  "compute-simulation": ["argus-gtc-compute_simulation", "argus-gtc-compute-simulation", "compute-done"],
  "agent-baseline": [],
  "host-access-attempt": ["open_demo_shell", "argus-gtc-agent-shell-", "bash --noprofile --norc -i", "/dev/tcp/"],
};

const SCENARIO_LABELS = {
  "audit-evasion": "Audit Evasion Attempt (demo correlation)",
  discovery: "Discovery (demo classification)",
  "exec-memory": "Executable Memory (demo correlation)",
  "phone-home": "Phone Home (demo correlation)",
  "reverse-shell": "Reverse Shell Simulation (demo classification)",
  "shell-history": "Shell History Tampering (demo classification)",
  "decoy-modify": "Decoy File Modification (demo classification)",
  "network-burst": "Network Burst (demo classification)",
  "compute-simulation": "Compute Simulation (demo classification)",
  "agent-baseline": "AI Agent Baseline (demo correlation)",
  "host-access-attempt": "Kata Agent Demo Shell (demo correlation)",
};

const SCENARIO_POD_PREFIXES = {
  "audit-evasion": ["invisible-vm"],
  discovery: ["invisible-vm"],
  "exec-memory": ["invisible-vm"],
  "phone-home": ["invisible-vm", "scenario-sink"],
  "compute-simulation": ["invisible-vm"],
  "shell-history": ["invisible-vm"],
  "decoy-modify": ["invisible-vm"],
  "reverse-shell": ["invisible-vm", "scenario-sink"],
  "network-burst": ["invisible-vm", "scenario-sink"],
  "agent-baseline": ["argus-gtc-agent"],
  "host-access-attempt": ["argus-gtc-agent"],
};
const DEMO_POD_PREFIXES = ["invisible-vm", "scenario-sink", "argus-gtc-agent"];
const SCENARIO_NATIVE_ALERTS = {
  "audit-evasion": ["Shell History Disabled", "Shell History Cleared"],
  "reverse-shell": ["Reverse Shell Detected"],
  "host-access-attempt": ["Reverse Shell Detected"],
};
const SCENARIO_NATIVE_EVENTS = {
  "exec-memory": "New Executable Anonymous Memory Mapped",
  "phone-home": "Network Connection Created",
};
const SCENARIO_NATIVE_EVENT_SEVERITIES = {
  "exec-memory": "WARNING",
  "phone-home": "INFO",
};

const STORY_STORAGE_KEY = "argus-demo-selected-story";
const GUIDED_STAGES = ["Setup", "Action", "Observation", "Result"];
const GUIDED_STORIES = {
  workload: {
    label: "Workload security",
    workload: "invisible-vm",
    scenes: [
      {
        stage: 0,
        title: "Show the environment",
        description: "This application runs inside an isolated Kata VM. Argus runs separately on the BlueField DPU and observes workload activity without software installed in the guest.",
        purpose: "Start with the workload and independent observer. Then run a bounded action and review what Argus reports.",
        action: "Start demo · Show activity inside the VM",
        hint: "Runs the bounded discovery scenario in invisible-vm.",
        scenario: "discovery",
      },
      {
        stage: 1,
        title: "Simulate suspicious activity",
        description: "We open a short remote shell session inside invisible-vm to a controlled demo destination. The shell runs inside this selected workload.",
        purpose: "A completed action and a native Argus detection are separate results. A matching HIGH alert appears only if Argus emits it.",
        action: "Simulate a remote shell",
        hint: "Uses the existing bounded reverse-shell scenario and local demo sink.",
        scenario: "reverse-shell",
      },
      {
        stage: 2,
        title: "Review the independent observation",
        description: "Argus observes process and socket activity from the BlueField DPU. OpenShift supplies the workload identity that connects the event to invisible-vm.",
        purpose: "The evidence card keeps action completion, observed activity, and native alert status separate.",
        action: "Refresh evidence",
        hint: "Refreshes status and retained events; it does not repeat the scenario.",
        refresh: true,
      },
      {
        stage: 3,
        title: "Respond and recover",
        description: "An operator can stop the invisible-vm demo workload and restore it after the response. The DPU observer remains a separate service.",
        purpose: "The response status follows observed pod state. A scale request by itself is not shown as stopped or restored.",
        action: "Refresh workload status",
        hint: "Stop and restore controls name their target below.",
        refresh: true,
        response: true,
      },
    ],
  },
  agent: {
    label: "AI agent behavior",
    workload: "argus-gtc-agent",
    scenes: [
      {
        stage: 0,
        title: "Start with a normal request",
        description: "The separate AI application runs in its own Kata VM. It is an application agent, not a security agent installed inside the guest.",
        purpose: "A status-summary request is the baseline. No shell-tool call is the expected result, so shell checks are not applicable.",
        action: "Ask for a status summary",
        hint: "Runs the baseline profile on argus-gtc-agent.",
        profile: "baseline",
      },
      {
        stage: 1,
        title: "Request bounded tool use",
        description: "We explicitly ask the AI agent to open a short demo shell session inside its own isolated workload.",
        purpose: "The authenticated tool report, listener response, Argus observation, and native alert are recorded as separate facts.",
        action: "Ask the AI agent to open a demo shell",
        hint: "Uses the fixed demo destination and the agent's bounded shell tool.",
        profile: "host-reachability",
      },
      {
        stage: 2,
        title: "Review independent evidence",
        description: "Argus runs separately on the BlueField DPU. It may report process or socket activity from argus-gtc-agent.",
        purpose: "A TCP connection alone does not prove a working shell. The listener must record the expected response; a native alert must be present in Argus evidence.",
        action: "Refresh evidence",
        hint: "Refreshes status and retained events; it does not repeat the agent request.",
        refresh: true,
      },
      {
        stage: 2,
        title: "Run the pasted-note example",
        description: "The current workflow asks the agent to complete a pasted maintenance note that requests the same bounded tool use.",
        purpose: "This is note-driven tool use under the current instructions. It does not establish that the model crossed a trust boundary.",
        action: "Run the pasted-note example",
        hint: "Optional comparison run; a missing tool call does not by itself prove a deliberate refusal.",
        profile: "note-driven",
      },
      {
        stage: 3,
        title: "Recap what happened",
        description: "Separate what the AI agent did, what the controlled listener confirmed, what Argus observed, and whether Argus emitted a native alert.",
        purpose: "No tool call or missing telemetry remains visible as a missing result; neither is promoted to detection or success.",
        action: "Refresh evidence",
        hint: "The response controls for invisible-vm do not apply to the AI workload.",
        refresh: true,
      },
    ],
  },
};

function readSelectedStory() {
  try {
    return localStorage.getItem(STORY_STORAGE_KEY) === "agent" ? "agent" : "workload";
  } catch (_error) {
    return "workload";
  }
}

let activeStory = readSelectedStory();
let activeSceneIndex = 0;
let guidedRuns = { workload: null, agent: null };
let workloadResponseState = "Not requested";
let streamState = "connecting";
let streamReconnectTimer = null;
let agentIsReady = false;
let appServerInstanceId = null;

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
let activeScenarioTarget = null;
let scenarioRunBaselineIds = new Set();
let demoActionInProgress = false;

function setStreamState(state, label) {
  const value = label || ({ connected: "Connected", connecting: "Connecting", disconnected: "Reconnecting" }[state] || "Connection unknown");
  if (connectionState) {
    connectionState.dataset.state = state;
    connectionState.lastElementChild.textContent = value;
  }
  if (legacyConnectionState?.lastElementChild) {
    legacyConnectionState.lastElementChild.textContent = value.toLowerCase();
  }
  if (legacyFeedState) {
    legacyFeedState.dataset.state = state;
    const label = document.getElementById("legacy-stream-label");
    if (label) label.textContent = value;
  }
  streamState = state;
}

function updateFeedFreshness(value) {
  const freshness = value || "Unknown";
  if (feedFreshness) {
    feedFreshness.textContent = freshness;
    feedFreshness.dataset.freshness = freshness.toLowerCase().replaceAll(" ", "-");
  }
  const legacyFreshness = document.getElementById("legacy-freshness");
  if (legacyFreshness) legacyFreshness.textContent = freshness;
}

function currentGuidedStory() {
  return GUIDED_STORIES[activeStory] || GUIDED_STORIES.workload;
}

function currentGuidedScene() {
  const scenes = currentGuidedStory().scenes;
  return scenes[Math.max(0, Math.min(activeSceneIndex, scenes.length - 1))];
}

function readRunReference() {
  try {
    return JSON.parse(sessionStorage.getItem("argus-demo-run-reference") || "null");
  } catch (_error) {
    return null;
  }
}

function saveRunReference(run) {
  try {
    sessionStorage.setItem("argus-demo-run-reference", JSON.stringify({
      runId: run.runId,
      story: run.story,
      scenarioId: run.scenarioId,
      profile: run.profile || null,
      serverInstanceId: appServerInstanceId,
    }));
  } catch (_error) {
    // The server-owned run state remains available even if session storage is disabled.
  }
}

function storyForServerRun(run) {
  return Boolean(
    run.profile || run.scenario_id === "agent-baseline" || run.scenario_id === "host-access-attempt"
  )
    ? "agent"
    : "workload";
}

function hydrateServerRun(runState, allowStorySwitch = false) {
  const story = storyForServerRun(runState);
  const isAgent = story === "agent";
  const snapshot = runState.result || null;
  const profile = runState.profile || snapshot?.profile || null;
  const run = {
    kind: isAgent ? "agent" : "scenario",
    story,
    scenarioId: runState.scenario_id || snapshot?.scenario_id,
    runId: runState.run_id,
    workload: runState.workload,
    profile,
    serverState: runState,
    running: !["complete", "failed"].includes(runState.phase),
    data: snapshot,
    error: runState.phase === "failed" ? runState.message : null,
    actionLabel: runState.message,
  };
  guidedRuns[story] = run;
  if (allowStorySwitch) {
    activeStory = story;
    storySelect.value = story;
    const scenes = GUIDED_STORIES[story].scenes;
    const matchingIndex = scenes.findIndex((scene) =>
      scene.scenario === run.scenarioId || scene.profile === run.profile
    );
    activeSceneIndex = matchingIndex >= 0 ? matchingIndex : 0;
  }
  saveRunReference({ ...run, story });
  renderGuidedScene();
}

function hasGuidedRunInProgress() {
  return Object.values(guidedRuns).some((run) => run?.running);
}

async function refreshServerRunState(initial = false) {
  try {
    const response = await fetch("/api/demo/run-state", { cache: "no-store" });
    const data = await parseJsonResponse(response);
    const reference = readRunReference();
    const runState = data.run;
    const instanceChanged = Boolean(reference?.serverInstanceId && reference.serverInstanceId !== data.server_instance_id);
    appServerInstanceId = data.server_instance_id || null;

    if (initial && reference && (instanceChanged || !runState || runState.run_id !== reference.runId)) {
      const story = reference.story === "agent" ? "agent" : "workload";
      const scenarioId = reference.scenarioId || "unknown";
      guidedRuns[story] = {
        story,
        runId: reference.runId,
        scenarioId,
        profile: reference.profile,
        workload: story === "agent" ? "argus-gtc-agent" : "invisible-vm",
        kind: story === "agent" ? "agent" : "scenario",
        lost: true,
      };
      activeStory = story;
      storySelect.value = story;
      const scenes = GUIDED_STORIES[story].scenes;
      const index = scenes.findIndex((scene) => scene.scenario === scenarioId || scene.profile === reference.profile);
      activeSceneIndex = index >= 0 ? index : 0;
      renderGuidedScene();
      return;
    }

    if (!runState) {
      const localRun = guidedRuns[activeStory];
      if (localRun?.running && localRun.serverState) {
        localRun.lost = true;
        localRun.running = false;
        renderGuidedResult();
      }
      return;
    }

    const story = storyForServerRun(runState);
    const localRun = guidedRuns[story];
    if (initial || !localRun || localRun.runId === runState.run_id || !localRun.running) {
      hydrateServerRun(runState, initial);
    }
  } catch (_error) {
    // Retain the current display; a later poll can recover server-owned progress.
  }
}

function renderGuidedScene() {
  const story = currentGuidedStory();
  const scene = currentGuidedScene();
  const isAgent = activeStory === "agent";
  const friendlyWorkload = isAgent ? "argus-gtc-agent · AI application" : "invisible-vm";
  document.getElementById("story-kicker").textContent = `Guided story · ${story.label}`;
  document.getElementById("selected-workload").textContent = friendlyWorkload;
  document.getElementById("result-workload").textContent = friendlyWorkload;
  document.getElementById("response-target").textContent = "invisible-vm";
  document.getElementById("diagram-workload").textContent = story.workload;
  document.getElementById("diagram-workload-detail").textContent = isAgent
    ? "AI application agent · not a guest security agent"
    : "Application activity · no in-guest security agent";
  document.getElementById("diagram-destination").textContent = isAgent
    ? "No AI workload stop/restore control is available"
    : "Operator can stop or restore invisible-vm";
  document.getElementById("diagram-caption").textContent = isAgent
    ? "The canary is the bounded action destination. Argus observes separately from the DPU."
    : "The demo listener is an action destination. It is separate from the DPU observer.";
  document.getElementById("scene-step-label").textContent = scene.stage === 2 && scene.profile === "note-driven"
    ? "Optional example"
    : GUIDED_STAGES[scene.stage];
  document.getElementById("scene-heading").textContent = scene.title;
  document.getElementById("scene-description").textContent = scene.description;
  document.getElementById("scene-purpose").textContent = scene.purpose;
  document.getElementById("action-hint").textContent = scene.hint;
  guidedActionButton.textContent = scene.action;
  guidedActionButton.hidden = Boolean(scene.response && isAgent);
  guidedActionButton.disabled = demoActionInProgress || hasGuidedRunInProgress() || (isAgent && Boolean(scene.profile) && !agentIsReady);
  document.getElementById("response-panel").hidden = !scene.response || isAgent;
  document.getElementById("scene-number").textContent = `Scene ${activeSceneIndex + 1} of ${story.scenes.length}`;
  document.getElementById("scene-prev").disabled = activeSceneIndex === 0;
  document.getElementById("scene-next").disabled = activeSceneIndex >= story.scenes.length - 1;
  const progress = document.getElementById("scene-progress");
  progress.replaceChildren();
  const activeStage = scene.stage;
  GUIDED_STAGES.forEach((stage, index) => {
    const item = document.createElement("li");
    item.dataset.number = String(index + 1);
    item.textContent = stage;
    if (index === activeStage) item.setAttribute("aria-current", "step");
    else if (index < activeStage) item.dataset.complete = "true";
    progress.appendChild(item);
  });
  renderGuidedResult();
}

function setGuidedActionState(state, label) {
  if (!guidedRunState) return;
  guidedRunState.dataset.state = state;
  guidedRunState.textContent = label;
}

function syncActionButtons() {
  const actionLocked = demoActionInProgress || hasGuidedRunInProgress();
  document.querySelectorAll("button[data-scenario], button[data-agent-profile], #guided-action, #contain-btn, #reset-btn, #guided-contain-btn, #guided-reset-btn").forEach((button) => {
    if (button.matches("[data-agent-profile]")) {
      button.disabled = actionLocked || !agentIsReady;
    } else if (button === guidedActionButton) {
      const scene = currentGuidedScene();
      button.disabled = actionLocked || (activeStory === "agent" && Boolean(scene.profile) && !agentIsReady);
    } else {
      button.disabled = actionLocked;
    }
  });
}

function setGuidedFact(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value;
}

function relevantRunEvents(run) {
  if (!run?.runId) return [];
  return retainedEvents().filter((event) => event.scenario_run_id === run.runId);
}

function renderGuidedEvidence(events, fallbackEvent) {
  if (!guidedEvidenceList) return;
  guidedEvidenceList.replaceChildren();
  const visibleEvents = events.length ? events.slice(-5).reverse() : fallbackEvent ? [fallbackEvent] : [];
  if (!visibleEvents.length) {
    const empty = document.createElement("p");
    empty.textContent = "No run-correlated event is available. Open Technical view to inspect retained telemetry and matching criteria.";
    guidedEvidenceList.appendChild(empty);
    return;
  }
  visibleEvents.forEach((event) => {
    const row = document.createElement("article");
    row.className = "guided-evidence-item";
    const title = document.createElement("strong");
    title.textContent = event.activity_name || "Argus activity";
    const classification = document.createElement("span");
    classification.textContent = `${event.message_type || "EVENT"} · ${event.severity || "severity unavailable"}`;
    const context = document.createElement("span");
    context.textContent = `${event.pod_name || "workload unavailable"} · ${event.occurred_at || event.received_at || "time unavailable"}`;
    row.append(title, classification, context);
    if (event.id) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "secondary compact";
      button.textContent = "View technical evidence";
      button.addEventListener("click", () => openEventDialog(event, button));
      row.appendChild(button);
    }
    guidedEvidenceList.appendChild(row);
  });
}

function renderGuidedResult() {
  const run = guidedRuns[activeStory];
  const isAgent = activeStory === "agent";
  const response = isAgent ? "Not applicable · AI workload response is unsupported" : workloadResponseState;
  setGuidedFact("fact-response", response);
  if (!run) {
    setGuidedActionState("ready", "Ready");
    setGuidedFact("fact-action", "Not started");
    setGuidedFact("fact-observation", "Waiting for a run");
    setGuidedFact("fact-alert", "No alert reported");
    document.getElementById("outcome-sentence").textContent = isAgent
      ? "The AI application agent is a separate workload. Choose a scene to make a request and review its independent evidence."
      : "Ready when you are. The result will separate the requested action from Argus evidence.";
    renderGuidedEvidence([], null);
    return;
  }
  if (run.lost) {
    setGuidedActionState("error", "Run state unavailable");
    setGuidedFact("fact-action", "Unknown after reload");
    setGuidedFact("fact-observation", "Unknown · server no longer has this run");
    setGuidedFact("fact-alert", "Unknown · no result retained");
    document.getElementById("outcome-sentence").textContent = "The server no longer has this run state. Its action and Argus result cannot be confirmed.";
    renderGuidedEvidence([], null);
    return;
  }
  if (run.running) {
    const state = run.serverState || {};
    const startedAt = Date.parse(state.started_at || "") || Date.now();
    const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    const elapsedText = `${elapsed}s elapsed`;
    const actionLabels = {
      running: "Action running",
      tool_authorized: "Bounded tool authorized",
      tool_reported: "Authenticated tool report received",
      completed: "Action completed",
      not_performed: "No tool call reported",
      failed: "Action failed",
    };
    const observationLabels = {
      waiting: `Waiting for matching Argus evidence · ${elapsedText}`,
      observed: "Matching evidence observed",
      not_observed: "No matching evidence observed",
      not_applicable: "Not applicable for this profile",
      not_checked: "This scenario has no server-side evidence check",
    };
    setGuidedActionState("running", `${state.phase === "observation" ? "Checking evidence" : "Action running"} · ${elapsedText}`);
    setGuidedFact("fact-action", actionLabels[state.action_status] || run.actionLabel || "Action in progress");
    setGuidedFact("fact-observation", observationLabels[state.observation_status] || "Waiting for server progress");
    setGuidedFact("fact-alert", "Not available yet");
    document.getElementById("outcome-sentence").textContent = state.message || `${run.actionLabel || "The request"} is running.`;
    renderGuidedEvidence([], null);
    return;
  }
  if (run.error) {
    setGuidedActionState("error", "Action failed");
    setGuidedFact("fact-action", `Failed · ${run.error}`);
    setGuidedFact("fact-observation", "Not evaluated");
    setGuidedFact("fact-alert", "Not evaluated");
    document.getElementById("outcome-sentence").textContent = `The request failed: ${run.error}`;
    renderGuidedEvidence([], null);
    return;
  }

  const data = run.data || {};
  const events = relevantRunEvents(run);
  if (run.kind === "scenario") {
    const nativeEvent = data.native_alert || data.native_event || events.find((event) =>
      isNativeHighAlert(event) && (SCENARIO_NATIVE_ALERTS[run.scenarioId] || []).includes(event.activity_name)
    ) || events.find((event) => (event.message_type || "").toUpperCase() === "EVENT");
    const nativeAlert = data.native_alert || events.find((event) =>
      isNativeHighAlert(event) && (SCENARIO_NATIVE_ALERTS[run.scenarioId] || []).includes(event.activity_name)
    );
    setGuidedActionState("complete", "Action complete");
    setGuidedFact("fact-action", `Completed · ${SCENARIO_LABELS[run.scenarioId] || run.scenarioId}`);
    setGuidedFact("fact-observation", nativeEvent
      ? `Observed · ${nativeEvent.message_type || "EVENT"} · ${nativeEvent.severity || "severity unavailable"} · ${nativeEvent.activity_name || "Argus activity"}`
      : data.status === "no-native-event" || data.status === "no-native-alert"
        ? "No matching Argus evidence arrived within the wait window"
        : events.length
          ? `${events.length} run-correlated Argus record${events.length === 1 ? "" : "s"} available`
          : "No run-correlated Argus evidence is available in the response");
    setGuidedFact("fact-alert", nativeAlert
      ? `${nativeAlert.severity || "HIGH"} · ${nativeAlert.activity_name || "Native alert"}`
      : (SCENARIO_NATIVE_ALERTS[run.scenarioId] || []).length
        ? "No matching native ALERT/HIGH observed"
        : "Not required for this action");
    document.getElementById("outcome-sentence").textContent = nativeAlert
      ? `Argus raised a ${nativeAlert.severity || "native"} alert: ${nativeAlert.activity_name}.`
      : nativeEvent && (SCENARIO_NATIVE_ALERTS[run.scenarioId] || []).length
        ? `Argus observed ${nativeEvent.activity_name || "activity"}. No matching native ALERT/HIGH was observed.`
      : data.status === "no-native-event" || data.status === "no-native-alert"
        ? `The action completed. ${data.message || "No matching Argus evidence arrived within the wait window."}`
        : nativeEvent
          ? `Argus observed ${nativeEvent.activity_name || "activity"} from ${nativeEvent.pod_name || run.workload}.`
          : events.length
            ? `The action completed. ${events.length} run-correlated Argus record${events.length === 1 ? " is" : "s are"} available below.`
            : "The action completed. No run-correlated Argus record is available in the response.";
    if (!run.pinnedEvidenceIds?.length && events.length) run.pinnedEvidenceIds = events.slice(-5).map((event) => event.id).filter(Boolean);
    const pinned = run.pinnedEvidenceIds.length
      ? events.filter((event) => run.pinnedEvidenceIds.includes(event.id))
      : events;
    renderGuidedEvidence(pinned, nativeEvent);
    return;
  }

  const baseline = run.profile === "baseline";
  const toolCalled = Boolean(data.authenticated_tool_report_observed && data.tool_result?.source_port);
  const argusEvent = data.argus_host_attempt_event || events.find((event) =>
    ["EVENT", "ALERT"].includes((event.message_type || "").toUpperCase())
  );
  const nativeAlert = Boolean(data.native_argus_alert) && argusEvent &&
    (argusEvent.message_type || "").toUpperCase() === "ALERT" &&
    (argusEvent.severity || "").toUpperCase() === "HIGH";
  const workingShell = Boolean(data.working_shell);
  setGuidedActionState("complete", "Request complete");
  setGuidedFact("fact-action", baseline
    ? data.status === "no-tool-call"
      ? "No shell-tool call recorded · expected baseline"
      : "Unexpected shell-tool activity · inspect details"
    : toolCalled
      ? `Authenticated tool report · ${data.tool_result.outcome || "outcome unavailable"}`
      : "No authenticated shell-tool report recorded");
  setGuidedFact("fact-observation", baseline
    ? "Not applicable · no shell action was requested"
    : argusEvent
      ? `Observed · ${argusEvent.message_type || "EVENT"} · ${argusEvent.severity || "severity unavailable"} · ${argusEvent.activity_name || "Argus activity"}`
      : data.policy_drop_observed
        ? "No matching Argus event · OVN recorded a separate policy deny"
        : "No matching Argus event observed during this run");
  setGuidedFact("fact-alert", baseline
    ? "Not applicable · baseline did not request a shell"
    : nativeAlert
      ? `HIGH · ${argusEvent.activity_name}`
      : argusEvent
        ? `No native HIGH alert · Argus reported ${argusEvent.message_type || "EVENT"}/${argusEvent.severity || "unknown"}`
        : "No matching native alert confirmed");
  let sentence;
  if (baseline && data.status === "no-tool-call") {
    sentence = "No shell-tool call was recorded. Shell-specific checks are not applicable to this normal request.";
  } else if (workingShell && argusEvent) {
    sentence = "The canary confirmed the shell session. Argus independently observed matching workload activity.";
  } else if (workingShell) {
    sentence = "The canary confirmed the shell session. No matching Argus event arrived during this run.";
  } else if (argusEvent) {
    sentence = `Argus observed ${argusEvent.activity_name || "activity"}. The listener did not confirm a working shell.`;
  } else if (data.policy_drop_observed) {
    sentence = "OVN recorded a matching policy deny. A network timeout alone would not prove a policy block.";
  } else if (data.status === "no-tool-call") {
    sentence = "No shell-tool call was recorded. The agent response is available in Technical view; this alone does not establish a deliberate refusal.";
  } else if (toolCalled) {
    sentence = "An authenticated tool report was recorded. The listener did not confirm a working shell.";
  } else {
    sentence = data.message || "The run did not produce enough evidence to confirm a shell action or Argus observation.";
  }
  if (nativeAlert) sentence = `Argus raised a HIGH alert: ${argusEvent.activity_name}.`;
  document.getElementById("outcome-sentence").textContent = sentence;
  if (!run.pinnedEvidenceIds?.length && events.length) run.pinnedEvidenceIds = events.slice(-5).map((event) => event.id).filter(Boolean);
  const pinned = run.pinnedEvidenceIds.length
    ? events.filter((event) => run.pinnedEvidenceIds.includes(event.id))
    : events;
  renderGuidedEvidence(pinned, argusEvent);
}

function pillClass(value) {
  if (!value) return "";
  const v = String(value).toLowerCase();
  if (["ready", "live", "allocated", "ok", "contained", "stopped", "restored"].includes(v)) return "ok";
  if (["pending", "unknown", "degraded", "stopping", "restoring"].includes(v)) return "warn";
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
  updateFeedFreshness(status.argus_freshness || "Unknown");
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
  kataBits.push(coverage.guest_agent ? "guest agent" : "no in-guest security agent");
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

function isRuntimeNoise(event) {
  if (isHypervisorNoise(event)) return true;
  const hay = [event.process_name, event.process_command].filter(Boolean).join(" ").toLowerCase();
  if (/multiprocessing[.-]fork|multiprocessing\.spawn|spawn_main\(|resource_tracker/.test(hay)) return true;
  if ((event.activity_name || "") === "Reverse Shell Detected") {
    if (/argus-gtc-agent-shell-|\/dev\/tcp\//.test(hay)) return false;
    if (/nat serve|\/usr\/bin\/pod(?:\s|$)/.test(hay)) return true;
  }
  return false;
}

function isDemoWorkload(event, scenarioId) {
  if (isRuntimeNoise(event)) return false;
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

function matchesNativeEventScenario(event, scenarioId) {
  if (!SCENARIO_NATIVE_EVENTS[scenarioId]) return false;
  if ((event.message_type || "").toUpperCase() !== "EVENT") return false;
  if ((event.severity || "").toUpperCase() !== SCENARIO_NATIVE_EVENT_SEVERITIES[scenarioId]) return false;
  if (event.activity_name !== SCENARIO_NATIVE_EVENTS[scenarioId]) return false;
  if (!podMatchesPrefixes(event.pod_name, ["invisible-vm"])) return false;
  if (scenarioId === lastClickScenario && activeScenarioRunId) {
    const occurred = Date.parse(event.occurred_at || "");
    if (!occurred || occurred < (activeScenarioTarget?.startedAt || lastClickAt)) return false;
    if (activeScenarioTarget?.pod && event.pod_name !== activeScenarioTarget.pod) return false;
    const markerRun = eventHaystack(event).match(/argus-gtc-(?:exec_memory|phone_home)-([0-9a-f]{12})/);
    if (markerRun && markerRun[1] !== activeScenarioRunId) return false;
    if (scenarioId === "exec-memory" && !eventHaystack(event).includes(`argus-gtc-exec_memory-${activeScenarioRunId}`)) return false;
  }
  if (scenarioId === "phone-home") {
    if (!["TCP", "6"].includes(String(event.protocol || "").toUpperCase())) return false;
    if (Number(event.destination_port) !== (activeScenarioTarget?.sinkPort || 4444)) return false;
    if (activeScenarioTarget?.sinkIP && event.destination_ip !== activeScenarioTarget.sinkIP) return false;
  }
  return event.scenario_id === scenarioId ||
    (lastClickScenario === scenarioId && (activeScenarioRunId ? true : inClickWindow(event)));
}

function isDemoRelevant(event) {
  if (isRuntimeNoise(event)) return false;
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
  if (isRuntimeNoise(event)) return false;
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
  if (SCENARIO_NATIVE_EVENTS[scenarioId] && event.activity_name === SCENARIO_NATIVE_EVENTS[scenarioId]) {
    return matchesNativeEventScenario(event, scenarioId);
  }
  if (isNativeAlert(event) && expectedNativeAlerts.length) {
    return matchesNativeScenario(event, scenarioId);
  }
  if (matchesNativeScenario(event, scenarioId)) return true;
  if (matchesNativeEventScenario(event, scenarioId)) return true;
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
  if (isRuntimeNoise(event)) return false;
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
  const correlatedAlert = type === "CORRELATED_ALERT";
  el.className = `event ${nativeAlert ? "alert" : ""} ${nativeHigh ? "high" : ""} ${correlatedAlert ? "correlated-alert" : ""}`;
  const origin = nativeHigh
    ? "native Argus ALERT/HIGH"
    : nativeAlert
      ? `native Argus ALERT/${severity || "UNKNOWN"} (not native HIGH)`
      : correlatedAlert
      ? "correlated demo alert (Argus TCP event + agent report + OVN policy)"
      : event.evidence_source === "ovn-acl-audit"
      ? "OVN-Kubernetes ACL audit (not Argus telemetry)"
      : event.demo_label
      ? "native Argus EVENT (demo correlated)"
      : "native Argus EVENT";
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
  const connection = document.createElement("div");
  connection.className = "detail";
  if (event.destination_ip && event.destination_port) {
    connection.textContent = `${event.protocol || "TCP"} ${event.connection_state || "connection"} · ${event.source_ip || "?"}:${event.source_port || "?"} → ${event.destination_ip}:${event.destination_port}`;
  }
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
  el.append(meta, title, process, context);
  if (connection.textContent) el.append(connection);
  el.append(actions);
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
  const correlatedAlerts = filtered.filter(
    (event) => (event.message_type || "").toUpperCase() === "CORRELATED_ALERT"
  ).length;
  const demoCorrelated = filtered.filter((event) => Boolean(event.demo_label)).length;
  timelineStory.textContent =
    `Current view: ${operationEvents} operation event${operationEvents === 1 ? "" : "s"} observed · ` +
    `${nativeAlerts} native alert${nativeAlerts === 1 ? "" : "s"} triggered · ` +
    `${nativeHigh} native HIGH · ${correlatedAlerts} correlated demo alert${correlatedAlerts === 1 ? "" : "s"} · ` +
    `${demoCorrelated} demo-correlated. ALERT means native Argus detection; CORRELATED_ALERT joins demo evidence sources.`;

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

  const incoming = eventQueue.splice(0, 250);
  incoming.forEach(rememberEvent);
  trimBuffers();
  renderTimeline();
  const currentRun = guidedRuns[activeStory];
  if (currentRun?.runId && incoming.some((event) => event.scenario_run_id === currentRun.runId)) {
    renderGuidedResult();
  }
  if (eventQueue.length) scheduleFlush();
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(flushEventQueue, FLUSH_INTERVAL_MS);
}

function queueEvent(event) {
  const currentRun = guidedRuns[activeStory];
  if (currentRun?.runId && event?.scenario_run_id === currentRun.runId) {
    rememberEvent(event);
    trimBuffers();
    if (!currentRun.running) renderGuidedResult();
  }
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
  activeScenarioTarget = null;
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
  try {
    const res = await fetch("/api/status");
    const data = await parseJsonResponse(res);
    updateRibbon(data);
  } catch (_error) {
    updateFeedFreshness("Unavailable");
  }
}

async function refreshAgentStatus() {
  const badge = document.getElementById("agent-readiness");
  const buttons = document.querySelectorAll("button[data-agent-profile]");
  try {
    const res = await fetch("/api/agent/status");
    const data = await parseJsonResponse(res);
    const ready = Boolean(data.ready && data.model_configured);
    agentIsReady = ready;
    badge.textContent = ready
      ? `Ready · Kata · ${data.model_name}`
      : !data.model_configured
        ? "Model not configured"
        : data.deployment?.ready && !data.deployment?.kata_runtime
          ? "Agent is not in Kata"
          : "Kata agent pod not ready";
    badge.className = `agent-state ${ready ? "ok" : "warn"}`;
    buttons.forEach((button) => { button.disabled = !ready || demoActionInProgress || hasGuidedRunInProgress(); });
    if (activeStory === "agent" && currentGuidedScene().profile) {
      guidedActionButton.disabled = !ready || demoActionInProgress || hasGuidedRunInProgress();
      if (!ready) document.getElementById("action-hint").textContent = data.message || badge.textContent;
      else document.getElementById("action-hint").textContent = currentGuidedScene().hint;
    }
    if (!ready) {
      document.getElementById("agent-log").textContent = data.message;
    }
  } catch (error) {
    agentIsReady = false;
    badge.textContent = "Agent status unavailable";
    badge.className = "agent-state warn";
    buttons.forEach((button) => { button.disabled = true; });
    if (activeStory === "agent" && currentGuidedScene().profile) {
      guidedActionButton.disabled = true;
      document.getElementById("action-hint").textContent = "Agent readiness could not be checked. Refresh status before running this scene.";
    }
  }
}

async function runScenario(id, options = {}) {
  const scenarioRunId = createScenarioRunId();
  const workload = "invisible-vm";
  setScenarioFilter(id, scenarioRunId);
  demoActionInProgress = true;
  if (options.fromGuided) {
    guidedRuns.workload = {
      kind: "scenario",
      story: "workload",
      scenarioId: id,
      runId: scenarioRunId,
      workload,
      running: true,
      actionLabel: SCENARIO_LABELS[id] || id,
    };
    saveRunReference(guidedRuns.workload);
    renderGuidedResult();
  }
  syncActionButtons();
  actionLog.className = "result-running";
  actionLog.textContent = SCENARIO_NATIVE_ALERTS[id]
    ? `Running ${id}. Waiting up to 45 seconds for a native Argus ALERT/HIGH.`
    : SCENARIO_NATIVE_EVENTS[id]
      ? `Running ${id}. Waiting for ${SCENARIO_NATIVE_EVENTS[id]} from Argus; the controller checks for up to 15 seconds after the action.`
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
    if (SCENARIO_NATIVE_EVENTS[id]) {
      activeScenarioTarget = {
        pod: data.workload_pod || null,
        sinkIP: data.sink_ip || null,
        sinkPort: Number(data.sink_port) || null,
        startedAt: Date.parse(data.started_at || "") || lastClickAt,
      };
      renderTimeline();
    }
    if (options.fromGuided) {
      guidedRuns.workload = {
        ...guidedRuns.workload,
        running: false,
        data,
        finishedAt: Date.now(),
      };
      renderGuidedResult();
    }
    actionLog.className = data.status === "native-alert" || data.status === "native-event"
      ? "result-success"
      : data.status === "no-native-alert" || data.status === "no-native-event"
        ? "result-inconclusive"
        : "";
    if (SCENARIO_NATIVE_EVENTS[id]) {
      const event = data.native_event;
      const summary = event
        ? [
            event.message_type || "EVENT",
            event.severity || "severity unavailable",
            event.activity_name || SCENARIO_NATIVE_EVENTS[id],
            event.pod_name ? `pod=${event.pod_name}` : null,
            event.process_command || event.process_name || null,
            event.source_ip && event.source_port
              ? `source=${event.source_ip}:${event.source_port}`
              : null,
            event.destination_ip && event.destination_port
              ? `destination=${event.destination_ip}:${event.destination_port}`
              : null,
          ].filter(Boolean).join(" · ")
        : "Matching event summary unavailable; inspect the current-run timeline.";
      const verdict = data.status === "native-event"
        ? `Native evidence observed: ${summary}`
        : data.status === "no-native-event"
          ? `No native event observed: ${data.message || SCENARIO_NATIVE_EVENTS[id]}`
          : `Scenario execution: ${data.message || data.status}`;
      actionLog.textContent = `${verdict}\n\n${JSON.stringify(data, null, 2)}`;
    } else {
      actionLog.textContent = JSON.stringify(data, null, 2);
    }
  } catch (error) {
    actionLog.className = "result-failed";
    actionLog.textContent = `Scenario failed: ${error.message}`;
    if (options.fromGuided) {
      guidedRuns.workload = {
        ...guidedRuns.workload,
        running: false,
        error: error.message,
      };
      renderGuidedResult();
    }
  } finally {
    demoActionInProgress = false;
    syncActionButtons();
    await refreshAgentStatus();
  }
}

function renderAgentChain(chain, profile) {
  const list = document.getElementById("agent-chain");
  if (!list) return;
  list.replaceChildren();
  (chain || []).forEach((item) => {
    const row = document.createElement("li");
    const baselineNA = profile === "baseline" && !["instruction", "tool_call"].includes(item.step);
    const expectedAbsent = Boolean(item.expected_absent) || (profile === "baseline" && item.step === "tool_call" && !item.ok);
    const applicable = item.applicable !== false && !baselineNA;
    row.className = !applicable ? "not-applicable" : expectedAbsent ? "expected" : item.ok ? "ok" : "miss";
    if (item.step === "instruction") row.classList.add("chain-instruction");
    const step = document.createElement("span");
    step.className = "chain-step";
    step.textContent = String(item.step || "").replaceAll("_", " ");
    const detail = document.createElement("span");
    detail.className = "chain-detail";
    const label = item.step === "instruction"
      ? `${item.detail || "Input sent"} · exact input is in Technical view`
      : !applicable
        ? "Not applicable for this profile"
        : expectedAbsent
          ? item.detail || "No tool call recorded as expected"
          : item.detail || "";
    detail.textContent = label;
    row.append(step, detail);
    list.appendChild(row);
  });
}

function setAgentPrompt(text) {
  const box = document.getElementById("agent-prompt");
  if (box) box.textContent = text;
}

async function runAgentProfile(profile, options = {}) {
  const scenarioId = profile === "baseline" ? "agent-baseline" : "host-access-attempt";
  const scenarioRunId = createScenarioRunId();
  const apiProfile = profile;
  setScenarioFilter(scenarioId, scenarioRunId);
  const result = document.getElementById("agent-log");
  demoActionInProgress = true;
  if (options.fromGuided) {
    guidedRuns.agent = {
      kind: "agent",
      story: "agent",
      profile,
      scenarioId,
      runId: scenarioRunId,
      workload: "argus-gtc-agent",
      running: true,
      actionLabel: GUIDED_STORIES.agent.scenes[activeSceneIndex]?.action || "AI agent request",
    };
    saveRunReference(guidedRuns.agent);
    renderGuidedResult();
  }
  syncActionButtons();
  result.className = "result-running";
  renderAgentChain([], profile);
  setAgentPrompt("Sending this run to the Kata agent. The exact prompt will appear here.");
  result.textContent = profile === "baseline"
    ? "Baseline: asking the Kata agent for a status summary. It must not open a shell."
    : profile === "host-reachability"
      ? "Authorized demo shell: we tell the Kata agent to call open_demo_shell. Bash stays in that pod. About one minute."
      : "Pasted-note example: the current workflow asks the Kata agent to complete the note using its bounded demo-shell tool.";
  try {
    const res = await fetch("/api/agent-runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profile: apiProfile, scenario_run_id: scenarioRunId }),
    });
    const data = await parseJsonResponse(res);
    if (data.scenario_run_id !== scenarioRunId) {
      throw new Error("agent run correlation mismatch");
    }
    renderAgentChain(data.evidence_chain, profile);
    setAgentPrompt(
      data.instruction
        ? data.instruction
        : "The server did not return the prompt for this run."
    );
    const expectedBaseline = profile === "baseline" && data.status === "no-tool-call";
    const shellObserved = Boolean(data.working_shell && data.argus_host_attempt_observed);
    result.className = expectedBaseline || shellObserved
      ? "result-success"
      : data.status === "tool-called" || data.status === "shell-connected" || profile === "note-driven"
        ? "result-inconclusive"
        : "result-failed";
    const argusEvent = data.argus_host_attempt_event;
    const listenerOutput = (data.listener_session?.output || "").trim();
    const scenarioChecks = profile === "baseline"
      ? [
          `Action: ${expectedBaseline ? "no shell-tool call recorded (expected baseline)" : "unexpected shell-tool activity; inspect the evidence"}`,
          "Shell connection: not applicable to the baseline",
          "Listener response: not applicable to the baseline",
          "Argus shell observation: not applicable to the baseline",
        ]
      : [
          `Agent workload: ${data.kata_runtime_ready ? "Kata RuntimeClass confirmed" : "Kata placement not confirmed"} · pod=${data.agent_pod || "unknown"} · node=${data.agent_node || "unknown"} · RuntimeClass=${data.agent_runtime_class || "unknown"}`,
          `Authenticated tool report: ${data.authenticated_tool_report_observed ? "recorded" : "not recorded"} · ${data.tool_result?.source_ip || "no source"}:${data.tool_result?.source_port || "none"} → ${data.tool_result?.destination_ip || "no destination"}:${data.tool_result?.destination_port || "none"} · outcome=${data.tool_result?.outcome || "no report"}`,
          `Listener proof: ${data.working_shell ? "canary recorded id output" : "no working shell confirmed"} · ${listenerOutput ? listenerOutput.slice(0, 180) : "no listener output"}`,
          `Argus observation: ${argusEvent ? `${argusEvent.message_type || "EVENT"} · ${argusEvent.severity || "unspecified"} · ${argusEvent.activity_name || "activity"} · pod=${argusEvent.pod_name || "not enriched"}` : "no matching native event observed"}`,
          `Native alert: ${data.native_argus_alert && argusEvent?.message_type === "ALERT" && argusEvent?.severity === "HIGH" ? `HIGH · ${argusEvent.activity_name}` : "no matching native ALERT/HIGH confirmed"}`,
          `OVN policy evidence: ${data.policy_drop_observed ? "matching deny recorded by OVN" : "none recorded"}`,
        ];
    result.textContent = [
      `Run ${scenarioRunId} · ${data.status}`,
      ...scenarioChecks,
      data.message,
      `Agent response: ${typeof data.agent_response === "string" ? data.agent_response : JSON.stringify(data.agent_response)}`,
    ].join("\n\n");
    if (options.fromGuided) {
      guidedRuns.agent = {
        ...guidedRuns.agent,
        running: false,
        data,
        finishedAt: Date.now(),
      };
      renderGuidedResult();
    }
  } catch (error) {
    result.className = "result-failed";
    result.textContent = `Agent run failed: ${error.message}`;
    if (options.fromGuided) {
      guidedRuns.agent = { ...guidedRuns.agent, running: false, error: error.message };
      renderGuidedResult();
    }
  } finally {
    demoActionInProgress = false;
    syncActionButtons();
    await refreshAgentStatus();
  }
}

document.querySelectorAll("button[data-scenario]").forEach((btn) => {
  btn.addEventListener("click", () => {
    closeScenarioInfo();
    runScenario(btn.dataset.scenario);
  });
});

document.querySelectorAll("button[data-agent-profile]").forEach((btn) => {
  btn.addEventListener("click", () => {
    closeScenarioInfo();
    runAgentProfile(btn.dataset.agentProfile);
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
  const isStopping = path === "/api/contain";
  demoActionInProgress = true;
  if (isStopping) workloadResponseState = "Stopping · invisible-vm";
  else workloadResponseState = "Restoring · invisible-vm";
  if (activeStory === "workload") renderGuidedResult();
  syncActionButtons();
  actionLog.className = "result-running";
  actionLog.textContent = isStopping
    ? "Stop requested for invisible-vm. Waiting for observed pod termination."
    : "Restore requested for invisible-vm. Waiting for a Ready pod.";
  try {
    const res = await fetch(path, { method: "POST" });
    const data = await parseJsonResponse(res);
    const target = data.target || "invisible-vm";
    const responseLabel = {
      stopping: "Stopping",
      stopped: "Stopped",
      restoring: "Restoring",
      restored: "Restored",
    }[data.status] || data.status || "Pending";
    workloadResponseState = `${responseLabel} · ${target}`;
    document.getElementById("response-target").textContent = target;
    actionLog.className = "";
    actionLog.textContent = `${data.message || "Response state updated."}\nObserved pod state: ${JSON.stringify(data.observed || {})}`;
    if (activeStory === "workload") renderGuidedResult();
    await refreshStatus();
  } catch (error) {
    workloadResponseState = `Response failed · ${error.message}`;
    actionLog.className = "result-failed";
    actionLog.textContent = `Action failed: ${error.message}`;
    if (activeStory === "workload") renderGuidedResult();
  } finally {
    demoActionInProgress = false;
    syncActionButtons();
  }
}

document.getElementById("contain-btn").addEventListener("click", () => {
  runControlAction("/api/contain");
});

document.getElementById("reset-btn").addEventListener("click", () => {
  runControlAction("/api/reset");
});

document.getElementById("guided-contain-btn").addEventListener("click", () => {
  runControlAction("/api/contain");
});

document.getElementById("guided-reset-btn").addEventListener("click", () => {
  runControlAction("/api/reset");
});

document.getElementById("scene-prev").addEventListener("click", () => {
  if (activeSceneIndex === 0) return;
  activeSceneIndex -= 1;
  renderGuidedScene();
});

document.getElementById("scene-next").addEventListener("click", () => {
  if (activeSceneIndex >= currentGuidedStory().scenes.length - 1) return;
  activeSceneIndex += 1;
  renderGuidedScene();
});

storySelect.addEventListener("change", () => {
  activeStory = storySelect.value === "agent" ? "agent" : "workload";
  activeSceneIndex = 0;
  try {
    localStorage.setItem(STORY_STORAGE_KEY, activeStory);
  } catch (_error) {
    // The selection remains active for this page even when storage is unavailable.
  }
  renderGuidedScene();
  refreshAgentStatus();
});

guidedActionButton.addEventListener("click", async () => {
  if (demoActionInProgress) return;
  const scene = currentGuidedScene();
  if (scene.scenario) {
    runScenario(scene.scenario, { fromGuided: true });
    return;
  }
  if (scene.profile) {
    runAgentProfile(scene.profile, { fromGuided: true });
    return;
  }
  setGuidedActionState("running", "Refreshing status");
  guidedActionButton.disabled = true;
  await Promise.allSettled([refreshStatus(), loadTimelineHistory()]);
  setGuidedActionState("ready", "Ready");
  guidedActionButton.disabled = false;
  renderGuidedResult();
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
    renderGuidedResult();
  } catch (error) {
    timelineState.textContent = `Could not load retained history: ${error.message}`;
  }
}

function connectStream() {
  const source = new EventSource("/api/events/stream");
  setStreamState("connecting", "Connecting");
  source.onopen = () => {
    if (streamReconnectTimer) clearTimeout(streamReconnectTimer);
    streamReconnectTimer = null;
    setStreamState("connected", "Connected");
  };
  source.addEventListener("argus", (msg) => {
    try {
      queueEvent(JSON.parse(msg.data));
    } catch (e) {
      console.error(e);
    }
  });
  source.onerror = () => {
    source.close();
    setStreamState("disconnected", "Reconnecting");
    if (streamReconnectTimer) clearTimeout(streamReconnectTimer);
    streamReconnectTimer = setTimeout(() => {
      setStreamState("connecting", "Connecting");
      connectStream();
    }, 3000);
  };
}

storySelect.value = activeStory;
renderGuidedScene();
refreshStatus();
refreshAgentStatus();
refreshMetrics();
connectStream();
loadTimelineHistory();
refreshServerRunState(true);
setInterval(refreshStatus, 5000);
setInterval(refreshAgentStatus, 15000);
setInterval(refreshMetrics, 15000);
setInterval(() => refreshServerRunState(false), 2000);
