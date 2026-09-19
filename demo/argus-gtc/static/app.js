const timeline = document.getElementById("timeline");
const actionLog = document.getElementById("action-log");
const metricGrid = document.getElementById("metric-grid");

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
}

function renderEvent(event) {
  const el = document.createElement("article");
  const severity = (event.severity || "").toUpperCase();
  const type = (event.message_type || "").toUpperCase();
  el.className = `event ${type === "ALERT" ? "alert" : ""} ${severity === "HIGH" ? "high" : ""}`;
  el.innerHTML = `
    <div class="meta">
      <span>${event.occurred_at || event.received_at || ""}</span>
      <span>${severity || "INFO"} · ${type || "EVENT"}</span>
    </div>
    <div class="title">${event.activity_name || "Activity"}</div>
    <div class="detail">${event.process_command || event.process_name || ""}</div>
    <div class="detail">pod=${event.pod_name || "—"} node=${event.node_name || "—"} ${event.demo_label ? "· " + event.demo_label : ""}</div>
  `;
  timeline.prepend(el);
  while (timeline.children.length > 80) {
    timeline.removeChild(timeline.lastChild);
  }
}

function sparkline(series) {
  const values = (series || []).map((s) => s.value || 0);
  const max = Math.max(...values, 1);
  return values.slice(-24).map((v) => `<span style="height:${Math.max(8, (v / max) * 100)}%"></span>`).join("");
}

async function refreshMetrics() {
  const res = await fetch("/api/metrics/dts");
  const data = await res.json();
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
  const data = await res.json();
  updateRibbon(data);
}

async function runScenario(id) {
  actionLog.textContent = `Running ${id}...`;
  const res = await fetch(`/api/scenarios/${id}`, { method: "POST" });
  const data = await res.json();
  actionLog.textContent = JSON.stringify(data, null, 2);
}

document.querySelectorAll("button[data-scenario]").forEach((btn) => {
  btn.addEventListener("click", () => runScenario(btn.dataset.scenario));
});

document.getElementById("contain-btn").addEventListener("click", async () => {
  const res = await fetch("/api/contain", { method: "POST" });
  actionLog.textContent = JSON.stringify(await res.json(), null, 2);
  refreshStatus();
});

document.getElementById("reset-btn").addEventListener("click", async () => {
  const res = await fetch("/api/reset", { method: "POST" });
  actionLog.textContent = JSON.stringify(await res.json(), null, 2);
  refreshStatus();
});

function connectStream() {
  const source = new EventSource("/api/events/stream");
  source.addEventListener("argus", (msg) => {
    try {
      renderEvent(JSON.parse(msg.data));
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
setInterval(refreshStatus, 5000);
setInterval(refreshMetrics, 15000);
