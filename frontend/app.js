const API_BASE = window.location.origin;
document.getElementById("api-base").textContent = API_BASE;

async function fetchJSON(path) {
  const res = await fetch(API_BASE + path);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

// Escape before inserting into innerHTML -- API values are treated as
// untrusted here regardless of backend validation.
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

function cardHTML(cls, n, label) {
  return `<div class="card ${cls}"><div class="n">${esc(n)}</div><div class="l">${esc(label)}</div></div>`;
}

async function refresh() {
  try {
    const stats = await fetchJSON("/statistics");
    document.getElementById("status").textContent = "live";

    document.getElementById("cards").innerHTML = [
      cardHTML("", stats.events_analyzed, "Events analysed"),
      cardHTML("", stats.total_alerts, "Total alerts"),
      cardHTML("critical", stats.critical_alerts, "Critical"),
      cardHTML("high", stats.high_alerts, "High"),
      cardHTML("medium", stats.medium_alerts, "Medium"),
      cardHTML("low", stats.low_alerts, "Low"),
      cardHTML("", stats.suspicious_devices, "Suspicious devices"),
    ].join("");

    const topBody = document.querySelector("#top-detections-table tbody");
    topBody.innerHTML = stats.top_detections.length
      ? stats.top_detections.map(d => `<tr><td>${esc(d.detection)}</td><td>${esc(d.count)}</td></tr>`).join("")
      : `<tr><td colspan="2" class="empty">No detections yet — run scripts/load_dataset.py or POST to /events</td></tr>`;

    const alerts = await fetchJSON("/alerts?limit=25");
    const alertsBody = document.querySelector("#alerts-table tbody");
    alertsBody.innerHTML = alerts.length
      ? alerts.map(a => `
        <tr>
          <td class="mono">${esc(a.alert_code)}</td>
          <td><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span></td>
          <td>${esc(a.detection)}</td>
          <td class="mono">${esc(a.source_ip)} → ${esc(a.destination_ip)}</td>
          <td>${a.mitre_technique ? `${esc(a.mitre_technique)} (${esc(a.mitre_technique_name)})` : "—"}</td>
          <td>${esc(a.risk_score)}</td>
          <td>${esc(a.status)}</td>
        </tr>`).join("")
      : `<tr><td colspan="7" class="empty">No alerts yet</td></tr>`;
  } catch (err) {
    document.getElementById("status").textContent = "disconnected";
    console.error(err);
  }
}

refresh();
setInterval(refresh, 5000);
