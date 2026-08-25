// LAN Sentinel Extension Popup Script

const API_BASE = "http://localhost:3000";
const GO_AGENT_BASE = "http://127.0.0.1:8080";

const ssidLabel = document.getElementById("ssidLabel");
const detailsLabel = document.getElementById("detailsLabel");
const cidrInput = document.getElementById("cidrInput");
const scanBtn = document.getElementById("scanBtn");
const progressWrap = document.getElementById("progressWrap");
const progressText = document.getElementById("progressText");
const progressFill = document.getElementById("progressFill");
const deviceList = document.getElementById("deviceList");
const agentBadge = document.getElementById("agentBadge");

async function loadNetworkInfo() {
  try {
    const res = await fetch(`${API_BASE}/api/network`).catch(() => fetch(`${GO_AGENT_BASE}/api/network`));
    if (res && res.ok) {
      const data = await res.json();
      ssidLabel.textContent = `Wi-Fi: ${data.ssid || data.hostname || "Active Network"}`;
      detailsLabel.textContent = `Gateway: ${data.gateway || "—"} · Subnet: ${data.cidr || "192.168.0.0/24"}`;
      if (data.cidr) cidrInput.value = data.cidr;
      agentBadge.textContent = "Agent Online";
    }
  } catch {
    agentBadge.textContent = "Connecting...";
  }

  // Load any active devices in memory
  try {
    const resDev = await fetch(`${API_BASE}/api/devices`).catch(() => fetch(`${GO_AGENT_BASE}/api/devices`));
    if (resDev && resDev.ok) {
      const data = await resDev.json();
      const list = Array.isArray(data) ? data : data.devices || [];
      if (list.length > 0) renderDevices(list);
    }
  } catch {}
}

function renderDevices(devices) {
  if (!devices || devices.length === 0) {
    deviceList.innerHTML = `<div class="empty-state">No devices discovered yet.</div>`;
    return;
  }

  deviceList.innerHTML = devices
    .map(
      (d) => `
    <div class="device-card">
      <div class="device-top">
        <span class="device-ip">${d.ip}</span>
        <span class="device-host">${d.hostname || "—"}</span>
      </div>
      <div class="device-meta">
        ${d.vendor ? `${d.vendor} · ` : ""}${d.ping_ms != null ? `${d.ping_ms}ms` : "Active"}
        ${(d.open_ports || []).map((p) => `<span class="ports-badge">${p}</span>`).join("")}
      </div>
    </div>
  `
    )
    .join("");
}

async function startScan() {
  const targetCidr = cidrInput.value || "192.168.0.0/24";
  scanBtn.disabled = true;
  progressWrap.style.display = "block";
  progressFill.style.width = "20%";
  progressText.textContent = "Scanning LAN subnet...";

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cidr: targetCidr })
    }).catch(() =>
      fetch(`${GO_AGENT_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cidr: targetCidr })
      })
    );

    if (res && res.ok) {
      const devices = await res.json();
      progressFill.style.width = "100%";
      progressText.textContent = `Scan complete: ${devices.length} devices found`;
      renderDevices(devices);
    } else {
      progressText.textContent = "Scan failed";
    }
  } catch (e) {
    progressText.textContent = "Error communicating with backend agent";
  } finally {
    scanBtn.disabled = false;
  }
}

scanBtn.addEventListener("click", startScan);
document.addEventListener("DOMContentLoaded", loadNetworkInfo);
