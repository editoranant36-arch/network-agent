"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Device,
  NetworkProfile,
  buildClientDefensiveAdvice,
  detectBrowserNetworkProfile,
  runClientNetworkScan
} from "./lib/clientScanner";

interface AgentStatus {
  status: string;
  engine: string;
  hostname: string;
  os: string;
  arch: string;
  uptimeSeconds?: number;
  goAgentOnline?: boolean;
  netlensAgentOnline?: boolean;
  port?: number;
  version?: string;
}

export default function Home() {
  const [cidr, setCidr] = useState("192.168.0.0/24");
  const [profile, setProfile] = useState<NetworkProfile | null>(null);
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [agentType, setAgentType] = useState<"netlens" | "nextjs" | "browser">("netlens");
  const [agentUrl, setAgentUrl] = useState<string>("");
  const [agentLatency, setAgentLatency] = useState<number | null>(null);
  const [showAgentConfig, setShowAgentConfig] = useState(false);
  const [customUrlInput, setCustomUrlInput] = useState("");
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testingConnection, setTestingConnection] = useState(false);

  const [devices, setDevices] = useState<Device[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState("");
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Device | null>(null);
  const [lastScanned, setLastScanned] = useState<string | null>(null);

  const abortControllerRef = useRef<AbortController | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const autoScanTriggeredRef = useRef(false);

  // 1. Initialize Agent URL and Network Info on mount
  useEffect(() => {
    // Restore cached session devices if available
    try {
      const cached = sessionStorage.getItem("lan_devices");
      const cachedTime = sessionStorage.getItem("lan_last_scan");
      if (cached) setDevices(JSON.parse(cached));
      if (cachedTime) setLastScanned(cachedTime);
    } catch {}

    // Determine initial Agent URL
    const envUrl = process.env.NEXT_PUBLIC_AGENT_URL;
    let initialUrl = "http://127.0.0.1:8080";
    try {
      const saved = localStorage.getItem("netlens_agent_url");
      if (saved) initialUrl = saved;
      else if (envUrl) initialUrl = envUrl;
    } catch {}

    setAgentUrl(initialUrl);
    setCustomUrlInput(initialUrl);

    // Check Agent and Network
    bootstrapAgent(initialUrl);
  }, []);

  function normalizeAgentUrl(rawUrl: string): string {
    let clean = rawUrl.trim().replace(/\/$/, "");
    if (!clean) return "";
    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
      clean = `https://${clean}`;
    }
    // On Render, public URLs are routed via standard HTTPS (port 443).
    // If a user entered *.onrender.com:8080 or :4000, strip the port!
    if (clean.includes(".onrender.com:") && !clean.includes("localhost")) {
      clean = clean.replace(/:\d+$/, "");
    }
    return clean;
  }

  async function bootstrapAgent(targetUrl: string) {
    const cleanUrl = normalizeAgentUrl(targetUrl);
    let connected = false;

    // A. Check specified Agent URL first (Go agent or Render or NetLens)
    if (cleanUrl) {
      try {
        const start = performance.now();
        const res = await fetch(`${cleanUrl}/api/agent/status`, {
          signal: AbortSignal.timeout(1500)
        }).catch(() => null);

        if (res && res.ok) {
          const data: AgentStatus = await res.json();
          const latency = Math.round(performance.now() - start);
          setAgentStatus(data);
          setAgentType("netlens");
          setAgentLatency(latency);
          connected = true;

          fetchNetworkProfile(`${cleanUrl}/api/network`);
          fetchDevices(`${cleanUrl}/api/devices`);
          return;
        }

        // Fallback probe to /health or /api/network on targetUrl
        const healthRes = await fetch(`${cleanUrl}/health`, {
          signal: AbortSignal.timeout(1500)
        }).catch(() => null);
        if (healthRes && healthRes.ok) {
          const healthData = await healthRes.json().catch(() => ({}));
          const latency = Math.round(performance.now() - start);
          setAgentStatus({
            status: "online",
            engine: healthData.agent === "go" ? "Go High-Speed Agent" : "Remote Backend Agent",
            hostname: "agent-host",
            os: "Linux",
            arch: "x86_64"
          });
          setAgentType("netlens");
          setAgentLatency(latency);
          connected = true;
          fetchNetworkProfile(`${cleanUrl}/api/network`);
          fetchDevices(`${cleanUrl}/api/devices`);
          return;
        }
      } catch {}
    }

    // B. Check local Go Agent on :8080 if targetUrl wasn't 8080
    if (!connected && cleanUrl !== "http://127.0.0.1:8080") {
      try {
        const start = performance.now();
        const res = await fetch("http://127.0.0.1:8080/api/agent/status", {
          signal: AbortSignal.timeout(1000)
        }).catch(() => null);
        if (res && res.ok) {
          const data: AgentStatus = await res.json();
          const latency = Math.round(performance.now() - start);
          setAgentUrl("http://127.0.0.1:8080");
          setCustomUrlInput("http://127.0.0.1:8080");
          setAgentStatus(data);
          setAgentType("netlens");
          setAgentLatency(latency);
          connected = true;

          fetchNetworkProfile("http://127.0.0.1:8080/api/network");
          fetchDevices("http://127.0.0.1:8080/api/devices");
          return;
        }
      } catch {}
    }

    // C. Fallback to local Next.js Backend
    if (!connected) {
      try {
        const start = performance.now();
        const res = await fetch("/api/agent/status", { signal: AbortSignal.timeout(1500) });
        if (res.ok) {
          const data: AgentStatus = await res.json();
          const latency = Math.round(performance.now() - start);
          setAgentStatus(data);
          setAgentType("nextjs");
          setAgentLatency(latency);
          connected = true;

          // Fetch network profile from Next.js backend
          fetchNetworkProfile("/api/network");
          fetchDevices("/api/devices");
          return;
        }
      } catch {}
    }

    // D. Fallback to Browser Client Scanner Engine
    if (!connected) {
      setAgentType("browser");
      setAgentStatus({
        status: "online",
        engine: "In-Browser Client Scanner Engine",
        hostname: typeof window !== "undefined" ? window.location.hostname : "localhost",
        os: "Client Browser Sandbox",
        arch: "wasm / js"
      });
      fallbackClientDetection();
    }
  }

  async function fetchNetworkProfile(endpoint: string) {
    try {
      const res = await fetch(endpoint, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        const netProfile: NetworkProfile = await res.json();
        if (netProfile && netProfile.cidr) {
          setProfile(netProfile);
          setCidr(netProfile.cidr);
          if (!autoScanTriggeredRef.current) {
            autoScanTriggeredRef.current = true;
            triggerAutoScan(netProfile.cidr);
          }
          return;
        }
      }
    } catch {}
    fallbackClientDetection();
  }

  async function fetchDevices(endpoint: string) {
    try {
      const res = await fetch(endpoint, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.devices) && data.devices.length > 0) {
          setDevices((prev) => (prev.length > 0 ? prev : data.devices));
          if (data.last_scan) {
            setLastScanned(new Date(data.last_scan).toLocaleTimeString());
          }
        }
      }
    } catch {}
  }

  function fallbackClientDetection() {
    detectBrowserNetworkProfile()
      .then((bProfile) => {
        setProfile((prev) => prev || bProfile);
        if (bProfile.cidr) setCidr((prev) => (prev === "192.168.0.0/24" ? bProfile.cidr : prev));
        if (!autoScanTriggeredRef.current) {
          autoScanTriggeredRef.current = true;
          triggerAutoScan(bProfile.cidr);
        }
      })
      .catch(() => {});
  }

  function triggerAutoScan(targetCidr?: string) {
    executeScan(targetCidr || cidr);
  }

  // Network Scan Execution: Streams from NetLens Backend, Next.js API, or Browser Fallback
  async function executeScan(targetCidr: string) {
    if (busy) return;

    setDevices([]);
    try {
      sessionStorage.removeItem("lan_devices");
    } catch {}

    setBusy(true);
    setError("");
    setProgress(5);
    setProgressText(`Connecting to ${agentType === "netlens" ? "NetLens Agent" : "Backend Agent"} & analyzing network...`);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const cleanAgentUrl = agentUrl.replace(/\/$/, "");
    const baseApiUrl = agentType === "netlens" ? cleanAgentUrl : "";

    // Method 1: Real-Time SSE Stream (from NetLens Agent or Next.js)
    if (agentType !== "browser") {
      try {
        let streamSucceeded = false;
        const discoveredMap = new Map<string, Device>();
        const streamUrl = `${baseApiUrl}/api/scan/stream?cidr=${encodeURIComponent(targetCidr)}`;

        const eventSource = new EventSource(streamUrl);
        eventSourceRef.current = eventSource;

        await new Promise<void>((resolve, reject) => {
          eventSource.addEventListener("status", (e: any) => {
            try {
              const data = JSON.parse(e.data);
              setProgressText(data.message || "Agent sweeping subnet...");
              setProgress((p) => Math.max(p, 10));
            } catch {}
          });

          eventSource.addEventListener("progress", (e: any) => {
            try {
              const data = JSON.parse(e.data);
              const pct = data.percentage || Math.round((data.scanned / data.total) * 100);
              setProgress(pct);
              const currentIpText = data.currentIp ? ` · Probing ${data.currentIp}` : "";
              setProgressText(`Agent sweeping subnet: ${pct}% (${data.scanned}/${data.total} IPs)${currentIpText}`);
            } catch {}
          });

          eventSource.addEventListener("device", (e: any) => {
            try {
              const dev: Device = JSON.parse(e.data);
              discoveredMap.set(dev.ip, dev);
              const sorted = Array.from(discoveredMap.values()).sort((a, b) => {
                const numA = a.ip.split(".").map(Number).reduce((acc, oct) => (acc << 8) + oct, 0) >>> 0;
                const numB = b.ip.split(".").map(Number).reduce((acc, oct) => (acc << 8) + oct, 0) >>> 0;
                return numA - numB;
              });
              setDevices(sorted);
            } catch {}
          });

          eventSource.addEventListener("complete", (e: any) => {
            streamSucceeded = true;
            eventSource.close();
            eventSourceRef.current = null;
            try {
              const data = JSON.parse(e.data);
              if (Array.isArray(data.devices)) {
                setDevices(data.devices);
                const timeStr = new Date().toLocaleTimeString();
                setLastScanned(timeStr);
                try {
                  sessionStorage.setItem("lan_devices", JSON.stringify(data.devices));
                  sessionStorage.setItem("lan_last_scan", timeStr);
                } catch {}
              }
            } catch {}
            resolve();
          });

          eventSource.addEventListener("error", () => {
            eventSource.close();
            eventSourceRef.current = null;
            if (!streamSucceeded) {
              reject(new Error("SSE stream failed"));
            } else {
              resolve();
            }
          });

          setTimeout(() => {
            if (!streamSucceeded && discoveredMap.size === 0 && progress <= 10) {
              eventSource.close();
              eventSourceRef.current = null;
              reject(new Error("SSE stream timeout"));
            }
          }, 15000);
        });

        if (streamSucceeded) {
          setProgress(100);
          setProgressText(`Scan completed by ${agentType === "netlens" ? "NetLens Agent" : "Backend Agent"}`);
          setBusy(false);
          return;
        }
      } catch {
        // Fallback to POST /api/scan
      }

      // Method 2: POST /api/scan REST API
      try {
        setProgress(35);
        setProgressText(`Executing scan via ${baseApiUrl || ""}/api/scan...`);

        const scanRes = await fetch(`${baseApiUrl}/api/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cidr: targetCidr }),
          signal: controller.signal
        });

        if (scanRes.ok) {
          const results: Device[] = await scanRes.json();
          setDevices(results);
          const timeStr = new Date().toLocaleTimeString();
          setLastScanned(timeStr);
          try {
            sessionStorage.setItem("lan_devices", JSON.stringify(results));
            sessionStorage.setItem("lan_last_scan", timeStr);
          } catch {}
          setProgress(100);
          setProgressText("Scan completed successfully");
          setBusy(false);
          return;
        }
      } catch {}
    }

    // Method 3: In-Browser Client Scanner (Pure Client Engine)
    try {
      setProgress(25);
      setProgressText("Probing subnet directly via client browser engine...");
      const scanPorts = [21, 22, 53, 80, 135, 139, 443, 445, 1883, 3000, 3389, 5000, 5353, 8000, 8080, 8443, 9000];

      const results = await runClientNetworkScan(
        targetCidr,
        scanPorts,
        (scanned, total, pct) => {
          setProgress(pct);
          setProgressText(`Scanning subnet IPs: ${pct}% (${scanned}/${total} IPs)`);
        },
        (dev) => {
          setDevices((prev) => {
            const exists = prev.some((d) => d.ip === dev.ip);
            const updated = exists ? prev.map((d) => (d.ip === dev.ip ? dev : d)) : [...prev, dev];
            return updated.sort((a, b) => {
              const numA = a.ip.split(".").map(Number).reduce((acc, oct) => (acc << 8) + oct, 0) >>> 0;
              const numB = b.ip.split(".").map(Number).reduce((acc, oct) => (acc << 8) + oct, 0) >>> 0;
              return numA - numB;
            });
          });
        },
        controller.signal
      );

      setDevices(results);
      const timeStr = new Date().toLocaleTimeString();
      setLastScanned(timeStr);
      try {
        sessionStorage.setItem("lan_devices", JSON.stringify(results));
        sessionStorage.setItem("lan_last_scan", timeStr);
      } catch {}
    } catch (e: any) {
      if (e?.name !== "AbortError") {
        setError(e?.message || "Scan failed");
      }
    } finally {
      setBusy(false);
      setProgress(100);
      abortControllerRef.current = null;
    }
  }

  function scan() {
    executeScan(cidr);
  }

  function stopScan() {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setBusy(false);
    setProgressText("Scan stopped by user");
  }

  async function clearMemory() {
    setDevices([]);
    setLastScanned(null);
    setProgress(0);
    setProgressText("");
    try {
      sessionStorage.removeItem("lan_devices");
      sessionStorage.removeItem("lan_last_scan");
      const baseApiUrl = agentType === "netlens" ? agentUrl.replace(/\/$/, "") : "";
      await fetch(`${baseApiUrl}/api/devices`, { method: "DELETE" }).catch(() => {});
    } catch {}
  }

  function exportJSON() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(devices, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `network-scan-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  async function testAndSaveAgentUrl() {
    setTestingConnection(true);
    setTestResult(null);
    const cleanUrl = normalizeAgentUrl(customUrlInput);

    if (!cleanUrl) {
      setTestResult({ ok: false, msg: "Please enter a valid agent URL or hostname." });
      setTestingConnection(false);
      return;
    }

    try {
      const start = performance.now();
      let res = await fetch(`${cleanUrl}/api/agent/status`, {
        signal: AbortSignal.timeout(3500)
      }).catch(() => null);

      if (res && res.ok) {
        const data: AgentStatus = await res.json();
        const latency = Math.round(performance.now() - start);
        setAgentUrl(cleanUrl);
        setAgentType("netlens");
        setAgentStatus(data);
        setAgentLatency(latency);
        localStorage.setItem("netlens_agent_url", cleanUrl);
        setTestResult({ ok: true, msg: `Connected successfully (${latency}ms)! Engine: ${data.engine || "Backend Agent"}` });
        fetchNetworkProfile(`${cleanUrl}/api/network`);
        fetchDevices(`${cleanUrl}/api/devices`);
        setTimeout(() => setShowAgentConfig(false), 1200);
        return;
      }

      // Fallback probe to /health or /api/network
      const healthRes = await fetch(`${cleanUrl}/health`, {
        signal: AbortSignal.timeout(3000)
      }).catch(() => null);

      if (healthRes && healthRes.ok) {
        const healthData = await healthRes.json().catch(() => ({}));
        const latency = Math.round(performance.now() - start);
        const data: AgentStatus = {
          status: "online",
          engine: healthData.agent === "go" ? "Go High-Speed Agent" : "Remote Backend Agent",
          hostname: "remote-agent",
          os: "Linux",
          arch: "x86_64"
        };
        setAgentUrl(cleanUrl);
        setAgentType("netlens");
        setAgentStatus(data);
        setAgentLatency(latency);
        localStorage.setItem("netlens_agent_url", cleanUrl);
        setTestResult({ ok: true, msg: `Connected successfully (${latency}ms)! Engine: ${data.engine}` });
        fetchNetworkProfile(`${cleanUrl}/api/network`);
        fetchDevices(`${cleanUrl}/api/devices`);
        setTimeout(() => setShowAgentConfig(false), 1200);
        return;
      }

      setTestResult({
        ok: false,
        msg: `HTTP error: Could not reach agent at ${cleanUrl}. Check URL and ensure agent is running.`
      });
    } catch (e: any) {
      setTestResult({
        ok: false,
        msg: `Connection failed: ${e?.message || "Ensure the agent is running and accessible."}`
      });
    } finally {
      setTestingConnection(false);
    }
  }

  const stats = useMemo(() => {
    const list = Array.isArray(devices) ? devices : [];
    return {
      live: list.length,
      ports: list.reduce((n, d) => n + (d.open_ports ? d.open_ports.length : 0), 0),
      identified: list.filter((d) => d.hostname || d.dns || d.vendor).length
    };
  }, [devices]);

  const deviceList = Array.isArray(devices) ? devices : [];

  const networkBadge = useMemo(() => {
    const type = profile?.networkType || "personal";
    if (type === "personal") {
      return {
        label: "🏠 PERSONAL HOME WI-FI",
        color: "#4ade80",
        bg: "#0d2818",
        border: "#1e5430",
        desc: "Trusted Private Network"
      };
    }
    if (type === "public") {
      return {
        label: "☕ PUBLIC / SHARED HOTSPOT",
        color: "#fbbf24",
        bg: "#2b2108",
        border: "#5c4811",
        desc: "Untrusted Network (High Risk)"
      };
    }
    return {
      label: "🏢 ENTERPRISE CORPORATE LAN",
      color: "#60a5fa",
      bg: "#0c2340",
      border: "#1e4775",
      desc: "Monitored Domain Network"
    };
  }, [profile]);

  return (
    <main>
      <header>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <div>
            <span className="dot" /> <b>LAN SENTINEL</b>
            <small> intelligent Wi-Fi auto-detection & security monitor</small>
          </div>

          {/* Backend Agent Status Badge */}
          <div
            onClick={() => setShowAgentConfig(true)}
            title="Click to configure or test Backend Agent URL"
            style={{
              background: agentType === "netlens" ? "#0f2316" : agentType === "nextjs" ? "#0c1b2c" : "#261d0f",
              border: `1px solid ${agentType === "netlens" ? "#23633b" : agentType === "nextjs" ? "#1e4775" : "#634718"}`,
              color: agentType === "netlens" ? "#4ade80" : agentType === "nextjs" ? "#60a5fa" : "#fbbf24",
              borderRadius: "16px",
              padding: "4px 12px",
              fontSize: "11px",
              fontWeight: 600,
              display: "flex",
              alignItems: "center",
              gap: "7px",
              cursor: "pointer",
              transition: "all 0.2s"
            }}
          >
            <span
              style={{
                display: "inline-block",
                width: "7px",
                height: "7px",
                borderRadius: "50%",
                background: agentType === "netlens" ? "#4ade80" : agentType === "nextjs" ? "#60a5fa" : "#fbbf24"
              }}
            />
            <span>
              {agentType === "netlens"
                ? `NetLens Agent Online ${agentLatency ? `(${agentLatency}ms)` : ""}`
                : agentType === "nextjs"
                ? "Next.js Core Backend"
                : "Browser Client Engine"}
            </span>
            <span style={{ fontSize: "10px", opacity: 0.7, textDecoration: "underline", marginLeft: "4px" }}>
              ⚙️ Settings
            </span>
          </div>
        </div>

        <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
          {lastScanned && <small style={{ color: "#8996a9" }}>Last scan: {lastScanned}</small>}
          {deviceList.length > 0 && (
            <>
              <button onClick={exportJSON} style={{ background: "#152233", color: "#62e6a7", border: "1px solid #20354a" }}>
                Export JSON
              </button>
              <button onClick={clearMemory} style={{ background: "#1b2737", color: "#dce7f5" }} disabled={busy}>
                Clear Memory
              </button>
            </>
          )}
          {busy ? (
            <button onClick={stopScan} style={{ background: "#4a1818", color: "#ff8f8f" }}>
              Stop Scan
            </button>
          ) : (
            <button onClick={scan}>Scan Network</button>
          )}
        </div>
      </header>

      {/* NetLens Agent Configuration Modal */}
      {showAgentConfig && (
        <div className="overlay" onClick={() => setShowAgentConfig(false)}>
          <aside
            className="advice"
            onClick={(e) => e.stopPropagation()}
            style={{ width: "min(560px, 95%)", height: "auto", maxHeight: "90vh", borderRadius: "14px", margin: "auto" }}
          >
            <div className="adviceHead">
              <div>
                <small style={{ color: "#4ade80" }}>BACKEND AGENT CONNECTIVITY</small>
                <h2 style={{ fontSize: "24px", margin: "4px 0" }}>NetLens Agent Connection</h2>
              </div>
              <button className="close" onClick={() => setShowAgentConfig(false)}>
                ×
              </button>
            </div>

            <div style={{ marginTop: "16px" }}>
              <p style={{ color: "#9aa8bb", fontSize: "13px", lineHeight: "1.5" }}>
                Connect your dashboard to the high-speed <b>NetLens Diagnostics Agent</b> running locally or hosted on Render.
              </p>

              <div style={{ marginTop: "14px" }}>
                <label style={{ display: "block", fontSize: "12px", color: "#8996a9", marginBottom: "6px", fontWeight: "bold" }}>
                  AGENT BACKEND URL (HTTP / REST / WEBSOCKET)
                </label>
                <div style={{ display: "flex", gap: "8px" }}>
                  <input
                    type="text"
                    value={customUrlInput}
                    onChange={(e) => setCustomUrlInput(e.target.value)}
                    placeholder="http://127.0.0.1:4000 or https://your-agent.onrender.com"
                    style={{
                      flex: 1,
                      background: "#0d131d",
                      border: "1px solid #253143",
                      borderRadius: "8px",
                      color: "white",
                      padding: "10px",
                      fontSize: "13px"
                    }}
                  />
                  <button
                    onClick={testAndSaveAgentUrl}
                    disabled={testingConnection}
                    style={{ background: "#4ade80", color: "#07101c", fontSize: "13px", padding: "0 16px" }}
                  >
                    {testingConnection ? "Connecting..." : "Connect"}
                  </button>
                </div>
              </div>

              {testResult && (
                <div
                  style={{
                    marginTop: "12px",
                    padding: "10px 14px",
                    borderRadius: "8px",
                    fontSize: "13px",
                    background: testResult.ok ? "#0e2417" : "#2a1212",
                    border: `1px solid ${testResult.ok ? "#1e5430" : "#5a2222"}`,
                    color: testResult.ok ? "#75e0b5" : "#ff8f8f"
                  }}
                >
                  {testResult.msg}
                </div>
              )}

              <div style={{ marginTop: "18px", padding: "14px", background: "#0e1520", borderRadius: "10px", border: "1px solid #1c2738" }}>
                <h4 style={{ margin: "0 0 8px", fontSize: "13px", color: "#dce7f5" }}>Current Active Engine</h4>
                <div style={{ fontSize: "12px", color: "#8da0b8", display: "grid", gap: "4px" }}>
                  <div>
                    Engine: <b style={{ color: "#fff" }}>{agentStatus?.engine || "NetLens Node.js Agent"}</b>
                  </div>
                  <div>
                    Host / OS: <b style={{ color: "#fff" }}>{agentStatus?.hostname || "Local"} ({agentStatus?.os || "Linux"})</b>
                  </div>
                  <div>
                    Status: <b style={{ color: "#4ade80" }}>{agentStatus?.status || "Ready"}</b> {agentLatency ? `· Latency: ${agentLatency}ms` : ""}
                  </div>
                  <div>
                    Active URL: <code style={{ color: "#62e6a7" }}>{agentType === "netlens" ? agentUrl : "Next.js Local Server"}</code>
                  </div>
                </div>
              </div>

              <div style={{ marginTop: "16px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
                <button
                  onClick={() => {
                    setCustomUrlInput("http://127.0.0.1:8080");
                    bootstrapAgent("http://127.0.0.1:8080");
                    setShowAgentConfig(false);
                  }}
                  style={{ background: "#162232", color: "#4ade80", border: "1px solid #23374d", fontSize: "12px", padding: "8px 12px" }}
                >
                  ⚡ Use Go Agent (:8080)
                </button>
                <button
                  onClick={() => {
                    setCustomUrlInput("http://127.0.0.1:4000");
                    bootstrapAgent("http://127.0.0.1:4000");
                    setShowAgentConfig(false);
                  }}
                  style={{ background: "#162232", color: "#62e6a7", border: "1px solid #23374d", fontSize: "12px", padding: "8px 12px" }}
                >
                  Use Node Agent (:4000)
                </button>
                <button
                  onClick={() => {
                    setAgentType("nextjs");
                    bootstrapAgent("");
                    setShowAgentConfig(false);
                  }}
                  style={{ background: "#162232", color: "#60a5fa", border: "1px solid #23374d", fontSize: "12px", padding: "8px 12px" }}
                >
                  Use Next.js Core
                </button>
                <button
                  onClick={() => {
                    setAgentType("browser");
                    fallbackClientDetection();
                    setShowAgentConfig(false);
                  }}
                  style={{ background: "#162232", color: "#fbbf24", border: "1px solid #23374d", fontSize: "12px", padding: "8px 12px" }}
                >
                  Use Browser Engine
                </button>
              </div>

              <div style={{ marginTop: "12px", fontSize: "11px", color: "#64748b" }}>
                💡 <b>Render Tip:</b> On Render, web services use HTTPS on standard port 443. Enter <code>https://your-agent.onrender.com</code> (do not append <code>:8080</code>).
              </div>
            </div>
          </aside>
        </div>
      )}

      {/* Wi-Fi Intelligence Auto-Detection Card */}
      {profile && (
        <section
          style={{
            background: "#0f1722",
            border: `1px solid ${networkBadge.border}`,
            borderRadius: "10px",
            padding: "16px 20px",
            marginTop: "16px",
            display: "flex",
            flexWrap: "wrap",
            gap: "16px",
            justifyContent: "space-between",
            alignItems: "center"
          }}
        >
          <div style={{ display: "flex", gap: "14px", alignItems: "center", flexWrap: "wrap" }}>
            <div
              style={{
                background: networkBadge.bg,
                color: networkBadge.color,
                border: `1px solid ${networkBadge.border}`,
                padding: "6px 14px",
                borderRadius: "20px",
                fontSize: "12px",
                fontWeight: "bold",
                letterSpacing: "0.5px"
              }}
            >
              {networkBadge.label}
            </div>
            <div>
              <div style={{ fontSize: "16px", fontWeight: "bold", color: "#fff" }}>
                SSID: <span style={{ color: "#62e6a7" }}>{profile.ssid}</span>
                {profile.signal && <span style={{ fontSize: "12px", color: "#8996a9", marginLeft: "8px" }}>📶 {profile.signal}</span>}
              </div>
              <div style={{ fontSize: "12px", color: "#8da0b8", marginTop: "2px" }}>
                Security: <b style={{ color: "#dce7f5" }}>{profile.security}</b> · Gateway:{" "}
                <b style={{ color: "#dce7f5" }}>{profile.gateway}</b> ({profile.gatewayVendor || "Router"})
              </div>
            </div>
          </div>

          <div style={{ display: "flex", gap: "20px", alignItems: "center" }}>
            <div style={{ textAlign: "right" }}>
              <div style={{ fontSize: "11px", color: "#8996a9", textTransform: "uppercase" }}>Network Trust Rating</div>
              <div style={{ fontSize: "18px", fontWeight: "bold", color: networkBadge.color }}>
                {profile.trustScore}/100 · <span style={{ fontSize: "12px", fontWeight: "normal" }}>{networkBadge.desc}</span>
              </div>
            </div>
          </div>
        </section>
      )}

      <section className="hero">
        <h1>
          Network <span>Overview</span>
        </h1>
        <p>
          {profile?.networkType === "public"
            ? "⚠️ Public Wi-Fi Hotspot detected. Monitoring for lateral scans, rogue gateways, and unencrypted traffic."
            : "Protected Wi-Fi network detected. Sweeps all subnet IPs (1-254), verifies ping & socket replies, and catalogs all active systems."}
        </p>
        <div className="bar">
          <input
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="192.168.0.0/24"
            disabled={busy}
          />
          {busy ? (
            <button onClick={stopScan} style={{ background: "#4a1818", color: "#ff8f8f" }}>
              Stop
            </button>
          ) : (
            <button onClick={scan}>Re-Scan Network</button>
          )}
        </div>

        {error && <div className="error">{error}</div>}

        {busy && (
          <div style={{ marginTop: "18px", maxWidth: "600px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "13px", color: "#62e6a7", marginBottom: "6px" }}>
              <span>{progressText}</span>
              <span>{progress}%</span>
            </div>
            <div style={{ height: "6px", background: "#15202e", borderRadius: "4px", overflow: "hidden" }}>
              <div
                style={{
                  height: "100%",
                  width: `${progress}%`,
                  background: "#4ade80",
                  transition: "width 0.2s ease"
                }}
              />
            </div>
          </div>
        )}
      </section>

      <section className="stats">
        <div>
          <small>ACTIVE ONLINE DEVICES</small>
          <strong>{stats.live}</strong>
        </div>
        <div>
          <small>IDENTIFIED HOSTS</small>
          <strong>{stats.identified}</strong>
        </div>
        <div>
          <small>OPEN SERVICES</small>
          <strong>{stats.ports}</strong>
        </div>
      </section>

      <section className="panel">
        <div className="panelHead">
          <h2>Active LAN Systems</h2>
          <span>
            {busy
              ? `Agent sweeping subnet... (${deviceList.length} active systems found)`
              : `${deviceList.length} active systems found`} · click a row for advice
          </span>
        </div>
        <div className="tableWrap">
          <table>
            <thead>
              <tr>
                <th>STATUS</th>
                <th>IP ADDRESS</th>
                <th>HOST NAME & DNS</th>
                <th>VENDOR / MAC</th>
                <th>GATEWAY</th>
                <th>PING</th>
                <th>OPEN PORTS</th>
              </tr>
            </thead>
            <tbody>
              {deviceList.map((d) => {
                return (
                  <tr key={d.ip} className="deviceRow" onClick={() => setSelected(d)}>
                    <td>
                      <span className="online">● online</span>
                    </td>
                    <td>
                      <b style={{ fontSize: "14px", color: "#fff" }}>{d.ip}</b>
                    </td>
                    <td>
                      {d.hostname ? (
                        <div>
                          <div style={{ color: "#62e6a7", fontWeight: 600 }}>{d.hostname}</div>
                          {d.dns && <small style={{ color: "#8da0b8", fontFamily: "monospace" }}>DNS: {d.dns}</small>}
                        </div>
                      ) : (
                        <span style={{ color: "#69778b" }}>—</span>
                      )}
                    </td>
                    <td>
                      {d.vendor && <div style={{ color: "#e9eef7", fontWeight: 500 }}>{d.vendor}</div>}
                      <small style={{ color: "#718097", fontFamily: "monospace" }}>{d.mac || "—"}</small>
                    </td>
                    <td>{d.gateway || "—"}</td>
                    <td>{d.ping_ms != null ? `${d.ping_ms} ms` : "—"}</td>
                    <td>
                      {d.open_ports && d.open_ports.length ? (
                        <div style={{ display: "flex", gap: "5px", flexWrap: "wrap" }}>
                          {d.open_ports.map((p) => (
                            <span
                              key={p}
                              style={{
                                background: "#162332",
                                border: "1px solid #283a4f",
                                color: "#87c7ff",
                                padding: "2px 6px",
                                borderRadius: "4px",
                                fontSize: "11px",
                                fontWeight: "bold"
                              }}
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span style={{ color: "#69778b" }}>none detected</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {!deviceList.length && !busy && (
                <tr>
                  <td colSpan={7} className="empty">
                    No active systems found yet. Click &quot;Scan Network&quot; above to scan for active devices on your LAN.
                  </td>
                </tr>
              )}
              {busy && !deviceList.length && (
                <tr>
                  <td colSpan={7} className="empty" style={{ color: "#62e6a7" }}>
                    Auto-probing subnet IPs 1-254 for active ping replies... online devices will appear here automatically.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {selected && (
        <div className="overlay" onClick={() => setSelected(null)}>
          <aside className="advice" onClick={(e) => e.stopPropagation()}>
            <div className="adviceHead">
              <div>
                <small>DEFENSIVE SECURITY ADVICE</small>
                <h2>{selected.hostname || selected.ip}</h2>
                <div style={{ color: "#8996a9", fontSize: "14px", marginTop: "4px" }}>
                  IP: <b style={{ color: "#fff" }}>{selected.ip}</b>
                  {selected.dns ? (
                    <span>
                      {" "}
                      · DNS: <code style={{ color: "#8da0b8" }}>{selected.dns}</code>
                    </span>
                  ) : null}
                  {selected.vendor ? (
                    <span>
                      {" "}
                      · Vendor: <b style={{ color: "#fff" }}>{selected.vendor}</b>
                    </span>
                  ) : null}
                  {selected.mac ? (
                    <span>
                      {" "}
                      · MAC: <code style={{ color: "#75e0b5" }}>{selected.mac}</code>
                    </span>
                  ) : null}
                </div>
              </div>
              <button className="close" onClick={() => setSelected(null)}>
                ×
              </button>
            </div>

            <div className="evidence">
              <b>Evidence from this scan</b>
              <p>
                Reachable: <strong>{selected.reachable ? "yes" : "no"}</strong> · Ping:{" "}
                <strong>{selected.ping_ms != null ? `${selected.ping_ms} ms` : "not measured"}</strong>
              </p>
              <p>
                Gateway: <strong>{selected.gateway || "—"}</strong>
              </p>
              <p>
                Detected TCP ports:{" "}
                <strong>{selected.open_ports && selected.open_ports.length ? selected.open_ports.join(", ") : "none"}</strong>
              </p>
              <small>
                Open-port detection proves only that a TCP connection was accepted during this scan. It does not prove a vulnerability,
                compromise, or attacker activity.
              </small>
            </div>

            <div className="notice">
              Recommendations are defensive. Verify the service owner and business need before changing firewall or service settings.
            </div>

            {buildClientDefensiveAdvice(selected, profile?.networkType).map((a, i) => (
              <article className="adviceItem" key={i}>
                <div className={`severity ${a.severity}`}>{a.severity.toUpperCase()}</div>
                <h3>{a.title}</h3>
                <p>{a.why}</p>
                <h4>Recommended protection</h4>
                <ul>
                  {a.actions.map((x, j) => (
                    <li key={j}>{x}</li>
                  ))}
                </ul>
              </article>
            ))}

            <button
              className="rescan"
              onClick={() => {
                setSelected(null);
                scan();
              }}
            >
              Re-scan network
            </button>
          </aside>
        </div>
      )}

      <footer>Run scans only against networks you own or are authorized to administer.</footer>
    </main>
  );
}
