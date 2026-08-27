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
  const [agentType, setAgentType] = useState<"netlens" | "nextjs" | "browser">("browser");
  const [agentUrl, setAgentUrl] = useState<string>("");
  const [agentLatency, setAgentLatency] = useState<number | null>(null);

  // Modals state
  const [showDownloadModal, setShowDownloadModal] = useState(true);
  const [showAgentConfig, setShowAgentConfig] = useState(false);
  const [activeDownloadTab, setActiveDownloadTab] = useState<"quick" | "windows" | "mac" | "linux" | "source">("quick");
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [dontShowAgain, setDontShowAgain] = useState(false);
  const [customUrlInput, setCustomUrlInput] = useState("");
  const [testResult, setTestResult] = useState<{ ok: boolean; msg: string } | null>(null);
  const [testingConnection, setTestingConnection] = useState(false);

  // Scan state
  const [devices, setDevices] = useState<Device[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState("");
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Device | null>(null);
  const [lastScanned, setLastScanned] = useState<string | null>(null);
  const [originUrl, setOriginUrl] = useState("");

  const abortControllerRef = useRef<AbortController | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const autoScanTriggeredRef = useRef(false);
  const isProbingRef = useRef(false);

  function normalizeAgentUrl(rawUrl: string): string {
    let clean = (rawUrl || "").trim().replace(/\/$/, "");
    if (!clean) return "";
    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
      clean = `http://${clean}`;
    }
    if (clean.includes(".onrender.com:") && !clean.includes("localhost")) {
      clean = clean.replace(/:\d+$/, "");
    }
    return clean;
  }

  function getAgentCandidates(): string[] {
    const list: string[] = [];
    const addCandidate = (url?: string | null) => {
      if (!url) return;
      const clean = normalizeAgentUrl(url);
      if (clean && !list.includes(clean)) list.push(clean);
    };

    try {
      addCandidate(localStorage.getItem("netlens_agent_url"));
    } catch {}
    if (process.env.NEXT_PUBLIC_AGENT_URL) {
      addCandidate(process.env.NEXT_PUBLIC_AGENT_URL);
    }
    addCandidate(agentUrl);
    addCandidate(customUrlInput);

    if (typeof window !== "undefined") {
      const host = window.location.hostname;
      if (window.location.protocol === "http:" && host && host !== "localhost" && host !== "127.0.0.1") {
        addCandidate(`http://${host}:8080`);
      }
    }

    addCandidate("http://127.0.0.1:8080");
    addCandidate("http://localhost:8080");

    return list;
  }

  async function onAgentDetected(url: string, status: AgentStatus, latency: number) {
    const isFirstAutoTrigger = !autoScanTriggeredRef.current;

    setAgentUrl(url);
    setCustomUrlInput(url);
    setAgentStatus(status);
    setAgentType("netlens");
    setAgentLatency(latency);
    try {
      localStorage.setItem("netlens_agent_url", url);
    } catch {}

    // 1. Fetch updated network profile & CIDR from the Go agent
    const netProfile = await fetchNetworkProfile(`${url}/api/network`);
    const targetCidr = netProfile?.cidr || cidr || "192.168.0.0/24";

    // 2. Fetch existing devices in memory
    fetchDevices(`${url}/api/devices`);

    // 3. Auto-close download modal when agent connects
    setShowDownloadModal(false);

    // 4. Auto-launch deep network sweep on fresh agent connect!
    if (isFirstAutoTrigger) {
      autoScanTriggeredRef.current = true;
      executeScan(targetCidr, url);
    }
  }

  // 1. Initialize on Mount
  useEffect(() => {
    if (typeof window !== "undefined") {
      setOriginUrl(window.location.origin);
      const hidePref = localStorage.getItem("hide_agent_popup");
      if (hidePref === "true") {
        setShowDownloadModal(false);
        setDontShowAgain(true);
      }
    }

    // Restore cached session devices if available
    try {
      const cached = sessionStorage.getItem("lan_devices");
      const cachedTime = sessionStorage.getItem("lan_last_scan");
      if (cached) setDevices(JSON.parse(cached));
      if (cachedTime) setLastScanned(cachedTime);
    } catch {}

    const candidates = getAgentCandidates();
    const initialUrl = candidates[0] || "http://127.0.0.1:8080";
    setAgentUrl(initialUrl);
    setCustomUrlInput(initialUrl);

    // Bootstrap initial agent probe
    probeAllCandidates();
  }, []);

  // 2. Continuous Fast Agent Auto-Discovery Polling (1s when waiting, 3.5s when connected)
  useEffect(() => {
    const isConnected = agentType === "netlens" && agentStatus?.status === "online";
    const intervalMs = isConnected ? 3500 : 1000;

    const timer = setInterval(() => {
      probeAllCandidates();
    }, intervalMs);

    return () => clearInterval(timer);
  }, [agentUrl, agentType, agentStatus?.status, cidr]);

  async function probeAllCandidates() {
    if (isProbingRef.current) return;
    isProbingRef.current = true;

    try {
      const candidates = getAgentCandidates();

      for (const url of candidates) {
        try {
          const start = performance.now();
          const res = await fetch(`${url}/api/agent/status`, {
            signal: AbortSignal.timeout(900)
          }).catch(() => null);

          if (res && res.ok) {
            const data: AgentStatus = await res.json();
            const latency = Math.max(1, Math.round(performance.now() - start));
            await onAgentDetected(url, data, latency);
            return;
          }

          const healthRes = await fetch(`${url}/health`, {
            signal: AbortSignal.timeout(900)
          }).catch(() => null);

          if (healthRes && healthRes.ok) {
            const latency = Math.max(1, Math.round(performance.now() - start));
            const healthData = await healthRes.json().catch(() => ({}));
            const data: AgentStatus = {
              status: "online",
              engine: healthData.agent === "go" ? "Go High-Speed Agent" : "Go High-Speed Agent",
              hostname: "127.0.0.1",
              os: "Linux",
              arch: "x86_64 / arm64"
            };
            await onAgentDetected(url, data, latency);
            return;
          }
        } catch {}
      }

      // If Go agent is not running yet, try Next.js Server Core if not already set
      if (agentType === "browser") {
        try {
          const start = performance.now();
          const res = await fetch("/api/agent/status", { signal: AbortSignal.timeout(1200) }).catch(() => null);
          if (res && res.ok) {
            const data: AgentStatus = await res.json();
            const latency = Math.max(1, Math.round(performance.now() - start));
            setAgentStatus(data);
            setAgentType("nextjs");
            setAgentLatency(latency);
            fetchNetworkProfile("/api/network");
            fetchDevices("/api/devices");
            return;
          }
        } catch {}
      }
    } finally {
      isProbingRef.current = false;
    }
  }

  async function bootstrapAgent(targetUrl?: string) {
    if (targetUrl) {
      const clean = normalizeAgentUrl(targetUrl);
      setAgentUrl(clean);
      setCustomUrlInput(clean);
    }
    await probeAllCandidates();
  }

  async function fetchNetworkProfile(endpoint: string): Promise<NetworkProfile | null> {
    try {
      const res = await fetch(endpoint, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        const netProfile: NetworkProfile = await res.json();
        if (netProfile && netProfile.cidr) {
          setProfile(netProfile);
          setCidr(netProfile.cidr);
          return netProfile;
        }
      }
    } catch {}
    fallbackClientDetection();
    return null;
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
      })
      .catch(() => {});
  }

  // Network Scan Execution
  async function executeScan(targetCidr?: string, overrideUrl?: string) {
    if (busy) return;

    const scanCidr = targetCidr || cidr || profile?.cidr || "192.168.0.0/24";
    const effectiveUrl = overrideUrl ? normalizeAgentUrl(overrideUrl) : normalizeAgentUrl(agentUrl);
    const isNetlens = overrideUrl ? true : (agentType === "netlens");

    setDevices([]);
    try {
      sessionStorage.removeItem("lan_devices");
    } catch {}

    setBusy(true);
    setError("");
    setProgress(5);
    setProgressText(`Connecting to ${isNetlens ? "Go High-Speed Agent" : "Subnet Scanner"} & sweeping subnet ${scanCidr}...`);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const cleanAgentUrl = effectiveUrl.replace(/\/$/, "");
    const baseApiUrl = isNetlens && cleanAgentUrl ? cleanAgentUrl : "";

    // Method 1: Real-Time SSE Stream (from NetLens Agent or Next.js)
    if (isNetlens || agentType === "nextjs") {
      let streamSucceeded = false;
      const discoveredMap = new Map<string, Device>();

      const runSseStream = (streamEndpoint: string): Promise<boolean> => {
        return new Promise((resolve) => {
          let sDone = false;
          try {
            const eventSource = new EventSource(streamEndpoint);
            eventSourceRef.current = eventSource;

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
              sDone = true;
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
              resolve(true);
            });

            eventSource.addEventListener("error", () => {
              eventSource.close();
              eventSourceRef.current = null;
              resolve(sDone);
            });

            setTimeout(() => {
              if (!sDone && discoveredMap.size === 0 && progress <= 10) {
                eventSource.close();
                eventSourceRef.current = null;
                resolve(false);
              }
            }, 12000);
          } catch {
            resolve(false);
          }
        });
      };

      try {
        const primaryStreamUrl = `${baseApiUrl}/api/scan/stream?cidr=${encodeURIComponent(scanCidr)}`;
        streamSucceeded = await runSseStream(primaryStreamUrl);

        if (!streamSucceeded && baseApiUrl !== "") {
          setProgressText("Direct agent connection unreachable; routing scan through Next.js Server...");
          streamSucceeded = await runSseStream(`/api/scan/stream?cidr=${encodeURIComponent(scanCidr)}`);
        }

        if (streamSucceeded) {
          setProgress(100);
          setProgressText("Scan completed successfully");
          setBusy(false);
          return;
        }
      } catch {}

      // Method 2: POST /api/scan REST API
      try {
        setProgress(35);
        setProgressText(`Executing scan via /api/scan...`);

        let scanRes = await fetch(`${baseApiUrl}/api/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cidr: scanCidr }),
          signal: controller.signal
        }).catch(() => null);

        if (!scanRes || !scanRes.ok) {
          scanRes = await fetch(`/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cidr: scanCidr }),
            signal: controller.signal
          }).catch(() => null);
        }

        if (scanRes && scanRes.ok) {
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

    // Method 3: In-Browser Client Scanner (Fallback)
    try {
      setProgress(25);
      setProgressText("Probing subnet directly via client browser engine...");
      const scanPorts = [21, 22, 53, 80, 135, 139, 443, 445, 1883, 3000, 3389, 5000, 5353, 8000, 8080, 8443, 9000];

      const results = await runClientNetworkScan(
        scanCidr,
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

  function startScanFromModal() {
    setShowDownloadModal(false);
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

  function copyToClipboard(text: string, id: string) {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedText(id);
      setTimeout(() => setCopiedText(null), 2200);
    }
  }

  function handleCloseModal() {
    if (dontShowAgain) {
      try {
        localStorage.setItem("hide_agent_popup", "true");
      } catch {}
    }
    setShowDownloadModal(false);
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

  // Terminal one-liners
  const quickCurlCmd = originUrl
    ? `curl -sSL ${originUrl}/api/agent/install | bash`
    : `curl -sSL http://localhost:3000/api/agent/install | bash`;

  const quickPowershellCmd = originUrl
    ? `irm ${originUrl}/api/agent/install?os=windows | iex`
    : `irm http://localhost:3000/api/agent/install?os=windows | iex`;

  const isAgentConnected = agentType === "netlens" && agentStatus?.status === "online";

  return (
    <main>
      <header>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <div>
            <span className="dot" /> <b>LAN SENTINEL</b>
            <small> intelligent Wi-Fi auto-detection & security monitor</small>
          </div>

          {/* Download Agent Button in Header */}
          <button
            onClick={() => setShowDownloadModal(true)}
            style={{
              background: "#16273c",
              border: "1px solid #254266",
              color: "#60a5fa",
              fontSize: "12px",
              padding: "5px 12px",
              borderRadius: "16px",
              display: "flex",
              alignItems: "center",
              gap: "6px"
            }}
          >
            <span>📥</span>
            <span>Download Agent & Instructions</span>
          </button>

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
              className={agentType === "netlens" ? "" : "pulsing"}
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

      {/* 🚀 PRIMARY POPUP: DOWNLOAD & RUN AGENT + INSTRUCTIONS MODAL */}
      {showDownloadModal && (
        <div className="overlay" onClick={handleCloseModal}>
          <div className="agentModal" onClick={(e) => e.stopPropagation()}>
            <div className="agentModalHeader">
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ fontSize: "20px" }}>⚡</span>
                  <span style={{ color: "#4ade80", fontSize: "12px", fontWeight: 700, letterSpacing: "0.06em" }}>
                    NETLENS AGENT QUICK START & DEEP SCANNER
                  </span>
                </div>
                <h2 style={{ fontSize: "26px", margin: "6px 0 2px", color: "#fff" }}>
                  Download & Run Local Network Agent
                </h2>
                <p style={{ color: "#8da0b8", fontSize: "13px", margin: 0, lineHeight: "1.5" }}>
                  Web browsers restrict raw ICMP pings and ARP hardware discovery. Run the lightweight, open-source Go agent on your machine for full 1-254 subnet sweeps, vendor detection, and latency measurement.
                </p>
              </div>
              <button className="close" onClick={handleCloseModal} title="Close popup">
                ×
              </button>
            </div>

            {/* Live Connection Status Banner */}
            <div
              style={{
                marginTop: "16px",
                padding: "14px 18px",
                borderRadius: "12px",
                background: isAgentConnected ? "#0e2617" : "#161b24",
                border: `1px solid ${isAgentConnected ? "#1e5e34" : "#283547"}`,
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: "12px"
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span
                  className={isAgentConnected ? "" : "pulsing"}
                  style={{
                    display: "inline-block",
                    width: "10px",
                    height: "10px",
                    borderRadius: "50%",
                    background: isAgentConnected ? "#4ade80" : "#fbbf24"
                  }}
                />
                <div>
                  <div style={{ fontSize: "14px", fontWeight: "bold", color: isAgentConnected ? "#4ade80" : "#fbbf24" }}>
                    {isAgentConnected
                      ? "🟢 NetLens Agent Online & Ready to Scan!"
                      : "🟡 Waiting for Local Agent on http://127.0.0.1:8080..."}
                  </div>
                  <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "2px" }}>
                    {isAgentConnected
                      ? `Engine: ${agentStatus?.engine || "Go Subnet Sweeper"} · Host: ${agentStatus?.hostname || "Local"} · Latency: ${agentLatency || 1}ms`
                      : "Run any command or executable below — this dashboard connects automatically in real-time."}
                  </div>
                </div>
              </div>

              {isAgentConnected ? (
                <button
                  onClick={startScanFromModal}
                  style={{
                    background: "#4ade80",
                    color: "#07101c",
                    fontSize: "13px",
                    fontWeight: 800,
                    padding: "10px 18px",
                    borderRadius: "8px"
                  }}
                >
                  🚀 Launch Deep Network Scan
                </button>
              ) : (
                <button
                  onClick={() => bootstrapAgent(agentUrl || "http://127.0.0.1:8080")}
                  style={{
                    background: "#1c2a3d",
                    color: "#93c5fd",
                    border: "1px solid #2d4566",
                    fontSize: "12px",
                    padding: "8px 14px",
                    borderRadius: "8px"
                  }}
                >
                  🔄 Check Status
                </button>
              )}
            </div>

            {/* Platform Selection Tabs */}
            <div className="tabNav">
              <button
                className={`tabBtn ${activeDownloadTab === "quick" ? "active" : ""}`}
                onClick={() => setActiveDownloadTab("quick")}
              >
                ⚡ 1-Click Terminal (Fastest)
              </button>
              <button
                className={`tabBtn ${activeDownloadTab === "windows" ? "active" : ""}`}
                onClick={() => setActiveDownloadTab("windows")}
              >
                🪟 Windows (EXE / PS)
              </button>
              <button
                className={`tabBtn ${activeDownloadTab === "mac" ? "active" : ""}`}
                onClick={() => setActiveDownloadTab("mac")}
              >
                🍎 macOS (Terminal / Binary)
              </button>
              <button
                className={`tabBtn ${activeDownloadTab === "linux" ? "active" : ""}`}
                onClick={() => setActiveDownloadTab("linux")}
              >
                🐧 Linux (Terminal / Binary)
              </button>
              <button
                className={`tabBtn ${activeDownloadTab === "source" ? "active" : ""}`}
                onClick={() => setActiveDownloadTab("source")}
              >
                📦 Go / Node Source
              </button>
            </div>

            {/* Tab Contents */}
            <div style={{ marginTop: "16px" }}>
              {/* TAB 1: 1-Click Quick Run */}
              {activeDownloadTab === "quick" && (
                <div>
                  <div style={{ fontSize: "13px", color: "#cbd5e1", marginBottom: "8px" }}>
                    <b>Option A: Linux / macOS Terminal (Paste & Press Enter)</b>
                  </div>
                  <div className="codeBox">
                    <span style={{ wordBreak: "break-all" }}>{quickCurlCmd}</span>
                    <button
                      className="copyBtn"
                      onClick={() => copyToClipboard(quickCurlCmd, "quick-sh")}
                    >
                      {copiedText === "quick-sh" ? "✅ Copied" : "📋 Copy"}
                    </button>
                  </div>

                  <div style={{ fontSize: "13px", color: "#cbd5e1", marginTop: "16px", marginBottom: "8px" }}>
                    <b>Option B: Windows PowerShell (Paste & Press Enter)</b>
                  </div>
                  <div className="codeBox">
                    <span style={{ wordBreak: "break-all" }}>{quickPowershellCmd}</span>
                    <button
                      className="copyBtn"
                      onClick={() => copyToClipboard(quickPowershellCmd, "quick-ps")}
                    >
                      {copiedText === "quick-ps" ? "✅ Copied" : "📋 Copy"}
                    </button>
                  </div>
                </div>
              )}

              {/* TAB 2: Windows */}
              {activeDownloadTab === "windows" && (
                <div>
                  <p style={{ color: "#94a3b8", fontSize: "13px", marginTop: 0 }}>
                    Download the pre-compiled Windows executable or run via PowerShell:
                  </p>

                  <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", margin: "12px 0" }}>
                    <a
                      href="/api/agent/download?os=windows"
                      download="wifi-agent.exe"
                      style={{
                        background: "#2563eb",
                        color: "#fff",
                        textDecoration: "none",
                        padding: "10px 18px",
                        borderRadius: "8px",
                        fontWeight: "bold",
                        fontSize: "13px",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px"
                      }}
                    >
                      ⬇️ Download wifi-agent.exe (Windows 64-bit)
                    </a>
                  </div>

                  <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "12px" }}>
                    <b>Or run directly via PowerShell:</b>
                  </div>
                  <div className="codeBox">
                    <span>{quickPowershellCmd}</span>
                    <button className="copyBtn" onClick={() => copyToClipboard(quickPowershellCmd, "win-ps")}>
                      {copiedText === "win-ps" ? "✅ Copied" : "📋 Copy"}
                    </button>
                  </div>
                </div>
              )}

              {/* TAB 3: macOS */}
              {activeDownloadTab === "mac" && (
                <div>
                  <p style={{ color: "#94a3b8", fontSize: "13px", marginTop: 0 }}>
                    Run the 1-liner in Terminal or download the native macOS binary:
                  </p>

                  <div className="codeBox">
                    <span>{quickCurlCmd}</span>
                    <button className="copyBtn" onClick={() => copyToClipboard(quickCurlCmd, "mac-sh")}>
                      {copiedText === "mac-sh" ? "✅ Copied" : "📋 Copy"}
                    </button>
                  </div>

                  <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", marginTop: "14px" }}>
                    <a
                      href="/api/agent/download?os=macos&arch=arm64"
                      download="wifi-agent-mac-arm64"
                      style={{
                        background: "#1e293b",
                        border: "1px solid #334155",
                        color: "#60a5fa",
                        textDecoration: "none",
                        padding: "9px 15px",
                        borderRadius: "8px",
                        fontSize: "13px",
                        fontWeight: 600
                      }}
                    >
                      ⬇️ Apple Silicon Binary (M1/M2/M3/M4)
                    </a>
                    <a
                      href="/api/agent/download?os=macos&arch=x86_64"
                      download="wifi-agent-mac-intel"
                      style={{
                        background: "#1e293b",
                        border: "1px solid #334155",
                        color: "#60a5fa",
                        textDecoration: "none",
                        padding: "9px 15px",
                        borderRadius: "8px",
                        fontSize: "13px",
                        fontWeight: 600
                      }}
                    >
                      ⬇️ Intel Mac Binary (x86_64)
                    </a>
                  </div>
                </div>
              )}

              {/* TAB 4: Linux */}
              {activeDownloadTab === "linux" && (
                <div>
                  <p style={{ color: "#94a3b8", fontSize: "13px", marginTop: 0 }}>
                    Run the installer script or download the standalone Linux binary:
                  </p>

                  <div className="codeBox">
                    <span>{quickCurlCmd}</span>
                    <button className="copyBtn" onClick={() => copyToClipboard(quickCurlCmd, "linux-sh")}>
                      {copiedText === "linux-sh" ? "✅ Copied" : "📋 Copy"}
                    </button>
                  </div>

                  <div style={{ marginTop: "14px" }}>
                    <a
                      href="/api/agent/download?os=linux"
                      download="wifi-agent-linux"
                      style={{
                        background: "#1e293b",
                        border: "1px solid #334155",
                        color: "#60a5fa",
                        textDecoration: "none",
                        padding: "9px 15px",
                        borderRadius: "8px",
                        fontSize: "13px",
                        fontWeight: 600,
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px"
                      }}
                    >
                      ⬇️ Download wifi-agent-linux-amd64 (64-bit)
                    </a>
                  </div>
                </div>
              )}

              {/* TAB 5: Source */}
              {activeDownloadTab === "source" && (
                <div>
                  <p style={{ color: "#94a3b8", fontSize: "13px", marginTop: 0 }}>
                    Run directly from source repository:
                  </p>

                  <div style={{ fontSize: "12px", color: "#94a3b8", marginBottom: "4px" }}>Go Agent:</div>
                  <div className="codeBox">
                    <span>cd agent-go && go run main.go</span>
                    <button className="copyBtn" onClick={() => copyToClipboard("cd agent-go && go run main.go", "src-go")}>
                      {copiedText === "src-go" ? "✅ Copied" : "📋 Copy"}
                    </button>
                  </div>

                  <div style={{ fontSize: "12px", color: "#94a3b8", marginTop: "12px", marginBottom: "4px" }}>
                    Or via root npm script:
                  </div>
                  <div className="codeBox">
                    <span>npm run agent:go</span>
                    <button className="copyBtn" onClick={() => copyToClipboard("npm run agent:go", "src-npm")}>
                      {copiedText === "src-npm" ? "✅ Copied" : "📋 Copy"}
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Step-by-Step Flow */}
            <div className="stepGrid">
              <div className="stepBox">
                <div className="stepNum">1</div>
                <h4 style={{ margin: "4px 0 6px", fontSize: "14px", color: "#f1f5f9" }}>Run or Download</h4>
                <p style={{ margin: 0, fontSize: "12px", color: "#8da0b8", lineHeight: "1.5" }}>
                  Paste the 1-line command in your terminal or launch the downloaded binary.
                </p>
              </div>

              <div className="stepBox">
                <div className="stepNum">2</div>
                <h4 style={{ margin: "4px 0 6px", fontSize: "14px", color: "#f1f5f9" }}>Daemon Starts</h4>
                <p style={{ margin: 0, fontSize: "12px", color: "#8da0b8", lineHeight: "1.5" }}>
                  Agent listens locally on <code>http://127.0.0.1:8080</code> with zero telemetry or tracking.
                </p>
              </div>

              <div className="stepBox">
                <div className="stepNum">3</div>
                <h4 style={{ margin: "4px 0 6px", fontSize: "14px", color: "#f1f5f9" }}>Deep LAN Sweep</h4>
                <p style={{ margin: 0, fontSize: "12px", color: "#8da0b8", lineHeight: "1.5" }}>
                  Dashboard auto-connects and streams active devices, MAC vendors, and open ports live.
                </p>
              </div>
            </div>

            {/* Footer Action Controls */}
            <div
              style={{
                marginTop: "22px",
                paddingTop: "16px",
                borderTop: "1px solid #1c2b3e",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                flexWrap: "wrap",
                gap: "12px"
              }}
            >
              <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", color: "#64748b", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={dontShowAgain}
                  onChange={(e) => setDontShowAgain(e.target.checked)}
                />
                <span>Don&apos;t show this popup automatically on startup</span>
              </label>

              <div style={{ display: "flex", gap: "10px" }}>
                <button
                  onClick={() => {
                    handleCloseModal();
                    setAgentType("browser");
                    fallbackClientDetection();
                    executeScan(cidr);
                  }}
                  style={{
                    background: "#16202e",
                    color: "#94a3b8",
                    border: "1px solid #233346",
                    fontSize: "12px",
                    padding: "9px 14px"
                  }}
                >
                  🌐 Scan in Browser (No Agent)
                </button>
                <button
                  onClick={startScanFromModal}
                  style={{
                    background: isAgentConnected ? "#4ade80" : "#3b82f6",
                    color: isAgentConnected ? "#07101c" : "#fff",
                    fontSize: "13px",
                    padding: "9px 18px"
                  }}
                >
                  {isAgentConnected ? "🚀 Start Deep Scan" : "Close & Continue"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

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
                    placeholder="http://127.0.0.1:8080 or https://your-agent.onrender.com"
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
                    Engine: <b style={{ color: "#fff" }}>{agentStatus?.engine || "In-Browser Engine"}</b>
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
                    const host = typeof window !== "undefined" ? window.location.hostname : "127.0.0.1";
                    const isLocal = host === "localhost" || host === "127.0.0.1";
                    const target = isLocal ? "http://127.0.0.1:8080" : `http://${host}:8080`;
                    setCustomUrlInput(target);
                    bootstrapAgent(target);
                    setShowAgentConfig(false);
                  }}
                  style={{ background: "#162232", color: "#4ade80", border: "1px solid #23374d", fontSize: "12px", padding: "8px 12px" }}
                >
                  ⚡ Use Host Go Agent (:8080)
                </button>
                <button
                  onClick={() => {
                    setAgentType("nextjs");
                    bootstrapAgent("");
                    setShowAgentConfig(false);
                  }}
                  style={{ background: "#162232", color: "#60a5fa", border: "1px solid #23374d", fontSize: "12px", padding: "8px 12px" }}
                >
                  🚀 Use Next.js Core (Recommended for Remote PCs)
                </button>
                <button
                  onClick={() => {
                    setAgentType("browser");
                    fallbackClientDetection();
                    setShowAgentConfig(false);
                  }}
                  style={{ background: "#162232", color: "#fbbf24", border: "1px solid #23374d", fontSize: "12px", padding: "8px 12px" }}
                >
                  🌐 Use Browser Sandbox
                </button>
              </div>

              <div style={{ marginTop: "12px", fontSize: "11px", color: "#64748b", lineHeight: "1.6" }}>
                💡 <b>Remote System Tip:</b> When accessing the dashboard from another PC or phone, select <b>Next.js Core</b> to automatically route requests through the host server, or use <code>http://&lt;HOST_IP&gt;:8080</code>.
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

      {/* Main Hero & Scan Control */}
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

      {/* Stats Cards */}
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

      {/* Active Systems Table */}
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

      {/* Defensive Security Advice Side Drawer */}
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
