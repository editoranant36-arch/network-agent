"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Device,
  NetworkProfile,
  buildClientDefensiveAdvice,
  detectBrowserNetworkProfile,
  runClientNetworkScan
} from "./lib/clientScanner";

export default function Home() {
  const [cidr, setCidr] = useState("192.168.0.0/24");
  const [profile, setProfile] = useState<NetworkProfile | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState("");
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Device | null>(null);
  const [lastScanned, setLastScanned] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const autoScanTriggeredRef = useRef(false);

  // Initialize network info and auto-detect Wi-Fi type (Personal vs Public)
  useEffect(() => {
    // 1. Restore previous session in-memory devices if present
    try {
      const cached = sessionStorage.getItem("lan_devices");
      const cachedTime = sessionStorage.getItem("lan_last_scan");
      if (cached) {
        setDevices(JSON.parse(cached));
      }
      if (cachedTime) {
        setLastScanned(cachedTime);
      }
    } catch {}

    // 2. Fetch network profile & Wi-Fi configuration from API, fallback to browser
    fetch("/api/network")
      .then((r) => r.json())
      .then((netProfile: NetworkProfile) => {
        if (netProfile) {
          setProfile(netProfile);
          if (netProfile.cidr) setCidr(netProfile.cidr);
          // Auto-trigger scan if no devices yet
          if (!autoScanTriggeredRef.current) {
            autoScanTriggeredRef.current = true;
            triggerAutoScan(netProfile.cidr);
          }
        }
      })
      .catch(() => {
        detectBrowserNetworkProfile()
          .then((bProfile) => {
            setProfile(bProfile);
            if (bProfile.cidr) setCidr(bProfile.cidr);
            if (!autoScanTriggeredRef.current) {
              autoScanTriggeredRef.current = true;
              triggerAutoScan(bProfile.cidr);
            }
          })
          .catch(() => {});
      });

    // 3. Load any active devices in memory from backend
    fetch("/api/devices")
      .then((r) => r.json())
      .then((res) => {
        if (res && Array.isArray(res.devices) && res.devices.length > 0) {
          setDevices((prev) => (prev.length > 0 ? prev : res.devices));
          if (res.last_scan) {
            setLastScanned(new Date(res.last_scan).toLocaleTimeString());
          }
        }
      })
      .catch(() => {});
  }, []);

  function triggerAutoScan(targetCidr?: string) {
    executeScan(targetCidr || cidr);
  }

  // Complete Network Scan: Sweeps all IPs 1-254, checks ping replies, and displays all active systems
  async function executeScan(targetCidr: string) {
    if (busy) return;

    // Clear previous scan data for a clean fresh scan
    setDevices([]);
    try {
      sessionStorage.removeItem("lan_devices");
    } catch {}

    setBusy(true);
    setError("");
    setProgress(15);
    setProgressText(`Auto-analyzing ${profile?.ssid || "Wi-Fi"} network and sweeping IPs...`);

    const controller = new AbortController();
    abortControllerRef.current = controller;

    const scanPorts = [21, 22, 53, 80, 135, 139, 443, 445, 1883, 3000, 3389, 5000, 5353, 8000, 8080, 8443, 9000];

    try {
      let results: Device[] = [];

      setProgress(35);
      setProgressText("Scanning active hosts, NetBIOS names, MAC vendors, and open ports...");

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cidr: targetCidr, ports: scanPorts }),
          signal: controller.signal
        });

        if (res.ok) {
          const data: Device[] = await res.json();
          if (Array.isArray(data) && data.length > 0) {
            results = data;
          }
        }
      } catch (err: any) {
        if (err?.name === "AbortError") throw err;
      }

      // If backend API was unreachable (e.g. static CDN host), run in-browser client scanner
      if (results.length === 0) {
        setProgress(25);
        setProgressText("Probing local Wi-Fi subnet directly in browser...");

        results = await runClientNetworkScan(
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
      }

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
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setBusy(false);
      setProgressText("Scan stopped by user");
    }
  }

  async function clearMemory() {
    setDevices([]);
    setLastScanned(null);
    setProgress(0);
    setProgressText("");
    try {
      sessionStorage.removeItem("lan_devices");
      sessionStorage.removeItem("lan_last_scan");
      await fetch("/api/devices", { method: "DELETE" }).catch(() => {});
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
        <div>
          <span className="dot" /> <b>LAN SENTINEL</b>
          <small> intelligent Wi-Fi auto-detection & security monitor</small>
        </div>
        <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
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
          <div style={{ display: "flex", gap: "14px", alignItems: "center" }}>
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
              ? `Sweeping subnet... (${deviceList.length} active systems found)`
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
