"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Device,
  DefensiveAdvice,
  buildClientDefensiveAdvice,
  detectClientLocalNetwork,
  runClientNetworkScan
} from "./lib/clientScanner";

export default function Home() {
  const [cidr, setCidr] = useState("192.168.0.0/24");
  const [devices, setDevices] = useState<Device[]>([]);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState("");
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Device | null>(null);
  const [lastScanned, setLastScanned] = useState<string | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Initialize purely in the browser on page load
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

    // 2. Detect local subnet using browser WebRTC
    detectClientLocalNetwork()
      .then((info) => {
        if (info.cidr) {
          setCidr(info.cidr);
        }
      })
      .catch(() => {});
  }, []);

  // 100% Client-side scan execution: immediately clears previous data
  async function scan() {
    if (busy) return;

    // Immediately remove previous scan data for a clean fresh scan
    setDevices([]);
    try {
      sessionStorage.removeItem("lan_devices");
    } catch {}

    setBusy(true);
    setError("");
    setProgress(0);
    setProgressText("Starting fresh network scan...");

    const controller = new AbortController();
    abortControllerRef.current = controller;

    try {
      const scanPorts = [21, 22, 53, 80, 135, 139, 443, 445, 1883, 3000, 3389, 5000, 5353, 8000, 8080, 8443, 9000];

      const results = await runClientNetworkScan(
        cidr,
        scanPorts,
        (scanned, total, pct) => {
          setProgress(pct);
          setProgressText(`Scanning: ${pct}% (${scanned}/${total} IPs)`);
        },
        (dev) => {
          // Stream fresh device directly to state in real-time
          setDevices((prev) => {
            const exists = prev.some((d) => d.ip === dev.ip);
            const updated = exists
              ? prev.map((d) => (d.ip === dev.ip ? dev : d))
              : [...prev, dev];
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

  function stopScan() {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setBusy(false);
      setProgressText("Scan stopped by user");
    }
  }

  function clearMemory() {
    setDevices([]);
    setLastScanned(null);
    setProgress(0);
    setProgressText("");
    try {
      sessionStorage.removeItem("lan_devices");
      sessionStorage.removeItem("lan_last_scan");
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

  return (
    <main>
      <header>
        <div>
          <span className="dot" /> <b>LAN SENTINEL</b>
          <small> in-dashboard network monitor (live client-side)</small>
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

      <section className="hero">
        <h1>
          Network <span>Overview</span>
        </h1>
        <p>Direct in-dashboard scanner. Discovers hosts, DNS, MAC vendors, and open ports in temporary memory.</p>
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
            <button onClick={scan}>Start scan</button>
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
          <small>ONLINE DEVICES</small>
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
          <h2>Discovered devices</h2>
          <span>{busy ? `Scanning... (${deviceList.length} discovered)` : `${deviceList.length} hosts discovered`} · click a row for advice</span>
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
                    No scan results in memory yet. Click &quot;Start scan&quot; above to scan the network.
                  </td>
                </tr>
              )}
              {busy && !deviceList.length && (
                <tr>
                  <td colSpan={7} className="empty" style={{ color: "#62e6a7" }}>
                    Probing subnet hosts and scanning open ports... live devices will appear here.
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

            {buildClientDefensiveAdvice(selected).map((a, i) => (
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
