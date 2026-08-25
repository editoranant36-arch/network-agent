"use client";

import {useEffect, useMemo, useState} from "react";

type Device = {
  ip:string;
  hostname?:string;
  dns?:string;
  vendor?:string;
  mac?:string;
  gateway?:string;
  reachable:boolean;
  ping_ms?:number;
  open_ports:number[];
};

type Advice = {
  title:string;
  severity:"info"|"low"|"medium";
  why:string;
  actions:string[];
};

const API = "";

function buildAdvice(d:Device): Advice[] {
  const advice: Advice[] = [];
  const ports = new Set(d.open_ports || []);

  if (ports.has(445) || ports.has(139)) {
    advice.push({
      title:"Windows/SMB file sharing exposed",
      severity:"medium",
      why:"TCP 445 or 139 is reachable from the scanned LAN. This is evidence that SMB-related services accept TCP connections; it does not prove compromise.",
      actions:[
        "Disable SMB/file sharing if the device does not need it.",
        "Use the host firewall to restrict SMB to trusted LAN segments/devices.",
        "Keep Windows and SMB components patched.",
        "Avoid exposing SMB beyond networks you control."
      ]
    });
  }

  if (ports.has(22)) {
    advice.push({
      title:"SSH service exposed",
      severity:"low",
      why:"TCP 22 accepted a connection during this scan. SSH is an administrative service and should be limited to trusted management sources.",
      actions:[
        "Disable SSH if it is not required.",
        "Restrict TCP 22 with the host firewall to trusted administrators.",
        "Prefer key-based authentication and disable password login where appropriate.",
        "Keep the SSH server and operating system updated."
      ]
    });
  }

  if (ports.has(3389)) {
    advice.push({
      title:"Remote Desktop exposed",
      severity:"medium",
      why:"TCP 3389 accepted a connection during this scan. RDP is a remote administration service and is a common target for credential attacks.",
      actions:[
        "Disable Remote Desktop when it is unnecessary.",
        "Restrict RDP to trusted management hosts or a VPN.",
        "Require Network Level Authentication where supported.",
        "Use strong unique credentials and keep the OS patched."
      ]
    });
  }

  if (ports.has(80)) {
    advice.push({
      title:"HTTP service exposed",
      severity:"info",
      why:"TCP 80 accepted a connection. This only establishes network reachability of an HTTP service; it does not indicate a vulnerability.",
      actions:[
        "Confirm that the web service is intentionally running.",
        "Keep the web server and application dependencies updated.",
        "Use HTTPS for sensitive traffic and redirect HTTP where appropriate.",
        "Remove unused web applications and administrative endpoints."
      ]
    });
  }

  if (ports.has(443)) {
    advice.push({
      title:"HTTPS service exposed",
      severity:"info",
      why:"TCP 443 accepted a connection. HTTPS exposure is not itself a security problem; verify that the service is intended and correctly maintained.",
      actions:[
        "Keep the web server/application patched.",
        "Use a valid certificate and modern TLS configuration.",
        "Restrict administrative interfaces to trusted users/networks.",
        "Remove unused services and endpoints."
      ]
    });
  }

  if (ports.has(8080) || ports.has(8443)) {
    advice.push({
      title:"Alternate web service exposed",
      severity:"low",
      why:"A common alternate web port accepted a connection. These ports are frequently used for development, dashboards, proxies, or application servers.",
      actions:[
        "Identify the application listening on the port.",
        "Disable it if it is not required.",
        "Restrict management/admin interfaces with firewall rules and authentication.",
        "Keep the application and dependencies updated."
      ]
    });
  }

  if (ports.has(53)) {
    advice.push({
      title:"DNS service exposed",
      severity:"info",
      why:"TCP 53 accepted a connection. This may be a DNS server, but this scan does not determine whether it is recursive, authoritative, or securely configured.",
      actions:[
        "Confirm that the host is intentionally providing DNS.",
        "Restrict recursive DNS access to trusted clients.",
        "Keep DNS software updated.",
        "Review DNS logs and configuration if this is an important infrastructure host."
      ]
    });
  }

  if (!advice.length) {
    advice.push({
      title:"No evidence-based service-specific warning",
      severity:"info",
      why:"The configured TCP probes did not identify any of the monitored ports as reachable. This is not proof that the device is secure or has no other services.",
      actions:[
        "Keep the operating system and installed software updated.",
        "Enable the host firewall.",
        "Remove software and services that are not required.",
        "Re-scan after configuration changes."
      ]
    });
  }

  return advice;
}

export default function Home(){
  const [cidr,setCidr] = useState("192.168.0.0/24");
  const [devices,setDevices] = useState<Device[]>([]);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState("");
  const [selected,setSelected] = useState<Device|null>(null);
  const [lastScanned,setLastScanned] = useState<string|null>(null);

  async function scan(){
    setBusy(true); setError("");
    try{
      const r = await fetch(`/api/scan`, {
        method:"POST", headers:{"content-type":"application/json"},
        body:JSON.stringify({cidr, ports:[22,53,80,135,139,443,445,3389,8080,8443]})
      });
      if(!r.ok) {
        const errData = await r.json().catch(() => ({}));
        throw new Error(errData.error || "Scan failed");
      }
      const data = await r.json();
      setDevices(Array.isArray(data) ? data : []);
      setLastScanned(new Date().toLocaleTimeString());
    }catch(e:any){setError(e.message || "Scan failed")}
    finally{setBusy(false)}
  }

  async function clearMemory(){
    try {
      await fetch(`/api/devices`, { method: "DELETE" });
      setDevices([]);
      setLastScanned(null);
    } catch {}
  }

  useEffect(()=>{
    fetch(`/api/network`)
      .then(r=>r.json())
      .then(info=>{
        if (info.cidr) setCidr(info.cidr);
      })
      .catch(()=>{});

    fetch(`/api/devices`)
      .then(r=>r.json())
      .then(res => {
        if (Array.isArray(res)) {
          setDevices(res);
        } else if (res && Array.isArray(res.devices)) {
          setDevices(res.devices);
          if (res.last_scan) {
            setLastScanned(new Date(res.last_scan).toLocaleTimeString());
          }
        }
      })
      .catch(()=>{});
  },[]);

  const stats = useMemo(()=>{
    const list = Array.isArray(devices) ? devices : [];
    return {
      live: list.length,
      ports: list.reduce((n,d)=>n+(d.open_ports ? d.open_ports.length : 0),0),
      identified: list.filter(d => d.hostname || d.dns || d.vendor).length
    };
  },[devices]);

  const deviceList = Array.isArray(devices) ? devices : [];

  return <main>
    <header>
      <div><span className="dot"/> <b>LAN SENTINEL</b><small> in-dashboard network monitor (temporary memory)</small></div>
      <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
        {lastScanned && <small style={{ color: "#8996a9" }}>Last scan: {lastScanned}</small>}
        {deviceList.length > 0 && <button onClick={clearMemory} style={{ background: "#1b2737", color: "#dce7f5" }} disabled={busy}>Clear Memory</button>}
        <button onClick={scan} disabled={busy}>{busy ? "Scanning…" : "Scan Network"}</button>
      </div>
    </header>

    <section className="hero">
      <h1>Network <span>Overview</span></h1>
      <p>Direct in-dashboard scanner. Discovers hosts, host names, DNS, MAC vendors, and open ports in temporary memory.</p>
      <div className="bar">
        <input value={cidr} onChange={e=>setCidr(e.target.value)} placeholder="192.168.0.0/24"/>
        <button onClick={scan} disabled={busy}>{busy ? "Scanning System…" : "Start scan"}</button>
      </div>
      {error && <div className="error">{error}</div>}
      {busy && <div style={{ color: "#62e6a7", marginTop: "12px", fontSize: "14px" }}>● Scanning network in progress... Discovering live hosts & open ports...</div>}
    </section>

    <section className="stats">
      <div><small>ONLINE DEVICES</small><strong>{stats.live}</strong></div>
      <div><small>IDENTIFIED HOSTS</small><strong>{stats.identified}</strong></div>
      <div><small>OPEN SERVICES</small><strong>{stats.ports}</strong></div>
    </section>

    <section className="panel">
      <div className="panelHead">
        <h2>Discovered devices</h2>
        <span>{busy ? "Scanning in progress..." : `${deviceList.length} hosts in temporary memory`} · click a row for advice</span>
      </div>
      <div className="tableWrap">
        <table><thead><tr>
          <th>STATUS</th>
          <th>IP ADDRESS</th>
          <th>HOST NAME</th>
          <th>VENDOR / MAC</th>
          <th>GATEWAY</th>
          <th>PING</th>
          <th>OPEN PORTS</th>
        </tr></thead><tbody>
        {deviceList.map(d=>{
          const hostDisplay = d.hostname || d.dns;
          return (
            <tr key={d.ip} className="deviceRow" onClick={()=>setSelected(d)}>
              <td><span className="online">● online</span></td>
              <td><b>{d.ip}</b></td>
              <td>
                {hostDisplay ? (
                  <span style={{ color: "#62e6a7", fontWeight: 600 }}>{hostDisplay}</span>
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
              <td>{d.open_ports && d.open_ports.length ? d.open_ports.join(", ") : "none detected"}</td>
            </tr>
          );
        })}
        {!deviceList.length && !busy && <tr><td colSpan={7} className="empty">No scan results in temporary memory yet. Click "Start scan" above to scan the network.</td></tr>}
        {busy && !deviceList.length && <tr><td colSpan={7} className="empty" style={{ color: "#62e6a7" }}>Scanning network and resolving hostnames... please wait a few seconds.</td></tr>}
        </tbody></table>
      </div>
    </section>

    {selected && <div className="overlay" onClick={()=>setSelected(null)}>
      <aside className="advice" onClick={e=>e.stopPropagation()}>
        <div className="adviceHead">
          <div>
            <small>DEFENSIVE SECURITY ADVICE</small>
            <h2>{selected.hostname || selected.dns || selected.ip}</h2>
            <div style={{ color: "#8996a9", fontSize: "14px", marginTop: "4px" }}>
              IP: <b style={{ color: "#fff" }}>{selected.ip}</b>
              {selected.vendor ? <span> · Vendor: <b style={{ color: "#fff" }}>{selected.vendor}</b></span> : null}
              {selected.mac ? <span> · MAC: <code style={{ color: "#75e0b5" }}>{selected.mac}</code></span> : null}
            </div>
          </div>
          <button className="close" onClick={()=>setSelected(null)}>×</button>
        </div>

        <div className="evidence">
          <b>Evidence from this scan</b>
          <p>Reachable: <strong>{selected.reachable ? "yes" : "no"}</strong> · Ping: <strong>{selected.ping_ms != null ? `${selected.ping_ms} ms` : "not measured"}</strong></p>
          <p>Detected TCP ports: <strong>{selected.open_ports && selected.open_ports.length ? selected.open_ports.join(", ") : "none"}</strong></p>
          <small>Open-port detection proves only that a TCP connection was accepted during this scan. It does not prove a vulnerability, compromise, or attacker activity.</small>
        </div>

        <div className="notice">
          Recommendations are defensive. Verify the service owner and business need before changing firewall or service settings.
        </div>

        {buildAdvice(selected).map((a,i)=><article className="adviceItem" key={i}>
          <div className={`severity ${a.severity}`}>{a.severity.toUpperCase()}</div>
          <h3>{a.title}</h3>
          <p>{a.why}</p>
          <h4>Recommended protection</h4>
          <ul>{a.actions.map((x,j)=><li key={j}>{x}</li>)}</ul>
        </article>)}

        <button className="rescan" onClick={()=>{setSelected(null);scan()}}>Re-scan network</button>
      </aside>
    </div>}

    <footer>Run scans only against networks you own or are authorized to administer.</footer>
  </main>;
}
