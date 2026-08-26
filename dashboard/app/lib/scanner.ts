import os from "node:os";
import fs from "node:fs";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns";
import { exec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(exec);

export interface Device {
  ip: string;
  hostname?: string;
  dns?: string;
  vendor?: string;
  mac?: string;
  gateway?: string;
  reachable: boolean;
  ping_ms?: number;
  open_ports: number[];
  scanned_at?: string;
}

export interface NetworkProfile {
  hostname: string;
  os: string;
  arch: string;
  localIP: string;
  mac: string;
  cidr: string;
  gateway: string;
  gatewayVendor?: string;
  ssid: string;
  bssid?: string;
  signal?: string;
  security: string;
  networkType: "personal" | "public" | "enterprise";
  trustScore: number;
  riskRating: string;
  scanStrategy: string;
}

// Temporary in-memory state for discovered devices on dashboard
let temporaryMemoryDevices: Device[] = [];
let lastScanTime: string | null = null;

export function getInMemoryDevices(): { devices: Device[]; last_scan: string | null } {
  return {
    devices: temporaryMemoryDevices,
    last_scan: lastScanTime
  };
}

export function clearInMemoryDevices(): void {
  temporaryMemoryDevices = [];
  lastScanTime = null;
}

const EMBEDDED_OUI: Record<string, string> = {
  "00000C": "Cisco Systems",
  "000142": "Cisco Systems",
  "0004F2": "Polycom",
  "000C29": "VMware",
  "00155D": "Microsoft Hyper-V",
  "001A11": "Google",
  "001A2B": "Ayecom Technology",
  "001E67": "Intel",
  "0024E8": "Dell",
  "005056": "VMware",
  "04D4C4": "Apple",
  "04D9F5": "Apple",
  "06829B": "Apple Device",
  "06DC7B": "Mobile Device",
  "080027": "Oracle VirtualBox",
  "10DA43": "Netgear",
  "147DDA": "Apple",
  "186590": "Apple",
  "18B430": "Google / Nest",
  "1C1B0D": "Giga-Byte",
  "203706": "Cisco",
  "244BFE": "Amazon",
  "2818FD": "Aditya Infotech",
  "286FB9": "Apple",
  "28C63F": "Intel Corporate",
  "2C3033": "Netgear",
  "30074D": "Samsung",
  "306893": "TP-Link Systems",
  "3464A9": "Apple",
  "38892C": "Apple",
  "3C0630": "Apple",
  "406C8F": "Apple",
  "40A8F0": "Hewlett Packard",
  "40B034": "Hewlett Packard",
  "44070B": "Google",
  "48A98A": "TP-Link",
  "4C3275": "Apple",
  "50C7BF": "TP-Link",
  "54E43A": "Apple",
  "58108C": "Amazon",
  "5C879C": "Apple",
  "600308": "Apple",
  "64A5C3": "Apple",
  "68DBCA": "Apple",
  "6C2995": "Intel",
  "7081EB": "Amazon",
  "74AC5F": "Ubiquiti Networks",
  "784F43": "Apple",
  "7CF17E": "TP-Link Systems",
  "7CD95C": "Apple",
  "802AA8": "Ubiquiti Networks",
  "8478AC": "Apple",
  "88665A": "Apple",
  "8A273F": "Mobile Device",
  "8C8590": "Apple",
  "9009D0": "Synology Incorporated",
  "907240": "Apple",
  "94B40F": "Espressif (IoT)",
  "980CA5": "Intel",
  "9C293F": "Apple",
  "A0369F": "Intel",
  "A47733": "Google",
  "A85B78": "Apple",
  "ACDE48": "Apple",
  "B0A737": "Apple",
  "B42E99": "Intel",
  "B827EB": "Raspberry Pi Foundation",
  "BC6EE8": "Apple",
  "C0A5DD": "Google",
  "C43875": "Google",
  "C869CD": "Apple",
  "C895CE": "Intel Corporate",
  "CC25EF": "Samsung",
  "D05099": "Apple",
  "D46D6D": "TP-Link",
  "D83062": "Apple",
  "DC5360": "Intel Corporate",
  "DC85DE": "Amazon Technologies",
  "DCF505": "Apple",
  "E063DA": "Apple",
  "E450EB": "Apple",
  "E88D28": "Apple",
  "ECB1D7": "Hewlett Packard",
  "ECFA52": "Samsung",
  "F01898": "Apple",
  "F29E3E": "Mobile Device",
  "F43909": "Apple",
  "F4B520": "Biostar Microtech",
  "F83DC6": "AzureWave Technology",
  "F86F38": "Apple",
  "FC3497": "Apple"
};

let macVendorMap: Map<string, string> | null = null;

function loadMacVendors(): Map<string, string> {
  if (macVendorMap) return macVendorMap;
  macVendorMap = new Map();

  for (const [prefix, name] of Object.entries(EMBEDDED_OUI)) {
    macVendorMap.set(prefix, name);
  }

  const candidatePaths = [
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/wireshark/manuf",
    "/usr/share/ieee-data/oui.txt"
  ];
  for (const p of candidatePaths) {
    try {
      if (fs.existsSync(/*turbopackIgnore: true*/ p)) {
        const content = fs.readFileSync(/*turbopackIgnore: true*/ p, "utf8");
        const lines = content.split("\n");
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith("#")) continue;
          const parts = trimmed.split(/\s+/);
          if (parts.length >= 2 && parts[0].length === 6) {
            macVendorMap.set(parts[0].toUpperCase(), parts.slice(1).join(" "));
          }
        }
        if (macVendorMap.size > 100) break;
      }
    } catch {}
  }
  return macVendorMap;
}

export function lookupVendor(mac?: string): string {
  if (!mac) return "";
  const clean = mac.replace(/[:-]/g, "").toUpperCase();
  if (clean.length < 6) return "";
  const map = loadMacVendors();
  return map.get(clean.substring(0, 6)) || "";
}

function getLinuxDefaultGateway(): string {
  try {
    const route = fs.readFileSync(/*turbopackIgnore: true*/ "/proc/net/route", "utf8");
    const lines = route.split("\n");
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].trim().split(/\s+/);
      if (parts.length >= 3 && parts[1] === "00000000") {
        const hex = parts[2];
        if (hex.length === 8) {
          const b0 = parseInt(hex.substring(6, 8), 16);
          const b1 = parseInt(hex.substring(4, 6), 16);
          const b2 = parseInt(hex.substring(2, 4), 16);
          const b3 = parseInt(hex.substring(0, 2), 16);
          return `${b0}.${b1}.${b2}.${b3}`;
        }
      }
    }
  } catch {}
  return "";
}

// Auto-detect Wi-Fi Configuration, SSID, Security Type & Network Trust Classification
export async function getDetailedNetworkProfile(): Promise<NetworkProfile> {
  const ifaces = os.networkInterfaces();
  let localIP = "";
  let localMAC = "";
  let localCIDR = "192.168.0.0/24";

  for (const name of Object.keys(ifaces)) {
    if (name === "lo") continue;
    const list = ifaces[name] || [];
    for (const item of list) {
      if (item.family === "IPv4" && !item.internal) {
        localIP = item.address;
        localMAC = item.mac || "";
        const netmaskParts = item.netmask.split(".").map(Number);
        let prefix = 0;
        for (const byte of netmaskParts) {
          prefix += (byte.toString(2).match(/1/g) || []).length;
        }
        const ipParts = item.address.split(".").map(Number);
        const baseParts = ipParts.map((b, i) => b & netmaskParts[i]);
        localCIDR = `${baseParts.join(".")}/${prefix}`;
        break;
      }
    }
    if (localIP) break;
  }

  const gateway = getLinuxDefaultGateway() || "192.168.0.1";
  const arpMap = readArpTable();
  const gatewayMac = arpMap.get(gateway) || "";
  const gatewayVendor = lookupVendor(gatewayMac) || (gateway === "192.168.0.1" ? "TP-Link Systems" : "Network Router");

  // Query Wi-Fi info via nmcli, iwgetid, or OS command
  let ssid = "Local Wi-Fi Network";
  let security = "WPA2 / WPA3 Personal";
  let networkType: "personal" | "public" | "enterprise" = "personal";
  let signal = "90%";
  let trustScore = 95;

  try {
    const { stdout } = await execAsync("nmcli -t -f active,ssid,signal,security dev wifi").catch(() => ({ stdout: "" }));
    for (const line of stdout.split("\n")) {
      if (line.startsWith("yes:")) {
        const parts = line.split(":");
        if (parts[1]) ssid = parts[1];
        if (parts[2]) signal = `${parts[2]}%`;
        const sec = parts[3] || "";
        if (sec.includes("WPA2") || sec.includes("WPA3")) {
          security = sec.trim();
          networkType = "personal";
          trustScore = 95;
        } else if (sec.includes("802.1X") || sec.includes("Enterprise")) {
          security = "WPA2/WPA3 Enterprise (802.1X)";
          networkType = "enterprise";
          trustScore = 90;
        } else if (!sec || sec === "--" || sec.toLowerCase().includes("open")) {
          security = "Open / Unencrypted (No Password)";
          networkType = "public";
          trustScore = 30;
        }
        break;
      }
    }
  } catch {}

  // Fallback to iwgetid if nmcli didn't find active SSID
  if (ssid === "Local Wi-Fi Network") {
    try {
      const { stdout } = await execAsync("iwgetid -r").catch(() => ({ stdout: "" }));
      const trimmed = stdout.trim();
      if (trimmed) ssid = trimmed;
    } catch {}
  }

  // Network Classification & Strategy
  let riskRating = "Low Risk - Protected Personal Wi-Fi";
  let scanStrategy = "Full Home LAN Device Discovery & Open Share Security Audit";

  if (networkType === "public") {
    riskRating = "High Risk - Open Public Hotspot";
    scanStrategy = "Stealth Perimeter Defense, Rogue Gateway & MITM Warning";
  } else if (networkType === "enterprise") {
    riskRating = "Medium Risk - Corporate Monitored Subnet";
    scanStrategy = "Domain Controller & Enterprise Service Audit";
  }

  return {
    hostname: os.hostname(),
    os: os.platform(),
    arch: os.arch(),
    localIP,
    mac: localMAC,
    cidr: localCIDR,
    gateway,
    gatewayVendor,
    ssid,
    signal,
    security,
    networkType,
    trustScore,
    riskRating,
    scanStrategy
  };
}

export function getLocalNetworkInfo() {
  const ifaces = os.networkInterfaces();
  let localIP = "";
  let localMAC = "";
  let localCIDR = "192.168.0.0/24";

  for (const name of Object.keys(ifaces)) {
    if (name === "lo") continue;
    const list = ifaces[name] || [];
    for (const item of list) {
      if (item.family === "IPv4" && !item.internal) {
        localIP = item.address;
        localMAC = item.mac || "";
        const netmaskParts = item.netmask.split(".").map(Number);
        let prefix = 0;
        for (const byte of netmaskParts) {
          prefix += (byte.toString(2).match(/1/g) || []).length;
        }
        const ipParts = item.address.split(".").map(Number);
        const baseParts = ipParts.map((b, i) => b & netmaskParts[i]);
        localCIDR = `${baseParts.join(".")}/${prefix}`;
        break;
      }
    }
    if (localIP) break;
  }

  const gateway = getLinuxDefaultGateway() || "192.168.0.1";

  return {
    hostname: os.hostname(),
    os: os.platform(),
    arch: os.arch(),
    localIP,
    mac: localMAC,
    cidr: localCIDR,
    gateway
  };
}

async function scanNetBIOS(cidr: string): Promise<Map<string, { name: string; mac: string }>> {
  const map = new Map<string, { name: string; mac: string }>();
  try {
    const { stdout } = await execAsync(`nbtscan -q -s : ${cidr}`);
    for (const line of stdout.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(":");
      if (parts.length >= 2) {
        const ip = parts[0].trim();
        const name = parts[1].trim();
        let mac = "";
        if (parts.length >= 5) {
          mac = parts.slice(4).join(":").trim().toLowerCase();
          if (mac.includes("00:00:00:00:00:00")) mac = "";
        }
        if (ip && name) {
          map.set(ip, { name, mac });
        }
      }
    }
  } catch {}
  return map;
}

async function fpingSweep(cidr: string): Promise<Map<string, number>> {
  const map = new Map<string, number>();
  try {
    const { stdout } = await execAsync(`fping -a -e -q -g ${cidr}`);
    for (const line of stdout.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 1 && parts[0]) {
        const ip = parts[0];
        let ms = 15;
        if (parts.length >= 2) {
          const raw = parts[1].replace(/[()ms ]/g, "");
          const num = parseFloat(raw);
          if (!isNaN(num)) ms = Math.round(num);
        }
        map.set(ip, ms);
      }
    }
  } catch {}
  return map;
}

function readArpTable(): Map<string, string> {
  const map = new Map<string, string>();
  try {
    const content = fs.readFileSync(/*turbopackIgnore: true*/ "/proc/net/arp", "utf8");
    for (const line of content.split("\n")) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 4) {
        const ip = parts[0];
        const mac = parts[3];
        if (mac && mac !== "00:00:00:00:00:00" && !ip.includes("IP")) {
          map.set(ip, mac);
        }
      }
    }
  } catch {}
  return map;
}

function queryTlsCN(ip: string, port: number): Promise<string> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: ip,
        port: port,
        rejectUnauthorized: false,
        timeout: 350
      },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          socket.destroy();
          if (cert && cert.subject && cert.subject.CN) {
            const cnVal = Array.isArray(cert.subject.CN) ? cert.subject.CN[0] : cert.subject.CN;
            if (cnVal) return resolve(String(cnVal));
          }
          if (cert && cert.subjectaltname) {
            const san = cert.subjectaltname.split(",")[0]?.replace(/DNS:/g, "").trim();
            if (san) return resolve(san);
          }
        } catch {}
        resolve("");
      }
    );
    socket.on("error", () => resolve(""));
    socket.on("timeout", () => {
      socket.destroy();
      resolve("");
    });
  });
}

async function reverseDnsLookup(ip: string): Promise<string> {
  try {
    const names = await dns.promises.reverse(ip);
    if (names && names.length > 0) {
      const name = names[0].replace(/\.$/, "");
      if (name && !name.includes("in-addr.arpa")) return name;
    }
  } catch {}
  return "";
}

// Deep Ping & Port Connection Check:
// Measures ping time and detects active responses (including TCP RST / ECONNREFUSED)
function probeSocketPingAndPort(
  ip: string,
  port: number
): Promise<{ open: boolean; hostReplied: boolean; ping: number }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = net.connect({ host: ip, port: port }, () => {
      const latency = Math.max(1, Date.now() - start);
      socket.destroy();
      resolve({ open: true, hostReplied: true, ping: latency });
    });

    socket.setTimeout(250);

    socket.on("error", (err: any) => {
      const latency = Math.max(1, Date.now() - start);
      if (err && err.code === "ECONNREFUSED") {
        resolve({ open: false, hostReplied: true, ping: latency });
      } else {
        resolve({ open: false, hostReplied: false, ping: 0 });
      }
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve({ open: false, hostReplied: false, ping: 0 });
    });
  });
}

function generateCIDRIps(cidr: string): string[] {
  const [baseIp, maskStr] = cidr.split("/");
  const prefix = parseInt(maskStr || "24", 10);
  const parts = baseIp.split(".").map(Number);
  if (parts.length !== 4) return [];

  const ipInt = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const hostBits = 32 - prefix;
  const numHosts = Math.pow(2, hostBits);
  const startIpInt = (ipInt >>> hostBits) << hostBits;

  const result: string[] = [];
  const start = numHosts > 2 ? 1 : 0;
  const end = numHosts > 2 ? numHosts - 1 : numHosts;

  for (let i = start; i < end; i++) {
    const cur = startIpInt + i;
    const b0 = (cur >>> 24) & 255;
    const b1 = (cur >>> 16) & 255;
    const b2 = (cur >>> 8) & 255;
    const b3 = cur & 255;
    result.push(`${b0}.${b1}.${b2}.${b3}`);
  }
  return result;
}

// Complete Subnet Loop: Checks all IPs 1 to 254 and pings/probes each one
export async function runDashboardNetworkScan(cidrInput?: string, portsInput?: number[]): Promise<Device[]> {
  return runDashboardNetworkScanStream(cidrInput, portsInput);
}

export async function runDashboardNetworkScanStream(
  cidrInput?: string,
  portsInput?: number[],
  onProgress?: (scanned: number, total: number, percentage: number, currentIp: string) => void,
  onDeviceDiscovered?: (device: Device) => void,
  abortSignal?: AbortSignal
): Promise<Device[]> {
  const netInfo = getLocalNetworkInfo();
  const cidr = cidrInput || netInfo.cidr || "192.168.0.0/24";
  const ports =
    portsInput && portsInput.length > 0
      ? portsInput
      : [21, 22, 53, 80, 135, 139, 443, 445, 1883, 3000, 3389, 5000, 5353, 8000, 8080, 8443, 9000];

  const allIps = generateCIDRIps(cidr);
  const total = allIps.length || 1;
  let scannedCount = 0;

  // Parallel Discovery: NetBIOS + Fping
  const [nbMap, fpingMap] = await Promise.all([scanNetBIOS(cidr), fpingSweep(cidr)]);

  const arpMap = readArpTable();

  interface HostMeta {
    pingMS: number;
    mac?: string;
    nbName?: string;
  }

  const liveHosts = new Map<string, HostMeta>();

  for (const [ip, ms] of fpingMap.entries()) {
    liveHosts.set(ip, { pingMS: ms });
  }

  for (const [ip, nb] of nbMap.entries()) {
    const existing = liveHosts.get(ip);
    if (existing) {
      existing.nbName = nb.name;
      if (nb.mac) existing.mac = nb.mac;
    } else {
      liveHosts.set(ip, { pingMS: 20, nbName: nb.name, mac: nb.mac });
    }
  }

  for (const [ip, mac] of arpMap.entries()) {
    if (allIps.includes(ip)) {
      const existing = liveHosts.get(ip);
      if (existing) {
        if (!existing.mac) existing.mac = mac;
      } else {
        liveHosts.set(ip, { pingMS: 25, mac });
      }
    }
  }

  if (netInfo.gateway && allIps.includes(netInfo.gateway) && !liveHosts.has(netInfo.gateway)) {
    liveHosts.set(netInfo.gateway, { pingMS: 10 });
  }
  if (netInfo.localIP && allIps.includes(netInfo.localIP) && !liveHosts.has(netInfo.localIP)) {
    liveHosts.set(netInfo.localIP, { pingMS: 1, mac: netInfo.mac });
  }

  const discoveredDevices: Device[] = [];
  const concurrency = 32;
  const queue = [...allIps];

  async function worker() {
    while (queue.length > 0) {
      if (abortSignal?.aborted) break;
      const ip = queue.shift();
      if (!ip) break;

      const meta = liveHosts.get(ip);
      const isKnownActive = Boolean(meta || ip === netInfo.gateway || ip === netInfo.localIP);

      // Probe ports & ping response
      const portResults = await Promise.all(ports.map((p) => probeSocketPingAndPort(ip, p)));
      const openPorts: number[] = [];
      let minPing = 0;
      let anyReplyReceived = false;

      for (let i = 0; i < ports.length; i++) {
        const r = portResults[i];
        if (r.open) {
          openPorts.push(ports[i]);
        }
        if (r.hostReplied) {
          anyReplyReceived = true;
          if (!minPing || r.ping < minPing) {
            minPing = r.ping;
          }
        }
      }

      // Check if host replied to ping/probe, is in ARP/NetBIOS, or is known active
      const isActive = isKnownActive || anyReplyReceived || openPorts.length > 0;

      if (isActive) {
        let mac = (meta && meta.mac) || arpMap.get(ip) || "";
        if (!mac && ip === netInfo.localIP) {
          mac = netInfo.mac;
        }

        const vendor = lookupVendor(mac);
        let pingMS = minPing || (meta ? meta.pingMS : (ip === netInfo.localIP ? 1 : 15));

        // Hostname Resolution
        let hostName = "";
        let dnsDomain = "";

        if (ip === netInfo.localIP || ip === "127.0.0.1") {
          hostName = `${os.hostname()} (This Device)`;
          dnsDomain = "localhost.lan";
        }

        if (!hostName && meta && meta.nbName) {
          hostName = meta.nbName;
          dnsDomain = `${meta.nbName.toLowerCase()}.local`;
        }

        if (!hostName) {
          hostName = await reverseDnsLookup(ip);
          if (hostName) dnsDomain = hostName;
        }

        if (!hostName && (openPorts.includes(443) || openPorts.includes(8443))) {
          const tlsPort = openPorts.includes(443) ? 443 : 8443;
          hostName = await queryTlsCN(ip, tlsPort);
          if (hostName) dnsDomain = `${hostName.toLowerCase()}`;
        }

        if (!hostName && (ip === netInfo.gateway || ip.endsWith(".1"))) {
          hostName = vendor ? `Gateway / Router (${vendor})` : "Default Gateway / Router";
          dnsDomain = "router.home.arpa";
        }

        if (!hostName && vendor) {
          hostName = `${vendor} Device`;
          dnsDomain = `${vendor.toLowerCase().replace(/[^a-z0-9]/g, "-")}.lan`;
        }

        if (!hostName) {
          const lastOctet = ip.split(".")[3];
          hostName = `Host-${lastOctet}`;
          dnsDomain = `host-${lastOctet}.lan`;
        }

        const dev: Device = {
          ip,
          hostname: hostName,
          dns: dnsDomain || hostName,
          vendor: vendor || undefined,
          mac: mac || undefined,
          gateway: netInfo.gateway,
          reachable: true,
          ping_ms: pingMS,
          open_ports: openPorts,
          scanned_at: new Date().toISOString()
        };

        discoveredDevices.push(dev);
        if (onDeviceDiscovered) {
          onDeviceDiscovered(dev);
        }
      }

      scannedCount++;
      if (onProgress) {
        const pct = Math.round((scannedCount / total) * 100);
        onProgress(scannedCount, total, pct, ip);
      }
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);

  discoveredDevices.sort((a, b) => {
    const numA = a.ip.split(".").map(Number).reduce((acc, oct) => (acc << 8) + oct, 0) >>> 0;
    const numB = b.ip.split(".").map(Number).reduce((acc, oct) => (acc << 8) + oct, 0) >>> 0;
    return numA - numB;
  });

  temporaryMemoryDevices = discoveredDevices;
  lastScanTime = new Date().toISOString();

  return discoveredDevices;
}

export interface AgentStatusInfo {
  status: "online" | "ready";
  engine: string;
  hostname: string;
  os: string;
  arch: string;
  uptimeSeconds: number;
  goAgentOnline: boolean;
  netlensAgentOnline: boolean;
}

export async function getBackendAgentStatus(): Promise<AgentStatusInfo> {
  const targetAgentUrl = process.env.AGENT_URL || process.env.NEXT_PUBLIC_AGENT_URL || "http://127.0.0.1:8080";
  let goOnline = false;

  try {
    const res = await fetch("http://127.0.0.1:8080/api/agent/status", {
      signal: AbortSignal.timeout(500)
    }).catch(() => null);
    if (res && res.ok) {
      goOnline = true;
    } else {
      // Check if remote agent URL is online
      const remoteRes = await fetch(`${targetAgentUrl.replace(/\/$/, "")}/api/agent/status`, {
        signal: AbortSignal.timeout(500)
      }).catch(() => null);
      if (remoteRes && remoteRes.ok) goOnline = true;
    }
  } catch {}

  let netlensOnline = false;
  try {
    const sock = net.connect({ host: "127.0.0.1", port: 4000 });
    sock.setTimeout(300);
    await new Promise<void>((resolve) => {
      sock.on("connect", () => {
        netlensOnline = true;
        sock.destroy();
        resolve();
      });
      sock.on("error", () => resolve());
      sock.on("timeout", () => {
        sock.destroy();
        resolve();
      });
    });
  } catch {}

  return {
    status: "online",
    engine: goOnline ? "Go High-Speed Agent & Next.js Core" : "Next.js Native System Agent",
    hostname: os.hostname(),
    os: os.platform(),
    arch: os.arch(),
    uptimeSeconds: Math.floor(os.uptime()),
    goAgentOnline: goOnline,
    netlensAgentOnline: netlensOnline
  };
}

export interface DefensiveAdvice {
  title: string;
  severity: "info" | "low" | "medium" | "high";
  why: string;
  actions: string[];
}

export function buildDefensiveAdvice(device: Device, networkType?: "personal" | "public" | "enterprise"): DefensiveAdvice[] {
  const advice: DefensiveAdvice[] = [];
  const ports = new Set(device.open_ports || []);

  if (networkType === "public") {
    advice.push({
      title: "Public / Shared Wi-Fi Security Warning",
      severity: "high",
      why: `Host ${device.ip} is on an open or public network segment. Devices on public Wi-Fi can be probed or targeted by lateral attacker activity.`,
      actions: [
        "Enable host-based firewall in strict/stealth mode.",
        "Use an encrypted VPN tunnel for all internet traffic.",
        "Disable local file, media, and printer sharing services.",
        "Do not accept unexpected certificate warnings or connection prompts."
      ]
    });
  }

  if (ports.has(445) || ports.has(139)) {
    advice.push({
      title: "Windows / SMB File Sharing Exposed",
      severity: "medium",
      why: "TCP 445 or 139 is reachable on this host. SMB services should not be exposed to untrusted network segments.",
      actions: [
        "Disable SMB/file sharing if this host does not require network shares.",
        "Use the host firewall to restrict SMB access to authorized management IPs.",
        "Keep the operating system and SMB stack updated with the latest security patches.",
        "Ensure SMBv1 is disabled in favor of SMBv2/SMBv3."
      ]
    });
  }

  if (ports.has(22)) {
    advice.push({
      title: "SSH Remote Administration Exposed",
      severity: "low",
      why: "TCP 22 accepted a connection. SSH is a common target for brute-force attacks.",
      actions: [
        "Disable password login and enforce SSH public key authentication.",
        "Restrict SSH access using firewall rules or a VPN gateway.",
        "Keep the OpenSSH daemon and host OS updated.",
        "Consider changing the default port or configuring fail2ban."
      ]
    });
  }

  if (ports.has(3389)) {
    advice.push({
      title: "Remote Desktop Protocol (RDP) Exposed",
      severity: "medium",
      why: "TCP 3389 accepted a connection. RDP endpoints are high-value targets for credential compromise.",
      actions: [
        "Enforce Network Level Authentication (NLA).",
        "Place RDP behind a secure VPN or Zero-Trust Access Gateway.",
        "Use strong, unique credentials and enable multi-factor authentication (MFA).",
        "Disable Remote Desktop when not actively required."
      ]
    });
  }

  if (ports.has(80)) {
    advice.push({
      title: "Unencrypted HTTP Web Service Exposed",
      severity: "info",
      why: "TCP 80 accepted a connection. Plaintext HTTP does not encrypt session credentials or payload data.",
      actions: [
        "Redirect HTTP traffic to HTTPS (port 443).",
        "Install and maintain a valid TLS certificate.",
        "Disable default administrative credentials on embedded web servers.",
        "Keep web application dependencies and web servers updated."
      ]
    });
  }

  if (ports.has(443)) {
    advice.push({
      title: "HTTPS Web Service Active",
      severity: "info",
      why: "TCP 443 accepted a connection. Confirm that this web portal is authorized and properly maintained.",
      actions: [
        "Enforce TLS 1.2 or TLS 1.3 with secure cipher suites.",
        "Ensure administrative portals require strong authentication.",
        "Keep web server software and CMS patched."
      ]
    });
  }

  if (ports.has(8080) || ports.has(8443) || ports.has(3000) || ports.has(5000) || ports.has(8000)) {
    advice.push({
      title: "Alternate Web / Development Service Exposed",
      severity: "low",
      why: "An alternate application or dev port is open. These frequently expose debug interfaces or unauthenticated dashboards.",
      actions: [
        "Identify the software bound to this port.",
        "Disable the service if it was intended only for local development.",
        "Add authentication if this is a management dashboard or proxy."
      ]
    });
  }

  if (ports.has(53)) {
    advice.push({
      title: "DNS Service Active",
      severity: "info",
      why: "Port 53 accepted a connection. Confirm this host is an intended DNS resolver or router.",
      actions: [
        "Ensure the resolver is restricted from open internet recursion.",
        "Keep DNS server software updated."
      ]
    });
  }

  if (!advice.length) {
    advice.push({
      title: "No High-Risk Services Detected",
      severity: "info",
      why: "Monitored high-risk ports were not found open during this scan.",
      actions: [
        "Enable the host firewall.",
        "Keep all device firmware and OS packages up to date.",
        "Re-scan periodically to catch newly opened ports."
      ]
    });
  }

  return advice;
}
