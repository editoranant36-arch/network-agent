import { NextResponse } from "next/server";
import { getInMemoryDevices, getDetailedNetworkProfile, Device, NetworkProfile } from "../../lib/scanner";

export const dynamic = "force-dynamic";

const DEFAULT_GROQ_KEY = process.env.GROQ_API_KEY || "";
const DEFAULT_MODEL = process.env.GROQ_MODEL || "openai/gpt-oss-120b";

const SUPPORTED_MODELS = [
  "openai/gpt-oss-120b",
  "openai/gpt-oss-20b",
  "qwen/qwen3.8-27b",
  "qwen/qwen3.6-27b",
  "groq/compound"
];

interface SummaryRequestBody {
  apiKey?: string;
  model?: string;
  devices?: Device[];
  profile?: NetworkProfile;
  agentStatus?: {
    engine?: string;
    hostname?: string;
    os?: string;
    arch?: string;
    status?: string;
    port?: number;
  };
  prompt?: string;
}

export async function GET() {
  const isKeyConfigured = Boolean(DEFAULT_GROQ_KEY && DEFAULT_GROQ_KEY.startsWith("gsk_"));
  const maskedKey = isKeyConfigured
    ? `${DEFAULT_GROQ_KEY.slice(0, 8)}...${DEFAULT_GROQ_KEY.slice(-4)}`
    : "Not configured";

  return NextResponse.json({
    status: "ok",
    configured: isKeyConfigured,
    maskedKey,
    currentModel: DEFAULT_MODEL,
    availableModels: SUPPORTED_MODELS
  });
}

export async function POST(req: Request) {
  try {
    let body: SummaryRequestBody = {};
    try {
      body = await req.json();
    } catch {
      body = {};
    }

    const apiKey = (body.apiKey && body.apiKey.trim().startsWith("gsk_"))
      ? body.apiKey.trim()
      : DEFAULT_GROQ_KEY;

    if (!apiKey) {
      return NextResponse.json(
        { error: "Groq API key not found. Please provide a valid Groq API key." },
        { status: 400 }
      );
    }

    const requestedModel = body.model || DEFAULT_MODEL;

    // 1. Gather devices
    let devices: Device[] = Array.isArray(body.devices) && body.devices.length > 0 ? body.devices : [];
    if (devices.length === 0) {
      const inMem = getInMemoryDevices();
      if (inMem && Array.isArray(inMem.devices) && inMem.devices.length > 0) {
        devices = inMem.devices;
      }
    }

    // 2. Gather profile
    let profile: NetworkProfile | null = body.profile || null;
    if (!profile) {
      try {
        profile = await getDetailedNetworkProfile();
      } catch {}
    }

    // If still no devices, check upstream Go agent if reachable
    if (devices.length === 0) {
      try {
        const agentBaseUrl = process.env.AGENT_URL || "http://127.0.0.1:8080";
        const res = await fetch(`${agentBaseUrl}/api/devices`, { signal: AbortSignal.timeout(1500) });
        if (res.ok) {
          const data = await res.json();
          if (data && Array.isArray(data.devices)) {
            devices = data.devices;
          }
        }
      } catch {}
    }

    // 3. Construct structured prompt
    const totalDevices = devices.length;
    const totalOpenPorts = devices.reduce(
      (acc, d) => acc + (Array.isArray(d.open_ports) ? d.open_ports.length : 0),
      0
    );
    const devicesWithPorts = devices.filter((d) => d.open_ports && d.open_ports.length > 0);
    const identifiedVendors = devices.filter((d) => d.vendor && d.vendor !== "Unknown").map((d) => d.vendor);
    const uniqueVendors = Array.from(new Set(identifiedVendors));

    const deviceBreakdown = devices.map((d, index) => {
      const ports = d.open_ports && d.open_ports.length > 0 ? d.open_ports.join(", ") : "None";
      const ping = d.ping_ms != null ? `${d.ping_ms}ms` : "N/A";
      return `Device #${index + 1}:
  - IP: ${d.ip}
  - Hostname: ${d.hostname || "Unspecified"}
  - DNS: ${d.dns || "None"}
  - Vendor: ${d.vendor || "Unknown"}
  - MAC: ${d.mac || "Not resolved"}
  - Gateway: ${d.gateway || "None"}
  - Ping Latency: ${ping}
  - Reachable: ${d.reachable ? "Yes" : "No"}
  - Open TCP Ports: [${ports}]`;
    }).join("\n\n");

    const systemPrompt = `You are LAN Sentinel AI, a senior network security auditor and systems architect.
Your mission is to examine network telemetry and live discovery scans from the local agent and generate a comprehensive, highly detailed network summary and defensive security assessment.

Guidelines for formatting your response:
- Use clean GitHub-flavored Markdown.
- Use structured headings, emoji indicators, bullet points, and data tables where helpful.
- Provide a rigorous, in-depth breakdown covering:
  1. 🌐 **Executive Network Overview & Architecture**:
     - Subnet, Gateway, SSID, Wi-Fi Security Protocol, Signal, Trust Rating, and overall network health.
  2. 💻 **Device Inventory & Host Categorization**:
     - Group discovered devices into categories (e.g., Gateways & Routers, Workstations & Servers, Mobile & Smart Home Devices, Stealth or Unidentified Nodes).
     - Mention specific IP, MAC vendor, hostname, and ping latency for each notable device.
  3. 🔓 **Port Exposure & Attack Surface Analysis**:
     - Identify all exposed services across the network (e.g., SSH, HTTP, HTTPS, SMB, RDP, RTSP, mDNS, etc.).
     - Highlight potentially vulnerable or unencrypted services (e.g. SMB port 445 on public networks, unencrypted HTTP admin interfaces).
  4. 🛡️ **Defensive Security Recommendations & Hardening Steps**:
     - Prioritized, actionable advice (Immediate Priority, Medium Priority, Network Hygiene).
     - Router & Wi-Fi configuration hardening (WPA3, disabling UPnP/WPS, VLAN/guest isolation).
  5. 📊 **Network Hygiene Score & Conclusion**:
     - Assign an overall Network Hygiene Score (0-100) with a concise verdict and summary takeaway.

Maintain a professional, authoritative, yet accessible cybersecurity tone.`;

    const userMessageContent = `Please generate an in-depth, detailed Network Summary for the following scan data:

--- NETWORK CONTEXT ---
Subnet CIDR: ${profile?.cidr || "Unknown (e.g. 192.168.0.0/24)"}
SSID: ${profile?.ssid || "Local Wi-Fi Network"}
Wi-Fi Security: ${profile?.security || "WPA2/WPA3 Personal"}
Signal Strength: ${profile?.signal || "Good"}
Gateway IP: ${profile?.gateway || "192.168.0.1"} (${profile?.gatewayVendor || "Default Router"})
Network Trust Rating: ${profile?.trustScore != null ? `${profile?.trustScore}/100` : "85/100"} (${profile?.networkType || "personal"})
Risk Classification: ${profile?.riskRating || "Standard"}

--- TELEMETRY & AGENT STATS ---
Agent Engine: ${body.agentStatus?.engine || "NetLens Go High-Speed Agent"}
Host Platform: ${body.agentStatus?.os || "Linux"} (${body.agentStatus?.arch || "x86_64"})
Total Live Devices Discovered: ${totalDevices}
Total Open TCP Services: ${totalOpenPorts}
Devices with Open Ports: ${devicesWithPorts.length}
Identified Hardware Vendors: ${uniqueVendors.length > 0 ? uniqueVendors.join(", ") : "Varied / None detected"}

--- DISCOVERED DEVICE DETAILS (${totalDevices} Systems) ---
${deviceBreakdown || "No devices discovered yet (Subnet was empty or scan just started)."}

${body.prompt ? `--- USER CUSTOM FOCUS / QUESTION ---\n${body.prompt}\n` : ""}

Generate the full, detailed summary now.`;

    // 4. Query Groq API with auto-fallback
    const modelsToTry = [requestedModel, ...SUPPORTED_MODELS.filter((m) => m !== requestedModel)];
    let lastError: any = null;
    let completionData: any = null;
    let activeModelUsed = requestedModel;

    for (const modelCandidate of modelsToTry) {
      try {
        const groqResponse = await fetch("https://api.groq.com/openai/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            model: modelCandidate,
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userMessageContent }
            ],
            temperature: 0.3,
            max_tokens: 4096
          }),
          signal: AbortSignal.timeout(30000)
        });

        if (!groqResponse.ok) {
          const errText = await groqResponse.text();
          lastError = new Error(`Groq API error (${groqResponse.status}): ${errText}`);
          continue;
        }

        const data = await groqResponse.json();
        if (data && data.choices && data.choices[0]?.message?.content) {
          completionData = data;
          activeModelUsed = modelCandidate;
          break;
        }
      } catch (err: any) {
        lastError = err;
      }
    }

    if (!completionData) {
      return NextResponse.json(
        {
          error: lastError?.message || "Failed to generate summary from Groq LLM.",
          details: String(lastError)
        },
        { status: 502 }
      );
    }

    const summaryText = completionData.choices[0].message.content;
    const usage = completionData.usage || {};

    return NextResponse.json({
      success: true,
      summary: summaryText,
      model: activeModelUsed,
      usage,
      deviceCount: totalDevices,
      portCount: totalOpenPorts,
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || "Internal server error generating summary" },
      { status: 500 }
    );
  }
}
