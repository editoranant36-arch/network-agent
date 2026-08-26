import { NextRequest, NextResponse } from "next/server";
import { runDashboardNetworkScan } from "../../lib/scanner";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const cidr = body.cidr;
    const ports = body.ports;

    const agentBaseUrl = process.env.AGENT_URL || process.env.NEXT_PUBLIC_AGENT_URL || "http://127.0.0.1:8080";

    try {
      const upstreamRes = await fetch(`${agentBaseUrl.replace(/\/$/, "")}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cidr, ports }),
        signal: AbortSignal.timeout(15000)
      });
      if (upstreamRes.ok) {
        const data = await upstreamRes.json();
        return NextResponse.json(data);
      }
    } catch {}

    const devices = await runDashboardNetworkScan(cidr, ports);
    return NextResponse.json(devices);
  } catch (error: any) {
    return NextResponse.json(
      { error: error?.message || "Network scan failed" },
      { status: 500 }
    );
  }
}
