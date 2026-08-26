import { NextResponse } from "next/server";
import { getDetailedNetworkProfile } from "../../lib/scanner";

export const dynamic = "force-dynamic";

export async function GET() {
  const agentBaseUrl = process.env.AGENT_URL || process.env.NEXT_PUBLIC_AGENT_URL || "http://127.0.0.1:8080";

  try {
    const upstreamRes = await fetch(`${agentBaseUrl.replace(/\/$/, "")}/api/network`, {
      signal: AbortSignal.timeout(2000)
    });
    if (upstreamRes.ok) {
      const data = await upstreamRes.json();
      if (data && data.cidr) {
        return NextResponse.json(data);
      }
    }
  } catch {}

  const profile = await getDetailedNetworkProfile();
  return NextResponse.json(profile);
}
