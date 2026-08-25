import { NextRequest, NextResponse } from "next/server";
import { runDashboardNetworkScan } from "../../lib/scanner";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const cidr = body.cidr;
    const ports = body.ports;

    const devices = await runDashboardNetworkScan(cidr, ports);
    return NextResponse.json(devices);
  } catch (error: any) {
    return NextResponse.json(
      { error: error?.message || "Network scan failed" },
      { status: 500 }
    );
  }
}
