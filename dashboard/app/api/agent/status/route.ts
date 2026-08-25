import { NextResponse } from "next/server";
import { getBackendAgentStatus } from "../../../lib/scanner";

export const dynamic = "force-dynamic";

export async function GET() {
  const status = await getBackendAgentStatus();
  return NextResponse.json(status);
}
