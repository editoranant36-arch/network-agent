import { NextResponse } from "next/server";
import { getLocalNetworkInfo } from "../../lib/scanner";

export async function GET() {
  const info = getLocalNetworkInfo();
  return NextResponse.json(info);
}
