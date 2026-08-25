import { NextResponse } from "next/server";
import { getDetailedNetworkProfile } from "../../lib/scanner";

export async function GET() {
  const profile = await getDetailedNetworkProfile();
  return NextResponse.json(profile);
}
