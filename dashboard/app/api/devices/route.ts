import { NextResponse } from "next/server";
import { getInMemoryDevices, clearInMemoryDevices } from "../../lib/scanner";

export async function GET() {
  const data = getInMemoryDevices();
  return NextResponse.json(data);
}

export async function DELETE() {
  clearInMemoryDevices();
  return NextResponse.json({ success: true, message: "Temporary scan memory cleared" });
}
