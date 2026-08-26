import { NextRequest, NextResponse } from "next/server";
import fs from "node:fs";
import path from "node:path";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const osParam = url.searchParams.get("os")?.toLowerCase() || "";
  const archParam = url.searchParams.get("arch")?.toLowerCase() || "";

  let fileName = "wifi-agent-linux-amd64";
  let downloadName = "wifi-agent";
  let contentType = "application/octet-stream";

  if (osParam === "windows" || osParam === "win") {
    fileName = "wifi-agent-windows-amd64.exe";
    downloadName = "wifi-agent.exe";
    contentType = "application/vnd.microsoft.portable-executable";
  } else if (osParam === "macos" || osParam === "darwin" || osParam === "mac") {
    if (archParam === "arm64" || archParam === "apple" || archParam === "m1" || archParam === "m2" || archParam === "m3") {
      fileName = "wifi-agent-darwin-arm64";
      downloadName = "wifi-agent-mac-arm64";
    } else {
      fileName = "wifi-agent-darwin-amd64";
      downloadName = "wifi-agent-mac-intel";
    }
  } else if (osParam === "linux") {
    fileName = "wifi-agent-linux-amd64";
    downloadName = "wifi-agent-linux";
  }

  const filePath = path.join(process.cwd(), "public", "bin", fileName);

  if (fs.existsSync(filePath)) {
    const fileBuffer = fs.readFileSync(filePath);
    return new NextResponse(fileBuffer, {
      headers: {
        "Content-Type": contentType,
        "Content-Disposition": `attachment; filename="${downloadName}"`,
        "Content-Length": fileBuffer.length.toString(),
        "Cache-Control": "public, max-age=3600"
      }
    });
  }

  // Fallback if binary is in agent-go directory
  const fallbackPath = path.join(process.cwd(), "..", "agent-go", fileName);
  if (fs.existsSync(fallbackPath)) {
    const fileBuffer = fs.readFileSync(fallbackPath);
    return new NextResponse(fileBuffer, {
      headers: {
        "Content-Type": contentType,
        "Content-Disposition": `attachment; filename="${downloadName}"`,
        "Content-Length": fileBuffer.length.toString(),
        "Cache-Control": "public, max-age=3600"
      }
    });
  }

  return NextResponse.json({ error: "Binary not found. Build via 'npm run build:agent'" }, { status: 404 });
}
