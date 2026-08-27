import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const hostHeader = req.headers.get("x-forwarded-host") || req.headers.get("host") || "localhost:3000";
  const proto = req.headers.get("x-forwarded-proto") || (url.protocol.startsWith("https") ? "https" : "http");
  const baseUrl = `${proto}://${hostHeader}`;
  const osParam = url.searchParams.get("os")?.toLowerCase() || "";

  if (osParam === "windows" || osParam === "ps1") {
    // PowerShell installer for Windows
    const ps1Script = `# LAN Sentinel & NetLens Go Agent Windows One-Click Installer
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  🚀 LAN SENTINEL - HIGH-SPEED GO NETWORK AGENT (WINDOWS)   " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$targetDir = Join-Path $env:TEMP "lan-sentinel-agent"
if (!(Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$exePath = Join-Path $targetDir "wifi-agent-windows-amd64.exe"
$downloadUrl = "${baseUrl}/bin/wifi-agent-windows-amd64.exe"

Write-Host "⬇️  Downloading NetLens Agent executable from ${baseUrl}..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $exePath -UseBasicParsing
    Write-Host "✅ Download complete ($exePath)" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to download binary: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  🟢 Starting NetLens Agent on http://127.0.0.1:8080 ...     " -ForegroundColor Green
Write-Host "  🌐 Switch to your browser to perform live network scans!   " -ForegroundColor Yellow
Write-Host "  ⚠️  Keep this terminal window open while scanning.          " -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

& $exePath
`;
    return new NextResponse(ps1Script, {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache, no-store, must-revalidate"
      }
    });
  }

  // Shell script for Linux / macOS
  const shScript = `#!/usr/bin/env bash
set -e

echo ""
echo -e "\\033[1;36m============================================================\\033[0m"
echo -e "\\033[1;32m  🚀 LAN SENTINEL - HIGH-SPEED GO NETWORK AGENT INSTALLER   \\033[0m"
echo -e "\\033[1;36m============================================================\\033[0m"
echo ""

BASE_URL="${baseUrl}"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux*)
    if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then
      BIN_NAME="wifi-agent-linux-amd64"
    else
      BIN_NAME="wifi-agent-linux-amd64"
    fi
    ;;
  darwin*)
    if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
      BIN_NAME="wifi-agent-darwin-arm64"
    else
      BIN_NAME="wifi-agent-darwin-amd64"
    fi
    ;;
  *)
    echo -e "\\033[1;31m❌ Unsupported OS: $OS. Please run via Go: 'cd agent-go && go run main.go'\\033[0m"
    exit 1
    ;;
esac

TARGET_DIR="/tmp/lan-sentinel-agent"
mkdir -p "$TARGET_DIR"
TARGET_FILE="$TARGET_DIR/$BIN_NAME"
DOWNLOAD_URL="$BASE_URL/bin/$BIN_NAME"
FALLBACK_URL="$BASE_URL/api/agent/download?os=$OS"

echo -e "\\033[1;33m⬇️  Downloading NetLens Agent ($BIN_NAME) from $BASE_URL...\\033[0m"

if command -v curl >/dev/null 2>&1; then
  curl -sSL -f -o "$TARGET_FILE" "$DOWNLOAD_URL" || curl -sSL -f -o "$TARGET_FILE" "$FALLBACK_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$TARGET_FILE" "$DOWNLOAD_URL" || wget -q -O "$TARGET_FILE" "$FALLBACK_URL"
else
  echo -e "\\033[1;31m❌ Neither curl nor wget was found. Please install curl.\\033[0m"
  exit 1
fi

if [ ! -s "$TARGET_FILE" ]; then
  echo -e "\\033[1;31m❌ Download failed or binary is empty. Please verify dashboard server is running.\\033[0m"
  exit 1
fi

chmod +x "$TARGET_FILE"

echo -e "\\033[1;32m✅ Download complete: $TARGET_FILE\\033[0m"
echo ""
echo -e "\\033[1;36m============================================================\\033[0m"
echo -e "\\033[1;32m  🟢 Starting NetLens Agent Daemon on http://127.0.0.1:8080 ...\\033[0m"
echo -e "\\033[1;33m  🌐 Your browser dashboard will auto-detect and scan LAN!   \\033[0m"
echo -e "\\033[1;30m  ⚠️  Press Ctrl+C at any time to stop the agent.             \\033[0m"
echo -e "\\033[1;36m============================================================\\033[0m"
echo ""

exec "$TARGET_FILE"
`;

  return new NextResponse(shScript, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-cache, no-store, must-revalidate"
    }
  });
}
