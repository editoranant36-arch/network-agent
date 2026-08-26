import { NextRequest } from "next/server";
import { runDashboardNetworkScanStream, Device } from "../../../lib/scanner";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const cidr = searchParams.get("cidr") || "";
  const portsParam = searchParams.get("ports") || "";

  const agentBaseUrl = process.env.AGENT_URL || process.env.NEXT_PUBLIC_AGENT_URL || "http://127.0.0.1:8080";

  // 1. Try proxying to local Go agent SSE stream first
  try {
    const upstreamUrl = `${agentBaseUrl.replace(/\/$/, "")}/api/scan/stream?cidr=${encodeURIComponent(cidr)}&ports=${encodeURIComponent(portsParam)}`;
    const upstreamRes = await fetch(upstreamUrl, {
      signal: AbortSignal.timeout(2500),
      headers: { Accept: "text/event-stream" }
    });

    if (upstreamRes.ok && upstreamRes.body) {
      return new Response(upstreamRes.body, {
        headers: {
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          "Connection": "keep-alive",
          "X-Accel-Buffering": "no"
        }
      });
    }
  } catch {}

  // 2. Fallback to native TypeScript scanner engine on the host
  const ports = portsParam
    ? portsParam.split(",").map(Number).filter((n) => !isNaN(n) && n > 0)
    : undefined;

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const sendEvent = (event: string, payload: any) => {
        try {
          const str = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
          controller.enqueue(encoder.encode(str));
        } catch {}
      };

      try {
        sendEvent("status", { message: "Backend Agent connected and analyzing network..." });

        const devices: Device[] = await runDashboardNetworkScanStream(
          cidr || undefined,
          ports,
          (scanned, total, pct, currentIp) => {
            sendEvent("progress", { scanned, total, percentage: pct, currentIp });
          },
          (device) => {
            sendEvent("device", device);
          }
        );

        sendEvent("complete", { devices, total: devices.length });
      } catch (err: any) {
        sendEvent("error", { message: err?.message || "Backend scan failed" });
      } finally {
        try {
          controller.close();
        } catch {}
      }
    }
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no"
    }
  });
}
