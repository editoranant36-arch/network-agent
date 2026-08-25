import { WebSocketServer, WebSocket } from "ws";
import { getNetworkInfo, scanSubnet } from "./network";

const PORT = 4000;
const wss = new WebSocketServer({ port: PORT });

console.log(`[Agent] Network Diagnostics Agent started on ws://127.0.0.1:${PORT}`);

wss.on("connection", (ws: WebSocket) => {
  console.log("[Agent] Client connected");

  ws.on("message", async (message: Buffer) => {
    try {
      const msg = JSON.parse(message.toString());
      console.log(`[Agent] Received message: ${msg.type}`);

      if (msg.type === "GET_NETWORK_INFO") {
        const info = await getNetworkInfo();
        if (info) {
          ws.send(JSON.stringify({
            type: "NETWORK_INFO_RESULT",
            payload: info
          }));
        } else {
          ws.send(JSON.stringify({
            type: "ERROR",
            payload: "Failed to fetch network information"
          }));
        }
      }

      if (msg.type === "START_DISCOVERY") {
        const { baseIp } = msg.payload;
        if (!baseIp) {
          ws.send(JSON.stringify({
            type: "ERROR",
            payload: "No base IP provided for scanning"
          }));
          return;
        }

        console.log(`[Agent] Starting scan on ${baseIp}`);
        
        // Notify start
        ws.send(JSON.stringify({ type: "SCAN_STARTED" }));

        await scanSubnet(baseIp, (progress, device) => {
          // Send progress update
          ws.send(JSON.stringify({
            type: "SCAN_PROGRESS",
            payload: { progress }
          }));

          // Send device if found
          if (device) {
            ws.send(JSON.stringify({
              type: "HOST_FOUND",
              payload: device
            }));
          }
        });

        // Notify complete
        ws.send(JSON.stringify({ type: "SCAN_COMPLETED" }));
        console.log(`[Agent] Scan completed`);
      }
      
    } catch (e) {
      console.error("[Agent] Failed to process message", e);
    }
  });

  ws.on("close", () => {
    console.log("[Agent] Client disconnected");
  });
});
