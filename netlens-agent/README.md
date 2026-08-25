# NetLens Local Agent

The NetLens Local Agent is a lightweight, secure background service that runs on your local machine. It allows the NetLens Web Dashboard to bypass browser sandbox restrictions to accurately scan your local network.

## Why is this needed?
Modern web browsers intentionally block websites from directly accessing your local network (LAN) for security reasons. The Local Agent runs natively on your machine, using standard OS-level networking APIs to safely detect your IP, subnet, and nearby devices, sending the results exclusively back to your NetLens Dashboard.

---

## Installation Instructions

### Option 1: Running via Node.js (Recommended for Developers)

**Prerequisites:** Ensure you have [Node.js](https://nodejs.org/) installed on your machine.

1. **Download the Agent:**
   Clone or download this repository to your local machine.
   ```bash
   git clone https://github.com/your-org/netlens.git
   cd netlens/apps/agent
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Start the Agent:**
   ```bash
   npm start
   ```
   *The agent will now be running on `ws://127.0.0.1:4000`.*

4. **Connect:**
   Open the [NetLens Web Dashboard](http://localhost:3000) (or your deployed Vercel URL) and click **"Connect to Agent"**.

---

## Security & Privacy Guarantee
- **No Arbitrary Execution:** The agent does *not* accept arbitrary shell or terminal commands from the browser. It only responds to strict, allowlisted commands (`GET_NETWORK_INFO`, `START_DISCOVERY`).
- **Local Access Only:** The agent binds exclusively to `127.0.0.1` (localhost). It cannot be accessed by anyone else on your network or the internet.
- **Outbound Only:** The agent only sends network diagnostic data directly to your active browser session.

## Troubleshooting
- **Address in Use (EADDRINUSE):** If you get an error that port 4000 is in use, you may already have the agent running in the background. You can terminate the existing process and restart it.
- **Connection Refused:** Ensure the agent is fully started and says `Network Diagnostics Agent started on ws://127.0.0.1:4000` before clicking "Connect" in the web UI.
