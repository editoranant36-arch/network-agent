# LAN Sentinel & NetLens Agent Ecosystem

An enterprise-grade, high-speed active Wi-Fi and LAN scanner with automatic network detection, live SSE streaming, defensive security recommendations, and an integrated **NetLens Backend Agent** & **Next.js Fullstack Dashboard**.

---

## 🏗️ Architecture Overview

```
wifi-network-agent/
├── netlens-agent/       # 🚀 Node.js / Express / WebSocket Backend Agent (Port 4000)
│   ├── src/
│   │   ├── index.ts     # Express REST API, SSE Streaming & WebSocket Server
│   │   └── network.ts   # Fast Subnet Scanner, OUI MAC Resolution & Port Auditor
│   ├── package.json
│   └── tsconfig.json
│
├── dashboard/           # 💻 Next.js 16 (Turbopack) Fullstack Dashboard UI (Port 3000)
│   ├── app/
│   │   ├── page.tsx     # Real-time interactive UI with Live Agent Switcher & Settings
│   │   ├── api/         # Proxy & Core Backend Endpoints (/api/network, /api/scan, etc.)
│   │   └── lib/         # Client & Server Scanner engines
│   └── package.json
│
├── render.yaml          # ☁️ 1-Click Multi-Service Render Blueprint
├── agent-go/            # High-Performance Go Agent (:8080)
├── scanner-rs/          # Rust Async CLI Scanner
├── electron/            # Desktop Wrapper
└── extension/           # Chrome Extension
```

---

## 🚀 Running Locally

### 1. Start Both Backend Agent & Dashboard

You can start both services in separate terminals:

#### Terminal 1: Start NetLens Backend Agent
```bash
npm run agent:node
# or: cd netlens-agent && npm install && npm run build && npm start
```
*NetLens Agent starts on `http://127.0.0.1:4000` (REST, SSE stream, and WebSockets).*

#### Terminal 2: Start the Web Dashboard UI
```bash
npm run dev
# or: cd dashboard && npm install && npm run dev
```
*Open [http://localhost:3000](http://localhost:3000) in your browser.*

The Dashboard will automatically detect the NetLens Agent on `http://127.0.0.1:4000`, show the **"🟢 NetLens Agent Online"** badge, auto-detect your Wi-Fi SSID / Gateway, and stream live scanning results directly onto your screen.

---

## ☁️ How to Deploy Both Files/Services on Render

You can deploy the entire stack to Render using either **Method A (Render Blueprint - Recommended)** or **Method B (Manual Service Creation)**.

### Method A: 1-Click Render Blueprint (`render.yaml`)

The repository includes a pre-configured [`render.yaml`](file:///home/manish/Downloads/wifi-network-agent/render.yaml) file that automatically configures and links both services together on Render.

1. **Push your repository to GitHub / GitLab:**
   ```bash
   git add .
   git commit -m "Configure NetLens backend agent and dashboard for Render"
   git push origin main
   ```
2. Log in to [Render](https://dashboard.render.com/).
3. Click **New +** → **Blueprint**.
4. Select your Git repository.
5. Render will automatically read `render.yaml` and create two web services:
   - **`netlens-agent`**: Node.js backend on `https://netlens-agent-xxxx.onrender.com`
   - **`lan-sentinel-dashboard`**: Next.js UI automatically connected to `netlens-agent` via `NEXT_PUBLIC_AGENT_URL`.
6. Click **Apply**. Both services will build and deploy automatically!

---

### Method B: Manual Web Service Setup on Render

If you prefer to configure each service manually in the Render dashboard:

#### Step 1: Deploy `netlens-agent` (Backend Service)
1. In Render, click **New +** → **Web Service**.
2. Select your repository.
3. Configure the following fields:
   - **Name**: `netlens-agent`
   - **Language / Runtime**: `Node`
   - **Root Directory**: `netlens-agent`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
   - **Plan**: `Free`
4. Under **Environment Variables**, add:
   - `NODE_VERSION` = `20.18.0`
   - `PORT` = `4000`
5. Click **Create Web Service**.
6. Copy the assigned URL (e.g. `https://netlens-agent-xxxx.onrender.com`).

---

#### Step 2: Deploy `dashboard` (Frontend Website)
1. In Render, click **New +** → **Web Service**.
2. Select the same repository.
3. Configure the following fields:
   - **Name**: `lan-sentinel-dashboard`
   - **Language / Runtime**: `Node`
   - **Root Directory**: `dashboard`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
   - **Plan**: `Free`
4. Under **Environment Variables**, add:
   - `NODE_VERSION` = `20.18.0`
   - `NEXT_PUBLIC_AGENT_URL` = `https://netlens-agent-xxxx.onrender.com` *(paste your NetLens Agent URL from Step 1)*
5. Click **Create Web Service**.
6. Once deployed, open your dashboard website URL (e.g. `https://lan-sentinel-dashboard.onrender.com`).

---

## 🔌 Connecting the Dashboard UI to the Agent

The Dashboard UI includes a built-in **Agent Connection Switcher**:
1. Click the **"⚙️ Settings"** badge next to the agent status in the top bar.
2. Enter any local URL (`http://127.0.0.1:4000`) or Render URL (`https://your-agent.onrender.com`).
3. Click **"Connect"** — the dashboard will measure ping latency, verify the REST/SSE endpoints, and immediately route all scanning requests through the chosen agent.

---

## 📡 API Endpoints Summary

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/agent/status` | `GET` | Backend agent health, OS info, and engine type. |
| `/api/network` | `GET` | Detected network profile (SSID, Gateway, CIDR, Trust Score). |
| `/api/scan/stream` | `GET` | Live SSE stream pushing scanning progress and newly discovered hosts. |
| `/api/scan` | `POST` | Executes complete subnet scan and returns JSON array of live devices. |
| `/api/devices` | `GET` / `DELETE` | Retrieves or clears temporary in-memory scan results. |
| `ws://HOST:PORT` | `WebSocket`| Real-time WebSocket connection for bidirectional diagnostic events. |
