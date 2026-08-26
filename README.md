# LAN Sentinel & NetLens Agent Ecosystem

An enterprise-grade, high-speed active Wi-Fi and LAN scanner with automatic network detection, live SSE streaming, defensive security recommendations, and an integrated **High-Speed Go Backend Agent** & **Next.js Fullstack Dashboard**.

---

## 🏗️ Architecture Overview

```
wifi-network-agent/
├── agent-go/            # 🚀 High-Performance Go REST, SSE & WebSocket Daemon (Port 8080 or $PORT)
│   ├── main.go          # Subnet Sweeper, SSE Streaming, NetBIOS, ARP & Port Auditor
│   ├── go.mod
│   └── go.sum
│
├── dashboard/           # 💻 Next.js 16 (Turbopack) Fullstack Dashboard UI (Port 3000)
│   ├── app/
│   │   ├── page.tsx     # Real-time interactive UI with Live Agent Switcher & Settings
│   │   ├── api/         # Proxy & Core Backend Endpoints (/api/network, /api/scan, etc.)
│   │   └── lib/         # Client & Server Scanner engines
│   └── package.json
│
├── render.yaml          # ☁️ 1-Click Multi-Service Render Blueprint
├── scanner-rs/          # Rust Async CLI Scanner
├── electron/            # Desktop Wrapper
└── extension/           # Chrome Extension
```

---

## 🚀 Running Locally

### 1. Start Both Backend Agent & Dashboard

You can start both services in separate terminals:

#### Terminal 1: Start Go Backend Agent
```bash
npm run agent:go
# or: cd agent-go && go run main.go
```
*Go Agent starts on `http://127.0.0.1:8080` (REST, SSE stream on `/api/scan/stream`, and WebSockets on `/ws`).*

#### Terminal 2: Start the Web Dashboard UI
```bash
npm run dev
# or: cd dashboard && npm install && npm run dev
```
*Open [http://localhost:3000](http://localhost:3000) in your browser.*

The Dashboard will automatically detect the Go Agent on `http://127.0.0.1:8080`, show the **"🟢 NetLens Agent Online"** badge, auto-detect your Wi-Fi SSID / Gateway, and stream live scanning results directly onto your screen.

---

## ☁️ How to Deploy on Render

### ⚠️ Critical Note on Render Port 8080
On Render:
- Free web services route public incoming traffic through Render's global proxy over **standard HTTPS (port 443)**.
- Render injects a dynamic `$PORT` environment variable (e.g. `10000` or `8080`) into your container.
- When connecting your frontend to a Render backend agent, **do NOT append `:8080`** to the Render URL!
- **Correct Render Agent URL format:** `https://wifi-agent-go-xxxx.onrender.com`
- **Incorrect:** `https://wifi-agent-go-xxxx.onrender.com:8080` *(will fail to connect)*

---

### Method A: 1-Click Render Blueprint (`render.yaml` - Recommended)

The repository includes a pre-configured [`render.yaml`](render.yaml) file that automatically configures and links both services together on Render.

1. **Push your repository to GitHub / GitLab:**
   ```bash
   git add .
   git commit -m "Configure Go agent and dashboard for Render"
   git push origin main
   ```
2. Log in to [Render](https://dashboard.render.com/).
3. Click **New +** → **Blueprint**.
4. Select your Git repository.
5. Render will automatically read `render.yaml` and create two web services:
   - **`wifi-agent-go`**: Go backend on `https://wifi-agent-go-xxxx.onrender.com`
   - **`lan-sentinel-dashboard`**: Next.js UI automatically connected to `wifi-agent-go` via `NEXT_PUBLIC_AGENT_URL`.
6. Click **Apply**. Both services will build and deploy automatically!

---

### Method B: Manual Web Service Setup on Render

If you prefer to configure each service manually in the Render dashboard:

#### Step 1: Deploy `wifi-agent-go` (Backend Service)
1. In Render, click **New +** → **Web Service**.
2. Select your repository.
3. Configure the following fields:
   - **Name**: `wifi-agent-go`
   - **Language / Runtime**: `Go`
   - **Root Directory**: `agent-go`
   - **Build Command**: `go build -o wifi-agent main.go`
   - **Start Command**: `./wifi-agent`
   - **Plan**: `Free`
4. Under **Environment Variables**, add:
   - `PORT` = `8080`
5. Click **Create Web Service**.
6. Copy the assigned URL (e.g. `https://wifi-agent-go-xxxx.onrender.com`).

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
   - `NEXT_PUBLIC_AGENT_URL` = `https://wifi-agent-go-xxxx.onrender.com` *(paste your backend URL from Step 1, without :8080)*
5. Click **Create Web Service**.
6. Once deployed, open your dashboard website URL (e.g. `https://lan-sentinel-dashboard.onrender.com`).

---

## 🔌 Connecting the Dashboard UI to the Agent

The Dashboard UI includes a built-in **Agent Connection Switcher**:
1. Click the **"⚙️ Settings"** badge next to the agent status in the top bar.
2. Enter any local URL (`http://127.0.0.1:8080`) or Render URL (`https://wifi-agent-go.onrender.com`).
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
| `ws://HOST:PORT/ws` | `WebSocket` | Real-time WebSocket connection for bidirectional diagnostic events. |
