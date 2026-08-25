# LAN Sentinel — Intelligent Wi-Fi Network Scanner & Agent Ecosystem

An enterprise-grade, high-speed active Wi-Fi and LAN scanner with automatic network detection, live SSE streaming, defensive security recommendations, and an integrated multi-agent backend architecture.

---

## 🚀 Key Features

- **⚡ Automatic Backend Agent Activation**: Automatically runs on website load to auto-detect Wi-Fi SSID, Gateway, CIDR, and execute complete subnet sweeps (IPs 1–254).
- **📡 Real-Time SSE Streaming**: Live Server-Sent Events stream discovered devices, ping latencies, and progress percentages to the dashboard in real-time.
- **🛡️ Wi-Fi Intelligence & Defensive Security**: Auto-classifies Personal Home Wi-Fi, Public/Hotspot Networks, and Enterprise LANs with tailored security advice and trust scores.
- **🔍 Deep Device & Port Fingerprinting**: NetBIOS name resolution (`nbtscan`), reverse DNS PTR, TLS Subject Common Names, ARP table inspection, and IEEE OUI MAC vendor lookup.
- **💾 Temporary In-Memory Persistence**: Discovered devices are saved in server temporary memory (`/api/devices`) and client session storage.
- **🔌 Multi-Engine Agent Connectivity**: Seamlessly bridges the Next.js Native Scanner, Go High-Speed Agent, NetLens Node.js Agent, Rust Async Scanner, Electron Desktop, and Chrome Extension.

---

## 📁 Repository Structure & Modules

```
wifi-network-agent/
├── dashboard/        # Next.js 16 (Turbopack) Fullstack Dashboard & Core Backend API
│   ├── app/
│   │   ├── api/
│   │   │   ├── agent/status/ # Backend agent connectivity & engine status
│   │   │   ├── devices/      # Temporary in-memory device cache (GET/DELETE)
│   │   │   ├── network/      # Live network profile (SSID, Gateway, Security, Trust)
│   │   │   ├── scan/         # Subnet scan POST endpoint
│   │   │   └── scan/stream/  # Server-Sent Events (SSE) live streaming scanner
│   │   ├── lib/
│   │   │   ├── scanner.ts    # Node.js backend high-speed socket & OS scanner engine
│   │   │   └── clientScanner.ts # In-browser fallback scanner engine
│   │   └── page.tsx          # Real-time interactive UI dashboard
├── agent-go/         # High-Performance Go Backend Agent (HTTP :8080 & WebSockets)
├── netlens-agent/    # TypeScript / Node.js Diagnostics Agent (ws:// :4000)
├── scanner-rs/       # Rust Async Multi-Threaded TCP/DNS Network Scanner CLI
├── electron/         # Electron Desktop Application Wrapper
└── extension/        # Chrome Extension for instant browser popup scanning
```

---

## 🛠️ Quick Start

### 1. Run the Dashboard (Primary Backend & UI)

```bash
cd dashboard
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The backend agent will automatically detect your network profile, initiate the subnet sweep, and display all active devices live on the dashboard.

### 2. Optional: Run the Go Backend Agent

```bash
npm run agent:go
# or: cd agent-go && go run main.go
```
The Go agent starts on `http://127.0.0.1:8080` and is automatically detected by the dashboard.

### 3. Optional: Run the NetLens Diagnostics Agent

```bash
npm run agent:node
# or: cd netlens-agent && npm run dev
```
Starts the diagnostics WebSocket server on `ws://127.0.0.1:4000`.

### 4. Optional: Run Rust High-Speed Scanner CLI

```bash
cargo run --manifest-path scanner-rs/Cargo.toml -- --cidr 192.168.0.0/24
```

### 5. Optional: Chrome Extension

1. Open Chrome and go to `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select the `extension/` folder.
4. Click the LAN Sentinel icon in your toolbar to scan directly from Chrome.

---

## 📡 API Endpoints Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/network` | `GET` | Returns detected network profile (SSID, Gateway, Subnet, Risk, Trust Score). |
| `/api/scan/stream` | `GET` | SSE stream pushing live scanning progress and discovered devices. |
| `/api/scan` | `POST` | Executes complete subnet scan and returns JSON array of live devices. |
| `/api/devices` | `GET` / `DELETE` | Retrieves or clears temporary in-memory scan results. |
| `/api/agent/status` | `GET` | Returns backend agent health and connected sub-services. |

---

## 🔒 Security & Defensive Advice

The system analyzes discovered open services (e.g. SSH `22`, DNS `53`, HTTP `80`, SMB `445`, HTTPS `443`, RDP `3389`, Dev Ports `3000/8080`) and generates targeted defensive hardening recommendations for each host.
