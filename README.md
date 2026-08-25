# LAN Sentinel — WiFi Network Scanner & Monitor

All-in-one Next.js network scanner and security dashboard. Discovers LAN devices, hostnames, DNS, MAC vendors, and open ports with in-memory temporary storage.

## Features

- **Direct In-Dashboard Scanning**: No external agent or daemon required — runs entirely inside Next.js.
- **Temporary In-Memory Storage**: Devices are stored in temporary server & client memory; rescanning replaces and updates the active device list immediately.
- **Hostname & DNS Resolution**: NetBIOS name resolution (`nbtscan`), reverse DNS PTR, TLS Subject Common Names, and local machine identification.
- **Hardware & Vendor Detection**: Resolves MAC manufacturer information directly from the IEEE OUI database.
- **Defensive Advice Panel**: Service-specific security advice for discovered open ports.

## Quick Start

### 1. Install & Run Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

### 2. Scan Network

1. Enter your subnet CIDR (defaults to your active subnet, e.g. `192.168.0.0/24`).
2. Click **Start scan** or **Scan Network**.
3. Re-scanning will execute a live network scan and update the temporary memory.
4. Click any host to inspect ping latency, open ports, and defensive security advice.

