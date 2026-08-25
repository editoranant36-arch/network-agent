import si from "systeminformation";
import ping from "ping";

export interface DeviceInfo {
  ip: string;
  status: "reachable" | "unreachable";
  responseTimeMs?: number;
}

export interface NetworkInfo {
  interface: string;
  localIp: string;
  subnet: string;
  netmask: string;
  gateway: string;
  dns: string[];
}

export async function getNetworkInfo(): Promise<NetworkInfo | null> {
  try {
    const interfaces = await si.networkInterfaces();
    const defaultGateway = await si.networkGatewayDefault();

    let activeInterface = Array.isArray(interfaces) 
      ? interfaces.find((iface) => iface.iface === defaultGateway)
      : undefined;

    // Fallback: finding the first non-internal interface with an IPv4 address
    if (!activeInterface && Array.isArray(interfaces)) {
      activeInterface = interfaces.find((iface) => !iface.internal && iface.ip4);
    }

    if (!activeInterface) {
      return null;
    }

    // Attempt to get DNS (systeminformation doesn't directly expose DNS cleanly in all OSes, 
    // but we can try os level or just omit it for MVP)
    
    return {
      interface: activeInterface.iface,
      localIp: activeInterface.ip4,
      subnet: getSubnetCidr(activeInterface.ip4, activeInterface.ip4subnet),
      netmask: activeInterface.ip4subnet,
      gateway: defaultGateway || "",
      dns: [] // Omitted for MVP simplicity
    };
  } catch (error) {
    console.error("Error fetching network info:", error);
    return null;
  }
}

// Simple CIDR calculator
function getSubnetCidr(ip: string, netmask: string): string {
  if (!ip || !netmask) return "";
  
  const ipParts = ip.split('.').map(Number);
  const maskParts = netmask.split('.').map(Number);
  
  if (ipParts.length !== 4 || maskParts.length !== 4) return "";
  
  const netParts = ipParts.map((part, i) => part & maskParts[i]);
  
  // Calculate CIDR prefix
  const cidr = maskParts.reduce((acc, part) => {
    let count = 0;
    let n = part;
    while (n > 0) {
      count += n & 1;
      n >>= 1;
    }
    return acc + count;
  }, 0);
  
  return `${netParts.join('.')}/${cidr}`;
}

export async function scanSubnet(
  baseIp: string, 
  onProgress: (progress: number, foundDevice?: DeviceInfo) => void
): Promise<DeviceInfo[]> {
  const parts = baseIp.split(".");
  if (parts.length !== 4) return [];
  
  const prefix = parts.slice(0, 3).join(".");
  const devices: DeviceInfo[] = [];
  
  // For MVP, we scan 1 to 254
  const totalHosts = 254;
  
  for (let i = 1; i <= 254; i++) {
    const targetIp = `${prefix}.${i}`;
    
    try {
      const res = await ping.promise.probe(targetIp, {
        timeout: 1, // 1 second timeout for fast scanning
      });
      
      let foundDevice: DeviceInfo | undefined = undefined;
      
      if (res.alive) {
        foundDevice = {
          ip: targetIp,
          status: "reachable",
          responseTimeMs: res.time !== 'unknown' ? Number(res.time) : undefined,
        };
        devices.push(foundDevice);
      }
      
      // Calculate progress percentage
      const progress = Math.round((i / totalHosts) * 100);
      onProgress(progress, foundDevice);
      
    } catch (e) {
      // Ignore errors for individual ping
      const progress = Math.round((i / totalHosts) * 100);
      onProgress(progress);
    }
  }
  
  return devices;
}
