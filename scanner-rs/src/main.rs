use anyhow::Result;
use clap::Parser;
use futures::stream::{self, StreamExt};
use ipnet::Ipv4Net;
use serde::Serialize;
use std::{net::{IpAddr, SocketAddr}, time::Duration};
use tokio::{net::TcpStream, time::timeout};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    cidr: String,

    #[arg(long, default_value = "22,53,80,135,139,443,445,3389,8080,8443")]
    ports: String,

    #[arg(long, default_value_t = 800)]
    timeout_ms: u64,
}

#[derive(Serialize)]
struct Device {
    ip: String,
    reachable: bool,
    ping_ms: Option<u128>,
    dns: Option<String>,
    open_ports: Vec<u16>,
}

async fn tcp_probe(ip: IpAddr, port: u16, ms: u64) -> bool {
    let addr = SocketAddr::new(ip, port);
    timeout(Duration::from_millis(ms), TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

async fn reverse_dns(ip: IpAddr) -> Option<String> {
    // tokio's lookup API is forward-only; use the OS resolver through a
    // short-lived `getent`/`nslookup` fallback where available.
    // Failure is normal on networks without PTR records.
    #[cfg(unix)]
    {
        if let Ok(out) = tokio::process::Command::new("getent")
            .arg("hosts").arg(ip.to_string()).output().await {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                let mut p = s.split_whitespace();
                let _ = p.next();
                if let Some(name) = p.next() { return Some(name.to_string()); }
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let net: Ipv4Net = args.cidr.parse()?;
    let ports: Vec<u16> = args.ports.split(',')
        .filter_map(|x| x.trim().parse().ok()).collect();

    let hosts: Vec<IpAddr> = net.hosts().map(IpAddr::V4).collect();

    let results = stream::iter(hosts)
        .map(|ip| {
            let ports = ports.clone();
            async move {
                let start = std::time::Instant::now();
                let mut open = Vec::new();

                // Reachability is approximated with TCP probes so the agent
                // does not require raw-socket privileges.
                for port in &ports {
                    if tcp_probe(ip, *port, args.timeout_ms).await {
                        open.push(*port);
                    }
                }

                let reachable = !open.is_empty();
                let ping_ms = if reachable { Some(start.elapsed().as_millis()) } else { None };
                let dns = if reachable { reverse_dns(ip).await } else { None };

                Device {
                    ip: ip.to_string(),
                    reachable,
                    ping_ms,
                    dns,
                    open_ports: open,
                }
            }
        })
        .buffer_unordered(64)
        .collect::<Vec<_>>()
        .await;

    let live: Vec<_> = results.into_iter().filter(|d| d.reachable).collect();
    println!("{}", serde_json::to_string_pretty(&live)?);
    Ok(())
}
