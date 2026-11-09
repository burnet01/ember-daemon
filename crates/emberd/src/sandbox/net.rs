//! Per-server network isolation.
//!
//! Each server sits in its own network namespace behind a veth pair. The nftables
//! table below is what keeps a compromised game server off the admin plane: it can
//! reach the public internet and answer players, but not this host, the tailnet,
//! private networks, cloud metadata, or any other server.

use anyhow::{anyhow, bail, Context, Result};
use ember_proto::Protocol;
use std::net::Ipv4Addr;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const SUBNET_BASE: u32 = u32::from_be_bytes([10, 213, 0, 0]);
pub const MAX_INDEX: u32 = 16_382;

/// Non-public IPv4 ranges a sandbox may never originate traffic to.
const BLOCKED_V4: &str = "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, \
192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4";

pub fn netns_name(index: u32) -> String {
    format!("ember-{index}")
}

/// `(host side, sandbox side)` addresses of a server's /30.
pub fn addrs(index: u32) -> (Ipv4Addr, Ipv4Addr) {
    let base = SUBNET_BASE + index * 4;
    (Ipv4Addr::from(base + 1), Ipv4Addr::from(base + 2))
}

fn ruleset() -> String {
    format!(
        r#"table inet ember {{}}
delete table inet ember
table inet ember {{
  map tcp_ports {{ type inet_service : ipv4_addr; }}
  map udp_ports {{ type inet_service : ipv4_addr; }}

  chain prerouting {{
    type nat hook prerouting priority -100; policy accept;
    iifname "embh*" return
    meta nfproto ipv4 fib daddr type local dnat ip to tcp dport map @tcp_ports
    meta nfproto ipv4 fib daddr type local dnat ip to udp dport map @udp_ports
  }}
  chain output_nat {{
    type nat hook output priority -100; policy accept;
    meta nfproto ipv4 fib daddr type local dnat ip to tcp dport map @tcp_ports
    meta nfproto ipv4 fib daddr type local dnat ip to udp dport map @udp_ports
  }}
  chain postrouting {{
    type nat hook postrouting priority 100; policy accept;
    ip saddr 10.213.0.0/16 oifname != "embh*" masquerade
  }}
  chain input {{
    type filter hook input priority -10; policy accept;
    iifname "embh*" ct state established,related accept
    iifname "embh*" counter drop
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    oifname "embh*" iifname "embh*" counter drop
    oifname "embh*" ct state established,related accept
    oifname "embh*" ct status dnat accept
    oifname "embh*" counter drop
    iifname "embh*" ct state established,related accept
    iifname "embh*" meta nfproto ipv6 counter drop
    iifname "embh*" ip daddr {{ {BLOCKED_V4} }} counter drop
    iifname "embh*" accept
  }}
}}
"#
    )
}

async fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("run {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

async fn nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("run nft (is nftables installed?)")?;
    child.stdin.take().ok_or_else(|| anyhow!("nft stdin"))?.write_all(script.as_bytes()).await?;
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Installs the firewall atomically and clears leftovers from a previous run.
pub async fn init() -> Result<()> {
    tokio::fs::write("/proc/sys/net/ipv4/ip_forward", "1").await.context("enable IPv4 forwarding")?;
    nft(&ruleset()).await.context("install firewall")?;
    allow_through_iptables().await;
    sweep_stale().await;
    Ok(())
}

/// Hosts with Docker or UFW default the iptables FORWARD chain to DROP, and a
/// packet must pass every base chain. These rules only let `embh*` traffic reach
/// our own nftables policy, which still makes the actual decision.
async fn allow_through_iptables() {
    for flag in ["-i", "-o"] {
        let check = run("iptables", &["-C", "FORWARD", flag, "embh+", "-j", "ACCEPT"]).await;
        if check.is_err() {
            if let Err(e) = run("iptables", &["-I", "FORWARD", "1", flag, "embh+", "-j", "ACCEPT"]).await {
                tracing::debug!("iptables not adjusted: {e}");
            }
        }
    }
}

async fn sweep_stale() {
    let Ok(mut rd) = tokio::fs::read_dir("/run/netns").await else {
        return;
    };
    while let Ok(Some(e)) = rd.next_entry().await {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.strip_prefix("ember-x").is_some_and(|i| i.parse::<u32>().is_ok()) {
            let _ = run("ip", &["netns", "del", &name]).await;
            continue;
        }
        if let Some(index) = name.strip_prefix("ember-").and_then(|i| i.parse::<u32>().ok()) {
            tracing::warn!(netns = %name, "removing stale network namespace");
            let host = format!("embh{index}");
            let _ = run("ip", &["link", "del", &host]).await;
            let _ = run("ip", &["netns", "del", &name]).await;
        }
    }
}

fn offline_name(index: u32) -> String {
    format!("ember-x{index}")
}

/// A namespace with nothing in it, for work that has no reason to touch a network.
pub async fn offline_up(index: u32) -> Result<String> {
    let ns = offline_name(index);
    let _ = run("ip", &["netns", "del", &ns]).await;
    run("ip", &["netns", "add", &ns]).await?;
    Ok(ns)
}

pub async fn offline_down(index: u32) {
    let _ = run("ip", &["netns", "del", &offline_name(index)]).await;
}

/// Creates the namespace, wires it to the host and opens the game port.
pub async fn up(index: u32, port: u16, proto: Protocol) -> Result<String> {
    if index == 0 || index > MAX_INDEX {
        bail!("network index {index} out of range");
    }
    let result = setup(index, port, proto).await;
    if let Err(e) = result {
        down(index, port, proto).await;
        return Err(e);
    }
    Ok(netns_name(index))
}

async fn setup(index: u32, port: u16, proto: Protocol) -> Result<()> {
    let ns = netns_name(index);
    let (host, peer) = (format!("embh{index}"), format!("embp{index}"));
    let (host_ip, sandbox_ip) = addrs(index);
    let (host_cidr, sandbox_cidr) = (format!("{host_ip}/30"), format!("{sandbox_ip}/30"));
    let gateway = host_ip.to_string();

    // A previous crash can leave these behind; failure here just means they were absent.
    let _ = run("ip", &["link", "del", &host]).await;
    let _ = run("ip", &["netns", "del", &ns]).await;

    run("ip", &["netns", "add", &ns]).await?;
    run("ip", &["link", "add", &host, "type", "veth", "peer", "name", &peer]).await?;
    run("ip", &["link", "set", &peer, "netns", &ns]).await?;
    run("ip", &["addr", "add", &host_cidr, "dev", &host]).await?;
    run("ip", &["link", "set", &host, "up"]).await?;
    run("ip", &["-n", &ns, "link", "set", "lo", "up"]).await?;
    run("ip", &["-n", &ns, "link", "set", &peer, "name", "eth0"]).await?;
    run("ip", &["-n", &ns, "addr", "add", &sandbox_cidr, "dev", "eth0"]).await?;
    run("ip", &["-n", &ns, "link", "set", "eth0", "up"]).await?;
    run("ip", &["-n", &ns, "route", "add", "default", "via", &gateway]).await?;
    run("ip", &["netns", "exec", &ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"]).await?;

    nft(&format!("add element inet ember {} {{ {port} : {sandbox_ip} }}\n", map_name(proto))).await
}

fn map_name(proto: Protocol) -> &'static str {
    match proto {
        Protocol::Tcp => "tcp_ports",
        Protocol::Udp => "udp_ports",
    }
}

/// Best-effort teardown; it also runs against partially built networks.
pub async fn down(index: u32, port: u16, proto: Protocol) {
    let ns = netns_name(index);
    let host = format!("embh{index}");
    let (_, sandbox_ip) = addrs(index);
    let _ = nft(&format!("delete element inet ember {} {{ {port} : {sandbox_ip} }}\n", map_name(proto))).await;
    let _ = run("ip", &["link", "del", &host]).await;
    let _ = run("ip", &["netns", "del", &ns]).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets_do_not_overlap() {
        assert_eq!(addrs(1), (Ipv4Addr::new(10, 213, 0, 5), Ipv4Addr::new(10, 213, 0, 6)));
        assert_eq!(addrs(2), (Ipv4Addr::new(10, 213, 0, 9), Ipv4Addr::new(10, 213, 0, 10)));
        let (_, last) = addrs(MAX_INDEX);
        assert_eq!(last.octets()[0..2], [10, 213]);
    }

    #[test]
    fn firewall_blocks_the_admin_plane() {
        let r = ruleset();
        for net in ["100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "10.0.0.0/8"] {
            assert!(r.contains(net), "missing {net}");
        }
        assert!(r.contains("iifname \"embh*\" counter drop"), "host input must be denied");
    }
}
