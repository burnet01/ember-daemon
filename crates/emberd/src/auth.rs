//! Tailscale is the login system. Every request is attributed to a person by
//! asking the local tailscaled who owns the source address, and it fails closed.
//!
//! The daemon has no cookies or browser sessions, but a web page open on an owner's
//! machine would still arrive with that machine's identity. `check_request_shape`
//! stops such pages from reaching the API through CSRF or DNS rebinding.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_RESPONSE: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct Tailscale {
    socket: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SelfInfo {
    pub ips: Vec<IpAddr>,
    pub dns_name: String,
    pub host_name: String,
}

impl SelfInfo {
    pub fn ipv4(&self) -> Option<IpAddr> {
        self.ips.iter().copied().find(IpAddr::is_ipv4)
    }
}

impl Tailscale {
    pub fn new(socket: &Path) -> Self {
        Self { socket: socket.to_path_buf() }
    }

    async fn get(&self, path_and_query: &str) -> Result<Vec<u8>> {
        let exchange = async {
            let mut s = UnixStream::connect(&self.socket)
                .await
                .with_context(|| format!("connect to tailscaled at {}", self.socket.display()))?;
            let req = format!(
                "GET {path_and_query} HTTP/1.0\r\nHost: local-tailscaled.sock\r\nConnection: close\r\n\r\n"
            );
            s.write_all(req.as_bytes()).await?;
            let mut buf = Vec::new();
            s.take(MAX_RESPONSE).read_to_end(&mut buf).await?;
            parse_http_body(&buf)
        };
        tokio::time::timeout(Duration::from_secs(5), exchange).await.map_err(|_| anyhow!("tailscaled timed out"))?
    }

    pub async fn status(&self) -> Result<SelfInfo> {
        let body = self.get("/localapi/v0/status").await?;
        parse_status(&body)
    }

    pub async fn whois(&self, peer: SocketAddr) -> Result<String> {
        let body = self.get(&format!("/localapi/v0/whois?addr={peer}")).await?;
        parse_whois(&body)
    }
}

fn parse_http_body(buf: &[u8]) -> Result<Vec<u8>> {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| anyhow!("malformed tailscaled response"))?;
    let head = String::from_utf8_lossy(&buf[..split]);
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        bail!("tailscaled returned status {status}");
    }
    Ok(buf[split + 4..].to_vec())
}

fn parse_status(body: &[u8]) -> Result<SelfInfo> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Status {
        #[serde(rename = "Self")]
        me: Me,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Me {
        #[serde(rename = "TailscaleIPs", default)]
        ips: Option<Vec<IpAddr>>,
        #[serde(rename = "DNSName", default)]
        dns_name: String,
        #[serde(default)]
        host_name: String,
    }
    let s: Status = serde_json::from_slice(body).context("parse tailscale status")?;
    Ok(SelfInfo {
        ips: s.me.ips.unwrap_or_default(),
        dns_name: s.me.dns_name.trim_end_matches('.').to_ascii_lowercase(),
        host_name: s.me.host_name.to_ascii_lowercase(),
    })
}

fn parse_whois(body: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct WhoIs {
        #[serde(rename = "UserProfile")]
        user: Option<User>,
    }
    #[derive(Deserialize)]
    struct User {
        #[serde(rename = "LoginName", default)]
        login: String,
    }
    let w: WhoIs = serde_json::from_slice(body).context("parse whois")?;
    let login = w.user.map(|u| u.login).unwrap_or_default();
    if login.is_empty() {
        bail!("whois returned no login");
    }
    Ok(login)
}

pub fn is_owner(owners: &[String], login: &str) -> bool {
    !login.eq_ignore_ascii_case("tagged-devices") && owners.iter().any(|o| o.eq_ignore_ascii_case(login))
}

/// Blocks anything that did not come from the desktop app.
pub fn check_request_shape(origin: Option<&str>, client: Option<&str>, host: Option<&str>, me: &SelfInfo) -> Result<(), &'static str> {
    // Browsers attach Origin to cross-site writes and WebSockets. The app never does.
    if origin.is_some() {
        return Err("browser requests are not accepted");
    }
    if client.is_none() {
        return Err("missing client header");
    }
    // A rebound hostname arrives with the attacker's name in Host.
    let host = host.ok_or("missing host header")?;
    if !host_allowed(host, me) {
        return Err("unexpected host header");
    }
    Ok(())
}

fn host_allowed(host: &str, me: &SelfInfo) -> bool {
    let name = host.rsplit_once(':').map_or(host, |(h, port)| {
        if port.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            host
        }
    });
    let name = name.trim_matches(['[', ']']).to_ascii_lowercase();
    if let Ok(ip) = name.parse::<IpAddr>() {
        return me.ips.contains(&ip);
    }
    (!me.dns_name.is_empty() && name == me.dns_name) || (!me.host_name.is_empty() && name == me.host_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> SelfInfo {
        SelfInfo {
            ips: vec!["100.100.1.2".parse().unwrap(), "fd7a:115c:a1e0::2".parse().unwrap()],
            dns_name: "node.tail1234.ts.net".into(),
            host_name: "node".into(),
        }
    }

    #[test]
    fn parses_tailscaled_payloads() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        assert_eq!(parse_http_body(raw).unwrap(), b"{\"a\":1}");
        assert!(parse_http_body(b"HTTP/1.0 403 Forbidden\r\n\r\nno").is_err());
        assert!(parse_http_body(b"garbage").is_err());

        let w = br#"{"Node":{},"UserProfile":{"LoginName":"me@example.com"}}"#;
        assert_eq!(parse_whois(w).unwrap(), "me@example.com");
        assert!(parse_whois(br#"{"Node":{}}"#).is_err(), "no identity must be an error");

        let s = br#"{"Self":{"TailscaleIPs":["100.100.1.2"],"DNSName":"Node.tail.ts.net.","HostName":"Node"}}"#;
        let info = parse_status(s).unwrap();
        assert_eq!(info.ipv4().unwrap().to_string(), "100.100.1.2");
        assert_eq!(info.dns_name, "node.tail.ts.net");
    }

    #[test]
    fn only_listed_people_are_owners() {
        let owners = vec!["me@example.com".to_string()];
        assert!(is_owner(&owners, "ME@example.com"));
        assert!(!is_owner(&owners, "other@example.com"));
        assert!(!is_owner(&["tagged-devices".to_string()], "tagged-devices"));
    }

    #[test]
    fn browser_attacks_are_rejected() {
        let m = me();
        let ok = |o, c, h| check_request_shape(o, c, h, &m).is_ok();
        assert!(ok(None, Some("panel"), Some("100.100.1.2:8787")));
        assert!(ok(None, Some("panel"), Some("node.tail1234.ts.net:8787")));
        assert!(!ok(Some("https://evil.example"), Some("panel"), Some("100.100.1.2:8787")), "CSRF");
        assert!(!ok(None, None, Some("100.100.1.2:8787")), "simple cross-site request");
        assert!(!ok(None, Some("panel"), Some("evil.example:8787")), "DNS rebinding");
        assert!(!ok(None, Some("panel"), Some("100.100.9.9:8787")), "foreign IP");
        assert!(!ok(None, Some("panel"), None));
    }
}
