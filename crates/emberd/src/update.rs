//! `emberd self-update`, run nightly by a systemd timer. Installs the latest release, has the
//! daemon restart once it is idle, and puts the old version back if the new one won't run.

use crate::{auth, config::Config, install};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

const RELEASE_BASE: &str = "https://github.com/burnet01/ember-daemon/releases/latest/download";
const ASSET: &str = "emberd-linux-x86_64";
const SERVICE: &str = "emberd";
/// How long the daemon gets to finish backups and installs before it is restarted anyway.
const BUSY_LIMIT: Duration = Duration::from_secs(2 * 60 * 60);
const START_LIMIT: Duration = Duration::from_secs(60);
/// A daemon that dies right after starting must not count as working.
const STABLE_FOR: Duration = Duration::from_secs(15);

/// Tells the daemon to restart when idle and bring back what's running. Removed once honored.
pub fn restart_marker(data_dir: &Path) -> PathBuf {
    data_dir.join("restart-requested")
}

/// The checksum of a release that failed to run here, so it isn't retried every night.
fn skip_file(data_dir: &Path) -> PathBuf {
    data_dir.join("update-skip")
}

/// Used by the installer so an update it applies brings servers back too.
pub fn prepare_restart(config: &Path) -> Result<()> {
    let cfg = Config::load(config)?;
    std::fs::write(restart_marker(&cfg.data_dir), "").context("write restart marker")
}

fn parse_checksum(text: &str) -> Result<String> {
    let sum = text.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();
    if sum.len() != 64 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("the release's checksum file is malformed");
    }
    Ok(sum)
}

fn file_sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn systemctl_ok(args: &[&str]) -> bool {
    std::process::Command::new("systemctl").args(args).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

fn service_pid() -> Option<String> {
    let out = std::process::Command::new("systemctl").args(["show", "-p", "MainPID", "--value", SERVICE]).output().ok()?;
    let pid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!pid.is_empty() && pid != "0").then_some(pid)
}

async fn listening(addr: std::net::SocketAddr) -> bool {
    matches!(tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await, Ok(Ok(_)))
}

async fn runs_here(binary: &Path) -> bool {
    let run = tokio::process::Command::new(binary).arg("version").stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).status();
    matches!(tokio::time::timeout(Duration::from_secs(10), run).await, Ok(Ok(s)) if s.success())
}

async fn wait_for_restart(old_pid: Option<&str>) {
    let start = Instant::now();
    while start.elapsed() < BUSY_LIMIT {
        if service_pid().is_some_and(|pid| Some(pid.as_str()) != old_pid) {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    println!("The daemon is still busy after {} minutes, so restarting it now.", BUSY_LIMIT.as_secs() / 60);
    systemctl_ok(&["restart", SERVICE]);
}

async fn healthy(addr: std::net::SocketAddr) -> bool {
    let start = Instant::now();
    while !listening(addr).await {
        if start.elapsed() > START_LIMIT {
            return false;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let pid = service_pid();
    tokio::time::sleep(STABLE_FOR).await;
    pid.is_some() && service_pid() == pid && listening(addr).await
}

pub async fn run(args: &[String], config: &Path) -> Result<()> {
    let cfg = Config::load(config)?;
    // Only for tests, and only root can run this. Real updates are HTTPS only.
    let from = args.windows(2).find(|w| w[0] == "--from").map(|w| w[1].clone());
    let base = from.as_deref().unwrap_or(RELEASE_BASE);
    let http = reqwest::Client::builder()
        .user_agent(concat!("emberd/", env!("CARGO_PKG_VERSION")))
        .https_only(from.is_none())
        .connect_timeout(Duration::from_secs(20))
        .read_timeout(Duration::from_secs(60))
        .build()?;

    let exe = std::env::current_exe().context("find this program")?;
    let text = http.get(format!("{base}/{ASSET}.sha256")).send().await.context("check for updates")?.error_for_status()?.text().await?;
    let wanted = parse_checksum(&text)?;
    if file_sha256(&exe)? == wanted {
        println!("Already on the latest version.");
        return Ok(());
    }
    let skip = skip_file(&cfg.data_dir);
    if std::fs::read_to_string(&skip).is_ok_and(|s| s.trim() == wanted) {
        println!("Skipping the latest release, because it failed to run on this machine.");
        return Ok(());
    }
    // Without Tailscale the new version couldn't be checked, and so couldn't be trusted.
    let me = auth::Tailscale::new(&cfg.tailscale_socket).status().await.context("Tailscale isn't reachable, so not updating")?;
    let ip = me.ipv4().ok_or_else(|| anyhow!("Tailscale has no address, so not updating"))?;
    let addr = std::net::SocketAddr::new(ip, cfg.port);

    let (new, previous) = (exe.with_extension("new"), exe.with_extension("previous"));
    install::download(&http, &format!("{base}/{ASSET}"), &new, install::Verify::Sha256(wanted.clone())).await?;
    std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
    if !runs_here(&new).await {
        let _ = std::fs::remove_file(&new);
        std::fs::write(&skip, &wanted)?;
        bail!("the new version can't run on this machine, so nothing changed");
    }
    std::fs::copy(&exe, &previous).context("keep the current version")?;
    // A rename is safe while the daemon runs, because it launches itself through /proc/self/exe.
    std::fs::rename(&new, &exe).context("install the new version")?;
    println!("Installed the new version.");

    if !systemctl_ok(&["is-active", "-q", SERVICE]) {
        println!("The daemon isn't running, so it will use the new version when it next starts.");
        return Ok(());
    }
    let old_pid = service_pid();
    std::fs::write(restart_marker(&cfg.data_dir), "").context("write restart marker")?;
    wait_for_restart(old_pid.as_deref()).await;
    if healthy(addr).await {
        let _ = std::fs::remove_file(&skip);
        println!("Updated, and the daemon is running.");
        return Ok(());
    }

    std::fs::rename(&previous, &exe).context("restore the previous version")?;
    std::fs::write(&skip, &wanted)?;
    let _ = std::fs::write(restart_marker(&cfg.data_dir), "");
    systemctl_ok(&["restart", SERVICE]);
    bail!("the new version didn't stay running, so the previous one is back in place")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_file_must_hold_a_real_checksum() {
        let sum = "A".repeat(64);
        assert_eq!(parse_checksum(&format!("{sum}  emberd-linux-x86_64\n")).unwrap(), "a".repeat(64));
        assert!(parse_checksum("").is_err());
        assert!(parse_checksum("<html>not found</html>").is_err());
        assert!(parse_checksum(&"g".repeat(64)).is_err());
    }
}
