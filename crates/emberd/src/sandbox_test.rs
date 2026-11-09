//! `emberd sandbox-test --probe <binary> [-- probe args]`
//!
//! Runs a program in a real sandbox built by the same code as a game server, with
//! its output inherited. CI uses it to run `ember-probe`'s escape attempts. It needs
//! root on the machine and is not reachable through the API.

use crate::files::Owner;
use crate::manager::build_spec;
use crate::sandbox::{cgroup, net, INIT_ARG, SPEC_ENV};
use anyhow::{Context, Result};
use ember_proto::{Limits, Protocol};
use std::os::unix::fs::{chown, DirBuilderExt, PermissionsExt};
use std::path::PathBuf;

const INDEX: u32 = 16_000;
const PORT: u16 = 39_876;
const UID: u32 = 299_000;

pub async fn run(args: &[String]) -> Result<i32> {
    let probe = args
        .windows(2)
        .find(|w| w[0] == "--probe")
        .map(|w| PathBuf::from(&w[1]))
        .context("usage: emberd sandbox-test --probe <binary> [-- probe args]")?;
    let probe_args: Vec<String> =
        args.iter().skip_while(|a| *a != "--").skip(1).cloned().collect();
    let pids = args.windows(2).find(|w| w[0] == "--pids").and_then(|w| w[1].parse().ok()).unwrap_or(128);
    let memory_mb = args.windows(2).find(|w| w[0] == "--memory-mb").and_then(|w| w[1].parse().ok()).unwrap_or(256);

    let base = std::env::temp_dir().join(format!("ember-sandbox-test-{}", std::process::id()));
    let data = base.join("data");
    std::fs::DirBuilder::new().recursive(true).mode(0o711).create(&base)?;
    std::fs::DirBuilder::new().mode(0o700).create(&data)?;
    chown(&data, Some(UID), Some(UID))?;
    let inside = data.join("probe");
    std::fs::copy(&probe, &inside).context("copy probe")?;
    std::fs::set_permissions(&inside, std::fs::Permissions::from_mode(0o755))?;
    chown(&inside, Some(UID), Some(UID))?;

    cgroup::prepare_root()?;
    net::init("tailscale0").await?;
    let key = "sandbox-test";
    let limits = Limits { memory_mb, cpu_percent: 200, disk_mb: 1024, pids };
    let cgroup_dir = cgroup::create(key, &limits)?;
    let netns = net::up(INDEX, PORT, Protocol::Tcp, true).await?;

    let cfg = crate::config::Config::parse(r#"owners = ["sandbox-test"]"#)?;
    let mut argv = vec![format!("{}/probe", crate::sandbox::HOME)];
    argv.extend(probe_args);
    let env = vec![("PATH".to_string(), "/usr/bin:/bin".to_string())];
    let owner = Owner { uid: UID, gid: UID };
    let spec = build_spec(&cfg, owner, data, cgroup_dir, netns, vec![], argv, env, limits.disk_mb);

    std::fs::create_dir_all("/run/ember")?;
    let status = tokio::process::Command::new("/proc/self/exe")
        .arg(INIT_ARG)
        .env_clear()
        .env(SPEC_ENV, serde_json::to_string(&spec)?)
        .stdin(std::process::Stdio::null())
        .status()
        .await;

    net::down(INDEX, PORT, Protocol::Tcp).await;
    cgroup::kill_and_remove(key);
    let _ = std::fs::remove_dir_all(&base);
    Ok(status?.code().unwrap_or(1))
}
