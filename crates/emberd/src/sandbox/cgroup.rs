//! cgroup v2 resource limits. Each server gets `/sys/fs/cgroup/ember/<key>`.

use anyhow::{bail, Context, Result};
use ember_proto::Limits;
use std::fs;
use std::path::{Path, PathBuf};

const CG_ROOT: &str = "/sys/fs/cgroup";
const PARENT: &str = "/sys/fs/cgroup/ember";
const CONTROLLERS: &str = "+cpu +memory +pids";

pub fn prepare_root() -> Result<()> {
    if !Path::new(CG_ROOT).join("cgroup.controllers").exists() {
        bail!("cgroup v2 is required but is not mounted at {CG_ROOT}");
    }
    fs::write(Path::new(CG_ROOT).join("cgroup.subtree_control"), CONTROLLERS)
        .context("enable controllers on the root cgroup")?;
    fs::create_dir_all(PARENT).context("create ember cgroup")?;
    fs::write(Path::new(PARENT).join("cgroup.subtree_control"), CONTROLLERS)
        .context("enable controllers on the ember cgroup")?;
    Ok(())
}

pub fn dir_for(key: &str) -> PathBuf {
    Path::new(PARENT).join(key)
}

pub fn create(key: &str, limits: &Limits) -> Result<PathBuf> {
    let dir = dir_for(key);
    if dir.exists() {
        kill_and_remove(key);
    }
    fs::create_dir(&dir).with_context(|| format!("create {}", dir.display()))?;
    let memory = limits.memory_mb * 1024 * 1024;
    let write = |file: &str, value: String| -> Result<()> {
        fs::write(dir.join(file), &value).with_context(|| format!("set {file}={value}"))
    };
    write("memory.max", memory.to_string())?;
    // Swap would let a server escape its memory limit at the cost of the whole node.
    // Absent when the kernel has swap accounting off, in which case there is nothing to cap.
    let _ = write("memory.swap.max", "0".into());
    // Out-of-memory kills the whole server at once, not a random thread inside it.
    write("memory.oom.group", "1".into())?;
    write("pids.max", limits.pids.to_string())?;
    // The period is 100ms, so 1% of a core is 1000us.
    write("cpu.max", format!("{} 100000", u64::from(limits.cpu_percent) * 1000))?;
    Ok(dir)
}

/// Atomically kills every process in the cgroup and removes it.
pub fn kill_and_remove(key: &str) {
    let dir = dir_for(key);
    if !dir.exists() {
        return;
    }
    let _ = fs::write(dir.join("cgroup.kill"), "1");
    for _ in 0..100 {
        if fs::remove_dir(&dir).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    tracing::warn!(cgroup = %dir.display(), "could not remove cgroup");
}

pub fn kill(key: &str) {
    let _ = fs::write(dir_for(key).join("cgroup.kill"), "1");
}

/// Removes anything left behind by a previous daemon run.
pub fn sweep_stale() {
    if let Ok(rd) = fs::read_dir(PARENT) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                tracing::warn!(cgroup = ?e.file_name(), "removing stale cgroup");
                kill_and_remove(&e.file_name().to_string_lossy());
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Usage {
    pub cpu_usec: u64,
    pub memory_bytes: u64,
    pub pids: u32,
}

pub fn read_usage(key: &str) -> Usage {
    let dir = dir_for(key);
    let read_u64 =
        |f: &str| -> u64 { fs::read_to_string(dir.join(f)).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0) };
    let cpu_usec = fs::read_to_string(dir.join("cpu.stat")).ok().and_then(|s| parse_usage_usec(&s)).unwrap_or(0);
    Usage { cpu_usec, memory_bytes: read_u64("memory.current"), pids: read_u64("pids.current") as u32 }
}

fn parse_usage_usec(stat: &str) -> Option<u64> {
    stat.lines().find_map(|l| l.strip_prefix("usage_usec ")).and_then(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::parse_usage_usec;

    #[test]
    fn parses_cpu_stat() {
        assert_eq!(parse_usage_usec("usage_usec 1234\nuser_usec 1000\nsystem_usec 234\n"), Some(1234));
        assert_eq!(parse_usage_usec("user_usec 1\n"), None);
    }
}
