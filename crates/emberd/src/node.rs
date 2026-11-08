//! Host information and the isolation self-check behind `emberd doctor`.

use ember_proto::{IsolationCheck, NodeStats};
use std::path::Path;
use std::process::Command;

pub fn read_cpu_times() -> Option<(u64, u64)> {
    parse_cpu_times(&std::fs::read_to_string("/proc/stat").ok()?)
}

fn parse_cpu_times(stat: &str) -> Option<(u64, u64)> {
    let f: Vec<u64> = stat.lines().next()?.split_whitespace().skip(1).filter_map(|v| v.parse().ok()).collect();
    if f.len() < 5 {
        return None;
    }
    // Only user through steal: guest time is already included in user.
    let total = f.iter().take(8).sum();
    Some((total, f[3] + f[4]))
}

fn parse_meminfo(text: &str) -> (u64, u64) {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            .unwrap_or(0)
            * 1024
    };
    let total = get("MemTotal:");
    (total.saturating_sub(get("MemAvailable:")), total)
}

fn statvfs(path: &Path) -> (u64, u64) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return (0, 0) };
    // SAFETY: all-zero is a valid statvfs, and the pointers are valid for the call.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return (0, 0);
    }
    let frag = s.f_frsize;
    let total = s.f_blocks * frag;
    (total.saturating_sub(s.f_bavail * frag), total)
}

pub fn stats(data_dir: &Path, cpu_percent: f32, total: u32, running: u32) -> NodeStats {
    let (memory_used, memory_total) = std::fs::read_to_string("/proc/meminfo").map_or((0, 0), |t| parse_meminfo(&t));
    let (disk_used, disk_total) = statvfs(data_dir);
    let first = |p: &str| -> f64 {
        std::fs::read_to_string(p).ok().and_then(|s| s.split_whitespace().next()?.parse().ok()).unwrap_or(0.0)
    };
    NodeStats {
        cpu_percent,
        memory_used,
        memory_total,
        disk_used,
        disk_total,
        load1: first("/proc/loadavg") as f32,
        uptime_secs: first("/proc/uptime") as u64,
        servers_total: total,
        servers_running: running,
    }
}

pub fn hostname() -> String {
    read_trim("/proc/sys/kernel/hostname").unwrap_or_else(|| "unknown".into())
}

pub fn kernel() -> String {
    read_trim("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into())
}

pub fn os_name() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| t.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string())))
        .unwrap_or_else(|| "Linux".into())
}

pub fn cpu_count() -> u32 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u32)
}

fn read_trim(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn check(name: &str, ok: bool, detail: impl Into<String>) -> IsolationCheck {
    IsolationCheck { name: name.into(), ok, detail: detail.into() }
}

fn has_binary(bin: &str) -> bool {
    Command::new(bin).arg("--version").output().is_ok_and(|o| o.status.success())
        || Command::new(bin).arg("-V").output().is_ok_and(|o| o.status.success())
}

pub fn isolation_checks() -> Vec<IsolationCheck> {
    let controllers = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").unwrap_or_default();
    let has_ctrl = |c: &str| controllers.split_whitespace().any(|x| x == c);
    let cg_ok = has_ctrl("cpu") && has_ctrl("memory") && has_ctrl("pids");
    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let seccomp = Path::new("/proc/sys/kernel/seccomp/actions_avail").exists();
    let forward = read_trim("/proc/sys/net/ipv4/ip_forward").as_deref() == Some("1");
    // SAFETY: takes no arguments and cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    vec![
        check("root", root, if root { "Running as root to build sandboxes" } else { "emberd must run as root" }),
        check("cgroups", cg_ok, if cg_ok { "cgroup v2 with cpu, memory and pids" } else { "cgroup v2 with cpu, memory and pids is required" }),
        check("seccomp", seccomp, if seccomp { "System call filtering available" } else { "Kernel lacks seccomp filters" }),
        check(
            "landlock",
            lsm.split(',').any(|l| l == "landlock"),
            if lsm.contains("landlock") {
                "Second filesystem layer active"
            } else {
                "Not enabled. Add lsm=landlock to the kernel command line for a second filesystem layer"
            },
        ),
        check("nftables", has_binary("nft"), "Required for the sandbox firewall"),
        check("iproute2", has_binary("ip"), "Required for sandbox networking"),
        check("forwarding", forward, if forward { "IPv4 forwarding is on" } else { "Turned on when emberd starts" }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_files() {
        let (total, idle) = parse_cpu_times("cpu  10 0 10 70 10 0 0 0 5 0\ncpu0 1 1 1 1").unwrap();
        assert_eq!((total, idle), (100, 80));
        assert!(parse_cpu_times("cpu 1 2").is_none());
        assert_eq!(
            parse_meminfo("MemTotal:  1000 kB\nMemFree: 10 kB\nMemAvailable:  400 kB\n"),
            (600 * 1024, 1000 * 1024)
        );
    }
}
