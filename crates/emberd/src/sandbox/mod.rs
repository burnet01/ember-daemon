//! Docker-free isolation built from Linux kernel primitives.
//!
//! * `cgroup` - CPU, memory and process limits.
//! * `net` - a private network namespace per server with a default-deny firewall.
//! * `child` - the single-threaded helper that assembles the sandbox and execs the game.
//! * `seccomp` - the system call filter applied last.

pub mod cgroup;
pub mod child;
pub mod net;
pub mod seccomp;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SPEC_ENV: &str = "EMBER_SANDBOX_SPEC";
pub const INIT_ARG: &str = "__sandbox-init";

/// Where the server's files appear inside the sandbox.
pub const HOME: &str = "/home/container";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoBind {
    pub src: PathBuf,
    pub dst: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub hostname: String,
    pub uid: u32,
    pub gid: u32,
    pub data_dir: PathBuf,
    pub ro_binds: Vec<RoBind>,
    pub cgroup_dir: PathBuf,
    pub netns: Option<String>,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub tmp_mb: u64,
    pub file_size_limit: u64,
    pub dns: Vec<String>,
}
