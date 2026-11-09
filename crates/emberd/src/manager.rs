//! Owns every server: persistence, lifecycle, console output, stats, disk
//! enforcement and schedules.

use crate::config::Config;
use crate::error::{bad_request, conflict, not_found, ApiErr, ApiResult};
use crate::files::{self, Owner};
use crate::sandbox::{cgroup, net, RoBind, SandboxSpec, HOME, INIT_ARG, SPEC_ENV};
use crate::{backup, install};
use anyhow::{anyhow, bail, Context, Result};
use ember_proto::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::{chown, DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{broadcast, mpsc, watch};
use uuid::Uuid;

const BACKLOG_LINES: usize = 2000;
const MAX_LINE_BYTES: usize = 8 * 1024;
const UID_BASE: u32 = 200_000;
const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DISK_SCAN_EVERY: Duration = Duration::from_secs(30);
const CPU_SAMPLE_WINDOW: Duration = Duration::from_secs(1);
const SCHEDULE_TICK: Duration = Duration::from_secs(5);
const MAX_CRASH_RESTARTS: usize = 5;
const CRASH_WINDOW: Duration = Duration::from_secs(600);

type EnvVars = Vec<(String, String)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StartSpec {
    Jar { path: String },
    ArgsFile { path: String },
    Native { binary: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRecord {
    pub id: Uuid,
    pub name: String,
    pub flavor: Flavor,
    pub version: String,
    pub bedrock_url: Option<String>,
    pub limits: Limits,
    pub port: u16,
    pub index: u32,
    pub autostart: bool,
    pub restart_on_crash: bool,
    #[serde(default)]
    pub startup: StartupOptions,
    pub java_major: Option<u32>,
    pub created_at: u64,
    pub start: Option<StartSpec>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub schedules: Vec<Schedule>,
}

pub struct Instance {
    pub id: Uuid,
    rec: Mutex<ServerRecord>,
    path: PathBuf,
    state: watch::Sender<ServerState>,
    lines: broadcast::Sender<String>,
    backlog: Mutex<VecDeque<String>>,
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    power: tokio::sync::Mutex<()>,
    started: Mutex<Option<Instant>>,
    disk_bytes: AtomicU64,
    cpu_sample: Mutex<Option<(Instant, u64, f32)>>,
    expected_exit: AtomicBool,
    crashes: Mutex<Vec<Instant>>,
    backup: Mutex<Option<(String, Arc<backup::Progress>)>>,
    restoring: AtomicBool,
    extracting: AtomicBool,
}

/// The first port from `start` up that `usable` accepts.
fn first_free_port(start: u16, usable: impl Fn(u16) -> bool) -> Option<u16> {
    (start..=u16::MAX).find(|&port| usable(port))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Keeps SGR colors, which the console renders, and strips other escapes and
/// control characters so a hostile server cannot drive the operator's UI.
pub fn sanitize_line(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() != Some(&'[') {
                chars.next();
                continue;
            }
            chars.next();
            let mut seq = String::new();
            let mut last = None;
            for n in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&n) {
                    last = Some(n);
                    break;
                }
                seq.push(n);
                if seq.len() > 32 {
                    break;
                }
            }
            if last == Some('m') && seq.chars().all(|d| d.is_ascii_digit() || d == ';') {
                out.push('\u{1b}');
                out.push('[');
                out.push_str(&seq);
                out.push('m');
            }
        } else if c == '\t' || !c.is_control() {
            out.push(c);
        }
    }
    out
}

impl Instance {
    fn new(rec: ServerRecord, path: PathBuf, state: ServerState) -> Arc<Self> {
        Arc::new(Self {
            id: rec.id,
            rec: Mutex::new(rec),
            path,
            state: watch::channel(state).0,
            lines: broadcast::channel(1024).0,
            backlog: Mutex::new(VecDeque::with_capacity(BACKLOG_LINES)),
            stdin: tokio::sync::Mutex::new(None),
            power: tokio::sync::Mutex::new(()),
            started: Mutex::new(None),
            disk_bytes: AtomicU64::new(0),
            cpu_sample: Mutex::new(None),
            expected_exit: AtomicBool::new(false),
            crashes: Mutex::new(Vec::new()),
            backup: Mutex::new(None),
            restoring: AtomicBool::new(false),
            extracting: AtomicBool::new(false),
        })
    }

    pub fn record(&self) -> ServerRecord {
        self.rec.lock().expect("record lock").clone()
    }

    pub fn state(&self) -> ServerState {
        *self.state.borrow()
    }

    pub fn watch_state(&self) -> watch::Receiver<ServerState> {
        self.state.subscribe()
    }

    pub fn subscribe_lines(&self) -> broadcast::Receiver<String> {
        self.lines.subscribe()
    }

    pub fn backlog(&self) -> Vec<String> {
        self.backlog.lock().expect("backlog lock").iter().cloned().collect()
    }

    pub fn owner(&self) -> Owner {
        let index = self.rec.lock().expect("record lock").index;
        Owner { uid: UID_BASE + index, gid: UID_BASE + index }
    }

    /// Applies a change and persists it.
    pub fn update(&self, f: impl FnOnce(&mut ServerRecord)) {
        let snapshot = {
            let mut r = self.rec.lock().expect("record lock");
            f(&mut r);
            r.clone()
        };
        if let Err(e) = save_record(&self.path, &snapshot) {
            tracing::error!(server = %self.id, "could not save server record: {e:#}");
        }
    }

    fn set_state(&self, s: ServerState) {
        self.state.send_replace(s);
    }

    pub fn log(&self, text: &str) {
        let text = sanitize_line(text.as_bytes());
        {
            let mut b = self.backlog.lock().expect("backlog lock");
            if b.len() >= BACKLOG_LINES {
                b.pop_front();
            }
            b.push_back(text.clone());
        }
        let _ = self.lines.send(text);
    }

    pub fn info(&self) -> ServerInfo {
        let r = self.record();
        ServerInfo {
            id: r.id,
            name: r.name,
            flavor: r.flavor,
            version: r.version,
            limits: r.limits,
            port: r.port,
            protocol: r.flavor.protocol(),
            state: self.state(),
            autostart: r.autostart,
            restart_on_crash: r.restart_on_crash,
            java_major: r.java_major,
            created_at: r.created_at,
            last_error: r.last_error,
        }
    }

    pub fn backup_progress(&self) -> Option<BackupProgress> {
        let slot = self.backup.lock().expect("backup lock");
        slot.as_ref().map(|(name, p)| {
            let total = p.total.load(Ordering::Relaxed);
            BackupProgress {
                name: name.clone(),
                // A file growing during the backup must not read as more than 100%.
                done_bytes: p.done.load(Ordering::Relaxed).min(total),
                total_bytes: total,
            }
        })
    }

    pub fn disk_used(&self) -> u64 {
        self.disk_bytes.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> ServerStats {
        let limits = self.record().limits;
        let key = self.id.to_string();
        let active = matches!(self.state(), ServerState::Starting | ServerState::Running | ServerState::Stopping);
        let usage = if active { cgroup::read_usage(&key) } else { cgroup::Usage::default() };
        let now = Instant::now();
        // Several readers share this sample, so it only advances about once a second.
        // Otherwise each reader measures a different, possibly tiny, slice of time.
        let cpu_percent = {
            let mut sample = self.cpu_sample.lock().expect("cpu lock");
            match *sample {
                Some((t, _, pct)) if active && now.duration_since(t) < CPU_SAMPLE_WINDOW => pct,
                Some((t, prev, _)) if active && usage.cpu_usec >= prev => {
                    let dt = now.duration_since(t).as_secs_f64();
                    let pct = ((usage.cpu_usec - prev) as f64 / 1e6 / dt * 100.0) as f32;
                    *sample = Some((now, usage.cpu_usec, pct));
                    pct
                }
                _ => {
                    *sample = active.then_some((now, usage.cpu_usec, 0.0));
                    0.0
                }
            }
        };
        ServerStats {
            cpu_percent,
            memory_bytes: usage.memory_bytes,
            memory_limit_bytes: limits.memory_mb * 1024 * 1024,
            disk_bytes: self.disk_bytes.load(Ordering::Relaxed),
            disk_limit_bytes: limits.disk_mb * 1024 * 1024,
            pids: usage.pids,
            uptime_secs: self.started.lock().expect("started lock").map_or(0, |t| t.elapsed().as_secs()),
        }
    }

    pub async fn send_stdin(&self, line: &str) -> Result<()> {
        let mut guard = self.stdin.lock().await;
        let stdin = guard.as_mut().ok_or_else(|| anyhow!("server is not running"))?;
        stdin.write_all(line.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }
}

fn save_record(path: &Path, rec: &ServerRecord) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(rec)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub struct Manager {
    pub cfg: Config,
    pub http: reqwest::Client,
    pub java_lock: tokio::sync::Mutex<()>,
    servers: RwLock<HashMap<Uuid, Arc<Instance>>>,
    index_lock: Mutex<()>,
    cpu_prev: Mutex<Option<(u64, u64)>>,
    restart_tx: mpsc::UnboundedSender<Arc<Instance>>,
    restart_rx: Mutex<Option<mpsc::UnboundedReceiver<Arc<Instance>>>>,
    creating: Mutex<()>,
    restart_wanted: tokio::sync::Notify,
    pub archive_tool_lock: tokio::sync::Mutex<()>,
    restarting: AtomicBool,
}

impl Manager {
    pub fn load(cfg: Config) -> Result<Arc<Self>> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("ember-panel/", env!("CARGO_PKG_VERSION")))
            .https_only(true)
            .connect_timeout(Duration::from_secs(20))
            .build()?;
        let (restart_tx, restart_rx) = mpsc::unbounded_channel();
        let mgr = Arc::new(Self {
            restart_tx,
            restart_rx: Mutex::new(Some(restart_rx)),
            creating: Mutex::new(()),
            restart_wanted: tokio::sync::Notify::new(),
            archive_tool_lock: tokio::sync::Mutex::new(()),
            restarting: AtomicBool::new(false),
            cfg,
            http,
            java_lock: tokio::sync::Mutex::new(()),
            servers: RwLock::new(HashMap::new()),
            index_lock: Mutex::new(()),
            cpu_prev: Mutex::new(None),
        });
        std::fs::DirBuilder::new().recursive(true).mode(0o711).create(&mgr.cfg.data_dir)?;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(mgr.servers_dir())?;
        std::fs::DirBuilder::new().recursive(true).mode(0o755).create(mgr.runtimes_dir())?;
        // A request from before this start has been answered by this start.
        let _ = std::fs::remove_file(crate::update::restart_marker(&mgr.cfg.data_dir));
        for e in std::fs::read_dir(mgr.servers_dir())? {
            let path = e?.path().join("server.json");
            if !path.exists() {
                continue;
            }
            let rec: ServerRecord = serde_json::from_slice(&std::fs::read(&path)?)
                .with_context(|| format!("read {}", path.display()))?;
            // No server survives a daemon restart, and an unfinished install has no start spec.
            let state = if rec.start.is_some() { ServerState::Offline } else { ServerState::InstallFailed };
            let inst = Instance::new(rec, path, state);
            mgr.servers.write().expect("servers lock").insert(inst.id, inst);
        }
        Ok(mgr)
    }

    fn resume_file(&self) -> PathBuf {
        self.cfg.data_dir.join("resume.json")
    }

    /// Whether anything is under way that a restart would ruin.
    fn is_busy(&self) -> bool {
        self.all().iter().any(|i| {
            matches!(i.state(), ServerState::Installing | ServerState::Stopping)
                || i.restoring.load(Ordering::SeqCst)
                || i.extracting.load(Ordering::SeqCst)
                || i.backup.lock().expect("backup lock").is_some()
        })
    }

    pub async fn restart_wanted(&self) {
        self.restart_wanted.notified().await;
    }

    pub fn restarting(&self) -> bool {
        self.restarting.load(Ordering::SeqCst)
    }

    fn servers_dir(&self) -> PathBuf {
        self.cfg.data_dir.join("servers")
    }
    pub fn runtimes_dir(&self) -> PathBuf {
        self.cfg.data_dir.join("runtimes")
    }
    pub fn server_dir(&self, id: Uuid) -> PathBuf {
        self.servers_dir().join(id.to_string())
    }
    pub fn data_dir(&self, id: Uuid) -> PathBuf {
        self.server_dir(id).join("data")
    }
    fn backups_dir(&self, id: Uuid) -> PathBuf {
        self.server_dir(id).join("backups")
    }

    pub fn get(&self, id: Uuid) -> ApiResult<Arc<Instance>> {
        self.servers.read().expect("servers lock").get(&id).cloned().ok_or_else(|| not_found("server not found"))
    }

    pub fn find_by_sftp_user(&self, user: &str) -> Option<Arc<Instance>> {
        self.all().into_iter().find(|s| sftp_user(s.id).eq_ignore_ascii_case(user))
    }

    pub fn all(&self) -> Vec<Arc<Instance>> {
        self.servers.read().expect("servers lock").values().cloned().collect()
    }

    /// Indexes are never reused, so an old file can never belong to a new server's uid.
    fn allocate_index(&self) -> Result<u32> {
        let _g = self.index_lock.lock().expect("index lock");
        let path = self.cfg.data_dir.join("next_index");
        let next: u32 = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(1);
        if next > net::MAX_INDEX {
            bail!("this node has used all of its server slots");
        }
        std::fs::write(&path, (next + 1).to_string())?;
        Ok(next)
    }

    fn port_taken(&self, port: u16, proto: Protocol) -> bool {
        self.all().iter().any(|s| {
            let r = s.record();
            r.port == port && r.flavor.protocol() == proto
        })
    }

    /// Memory limits added up across this node's servers, leaving out `except`.
    pub fn memory_allocated_mb(&self, except: Option<Uuid>) -> u64 {
        self.all().iter().filter(|s| Some(s.id) != except).map(|s| s.record().limits.memory_mb).sum()
    }

    fn port_reserved(&self, port: u16) -> bool {
        port < 1024 || port == self.cfg.port || port == SFTP_PORT
    }

    /// Takes `wanted`, or the next free port above it if something already has it.
    /// DNAT would silently shadow anything bound on the host, including tailscaled's UDP port.
    fn pick_port(&self, wanted: u16, proto: Protocol) -> ApiResult<u16> {
        if self.port_reserved(wanted) {
            return Err(bad_request(format!("port {wanted} is reserved")));
        }
        first_free_port(wanted, |port| {
            !self.port_reserved(port)
                && !self.port_taken(port, proto)
                && match proto {
                    Protocol::Tcp => std::net::TcpListener::bind(("0.0.0.0", port)).is_ok(),
                    Protocol::Udp => std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok(),
                }
        })
        .ok_or_else(|| conflict(format!("no free port from {wanted} up")))
    }

    pub async fn create(self: &Arc<Self>, req: CreateServer) -> ApiResult<ServerInfo> {
        // Two creates at once must not pick the same port. Nothing below awaits.
        let _creating = self.creating.lock().expect("create lock");
        validate_name(&req.name).map_err(bad_request)?;
        req.limits.validate().map_err(bad_request)?;
        let cap = crate::node::capacity(&self.cfg.data_dir);
        crate::node::check_limits(&req.limits, &cap, cap.disk_free_mb).map_err(bad_request)?;
        crate::node::check_memory(req.limits.memory_mb, self.memory_allocated_mb(None), cap.memory_mb, req.allow_overallocate).map_err(bad_request)?;
        if !req.eula_accepted {
            return Err(bad_request("you must accept the Minecraft EULA to create a server"));
        }
        let version = if req.flavor == Flavor::Bedrock {
            let url = req.bedrock_url.as_deref().ok_or_else(|| bad_request("Bedrock needs a download link"))?;
            install::validate_bedrock_url(url).map_err(|e| bad_request(e.to_string()))?
        } else {
            install::validate_version(&req.version).map_err(|e| bad_request(e.to_string()))?;
            req.version.clone()
        };
        let port = self.pick_port(req.port, req.flavor.protocol())?;

        let index = self.allocate_index()?;
        let id = Uuid::new_v4();
        let rec = ServerRecord {
            id,
            name: req.name.trim().to_string(),
            flavor: req.flavor,
            version,
            bedrock_url: req.bedrock_url,
            limits: req.limits,
            port,
            index,
            autostart: false,
            restart_on_crash: false,
            startup: StartupOptions {
                server_args: if req.flavor == Flavor::Bedrock { vec![] } else { vec!["nogui".to_string()] },
                ..Default::default()
            },
            java_major: None,
            created_at: now_secs(),
            start: None,
            last_error: None,
            schedules: Vec::new(),
        };
        let dir = self.server_dir(id);
        let path = dir.join("server.json");
        let build = || -> Result<()> {
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
            std::fs::DirBuilder::new().mode(0o700).create(dir.join("backups"))?;
            std::fs::DirBuilder::new().mode(0o700).create(dir.join("data"))?;
            chown(dir.join("data"), Some(UID_BASE + index), Some(UID_BASE + index))?;
            save_record(&path, &rec)
        };
        build().context("create server directory")?;

        let inst = Instance::new(rec, path, ServerState::Installing);
        self.servers.write().expect("servers lock").insert(id, inst.clone());
        self.spawn_install(inst.clone(), req.start_after_install);
        Ok(inst.info())
    }

    fn spawn_install(self: &Arc<Self>, inst: Arc<Instance>, start_after: bool) {
        let mgr = self.clone();
        tokio::spawn(async move {
            let _power = inst.power.lock().await;
            inst.set_state(ServerState::Installing);
            inst.update(|r| r.last_error = None);
            match install::run(&mgr, &inst).await {
                Ok(()) => {
                    inst.log("[ember] Install complete. The server is ready to start.");
                    inst.set_state(ServerState::Offline);
                    if start_after {
                        let _ = mgr.restart_tx.send(inst.clone());
                    }
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    tracing::error!(server = %inst.id, "install failed: {msg}");
                    inst.log(&format!("[ember] Install failed: {msg}"));
                    inst.update(|r| r.last_error = Some(msg));
                    inst.set_state(ServerState::InstallFailed);
                }
            }
        });
    }

    pub async fn reinstall(self: &Arc<Self>, inst: Arc<Instance>) -> ApiResult<()> {
        if inst.extracting.load(Ordering::SeqCst) {
            return Err(conflict("wait for the archive to finish extracting"));
        }
        match inst.state() {
            ServerState::Offline | ServerState::Crashed | ServerState::InstallFailed => {
                self.spawn_install(inst, false);
                Ok(())
            }
            _ => Err(conflict("stop the server before reinstalling it")),
        }
    }

    fn sandbox_spec(&self, inst: &Instance, argv: Vec<String>, env: Vec<(String, String)>, netns: String) -> SandboxSpec {
        let rec = inst.record();
        let owner = inst.owner();
        let mut ro_binds = Vec::new();
        if let Some(major) = rec.startup.java_major.or(rec.java_major) {
            ro_binds.push(RoBind { src: self.runtimes_dir().join(format!("java-{major}")), dst: "/opt/java".into() });
        }
        build_spec(&self.cfg, owner, self.data_dir(inst.id), cgroup::dir_for(&inst.id.to_string()), netns, ro_binds, argv, env, rec.limits.disk_mb)
    }

    async fn spawn_sandboxed(&self, inst: &Instance, argv: Vec<String>, env: Vec<(String, String)>) -> Result<Child> {
        let rec = inst.record();
        let key = inst.id.to_string();
        let limits = rec.limits;
        tokio::task::spawn_blocking({
            let key = key.clone();
            move || cgroup::create(&key, &limits)
        })
        .await??;
        let proto = rec.flavor.protocol();
        let netns = match net::up(rec.index, rec.port, proto).await {
            Ok(ns) => ns,
            Err(e) => {
                cgroup::kill_and_remove(&key);
                return Err(e);
            }
        };
        let spec = self.sandbox_spec(inst, argv, env, netns);
        let spawned = spawn_helper(&spec);
        if spawned.is_err() {
            self.teardown(inst).await;
        }
        spawned
    }

    async fn teardown(&self, inst: &Instance) {
        let rec = inst.record();
        net::down(rec.index, rec.port, rec.flavor.protocol()).await;
        let key = inst.id.to_string();
        let _ = tokio::task::spawn_blocking(move || cgroup::kill_and_remove(&key)).await;
    }

    /// Runs a one-shot command such as an installer in the server's sandbox.
    pub async fn run_once(&self, inst: &Arc<Instance>, argv: Vec<String>) -> Result<()> {
        let mut child = self.spawn_sandboxed(inst, argv, base_env()).await?;
        drop(child.stdin.take());
        let readers = start_pumps(&mut child, inst, false);
        let waited = tokio::time::timeout(INSTALL_TIMEOUT, child.wait()).await;
        if waited.is_err() {
            cgroup::kill(&inst.id.to_string());
        }
        let status = match waited {
            Ok(s) => s.map(Some),
            Err(_) => child.wait().await.map(|_| None),
        };
        finish_pumps(readers).await;
        self.teardown(inst).await;
        match status? {
            Some(s) if s.success() => Ok(()),
            Some(s) => bail!("exited with {s}"),
            None => bail!("timed out"),
        }
    }

    pub async fn start(self: &Arc<Self>, inst: Arc<Instance>) -> ApiResult<()> {
        let _power = inst.power.lock().await;
        self.start_locked(&inst).await
    }

    async fn start_locked(self: &Arc<Self>, inst: &Arc<Instance>) -> ApiResult<()> {
        match inst.state() {
            ServerState::Offline | ServerState::Crashed => {}
            ServerState::Starting | ServerState::Running => return Ok(()),
            ServerState::InstallFailed => return Err(conflict("the install failed; reinstall the server first")),
            ServerState::Installing | ServerState::Stopping => return Err(conflict("the server is busy")),
        }
        let rec = inst.record();
        let scanned = self.scan_disk(inst).await;
        if scanned > rec.limits.disk_mb * 1024 * 1024 {
            return Err(conflict("the server is over its disk limit; free space or raise the limit"));
        }
        let (argv, env) = build_command(&rec)?;
        if let Some(major) = rec.startup.java_major.or(rec.java_major).filter(|_| rec.flavor != Flavor::Bedrock) {
            install::ensure_java(self, major).await.context("prepare Java")?;
        }

        let data = self.data_dir(inst.id);
        let owner = inst.owner();
        let port = rec.port;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let root = files::open_root(&data)?;
            files::enforce_property(&root, "server-port", &port.to_string(), owner)?;
            files::enforce_property(&root, "server-ip", "", owner)
        })
        .await
        .map_err(anyhow::Error::from)??;

        inst.expected_exit.store(false, Ordering::SeqCst);
        inst.update(|r| r.last_error = None);
        inst.set_state(ServerState::Starting);
        inst.log("[ember] Starting server");
        let mut child = match self.spawn_sandboxed(inst, argv, env).await {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("{e:#}");
                inst.log(&format!("[ember] Could not start: {msg}"));
                inst.update(|r| r.last_error = Some(msg));
                inst.set_state(ServerState::Crashed);
                return Err(e.into());
            }
        };
        *inst.stdin.lock().await = child.stdin.take();
        *inst.started.lock().expect("started lock") = Some(Instant::now());
        let readers = start_pumps(&mut child, inst, true);
        let (mgr, inst2) = (self.clone(), inst.clone());
        tokio::spawn(async move { mgr.monitor(inst2, child, readers).await });
        Ok(())
    }

    async fn monitor(self: Arc<Self>, inst: Arc<Instance>, mut child: Child, readers: Pumps) {
        let status = child.wait().await;
        finish_pumps(readers).await;
        *inst.stdin.lock().await = None;
        *inst.started.lock().expect("started lock") = None;
        self.teardown(&inst).await;

        let expected = inst.expected_exit.load(Ordering::SeqCst);
        let clean = status.as_ref().is_ok_and(std::process::ExitStatus::success);
        if expected || clean {
            inst.log("[ember] Server stopped");
            inst.set_state(ServerState::Offline);
            return;
        }
        let msg = match &status {
            Ok(s) => format!("the server exited unexpectedly ({s})"),
            Err(e) => format!("could not read server status: {e}"),
        };
        inst.log(&format!("[ember] {msg}"));
        inst.update(|r| r.last_error = Some(msg));
        inst.set_state(ServerState::Crashed);

        if inst.record().restart_on_crash {
            let allowed = {
                let mut c = inst.crashes.lock().expect("crash lock");
                c.retain(|t| t.elapsed() < CRASH_WINDOW);
                c.push(Instant::now());
                c.len() <= MAX_CRASH_RESTARTS
            };
            if !allowed {
                inst.log("[ember] Too many crashes in a short time. Automatic restart is paused.");
                return;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            if inst.state() == ServerState::Crashed {
                inst.log("[ember] Restarting after crash");
                // Queued rather than awaited: starting a server spawns this monitor, so
                // calling start here would make the two futures depend on each other.
                let _ = self.restart_tx.send(inst.clone());
            }
        }
    }

    pub async fn stop(&self, inst: Arc<Instance>) -> ApiResult<()> {
        let _power = inst.power.lock().await;
        self.stop_locked(&inst).await
    }

    async fn stop_locked(&self, inst: &Instance) -> ApiResult<()> {
        match inst.state() {
            ServerState::Offline | ServerState::Crashed | ServerState::InstallFailed => return Ok(()),
            ServerState::Installing => return Err(conflict("the server is installing")),
            _ => {}
        }
        inst.expected_exit.store(true, Ordering::SeqCst);
        inst.set_state(ServerState::Stopping);
        inst.log("[ember] Stopping server");
        let _ = inst.send_stdin("stop").await;
        let timeout = Duration::from_secs(self.cfg.stop_timeout_secs);
        if !wait_until_stopped(inst, timeout).await {
            inst.log("[ember] The server did not stop in time. Killing it.");
            cgroup::kill(&inst.id.to_string());
            if !wait_until_stopped(inst, Duration::from_secs(15)).await {
                return Err(anyhow!("the server could not be stopped").into());
            }
        }
        Ok(())
    }

    pub async fn kill(&self, inst: Arc<Instance>) -> ApiResult<()> {
        if !matches!(inst.state(), ServerState::Starting | ServerState::Running | ServerState::Stopping) {
            return Ok(());
        }
        inst.expected_exit.store(true, Ordering::SeqCst);
        inst.log("[ember] Killing server");
        cgroup::kill(&inst.id.to_string());
        Ok(())
    }

    pub async fn restart(self: &Arc<Self>, inst: Arc<Instance>) -> ApiResult<()> {
        let _power = inst.power.lock().await;
        self.stop_locked(&inst).await?;
        self.start_locked(&inst).await
    }

    pub async fn delete(&self, inst: Arc<Instance>) -> ApiResult<()> {
        let _power = inst.power.lock().await;
        if inst.state() == ServerState::Installing {
            return Err(conflict("wait for the install to finish"));
        }
        if inst.extracting.load(Ordering::SeqCst) {
            return Err(conflict("wait for the archive to finish extracting"));
        }
        self.stop_locked(&inst).await?;
        self.servers.write().expect("servers lock").remove(&inst.id);
        let dir = self.server_dir(inst.id);
        // std's remove_dir_all does not follow symlinks.
        tokio::task::spawn_blocking(move || std::fs::remove_dir_all(dir)).await.map_err(anyhow::Error::from)?.map_err(anyhow::Error::from)?;
        Ok(())
    }

    pub async fn update_settings(&self, inst: &Instance, req: UpdateServer) -> ApiResult<()> {
        // Shared with create, so two changes at once can't both claim the same free memory.
        let _creating = self.creating.lock().expect("create lock");
        if let Some(n) = &req.name {
            validate_name(n).map_err(bad_request)?;
        }
        if let Some(l) = &req.limits {
            l.validate().map_err(bad_request)?;
            let cap = crate::node::capacity(&self.cfg.data_dir);
            crate::node::check_limits(l, &cap, cap.disk_total_mb).map_err(bad_request)?;
            // Only an increase is checked, so an overbooked server can still change other settings.
            if l.memory_mb > inst.record().limits.memory_mb {
                crate::node::check_memory(l.memory_mb, self.memory_allocated_mb(Some(inst.id)), cap.memory_mb, req.allow_overallocate).map_err(bad_request)?;
            }
        }
        inst.update(|r| {
            if let Some(n) = req.name {
                r.name = n.trim().to_string();
            }
            if let Some(l) = req.limits {
                r.limits = l;
            }
            if let Some(a) = req.autostart {
                r.autostart = a;
            }
            if let Some(c) = req.restart_on_crash {
                r.restart_on_crash = c;
            }
        });
        Ok(())
    }

    pub fn startup_info(&self, inst: &Instance) -> StartupInfo {
        let rec = inst.record();
        let command = match build_command(&rec) {
            Ok((argv, _)) => display_command(&rec.startup.env, &argv),
            Err(e) => e.to_string(),
        };
        StartupInfo {
            options: rec.startup.clone(),
            command,
            auto_command: rec.start.as_ref().map_or_else(String::new, |start| {
                let mut argv = auto_argv(&rec, start);
                if argv[0] == "/opt/java/bin/java" {
                    argv[0] = "java".into();
                }
                display_command(&[], &argv)
            }),
            is_java: rec.flavor != Flavor::Bedrock,
            version: rec.version.clone(),
            default_java: rec.java_major,
            java_versions: JAVA_VERSIONS.to_vec(),
            default_max_heap_mb: heap_mb(rec.limits.memory_mb),
        }
    }

    pub async fn update_startup(self: &Arc<Self>, inst: Arc<Instance>, req: UpdateStartup) -> ApiResult<()> {
        let rec = inst.record();
        validate_startup(&req.options, rec.limits.memory_mb).map_err(bad_request)?;
        let new_version = match req.version.filter(|v| *v != rec.version) {
            Some(_) if rec.flavor == Flavor::Bedrock => {
                return Err(bad_request("change a Bedrock version by reinstalling with a new download link"));
            }
            Some(v) => {
                install::validate_version(&v).map_err(|e| bad_request(e.to_string()))?;
                if !matches!(inst.state(), ServerState::Offline | ServerState::Crashed | ServerState::InstallFailed) {
                    return Err(conflict("stop the server before changing its version"));
                }
                Some(v)
            }
            None => None,
        };
        let reinstall = new_version.is_some();
        inst.update(|r| {
            r.startup = req.options;
            if let Some(v) = new_version {
                r.version = v;
            }
        });
        if reinstall {
            self.reinstall(inst).await?;
        }
        Ok(())
    }

    // ---- Disk usage ----

    async fn scan_disk(&self, inst: &Instance) -> u64 {
        let data = self.data_dir(inst.id);
        let bytes = tokio::task::spawn_blocking(move || disk_usage(&data)).await.unwrap_or(0);
        inst.disk_bytes.store(bytes, Ordering::Relaxed);
        bytes
    }

    // ---- Backups ----

    pub fn list_backups(&self, id: Uuid) -> Result<Vec<BackupInfo>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(self.backups_dir(id))? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "json") {
                if let Ok(b) = std::fs::read(&p).map_err(anyhow::Error::from).and_then(|d| Ok(serde_json::from_slice(&d)?)) {
                    out.push(b);
                }
            }
        }
        out.sort_by_key(|b: &BackupInfo| std::cmp::Reverse(b.created_at));
        Ok(out)
    }

    pub async fn create_backup(&self, inst: &Instance, name: &str) -> ApiResult<BackupInfo> {
        validate_name(name).map_err(bad_request)?;
        let progress = Arc::new(backup::Progress::default());
        {
            let mut slot = inst.backup.lock().expect("backup lock");
            if slot.is_some() {
                return Err(conflict("a backup of this server is already running"));
            }
            *slot = Some((name.trim().to_string(), progress.clone()));
        }
        // Checked after claiming the slot, and restores check the slot after setting this,
        // so a backup and a restore starting together always see each other.
        let result = if inst.restoring.load(Ordering::SeqCst) {
            Err(conflict("a backup is being restored on this server"))
        } else {
            self.run_backup(inst, name, progress).await
        };
        *inst.backup.lock().expect("backup lock") = None;
        result
    }

    async fn run_backup(&self, inst: &Instance, name: &str, progress: Arc<backup::Progress>) -> ApiResult<BackupInfo> {
        if matches!(inst.state(), ServerState::Running) && inst.record().flavor != Flavor::Bedrock {
            let _ = inst.send_stdin("save-all flush").await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let id = Uuid::new_v4();
        let dir = self.backups_dir(inst.id);
        let archive = dir.join(format!("{id}.tar.gz"));
        let data = self.data_dir(inst.id);
        let target = archive.clone();
        let made = tokio::task::spawn_blocking(move || -> Result<u64> {
            let root = files::open_root(&data)?;
            backup::create(&root, &target, &progress)?;
            Ok(std::fs::metadata(&target)?.len())
        })
        .await
        .map_err(anyhow::Error::from)?;
        let size = match made {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_file(&archive);
                return Err(e.into());
            }
        };
        let info = BackupInfo { id, name: name.trim().to_string(), size, created_at: now_secs() };
        std::fs::write(dir.join(format!("{id}.json")), serde_json::to_vec(&info).map_err(anyhow::Error::from)?).map_err(anyhow::Error::from)?;
        inst.log(&format!("[ember] Backup \"{}\" created", info.name));
        Ok(info)
    }

    /// Works in any state but an install. A server that was online stops first and comes back
    /// straight away running the backup.
    pub async fn restore_backup(self: &Arc<Self>, inst: Arc<Instance>, backup_id: Uuid) -> ApiResult<()> {
        let _power = inst.power.lock().await;
        let state = inst.state();
        if matches!(state, ServerState::Installing | ServerState::InstallFailed) {
            return Err(conflict("a server can't be restored until it has installed"));
        }
        if inst.extracting.load(Ordering::SeqCst) {
            return Err(conflict("wait for the archive to finish extracting"));
        }
        let archive = self.backups_dir(inst.id).join(format!("{backup_id}.tar.gz"));
        if !archive.exists() {
            return Err(not_found("backup not found"));
        }
        inst.restoring.store(true, Ordering::SeqCst);
        let was_online = matches!(state, ServerState::Running | ServerState::Starting);
        let result = self.replace_files(&inst, archive, was_online).await;
        inst.restoring.store(false, Ordering::SeqCst);
        result
    }

    async fn replace_files(self: &Arc<Self>, inst: &Arc<Instance>, archive: PathBuf, was_online: bool) -> ApiResult<()> {
        if inst.backup.lock().expect("backup lock").is_some() {
            return Err(conflict("wait for the running backup to finish"));
        }
        self.stop_locked(inst).await?;
        inst.log("[ember] Restoring backup");
        let data = self.data_dir(inst.id);
        let owner = inst.owner();
        let max = inst.record().limits.disk_mb * 1024 * 1024;
        let restored = tokio::task::spawn_blocking(move || -> Result<()> {
            let root = files::open_root(&data)?;
            backup::restore(&root, &archive, owner, max)
        })
        .await
        .map_err(anyhow::Error::from)?;
        self.scan_disk(inst).await;
        if let Err(e) = restored {
            // The files are incomplete, and booting them could write a fresh world over the rest.
            inst.log(&format!("[ember] Restore failed, so the server stays offline: {e:#}"));
            return Err(e.into());
        }
        inst.log("[ember] Backup restored");
        if was_online {
            self.start_locked(inst)
                .await
                .map_err(|e| ApiErr(e.0, format!("the backup was restored, but the server could not start: {}", e.1)))?;
        }
        Ok(())
    }

    /// Unpacks an archive next to itself. The archive may be hostile and the parser is large,
    /// so it runs in a sandbox like the server's: its user, its files, its limits and no
    /// network. It gets a cgroup of its own, so it works while the server runs.
    pub async fn extract(self: &Arc<Self>, inst: Arc<Instance>, rel: &str) -> ApiResult<()> {
        if inst.state() == ServerState::Installing {
            return Err(conflict("wait for the install to finish"));
        }
        if inst.extracting.swap(true, Ordering::SeqCst) {
            return Err(conflict("this server is already extracting an archive"));
        }
        let result = self.run_extract(&inst, rel).await;
        inst.extracting.store(false, Ordering::SeqCst);
        result
    }

    async fn run_extract(self: &Arc<Self>, inst: &Arc<Instance>, rel: &str) -> ApiResult<()> {
        let path = files::clean_nonroot(rel).map_err(|e| bad_request(e.to_string()))?;
        let (data, checked) = (self.data_dir(inst.id), path.clone());
        tokio::task::spawn_blocking(move || files::open_regular(&files::open_root(&data)?, &checked).map(|_| ()))
            .await
            .map_err(anyhow::Error::from)?
            .map_err(|e| bad_request(format!("{e:#}")))?;
        let tool = install::ensure_archive_tool(self).await?;

        let rec = inst.record();
        let key = format!("{}-extract", inst.id);
        let limits = rec.limits;
        let cg_key = key.clone();
        tokio::task::spawn_blocking(move || cgroup::create(&cg_key, &limits)).await.map_err(anyhow::Error::from)??;
        let result = self.extract_in_sandbox(inst, tool, &path, &key).await;
        net::offline_down(rec.index).await;
        let cleanup = key.clone();
        let _ = tokio::task::spawn_blocking(move || cgroup::kill_and_remove(&cleanup)).await;
        self.scan_disk(inst).await;
        result
    }

    async fn extract_in_sandbox(&self, inst: &Arc<Instance>, tool: &str, path: &Path, key: &str) -> ApiResult<()> {
        let rec = inst.record();
        let netns = net::offline_up(rec.index).await?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        // The ./ keeps a file named like an option from being read as one.
        let argv = vec![tool.to_string(), "-xf".into(), format!("./{}", path.display()), "-C".into(), format!("./{}", parent.display())];
        let spec = build_spec(&self.cfg, inst.owner(), self.data_dir(inst.id), cgroup::dir_for(key), netns, vec![], argv, base_env(), rec.limits.disk_mb);
        let name = path.display();
        inst.log(&format!("[ember] Extracting {name}"));
        let mut child = spawn_helper(&spec)?;
        drop(child.stdin.take());
        let readers = start_pumps(&mut child, inst, false);

        let limit = rec.limits.disk_mb * 1024 * 1024;
        let started = Instant::now();
        let mut check = tokio::time::interval(Duration::from_secs(1));
        let mut over_limit = false;
        let mut timed_out = false;
        let status = loop {
            tokio::select! {
                status = child.wait() => break status,
                _ = check.tick() => {
                    over_limit = over_limit || self.scan_disk(inst).await > limit;
                    timed_out = started.elapsed() > INSTALL_TIMEOUT;
                    if over_limit || timed_out {
                        cgroup::kill(key);
                    }
                }
            }
        };
        finish_pumps(readers).await;
        // Checked again after it exits, because a fast bomb can finish between checks.
        over_limit = over_limit || self.scan_disk(inst).await > limit;
        let message = if over_limit {
            format!("{name} is too big for this server's disk limit. It was stopped, so some of its files may be there")
        } else if timed_out {
            format!("{name} took too long to extract and was stopped")
        } else if status.map_err(anyhow::Error::from)?.success() {
            inst.log(&format!("[ember] Extracted {name}"));
            return Ok(());
        } else {
            format!("{name} couldn't be extracted. It may be damaged or password protected. The console has details")
        };
        inst.log(&format!("[ember] {message}"));
        Err(bad_request(message))
    }

    pub fn delete_backup(&self, id: Uuid, backup_id: Uuid) -> ApiResult<()> {
        let dir = self.backups_dir(id);
        let archive = dir.join(format!("{backup_id}.tar.gz"));
        if !archive.exists() {
            return Err(not_found("backup not found"));
        }
        std::fs::remove_file(archive).map_err(anyhow::Error::from)?;
        let _ = std::fs::remove_file(dir.join(format!("{backup_id}.json")));
        Ok(())
    }

    // ---- Background work ----

    pub fn spawn_background(self: &Arc<Self>) {
        if let Some(mut rx) = self.restart_rx.lock().expect("restart lock").take() {
            let mgr = self.clone();
            tokio::spawn(async move {
                while let Some(inst) = rx.recv().await {
                    if let Err(e) = mgr.start(inst.clone()).await {
                        inst.log(&format!("[ember] Restart failed: {}", e.1));
                    }
                }
            });
        }

        let mgr = self.clone();
        tokio::spawn(async move {
            loop {
                for inst in mgr.all() {
                    let bytes = mgr.scan_disk(&inst).await;
                    let limit = inst.record().limits.disk_mb * 1024 * 1024;
                    if bytes > limit && inst.state() == ServerState::Running {
                        let msg = "the server went over its disk limit and was stopped";
                        inst.log(&format!("[ember] {msg}"));
                        inst.update(|r| r.last_error = Some(msg.to_string()));
                        let _ = mgr.stop(inst.clone()).await;
                    }
                }
                tokio::time::sleep(DISK_SCAN_EVERY).await;
            }
        });

        let mgr = self.clone();
        tokio::spawn(async move {
            let mut prev = chrono::Utc::now();
            loop {
                tokio::time::sleep(SCHEDULE_TICK).await;
                let now = chrono::Utc::now();
                for inst in mgr.all() {
                    for sched in inst.record().schedules.iter().filter(|s| s.enabled) {
                        if schedule_due(&sched.cron, prev, now) {
                            let (mgr, inst, sched) = (mgr.clone(), inst.clone(), sched.clone());
                            tokio::spawn(async move { mgr.run_schedule(inst, sched).await });
                        }
                    }
                }
                prev = now;
            }
        });

        let mgr = self.clone();
        tokio::spawn(async move {
            // Servers that were running before an update come back with those set to autostart.
            let resume: Vec<Uuid> = std::fs::read(mgr.resume_file()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            for inst in mgr.all() {
                if (inst.record().autostart || resume.contains(&inst.id)) && inst.state() == ServerState::Offline {
                    if let Err(e) = mgr.start(inst.clone()).await {
                        tracing::error!(server = %inst.id, "autostart failed: {}", e.1);
                    }
                }
            }
            let _ = std::fs::remove_file(mgr.resume_file());
        });

        let mgr = self.clone();
        tokio::spawn(async move {
            let marker = crate::update::restart_marker(&mgr.cfg.data_dir);
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if marker.exists() && !mgr.is_busy() {
                    mgr.restarting.store(true, Ordering::SeqCst);
                    mgr.restart_wanted.notify_one();
                    return;
                }
            }
        });
    }

    async fn run_schedule(self: Arc<Self>, inst: Arc<Instance>, sched: Schedule) {
        inst.log(&format!("[ember] Running schedule \"{}\"", sched.name));
        let result = match &sched.action {
            ScheduleAction::Command(c) => inst.send_stdin(c).await.map_err(|e| format!("{e:#}")),
            ScheduleAction::Restart => self.restart(inst.clone()).await.map_err(|e| e.1),
            ScheduleAction::Backup => {
                let name = format!("{} {}", sched.name, chrono::Utc::now().format("%Y-%m-%d %H:%M"));
                self.create_backup(&inst, &name).await.map(|_| ()).map_err(|e| e.1)
            }
        };
        let err = result.err();
        if let Some(e) = &err {
            inst.log(&format!("[ember] Schedule \"{}\" failed: {e}", sched.name));
        }
        inst.update(|r| {
            if let Some(s) = r.schedules.iter_mut().find(|s| s.id == sched.id) {
                s.last_run = Some(now_secs());
                s.last_error = err;
            }
        });
    }

    pub async fn shutdown(&self) {
        let marker = crate::update::restart_marker(&self.cfg.data_dir);
        if marker.exists() {
            let running: Vec<Uuid> = self.all().iter().filter(|i| matches!(i.state(), ServerState::Running | ServerState::Starting)).map(|i| i.id).collect();
            for inst in self.all().iter().filter(|i| running.contains(&i.id)) {
                inst.log("[ember] Restarting for an update. This server will come back by itself.");
            }
            match serde_json::to_vec(&running).map_err(anyhow::Error::from).and_then(|b| Ok(std::fs::write(self.resume_file(), b)?)) {
                Ok(()) => {
                    let _ = std::fs::remove_file(marker);
                }
                Err(e) => tracing::error!("could not record running servers: {e:#}"),
            }
        }
        let stops = self.all().into_iter().map(|inst| async move {
            if let Err(e) = self.stop(inst).await {
                tracing::error!("stop during shutdown failed: {}", e.1);
            }
        });
        futures_util::future::join_all(stops).await;
    }

    pub fn node_cpu_percent(&self) -> f32 {
        let Some((total, idle)) = crate::node::read_cpu_times() else { return 0.0 };
        let mut prev = self.cpu_prev.lock().expect("cpu lock");
        let pct = match *prev {
            Some((t0, i0)) if total > t0 => (1.0 - (idle.saturating_sub(i0)) as f64 / (total - t0) as f64) * 100.0,
            _ => 0.0,
        };
        *prev = Some((total, idle));
        pct.clamp(0.0, 100.0) as f32
    }
}

pub fn validate_cron(expr: &str) -> Result<(), String> {
    use std::str::FromStr;
    cron::Schedule::from_str(expr).map(|_| ()).map_err(|e| format!("invalid schedule: {e}"))
}

/// True when the schedule has a firing time in `(prev, now]`.
fn schedule_due(expr: &str, prev: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> bool {
    use std::str::FromStr;
    cron::Schedule::from_str(expr).ok().and_then(|s| s.after(&prev).next()).is_some_and(|next| next <= now)
}

fn heap_mb(memory_mb: u64) -> u64 {
    // Leave room for the JVM's own native memory, or the kernel kills it under load.
    let overhead = (memory_mb / 8).max(256);
    memory_mb.saturating_sub(overhead).max(128)
}

const JAVA_VERSIONS: [u32; 5] = [8, 11, 17, 21, 25];

fn validate_startup(o: &StartupOptions, memory_mb: u64) -> Result<(), String> {
    if let Some(cmd) = &o.custom_command {
        if cmd.len() > 8192 || cmd.contains(['\n', '\r', '\0']) {
            return Err("the command must be a single line".into());
        }
        parse_command(cmd)?;
    }
    if let Some(j) = o.java_major {
        if !JAVA_VERSIONS.contains(&j) {
            return Err(format!("Java {j} is not available"));
        }
    }
    if let Some(max) = o.max_heap_mb {
        if !(128..=memory_mb).contains(&max) {
            return Err(format!("maximum heap must be between 128 MB and the {memory_mb} MB memory limit"));
        }
    }
    if let Some(min) = o.min_heap_mb {
        if min < 64 || min > o.max_heap_mb.unwrap_or_else(|| heap_mb(memory_mb)) {
            return Err("minimum heap must be at least 64 MB and no more than the maximum heap".into());
        }
    }
    if let Some(jar) = &o.jar {
        files::clean_nonroot(jar).map_err(|_| "the jar must be a path inside the server folder".to_string())?;
    }
    let bad_arg = |a: &String| a.is_empty() || a.len() > 1024 || a.contains('\0');
    if o.jvm_args.len() > 128 || o.jvm_args.iter().any(|a| bad_arg(a) || !a.starts_with('-')) {
        return Err("JVM flags must each start with '-'".into());
    }
    if o.server_args.len() > 64 || o.server_args.iter().any(bad_arg) {
        return Err("invalid server argument".into());
    }
    if o.env.len() > 64 {
        return Err("too many environment variables".into());
    }
    for e in &o.env {
        let mut chars = e.name.chars();
        let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
            && e.name.len() <= 128;
        if !valid || e.value.contains('\0') || e.value.len() > 4096 {
            return Err(format!("invalid environment variable {:?}", e.name));
        }
    }
    Ok(())
}

/// The single source of truth for what runs: both start and the Startup tab's preview use it.
fn build_command(rec: &ServerRecord) -> Result<(Vec<String>, EnvVars)> {
    let o = &rec.startup;
    let mut env = base_env();
    let start = rec.start.as_ref().ok_or_else(|| anyhow!("Available after the server finishes installing."))?;
    if matches!(start, StartSpec::Native { .. }) {
        env.push(("LD_LIBRARY_PATH".into(), ".".into()));
    }
    let argv = match &o.custom_command {
        Some(cmd) => resolve_program(parse_command(&expand_variables(cmd, rec)).map_err(|e| anyhow!(e))?),
        None => auto_argv(rec, start),
    };
    for var in &o.env {
        env.retain(|(k, _)| *k != var.name);
        env.push((var.name.clone(), var.value.clone()));
    }
    Ok((argv, env))
}

/// `{{MEMORY}}` is the automatic heap in MB, and `{{PORT}}` is the server's game port.
fn expand_variables(cmd: &str, rec: &ServerRecord) -> String {
    cmd.replace("{{MEMORY}}", &heap_mb(rec.limits.memory_mb).to_string()).replace("{{PORT}}", &rec.port.to_string())
}

/// Splits a command line the way a shell would, without running one: plain words,
/// single quotes, double quotes and backslash escapes. For real shell features,
/// the command can be `sh -c '...'`, which still runs inside the sandbox.
fn parse_command(cmd: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = cmd.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(q) => word.push(q),
                        None => return Err("the command has an unclosed single quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => word.push(chars.next().ok_or("the command ends with a backslash")?),
                        Some(q) => word.push(q),
                        None => return Err("the command has an unclosed double quote".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                word.push(chars.next().ok_or("the command ends with a backslash")?);
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    if words.is_empty() {
        return Err("the command is empty".into());
    }
    Ok(words)
}

/// `java` means the server's selected runtime, and other bare names are found on the PATH.
fn resolve_program(mut argv: Vec<String>) -> Vec<String> {
    if argv[0] == "java" {
        argv[0] = "/opt/java/bin/java".into();
    } else if !argv[0].contains('/') {
        argv.insert(0, "/usr/bin/env".into());
    }
    argv
}

fn auto_argv(rec: &ServerRecord, start: &StartSpec) -> Vec<String> {
    let o = &rec.startup;
    let mut argv = match start {
        StartSpec::Native { binary } => vec![format!("{HOME}/{binary}")],
        StartSpec::Jar { .. } | StartSpec::ArgsFile { .. } => {
            let max = o.max_heap_mb.unwrap_or_else(|| heap_mb(rec.limits.memory_mb)).min(rec.limits.memory_mb);
            let min = o.min_heap_mb.unwrap_or(512).min(max);
            let mut a = vec!["/opt/java/bin/java".to_string(), format!("-Xms{min}M"), format!("-Xmx{max}M")];
            a.extend(o.jvm_args.iter().cloned());
            match (&o.jar, start) {
                (Some(jar), _) => a.extend(["-jar".to_string(), jar.clone()]),
                (None, StartSpec::Jar { path }) => a.extend(["-jar".to_string(), path.clone()]),
                (None, StartSpec::ArgsFile { path }) => a.push(format!("@{path}")),
                (None, StartSpec::Native { .. }) => unreachable!("matched above"),
            }
            a
        }
    };
    argv.extend(o.server_args.iter().cloned());
    argv
}

fn display_command(env: &[EnvVar], argv: &[String]) -> String {
    let quote = |s: &str| {
        if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_=./:@+,".contains(c)) {
            s.to_string()
        } else {
            format!("'{}'", s.replace('\'', "'\\''"))
        }
    };
    env.iter()
        .map(|e| format!("{}={}", e.name, quote(&e.value)))
        .chain(argv.iter().map(|a| quote(a)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn base_env() -> Vec<(String, String)> {
    [
        ("HOME", HOME),
        ("USER", "container"),
        ("LANG", "C.UTF-8"),
        ("PATH", "/opt/java/bin:/usr/local/bin:/usr/bin:/bin"),
        ("JAVA_HOME", "/opt/java"),
        ("TERM", "xterm-256color"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn build_spec(
    cfg: &Config,
    owner: Owner,
    data_dir: PathBuf,
    cgroup_dir: PathBuf,
    netns: String,
    ro_binds: Vec<RoBind>,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    disk_mb: u64,
) -> SandboxSpec {
    SandboxSpec {
        hostname: "ember".into(),
        uid: owner.uid,
        gid: owner.gid,
        data_dir,
        ro_binds,
        cgroup_dir,
        netns: Some(netns),
        argv,
        env,
        tmp_mb: cfg.tmp_mb,
        file_size_limit: disk_mb * 1024 * 1024,
        dns: cfg.dns.clone(),
    }
}

pub fn spawn_helper(spec: &SandboxSpec) -> Result<Child> {
    std::fs::create_dir_all("/run/ember").context("create /run/ember")?;
    Command::new("/proc/self/exe")
        .arg(INIT_ARG)
        .env_clear()
        .env(SPEC_ENV, serde_json::to_string(spec)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start sandbox helper")
}

type Pumps = Vec<tokio::task::JoinHandle<()>>;

fn start_pumps(child: &mut Child, inst: &Arc<Instance>, detect_ready: bool) -> Pumps {
    let mut v = Vec::new();
    if let Some(o) = child.stdout.take() {
        v.push(tokio::spawn(pump(o, inst.clone(), detect_ready)));
    }
    if let Some(e) = child.stderr.take() {
        v.push(tokio::spawn(pump(e, inst.clone(), detect_ready)));
    }
    v
}

async fn finish_pumps(pumps: Pumps) {
    let all = futures_util::future::join_all(pumps);
    let _ = tokio::time::timeout(Duration::from_secs(3), all).await;
}

/// Forwards output a line at a time, with bounded memory: a server printing
/// without newlines gets split rather than growing a buffer forever.
async fn pump(reader: impl AsyncRead + Unpin, inst: Arc<Instance>, detect_ready: bool) {
    let mut r = BufReader::with_capacity(16 * 1024, reader);
    let mut line: Vec<u8> = Vec::with_capacity(512);
    loop {
        let chunk = match r.fill_buf().await {
            Ok([]) | Err(_) => break,
            Ok(c) => c,
        };
        let (take, complete) = match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (chunk.len(), false),
        };
        let room = MAX_LINE_BYTES.saturating_sub(line.len());
        let copied = take.min(room);
        line.extend_from_slice(&chunk[..copied]);
        r.consume(copied);
        if (complete && copied == take) || line.len() >= MAX_LINE_BYTES {
            emit(&inst, &line, detect_ready);
            line.clear();
        }
    }
    if !line.is_empty() {
        emit(&inst, &line, detect_ready);
    }
}

fn emit(inst: &Instance, raw: &[u8], detect_ready: bool) {
    let text = String::from_utf8_lossy(raw);
    let text = text.trim_end_matches(['\r', '\n']);
    inst.log(text);
    if detect_ready && inst.state() == ServerState::Starting && is_ready_line(text) {
        inst.set_state(ServerState::Running);
    }
}

fn is_ready_line(line: &str) -> bool {
    (line.contains("Done (") && line.contains("For help")) || line.contains("Server started.")
}

async fn wait_until_stopped(inst: &Instance, timeout: Duration) -> bool {
    let mut rx = inst.watch_state();
    let done = async {
        rx.wait_for(|s| !matches!(s, ServerState::Stopping | ServerState::Running | ServerState::Starting)).await.is_ok()
    };
    tokio::time::timeout(timeout, done).await.unwrap_or(false)
}

/// Real blocks used, so sparse files are not overcounted. Does not follow symlinks.
fn disk_usage(path: &Path) -> u64 {
    walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.blocks() * 512)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_search_moves_up_to_the_next_free_port() {
        assert_eq!(first_free_port(25565, |_| true), Some(25565));
        assert_eq!(first_free_port(25565, |p| p != 25565 && p != 25566), Some(25567));
        assert_eq!(first_free_port(65534, |p| p == 65535), Some(65535));
        assert_eq!(first_free_port(65534, |_| false), None, "the top of the range must not wrap");
    }

    #[test]
    fn sanitizer_keeps_colors_and_strips_terminal_attacks() {
        assert_eq!(sanitize_line(b"\x1b[32mok\x1b[0m"), "\x1b[32mok\x1b[0m");
        assert_eq!(sanitize_line(b"a\x1b[2Jb"), "ab", "screen clear");
        assert_eq!(sanitize_line(b"a\x1b]52;c;ZXZpbA==\x07b"), "a52;c;ZXZpbA==b", "OSC introducer removed");
        assert_eq!(sanitize_line(b"x\x07y\x08z"), "xyz");
        assert_eq!(sanitize_line(b"tab\tok"), "tab\tok");
    }

    fn java_record() -> ServerRecord {
        ServerRecord {
            id: Uuid::nil(),
            name: "t".into(),
            flavor: Flavor::Paper,
            version: "26.3".into(),
            bedrock_url: None,
            limits: Limits { memory_mb: 4096, cpu_percent: 100, disk_mb: 1024, pids: 128 },
            port: 25565,
            index: 1,
            autostart: false,
            restart_on_crash: false,
            startup: StartupOptions { server_args: vec!["nogui".into()], ..Default::default() },
            java_major: Some(25),
            created_at: 0,
            start: Some(StartSpec::Jar { path: "server.jar".into() }),
            last_error: None,
            schedules: vec![],
        }
    }

    #[test]
    fn command_uses_defaults_then_overrides() {
        let mut r = java_record();
        let (argv, _) = build_command(&r).unwrap();
        assert_eq!(argv, ["/opt/java/bin/java", "-Xms512M", "-Xmx3584M", "-jar", "server.jar", "nogui"]);

        r.startup.min_heap_mb = Some(1024);
        r.startup.max_heap_mb = Some(2048);
        r.startup.jar = Some("custom.jar".into());
        r.startup.jvm_args = vec!["-XX:+UseG1GC".into()];
        r.startup.server_args = vec!["--port".into(), "1".into()];
        r.startup.env = vec![EnvVar { name: "HOME".into(), value: "/x".into() }];
        let (argv, env) = build_command(&r).unwrap();
        assert_eq!(argv, ["/opt/java/bin/java", "-Xms1024M", "-Xmx2048M", "-XX:+UseG1GC", "-jar", "custom.jar", "--port", "1"]);
        assert_eq!(env.iter().filter(|(k, _)| k == "HOME").count(), 1, "an override replaces the default");
        assert!(env.iter().any(|(k, v)| k == "HOME" && v == "/x"));
    }

    #[test]
    fn parses_command_lines_like_a_shell() {
        let w = |s: &str| parse_command(s).unwrap();
        assert_eq!(w("java -Xmx4G -jar server.jar nogui"), ["java", "-Xmx4G", "-jar", "server.jar", "nogui"]);
        assert_eq!(w(r#"java "-Dmotd=hello world" 'a b' c\ d"#), ["java", "-Dmotd=hello world", "a b", "c d"]);
        assert_eq!(w("  a   b  "), ["a", "b"]);
        assert_eq!(w("a ''"), ["a", ""]);
        for bad in ["", "   ", "java 'open", "java \"open", "java \\"] {
            assert!(parse_command(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn custom_command_replaces_the_automatic_one() {
        let mut r = java_record();
        r.startup.jvm_args = vec!["-Dignored=yes".into()];
        r.startup.custom_command = Some("java -Xmx{{MEMORY}}M -Dport={{PORT}} -jar paper.jar".into());
        let (argv, _) = build_command(&r).unwrap();
        assert_eq!(argv, ["/opt/java/bin/java", "-Xmx3584M", "-Dport=25565", "-jar", "paper.jar"]);

        r.startup.custom_command = Some("sh -c 'exec java -jar a.jar'".into());
        assert_eq!(build_command(&r).unwrap().0, ["/usr/bin/env", "sh", "-c", "exec java -jar a.jar"]);

        r.startup.custom_command = Some("./start.sh now".into());
        assert_eq!(build_command(&r).unwrap().0, ["./start.sh", "now"]);

        for bad in ["java 'open", "a\nb", "   "] {
            let o = StartupOptions { custom_command: Some(bad.into()), ..Default::default() };
            assert!(validate_startup(&o, 4096).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn startup_validation_rejects_bad_values() {
        let ok = StartupOptions { java_major: Some(21), max_heap_mb: Some(2048), min_heap_mb: Some(512), ..Default::default() };
        assert!(validate_startup(&ok, 4096).is_ok());
        let bad = [
            StartupOptions { java_major: Some(99), ..Default::default() },
            StartupOptions { max_heap_mb: Some(8192), ..Default::default() },
            StartupOptions { max_heap_mb: Some(1024), min_heap_mb: Some(2048), ..Default::default() },
            StartupOptions { jar: Some("../../etc/passwd".into()), ..Default::default() },
            StartupOptions { jvm_args: vec!["nope".into()], ..Default::default() },
            StartupOptions { env: vec![EnvVar { name: "BAD NAME".into(), value: "x".into() }], ..Default::default() },
        ];
        for o in bad {
            assert!(validate_startup(&o, 4096).is_err(), "{o:?}");
        }
    }

    #[test]
    fn displayed_command_is_quoted() {
        let argv = vec!["java".to_string(), "-Dmotd=hello world".to_string()];
        let env = [EnvVar { name: "A".into(), value: "b c".into() }];
        assert_eq!(display_command(&env, &argv), "A='b c' java '-Dmotd=hello world'");
    }

    #[test]
    fn heap_leaves_native_headroom() {
        assert_eq!(heap_mb(2048), 1792);
        assert_eq!(heap_mb(8192), 7168);
        assert_eq!(heap_mb(256), 128);
    }

    #[test]
    fn detects_ready_lines() {
        assert!(is_ready_line("[12:00:00] [Server thread/INFO]: Done (12.3s)! For help, type \"help\""));
        assert!(is_ready_line("[2026-01-01 INFO] Server started."));
        assert!(!is_ready_line("Done loading"));
    }

    #[test]
    fn schedules_fire_only_inside_the_window() {
        use chrono::TimeZone;
        let t = |s| chrono::Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, s).unwrap();
        let every_min = "0 * * * * *";
        assert!(schedule_due(every_min, chrono::Utc.with_ymd_and_hms(2026, 1, 1, 11, 59, 58).unwrap(), t(2)));
        assert!(!schedule_due(every_min, t(1), t(5)));
        assert!(!schedule_due("not cron", t(0), t(5)));
        assert!(validate_cron(every_min).is_ok());
        assert!(validate_cron("nope").is_err());
    }

    #[tokio::test]
    async fn pump_splits_runaway_lines_and_keeps_everything() {
        let rec = ServerRecord {
            id: Uuid::new_v4(),
            name: "t".into(),
            flavor: Flavor::Vanilla,
            version: "1".into(),
            bedrock_url: None,
            limits: Limits { memory_mb: 1024, cpu_percent: 100, disk_mb: 1024, pids: 128 },
            port: 25565,
            index: 1,
            autostart: false,
            restart_on_crash: false,
            startup: StartupOptions::default(),
            java_major: None,
            created_at: 0,
            start: None,
            last_error: None,
            schedules: vec![],
        };
        let dir = tempfile::tempdir().unwrap();
        let inst = Instance::new(rec, dir.path().join("s.json"), ServerState::Starting);
        let mut input = vec![b'a'; MAX_LINE_BYTES + 100];
        input.extend_from_slice(b"\nDone (1s)! For help\nlast");
        pump(&input[..], inst.clone(), true).await;
        let b = inst.backlog();
        assert_eq!(b.len(), 4, "{:?}", b.iter().map(String::len).collect::<Vec<_>>());
        assert_eq!(b[0].len(), MAX_LINE_BYTES);
        assert_eq!(b[1].len(), 100);
        assert_eq!(b[3], "last");
        assert_eq!(inst.state(), ServerState::Running);
    }
}
