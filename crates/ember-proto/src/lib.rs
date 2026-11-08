//! Wire types shared by the `emberd` daemon and the Ember Panel desktop app.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const API_VERSION: u32 = 1;
pub const DEFAULT_PORT: u16 = 8787;
/// Every request must carry this header. Browsers cannot attach it to a
/// cross-site request without a CORS preflight, which the daemon never grants.
pub const CLIENT_HEADER: &str = "x-ember-client";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Flavor {
    Vanilla,
    Paper,
    Fabric,
    Forge,
    Bedrock,
}

impl Flavor {
    pub fn default_port(self) -> u16 {
        match self {
            Flavor::Bedrock => 19132,
            _ => 25565,
        }
    }

    pub fn protocol(self) -> Protocol {
        match self {
            Flavor::Bedrock => Protocol::Udp,
            _ => Protocol::Tcp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub memory_mb: u64,
    /// 100 = one full core.
    pub cpu_percent: u32,
    pub disk_mb: u64,
    pub pids: u32,
}

impl Limits {
    pub fn validate(&self) -> Result<(), String> {
        if !(256..=4_194_304).contains(&self.memory_mb) {
            return Err("memory must be between 256 MB and 4 TB".into());
        }
        if !(10..=25_600).contains(&self.cpu_percent) {
            return Err("cpu must be between 10% and 25600%".into());
        }
        if !(256..=1_073_741_824).contains(&self.disk_mb) {
            return Err("disk must be at least 256 MB".into());
        }
        if !(64..=65_536).contains(&self.pids) {
            return Err("process limit must be between 64 and 65536".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    Installing,
    InstallFailed,
    Offline,
    Starting,
    Running,
    Stopping,
    Crashed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateServer {
    pub name: String,
    pub flavor: Flavor,
    /// Minecraft version. Ignored for Bedrock, whose version comes from the URL.
    #[serde(default)]
    pub version: String,
    /// Official `minecraft.net` Bedrock server download link. Bedrock only.
    #[serde(default)]
    pub bedrock_url: Option<String>,
    pub limits: Limits,
    pub port: u16,
    /// The operator must explicitly accept the Minecraft EULA.
    pub eula_accepted: bool,
    /// Starts the server once its install finishes, even if the panel has closed.
    #[serde(default)]
    pub start_after_install: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateServer {
    pub name: Option<String>,
    pub limits: Option<Limits>,
    pub autostart: Option<bool>,
    pub restart_on_crash: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub id: Uuid,
    pub name: String,
    pub flavor: Flavor,
    pub version: String,
    pub limits: Limits,
    pub port: u16,
    pub protocol: Protocol,
    pub state: ServerState,
    pub autostart: bool,
    pub restart_on_crash: bool,
    pub java_major: Option<u32>,
    pub created_at: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

/// What a server starts with. `None` and empty values use the automatic defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupOptions {
    /// A full command line, like `java -Xmx4G -jar server.jar nogui`. When set it
    /// replaces the heap, jar, flag and argument fields below.
    #[serde(default)]
    pub custom_command: Option<String>,
    /// Java version override. `None` uses the version Minecraft asks for.
    #[serde(default)]
    pub java_major: Option<u32>,
    #[serde(default)]
    pub min_heap_mb: Option<u64>,
    #[serde(default)]
    pub max_heap_mb: Option<u64>,
    /// Jar to run, relative to the server folder. `None` uses the installed one.
    #[serde(default)]
    pub jar: Option<String>,
    #[serde(default)]
    pub jvm_args: Vec<String>,
    /// Arguments after the jar, such as `nogui`.
    #[serde(default)]
    pub server_args: Vec<String>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupInfo {
    pub options: StartupOptions,
    /// The exact command the server will run, or why it cannot be built yet.
    pub command: String,
    /// The automatic command in editable form, as a starting point for a custom one.
    #[serde(default)]
    pub auto_command: String,
    pub is_java: bool,
    pub version: String,
    /// The version Minecraft asks for, used when `options.java_major` is `None`.
    pub default_java: Option<u32>,
    pub java_versions: Vec<u32>,
    pub default_max_heap_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateStartup {
    pub options: StartupOptions,
    /// A different Minecraft version here reinstalls the server software.
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PowerAction {
    Start,
    Stop,
    Restart,
    Kill,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerRequest {
    pub action: PowerAction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerStats {
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub memory_limit_bytes: u64,
    pub disk_bytes: u64,
    pub disk_limit_bytes: u64,
    pub pids: u32,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub api_version: u32,
    pub version: String,
    pub hostname: String,
    pub tailscale_ip: String,
    pub login: String,
    pub kernel: String,
    pub os: String,
    pub arch: String,
    pub cpu_count: u32,
    pub isolation: Vec<IsolationCheck>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStats {
    pub cpu_percent: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    pub disk_used: u64,
    pub disk_total: u64,
    pub load1: f32,
    pub uptime_secs: u64,
    pub servers_total: u32,
    pub servers_running: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRequest {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameRequest {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContent {
    pub content: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfo {
    pub id: Uuid,
    pub name: String,
    pub size: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBackup {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum ScheduleAction {
    Command(String),
    Restart,
    Backup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub id: Uuid,
    pub name: String,
    /// Six-field cron expression: `sec min hour day month weekday`, evaluated in UTC.
    pub cron: String,
    pub action: ScheduleAction,
    pub enabled: bool,
    pub last_run: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertSchedule {
    pub name: String,
    pub cron: String,
    pub action: ScheduleAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameVersion {
    pub id: String,
    pub stable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsoleEvent {
    Line { text: String },
    State { state: ServerState },
    Stats { stats: ServerStats },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

/// Rejects names that would be confusing in the UI or unsafe in logs.
pub fn validate_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 64 {
        return Err("name must be 1-64 characters".into());
    }
    if n.chars().any(char::is_control) {
        return Err("name cannot contain control characters".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_out_of_range() {
        let ok = Limits { memory_mb: 2048, cpu_percent: 200, disk_mb: 10240, pids: 512 };
        assert!(ok.validate().is_ok());
        assert!(Limits { memory_mb: 1, ..ok }.validate().is_err());
        assert!(Limits { cpu_percent: 0, ..ok }.validate().is_err());
        assert!(Limits { pids: 1, ..ok }.validate().is_err());
    }

    #[test]
    fn names_are_validated() {
        assert!(validate_name("Survival SMP").is_ok());
        assert!(validate_name("   ").is_err());
        assert!(validate_name("bad\nname").is_err());
    }

    #[test]
    fn schedule_action_round_trips() {
        let json = serde_json::to_string(&ScheduleAction::Command("say hi".into())).unwrap();
        assert_eq!(serde_json::from_str::<ScheduleAction>(&json).unwrap(), ScheduleAction::Command("say hi".into()));
    }
}
