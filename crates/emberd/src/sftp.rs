//! A built-in SFTP server, so tools like FileZilla and WinSCP can manage a server's files.
//!
//! It follows the same rules as the rest of the daemon. It listens only on the Tailscale
//! address and checks the Tailscale identity of each connection before any SSH traffic,
//! so there are no separate passwords. The SSH username selects a server, and every file
//! operation goes through `cap_std`, confined to that server's folder. The folder belongs
//! to a possibly hostile game server, so links are never followed out of it and cannot
//! be created through SFTP.

use crate::auth::{self, SelfInfo, Tailscale};
use crate::files::{self, Owner};
use crate::manager::{Instance, Manager};
use anyhow::{Context, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, Metadata, OpenOptions, OpenOptionsExt as _, PermissionsExt as _};
use ember_proto::SFTP_PORT;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::os::unix::fs::{fchown, DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::task::block_in_place;

const MAX_READ: u32 = 256 * 1024;
const DIR_BATCH: usize = 128;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

fn load_host_key(path: &Path) -> Result<PrivateKey> {
    if let Ok(pem) = std::fs::read_to_string(path) {
        return PrivateKey::from_openssh(pem).context("read SFTP host key");
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).context("generate SFTP host key")?;
    let pem = key.to_openssh(LineEnding::LF).context("encode SFTP host key")?;
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(pem.as_bytes()))
        .context("save SFTP host key")?;
    Ok(key)
}

/// Accepts connections until the daemon exits. The host key is kept, so clients only
/// have to trust it once.
pub async fn serve(mgr: Arc<Manager>, ts: Tailscale, me: SelfInfo, ip: IpAddr) -> Result<()> {
    std::fs::DirBuilder::new().recursive(true).mode(0o711).create(&mgr.cfg.data_dir)?;
    let key = load_host_key(&mgr.cfg.data_dir.join("sftp_host_key"))?;
    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind((ip, SFTP_PORT)).await.with_context(|| format!("listen on {ip}:{SFTP_PORT}"))?;
    tracing::info!(addr = %format!("{ip}:{SFTP_PORT}"), "SFTP is listening on Tailscale");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("SFTP accept failed: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let (mgr, ts, me, config) = (mgr.clone(), ts.clone(), me.clone(), config.clone());
        tokio::spawn(async move {
            // The same rules as the API, applied before any SSH traffic is exchanged.
            if me.ips.contains(&peer.ip()) {
                tracing::warn!(%peer, "rejected SFTP connection from the node itself");
                return;
            }
            let login = match ts.whois(peer).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(%peer, "SFTP identity lookup failed: {e:#}");
                    return;
                }
            };
            if !auth::is_owner(&mgr.cfg.owners, &login) {
                tracing::warn!(%peer, %login, "rejected SFTP login that is not an owner");
                return;
            }
            tracing::info!(%login, %peer, "SFTP connection");
            let handler = Connection { mgr, target: None, channels: HashMap::new() };
            match russh::server::run_stream(config, stream, handler).await {
                Ok(session) => {
                    if let Err(e) = session.await {
                        tracing::debug!(%peer, "SFTP session ended: {e:#}");
                    }
                }
                Err(e) => tracing::debug!(%peer, "SFTP handshake failed: {e:#}"),
            }
        });
    }
}

struct Connection {
    mgr: Arc<Manager>,
    target: Option<Arc<Instance>>,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl Connection {
    /// Identity was proven when the connection opened, so any password is fine here.
    /// All that remains is working out which server the username means.
    fn login(&mut self, user: &str) -> Auth {
        self.target = self.mgr.find_by_sftp_user(user);
        if self.target.is_some() {
            Auth::Accept
        } else {
            Auth::reject()
        }
    }
}

impl russh::server::Handler for Connection {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(self.login(user))
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(self.login(user))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    /// SFTP is the only thing offered. There is no shell, exec or port forwarding.
    async fn subsystem_request(&mut self, id: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        let (Some(inst), true) = (self.target.clone(), name == "sftp") else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let Some(channel) = self.channels.remove(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let root = files::open_root(&self.mgr.data_dir(inst.id))?;
        session.channel_success(id)?;
        let sftp = SftpSession { root: Arc::new(root), inst, handles: HashMap::new(), next: 0, written: 0 };
        // Spawned so that the SSH session keeps delivering this channel's data.
        tokio::spawn(russh_sftp::server::run(channel.into_stream(), sftp));
        Ok(())
    }
}

enum Open {
    File(std::fs::File),
    Dir { entries: Vec<File> },
}

struct SftpSession {
    root: Arc<Dir>,
    inst: Arc<Instance>,
    handles: HashMap<String, Open>,
    next: u64,
    /// Bytes this session has written since the last disk scan could see them.
    written: u64,
}

/// Turns a client path into one relative to the server's folder. As in a chroot,
/// `/` is the server's folder and `..` stops there.
fn resolve(path: &str) -> Result<PathBuf, StatusCode> {
    if path.contains('\0') {
        return Err(StatusCode::BadMessage);
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        return Ok(PathBuf::from("."));
    }
    Ok(parts.iter().collect())
}

fn absolute(rel: &Path) -> String {
    if rel == Path::new(".") {
        "/".to_string()
    } else {
        format!("/{}", rel.to_string_lossy())
    }
}

fn status_of(e: &std::io::Error) -> StatusCode {
    match e.kind() {
        ErrorKind::NotFound => StatusCode::NoSuchFile,
        ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".to_string(), language_tag: "en-US".to_string() }
}

fn attrs_from(size: u64, mode: u32, mtime: u64, owner: Owner) -> FileAttributes {
    FileAttributes {
        size: Some(size),
        uid: Some(owner.uid),
        user: None,
        gid: Some(owner.gid),
        group: None,
        permissions: Some(mode),
        atime: Some(mtime as u32),
        mtime: Some(mtime as u32),
    }
}

fn cap_attrs(m: &Metadata, owner: Owner) -> FileAttributes {
    let kind = if m.file_type().is_symlink() {
        S_IFLNK
    } else if m.is_dir() {
        S_IFDIR
    } else {
        S_IFREG
    };
    let mtime = m.modified().ok().and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
    attrs_from(m.len(), kind | (m.permissions().mode() & 0o777), mtime, owner)
}

impl SftpSession {
    fn add_handle(&mut self, open: Open) -> String {
        self.next += 1;
        let key = self.next.to_string();
        self.handles.insert(key.clone(), open);
        key
    }

    fn stat_path(&self, path: &str, follow: bool) -> Result<FileAttributes, StatusCode> {
        let rel = resolve(path)?;
        let m = if follow { self.root.metadata(&rel) } else { self.root.symlink_metadata(&rel) };
        m.map(|m| cap_attrs(&m, self.inst.owner())).map_err(|e| status_of(&e))
    }

    /// Stops a session from filling the disk faster than the periodic scan can notice.
    fn check_quota(&mut self, offset: u64, len: u64) -> Result<(), StatusCode> {
        let limit = self.inst.record().limits.disk_mb * 1024 * 1024;
        if offset.saturating_add(len) > limit || self.inst.disk_used().saturating_add(self.written).saturating_add(len) > limit {
            return Err(StatusCode::Failure);
        }
        self.written += len;
        Ok(())
    }

    fn apply_attrs(file: &std::fs::File, attrs: &FileAttributes) -> std::io::Result<()> {
        if let Some(size) = attrs.size {
            file.set_len(size)?;
        }
        if let Some(mode) = attrs.permissions {
            // Never setuid, setgid or sticky, whatever the client asks for.
            file.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))?;
        }
        Ok(())
    }
}

impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, _version: u32, _extensions: HashMap<String, String>) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let rel = resolve(&path)?;
        Ok(Name { id, files: vec![File::dummy(absolute(&rel))] })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        block_in_place(|| Ok(Attrs { id, attrs: self.stat_path(&path, true)? }))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        block_in_place(|| Ok(Attrs { id, attrs: self.stat_path(&path, false)? }))
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(Open::File(f)) = self.handles.get(&handle) else { return Err(StatusCode::Failure) };
        let m = block_in_place(|| f.metadata()).map_err(|e| status_of(&e))?;
        Ok(Attrs { id, attrs: attrs_from(m.len(), m.mode() & 0o170_777, m.mtime().max(0) as u64, self.inst.owner()) })
    }

    /// Timestamps are accepted and ignored: clients set them after uploads, and failing would look like a failed upload.
    async fn setstat(&mut self, id: u32, path: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        if attrs.size.is_none() && attrs.permissions.is_none() {
            return Ok(ok(id));
        }
        let rel = resolve(&path)?;
        block_in_place(|| {
            let mut o = OpenOptions::new();
            o.read(true).write(attrs.size.is_some()).custom_flags(libc::O_NONBLOCK).follow(FollowSymlinks::No);
            let f = self.root.open_with(&rel, &o).map_err(|e| status_of(&e))?;
            Self::apply_attrs(&f.into_std(), &attrs).map_err(|e| status_of(&e))?;
            Ok(ok(id))
        })
    }

    async fn fsetstat(&mut self, id: u32, handle: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        if let Some(Open::File(f)) = self.handles.get(&handle) {
            block_in_place(|| Self::apply_attrs(f, &attrs)).map_err(|e| status_of(&e))?;
        }
        Ok(ok(id))
    }

    async fn open(&mut self, id: u32, filename: String, pflags: OpenFlags, _attrs: FileAttributes) -> Result<Handle, Self::Error> {
        let rel = resolve(&filename)?;
        if rel == Path::new(".") {
            return Err(StatusCode::Failure);
        }
        let writing = pflags.intersects(OpenFlags::WRITE | OpenFlags::APPEND);
        let owner = self.inst.owner();
        let file = block_in_place(|| {
            let mut o = OpenOptions::new();
            o.read(pflags.contains(OpenFlags::READ))
                .write(pflags.contains(OpenFlags::WRITE))
                .append(pflags.contains(OpenFlags::APPEND))
                .create(pflags.contains(OpenFlags::CREATE))
                .truncate(pflags.contains(OpenFlags::TRUNCATE))
                .create_new(pflags.contains(OpenFlags::CREATE) && pflags.contains(OpenFlags::EXCLUDE))
                .custom_flags(libc::O_NONBLOCK)
                .follow(FollowSymlinks::No);
            let f = self.root.open_with(&rel, &o).map_err(|e| status_of(&e))?;
            if !f.metadata().map_err(|e| status_of(&e))?.is_file() {
                return Err(StatusCode::Failure);
            }
            if writing {
                fchown(&f, Some(owner.uid), Some(owner.gid)).map_err(|e| status_of(&e))?;
            }
            Ok(f.into_std())
        })?;
        Ok(Handle { id, handle: self.add_handle(Open::File(file)) })
    }

    async fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let Some(Open::File(f)) = self.handles.get(&handle) else { return Err(StatusCode::Failure) };
        let mut buf = vec![0u8; len.min(MAX_READ) as usize];
        let n = block_in_place(|| f.read_at(&mut buf, offset)).map_err(|e| status_of(&e))?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        self.check_quota(offset, data.len() as u64)?;
        let Some(Open::File(f)) = self.handles.get(&handle) else { return Err(StatusCode::Failure) };
        block_in_place(|| f.write_all_at(&data, offset)).map_err(|e| status_of(&e))?;
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let rel = resolve(&path)?;
        let owner = self.inst.owner();
        let entries = block_in_place(|| -> std::io::Result<Vec<File>> {
            let mut out = Vec::new();
            for e in self.root.read_dir(&rel)? {
                let e = e?;
                let Ok(m) = e.metadata() else { continue };
                out.push(File::new(e.file_name().to_string_lossy().into_owned(), cap_attrs(&m, owner)));
            }
            Ok(out)
        })
        .map_err(|e| status_of(&e))?;
        Ok(Handle { id, handle: self.add_handle(Open::Dir { entries }) })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Dir { entries }) = self.handles.get_mut(&handle) else { return Err(StatusCode::Failure) };
        if entries.is_empty() {
            return Err(StatusCode::Eof);
        }
        let at = entries.len().saturating_sub(DIR_BATCH);
        Ok(Name { id, files: entries.split_off(at) })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let rel = resolve(&filename)?;
        block_in_place(|| self.root.remove_file(&rel)).map_err(|e| status_of(&e))?;
        Ok(ok(id))
    }

    async fn mkdir(&mut self, id: u32, path: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        let rel = resolve(&path)?;
        if block_in_place(|| self.root.symlink_metadata(&rel)).is_ok() {
            return Err(StatusCode::Failure);
        }
        block_in_place(|| files::mkdirs(&self.root, &rel, self.inst.owner())).map_err(|_| StatusCode::Failure)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let rel = resolve(&path)?;
        if rel == Path::new(".") {
            return Err(StatusCode::PermissionDenied);
        }
        block_in_place(|| self.root.remove_dir(&rel)).map_err(|e| status_of(&e))?;
        Ok(ok(id))
    }

    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        let (from, to) = (resolve(&oldpath)?, resolve(&newpath)?);
        block_in_place(|| files::rename(&self.root, &from.to_string_lossy(), &to.to_string_lossy(), self.inst.owner()))
            .map_err(|_| StatusCode::Failure)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let rel = resolve(&path)?;
        let target = block_in_place(|| self.root.read_link(&rel)).map_err(|e| status_of(&e))?;
        Ok(Name { id, files: vec![File::dummy(target.to_string_lossy().into_owned())] })
    }

    // `symlink` is deliberately left unimplemented, so links cannot be created through SFTP.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside_the_server_folder() {
        let r = |p: &str| resolve(p).unwrap();
        assert_eq!(r("/"), PathBuf::from("."));
        assert_eq!(r(""), PathBuf::from("."));
        assert_eq!(r("."), PathBuf::from("."));
        assert_eq!(r("/world/level.dat"), PathBuf::from("world/level.dat"));
        assert_eq!(r("world/./a//b"), PathBuf::from("world/a/b"));
        assert_eq!(r("/a/../b"), PathBuf::from("b"));
        assert_eq!(r("../../../etc/shadow"), PathBuf::from("etc/shadow"), "`..` stops at the top");
        assert_eq!(r("/../.."), PathBuf::from("."));
        assert!(resolve("a\0b").is_err());
    }

    #[test]
    fn absolute_paths_are_what_clients_expect() {
        assert_eq!(absolute(Path::new(".")), "/");
        assert_eq!(absolute(Path::new("world/a")), "/world/a");
    }

    #[test]
    fn host_key_is_created_once_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let first = load_host_key(&path).unwrap();
        let second = load_host_key(&path).unwrap();
        assert_eq!(first.public_key(), second.public_key(), "the key must survive restarts");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
