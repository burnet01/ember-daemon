//! Safe access to a server's files from the root-privileged daemon.
//!
//! The directory tree is controlled by a possibly compromised game server. Plain
//! path joins would let a planted symlink trick the daemon into reading or
//! overwriting host files, so all access goes through `cap_std::Dir`, which
//! resolves every component beneath the root and refuses to leave it.

use anyhow::{anyhow, bail, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions, OpenOptionsExt as _, PermissionsExt as _};
use ember_proto::FileEntry;
use std::io::{Read, Write};
use std::os::unix::fs::fchown;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

pub const MAX_EDIT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

pub fn open_root(path: &Path) -> Result<Dir> {
    Dir::open_ambient_dir(path, ambient_authority()).with_context(|| format!("open {}", path.display()))
}

/// Normalises an API path. Rejects anything that is not a plain relative path.
pub fn clean(rel: &str) -> Result<PathBuf> {
    if rel.contains('\0') || rel.contains('\\') {
        bail!("invalid path");
    }
    let mut out = PathBuf::new();
    for c in Path::new(rel.trim_start_matches('/')).components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            _ => bail!("invalid path"),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    Ok(out)
}

pub fn clean_nonroot(rel: &str) -> Result<PathBuf> {
    let p = clean(rel)?;
    if p == Path::new(".") {
        bail!("this operation cannot target the server root");
    }
    Ok(p)
}

fn read_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    // O_NONBLOCK so a planted FIFO cannot hang the daemon; the type is checked after open.
    o.read(true).custom_flags(libc::O_NONBLOCK).follow(FollowSymlinks::No);
    o
}

fn write_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(false).custom_flags(libc::O_NONBLOCK).follow(FollowSymlinks::No);
    o
}

/// Opens a regular file for reading. Refuses symlinks, FIFOs and devices.
pub fn open_regular(root: &Dir, path: &Path) -> Result<File> {
    let f = root.open_with(path, &read_options()).context("open file")?;
    if !f.metadata()?.is_file() {
        bail!("not a regular file");
    }
    Ok(f)
}

pub fn list(root: &Dir, rel: &str) -> Result<Vec<FileEntry>> {
    let path = clean(rel)?;
    let mut entries = Vec::new();
    for e in root.read_dir(&path).context("read directory")? {
        let e = e?;
        let Ok(m) = e.metadata() else { continue };
        let is_symlink = e.file_type()?.is_symlink();
        entries.push(FileEntry {
            name: e.file_name().to_string_lossy().into_owned(),
            is_dir: m.is_dir(),
            is_symlink,
            size: m.len(),
            modified: m
                .modified()
                .ok()
                .and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs()),
        });
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(entries)
}

pub fn read_text(root: &Dir, rel: &str) -> Result<(String, u64)> {
    let path = clean_nonroot(rel)?;
    let f = open_regular(root, &path)?;
    let size = f.metadata()?.len();
    if size > MAX_EDIT_BYTES {
        bail!("file is too large to edit here; download it instead");
    }
    let mut buf = Vec::with_capacity(size as usize);
    f.take(MAX_EDIT_BYTES).read_to_end(&mut buf)?;
    let text = String::from_utf8(buf).map_err(|_| anyhow!("this looks like a binary file; download it instead"))?;
    Ok((text, size))
}

/// Creates each missing directory and hands it to the server's user.
pub fn mkdirs(root: &Dir, rel: &Path, owner: Owner) -> Result<()> {
    let mut cur = PathBuf::new();
    for c in rel.components() {
        let Component::Normal(name) = c else { continue };
        cur.push(name);
        match root.create_dir(&cur) {
            Ok(()) => {
                let d = root.open_dir_nofollow(&cur).context("open directory")?;
                fchown(&d, Some(owner.uid), Some(owner.gid))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).context("create directory"),
        }
    }
    Ok(())
}

pub fn make_dir(root: &Dir, rel: &str, owner: Owner) -> Result<()> {
    mkdirs(root, &clean_nonroot(rel)?, owner)
}

/// Writes a file owned by the server's user. Refuses to write through a symlink.
pub fn write_bytes(root: &Dir, path: &Path, data: &[u8], owner: Owner, mode: u32) -> Result<()> {
    let mut f = create_owned(root, path, owner, mode)?;
    f.write_all(data)?;
    f.flush()?;
    Ok(())
}

/// Opens a file for overwriting and hands it to the server's user.
pub fn create_owned(root: &Dir, path: &Path, owner: Owner, mode: u32) -> Result<File> {
    if let Some(parent) = path.parent() {
        mkdirs(root, parent, owner)?;
    }
    let f = root.open_with(path, &write_options()).context("open file for writing")?;
    if !f.metadata()?.is_file() {
        bail!("not a regular file");
    }
    fchown(&f, Some(owner.uid), Some(owner.gid))?;
    f.set_len(0)?;
    f.set_permissions(cap_std::fs::Permissions::from_mode(mode))?;
    Ok(f)
}

pub fn write_text(root: &Dir, rel: &str, content: &str, owner: Owner) -> Result<()> {
    if content.len() as u64 > MAX_EDIT_BYTES {
        bail!("file is too large to save here");
    }
    write_bytes(root, &clean_nonroot(rel)?, content.as_bytes(), owner, 0o644)
}

pub fn remove(root: &Dir, rel: &str) -> Result<()> {
    let path = clean_nonroot(rel)?;
    let meta = root.symlink_metadata(&path).context("find file")?;
    if meta.is_dir() {
        root.remove_dir_all(&path).context("remove directory")
    } else {
        root.remove_file(&path).context("remove file")
    }
}

pub fn rename(root: &Dir, from: &str, to: &str, owner: Owner) -> Result<()> {
    let (from, to) = (clean_nonroot(from)?, clean_nonroot(to)?);
    if let Some(parent) = to.parent() {
        mkdirs(root, parent, owner)?;
    }
    root.rename(&from, root, &to).context("rename")
}

/// Removes everything inside `root`, leaving the directory itself.
pub fn clear(root: &Dir) -> Result<()> {
    for e in root.entries()? {
        let e = e?;
        let name = e.file_name();
        if e.file_type()?.is_dir() {
            root.remove_dir_all(&name)?;
        } else {
            root.remove_file(&name)?;
        }
    }
    Ok(())
}

/// Forces the configured game port on each start. Forwarding targets this port,
/// so a stale value in the file would make a running server unreachable.
pub fn enforce_property(root: &Dir, key: &str, value: &str, owner: Owner) -> Result<()> {
    let path = Path::new("server.properties");
    let existing = match open_regular(root, path) {
        Ok(mut f) => {
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap_or_default();
            s
        }
        Err(_) => String::new(),
    };
    write_bytes(root, path, set_property(&existing, key, value).as_bytes(), owner, 0o644)
}

fn set_property(text: &str, key: &str, value: &str) -> String {
    let wanted = format!("{key}={value}");
    let mut found = false;
    let mut lines: Vec<String> = text
        .lines()
        .map(|l| {
            if l.split('=').next().map(str::trim) == Some(key) {
                found = true;
                wanted.clone()
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        lines.push(wanted);
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Owned by the current test user, so tests also pass without root.
    fn me() -> Owner {
        // SAFETY: these calls take no arguments and cannot fail.
        unsafe { Owner { uid: libc::getuid(), gid: libc::getgid() } }
    }

    fn setup() -> (tempfile::TempDir, tempfile::TempDir, Dir) {
        let (data, secret) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::write(secret.path().join("shadow"), "root:hash").unwrap();
        let root = open_root(data.path()).unwrap();
        (data, secret, root)
    }

    #[test]
    fn clean_rejects_traversal() {
        assert_eq!(clean("a/./b").unwrap(), PathBuf::from("a/b"));
        assert_eq!(clean("/a").unwrap(), PathBuf::from("a"));
        assert_eq!(clean("").unwrap(), PathBuf::from("."));
        for bad in ["../x", "a/../../x", "a\0b", "..\\x"] {
            assert!(clean(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn symlink_to_host_file_cannot_be_read_or_overwritten() {
        let (data, secret, root) = setup();
        let target = secret.path().join("shadow");
        symlink(&target, data.path().join("evil")).unwrap();
        assert!(read_text(&root, "evil").is_err());
        assert!(write_text(&root, "evil", "pwned", me()).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "root:hash");
    }

    #[test]
    fn symlinked_directory_cannot_leave_the_root() {
        let (data, secret, root) = setup();
        symlink(secret.path(), data.path().join("evildir")).unwrap();
        assert!(list(&root, "evildir").is_err());
        assert!(read_text(&root, "evildir/shadow").is_err());
        assert!(write_text(&root, "evildir/new", "x", me()).is_err());
        assert!(!secret.path().join("new").exists());
    }

    #[test]
    fn removing_a_symlink_keeps_its_target() {
        let (data, secret, root) = setup();
        symlink(secret.path(), data.path().join("evildir")).unwrap();
        remove(&root, "evildir").unwrap();
        assert!(secret.path().join("shadow").exists());
    }

    #[test]
    fn fifo_does_not_hang_reads() {
        let (data, _secret, root) = setup();
        let p = std::ffi::CString::new(data.path().join("pipe").to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(p.as_ptr(), 0o644) }, 0);
        assert!(read_text(&root, "pipe").is_err());
    }

    #[test]
    fn round_trips_and_lists_files() {
        let (_data, _secret, root) = setup();
        write_text(&root, "plugins/a.yml", "hello", me()).unwrap();
        assert_eq!(read_text(&root, "plugins/a.yml").unwrap().0, "hello");
        let top = list(&root, "").unwrap();
        assert_eq!(top[0].name, "plugins");
        assert!(top[0].is_dir);
        rename(&root, "plugins/a.yml", "plugins/b.yml", me()).unwrap();
        assert_eq!(list(&root, "plugins").unwrap()[0].name, "b.yml");
    }

    #[test]
    fn root_is_protected_from_destructive_calls() {
        let (_data, _secret, root) = setup();
        assert!(remove(&root, "").is_err());
        assert!(remove(&root, ".").is_err());
        assert!(rename(&root, ".", "x", me()).is_err());
    }

    #[test]
    fn set_property_replaces_or_appends() {
        assert_eq!(set_property("a=1\nserver-port=1\n", "server-port", "25565"), "a=1\nserver-port=25565\n");
        assert_eq!(set_property("#c\n", "server-port", "25565"), "#c\nserver-port=25565\n");
        assert_eq!(set_property("server-port-v6=1\n", "server-port", "2"), "server-port-v6=1\nserver-port=2\n");
    }
}
