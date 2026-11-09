//! Backups are built through `cap_std` for the same reason file access is: the
//! tree belongs to a possibly hostile server. Only regular files and directories
//! are archived or restored, so links can never be smuggled through a backup.

use crate::files::{self, Owner};
use anyhow::{bail, Context, Result};
use cap_fs_ext::DirExt;
use cap_std::fs::{Dir, PermissionsExt as _};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

const MAX_DEPTH: usize = 128;

/// Shared with the API so the panel can watch a backup while it runs.
#[derive(Debug, Default)]
pub struct Progress {
    pub done: AtomicU64,
    pub total: AtomicU64,
}

struct CountingReader<'a, R> {
    inner: R,
    progress: &'a Progress,
}

impl<R: Read> Read for CountingReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.progress.done.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Adds up regular files the same way the archive walk finds them.
pub fn measure(dir: &Dir, depth: usize) -> u64 {
    if depth > MAX_DEPTH {
        return 0;
    }
    let Ok(entries) = dir.entries() else { return 0 };
    entries
        .flatten()
        .map(|e| match e.file_type() {
            Ok(k) if k.is_dir() => dir.open_dir_nofollow(e.file_name()).map_or(0, |d| measure(&d, depth + 1)),
            Ok(k) if k.is_file() => e.metadata().map_or(0, |m| m.len()),
            _ => 0,
        })
        .sum()
}

pub fn create(root: &Dir, dest: &Path, progress: &Progress) -> Result<()> {
    progress.total.store(measure(root, 0), Ordering::Relaxed);
    let out = std::fs::File::create(dest).context("create backup file")?;
    let mut tar = tar::Builder::new(GzEncoder::new(out, Compression::fast()));
    tar.follow_symlinks(false);
    add_dir(&mut tar, root, Path::new(""), 0, progress)?;
    tar.into_inner()?.finish()?.sync_all()?;
    Ok(())
}

fn add_dir<W: io::Write>(tar: &mut tar::Builder<W>, dir: &Dir, prefix: &Path, depth: usize, progress: &Progress) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("directory tree is too deep to back up");
    }
    for entry in dir.entries()? {
        let entry = entry?;
        let name = PathBuf::from(entry.file_name());
        let rel = prefix.join(&name);
        let kind = entry.file_type()?;
        if kind.is_dir() {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Directory);
            h.set_size(0);
            h.set_mode(0o755);
            tar.append_data(&mut h, &rel, io::empty())?;
            let sub = dir.open_dir_nofollow(&name)?;
            add_dir(tar, &sub, &rel, depth + 1, progress)?;
        } else if kind.is_file() {
            // A file can vanish or change type mid-walk; a live server makes that normal.
            let Ok(file) = files::open_regular(dir, &name) else { continue };
            let meta = file.metadata()?;
            let size = meta.len();
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(size);
            h.set_mode(if meta.permissions().mode() & 0o111 != 0 { 0o755 } else { 0o644 });
            let mtime = meta.modified().ok().and_then(|t| t.into_std().duration_since(UNIX_EPOCH).ok());
            h.set_mtime(mtime.map_or(0, |d| d.as_secs()));
            // Exactly `size` bytes even if the server changes the file during the copy.
            let body = (&file).take(size).chain(io::repeat(0)).take(size);
            tar.append_data(&mut h, &rel, CountingReader { inner: body, progress })?;
        }
    }
    Ok(())
}

/// A server controls its file names, and a name like `..\\..\\evil` could write outside the
/// target folder when the zip is extracted on the operator's Windows machine.
fn zip_safe_name(name: &str) -> bool {
    !name.contains(['\\', ':', '/']) && !name.chars().any(char::is_control)
}

/// Writes `dir` to `out` as a zip whose entries start with `top`, for downloading a folder.
/// Only regular files and directories are included, so links can't pull in anything else.
pub fn zip_dir(dir: &Dir, top: &str, out: &mut std::fs::File) -> Result<()> {
    let mut zip = zip::ZipWriter::new(out);
    add_to_zip(&mut zip, dir, top, 0)?;
    zip.finish()?;
    Ok(())
}

fn add_to_zip<W: io::Write + io::Seek>(zip: &mut zip::ZipWriter<W>, dir: &Dir, prefix: &str, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("directory tree is too deep to zip");
    }
    // Fastest compression: this is for handing files over, not for storing them.
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).compression_level(Some(1));
    zip.add_directory(format!("{prefix}/"), options)?;
    for entry in dir.entries()? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str().filter(|n| zip_safe_name(n)) else { continue };
        let rel = format!("{prefix}/{name}");
        let kind = entry.file_type()?;
        if kind.is_dir() {
            add_to_zip(zip, &dir.open_dir_nofollow(name)?, &rel, depth + 1)?;
        } else if kind.is_file() {
            // A file can vanish or change type mid-walk; a live server makes that normal.
            let Ok(file) = files::open_regular(dir, Path::new(name)) else { continue };
            let size = file.metadata()?.len();
            zip.start_file(rel, options.large_file(size >= u64::from(u32::MAX)))?;
            // Capped, so a server appending as fast as it can't make this run forever.
            io::copy(&mut (&file).take(size), zip)?;
        }
    }
    Ok(())
}

/// Replaces the server's files. `max_bytes` stops an oversized archive from filling the disk.
pub fn restore(root: &Dir, archive: &Path, owner: Owner, max_bytes: u64) -> Result<()> {
    let file = std::fs::File::open(archive).context("open backup")?;
    files::clear(root).context("clear server files")?;
    let mut tar = tar::Archive::new(GzDecoder::new(file));
    let mut total = 0u64;
    for entry in tar.entries()? {
        let mut entry = entry?;
        let raw = entry.path()?.to_string_lossy().into_owned();
        let path = files::clean_nonroot(&raw).with_context(|| format!("unsafe path in backup: {raw}"))?;
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            files::mkdirs(root, &path, owner)?;
        } else if kind.is_file() {
            total = total.saturating_add(entry.size());
            if total > max_bytes {
                bail!("backup is larger than this server's disk limit");
            }
            let mode = if entry.header().mode().unwrap_or(0o644) & 0o111 != 0 { 0o755 } else { 0o644 };
            let mut out = files::create_owned(root, &path, owner, mode)?;
            io::copy(&mut entry, &mut out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn me() -> Owner {
        // SAFETY: these calls take no arguments and cannot fail.
        unsafe { Owner { uid: libc::getuid(), gid: libc::getgid() } }
    }

    #[test]
    fn round_trips_files_and_drops_links() {
        let (data, outside, store) =
            (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::write(outside.path().join("secret"), "s3cret").unwrap();
        std::fs::create_dir(data.path().join("world")).unwrap();
        std::fs::write(data.path().join("world/level.dat"), "level").unwrap();
        symlink(outside.path().join("secret"), data.path().join("evil")).unwrap();

        let root = files::open_root(data.path()).unwrap();
        let archive = store.path().join("b.tar.gz");
        let progress = Progress::default();
        create(&root, &archive, &progress).unwrap();
        // Only level.dat counts: the symlink's target is outside and never archived.
        assert_eq!(progress.total.load(Ordering::Relaxed), 5);
        assert_eq!(progress.done.load(Ordering::Relaxed), 5);

        std::fs::write(data.path().join("junk"), "junk").unwrap();
        restore(&root, &archive, me(), 1 << 20).unwrap();

        assert_eq!(std::fs::read_to_string(data.path().join("world/level.dat")).unwrap(), "level");
        assert!(!data.path().join("junk").exists(), "restore must replace, not merge");
        assert!(std::fs::symlink_metadata(data.path().join("evil")).is_err(), "links must not survive");
        assert_eq!(std::fs::read_to_string(outside.path().join("secret")).unwrap(), "s3cret");
    }

    #[test]
    fn zip_holds_only_safe_regular_files() {
        let (data, outside, store) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::write(outside.path().join("secret"), "s3cret").unwrap();
        std::fs::create_dir_all(data.path().join("world/region")).unwrap();
        std::fs::write(data.path().join("world/level.dat"), "level").unwrap();
        std::fs::write(data.path().join("world/region/r.0.0.mca"), "chunk").unwrap();
        symlink(outside.path().join("secret"), data.path().join("world/evil")).unwrap();
        symlink(outside.path(), data.path().join("world/evildir")).unwrap();
        std::fs::write(data.path().join("world/..\\..\\evil.bat"), "x").unwrap();
        std::fs::write(data.path().join("world/C:evil"), "x").unwrap();

        let root = files::open_root(data.path()).unwrap();
        let dir = root.open_dir_nofollow("world").unwrap();
        let path = store.path().join("w.zip");
        let mut out = std::fs::File::options().read(true).write(true).create_new(true).open(&path).unwrap();
        zip_dir(&dir, "world", &mut out).unwrap();
        drop(out);

        let mut zip = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
        let mut names: Vec<String> = zip.file_names().map(str::to_string).collect();
        names.sort();
        assert_eq!(names, ["world/", "world/level.dat", "world/region/", "world/region/r.0.0.mca"]);
        let mut text = String::new();
        zip.by_name("world/region/r.0.0.mca").unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, "chunk");
    }

    #[test]
    fn restore_refuses_traversal_and_oversize() {
        let (data, store) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let root = files::open_root(data.path()).unwrap();
        let archive = store.path().join("x.tar.gz");

        let write_archive = |path_bytes: &[u8], content: &[u8]| {
            let f = std::fs::File::create(&archive).unwrap();
            let mut b = tar::Builder::new(GzEncoder::new(f, Compression::fast()));
            let mut h = tar::Header::new_gnu();
            h.as_old_mut().name[..path_bytes.len()].copy_from_slice(path_bytes);
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append(&h, content).unwrap();
            b.into_inner().unwrap().finish().unwrap();
        };

        write_archive(b"../escape", b"x");
        assert!(restore(&root, &archive, me(), 1 << 20).is_err());
        assert!(!data.path().parent().unwrap().join("escape").exists());

        write_archive(b"big", &[0u8; 2048]);
        assert!(restore(&root, &archive, me(), 1024).is_err());
    }
}
