//! Runs in a freshly exec'd, single-threaded copy of `emberd`, so forking here
//! carries none of the risks of forking from the multi-threaded daemon.
//!
//! Order matters, and each step depends on privileges the next one removes:
//! join cgroup -> enter netns -> new namespaces -> fork into the PID namespace ->
//! build the filesystem -> pivot_root -> rlimits -> drop identity and capabilities ->
//! no_new_privs -> Landlock -> seccomp -> fork and exec the game.

use super::{seccomp, SandboxSpec, HOME, SPEC_ENV};
use landlock::{
    path_beneath_rules, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use std::ffi::CString;
use std::fs;
use std::io::{self, Error};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, DirBuilderExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

const ROOT: &str = "/run/ember/rootfs";

/// Entry point for `emberd __sandbox-init`. Never returns.
pub fn main() -> ! {
    let code = match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[ember] sandbox setup failed: {e}");
            125
        }
    };
    std::process::exit(code);
}

fn ctx<T>(r: io::Result<T>, what: &str) -> io::Result<T> {
    r.map_err(|e| Error::new(e.kind(), format!("{what}: {e}")))
}

fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(rc)
    }
}

fn cstr(s: impl AsRef<std::ffi::OsStr>) -> io::Result<CString> {
    CString::new(s.as_ref().as_bytes()).map_err(|_| Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))
}

fn run() -> io::Result<i32> {
    let raw = std::env::var(SPEC_ENV).map_err(|_| Error::other("missing sandbox spec"))?;
    let spec: SandboxSpec = serde_json::from_str(&raw).map_err(Error::other)?;

    ctx(fs::write(spec.cgroup_dir.join("cgroup.procs"), std::process::id().to_string()), "join cgroup")?;

    if let Some(ns) = &spec.netns {
        let f = ctx(fs::File::open(format!("/run/netns/{ns}")), "open netns")?;
        // SAFETY: `f` is a valid fd for the duration of the call.
        ctx(cvt(unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) }), "setns")?;
    }

    let flags = libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWCGROUP;
    // SAFETY: plain syscall with constant flags.
    ctx(cvt(unsafe { libc::unshare(flags) }), "unshare")?;

    // SAFETY: single-threaded, so the child has a consistent copy of everything.
    match cvt(unsafe { libc::fork() })? {
        0 => {
            let code = match pid1(&spec) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("[ember] sandbox setup failed: {e}");
                    125
                }
            };
            std::process::exit(code);
        }
        child => wait_for(child),
    }
}

/// Waits for `pid` and maps its result to a shell-style exit code.
fn wait_for(pid: libc::pid_t) -> io::Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a valid out-pointer.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(exit_code(status));
        }
        let e = Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
}

fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

fn pid1(spec: &SandboxSpec) -> io::Result<i32> {
    // SAFETY: valid buffer and length.
    ctx(
        cvt(unsafe { libc::sethostname(spec.hostname.as_ptr().cast(), spec.hostname.len()) }),
        "sethostname",
    )?;
    build_rootfs(spec)?;
    pivot()?;
    apply_rlimits(spec)?;
    close_extra_fds();
    drop_identity(spec)?;
    no_new_privs()?;
    apply_landlock()?;
    ctx(seccomp::install(), "seccomp")?;
    ctx(std::env::set_current_dir(HOME), "chdir home")?;

    // SAFETY: still single-threaded.
    match cvt(unsafe { libc::fork() })? {
        0 => {
            let e = exec(spec);
            eprintln!("[ember] failed to start {}: {e}", spec.argv.first().map_or("?", String::as_str));
            // SAFETY: immediate exit in the forked child without running destructors.
            unsafe { libc::_exit(127) }
        }
        game => reap_until(game),
    }
}

/// PID 1 duties: adopt orphans and leave once the game does. When PID 1 exits
/// the kernel kills everything left in the namespace.
fn reap_until(game: libc::pid_t) -> io::Result<i32> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        let rc = unsafe { libc::waitpid(-1, &mut status, 0) };
        if rc == game {
            return Ok(exit_code(status));
        }
        if rc < 0 {
            let e = Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINTR) {
                return Err(e);
            }
        }
    }
}

fn exec(spec: &SandboxSpec) -> Error {
    let build = || -> io::Result<(Vec<CString>, Vec<CString>)> {
        let argv = spec.argv.iter().map(cstr).collect::<io::Result<Vec<_>>>()?;
        let env = spec.env.iter().map(|(k, v)| cstr(format!("{k}={v}"))).collect::<io::Result<Vec<_>>>()?;
        Ok((argv, env))
    };
    let (argv, env) = match build() {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(prog) = argv.first() else {
        return Error::new(io::ErrorKind::InvalidInput, "empty argv");
    };
    let to_ptrs = |v: &[CString]| -> Vec<*const libc::c_char> {
        v.iter().map(|s| s.as_ptr()).chain(std::iter::once(std::ptr::null())).collect()
    };
    let (argp, envp) = (to_ptrs(&argv), to_ptrs(&env));
    // SAFETY: both arrays are NULL-terminated and their strings outlive the call.
    unsafe { libc::execve(prog.as_ptr(), argp.as_ptr(), envp.as_ptr()) };
    Error::last_os_error()
}

fn sys_mount(src: &str, dst: &Path, fstype: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> io::Result<()> {
    let src_c = cstr(src)?;
    let dst_c = cstr(dst)?;
    let fs_c = fstype.map(cstr).transpose()?;
    let data_c = data.map(cstr).transpose()?;
    // SAFETY: all pointers are NUL-terminated strings or null, alive across the call.
    let rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            dst_c.as_ptr(),
            fs_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            flags,
            data_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr().cast()),
        )
    };
    ctx(cvt(rc), &format!("mount {src} on {}", dst.display()))?;
    Ok(())
}

fn mkdirs(p: &Path, mode: u32) -> io::Result<()> {
    ctx(fs::DirBuilder::new().recursive(true).mode(mode).create(p), &format!("mkdir {}", p.display()))
}

/// Bind `src` at `dst` then harden it. Read-only and nosuid need a separate remount.
fn bind(src: &Path, dst: &Path, read_only: bool) -> io::Result<()> {
    sys_mount(&src.to_string_lossy(), dst, None, libc::MS_BIND, None)?;
    let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV;
    if read_only {
        flags |= libc::MS_RDONLY;
    }
    sys_mount("none", dst, None, flags, None)
}

/// Mirrors a system path. On merged-usr distros `/lib` and friends are
/// symlinks, so those must stay symlinks rather than becoming bind mounts.
fn mirror_ro(root: &Path, path: &str) -> io::Result<()> {
    let host = Path::new(path);
    let Ok(meta) = fs::symlink_metadata(host) else {
        return Ok(());
    };
    let dst = root.join(path.trim_start_matches('/'));
    if let Some(parent) = dst.parent() {
        mkdirs(parent, 0o755)?;
    }
    if meta.file_type().is_symlink() {
        return ctx(symlink(fs::read_link(host)?, &dst), &format!("symlink {path}"));
    }
    if meta.is_dir() {
        mkdirs(&dst, 0o755)?;
    } else {
        fs::write(&dst, b"")?;
    }
    bind(host, &dst, true)
}

fn build_rootfs(spec: &SandboxSpec) -> io::Result<()> {
    let root = Path::new(ROOT);
    let nosuid_nodev = libc::MS_NOSUID | libc::MS_NODEV;
    let no_exec = libc::MS_NOEXEC;

    // Without this, mounts made here could propagate back to the host.
    sys_mount("none", Path::new("/"), None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    mkdirs(root, 0o755)?;
    sys_mount("tmpfs", root, Some("tmpfs"), nosuid_nodev, Some("size=16m,mode=755"))?;

    for p in [
        "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc/ssl", "/etc/ca-certificates",
        "/etc/ld.so.cache", "/etc/localtime", "/etc/alternatives",
    ] {
        mirror_ro(root, p)?;
    }

    for b in &spec.ro_binds {
        let dst = root.join(b.dst.strip_prefix("/").unwrap_or(&b.dst));
        mkdirs(&dst, 0o755)?;
        bind(&b.src, &dst, true)?;
    }

    let home = root.join(HOME.trim_start_matches('/'));
    mkdirs(&home, 0o755)?;
    bind(&spec.data_dir, &home, false)?;

    // Writable /tmp keeps exec: the JVM extracts and dlopens native libraries there.
    let tmp = root.join("tmp");
    mkdirs(&tmp, 0o755)?;
    let tmp_opts = format!("size={}m,mode=1777", spec.tmp_mb);
    sys_mount("tmpfs", &tmp, Some("tmpfs"), nosuid_nodev, Some(&tmp_opts))?;

    let dev = root.join("dev");
    mkdirs(&dev, 0o755)?;
    sys_mount("tmpfs", &dev, Some("tmpfs"), libc::MS_NOSUID | no_exec, Some("size=64k,mode=755"))?;
    for node in ["null", "zero", "full", "random", "urandom"] {
        let dst = dev.join(node);
        fs::write(&dst, b"")?;
        let src = Path::new("/dev").join(node);
        // These must stay device-capable, so MS_NODEV is deliberately not set here.
        sys_mount(&src.to_string_lossy(), &dst, None, libc::MS_BIND, None)?;
        sys_mount("none", &dst, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | no_exec, None)?;
    }
    let shm = dev.join("shm");
    mkdirs(&shm, 0o755)?;
    let shm_opts = format!("size={}m,mode=1777", spec.tmp_mb.min(256));
    sys_mount("tmpfs", &shm, Some("tmpfs"), nosuid_nodev | no_exec, Some(&shm_opts))?;
    symlink("/proc/self/fd", dev.join("fd"))?;
    symlink("/proc/self/fd/0", dev.join("stdin"))?;
    symlink("/proc/self/fd/1", dev.join("stdout"))?;
    symlink("/proc/self/fd/2", dev.join("stderr"))?;

    let proc = root.join("proc");
    mkdirs(&proc, 0o555)?;
    sys_mount("proc", &proc, Some("proc"), nosuid_nodev | no_exec, Some("hidepid=2"))?;
    // /proc/sys goes read-only; sysrq and kernel memory views are masked outright.
    let sys = proc.join("sys");
    sys_mount(&sys.to_string_lossy(), &sys, None, libc::MS_BIND, None)?;
    sys_mount("none", &sys, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | nosuid_nodev | no_exec, None)?;
    for masked in ["kcore", "keys", "kallsyms", "sysrq-trigger", "kmsg", "timer_list", "sched_debug"] {
        let p = proc.join(masked);
        if p.exists() {
            sys_mount("/dev/null", &p, None, libc::MS_BIND, None)?;
        }
    }

    // A read-only view of only this server's cgroup lets the JVM size itself.
    let cg = root.join("sys/fs/cgroup");
    mkdirs(&cg, 0o755)?;
    sys_mount("cgroup2", &cg, Some("cgroup2"), nosuid_nodev | no_exec | libc::MS_RDONLY, None)?;

    write_etc(root, spec)
}

fn write_etc(root: &Path, spec: &SandboxSpec) -> io::Result<()> {
    let etc = root.join("etc");
    mkdirs(&etc, 0o755)?;
    let (uid, gid, host) = (spec.uid, spec.gid, &spec.hostname);
    fs::write(
        etc.join("passwd"),
        format!("root:x:0:0:root:/nonexistent:/usr/sbin/nologin\ncontainer:x:{uid}:{gid}:ember:{HOME}:/bin/sh\n"),
    )?;
    fs::write(etc.join("group"), format!("root:x:0:\ncontainer:x:{gid}:\n"))?;
    fs::write(etc.join("hostname"), format!("{host}\n"))?;
    fs::write(etc.join("hosts"), format!("127.0.0.1 localhost {host}\n::1 localhost\n"))?;
    fs::write(etc.join("nsswitch.conf"), "passwd: files\ngroup: files\nhosts: files dns\n")?;
    let dns: String = spec.dns.iter().map(|d| format!("nameserver {d}\n")).collect();
    fs::write(etc.join("resolv.conf"), dns)?;
    Ok(())
}

fn pivot() -> io::Result<()> {
    let root = Path::new(ROOT);
    let old = root.join(".old");
    mkdirs(&old, 0o700)?;
    ctx(std::env::set_current_dir(root), "chdir rootfs")?;
    let (new_c, old_c) = (cstr(".")?, cstr(".old")?);
    // SAFETY: both strings are valid for the call.
    ctx(cvt(unsafe { libc::syscall(libc::SYS_pivot_root, new_c.as_ptr(), old_c.as_ptr()) } as i32), "pivot_root")?;
    // SAFETY: as above. MNT_DETACH drops the host filesystem from this namespace.
    ctx(cvt(unsafe { libc::umount2(old_c.as_ptr(), libc::MNT_DETACH) }), "detach old root")?;
    ctx(fs::remove_dir(".old"), "remove old root")?;
    ctx(std::env::set_current_dir("/"), "chdir /")?;
    // The skeleton never changes after this point.
    let flags = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
    sys_mount("none", Path::new("/"), None, flags, None)
}

#[cfg(target_env = "musl")]
type RlimitResource = libc::c_int;
#[cfg(not(target_env = "musl"))]
type RlimitResource = libc::__rlimit_resource_t;

fn set_rlimit(res: RlimitResource, soft: u64, hard: u64) -> io::Result<()> {
    let lim = libc::rlimit { rlim_cur: soft, rlim_max: hard };
    // SAFETY: `lim` is a valid pointer for the call.
    cvt(unsafe { libc::setrlimit(res, &lim) })?;
    Ok(())
}

fn apply_rlimits(spec: &SandboxSpec) -> io::Result<()> {
    set_rlimit(libc::RLIMIT_CORE, 0, 0)?;
    set_rlimit(libc::RLIMIT_NOFILE, 65_536, 65_536)?;
    // A hard cap on any one file, independent of the periodic disk usage scan.
    set_rlimit(libc::RLIMIT_FSIZE, spec.file_size_limit, spec.file_size_limit)
}

fn close_extra_fds() {
    // SAFETY: closes only descriptors the game must not inherit.
    unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
}

fn drop_identity(spec: &SandboxSpec) -> io::Result<()> {
    if spec.uid == 0 || spec.gid == 0 {
        return Err(Error::new(io::ErrorKind::InvalidInput, "refusing to run a server as root"));
    }
    // The bounding set must go first: clearing it needs CAP_SETPCAP.
    for cap in 0..64 {
        // SAFETY: EINVAL for capabilities unknown to this kernel is expected.
        unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
    }
    // SAFETY: plain syscalls with scalar args; a null list with size 0 clears groups.
    unsafe {
        libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong, 0, 0, 0);
        ctx(cvt(libc::setgroups(0, std::ptr::null())), "setgroups")?;
        ctx(cvt(libc::setresgid(spec.gid, spec.gid, spec.gid)), "setresgid")?;
        // Leaving uid 0 this way clears effective and permitted capabilities.
        ctx(cvt(libc::setresuid(spec.uid, spec.uid, spec.uid)), "setresuid")?;
    }
    // Verify rather than assume: a failed drop must never start the game.
    // SAFETY: these calls take no pointers.
    let still_root = unsafe { libc::setuid(0) == 0 || libc::geteuid() == 0 || libc::getegid() == 0 };
    if still_root {
        return Err(Error::other("privilege drop did not take effect"));
    }
    Ok(())
}

fn no_new_privs() -> io::Result<()> {
    // SAFETY: scalar args only.
    cvt(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) })?;
    // Keeps same-uid processes from opening this process's /proc entries.
    // SAFETY: scalar args only.
    cvt(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) })?;
    Ok(())
}

/// Second, independent filesystem layer. BestEffort so older kernels still run,
/// with the mount namespace as the primary boundary. `emberd doctor` reports support.
fn apply_landlock() -> io::Result<()> {
    let abi = ABI::V3;
    let read_exec = AccessFs::from_read(abi);
    let all = AccessFs::from_all(abi);
    let existing = |paths: &[&'static str]| -> Vec<&'static str> {
        paths.iter().copied().filter(|p| Path::new(p).exists()).collect()
    };
    let map_err = |e: landlock::RulesetError| Error::other(format!("landlock: {e}"));
    Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all)
        .map_err(map_err)?
        .create()
        .map_err(map_err)?
        .add_rules(path_beneath_rules(existing(&["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/etc", "/proc", "/sys"]), read_exec))
        .map_err(map_err)?
        .add_rules(path_beneath_rules(existing(&[HOME, "/tmp", "/dev"]), all))
        .map_err(map_err)?
        .restrict_self()
        .map_err(map_err)?;
    Ok(())
}
