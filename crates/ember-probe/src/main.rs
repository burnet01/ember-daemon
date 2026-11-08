//! Plays the part of a compromised game server. Run inside an Ember sandbox by CI,
//! it attempts real escapes and exits non-zero if any of them work, or if something
//! a game server legitimately needs is broken.
//!
//! Modes: default runs the full check. `--thread-bomb` and `--memory-bomb` test limits.
//! Options: `--secret <path>`, `--deny <ip:port>` (repeatable), `--internet <ip:port>`.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ember-probe only runs on Linux.");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Error;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    struct Report {
        failures: u32,
    }

    impl Report {
        fn check(&mut self, name: &str, ok: bool, detail: String) {
            println!("{} {name}{}", if ok { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" ({detail})") });
            if !ok {
                self.failures += 1;
            }
        }

        /// The syscall must fail. `rc` is its return value, read with errno immediately after.
        fn denied(&mut self, name: &str, rc: i64) {
            let e = Error::last_os_error();
            self.check(name, rc < 0, format!("rc={rc} {e}"));
        }
    }

    fn opt_all(args: &[String], key: &str) -> Vec<String> {
        args.windows(2).filter(|w| w[0] == key).map(|w| w[1].clone()).collect()
    }

    fn proc_status_field(name: &str) -> String {
        fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
            .unwrap_or_default()
    }

    fn identity(r: &mut Report) {
        // SAFETY: these calls take no pointers and have no failure modes that matter here.
        let (uid, euid, gid) = unsafe { (libc::getuid(), libc::geteuid(), libc::getgid()) };
        r.check("not root", uid != 0 && euid != 0 && gid != 0, format!("uid={uid} gid={gid}"));
        // SAFETY: as above.
        r.denied("setuid(0) refused", i64::from(unsafe { libc::setuid(0) }));
        let caps = proc_status_field("CapEff:");
        r.check("no effective capabilities", !caps.is_empty() && caps.chars().all(|c| c == '0'), caps);
        let bnd = proc_status_field("CapBnd:");
        r.check("capability bounding set empty", !bnd.is_empty() && bnd.chars().all(|c| c == '0'), bnd);
        let nnp = proc_status_field("NoNewPrivs:");
        r.check("no_new_privs set", nnp == "1", nnp);
        let sc = proc_status_field("Seccomp:");
        r.check("seccomp filter active", sc == "2", sc);
    }

    fn filesystem(r: &mut Report, args: &[String]) {
        r.check("/etc/shadow is absent", fs::read("/etc/shadow").is_err(), String::new());
        r.check("host /root is absent", fs::read_dir("/root").is_err(), String::new());
        r.check("host /var is absent", fs::read_dir("/var").is_err(), String::new());
        r.check("host /run is absent", fs::read_dir("/run").is_err(), String::new());
        for secret in opt_all(args, "--secret") {
            r.check(&format!("host secret {secret} is absent"), fs::read(&secret).is_err(), String::new());
        }
        for target in ["/usr/ember-pwned", "/etc/ember-pwned", "/ember-pwned", "/bin/ember-pwned", "/proc/sys/kernel/hostname"] {
            r.check(&format!("{target} is not writable"), fs::write(target, "x").is_err(), String::new());
        }
        let node = c"/home/container/fake-disk";
        // SAFETY: valid NUL-terminated path; the call only creates a filesystem node.
        let rc = unsafe { libc::mknod(node.as_ptr(), libc::S_IFBLK | 0o600, libc::makedev(8, 0)) };
        r.denied("mknod of a block device refused", i64::from(rc));
        r.check("/proc/1 is hidden or unreadable", fs::read("/proc/1/mem").is_err(), String::new());
        r.check("kernel memory is masked", fs::read("/proc/kcore").map_or(true, |d| d.is_empty()), String::new());
    }

    fn pid_namespace(r: &mut Report) {
        // SAFETY: takes no arguments.
        let pid = unsafe { libc::getpid() };
        r.check("inside a PID namespace", pid < 64, format!("pid={pid}"));
        let visible = fs::read_dir("/proc")
            .map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit())).count())
            .unwrap_or(usize::MAX);
        r.check("host processes are not visible", visible < 8, format!("{visible} visible"));
        let host = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
        r.check("hostname is isolated", host.trim() == "ember", host.trim().to_string());
    }

    fn syscalls(r: &mut Report) {
        let (none, tmp, tmpfs) = (c"none", c"/tmp", c"tmpfs");
        // SAFETY: each call receives valid pointers or scalars, and every one is expected to be refused.
        unsafe {
            r.denied("mount refused", i64::from(libc::mount(none.as_ptr(), tmp.as_ptr(), tmpfs.as_ptr(), 0, std::ptr::null())));
            r.denied("umount refused", i64::from(libc::umount2(tmp.as_ptr(), libc::MNT_DETACH)));
            r.denied("chroot refused", i64::from(libc::chroot(tmp.as_ptr())));
            r.denied("user namespace refused", i64::from(libc::unshare(libc::CLONE_NEWUSER)));
            r.denied("mount namespace refused", i64::from(libc::unshare(libc::CLONE_NEWNS)));
            r.denied("clone into a new namespace refused", libc::syscall(libc::SYS_clone, i64::from(libc::CLONE_NEWUSER), 0, 0, 0, 0));
            r.denied("clone3 refused", libc::syscall(libc::SYS_clone3, 0, 0));
            r.denied("ptrace refused", libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0));
            r.denied("bpf refused", libc::syscall(libc::SYS_bpf, 0, 0, 0));
            r.denied("io_uring refused", libc::syscall(libc::SYS_io_uring_setup, 1, 0));
            r.denied("perf_event_open refused", libc::syscall(libc::SYS_perf_event_open, 0, 0, -1, -1, 0));
            r.denied("userfaultfd refused", libc::syscall(libc::SYS_userfaultfd, 0));
            r.denied("kernel keyring refused", libc::syscall(libc::SYS_keyctl, 0, 0, 0, 0, 0));
            r.denied("kernel module load refused", libc::syscall(libc::SYS_finit_module, -1, 0, 0));
            r.denied("reboot refused", libc::syscall(libc::SYS_reboot, 0, 0, 0, 0));
            r.denied("open_by_handle_at refused", libc::syscall(libc::SYS_open_by_handle_at, -1, 0, 0));
            r.denied("raw packet socket refused", i64::from(libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0)));
            r.denied("kernel crypto socket refused", i64::from(libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0)));
            #[cfg(target_arch = "x86_64")]
            r.denied("x32 syscall bypass refused", libc::syscall(0x4000_0000 | libc::SYS_getpid));
        }
    }

    fn connects(addr: &str) -> Option<bool> {
        let parsed: SocketAddr = addr.parse().ok()?;
        Some(TcpStream::connect_timeout(&parsed, Duration::from_secs(3)).is_ok())
    }

    fn network(r: &mut Report, args: &[String]) {
        let always = [
            "100.100.100.100:53",
            "100.64.0.1:8787",
            "169.254.169.254:80",
            "192.168.0.1:80",
            "10.0.0.1:80",
            "172.16.0.1:80",
        ];
        let extra = opt_all(args, "--deny");
        for addr in always.iter().map(|s| s.to_string()).chain(extra) {
            r.check(&format!("{addr} is unreachable"), connects(&addr) == Some(false), String::new());
        }
    }

    /// Isolation that breaks the game is not a win, so these must keep working.
    fn usability(r: &mut Report, args: &[String]) {
        let f = "/home/container/ember-write-test";
        r.check("home is writable", fs::write(f, "ok").is_ok(), String::new());
        r.check("home is readable", fs::read_to_string(f).is_ok_and(|s| s == "ok"), String::new());
        let _ = fs::remove_file(f);
        r.check("/tmp is writable", fs::write("/tmp/ember-write-test", "ok").is_ok(), String::new());
        r.check("system libraries are readable", fs::read_dir("/usr/lib").is_ok(), String::new());
        let mut buf = [0u8; 8];
        let got = fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf));
        r.check("/dev/urandom is readable", got.is_ok(), String::new());
        let thread = std::thread::Builder::new().spawn(|| 7).map(|h| h.join().unwrap_or(0));
        r.check("threads can be created", thread.is_ok_and(|v| v == 7), String::new());
        let listener = std::net::TcpListener::bind("0.0.0.0:39876");
        r.check("game port can be bound", listener.is_ok(), String::new());
        let child = std::process::Command::new("/bin/sh").args(["-c", "exit 0"]).status();
        r.check("programs can be executed", child.is_ok_and(|s| s.success()), String::new());
        for addr in opt_all(args, "--internet") {
            r.check(&format!("public internet {addr} is reachable"), connects(&addr) == Some(true), String::new());
        }
    }

    fn thread_bomb() -> ! {
        let mut count = 0u32;
        loop {
            let spawned = std::thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(|| std::thread::sleep(Duration::from_secs(120)));
            if spawned.is_err() {
                break;
            }
            count += 1;
            if count > 100_000 {
                break;
            }
        }
        println!("THREADS {count}");
        std::process::exit(0);
    }

    fn memory_bomb() -> ! {
        let mut hoard: Vec<Vec<u8>> = Vec::new();
        for _ in 0..20_000 {
            hoard.push(vec![1u8; 1024 * 1024]);
        }
        println!("SURVIVED {} MB", hoard.len());
        std::process::exit(0);
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.iter().any(|a| a == "--thread-bomb") {
            thread_bomb();
        }
        if args.iter().any(|a| a == "--memory-bomb") {
            memory_bomb();
        }
        let mut r = Report { failures: 0 };
        identity(&mut r);
        filesystem(&mut r, &args);
        pid_namespace(&mut r);
        syscalls(&mut r);
        network(&mut r, &args);
        usability(&mut r, &args);
        println!("RESULT failures={}", r.failures);
        std::process::exit(if r.failures == 0 { 0 } else { 1 });
    }
}
