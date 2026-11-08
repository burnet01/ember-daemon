//! A hand-assembled classic-BPF seccomp filter.
//!
//! It is written directly, rather than through a helper crate, because it needs
//! three things most helpers cannot express: rejecting the x32 syscall range,
//! inspecting `clone` flags, and filtering `socket` families.

use libc::{c_long, c_uint, sock_filter, sock_fprog};

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
#[cfg(target_arch = "x86_64")]
const BPF_JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const BPF_JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_low(i: u32) -> u32 {
    16 + i * 8
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Any of these flags would create a new namespace.
const CLONE_NS_MASK: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWCGROUP) as u32;

const fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter { code, jt: 0, jf: 0, k }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

fn denied_syscalls() -> Vec<c_long> {
    #[allow(unused_mut)]
    let mut v = vec![
        // Namespaces and mounts: the sandbox must not rearrange its own view.
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
        // Reaching into other processes.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        libc::SYS_pidfd_getfd,
        // Large kernel attack surface a game server has no use for.
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        // Host administration.
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_clock_adjtime,
        libc::SYS_adjtimex,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        libc::SYS_syslog,
        // File-handle tricks that walk around path checks.
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend_from_slice(&[libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_modify_ldt, libc::SYS_uselib]);
    v
}

/// Socket families with no legitimate use here and a poor security history.
const DENIED_SOCKET_FAMILIES: &[c_uint] = &[
    libc::AF_ALG as c_uint,
    libc::AF_VSOCK as c_uint,
    libc::AF_PACKET as c_uint,
    libc::AF_KEY as c_uint,
    libc::AF_BLUETOOTH as c_uint,
    libc::AF_TIPC as c_uint,
    libc::AF_RDS as c_uint,
    libc::AF_XDP as c_uint,
    libc::AF_NFC as c_uint,
];

pub fn build_filter() -> Vec<sock_filter> {
    let eperm = RET_ERRNO | libc::EPERM as u32;
    let enosys = RET_ERRNO | libc::ENOSYS as u32;
    let mut f = Vec::with_capacity(128);

    // Kill anything entering through a foreign architecture's syscall table.
    f.push(stmt(BPF_LD_W_ABS, OFF_ARCH));
    f.push(jump(BPF_JEQ_K, AUDIT_ARCH, 1, 0));
    f.push(stmt(BPF_RET_K, RET_KILL_PROCESS));

    f.push(stmt(BPF_LD_W_ABS, OFF_NR));

    // x32 shares AUDIT_ARCH_X86_64, so its range has to be rejected by number.
    #[cfg(target_arch = "x86_64")]
    {
        f.push(jump(BPF_JGE_K, X32_SYSCALL_BIT, 0, 1));
        f.push(stmt(BPF_RET_K, enosys));
    }

    for nr in denied_syscalls() {
        f.push(jump(BPF_JEQ_K, nr as u32, 0, 1));
        f.push(stmt(BPF_RET_K, eperm));
    }

    // clone3 passes flags through a pointer BPF cannot read. ENOSYS makes glibc
    // fall back to clone, whose flags are visible in a register.
    f.push(jump(BPF_JEQ_K, libc::SYS_clone3 as u32, 0, 1));
    f.push(stmt(BPF_RET_K, enosys));

    f.push(jump(BPF_JEQ_K, libc::SYS_clone as u32, 0, 4));
    f.push(stmt(BPF_LD_W_ABS, off_arg_low(CLONE_FLAGS_ARG)));
    f.push(jump(BPF_JSET_K, CLONE_NS_MASK, 0, 1));
    f.push(stmt(BPF_RET_K, eperm));
    f.push(stmt(BPF_RET_K, RET_ALLOW));

    // TIOCSTI / TIOCLINUX can inject keystrokes into a controlling terminal.
    f.push(jump(BPF_JEQ_K, libc::SYS_ioctl as u32, 0, 5));
    f.push(stmt(BPF_LD_W_ABS, off_arg_low(1)));
    f.push(jump(BPF_JEQ_K, libc::TIOCSTI as u32, 1, 0));
    f.push(jump(BPF_JEQ_K, libc::TIOCLINUX as u32, 0, 1));
    f.push(stmt(BPF_RET_K, eperm));
    f.push(stmt(BPF_RET_K, RET_ALLOW));

    f.push(jump(BPF_JEQ_K, libc::SYS_socket as u32, 0, (DENIED_SOCKET_FAMILIES.len() * 2 + 2) as u8));
    f.push(stmt(BPF_LD_W_ABS, off_arg_low(0)));
    for fam in DENIED_SOCKET_FAMILIES {
        f.push(jump(BPF_JEQ_K, *fam, 0, 1));
        f.push(stmt(BPF_RET_K, eperm));
    }
    f.push(stmt(BPF_RET_K, RET_ALLOW));

    f.push(stmt(BPF_RET_K, RET_ALLOW));
    f
}

/// `clone(flags, ...)` keeps its flags in the first argument on both supported architectures.
const CLONE_FLAGS_ARG: u32 = 0;

/// Installs the filter on the calling thread. `no_new_privs` must already be set.
pub fn install() -> std::io::Result<()> {
    let filter = build_filter();
    let prog = sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut sock_filter };
    // SAFETY: `prog` and the filter it points at outlive the call; the kernel copies them.
    let rc = unsafe {
        libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER as libc::c_ulong, &prog as *const sock_fprog)
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal interpreter for the opcodes the filter uses, so its decision
    /// logic can be tested without installing it.
    fn eval(prog: &[sock_filter], nr: u32, arch: u32, args: [u32; 6]) -> u32 {
        let (mut pc, mut a) = (0usize, 0u32);
        loop {
            let i = &prog[pc];
            match i.code {
                BPF_LD_W_ABS => {
                    a = match i.k {
                        OFF_NR => nr,
                        OFF_ARCH => arch,
                        k if k >= 16 => args[((k - 16) / 8) as usize],
                        k => panic!("unexpected load offset {k}"),
                    };
                    pc += 1;
                }
                BPF_RET_K => return i.k,
                code => {
                    let taken = match code {
                        BPF_JEQ_K => a == i.k,
                        0x35 => a >= i.k,
                        BPF_JSET_K => a & i.k != 0,
                        other => panic!("unexpected opcode {other:#x}"),
                    };
                    pc += 1 + if taken { i.jt as usize } else { i.jf as usize };
                }
            }
        }
    }

    fn check(nr: c_long, args: [u32; 6]) -> u32 {
        eval(&build_filter(), nr as u32, AUDIT_ARCH, args)
    }

    #[test]
    fn program_fits_and_jumps_stay_in_bounds() {
        let p = build_filter();
        assert!(p.len() < u16::MAX as usize);
        for (i, ins) in p.iter().enumerate() {
            if ins.code != BPF_LD_W_ABS && ins.code != BPF_RET_K {
                assert!(i + 1 + (ins.jt as usize) < p.len());
                assert!(i + 1 + (ins.jf as usize) < p.len());
            }
        }
    }

    #[test]
    fn foreign_arch_is_killed() {
        assert_eq!(eval(&build_filter(), 0, 0x4000_0003, [0; 6]), RET_KILL_PROCESS);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_range_is_rejected() {
        let r = eval(&build_filter(), X32_SYSCALL_BIT | libc::SYS_mount as u32, AUDIT_ARCH, [0; 6]);
        assert_eq!(r, RET_ERRNO | libc::ENOSYS as u32);
    }

    #[test]
    fn dangerous_syscalls_are_denied() {
        for nr in [libc::SYS_mount, libc::SYS_ptrace, libc::SYS_bpf, libc::SYS_unshare, libc::SYS_io_uring_setup] {
            assert_eq!(check(nr, [0; 6]), RET_ERRNO | libc::EPERM as u32, "syscall {nr}");
        }
    }

    #[test]
    fn everyday_syscalls_are_allowed() {
        for nr in [libc::SYS_read, libc::SYS_write, libc::SYS_futex, libc::SYS_execve, libc::SYS_mmap] {
            assert_eq!(check(nr, [0; 6]), RET_ALLOW, "syscall {nr}");
        }
    }

    #[test]
    fn clone_is_filtered_by_flags() {
        let thread = (libc::CLONE_VM | libc::CLONE_THREAD | libc::CLONE_SIGHAND) as u32;
        assert_eq!(check(libc::SYS_clone, [thread, 0, 0, 0, 0, 0]), RET_ALLOW);
        let userns = libc::CLONE_NEWUSER as u32;
        assert_eq!(check(libc::SYS_clone, [userns, 0, 0, 0, 0, 0]), RET_ERRNO | libc::EPERM as u32);
        assert_eq!(check(libc::SYS_clone3, [0; 6]), RET_ERRNO | libc::ENOSYS as u32);
    }

    #[test]
    fn ioctl_blocks_only_terminal_injection() {
        assert_eq!(check(libc::SYS_ioctl, [1, libc::TIOCSTI as u32, 0, 0, 0, 0]), RET_ERRNO | libc::EPERM as u32);
        assert_eq!(check(libc::SYS_ioctl, [1, libc::TIOCLINUX as u32, 0, 0, 0, 0]), RET_ERRNO | libc::EPERM as u32);
        assert_eq!(check(libc::SYS_ioctl, [1, libc::FIONREAD as u32, 0, 0, 0, 0]), RET_ALLOW);
    }

    #[test]
    fn socket_filter_allows_inet_but_not_alg() {
        assert_eq!(check(libc::SYS_socket, [libc::AF_INET as u32, 1, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(check(libc::SYS_socket, [libc::AF_UNIX as u32, 1, 0, 0, 0, 0]), RET_ALLOW);
        assert_eq!(check(libc::SYS_socket, [libc::AF_ALG as u32, 5, 0, 0, 0, 0]), RET_ERRNO | libc::EPERM as u32);
    }
}
