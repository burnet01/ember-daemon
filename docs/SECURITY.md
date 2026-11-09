# Security model

Ember assumes a game server can be fully compromised, because Minecraft plugins and mods are arbitrary code. The goal is that a compromise stays inside that one server's sandbox.

## Admin access

- `emberd` listens only on the node's Tailscale address. There is no setting to change this, and unknown config keys are rejected.
- Each request's source address is resolved to a person by the local tailscaled. Only logins listed in `owners` are accepted, and anything else fails closed.
- Tagged devices are always refused, because they share one pseudo-identity.
- Requests from the node itself are refused, because they would carry the node's own identity whoever sent them.
- Requests with an `Origin` header, without the client header, or with an unexpected `Host` are refused. That stops a web page open on your computer from reaching the API through CSRF or DNS rebinding.
- The app refuses to connect to anything outside Tailscale's address ranges and ignores system proxies.

## SFTP

- The built-in SFTP server listens only on the Tailscale address, on port 2022.
- Identity is checked when each connection opens, with the same rules as the API, before any SSH traffic. Any password is accepted after that, because the Tailscale identity is the login.
- Each server has its own username, and a username only ever opens that server's folder. An owner can use every server's username, because owners already manage every server.
- It offers SFTP only: no shell, command execution or port forwarding. Links cannot be created, and existing links are never followed out of the folder.
- FTP is not offered, because it has no encryption of its own.

## Automatic updates

- Each night a systemd timer runs `emberd self-update` as root. It downloads the latest GitHub release over HTTPS and checks it against the release's checksum file.
- That checksum catches a damaged download, not a malicious release, because both files come from the same place. Anyone who can publish a release on the GitHub repo can run code as root on every node at its next update, so protect that account with two-factor authentication.
- To opt out, run the installer with `--no-auto-update`.

## Auth keys

The installer can log in to Tailscale with a key from `--auth-key` or `TS_AUTHKEY`. It never prints the key, and it hands it to Tailscale in a private temporary file. A key typed into a command still stays in that shell's history and is briefly visible in the process list, so use single-use keys. In a workflow, use a secret.

## Sandbox layers

| Layer | Provides |
| --- | --- |
| Unique unprivileged UID | No uid is ever reused, and no capabilities or setuid paths remain |
| Mount namespace and `pivot_root` | A minimal read-only system view plus the server's own files. The host filesystem is detached |
| PID, IPC, UTS and cgroup namespaces | Host processes and shared memory are invisible |
| Network namespace and nftables | Public internet and inbound players only. No access to the host, tailnet, private networks, cloud metadata or other servers. IPv6 is disabled |
| cgroup v2 | CPU, memory and process limits, with no swap. Out of memory kills the whole server |
| seccomp | Blocks namespace and mount calls, ptrace, bpf, io_uring, kernel modules, keyrings and the x32 bypass, among others |
| Landlock | An independent second filesystem layer on supported kernels |
| `no_new_privs` and rlimits | No privilege gain through exec, no core dumps, capped file size |

## The daemon handling hostile files

The daemon runs as root and handles files a compromised server controls. All file, backup and restore access goes through `cap-std`, which resolves paths beneath the server's directory and refuses to leave it. FIFOs cannot hang it, links are never archived or restored, and uploads are staged outside the tree and renamed in. Folder downloads leave out file names that could escape the target folder when extracted on Windows.

Console output is sanitized so a server cannot send terminal control sequences to the panel.

## Known limits

- **Shared kernel.** Like Docker, this is not a virtual machine. A kernel exploit that survives the seccomp filter could escape. For strangers' code, use a VM per tenant.
- **Disk limits are not instant.** Usage is scanned every 30 seconds, then the server is stopped. A fast writer can pass its limit between scans, and a single file is capped at the disk limit. Use a dedicated partition for `/var/lib/ember` if a full disk would hurt other services.
- **`/usr` is shared read-only.** A sandbox can read system libraries and anything else in `/usr`, so do not keep secrets there.
- **Servers cannot reach each other.** This is deliberate, but proxy setups such as Velocity need it, and it is not supported yet.
- **Game ports are public.** Anyone on the internet can connect to a port you open, so use a whitelist on private servers.
- **Traffic between the panel and daemon** relies on Tailscale's WireGuard encryption rather than TLS.
- **Servers stop when the daemon stops.** After an update, servers that were running come back. After any other restart or a reboot, only those with autostart do.

## Not yet verified

- Bedrock installs are not exercised in CI, because the download link comes from you.
- Real Tailscale identity is not exercised in CI, because the runners are not on a tailnet. It uses the same code path with a fake tailscaled, and needs checking on a real node.
