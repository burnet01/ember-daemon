# Ember

A private, Docker-free game server panel with a native desktop app, managed entirely over Tailscale.

- **Ember Panel** (`crates/ember-panel`): native desktop app built with Rust and Slint. It finds your nodes through Tailscale.
- **emberd** (`crates/emberd`): Linux daemon that installs, sandboxes and runs game servers.
- **ember-probe** (`crates/ember-probe`): test program that attempts sandbox escapes in CI.

Minecraft is supported: Paper, Vanilla, Fabric, Forge and Bedrock.

## Install a node

The steps are also at <https://burnet01.github.io/TESTME/>. On x86_64 Linux with systemd and cgroup v2, run:

```sh
curl -fsSL https://burnet01.github.io/TESTME/install.sh | sudo bash
```

It installs `nftables`, `iproute2` and Tailscale if they're missing, shows a login link if the machine isn't on Tailscale, and makes that machine's Tailscale login the owner. To set a different owner, add `-s -- --owner you@example.com` after `bash`.

Run the same command to update. Check a node with `sudo emberd doctor`.

## Run the panel

Download [`ember-panel.exe`](https://github.com/burnet01/TESTME/releases/latest/download/ember-panel.exe), or run `cargo run --release -p ember-panel`, on a machine logged in to Tailscale as that same account. Nodes appear automatically.

`ember-panel --demo` shows the interface with sample data and makes no network connections.

## File transfer

Each server's Files tab shows its SFTP address, like `sftp://1a2b3c4d@100.x.y.z:2022`. Use it with FileZilla or WinSCP from a device logged in to your Tailscale account. No password is needed.

## Security model

See [docs/SECURITY.md](docs/SECURITY.md) for what is protected, how, and the known limits.

## Testing

The test suites never run automatically, to keep GitHub Actions usage low. Start one at a time, for example `gh workflow run CI -f suite=sandbox`:

| Suite | What it proves |
| --- | --- |
| `unit` | Filter logic, file safety, auth rules and parsers |
| `sandbox` | `ember-probe` tries real attacks from inside a real sandbox, and tests the memory and process limits |
| `e2e-vanilla` | Boots a real server, pings it from a separate network namespace, and attacks the API |
| `e2e-all-flavors` | The same, plus Paper, Fabric and Forge boots |
| `panel` | Builds and tests the Windows app |
| `release` | Builds the release daemon |
| `tailnet-test` | Runs a temporary node on your tailnet for 20 minutes to try the panel, then leaves. Needs the `TS_AUTHKEY` (ephemeral) and `EMBER_OWNER` secrets. Not for hosting |

CI runners are not on a tailnet, so the end-to-end test replaces tailscaled with a fake one speaking the same local API. Everything else in that path is real.

## Publishing

Pushing a version tag such as `v0.2.0` runs the `Publish` workflow, which tests and builds both programs and creates a release. The install command and download link always use the latest release. The `Website` workflow updates the site in a few seconds when `site/` or `packaging/install.sh` changes.

## Development

On Windows, the daemon can be type-checked but not run:

```sh
rustup target add x86_64-unknown-linux-gnu
cargo check -p emberd --tests --no-default-features --target x86_64-unknown-linux-gnu
```
