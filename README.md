# Ember

A private, Docker-free game server panel with a native desktop app, managed entirely over Tailscale.

- **Ember Panel** (`crates/ember-panel`): native desktop app built with Rust and Slint. It finds your nodes through Tailscale.
- **emberd** (`crates/emberd`): Linux daemon that installs, sandboxes and runs game servers.
- **ember-probe** (`crates/ember-probe`): test program that attempts sandbox escapes in CI.

Minecraft is supported: Paper, Vanilla, Fabric, Forge and Bedrock.

## Install a node

Requires Linux with cgroup v2, `nftables`, `iproute2` and Tailscale logged in.

1. Download `emberd-linux-x86_64` from a successful `release` CI run.
2. Run:

   ```sh
   sudo bash packaging/install.sh ./target/release/emberd you@example.com
   ```

   The second argument is your Tailscale login. Find it with `tailscale status --json | grep LoginName`.
3. Check the node with `sudo emberd doctor`.

## Run the panel

Download `ember-panel-windows` from a `panel` CI run, or run `cargo run --release -p ember-panel`, on a machine logged in to Tailscale as that same account. Nodes appear automatically.

`ember-panel --demo` shows the interface with sample data and makes no network connections.

## Security model

See [docs/SECURITY.md](docs/SECURITY.md) for what is protected, how, and the known limits.

## Testing

GitHub Actions never runs automatically, to keep usage low. Start one suite at a time, for example `gh workflow run CI -f suite=sandbox`:

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

## Development

On Windows, the daemon can be type-checked but not run:

```sh
rustup target add x86_64-unknown-linux-gnu
cargo check -p emberd --tests --no-default-features --target x86_64-unknown-linux-gnu
```
