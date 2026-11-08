//! `emberd`: the Ember node daemon. Linux only, because its isolation is built
//! directly on Linux kernel features.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("emberd only runs on Linux.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod api;
#[cfg(target_os = "linux")]
mod auth;
#[cfg(target_os = "linux")]
mod backup;
#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod error;
#[cfg(target_os = "linux")]
mod files;
#[cfg(target_os = "linux")]
mod install;
#[cfg(target_os = "linux")]
mod manager;
#[cfg(target_os = "linux")]
mod node;
#[cfg(target_os = "linux")]
mod sandbox;
#[cfg(target_os = "linux")]
mod sandbox_test;
#[cfg(target_os = "linux")]
mod sftp;

#[cfg(target_os = "linux")]
fn main() {
    // Must run before any thread exists, because the helper forks.
    if std::env::args().nth(1).as_deref() == Some(sandbox::INIT_ARG) {
        sandbox::child::main();
    }
    if let Err(e) = cli() {
        eprintln!("emberd: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn config_path(args: &[String]) -> std::path::PathBuf {
    args.windows(2)
        .find(|w| w[0] == "--config")
        .map_or_else(|| config::DEFAULT_CONFIG.into(), |w| w[1].clone().into())
}

#[cfg(target_os = "linux")]
fn cli() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") | None => tokio::runtime::Runtime::new()?.block_on(serve(config_path(&args))),
        Some("doctor") => doctor(),
        Some("sandbox-test") => {
            let code = tokio::runtime::Runtime::new()?.block_on(sandbox_test::run(&args[1..]))?;
            std::process::exit(code);
        }
        Some("version" | "--version") => {
            println!("emberd {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(other) => anyhow::bail!("unknown command {other:?}. Commands: run, doctor, sandbox-test, version"),
    }
}

#[cfg(target_os = "linux")]
fn doctor() -> anyhow::Result<()> {
    // Landlock is an extra layer that older kernels lack, and emberd turns forwarding on itself.
    let optional = |name: &str| matches!(name, "landlock" | "forwarding");
    let checks = node::isolation_checks();
    for c in &checks {
        let tag = match (c.ok, optional(&c.name)) {
            (true, _) => "[ ok ]",
            (false, true) => "[warn]",
            (false, false) => "[FAIL]",
        };
        println!("{tag} {:<11} {}", c.name, c.detail);
    }
    if checks.iter().any(|c| !c.ok && !optional(&c.name)) {
        anyhow::bail!("this machine is missing requirements");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn wait_for_tailscale(ts: &auth::Tailscale) -> auth::SelfInfo {
    loop {
        match ts.status().await {
            Ok(me) if me.ipv4().is_some() => return me,
            Ok(_) => tracing::warn!("Tailscale has no address yet; waiting"),
            Err(e) => tracing::warn!("Tailscale is not reachable yet: {e:#}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

#[cfg(target_os = "linux")]
async fn serve(config: std::path::PathBuf) -> anyhow::Result<()> {
    use anyhow::Context;
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "emberd=info".into()))
        .init();

    let cfg = config::Config::load(&config)?;
    let ts = auth::Tailscale::new(&cfg.tailscale_socket);
    let me = wait_for_tailscale(&ts).await;
    // There is deliberately no bind setting: the API only ever listens on Tailscale.
    let ip = me.ipv4().context("no Tailscale IPv4 address")?;
    let addr = std::net::SocketAddr::new(ip, cfg.port);

    sandbox::cgroup::prepare_root()?;
    sandbox::cgroup::sweep_stale();
    sandbox::net::init().await?;

    let mgr = manager::Manager::load(cfg)?;
    mgr.spawn_background();

    {
        let (mgr, ts, me) = (mgr.clone(), ts.clone(), me.clone());
        tokio::spawn(async move {
            // File transfer is an extra: the panel should still work if this cannot start.
            if let Err(e) = sftp::serve(mgr, ts, me, ip).await {
                tracing::error!("SFTP stopped: {e:#}");
            }
        });
    }

    let app = api::router(api::AppState { mgr: mgr.clone(), ts, me });
    let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("listen on {addr}"))?;
    tracing::info!(%addr, "emberd is listening on Tailscale");

    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("stopping all servers");
    mgr.shutdown().await;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let Ok(mut term) = signal(SignalKind::terminate()) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
