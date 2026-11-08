//! The HTTP and WebSocket API. Reachable only on the Tailscale address, and every
//! route passes through `guard`, including health checks.

use crate::auth::{self, SelfInfo, Tailscale};
use crate::error::{bad_request, conflict, ApiErr, ApiResult};
use crate::files;
use crate::install;
use crate::manager::{validate_cron, Instance, Manager};
use crate::node;
use anyhow::{anyhow, Context};
use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use ember_proto::*;
use futures_util::StreamExt;
use serde::Deserialize;
use std::net::SocketAddr;
use std::os::unix::fs::fchown;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast::error::RecvError;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

const MAX_COMMAND_LEN: usize = 4096;

#[derive(Clone)]
pub struct AppState {
    pub mgr: Arc<Manager>,
    pub ts: Tailscale,
    pub me: SelfInfo,
}

#[derive(Clone)]
struct Login(String);

fn forbidden(msg: &str) -> Response {
    ApiErr(StatusCode::FORBIDDEN, msg.to_string()).into_response()
}

async fn guard(State(app): State<AppState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, mut req: Request, next: Next) -> Response {
    let header_str = |h: &HeaderMap, name: &str| h.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let headers = req.headers();
    let (origin, client, host) =
        (header_str(headers, "origin"), header_str(headers, CLIENT_HEADER), header_str(headers, "host"));
    if let Err(why) = auth::check_request_shape(origin.as_deref(), client.as_deref(), host.as_deref(), &app.me) {
        tracing::warn!(%peer, why, "rejected request");
        return forbidden(why);
    }
    // Traffic from this host carries this node's own identity, whoever really sent it.
    if app.me.ips.contains(&peer.ip()) {
        tracing::warn!(%peer, "rejected request from the node itself");
        return forbidden("requests from the node itself are not accepted");
    }
    let login = match app.ts.whois(peer).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(%peer, "identity lookup failed: {e:#}");
            return forbidden("could not verify your Tailscale identity");
        }
    };
    if !auth::is_owner(&app.mgr.cfg.owners, &login) {
        tracing::warn!(%peer, %login, "rejected login that is not an owner");
        return forbidden("your Tailscale account is not an owner of this node");
    }
    if req.method() != axum::http::Method::GET {
        tracing::info!(%login, method = %req.method(), path = %req.uri().path(), "admin action");
    }
    req.extensions_mut().insert(Login(login));
    next.run(req).await
}

pub fn router(app: AppState) -> Router {
    let server = Router::new()
        .route("/", get(get_server).patch(patch_server).delete(delete_server))
        .route("/power", post(power))
        .route("/command", post(command))
        .route("/reinstall", post(reinstall))
        .route("/stats", get(server_stats))
        .route("/startup", get(get_startup).put(put_startup))
        .route("/console", get(console))
        .route("/files", get(list_files).delete(remove_file))
        .route("/files/content", get(read_file).put(write_file))
        .route("/files/mkdir", post(make_dir))
        .route("/files/rename", post(rename_file))
        .route("/files/download", get(download_file))
        .route("/files/upload", put(upload_file).layer(DefaultBodyLimit::disable()))
        .route("/backups", get(list_backups).post(create_backup))
        .route("/backups/progress", get(backup_progress))
        .route("/backups/{backup}", delete(delete_backup))
        .route("/backups/{backup}/restore", post(restore_backup))
        .route("/schedules", get(list_schedules).post(create_schedule))
        .route("/schedules/{schedule}", put(update_schedule).delete(delete_schedule));

    Router::new()
        .route("/v1/node", get(node_info))
        .route("/v1/node/stats", get(node_stats))
        .route("/v1/versions/{flavor}", get(versions))
        .route("/v1/servers", get(list_servers).post(create_server))
        .nest("/v1/servers/{id}", server)
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> ApiResult<T> {
    Ok(tokio::task::spawn_blocking(f).await.map_err(anyhow::Error::from)??)
}

/// File errors are nearly always a bad path or a refused file, so they are the caller's to fix.
async fn file_op<T: Send + 'static>(f: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> ApiResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(anyhow::Error::from)?
        .map_err(|e| bad_request(format!("{e:#}")))
}

// ---- Node ----

async fn node_info(State(app): State<AppState>, Extension(Login(login)): Extension<Login>) -> Json<NodeInfo> {
    Json(NodeInfo {
        api_version: API_VERSION,
        version: env!("CARGO_PKG_VERSION").into(),
        hostname: node::hostname(),
        tailscale_ip: app.me.ipv4().map(|i| i.to_string()).unwrap_or_default(),
        login,
        kernel: node::kernel(),
        os: node::os_name(),
        arch: std::env::consts::ARCH.into(),
        cpu_count: node::cpu_count(),
        isolation: node::isolation_checks(),
    })
}

async fn node_stats(State(app): State<AppState>) -> Json<NodeStats> {
    let all = app.mgr.all();
    let running = all.iter().filter(|s| matches!(s.state(), ServerState::Running | ServerState::Starting)).count();
    let cpu = app.mgr.node_cpu_percent();
    Json(node::stats(&app.mgr.cfg.data_dir, cpu, all.len() as u32, running as u32))
}

async fn versions(State(app): State<AppState>, Path(flavor): Path<Flavor>) -> ApiResult<Json<Vec<GameVersion>>> {
    Ok(Json(install::list_versions(&app.mgr.http, flavor).await?))
}

// ---- Servers ----

fn inst(app: &AppState, id: Uuid) -> ApiResult<Arc<Instance>> {
    app.mgr.get(id)
}

async fn list_servers(State(app): State<AppState>) -> Json<Vec<ServerInfo>> {
    let mut list: Vec<_> = app.mgr.all().iter().map(|s| s.info()).collect();
    list.sort_by_key(|s| s.created_at);
    Json(list)
}

async fn create_server(State(app): State<AppState>, Json(req): Json<CreateServer>) -> ApiResult<(StatusCode, Json<ServerInfo>)> {
    Ok((StatusCode::CREATED, Json(app.mgr.create(req).await?)))
}

async fn get_server(State(app): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<ServerInfo>> {
    Ok(Json(inst(&app, id)?.info()))
}

async fn patch_server(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<UpdateServer>) -> ApiResult<Json<ServerInfo>> {
    let s = inst(&app, id)?;
    app.mgr.update_settings(&s, req).await?;
    Ok(Json(s.info()))
}

async fn delete_server(State(app): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    app.mgr.delete(inst(&app, id)?).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn power(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<PowerRequest>) -> ApiResult<StatusCode> {
    let s = inst(&app, id)?;
    match req.action {
        PowerAction::Start => app.mgr.start(s).await?,
        PowerAction::Kill => app.mgr.kill(s).await?,
        // A graceful stop can take a minute, so these answer now and report through state.
        PowerAction::Stop => {
            let mgr = app.mgr.clone();
            tokio::spawn(async move {
                let _ = mgr.stop(s).await;
            });
        }
        PowerAction::Restart => {
            let mgr = app.mgr.clone();
            tokio::spawn(async move {
                let target = s.clone();
                if let Err(e) = mgr.restart(s).await {
                    target.log(&format!("[ember] Restart failed: {}", e.1));
                }
            });
        }
    }
    Ok(StatusCode::ACCEPTED)
}

fn check_command(c: &str) -> ApiResult<()> {
    if c.len() > MAX_COMMAND_LEN || c.contains(['\n', '\r', '\0']) {
        return Err(bad_request("a command must be a single line"));
    }
    Ok(())
}

async fn command(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<CommandRequest>) -> ApiResult<StatusCode> {
    check_command(&req.command)?;
    inst(&app, id)?.send_stdin(&req.command).await.map_err(|e| conflict(e.to_string()))?;
    Ok(StatusCode::ACCEPTED)
}

async fn reinstall(State(app): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    app.mgr.reinstall(inst(&app, id)?).await?;
    Ok(StatusCode::ACCEPTED)
}

async fn server_stats(State(app): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<ServerStats>> {
    Ok(Json(inst(&app, id)?.stats()))
}

async fn get_startup(State(app): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<StartupInfo>> {
    let s = inst(&app, id)?;
    Ok(Json(app.mgr.startup_info(&s)))
}

async fn put_startup(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<UpdateStartup>) -> ApiResult<Json<StartupInfo>> {
    let s = inst(&app, id)?;
    app.mgr.update_startup(s.clone(), req).await?;
    Ok(Json(app.mgr.startup_info(&s)))
}

// ---- Console ----

async fn console(State(app): State<AppState>, Path(id): Path<Uuid>, ws: WebSocketUpgrade) -> ApiResult<Response> {
    let s = inst(&app, id)?;
    Ok(ws.max_message_size(64 * 1024).on_upgrade(move |socket| console_session(socket, s)))
}

async fn send_event(socket: &mut WebSocket, event: &ConsoleEvent) -> bool {
    match serde_json::to_string(event) {
        Ok(t) => socket.send(Message::text(t)).await.is_ok(),
        Err(_) => false,
    }
}

async fn console_session(mut socket: WebSocket, s: Arc<Instance>) {
    // Subscribe first: a line printed during the backlog send may repeat, but is never lost.
    let mut lines = s.subscribe_lines();
    let mut state = s.watch_state();
    for text in s.backlog() {
        if !send_event(&mut socket, &ConsoleEvent::Line { text }).await {
            return;
        }
    }
    if !send_event(&mut socket, &ConsoleEvent::State { state: s.state() }).await {
        return;
    }
    let mut stats_tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            line = lines.recv() => match line {
                Ok(text) => if !send_event(&mut socket, &ConsoleEvent::Line { text }).await { return },
                Err(RecvError::Lagged(n)) => {
                    let text = format!("[ember] Skipped {n} lines of fast output");
                    if !send_event(&mut socket, &ConsoleEvent::Line { text }).await { return }
                }
                Err(RecvError::Closed) => return,
            },
            changed = state.changed() => {
                if changed.is_err() { return }
                let current = *state.borrow_and_update();
                if !send_event(&mut socket, &ConsoleEvent::State { state: current }).await { return }
            },
            _ = stats_tick.tick() => {
                if !send_event(&mut socket, &ConsoleEvent::Stats { stats: s.stats() }).await { return }
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Text(t))) => {
                    let Ok(req) = serde_json::from_str::<CommandRequest>(&t) else { continue };
                    if check_command(&req.command).is_err() { continue }
                    if let Err(e) = s.send_stdin(&req.command).await {
                        s.log(&format!("[ember] Command not sent: {e}"));
                    }
                }
                Some(Ok(_)) => {}
                _ => return,
            },
        }
    }
}

// ---- Files ----

#[derive(Deserialize)]
struct PathQuery {
    #[serde(default)]
    path: String,
}

async fn list_files(State(app): State<AppState>, Path(id): Path<Uuid>, Query(q): Query<PathQuery>) -> ApiResult<Json<Vec<FileEntry>>> {
    inst(&app, id)?;
    let data = app.mgr.data_dir(id);
    Ok(Json(file_op(move || files::list(&files::open_root(&data)?, &q.path)).await?))
}

async fn read_file(State(app): State<AppState>, Path(id): Path<Uuid>, Query(q): Query<PathQuery>) -> ApiResult<Json<FileContent>> {
    inst(&app, id)?;
    let data = app.mgr.data_dir(id);
    let (content, size) = file_op(move || files::read_text(&files::open_root(&data)?, &q.path)).await?;
    Ok(Json(FileContent { content, size }))
}

async fn write_file(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<WriteFile>) -> ApiResult<StatusCode> {
    let owner = inst(&app, id)?.owner();
    let data = app.mgr.data_dir(id);
    file_op(move || files::write_text(&files::open_root(&data)?, &req.path, &req.content, owner)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn make_dir(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<PathRequest>) -> ApiResult<StatusCode> {
    let owner = inst(&app, id)?.owner();
    let data = app.mgr.data_dir(id);
    file_op(move || files::make_dir(&files::open_root(&data)?, &req.path, owner)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rename_file(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<RenameRequest>) -> ApiResult<StatusCode> {
    let owner = inst(&app, id)?.owner();
    let data = app.mgr.data_dir(id);
    file_op(move || files::rename(&files::open_root(&data)?, &req.from, &req.to, owner)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_file(State(app): State<AppState>, Path(id): Path<Uuid>, Query(q): Query<PathQuery>) -> ApiResult<StatusCode> {
    inst(&app, id)?;
    let data = app.mgr.data_dir(id);
    file_op(move || files::remove(&files::open_root(&data)?, &q.path)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn download_file(State(app): State<AppState>, Path(id): Path<Uuid>, Query(q): Query<PathQuery>) -> ApiResult<Response> {
    inst(&app, id)?;
    let data = app.mgr.data_dir(id);
    let (file, size) = file_op(move || {
        let root = files::open_root(&data)?;
        let path = files::clean_nonroot(&q.path)?;
        let f = files::open_regular(&root, &path)?;
        let size = f.metadata()?.len();
        Ok((f.into_std(), size))
    })
    .await?;
    let stream = ReaderStream::new(tokio::fs::File::from_std(file));
    Ok(([(header::CONTENT_LENGTH, size.to_string())], Body::from_stream(stream)).into_response())
}

/// Stages outside the server's tree, then renames in, so a server can never see or
/// race a partial upload. Renaming over a planted symlink replaces only the link.
async fn upload_file(State(app): State<AppState>, Path(id): Path<Uuid>, Query(q): Query<PathQuery>, body: Body) -> ApiResult<StatusCode> {
    let s = inst(&app, id)?;
    let owner = s.owner();
    let limit = s.record().limits.disk_mb * 1024 * 1024;
    let target = files::clean_nonroot(&q.path).map_err(|e| bad_request(e.to_string()))?;

    let server_dir = app.mgr.server_dir(id);
    let tmp_name = format!(".upload-{}", Uuid::new_v4());
    let tmp_path = server_dir.join(&tmp_name);
    let result = async {
        let mut out = tokio::fs::File::create(&tmp_path).await.context("create upload file")?;
        let mut stream = body.into_data_stream();
        let mut total = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("upload interrupted")?;
            total += chunk.len() as u64;
            if total > limit {
                return Err(anyhow!("the file is larger than this server's disk limit"));
            }
            out.write_all(&chunk).await?;
        }
        out.flush().await?;
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(bad_request(format!("{e:#}")));
    }

    let data = app.mgr.data_dir(id);
    let moved = file_op(move || {
        let root = files::open_root(&data)?;
        if let Some(parent) = target.parent() {
            files::mkdirs(&root, parent, owner)?;
        }
        let staging = files::open_root(&server_dir)?;
        staging.rename(&tmp_name, &root, &target).context("move upload into place")?;
        let f = files::open_regular(&root, &target)?;
        fchown(&f, Some(owner.uid), Some(owner.gid))?;
        Ok(())
    })
    .await;
    if moved.is_err() {
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }
    moved?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Backups ----

async fn list_backups(State(app): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<BackupInfo>>> {
    inst(&app, id)?;
    let mgr = app.mgr.clone();
    Ok(Json(blocking(move || mgr.list_backups(id)).await?))
}

async fn backup_progress(State(app): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Option<BackupProgress>>> {
    Ok(Json(inst(&app, id)?.backup_progress()))
}

async fn create_backup(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<CreateBackup>) -> ApiResult<(StatusCode, Json<BackupInfo>)> {
    let s = inst(&app, id)?;
    Ok((StatusCode::CREATED, Json(app.mgr.create_backup(&s, &req.name).await?)))
}

async fn delete_backup(State(app): State<AppState>, Path((id, backup)): Path<(Uuid, Uuid)>) -> ApiResult<StatusCode> {
    inst(&app, id)?;
    app.mgr.delete_backup(id, backup)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn restore_backup(State(app): State<AppState>, Path((id, backup)): Path<(Uuid, Uuid)>) -> ApiResult<StatusCode> {
    app.mgr.restore_backup(inst(&app, id)?, backup).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Schedules ----

fn validate_schedule(req: &UpsertSchedule) -> ApiResult<()> {
    validate_name(&req.name).map_err(bad_request)?;
    validate_cron(&req.cron).map_err(bad_request)?;
    if let ScheduleAction::Command(c) = &req.action {
        check_command(c)?;
    }
    Ok(())
}

async fn list_schedules(State(app): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<Schedule>>> {
    Ok(Json(inst(&app, id)?.record().schedules))
}

async fn create_schedule(State(app): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<UpsertSchedule>) -> ApiResult<(StatusCode, Json<Schedule>)> {
    validate_schedule(&req)?;
    let s = inst(&app, id)?;
    let sched = Schedule {
        id: Uuid::new_v4(),
        name: req.name.trim().to_string(),
        cron: req.cron,
        action: req.action,
        enabled: req.enabled,
        last_run: None,
        last_error: None,
    };
    let stored = sched.clone();
    s.update(|r| r.schedules.push(stored));
    Ok((StatusCode::CREATED, Json(sched)))
}

async fn update_schedule(State(app): State<AppState>, Path((id, sid)): Path<(Uuid, Uuid)>, Json(req): Json<UpsertSchedule>) -> ApiResult<StatusCode> {
    validate_schedule(&req)?;
    let s = inst(&app, id)?;
    if !s.record().schedules.iter().any(|x| x.id == sid) {
        return Err(crate::error::not_found("schedule not found"));
    }
    s.update(|r| {
        if let Some(x) = r.schedules.iter_mut().find(|x| x.id == sid) {
            x.name = req.name.trim().to_string();
            x.cron = req.cron;
            x.action = req.action;
            x.enabled = req.enabled;
        }
    });
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_schedule(State(app): State<AppState>, Path((id, sid)): Path<(Uuid, Uuid)>) -> ApiResult<StatusCode> {
    inst(&app, id)?.update(|r| r.schedules.retain(|x| x.id != sid));
    Ok(StatusCode::NO_CONTENT)
}
