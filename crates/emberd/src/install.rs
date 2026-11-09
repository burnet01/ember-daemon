//! Minecraft installers. Downloads run in the daemon, restricted to fixed official
//! hosts and verified wherever the source publishes a checksum. Anything that has
//! to execute third-party code, like the Forge installer, runs inside the sandbox.

use crate::files::{self, Owner};
use crate::manager::{Instance, Manager, StartSpec};
use anyhow::{anyhow, bail, Context, Result};
use ember_proto::{Flavor, GameVersion};
use futures_util::StreamExt;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MOJANG_MANIFEST: &str = "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json";
const PAPER_API: &str = "https://fill.papermc.io/v3/projects/paper";
const FABRIC_META: &str = "https://meta.fabricmc.net/v2/versions";
const FORGE_PROMOS: &str = "https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json";
const FORGE_MAVEN: &str = "https://maven.minecraftforge.net/net/minecraftforge/forge";
const ADOPTIUM: &str = "https://api.adoptium.net/v3/assets/latest";

const MAX_DOWNLOAD: u64 = 2 * 1024 * 1024 * 1024;

pub enum Verify {
    Sha1(String),
    Sha256(String),
    /// The source publishes no checksum, so only HTTPS protects the transfer.
    Tls,
}

/// What custom jars run on unless the Startup page picks another version.
pub const CUSTOM_JAVA: u32 = 25;

pub fn validate_version(v: &str) -> Result<()> {
    let ok = !v.is_empty() && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
    if !ok {
        bail!("invalid version");
    }
    Ok(())
}

/// Only Mojang's own hosts, over HTTPS. Returns the version embedded in the file name.
pub fn validate_bedrock_url(url: &str) -> Result<String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| anyhow!("the Bedrock link must use https"))?;
    let (host, path) = rest.split_once('/').ok_or_else(|| anyhow!("invalid Bedrock link"))?;
    let host = host.to_ascii_lowercase();
    if host != "minecraft.net" && !host.ends_with(".minecraft.net") {
        bail!("the Bedrock link must come from minecraft.net");
    }
    let file = path.rsplit('/').next().unwrap_or("");
    let version = file
        .strip_prefix("bedrock-server-")
        .and_then(|f| f.strip_suffix(".zip"))
        .ok_or_else(|| anyhow!("that does not look like a Bedrock server download"))?;
    validate_version(version)?;
    Ok(version.to_string())
}

async fn get_json<T: serde::de::DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T> {
    http.get(url)
        .send()
        .await
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("fetch {url}"))?
        .json()
        .await
        .with_context(|| format!("parse {url}"))
}

#[derive(Deserialize)]
struct Manifest {
    versions: Vec<ManifestVersion>,
}
#[derive(Deserialize)]
struct ManifestVersion {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    url: String,
}

struct MojangVersion {
    server_url: Option<(String, String)>,
    java_major: u32,
}

async fn mojang_version(http: &reqwest::Client, id: &str) -> Result<MojangVersion> {
    #[derive(Deserialize)]
    struct Detail {
        #[serde(rename = "javaVersion")]
        java: Option<Java>,
        downloads: Downloads,
    }
    #[derive(Deserialize)]
    struct Java {
        #[serde(rename = "majorVersion")]
        major: u32,
    }
    #[derive(Deserialize)]
    struct Downloads {
        server: Option<Server>,
    }
    #[derive(Deserialize)]
    struct Server {
        url: String,
        sha1: String,
    }
    let manifest: Manifest = get_json(http, MOJANG_MANIFEST).await?;
    let entry = manifest.versions.iter().find(|v| v.id == id).ok_or_else(|| anyhow!("unknown Minecraft version {id}"))?;
    let d: Detail = get_json(http, &entry.url).await?;
    Ok(MojangVersion {
        server_url: d.downloads.server.map(|s| (s.url, s.sha1)),
        // Versions predating this field all ran on Java 8.
        java_major: d.java.map_or(8, |j| j.major),
    })
}

pub async fn list_versions(http: &reqwest::Client, flavor: Flavor) -> Result<Vec<GameVersion>> {
    match flavor {
        Flavor::Bedrock | Flavor::Custom => Ok(vec![]),
        Flavor::Vanilla => {
            let m: Manifest = get_json(http, MOJANG_MANIFEST).await?;
            Ok(m.versions
                .into_iter()
                .filter(|v| v.kind == "release" || v.kind == "snapshot")
                .map(|v| GameVersion { stable: v.kind == "release", id: v.id })
                .collect())
        }
        Flavor::Paper => {
            let v: serde_json::Value = get_json(http, PAPER_API).await?;
            Ok(paper_versions(&v))
        }
        Flavor::Fabric => {
            #[derive(Deserialize)]
            struct G {
                version: String,
                stable: bool,
            }
            let g: Vec<G> = get_json(http, &format!("{FABRIC_META}/game")).await?;
            Ok(g.into_iter().map(|g| GameVersion { id: g.version, stable: g.stable }).collect())
        }
        Flavor::Forge => {
            #[derive(Deserialize)]
            struct P {
                promos: serde_json::Map<String, serde_json::Value>,
            }
            let p: P = get_json(http, FORGE_PROMOS).await?;
            Ok(forge_versions(p.promos.keys().map(String::as_str)))
        }
    }
}

/// Newest first. The API groups versions by minor line, newest group first.
fn paper_versions(v: &serde_json::Value) -> Vec<GameVersion> {
    let mut out = Vec::new();
    if let Some(groups) = v.get("versions").and_then(|x| x.as_object()) {
        for list in groups.values() {
            for id in list.as_array().into_iter().flatten().filter_map(|i| i.as_str()) {
                out.push(GameVersion { id: id.to_string(), stable: !id.contains('-') });
            }
        }
    }
    sort_newest_first(&mut out);
    out
}

fn forge_versions<'a>(keys: impl Iterator<Item = &'a str>) -> Vec<GameVersion> {
    let mut out: Vec<GameVersion> = Vec::new();
    for k in keys {
        if let Some((mc, _)) = k.rsplit_once('-') {
            if !out.iter().any(|g| g.id == mc) {
                out.push(GameVersion { id: mc.to_string(), stable: true });
            }
        }
    }
    sort_newest_first(&mut out);
    out
}

/// Compares the numeric release first, then ranks a final release above its release candidates.
fn sort_newest_first(v: &mut [GameVersion]) {
    let key = |g: &GameVersion| -> (Vec<u32>, bool) {
        let base = g.id.split('-').next().unwrap_or("");
        (base.split('.').map(|p| p.parse().unwrap_or(0)).collect(), !g.id.contains('-'))
    };
    v.sort_by_key(|g| std::cmp::Reverse(key(g)));
}

/// Picks a runtime Adoptium actually publishes, never older than requested.
pub fn runtime_major(required: u32) -> u32 {
    match required {
        0..=8 => 8,
        9..=11 => 11,
        12..=17 => 17,
        18..=21 => 21,
        other => other,
    }
}

/// Streams to `dest`, checking size and checksum. On failure `dest` is removed.
pub async fn download(http: &reqwest::Client, url: &str, dest: &Path, verify: Verify) -> Result<()> {
    let result = download_inner(http, url, dest, verify).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(dest).await;
    }
    result
}

async fn download_inner(http: &reqwest::Client, url: &str, dest: &Path, verify: Verify) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let resp = http.get(url).send().await.with_context(|| format!("fetch {url}"))?.error_for_status()?;
    let mut stream = resp.bytes_stream();
    let mut out = tokio::fs::File::create(dest).await?;
    let (mut s1, mut s256, mut total) = (Sha1::new(), Sha256::new(), 0u64);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("download interrupted")?;
        total += chunk.len() as u64;
        if total > MAX_DOWNLOAD {
            bail!("download is unexpectedly large");
        }
        match verify {
            Verify::Sha1(_) => s1.update(&chunk),
            Verify::Sha256(_) => s256.update(&chunk),
            Verify::Tls => {}
        }
        out.write_all(&chunk).await?;
    }
    out.flush().await?;
    match verify {
        Verify::Sha1(want) if !hex::encode(s1.finalize()).eq_ignore_ascii_case(&want) => {
            bail!("checksum mismatch for {url}")
        }
        Verify::Sha256(want) if !hex::encode(s256.finalize()).eq_ignore_ascii_case(&want) => {
            bail!("checksum mismatch for {url}")
        }
        _ => Ok(()),
    }
}

const ARCHIVE_TOOL_PATHS: [&str; 2] = ["/usr/bin/bsdtar", "/bin/bsdtar"];

fn find_archive_tool() -> Option<&'static str> {
    ARCHIVE_TOOL_PATHS.into_iter().find(|p| Path::new(p).exists())
}

/// Finds `bsdtar`, which reads zip, rar, 7z and tar. A node that got here through automatic
/// updates never ran the newer installer, so this installs it the first time it's needed.
pub async fn ensure_archive_tool(mgr: &Manager) -> Result<&'static str> {
    if let Some(tool) = find_archive_tool() {
        return Ok(tool);
    }
    let _guard = mgr.archive_tool_lock.lock().await;
    if let Some(tool) = find_archive_tool() {
        return Ok(tool);
    }
    let attempts: [(&str, &[&str]); 4] = [
        ("apt-get", &["install", "-y", "-qq", "libarchive-tools"]),
        ("dnf", &["install", "-y", "-q", "bsdtar"]),
        ("pacman", &["-S", "--noconfirm", "--needed", "libarchive"]),
        ("zypper", &["--non-interactive", "install", "bsdtar"]),
    ];
    for (manager, args) in attempts {
        if manager == "apt-get" {
            let _ = package_command("apt-get", &["update", "-qq"]).await;
        }
        if package_command(manager, args).await {
            break;
        }
    }
    find_archive_tool().ok_or_else(|| anyhow!("couldn't install the archive tool. Install libarchive-tools on this node, then try again"))
}

async fn package_command(program: &str, args: &[&str]) -> bool {
    let run = tokio::process::Command::new(program)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .status();
    matches!(tokio::time::timeout(std::time::Duration::from_secs(300), run).await, Ok(Ok(s)) if s.success())
}

/// Installs an Eclipse Temurin runtime shared read-only by all servers that need it.
pub async fn ensure_java(mgr: &Manager, major: u32) -> Result<PathBuf> {
    #[derive(Deserialize)]
    struct Asset {
        binary: Binary,
    }
    #[derive(Deserialize)]
    struct Binary {
        package: Package,
    }
    #[derive(Deserialize)]
    struct Package {
        link: String,
        checksum: String,
    }
    let _guard = mgr.java_lock.lock().await;
    let dir = mgr.runtimes_dir().join(format!("java-{major}"));
    if dir.join("bin/java").exists() {
        return Ok(dir);
    }
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "aarch64",
        other => bail!("no Java runtime available for {other}"),
    };
    let url = format!("{ADOPTIUM}/{major}/hotspot?architecture={arch}&image_type=jre&os=linux&vendor=eclipse");
    let assets: Vec<Asset> = get_json(&mgr.http, &url).await?;
    let pkg = &assets.first().ok_or_else(|| anyhow!("no Java {major} build available"))?.binary.package;

    tokio::fs::create_dir_all(mgr.runtimes_dir()).await?;
    let archive = mgr.runtimes_dir().join(format!(".java-{major}.tar.gz"));
    download(&mgr.http, &pkg.link, &archive, Verify::Sha256(pkg.checksum.clone())).await?;

    let (archive_c, dir_c) = (archive.clone(), dir.clone());
    tokio::task::spawn_blocking(move || extract_runtime(&archive_c, &dir_c)).await??;
    tokio::fs::remove_file(&archive).await.ok();
    Ok(dir)
}

fn extract_runtime(archive: &Path, final_dir: &Path) -> Result<()> {
    let tmp = final_dir.with_extension("partial");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(std::fs::File::open(archive)?));
    tar.set_preserve_permissions(true);
    for entry in tar.entries()? {
        let mut entry = entry?;
        // Archives wrap everything in a versioned folder; `unpack` still refuses `..`.
        let stripped: PathBuf = entry.path()?.components().skip(1).collect();
        if stripped.as_os_str().is_empty() {
            continue;
        }
        let dest = tmp.join(stripped);
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p)?;
        }
        entry.unpack(&dest)?;
    }
    if !tmp.join("bin/java").exists() {
        bail!("Java archive did not contain bin/java");
    }
    std::fs::rename(&tmp, final_dir)?;
    Ok(())
}

/// Copies a verified download into the server's tree, owned by the server's user.
async fn place(root_path: PathBuf, src: PathBuf, name: &'static str, owner: Owner) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let root = files::open_root(&root_path)?;
        let mut out = files::create_owned(&root, Path::new(name), owner, 0o644)?;
        let mut input = std::fs::File::open(&src)?;
        std::io::copy(&mut input, &mut out)?;
        out.flush()?;
        std::fs::remove_file(&src)?;
        Ok(())
    })
    .await?
}

/// Runs the full install. The caller owns state transitions and error reporting.
pub async fn run(mgr: &Arc<Manager>, inst: &Arc<Instance>) -> Result<()> {
    let (flavor, version, bedrock_url) = {
        let r = inst.record();
        (r.flavor, r.version.clone(), r.bedrock_url.clone())
    };
    let owner = inst.owner();
    let data = mgr.data_dir(inst.id);
    let tmp = mgr.server_dir(inst.id).join(".download");
    let http = &mgr.http;

    if flavor == Flavor::Bedrock {
        let url = bedrock_url.ok_or_else(|| anyhow!("Bedrock needs a download link"))?;
        validate_bedrock_url(&url)?;
        inst.log("[ember] Downloading the Bedrock server from minecraft.net");
        download(http, &url, &tmp, Verify::Tls).await?;
        let (d, t) = (data.clone(), tmp.clone());
        tokio::task::spawn_blocking(move || extract_bedrock(&t, &d, owner)).await??;
        tokio::fs::remove_file(&tmp).await.ok();
        inst.update(|r| r.start = Some(StartSpec::Native { binary: "bedrock_server".into() }));
        return Ok(());
    }

    if flavor == Flavor::Custom {
        let major = inst.record().startup.java_major.unwrap_or(CUSTOM_JAVA);
        ensure_java(mgr, major).await?;
        inst.update(|r| {
            r.java_major = Some(major);
            r.start = Some(StartSpec::Jar { path: "server.jar".into() });
        });
        inst.log(&format!("[ember] Java {major} is ready. Upload server.jar, then start the server."));
        return Ok(());
    }

    validate_version(&version)?;
    let mojang = mojang_version(http, &version).await?;
    let major = runtime_major(mojang.java_major);
    inst.log(&format!("[ember] Minecraft {version} needs Java {}. Using Java {major}.", mojang.java_major));
    ensure_java(mgr, major).await?;
    if let Some(chosen) = inst.record().startup.java_major {
        ensure_java(mgr, chosen).await?;
    }
    inst.update(|r| r.java_major = Some(major));

    let start = match flavor {
        Flavor::Vanilla => {
            let (url, sha1) = mojang.server_url.ok_or_else(|| anyhow!("Mojang has no server download for {version}"))?;
            inst.log("[ember] Downloading the Minecraft server from Mojang");
            download(http, &url, &tmp, Verify::Sha1(sha1)).await?;
            place(data.clone(), tmp.clone(), "server.jar", owner).await?;
            StartSpec::Jar { path: "server.jar".into() }
        }
        Flavor::Paper => {
            let (url, sha256) = paper_build(http, &version).await?;
            inst.log("[ember] Downloading Paper");
            download(http, &url, &tmp, Verify::Sha256(sha256)).await?;
            place(data.clone(), tmp.clone(), "server.jar", owner).await?;
            StartSpec::Jar { path: "server.jar".into() }
        }
        Flavor::Fabric => {
            let url = fabric_url(http, &version).await?;
            inst.log("[ember] Downloading the Fabric launcher");
            download(http, &url, &tmp, Verify::Tls).await?;
            place(data.clone(), tmp.clone(), "server.jar", owner).await?;
            StartSpec::Jar { path: "server.jar".into() }
        }
        Flavor::Forge => {
            let forge = forge_build(http, &version).await?;
            validate_version(&forge)?;
            let url = format!("{FORGE_MAVEN}/{version}-{forge}/forge-{version}-{forge}-installer.jar");
            inst.log(&format!("[ember] Downloading Forge {forge}"));
            download(http, &url, &tmp, Verify::Tls).await?;
            place(data.clone(), tmp.clone(), "forge-installer.jar", owner).await?;
            inst.log("[ember] Running the Forge installer inside the sandbox");
            let argv = vec![
                "/opt/java/bin/java".to_string(),
                "-jar".into(),
                "forge-installer.jar".into(),
                "--installServer".into(),
            ];
            mgr.run_once(inst, argv).await.context("Forge installer")?;
            let d = data.clone();
            let spec = tokio::task::spawn_blocking(move || locate_forge_start(&d)).await??;
            let d = data.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let root = files::open_root(&d)?;
                files::remove(&root, "forge-installer.jar")
            })
            .await??;
            spec
        }
        Flavor::Bedrock | Flavor::Custom => unreachable!("handled above"),
    };

    let d = data.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let root = files::open_root(&d)?;
        // The API refuses to create a server unless the operator accepted the EULA.
        files::write_text(&root, "eula.txt", "eula=true\n", owner)
    })
    .await??;
    inst.update(|r| r.start = Some(start));
    Ok(())
}

async fn paper_build(http: &reqwest::Client, version: &str) -> Result<(String, String)> {
    let v: serde_json::Value = get_json(http, &format!("{PAPER_API}/versions/{version}/builds/latest")).await?;
    parse_paper_build(&v)
}

fn parse_paper_build(v: &serde_json::Value) -> Result<(String, String)> {
    let d = v.get("downloads").and_then(|d| d.get("server:default")).ok_or_else(|| anyhow!("Paper build has no server download"))?;
    let url = d.get("url").and_then(|u| u.as_str()).ok_or_else(|| anyhow!("Paper build has no URL"))?;
    let sha = d.pointer("/checksums/sha256").and_then(|s| s.as_str()).ok_or_else(|| anyhow!("Paper build has no checksum"))?;
    Ok((url.to_string(), sha.to_string()))
}

async fn fabric_url(http: &reqwest::Client, version: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct LoaderEntry {
        loader: Versioned,
    }
    #[derive(Deserialize)]
    struct Versioned {
        version: String,
    }
    let loaders: Vec<LoaderEntry> = get_json(http, &format!("{FABRIC_META}/loader/{version}")).await?;
    let installers: Vec<Versioned> = get_json(http, &format!("{FABRIC_META}/installer")).await?;
    let loader = &loaders.first().ok_or_else(|| anyhow!("Fabric does not support {version}"))?.loader.version;
    let installer = &installers.first().ok_or_else(|| anyhow!("no Fabric installer available"))?.version;
    validate_version(loader)?;
    validate_version(installer)?;
    Ok(format!("{FABRIC_META}/loader/{version}/{loader}/{installer}/server/jar"))
}

async fn forge_build(http: &reqwest::Client, version: &str) -> Result<String> {
    #[derive(Deserialize)]
    struct P {
        promos: std::collections::HashMap<String, String>,
    }
    let p: P = get_json(http, FORGE_PROMOS).await?;
    p.promos
        .get(&format!("{version}-recommended"))
        .or_else(|| p.promos.get(&format!("{version}-latest")))
        .cloned()
        .ok_or_else(|| anyhow!("Forge does not support {version}"))
}

/// Modern Forge starts from an argument file, older Forge from a universal jar.
fn locate_forge_start(data: &Path) -> Result<StartSpec> {
    let root = files::open_root(data)?;
    let base = "libraries/net/minecraftforge/forge";
    if let Ok(builds) = files::list(&root, base) {
        for b in builds.iter().filter(|b| b.is_dir && !b.is_symlink) {
            let rel = format!("{base}/{}/unix_args.txt", b.name);
            if files::open_regular(&root, Path::new(&rel)).is_ok() {
                return Ok(StartSpec::ArgsFile { path: rel });
            }
        }
    }
    let jar = files::list(&root, "")?
        .into_iter()
        .find(|e| !e.is_dir && !e.is_symlink && e.name.starts_with("forge-") && e.name.ends_with(".jar") && !e.name.contains("installer"));
    match jar {
        Some(j) => Ok(StartSpec::Jar { path: j.name }),
        None => bail!("the Forge installer finished but no start file was found"),
    }
}

fn extract_bedrock(archive: &Path, data: &Path, owner: Owner) -> Result<()> {
    let root = files::open_root(data)?;
    let mut zip = zip::ZipArchive::new(std::fs::File::open(archive)?).context("read Bedrock archive")?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let Some(name) = entry.enclosed_name() else { continue };
        if entry.is_dir() {
            files::mkdirs(&root, &name, owner)?;
            continue;
        }
        let mode = if name == Path::new("bedrock_server") { 0o755 } else { 0o644 };
        let mut out = files::create_owned(&root, &name, owner, mode)?;
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        out.write_all(&buf)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bedrock_links_must_be_official() {
        let ok = "https://www.minecraft.net/bedrockdedicatedserver/bin-linux/bedrock-server-1.21.50.07.zip";
        assert_eq!(validate_bedrock_url(ok).unwrap(), "1.21.50.07");
        for bad in [
            "http://www.minecraft.net/bin-linux/bedrock-server-1.zip",
            "https://minecraft.net.evil.example/bedrock-server-1.zip",
            "https://evil.example/www.minecraft.net/bedrock-server-1.zip",
            "https://www.minecraft.net/bin-linux/other.zip",
            "https://www.minecraft.net/bin-linux/bedrock-server-$(id).zip",
        ] {
            assert!(validate_bedrock_url(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn versions_cannot_inject_into_urls() {
        assert!(validate_version("1.21.11-rc3").is_ok());
        assert!(validate_version("26.3").is_ok());
        for bad in ["", "../../evil", "1.0?x=y", "a/b", "a b"] {
            assert!(validate_version(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn java_runtime_mapping_prefers_published_builds() {
        assert_eq!(runtime_major(8), 8);
        assert_eq!(runtime_major(16), 17);
        assert_eq!(runtime_major(21), 21);
        assert_eq!(runtime_major(25), 25);
    }

    #[test]
    fn parses_paper_responses() {
        let v = serde_json::json!({"versions": {"26.3": ["26.3", "26.3-rc-3"], "1.21": ["1.21.11", "1.21.10"]}});
        let list = paper_versions(&v);
        assert_eq!(list[0].id, "26.3", "a final release outranks its release candidates");
        assert!(list[0].stable);
        assert!(list.iter().any(|g| g.id == "26.3-rc-3" && !g.stable));
        assert_eq!(list.last().unwrap().id, "1.21.10");

        let b = serde_json::json!({"downloads": {"server:default": {"url": "https://x/y.jar", "checksums": {"sha256": "abc"}}}});
        assert_eq!(parse_paper_build(&b).unwrap(), ("https://x/y.jar".to_string(), "abc".to_string()));
        assert!(parse_paper_build(&serde_json::json!({"downloads": {}})).is_err());
    }

    #[test]
    fn forge_versions_are_deduplicated_and_sorted() {
        let list = forge_versions(["1.20.1-latest", "1.20.1-recommended", "26.3-latest", "1.9-latest"].into_iter());
        let ids: Vec<_> = list.iter().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, ["26.3", "1.20.1", "1.9"]);
    }
}
