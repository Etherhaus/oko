//! The updater: ask GitHub for the newest release, download it, check the
//! minisign signature, and swap the binary in place.
//!
//! The rule the module is built around: nothing is installed that was not
//! verified. A missing signature, a signature made with another key, a broken
//! archive — each of them ends the install with the old binary untouched and
//! the temporary file gone.
//!
//! The release contract, fixed before the first release exists:
//!
//! - tags are `vX.Y.Z`;
//! - the assets are `oko-<version>-<os>-<arch>.tar.gz`, with the `oko` binary
//!   inside, and `oko-<version>-<os>-<arch>.tar.gz.minisig` beside it;
//! - the list comes from `GET https://api.github.com/repos/etherhaus/oko/releases/latest`.
//!
//! `OKO_UPDATE_URL` points the updater at a stand-in: an `http://` base URL or
//! a directory laid out like the API. It exists so the whole path can be
//! exercised before the repository has a single release.

use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;

/// The version this binary was built as.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// The release key, exactly as `minisign -G` writes it: the comment line and
/// the base64 line. The private half never enters the repository.
const PUBLIC_KEY: &str = include_str!("../keys/minisign.pub");

/// Where the releases live.
const REPOSITORY: &str = "etherhaus/oko";

/// The largest download the updater will take. A release is a few megabytes;
/// anything past this is not a release.
pub const MAX_DOWNLOAD: u64 = 200 * 1024 * 1024;

/// The largest signature file it will take.
const MAX_SIGNATURE: u64 = 8 * 1024;

/// The largest release JSON it will take.
const MAX_JSON: u64 = 1024 * 1024;

/// How long the whole download may take, however slow the link is.
const DOWNLOAD_BUDGET: Duration = Duration::from_secs(600);

/// The name of the binary inside the archive.
const BINARY: &str = if cfg!(windows) { "oko.exe" } else { "oko" };

/// The file the new binary is written to before it takes the old one's place.
const STAGED: &str = ".oko-update";

/// The folders a package manager owns. A binary there is updated by the
/// package manager, not by itself: replacing it would leave the package
/// database lying about what is installed.
const SYSTEM_PREFIXES: [&str; 5] = ["/usr", "/usr/local", "/opt", "/bin", "/sbin"];

/// What went wrong, in the updater's own words.
///
/// The window translates the part it can and shows the rest as it is: a
/// signature that does not match is not something to paraphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The network or the server said no.
    Network(String),
    /// The release has no asset for this platform.
    NoAsset(String),
    /// The download is bigger than a release should be.
    TooLarge,
    /// The download took longer than the budget.
    TimedOut,
    /// The signature is missing, unreadable, or does not match.
    Signature(String),
    /// The archive is not a tarball with the binary in it.
    Archive(String),
    /// The binary lives where the package manager owns it.
    Managed(String),
    /// Writing next to the binary failed.
    Install(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Network(why) => write!(out, "{why}"),
            Error::NoAsset(name) => write!(out, "this release has no {name}"),
            Error::TooLarge => write!(out, "the download is far larger than a release should be"),
            Error::TimedOut => write!(out, "the download took too long"),
            Error::Signature(why) => write!(out, "{why}"),
            Error::Archive(why) => write!(out, "{why}"),
            Error::Managed(path) => write!(
                out,
                "{path} belongs to the package manager: update it with the package manager"
            ),
            Error::Install(why) => write!(out, "{why}"),
        }
    }
}

impl std::error::Error for Error {}

/// The updater's result.
pub type Result<T> = std::result::Result<T, Error>;

/// One file of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    /// The URL the JSON gave. For a directory stand-in it is a file name.
    pub url: String,
    pub size: u64,
}

/// A release newer than this binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// `0.5.0`: the tag without its `v`.
    pub version: String,
    /// `v0.5.0`, as GitHub spells it.
    pub tag: String,
    pub assets: Vec<Asset>,
}

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// The newest release is not newer than this binary.
    UpToDate,
    /// A newer release is on GitHub.
    Available(Release),
}

/// Where the release list comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// `api.github.com/repos/etherhaus/oko`.
    GitHub,
    /// A base URL that stands in for it: `OKO_UPDATE_URL=http://127.0.0.1:8000`.
    Base(String),
    /// A directory that stands in for it: `OKO_UPDATE_URL=/tmp/release`.
    Dir(PathBuf),
}

impl Source {
    /// The stand-in named by `OKO_UPDATE_URL`, or GitHub itself.
    fn from_env() -> Source {
        match std::env::var("OKO_UPDATE_URL") {
            Ok(value) if value.starts_with("http://") || value.starts_with("https://") => {
                Source::Base(value.trim_end_matches('/').to_string())
            }
            Ok(value) if !value.is_empty() => Source::Dir(PathBuf::from(value)),
            _ => Source::GitHub,
        }
    }

    /// The newest release's JSON. `None` means the repository has no releases
    /// yet, which is not a failure: it is the state before the first one.
    fn latest(&self) -> Result<Option<Vec<u8>>> {
        match self {
            Source::GitHub => http_get(
                &format!("https://api.github.com/repos/{REPOSITORY}/releases/latest"),
                MAX_JSON,
            ),
            Source::Base(base) => http_get(&format!("{base}/releases/latest"), MAX_JSON),
            Source::Dir(dir) => {
                let path = dir.join("releases").join("latest");
                match fs::read(&path) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                    Err(err) => Err(Error::Network(format!("cannot read {}: {err}", path.display()))),
                }
            }
        }
    }

    /// One asset of the release, whole.
    fn asset_bytes(&self, asset: &Asset, limit: u64) -> Result<Vec<u8>> {
        match self {
            Source::Dir(dir) => {
                let path = dir.join(&asset.url);
                let bytes =
                    fs::read(&path).map_err(|err| Error::Network(format!("cannot read {}: {err}", path.display())))?;
                if bytes.len() as u64 > limit {
                    return Err(Error::TooLarge);
                }
                Ok(bytes)
            }
            _ => http_get(&asset.url, limit)?
                .ok_or_else(|| Error::Network(format!("{} is not on the release", asset.name))),
        }
    }

    /// One asset of the release, streamed into `path` so a large archive never
    /// sits in memory.
    fn download(&self, asset: &Asset, path: &Path, report: &dyn Fn(f32)) -> Result<()> {
        let deadline = Instant::now() + DOWNLOAD_BUDGET;
        let mut out =
            fs::File::create(path).map_err(|err| Error::Install(format!("cannot save the download: {err}")))?;
        match self {
            Source::Dir(dir) => {
                let file = fs::File::open(dir.join(&asset.url))
                    .map_err(|err| Error::Network(format!("cannot read {}: {err}", asset.url)))?;
                let total = file.metadata().map(|meta| meta.len()).unwrap_or(asset.size);
                copy_limited(
                    &mut BufReader::new(file),
                    &mut out,
                    total,
                    MAX_DOWNLOAD,
                    deadline,
                    report,
                )?;
            }
            _ => {
                let agent = agent();
                let user_agent = user_agent();
                let mut response = agent
                    .get(&asset.url)
                    .header("User-Agent", user_agent.as_str())
                    .call()
                    .map_err(|err| Error::Network(format!("cannot download the update: {err}")))?;
                let status = response.status().as_u16();
                if status != 200 {
                    return Err(Error::Network(format!("the download answered with HTTP {status}")));
                }
                let total = response.body().content_length().unwrap_or(asset.size).max(1);
                let mut reader = response.body_mut().as_reader();
                copy_limited(&mut reader, &mut out, total, MAX_DOWNLOAD, deadline, report)?;
            }
        }
        out.flush()
            .map_err(|err| Error::Install(format!("cannot save the download: {err}")))?;
        Ok(())
    }
}

/// The HTTP client of the updater: a short connect, a patient read, and no
/// error for a status the caller wants to look at itself.
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_per_read(Some(Duration::from_secs(60)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// GitHub refuses a request without one.
fn user_agent() -> String {
    format!("oko/{CURRENT} (+https://github.com/{REPOSITORY})")
}

/// `GET url`, with a 404 read as "there is nothing there" rather than a
/// failure. Redirects are followed: the assets live on another host.
fn http_get(url: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    let agent = agent();
    let user_agent = user_agent();
    let mut response = agent
        .get(url)
        .header("User-Agent", user_agent.as_str())
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|err| Error::Network(format!("cannot reach GitHub: {err}")))?;
    match response.status().as_u16() {
        200 => {}
        404 => return Ok(None),
        code => {
            return Err(Error::Network(format!("GitHub answered with HTTP {code}")));
        }
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|err| Error::Network(format!("cannot read the answer: {err}")))?;
    Ok(Some(body))
}

/// The release JSON, as much of it as the updater reads.
#[derive(Debug, Deserialize)]
struct Latest {
    tag_name: String,
    #[serde(default)]
    assets: Vec<RawAsset>,
}

#[derive(Debug, Deserialize)]
struct RawAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

/// Whether `candidate` is an update for `current`.
///
/// A pre-release is not an update for a stable build: it is a test build that
/// happens to sort above the release before it. A build that is itself a
/// pre-release does take the next one.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (Ok(candidate), Ok(current)) = (semver::Version::parse(candidate), semver::Version::parse(current)) else {
        return false;
    };
    if candidate <= current {
        return false;
    }
    !(!candidate.pre.is_empty() && current.pre.is_empty())
}

/// The asset name this platform takes: `oko-<version>-<os>-<arch>.tar.gz`.
pub fn asset_name(version: &str) -> String {
    format!(
        "oko-{version}-{}-{}.tar.gz",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// The asset called `name`, or an honest error naming what is missing.
fn pick<'a>(assets: &'a [Asset], name: &str) -> Result<&'a Asset> {
    assets
        .iter()
        .find(|asset| asset.name == name)
        .ok_or_else(|| Error::NoAsset(name.to_string()))
}

/// Ask the release list what the newest version is.
pub fn check() -> Result<Check> {
    check_with(&Source::from_env())
}

fn check_with(source: &Source) -> Result<Check> {
    let Some(body) = source.latest()? else {
        // No releases yet: the binary is as new as anything that exists.
        return Ok(Check::UpToDate);
    };
    let latest: Latest = serde_json::from_slice(&body)
        .map_err(|err| Error::Network(format!("GitHub sent something other than a release: {err}")))?;
    let version = latest.tag_name.trim_start_matches('v').to_string();
    if !is_newer(&version, CURRENT) {
        return Ok(Check::UpToDate);
    }
    Ok(Check::Available(Release {
        version,
        tag: latest.tag_name,
        assets: latest
            .assets
            .into_iter()
            .map(|raw| Asset {
                name: raw.name,
                url: raw.browser_download_url,
                size: raw.size,
            })
            .collect(),
    }))
}

/// Download the release, check its signature, and put the new binary in place.
///
/// The old binary keeps running: on Linux renaming over it does not touch the
/// open file. The caller restarts the process to pick the new one up.
/// The path that was replaced comes back with it: after the swap the running
/// inode has no name left, so the restart needs the name the install used.
pub fn install(release: &Release, report: &dyn Fn(f32)) -> Result<PathBuf> {
    let exe =
        std::env::current_exe().map_err(|err| Error::Install(format!("cannot find the running binary: {err}")))?;
    let cache = cache_dir().ok_or_else(|| Error::Install("this system has no cache directory".to_string()))?;
    install_into(&Source::from_env(), release, &exe, &cache, report)
}

fn install_into(source: &Source, release: &Release, exe: &Path, cache: &Path, report: &dyn Fn(f32)) -> Result<PathBuf> {
    let name = asset_name(&release.version);
    let asset = pick(&release.assets, &name)?;
    fs::create_dir_all(cache).map_err(|err| Error::Install(format!("cannot create {}: {err}", cache.display())))?;
    let tarball = cache.join(&name);
    let result = install_verified(source, release, asset, &tarball, exe, report);
    // Nothing half-downloaded stays behind: the next attempt starts clean.
    let _ = fs::remove_file(&tarball);
    result.map(|()| exe.to_path_buf())
}

fn install_verified(
    source: &Source,
    release: &Release,
    asset: &Asset,
    tarball: &Path,
    exe: &Path,
    report: &dyn Fn(f32),
) -> Result<()> {
    source.download(asset, tarball, report)?;

    // The signature is fetched by name, not by URL: a release that forgot it
    // is refused here, before anything is unpacked.
    let signature_name = format!("{}.minisig", asset.name);
    let signature_asset = pick(&release.assets, &signature_name)?;
    let signature = source.asset_bytes(signature_asset, MAX_SIGNATURE)?;
    let signature =
        String::from_utf8(signature).map_err(|_| Error::Signature("the signature is not text".to_string()))?;
    let bytes = fs::read(tarball).map_err(|err| Error::Install(format!("cannot read the download back: {err}")))?;
    verify(&bytes, &signature)?;

    // Verified. Only now does the question of where the binary lives matter:
    // a package-managed binary can be downloaded and checked, but not
    // replaced.
    if managed(exe) {
        return Err(Error::Managed(exe.display().to_string()));
    }
    let staged = exe
        .parent()
        .map(|dir| dir.join(STAGED))
        .ok_or_else(|| Error::Install("cannot find the folder the binary is in".to_string()))?;
    extract(tarball, &staged)?;
    if let Err(err) = swap(&staged, exe) {
        let _ = fs::remove_file(&staged);
        return Err(err);
    }
    Ok(())
}

/// Check `data` against the release key.
fn verify(data: &[u8], signature: &str) -> Result<()> {
    verify_with_key(PUBLIC_KEY, data, signature)
}

/// The same with the key passed in, so a test can use a key of its own.
fn verify_with_key(key: &str, data: &[u8], signature: &str) -> Result<()> {
    let key = minisign_verify::PublicKey::decode(key)
        .map_err(|err| Error::Signature(format!("the built-in release key is unreadable: {err}")))?;
    let signature = minisign_verify::Signature::decode(signature)
        .map_err(|err| Error::Signature(format!("the update's signature is unreadable: {err}")))?;
    key.verify(data, &signature, false).map_err(|err| match err {
        minisign_verify::Error::UnexpectedKeyId => {
            Error::Signature("the update was signed with a key that is not Oko's".to_string())
        }
        minisign_verify::Error::InvalidSignature => {
            Error::Signature("the signature does not match the download".to_string())
        }
        minisign_verify::Error::UnexpectedAlgorithm | minisign_verify::Error::UnsupportedAlgorithm => {
            Error::Signature("the signature is in a format this build cannot check".to_string())
        }
        other => Error::Signature(format!("the signature could not be checked: {other}")),
    })
}

/// Copy `reader` into `out`, reporting how far along it is.
///
/// The limit and the deadline are checked between reads, so a server that
/// never stops sending, or one that stops sending at all, both end here.
fn copy_limited(
    reader: &mut impl Read,
    out: &mut impl Write,
    total: u64,
    limit: u64,
    deadline: Instant,
    report: &dyn Fn(f32),
) -> Result<u64> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    let mut last = -1.0f32;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::TimedOut);
        }
        let read = reader
            .read(&mut buffer)
            .map_err(|err| Error::Network(format!("the download stopped: {err}")))?;
        if read == 0 {
            return Ok(done);
        }
        done += read as u64;
        if done > limit {
            return Err(Error::TooLarge);
        }
        out.write_all(&buffer[..read])
            .map_err(|err| Error::Install(format!("cannot save the download: {err}")))?;
        let fraction = if total == 0 {
            0.0
        } else {
            (done as f32 / total as f32).min(1.0)
        };
        if fraction - last >= 0.01 {
            last = fraction;
            report(fraction);
        }
    }
}

/// Write the `oko` binary out of the archive to `staged`.
///
/// The entry is copied by hand rather than unpacked by path: an archive that
/// carries `../../etc/passwd` has nowhere to go.
fn extract(tarball: &Path, staged: &Path) -> Result<()> {
    let file = fs::File::open(tarball).map_err(|err| Error::Archive(format!("cannot open the download: {err}")))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(BufReader::new(file)));
    let entries = archive
        .entries()
        .map_err(|err| Error::Archive(format!("the download is not a valid archive: {err}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|err| Error::Archive(format!("the download is not a valid archive: {err}")))?;
        let path = entry
            .path()
            .map_err(|err| Error::Archive(format!("the archive has an unreadable name: {err}")))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        if !path.file_name().is_some_and(|name| name == BINARY) {
            continue;
        }
        let mut out = fs::File::create(staged)
            .map_err(|err| Error::Install(format!("cannot write next to the binary: {err}")))?;
        io::copy(&mut entry, &mut out).map_err(|err| Error::Archive(format!("cannot unpack the binary: {err}")))?;
        return Ok(());
    }
    Err(Error::Archive(format!("the archive has no {BINARY} in it")))
}

/// Put `staged` in `exe`'s place.
fn swap(staged: &Path, exe: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(staged, fs::Permissions::from_mode(0o755))
            .map_err(|err| Error::Install(format!("cannot make the new binary runnable: {err}")))?;
        // A rename over a running binary is allowed: the running process keeps
        // the file it opened, the next start gets the new one.
        fs::rename(staged, exe).map_err(|err| Error::Install(format!("cannot replace {}: {err}", exe.display())))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        swap_windows(staged, exe).map_err(|err| Error::Install(format!("cannot replace {}: {err}", exe.display())))
    }
}

/// The Windows dance: a running `.exe` cannot be replaced, but it can be
/// renamed out of the way, and the new one takes its name.
///
/// Kept apart from [`swap`] so it can be tested on Linux, where the rename
/// rules are the same and the running-binary rule is not.
#[cfg_attr(not(windows), allow(dead_code))]
fn swap_windows(staged: &Path, exe: &Path) -> io::Result<()> {
    let old = exe.with_extension("old");
    let _ = fs::remove_file(&old);
    fs::rename(exe, &old)?;
    if let Err(err) = fs::rename(staged, exe) {
        // The new one did not land: put the old one back rather than leave the
        // user without a binary.
        let _ = fs::rename(&old, exe);
        return Err(err);
    }
    Ok(())
}

/// Whether the binary lives where a package manager owns it.
///
/// The path is resolved first, so a symlink into `/usr/bin` counts as `/usr/bin`
/// and not as wherever the link sits. A path that does not exist is taken as
/// written: the answer is about the folder, not about the file.
pub fn managed(exe: &Path) -> bool {
    let path = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let text = path.to_string_lossy();
    SYSTEM_PREFIXES
        .iter()
        .any(|prefix| text == *prefix || text.starts_with(&format!("{prefix}/")))
}

/// Restart the process on the binary that is now in place.
///
/// On Unix the process image is replaced, so this does not return on success.
/// On Windows the new binary is started and the caller exits.
/// Replace this process with the binary at `exe`.
///
/// The path comes from the install rather than from `current_exe`: once the
/// new binary is renamed over the old one, the running inode has no name left
/// and Linux reports the old path with a `" (deleted)"` suffix that cannot be
/// executed.
pub fn restart(exe: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(exe).exec();
        Err(Error::Install(format!("cannot restart: {err}")))
    }
    #[cfg(windows)]
    {
        std::process::Command::new(exe)
            .spawn()
            .map_err(|err| Error::Install(format!("cannot restart: {err}")))?;
        Ok(())
    }
}

/// Where the download is kept while it is checked: `~/.cache/oko` on Linux,
/// `%LOCALAPPDATA%\oko\cache` on Windows, `~/Library/Caches/oko` on macOS.
pub fn cache_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(|base| PathBuf::from(base).join("oko").join("cache"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library").join("Caches").join("oko"))
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|base| base.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .map(|base| base.join("oko"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory under the system temp folder that goes away with the test.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let path = std::env::temp_dir().join(format!("oko-update-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("a scratch directory");
            Scratch(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A real release archive, made with `tar czf` and signed with the release key
    /// in `keys/`: `oko-0.5.0-linux-x86_64/oko` holding `the new binary`.
    ///
    /// It is embedded rather than built here because a signature covers exact
    /// bytes, and a gzip stream is not the same twice.
    const SIGNED_TARBALL: &str = "\
        1f8b0800000000000003edd1d10a82301480e13dca5e40db7467eb6dc248482a0553b2b74f2f82884637bbc9feefe6c036d8c6df9dbacce4929becdcb4e3944d5bbff36ea35232b320b24c1bc4bcce2765a508be28a50c4e19eb8c15a525e92b22c6eb50f55aabc3a519fa7bfcdcb7fd1fd57dee3f2fa7bb6309ec9d8bf7b7febdbf14737f93ee09717fde7f38d6baad6f7adfb4d50abf07000000000000000000000000acda03641a7cef00280000";

    /// The `.minisig` of [`SIGNED_TARBALL`], made with the release key.
    const SIGNED_SIGNATURE: &str = "\
        untrusted comment: signature from minisign secret key\n\
        RURKvw8XRG50X/lGbIHXXiKmuwdcguD+AsVy7v/UfAnUeV1q5xNDC7itkiBTJbwM4KkOZOJw8tyGDPklXOiNBCXp37CxFP9A1wg=\n\
        trusted comment: oko 0.5.0 linux x86_64\n\
        9vaEfgZIzNY7xtndw4EETJms0qpucpZKNCpmpICHaYPm8S9bv3lZ2xUyeSV3j91WedgC00DP3Lf2S+2K7Pe0DA==\n";

    /// The bytes of [`SIGNED_TARBALL`].
    fn signed_tarball() -> Vec<u8> {
        let text: String = SIGNED_TARBALL.split_whitespace().collect();
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex"))
            .collect()
    }

    fn asset(name: &str) -> Asset {
        Asset {
            name: name.to_string(),
            url: name.to_string(),
            size: 0,
        }
    }

    fn release(version: &str, assets: Vec<Asset>) -> Release {
        Release {
            version: version.to_string(),
            tag: format!("v{version}"),
            assets,
        }
    }

    /// A tarball with the given files in it.
    fn write_tarball(path: &Path, files: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("the tarball");
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        let mut builder = tar::Builder::new(encoder);
        for (name, body) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *body).expect("the entry");
        }
        builder.into_inner().expect("the archive").finish().expect("the gzip");
    }

    #[test]
    fn a_newer_version_is_an_update() {
        assert!(is_newer("0.5.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.1.0"), "the same version is not newer");
        assert!(!is_newer("0.0.9", "0.1.0"), "an older version is not newer");
    }

    #[test]
    fn a_prerelease_is_not_an_update_for_a_stable_build() {
        assert!(!is_newer("0.5.0-beta.1", "0.1.0"));
        assert!(!is_newer("0.5.0-rc.1", "0.5.0"));
        // A build that is itself a pre-release does take the next one.
        assert!(is_newer("0.5.0-beta.2", "0.5.0-beta.1"));
        assert!(is_newer("0.5.0", "0.5.0-beta.1"));
    }

    #[test]
    fn a_version_that_is_not_semver_is_never_newer() {
        assert!(!is_newer("nightly", "0.1.0"));
        assert!(!is_newer("0.5.0", "not a version"));
        assert!(!is_newer("", "0.1.0"));
    }

    #[test]
    fn the_asset_name_follows_the_platform() {
        assert_eq!(
            asset_name("0.5.0"),
            format!("oko-0.5.0-{}-{}.tar.gz", std::env::consts::OS, std::env::consts::ARCH)
        );
    }

    #[test]
    fn the_asset_for_this_platform_is_picked() {
        let name = asset_name("0.5.0");
        let assets = vec![
            asset("oko-0.5.0-windows-x86_64.tar.gz"),
            asset(&name),
            asset(&format!("{name}.minisig")),
        ];
        assert_eq!(pick(&assets, &name).map(|found| found.name.as_str()), Ok(name.as_str()));
    }

    #[test]
    fn a_release_without_this_platform_is_an_honest_error() {
        let assets = vec![asset("oko-0.5.0-windows-x86_64.tar.gz")];
        let name = asset_name("0.5.0");
        assert_eq!(
            pick(&assets, &name),
            Err(Error::NoAsset(name.clone())),
            "the error names the file that is missing"
        );
    }

    #[test]
    fn a_repository_without_releases_is_up_to_date_not_a_failure() {
        let scratch = Scratch::new("no-releases");
        let source = Source::Dir(scratch.path().to_path_buf());
        assert_eq!(check_with(&source), Ok(Check::UpToDate));
    }

    #[test]
    fn a_release_json_becomes_a_release() {
        let scratch = Scratch::new("release-json");
        fs::create_dir_all(scratch.path().join("releases")).expect("the releases folder");
        let name = asset_name("0.5.0");
        let json = format!(
            r#"{{"tag_name": "v0.5.0", "assets": [
                {{"name": "{name}", "browser_download_url": "{name}", "size": 4096}},
                {{"name": "{name}.minisig", "browser_download_url": "{name}.minisig", "size": 300}}
            ]}}"#
        );
        fs::write(scratch.path().join("releases").join("latest"), json).expect("the release");

        let source = Source::Dir(scratch.path().to_path_buf());
        let Check::Available(release) = check_with(&source).expect("a release") else {
            panic!("a newer version is an update");
        };
        assert_eq!(release.version, "0.5.0");
        assert_eq!(release.tag, "v0.5.0");
        assert_eq!(release.assets.len(), 2);
        assert_eq!(release.assets[0].name, name);
        assert_eq!(release.assets[0].size, 4096);
    }

    #[test]
    fn a_release_that_is_not_newer_is_up_to_date() {
        let scratch = Scratch::new("same-version");
        fs::create_dir_all(scratch.path().join("releases")).expect("the releases folder");
        let json = format!(r#"{{"tag_name": "v{CURRENT}", "assets": []}}"#);
        fs::write(scratch.path().join("releases").join("latest"), json).expect("the release");
        let source = Source::Dir(scratch.path().to_path_buf());
        assert_eq!(check_with(&source), Ok(Check::UpToDate));
    }

    #[test]
    fn the_release_key_in_the_repository_is_readable() {
        assert!(
            minisign_verify::PublicKey::decode(PUBLIC_KEY).is_ok(),
            "keys/minisign.pub must be a minisign public key"
        );
        assert_eq!(
            PUBLIC_KEY.lines().count(),
            2,
            "the comment line and the base64 line, nothing else"
        );
    }

    #[test]
    fn a_signed_archive_passes_verification() {
        assert_eq!(verify(&signed_tarball(), SIGNED_SIGNATURE), Ok(()));
    }

    #[test]
    fn a_tampered_archive_is_refused() {
        let mut bytes = signed_tarball();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let err = verify(&bytes, SIGNED_SIGNATURE);
        assert!(matches!(err, Err(Error::Signature(_))), "{err:?}");
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        // A well-formed key that did not make this signature.
        let other = "untrusted comment: minisign public key 1\n\
            RWT9usxyt6R/zXg0l9DYvM9TF1bIONDyzZwB6HvRY6gt1ONRphqk6Mt\n";
        let err = verify_with_key(other, &signed_tarball(), SIGNED_SIGNATURE);
        assert!(matches!(err, Err(Error::Signature(_))), "{err:?}");
    }

    #[test]
    fn a_signature_that_is_not_a_signature_is_refused() {
        assert!(matches!(
            verify(&signed_tarball(), "not a signature"),
            Err(Error::Signature(_))
        ));
    }

    #[test]
    fn a_download_that_never_ends_hits_the_deadline() {
        let mut reader = io::repeat(b'x');
        let mut out = Vec::new();
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            copy_limited(&mut reader, &mut out, 100, MAX_DOWNLOAD, past, &|_| {}),
            Err(Error::TimedOut)
        );
    }

    #[test]
    fn a_download_larger_than_the_limit_is_refused() {
        let mut reader = io::repeat(b'x').take(64);
        let mut out = Vec::new();
        let ahead = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            copy_limited(&mut reader, &mut out, 64, 32, ahead, &|_| {}),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn a_download_reports_how_far_along_it_is() {
        let mut reader = io::repeat(b'x').take(1000);
        let mut out = Vec::new();
        let ahead = Instant::now() + Duration::from_secs(60);
        let seen = std::cell::RefCell::new(Vec::new());
        let done = copy_limited(&mut reader, &mut out, 1000, MAX_DOWNLOAD, ahead, &|fraction| {
            seen.borrow_mut().push(fraction)
        })
        .expect("a short download");
        assert_eq!(done, 1000);
        assert_eq!(out.len(), 1000);
        let seen = seen.into_inner();
        assert!(!seen.is_empty(), "the progress was reported");
        assert_eq!(seen.last().copied(), Some(1.0), "it ends at the whole file");
    }

    #[test]
    fn the_guard_refuses_the_folders_a_package_manager_owns() {
        for path in ["/usr/bin/oko", "/usr/local/bin/oko", "/opt/oko/oko", "/bin/oko"] {
            assert!(managed(Path::new(path)), "{path} belongs to the package manager");
        }
        // A prefix that only looks like one is not one.
        assert!(!managed(Path::new("/usr2/bin/oko")));
        assert!(!managed(Path::new("/home/dmitry/.local/bin/oko")));
    }

    #[test]
    fn an_archive_without_the_binary_is_refused() {
        let scratch = Scratch::new("no-binary");
        let tarball = scratch.path().join("release.tar.gz");
        write_tarball(&tarball, &[("oko-0.5.0-linux-x86_64/README.md", b"nothing here")]);
        let staged = scratch.path().join(STAGED);
        let err = extract(&tarball, &staged);
        assert!(matches!(err, Err(Error::Archive(_))), "{err:?}");
        assert!(!staged.exists(), "nothing was written");
    }

    #[test]
    fn the_binary_is_taken_out_of_the_archive() {
        let scratch = Scratch::new("binary");
        let tarball = scratch.path().join("release.tar.gz");
        let inside = format!("oko-0.5.0-linux-x86_64/{BINARY}");
        write_tarball(
            &tarball,
            &[
                ("oko-0.5.0-linux-x86_64/README.md", b"nothing here"),
                (&inside, b"the new binary"),
            ],
        );
        let staged = scratch.path().join(STAGED);
        extract(&tarball, &staged).expect("the binary is in the archive");
        assert_eq!(fs::read(&staged).expect("the staged binary"), b"the new binary");
    }

    #[test]
    fn the_windows_swap_puts_the_new_binary_in_place() {
        let scratch = Scratch::new("swap");
        let exe = scratch.path().join("oko.exe");
        let staged = scratch.path().join(STAGED);
        fs::write(&exe, b"the old binary").expect("the old binary");
        fs::write(&staged, b"the new binary").expect("the new binary");

        swap_windows(&staged, &exe).expect("the swap");
        assert_eq!(fs::read(&exe).expect("the binary"), b"the new binary");
        assert!(!staged.exists(), "the staged file is gone");
        assert_eq!(
            fs::read(exe.with_extension("old")).expect("the old binary"),
            b"the old binary",
            "the old one is kept beside it"
        );
    }

    #[test]
    fn a_failed_windows_swap_puts_the_old_binary_back() {
        let scratch = Scratch::new("swap-fails");
        let exe = scratch.path().join("oko.exe");
        fs::write(&exe, b"the old binary").expect("the old binary");
        // The staged file is not there, so the second rename fails.
        let staged = scratch.path().join("missing");

        assert!(swap_windows(&staged, &exe).is_err());
        assert_eq!(
            fs::read(&exe).expect("the binary is back"),
            b"the old binary",
            "the user is not left without a binary"
        );
    }

    #[test]
    fn a_release_without_a_signature_is_refused_and_the_download_is_cleaned_up() {
        let scratch = Scratch::new("no-signature");
        let name = asset_name("0.5.0");
        write_tarball(
            &scratch.path().join(&name),
            &[("oko-0.5.0-linux-x86_64/oko", b"the new binary")],
        );
        let exe = scratch.path().join("oko");
        fs::write(&exe, b"the old binary").expect("the old binary");

        // The release lists the archive but not its signature.
        let release = release("0.5.0", vec![asset(&name)]);
        let cache = scratch.path().join("cache");
        let err = install_into(
            &Source::Dir(scratch.path().to_path_buf()),
            &release,
            &exe,
            &cache,
            &|_| {},
        );
        assert_eq!(err, Err(Error::NoAsset(format!("{name}.minisig"))));
        assert_eq!(
            fs::read(&exe).expect("the binary"),
            b"the old binary",
            "the old binary is untouched"
        );
        assert!(
            !cache.join(&name).exists(),
            "the download is cleaned up after a refusal"
        );
    }

    #[test]
    fn a_tampered_archive_is_refused_and_the_download_is_cleaned_up() {
        let scratch = Scratch::new("tampered");
        let name = asset_name("0.5.0");
        // A different archive than the one the signature covers.
        write_tarball(
            &scratch.path().join(&name),
            &[("oko-0.5.0-linux-x86_64/oko", b"the new binary")],
        );
        fs::write(scratch.path().join(format!("{name}.minisig")), SIGNED_SIGNATURE).expect("the signature");
        let exe = scratch.path().join("oko");
        fs::write(&exe, b"the old binary").expect("the old binary");

        let release = release("0.5.0", vec![asset(&name), asset(&format!("{name}.minisig"))]);
        let cache = scratch.path().join("cache");
        let err = install_into(
            &Source::Dir(scratch.path().to_path_buf()),
            &release,
            &exe,
            &cache,
            &|_| {},
        );
        assert!(matches!(err, Err(Error::Signature(_))), "{err:?}");
        assert_eq!(
            fs::read(&exe).expect("the binary"),
            b"the old binary",
            "the old binary is untouched"
        );
        assert!(
            !cache.join(&name).exists(),
            "the download is cleaned up after a refusal"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_verified_release_replaces_the_binary() {
        let scratch = Scratch::new("install");
        let name = asset_name("0.5.0");
        fs::write(scratch.path().join(&name), signed_tarball()).expect("the archive");
        fs::write(scratch.path().join(format!("{name}.minisig")), SIGNED_SIGNATURE).expect("the signature");
        let exe = scratch.path().join("oko");
        fs::write(&exe, b"the old binary").expect("the old binary");

        let release = release("0.5.0", vec![asset(&name), asset(&format!("{name}.minisig"))]);
        let cache = scratch.path().join("cache");
        let seen = std::cell::RefCell::new(Vec::new());
        let replaced = install_into(
            &Source::Dir(scratch.path().to_path_buf()),
            &release,
            &exe,
            &cache,
            &|fraction| seen.borrow_mut().push(fraction),
        )
        .expect("a verified release installs");

        // The restart execs this path: `current_exe` is the deleted inode by
        // now, so the install has to hand the name back.
        assert_eq!(replaced, exe, "the install reports the path it replaced");
        assert_eq!(fs::read(&exe).expect("the binary"), b"the new binary");
        assert!(!scratch.path().join(STAGED).exists(), "the staged file is gone");
        assert!(!cache.join(&name).exists(), "the download is gone");
        assert!(!seen.into_inner().is_empty(), "the progress was reported");
    }

    #[cfg(unix)]
    #[test]
    fn a_managed_binary_is_downloaded_and_checked_but_not_replaced() {
        let scratch = Scratch::new("managed");
        let name = asset_name("0.5.0");
        fs::write(scratch.path().join(&name), signed_tarball()).expect("the archive");
        fs::write(scratch.path().join(format!("{name}.minisig")), SIGNED_SIGNATURE).expect("the signature");
        let release = release("0.5.0", vec![asset(&name), asset(&format!("{name}.minisig"))]);
        let cache = scratch.path().join("cache");

        // A path the guard knows, without needing root to write there.
        let err = install_into(
            &Source::Dir(scratch.path().to_path_buf()),
            &release,
            Path::new("/usr/bin/oko"),
            &cache,
            &|_| {},
        );
        assert!(matches!(err, Err(Error::Managed(_))), "{err:?}");
        assert!(
            !cache.join(&name).exists(),
            "the download is cleaned up after the refusal"
        );
    }
}
