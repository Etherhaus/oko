//! The window's settings and the run history.
//!
//! Everything lives in the platform's config directory: `~/.config/oko` on
//! Linux, `%APPDATA%\oko` on Windows, `~/Library/Application Support/oko` on
//! macOS. The file is JSON with a schema version, so a future change can tell
//! an old file from a new one instead of half-reading it.
//!
//! The CLI does not read this file: `oko probe` stays a pure command.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The schema version of the file. A file with another version is ignored
/// rather than half-read.
pub const SCHEMA_VERSION: u32 = 1;

/// How many runs the history keeps.
pub const HISTORY_LIMIT: usize = 20;

/// How long the updater waits between automatic checks, in seconds.
pub const DAY: u64 = 24 * 60 * 60;

/// The smallest and largest probe timeout the window allows, in seconds.
pub const MIN_TIMEOUT: u64 = 1;
pub const MAX_TIMEOUT: u64 = 120;

/// One finished run, as the dashboard and the history remember it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    /// When the run finished, `YYYY-MM-DDTHH:MM:SSZ`.
    pub at: String,
    /// How long it took, in seconds.
    pub seconds: u64,
    /// Targets that came out reachable.
    pub ok: usize,
    /// Targets that came out blocked.
    pub blocked: usize,
    /// Targets the run could not decide about.
    pub unknown: usize,
}

/// The verdict one target had at the end of the last full run.
///
/// The table compares it with the fresh verdict and draws a triangle when the
/// target moved. It is the window's own memory: the exported report keeps its
/// own fields and never reads this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrevVerdict {
    pub domain: String,
    /// The verdict kind the table showed, in the engine's own words.
    pub verdict: String,
}

/// Everything the window remembers between runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// A file written before the field existed is version 1: the schema has
    /// not changed yet.
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub socks5: String,
    #[serde(default = "default_true")]
    pub dark: bool,
    #[serde(default = "default_lang")]
    pub lang: String,
    /// The coral frame around the window. Tiling window managers give the
    /// window the whole screen, and there the frame is just lost pixels.
    #[serde(default = "default_true")]
    pub frame: bool,
    /// The domains whose boxes are ticked. `None` means the file never said,
    /// so everything starts ticked.
    #[serde(default)]
    pub checked: Option<Vec<String>>,
    /// The domains the user added, in the order they were added.
    #[serde(default)]
    pub custom: Vec<String>,
    /// The last runs, oldest first.
    #[serde(default)]
    pub history: Vec<RunSummary>,
    /// The verdict each target had at the end of the last full run. A stopped
    /// or interrupted run leaves it alone: the delta compares two complete
    /// runs, not a run and a half.
    #[serde(default)]
    pub prev: Vec<PrevVerdict>,
    /// When the updater last asked GitHub, in seconds since the Unix epoch.
    /// The window asks at most once a day, and this is the clock it reads.
    #[serde(default)]
    pub last_check: u64,
    /// What that check found: `up-to-date`, `available`, `failed`, or empty
    /// when the updater has never run.
    #[serde(default)]
    pub last_state: String,
    /// The version that check found, when one was available. The dot on the
    /// settings button is drawn from it, so it survives a restart.
    #[serde(default)]
    pub last_version: String,
}

fn default_version() -> u32 {
    SCHEMA_VERSION
}

fn default_timeout() -> u64 {
    5
}

fn default_true() -> bool {
    true
}

fn default_lang() -> String {
    "en".to_string()
}

impl Default for Config {
    fn default() -> Config {
        Config {
            version: SCHEMA_VERSION,
            timeout: default_timeout(),
            socks5: String::new(),
            dark: true,
            lang: default_lang(),
            frame: true,
            checked: None,
            custom: Vec::new(),
            history: Vec::new(),
            prev: Vec::new(),
            last_check: 0,
            last_state: String::new(),
            last_version: String::new(),
        }
    }
}

impl Config {
    /// Read the file, or `None` when there is none, it is unreadable, or it was
    /// written by another schema version.
    ///
    /// The window tells a first launch from a saved state by this: on a first
    /// launch it follows the desktop's language, afterwards the file decides.
    pub fn load() -> Option<Config> {
        let path = path()?;
        let text = fs::read_to_string(path).ok()?;
        Config::from_json(&text)
    }

    /// Parse a file's contents. A file from another schema version is not
    /// half-read: it is ignored.
    pub fn from_json(text: &str) -> Option<Config> {
        let config: Config = serde_json::from_str(text).ok()?;
        if config.version != SCHEMA_VERSION {
            return None;
        }
        Some(config.sanitised())
    }

    /// The file's contents.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Write the file, creating the directory when it is missing.
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = path() else {
            return Err(std::io::Error::other("no config directory on this system"));
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.to_json())
    }

    /// Keep the values inside the ranges the window promises.
    fn sanitised(mut self) -> Config {
        self.timeout = self.timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT);
        if self.lang != "ru" && self.lang != "en" {
            self.lang = default_lang();
        }
        self.history.truncate(HISTORY_LIMIT);
        self
    }

    /// Add a finished run to the history, keeping the newest
    /// [`HISTORY_LIMIT`].
    pub fn remember(&mut self, summary: RunSummary) {
        self.history.push(summary);
        let excess = self.history.len().saturating_sub(HISTORY_LIMIT);
        self.history.drain(..excess);
    }

    /// The run before the last one, for the dashboard's delta.
    pub fn previous(&self) -> Option<&RunSummary> {
        let len = self.history.len();
        if len < 2 {
            return None;
        }
        self.history.get(len - 2)
    }

    /// The last run, if the history has one.
    pub fn last(&self) -> Option<&RunSummary> {
        self.history.last()
    }

    /// The verdict a target had at the end of the last full run.
    pub fn prev_of(&self, domain: &str) -> Option<&str> {
        self.prev
            .iter()
            .find(|entry| entry.domain == domain)
            .map(|entry| entry.verdict.as_str())
    }

    /// Replace the remembered verdicts with the ones a full run just produced.
    pub fn remember_verdicts(&mut self, verdicts: Vec<PrevVerdict>) {
        self.prev = verdicts;
    }

    /// Whether the updater should ask GitHub on this start.
    ///
    /// Once a day, counted from the last attempt rather than the last success:
    /// a machine that is offline for a week should not ask on every start.
    pub fn check_due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_check) >= DAY
    }

    /// Record what a check found, so the next start knows when to ask again
    /// and the settings section can say what the last answer was.
    pub fn remember_check(&mut self, now: u64, state: &str, version: &str) {
        self.last_check = now;
        self.last_state = state.to_string();
        self.last_version = version.to_string();
    }
}

/// The config directory of this platform.
pub fn path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("config.json"))
}

/// `~/.config/oko`, `%APPDATA%\oko` or `~/Library/Application Support/oko`.
pub fn config_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(|base| PathBuf::from(base).join("oko"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("oko")
        })
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|base| base.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|base| base.join("oko"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(at: &str, ok: usize, blocked: usize, unknown: usize) -> RunSummary {
        RunSummary {
            at: at.to_string(),
            seconds: 44,
            ok,
            blocked,
            unknown,
        }
    }

    #[test]
    fn the_defaults_are_the_ones_the_window_opens_with() {
        let config = Config::default();
        assert_eq!(config.version, SCHEMA_VERSION);
        assert_eq!(config.timeout, 5);
        assert!(config.socks5.is_empty());
        assert!(config.dark);
        assert!(config.frame);
        assert_eq!(config.lang, "en");
        assert!(config.checked.is_none(), "nothing saved means all ticked");
        assert!(config.custom.is_empty());
        assert!(config.history.is_empty());
        assert!(config.prev.is_empty(), "no run yet, nothing to compare");
        assert_eq!(config.last_check, 0, "the updater has never asked");
        assert!(config.last_state.is_empty());
        assert!(config.last_version.is_empty());
    }

    #[test]
    fn the_updater_asks_once_a_day() {
        let mut config = Config::default();
        assert!(config.check_due(1_000_000), "a fresh file has never asked");
        config.remember_check(1_000_000, "up-to-date", "");
        assert!(!config.check_due(1_000_000), "just asked");
        assert!(!config.check_due(1_000_000 + DAY - 1), "a second short of a day");
        assert!(config.check_due(1_000_000 + DAY), "a day later");
        // A clock that went backwards does not make it ask again.
        assert!(!config.check_due(999_000));
    }

    #[test]
    fn a_check_is_remembered_with_what_it_found() {
        let mut config = Config::default();
        config.remember_check(1_700_000_000, "available", "0.5.0");
        assert_eq!(config.last_check, 1_700_000_000);
        assert_eq!(config.last_state, "available");
        assert_eq!(config.last_version, "0.5.0");
        // A later check replaces the answer instead of adding to it.
        config.remember_check(1_700_100_000, "up-to-date", "");
        assert_eq!(config.last_state, "up-to-date");
        assert!(config.last_version.is_empty());
    }

    #[test]
    fn a_file_round_trips_through_json() {
        let mut config = Config {
            timeout: 9,
            socks5: "127.0.0.1:1080".to_string(),
            dark: false,
            lang: "ru".to_string(),
            frame: false,
            checked: Some(vec!["github.com".to_string()]),
            custom: vec!["example.org".to_string()],
            ..Config::default()
        };
        config.remember(summary("2026-11-14T17:24:45Z", 2, 4, 0));
        config.remember_verdicts(vec![PrevVerdict {
            domain: "github.com".to_string(),
            verdict: "dpi_sni".to_string(),
        }]);
        config.remember_check(1_700_000_000, "available", "0.5.0");

        let text = config.to_json();
        let back = Config::from_json(&text).expect("the file it wrote parses");
        assert_eq!(back, config);
    }

    #[test]
    fn an_empty_object_is_the_defaults() {
        let config = Config::from_json("{}").expect("an empty object is a valid file");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn a_file_from_another_schema_version_is_ignored() {
        assert!(Config::from_json(r#"{"version": 99, "timeout": 5}"#).is_none());
        assert!(Config::from_json("not json at all").is_none());
    }

    #[test]
    fn a_timeout_outside_the_range_is_clamped_on_load() {
        let config = Config::from_json(r#"{"version": 1, "timeout": 5000}"#).expect("parses");
        assert_eq!(config.timeout, MAX_TIMEOUT);
        let config = Config::from_json(r#"{"version": 1, "timeout": 0}"#).expect("parses");
        assert_eq!(config.timeout, MIN_TIMEOUT);
    }

    #[test]
    fn an_unknown_language_falls_back_to_english() {
        let config = Config::from_json(r#"{"version": 1, "lang": "de"}"#).expect("parses");
        assert_eq!(config.lang, "en");
    }

    #[test]
    fn the_history_keeps_the_newest_twenty() {
        let mut config = Config::default();
        for index in 0..25 {
            config.remember(summary(&format!("run {index}"), 1, 1, 1));
        }
        assert_eq!(config.history.len(), HISTORY_LIMIT);
        assert_eq!(config.history.first().map(|run| run.at.as_str()), Some("run 5"));
        assert_eq!(config.history.last().map(|run| run.at.as_str()), Some("run 24"));
    }

    #[test]
    fn the_previous_run_is_the_one_before_the_last() {
        let mut config = Config::default();
        assert!(config.previous().is_none());
        config.remember(summary("first", 1, 0, 0));
        assert!(config.previous().is_none(), "one run has nothing to compare");
        config.remember(summary("second", 2, 1, 0));
        assert_eq!(config.previous().map(|run| run.at.as_str()), Some("first"));
        assert_eq!(config.last().map(|run| run.at.as_str()), Some("second"));
    }

    #[test]
    fn the_remembered_verdicts_are_the_ones_of_the_last_full_run() {
        let mut config = Config::default();
        assert_eq!(config.prev_of("github.com"), None, "no run yet");
        config.remember_verdicts(vec![
            PrevVerdict {
                domain: "github.com".to_string(),
                verdict: "dpi_sni".to_string(),
            },
            PrevVerdict {
                domain: "youtube.com".to_string(),
                verdict: "ok".to_string(),
            },
        ]);
        assert_eq!(config.prev_of("github.com"), Some("dpi_sni"));
        assert_eq!(config.prev_of("youtube.com"), Some("ok"));
        assert_eq!(config.prev_of("example.org"), None, "a target the run did not cover");
        // A second full run replaces the memory instead of growing it.
        config.remember_verdicts(vec![PrevVerdict {
            domain: "github.com".to_string(),
            verdict: "ok".to_string(),
        }]);
        assert_eq!(config.prev_of("github.com"), Some("ok"));
        assert_eq!(config.prev_of("youtube.com"), None);
    }

    #[test]
    fn the_config_directory_follows_the_platform() {
        let dir = config_dir().expect("this machine has a home directory");
        assert!(dir.ends_with("oko"), "{}", dir.display());
        if cfg!(target_os = "linux") {
            assert!(
                dir.to_string_lossy().contains(".config") || std::env::var_os("XDG_CONFIG_HOME").is_some(),
                "{}",
                dir.display()
            );
        }
    }
}
