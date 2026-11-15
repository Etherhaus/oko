//!
//! The engine runs on its own thread with its own tokio runtime and sends
//! events over a channel; a timer on the UI thread drains them. Nothing the
//! probes do can block the window, and the table fills in target by target.
//!
//! Every run gets its own thread and its own id. When the watchdog ends a run
//! early, the window is free again at once; the thread that is still stuck in
//! a probe finishes on its own and its events are dropped because their id is
//! stale.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use crate::config::{self, Config, RunSummary};
use crate::i18n::{self, Lang, Strings};
use crate::probes::dns::ResolveOutcome;
use crate::probes::http::HttpOutcome;
use crate::probes::payload::PayloadOutcome;
use crate::probes::quic::QuicOutcome;
use crate::probes::tls::TlsOutcome;
use crate::report::{self, RunReport, TargetReport};
use crate::run::{self, Options, Progress};
use crate::target::{self, Category, Target};
use crate::update;
use crate::verdict::{DiffKind, Level};

slint::include_modules!();

/// How often the UI thread drains the engine's channel.
const TICK: Duration = Duration::from_millis(50);

/// How long a toast stays on screen.
const TOAST: Duration = Duration::from_secs(3);

/// One target in the table, with everything the inspector needs.
struct Row {
    target: Target,
    checked: bool,
    running: bool,
    report: Option<TargetReport>,
    tunnel: Option<TargetReport>,
    /// When the run reached this target, so the table can say how long its
    /// probes took.
    started: Option<Instant>,
    /// How long they took, in milliseconds.
    ms: Option<u64>,
    /// The verdict the table showed at the end of the last full run, taken
    /// when a run starts: the triangle keeps pointing at the run before this
    /// one while this one is still going.
    prev: Option<String>,
}

impl Row {
    fn new(target: Target, checked: bool) -> Row {
        Row {
            target,
            checked,
            running: false,
            report: None,
            tunnel: None,
            started: None,
            ms: None,
            prev: None,
        }
    }

    /// The verdict the table shows for this row, or an empty kind before the
    /// first run.
    fn kind(&self) -> &'static str {
        self.report.as_ref().map(display).map(|(kind, _)| kind).unwrap_or("")
    }

    /// The row as the list and the table show it.
    fn view(&self, index: usize, strings: &Strings, pending: bool) -> TargetRow {
        let shown = self.report.as_ref().map(display);
        let kind = shown.map(|(kind, _)| kind).unwrap_or("");
        let delta = self.delta();
        let mut tip = tip(kind, strings).to_string();
        if delta != 0 {
            if let Some(prev) = &self.prev {
                tip = format!("{tip} · {}: {}", strings.last_run, badge(prev, strings));
            }
        }
        TargetRow {
            index: index as i32,
            group: 0,
            header: false,
            domain: self.target.domain.clone().into(),
            checked: self.checked,
            verdict: badge(kind, strings).into(),
            level: shown.map(|(_, level)| level_code(level)).unwrap_or(4),
            why: why(kind, strings).into(),
            ms: self.ms.map(millis).unwrap_or_default().into(),
            category: strings.category(self.target.category).into(),
            pending,
            custom: self.target.custom,
            // Header-only fields: a target row leaves them empty.
            count: "".into(),
            collapsed: false,
            tip: tip.into(),
            hollow: hollow(kind),
            delta,
            prev: self.prev.clone().unwrap_or_default().into(),
        }
    }

    /// How the target moved since the run before this one: 0 no change or no
    /// history, 1 better, 2 worse.
    fn delta(&self) -> i32 {
        let Some(prev) = &self.prev else {
            return 0;
        };
        let kind = self.kind();
        if kind.is_empty() {
            return 0;
        }
        match rank(kind).cmp(&rank(prev)) {
            std::cmp::Ordering::Less => 1,
            std::cmp::Ordering::Greater => 2,
            std::cmp::Ordering::Equal => 0,
        }
    }
}

/// The ladder of the verdicts, best first: a definite answer beats an
/// uncertain one, and the service's own refusal beats the provider's cut.
fn rank(kind: &str) -> i32 {
    match kind {
        "ok" | "both_ok" => 0,
        "unknown" => 1,
        "geo_block_by_service" | "service_block" => 2,
        "" => 4,
        _ => 3,
    }
}

/// The service's own refusal: the badge draws a hollow dot, because the wall
/// is on the way, not at the far end.
fn hollow(kind: &str) -> bool {
    matches!(kind, "geo_block_by_service" | "service_block")
}

/// What a verdict word means, in one sentence, for the badge's tooltip.
fn tip(kind: &str, strings: &Strings) -> &'static str {
    match kind {
        "ok" | "both_ok" => strings.tip_ok,
        "geo_block_by_service" | "service_block" => strings.tip_svc,
        "unknown" => strings.tip_unknown,
        "" => "",
        _ => strings.tip_path,
    }
}

/// The table's filter: one bucket of the verdicts, or all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Filter {
    #[default]
    All,
    Blocked,
    Ok,
    Unknown,
}

impl Filter {
    /// The code the window's chips, stats and wall speak.
    fn code(self) -> i32 {
        match self {
            Filter::All => 0,
            Filter::Blocked => 1,
            Filter::Ok => 2,
            Filter::Unknown => 3,
        }
    }

    fn from_code(code: i32) -> Filter {
        match code {
            1 => Filter::Blocked,
            2 => Filter::Ok,
            3 => Filter::Unknown,
            _ => Filter::All,
        }
    }

    /// The bucket a verdict kind falls into. A target that has not been probed
    /// is in none of them: it shows under "all" only.
    fn of(kind: &str) -> Option<Filter> {
        match kind {
            "" => None,
            "ok" | "both_ok" => Some(Filter::Ok),
            "unknown" => Some(Filter::Unknown),
            _ => Some(Filter::Blocked),
        }
    }

    fn keeps(self, kind: &str) -> bool {
        match self {
            Filter::All => true,
            filter => Filter::of(kind) == Some(filter),
        }
    }
}

/// The badge word of a verdict: the four words the window uses, whatever the
/// engine called the finding.
fn badge(kind: &str, strings: &Strings) -> &'static str {
    match kind {
        "ok" | "both_ok" => strings.badge_ok,
        "geo_block_by_service" | "service_block" => strings.badge_service,
        "unknown" => strings.badge_unknown,
        "" => strings.badge_none,
        _ => strings.badge_provider,
    }
}

/// The short reason of a verdict, for the table's second column.
fn why(kind: &str, strings: &Strings) -> &'static str {
    match kind {
        "ok" => strings.why_ok,
        "dns_spoof" => strings.why_dns_spoof,
        "dpi_sni" => strings.why_dpi_sni,
        "ip_block" => strings.why_ip_block,
        "host_filter" => strings.why_host_filter,
        "l4_drop" => strings.why_l4_drop,
        "geo_block_by_service" => strings.why_geo_block,
        "path_block" => strings.why_path_block,
        "both_ok" => strings.why_both_ok,
        "service_block" => strings.why_service_block,
        "unknown" => strings.why_unknown,
        _ => strings.why_not_probed,
    }
}

/// A duration as the table shows it: seconds with one decimal above a second.
fn millis(ms: u64) -> String {
    if ms >= 1000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{ms} ms")
    }
}

/// One card of the inspector.
fn step(name: &str, result: &str, note: &str, tone: i32) -> Step {
    Step {
        name: name.into(),
        result: result.into(),
        note: note.into(),
        tone,
    }
}

/// The inspector's cards: one per probe, in the order the run makes them.
///
/// The tone is the reading, not the verdict: a silent QUIC probe is "not
/// applicable", because UDP silence is a legitimate NAT as often as a filter.
fn steps_for(row: &Row, strings: &Strings) -> Vec<Step> {
    let Some(report) = &row.report else {
        // A target that has not been probed still shows the shape of the run:
        // seven steps, each saying what it will look at.
        return [
            (strings.step_dns, strings.note_pending_dns),
            (strings.step_tcp, strings.note_pending_tcp),
            (strings.step_tls, strings.note_pending_tls),
            (strings.step_http, strings.note_pending_http),
            (strings.step_payload, strings.note_pending_payload),
            (strings.step_quic, strings.note_pending_quic),
            (strings.step_tunnel, strings.note_pending_tunnel),
        ]
        .into_iter()
        .map(|(name, note)| step(name, strings.res_na, note, 4))
        .collect();
    };
    let mut steps = Vec::new();

    // DNS: the system resolver against the DoH references.
    let system_ok = matches!(report.dns.system, ResolveOutcome::Resolved { .. });
    let doh_ok = report
        .dns
        .doh
        .iter()
        .any(|answer| matches!(answer.outcome, ResolveOutcome::Resolved { .. }));
    let (tone, result, note) = match (system_ok, doh_ok) {
        (true, true) => (0, strings.res_ok, strings.note_dns_ok),
        (false, true) => (1, strings.res_fail, strings.note_dns_spoof),
        _ => (3, strings.res_na, strings.note_dns_ref),
    };
    steps.push(step(strings.step_dns, result, note, tone));

    // TCP: one connect is enough to say the address answers.
    let connected = report.tcp.iter().filter(|probe| probe.outcome.is_connected()).count();
    let (tone, result, note) = if connected > 0 {
        (0, strings.res_ok, strings.note_tcp_ok)
    } else if report.tcp.is_empty() {
        (3, strings.res_na, strings.note_tcp_fail)
    } else {
        (1, strings.res_fail, strings.note_tcp_fail)
    };
    steps.push(step(strings.step_tcp, result, note, tone));

    // TLS: the server's answer, not the certificate.
    let (tone, result, note) = match report.tls.as_ref().map(|tls| &tls.real.outcome) {
        Some(TlsOutcome::Ok { .. }) => (0, strings.res_ok, strings.note_tls_ok),
        Some(TlsOutcome::ServerResponded {
            cert_mismatch: true, ..
        }) => (2, strings.res_answered, strings.note_tls_mismatch),
        Some(TlsOutcome::ServerResponded { .. }) => (2, strings.res_answered, strings.note_tls_ok),
        Some(TlsOutcome::RstAfterClientHello { .. }) => (1, strings.res_reset, strings.note_tls_rst),
        Some(TlsOutcome::Timeout { .. }) => (1, strings.res_timeout, strings.note_tls_rst),
        Some(TlsOutcome::TlsAlert { .. }) => (2, strings.res_answered, strings.note_tls_alert),
        Some(TlsOutcome::Failed { .. }) | None => (3, strings.res_na, strings.note_tls_alert),
    };
    steps.push(step(strings.step_tls, result, note, tone));

    // HTTP: a status line means the Host header got through.
    let (tone, result, note) = match report.http.as_ref().map(|http| &http.real.outcome) {
        Some(HttpOutcome::Response { status, .. }) if *status < 300 => (0, strings.res_ok, strings.note_http_ok),
        Some(HttpOutcome::Response { status, .. }) if *status < 400 => (0, strings.res_redirect, strings.note_http_ok),
        Some(HttpOutcome::Response { .. }) => (2, strings.res_fail, strings.note_http_status),
        Some(HttpOutcome::Reset { .. }) => (1, strings.res_reset, strings.note_http_reset),
        Some(HttpOutcome::Timeout { .. }) => (1, strings.res_timeout, strings.note_http_reset),
        Some(HttpOutcome::Failed { .. }) | None => (3, strings.res_na, strings.note_http_reset),
    };
    steps.push(step(strings.step_http, result, note, tone));

    // The payload: how much of the body the path carried.
    let (tone, result, note) = match report.payload.as_ref().map(|payload| &payload.outcome) {
        Some(PayloadOutcome::Complete { .. }) | Some(PayloadOutcome::Ended { .. }) => {
            (0, strings.res_full, strings.note_payload_full)
        }
        Some(PayloadOutcome::KbDrop { .. }) => (1, strings.res_drop, strings.note_payload_drop),
        Some(PayloadOutcome::Truncated { .. }) | Some(PayloadOutcome::Stalled { .. }) => {
            (2, strings.res_stalled, strings.note_payload_drop)
        }
        Some(PayloadOutcome::NotAttempted { .. }) | Some(PayloadOutcome::Failed { .. }) | None => {
            (3, strings.res_na, strings.note_payload_na)
        }
    };
    steps.push(step(strings.step_payload, result, note, tone));

    // QUIC: an answer proves the UDP path; silence proves nothing.
    let (tone, result, note) = match report.quic.as_ref().map(|quic| &quic.outcome) {
        Some(QuicOutcome::Answered { .. }) => (0, strings.res_answered, strings.note_quic_answer),
        Some(QuicOutcome::Silent { .. }) => (3, strings.res_silent, strings.note_quic_silent),
        Some(QuicOutcome::Failed { .. }) | None => (3, strings.res_na, strings.note_quic_silent),
    };
    steps.push(step(strings.step_quic, result, note, tone));

    // The tunnel: what the comparison says about the path.
    let (tone, result, note) = match report.diff.as_ref().map(|diff| diff.kind) {
        Some(DiffKind::BothOk) => (0, strings.res_ok, strings.note_tunnel_ok),
        Some(DiffKind::PathBlock) => (1, strings.res_fail, strings.note_tunnel_path),
        Some(DiffKind::ServiceBlock) => (1, strings.res_fail, strings.note_tunnel_service),
        Some(DiffKind::Unknown) | None => (3, strings.res_na, strings.note_tunnel_off),
    };
    steps.push(step(strings.step_tunnel, result, note, tone));

    steps
}

/// The verdict the table shows: the tunnel comparison when one ran, the direct
/// verdict otherwise. The direct verdict stays in the details panel and in the
/// JSON either way.
fn display(report: &TargetReport) -> (&'static str, Level) {
    match &report.diff {
        Some(diff) => (diff.kind.as_str(), diff_level(diff.kind)),
        None => (report.verdict.kind.as_str(), report.verdict.level),
    }
}

/// How alarming a comparison is.
fn diff_level(kind: DiffKind) -> Level {
    match kind {
        DiffKind::BothOk => Level::Ok,
        DiffKind::PathBlock | DiffKind::ServiceBlock => Level::Bad,
        DiffKind::Unknown => Level::Undetermined,
    }
}

/// The table's level code: 0 ok, 1 warn, 2 bad, 3 undetermined, 4 not probed.
fn level_code(level: Level) -> i32 {
    match level {
        Level::Ok => 0,
        Level::Warn => 1,
        Level::Bad => 2,
        Level::Undetermined => 3,
    }
}

/// What the run header says. Everything that is not about the run itself — a
/// bad domain, a written export — goes to the toast instead.
enum Status {
    Ready,
    Checking { done: usize, total: usize },
    Done,
    Stopped,
    ControlDead,
    Interrupted(String),
    Failed(String),
}

impl Status {
    /// The state, in one short line.
    fn state(&self, app: &App, strings: &Strings) -> String {
        match self {
            Status::Ready => strings.ready.to_string(),
            // The counter lives here; the button says what it does.
            Status::Checking { done, total } => {
                format!("{} {done}/{total}…", strings.checking.trim_end_matches('…'))
            }
            // The run's own count, in the words of the chips.
            Status::Done => match app.config.last() {
                Some(last) => format!(
                    "{}: {} {} · {} {} · {} {}",
                    strings.done,
                    strings.filter_blocked,
                    last.blocked,
                    strings.filter_ok,
                    last.ok,
                    strings.filter_unknown,
                    last.unknown
                ),
                None => strings.done.to_string(),
            },
            Status::Stopped => strings.stopped.to_string(),
            Status::ControlDead => strings.control_dead_short.to_string(),
            Status::Interrupted(_) => strings.interrupted.to_string(),
            Status::Failed(_) => strings.run_failed.to_string(),
        }
    }

    /// The line under the state: when the run happened, how long it took, and
    /// what it covered. A failure says what failed instead.
    fn detail(&self, app: &App, strings: &Strings) -> String {
        match self {
            Status::ControlDead => strings.control_dead.to_string(),
            Status::Interrupted(target) => target.clone(),
            Status::Failed(reason) => reason.clone(),
            _ => match app.config.last() {
                Some(last) => run_line(&last.at, last.seconds, last.ok + last.blocked + last.unknown, strings),
                None => String::new(),
            },
        }
    }
}

/// The line under the state: when the run happened, how long it took, and
/// what it covered. The mockup writes the count in the small word — the
/// panel's «Цели» capital would read as a leak.
fn run_line(at: &str, seconds: u64, count: usize, strings: &Strings) -> String {
    format!(
        "{} · {} · {count} {}",
        stamp(at),
        human_seconds(seconds, strings),
        strings.run_count
    )
}

/// A duration in words: seconds under a minute, minutes and seconds above.
fn human_seconds(seconds: u64, strings: &Strings) -> String {
    if seconds < 60 {
        format!("{seconds} {}", strings.seconds)
    } else {
        format!(
            "{} {} {} {}",
            seconds / 60,
            strings.minutes,
            seconds % 60,
            strings.seconds
        )
    }
}

/// What the UI thread owns.
struct App {
    rows: Vec<Row>,
    selected: Option<usize>,
    lang: Lang,
    dark: bool,
    frame: bool,
    timeout: u64,
    socks5: String,
    adding: bool,
    add_text: String,
    /// One flag per group of `Category::GROUPS`: a collapsed group shows its
    /// header and hides its targets.
    collapsed: Vec<bool>,
    /// The settings popover is an overlay, not a screen.
    settings_open: bool,
    /// The table's filter and the search over the list. The window's own
    /// state: neither is written to the file.
    filter: Filter,
    search: String,
    /// The stop button was pressed: the run ends after the target it is on,
    /// and the history and the remembered verdicts stay as they were.
    stopping: bool,
    /// The token the running thread reads.
    cancel: run::Cancel,
    /// The table's order: the worst verdicts first, so the walls are on top.
    /// It is fixed while a run goes on and sorted when one ends.
    order: Vec<usize>,
    /// A short message at the bottom of the window, and when it goes away.
    toast: Option<(String, Instant)>,
    running: bool,
    /// The id of the run the window is waiting for. Events of any other run
    /// are stale and dropped.
    run_id: u64,
    /// The row indices of the targets in the current run, in the order the run
    /// probes them. The engine numbers the targets it was given, and those are
    /// only the ticked ones, so its index is not the row's.
    running_rows: Vec<usize>,
    started: Option<Instant>,
    report: Option<RunReport>,
    status: Status,
    progress: f32,
    control_dead: bool,
    /// The updater's state, and the release it is working on.
    update: Update,
    update_release: Option<update::Release>,
    /// The check was asked for by the button rather than by the start: only
    /// then does its answer become a toast.
    update_manual: bool,
    /// The binary lives where a package manager owns it: it can be downloaded
    /// and checked, but not replaced.
    update_managed: bool,
    config: Config,
    events: mpsc::Sender<Event>,
}

impl App {
    fn new(config: Config, events: mpsc::Sender<Event>) -> App {
        let mut rows: Vec<Row> = target::services()
            .into_iter()
            .map(|target| {
                let checked = config
                    .checked
                    .as_ref()
                    .map(|list| list.iter().any(|domain| domain == &target.domain))
                    .unwrap_or(true);
                Row::new(target, checked)
            })
            .collect();
        for domain in &config.custom {
            let checked = config
                .checked
                .as_ref()
                .map(|list| list.iter().any(|saved| saved == domain))
                .unwrap_or(true);
            rows.push(Row::new(target::ad_hoc(domain), checked));
        }
        let lang = match config.lang.as_str() {
            "ru" => Lang::Ru,
            _ => Lang::En,
        };
        let order = (0..rows.len()).collect();
        App {
            rows,
            selected: None,
            lang,
            dark: config.dark,
            frame: config.frame,
            timeout: config.timeout,
            socks5: config.socks5.clone(),
            adding: false,
            add_text: String::new(),
            collapsed: vec![false; Category::GROUPS.len()],
            settings_open: false,
            filter: Filter::All,
            search: String::new(),
            stopping: false,
            cancel: run::Cancel::never(),
            order,
            toast: None,
            running: false,
            run_id: 0,
            running_rows: Vec::new(),
            started: None,
            report: None,
            status: Status::Ready,
            progress: 0.0,
            control_dead: false,
            update: Update::Idle,
            update_release: None,
            update_manual: false,
            update_managed: false,
            config,
            events,
        }
    }

    fn strings(&self) -> Strings {
        Strings::new(self.lang)
    }

    fn done(&self) -> usize {
        self.rows.iter().filter(|row| row.report.is_some()).count()
    }

    /// Copy the window's state into the config and write it.
    fn persist(&mut self) {
        self.config.timeout = self.timeout;
        self.config.socks5 = self.socks5.clone();
        self.config.dark = self.dark;
        self.config.lang = self.lang.code().to_string();
        self.config.frame = self.frame;
        self.config.checked = Some(
            self.rows
                .iter()
                .filter(|row| row.checked)
                .map(|row| row.target.domain.clone())
                .collect(),
        );
        self.config.custom = self
            .rows
            .iter()
            .filter(|row| row.target.custom)
            .map(|row| row.target.domain.clone())
            .collect();
        let _ = self.config.save();
    }

    /// Remember what this run said about each target, for the next run's
    /// delta. Only a full run calls this: a stopped one leaves the memory of
    /// the last complete run alone.
    fn remember_prev(&mut self) {
        let verdicts = self
            .rows
            .iter()
            .filter_map(|row| {
                let kind = row.kind();
                if kind.is_empty() {
                    return None;
                }
                Some(config::PrevVerdict {
                    domain: row.target.domain.clone(),
                    verdict: kind.to_string(),
                })
            })
            .collect();
        self.config.remember_verdicts(verdicts);
    }
}

/// What the updater is doing, as the settings section shows it.
///
/// The section is one line of status and one button, so the states are the
/// button's own story: check, download, restart.
#[derive(Debug, Clone, PartialEq)]
enum Update {
    /// Nothing asked yet in this session.
    Idle,
    /// A check is in flight.
    Checking,
    /// The newest release is not newer than this binary.
    UpToDate,
    /// A newer release is on GitHub.
    Available(String),
    /// The archive is coming down.
    Downloading(f32),
    /// Downloaded, verified, and in place: a restart picks it up. The path is
    /// the one the install replaced, which is what the restart has to exec.
    Ready { version: String, exe: PathBuf },
    /// Something went wrong, in the updater's own words.
    Failed(String),
}

/// What the updater thread tells the UI.
enum UpdateEvent {
    /// The check came back: the release, nothing new, or why it failed.
    Checked(Result<Option<update::Release>, update::Error>),
    /// The download is this far along.
    Progress(f32),
    /// The install ended: the path it replaced, or why it did not.
    Installed(Result<PathBuf, update::Error>),
}

/// What the UI asks a run to do, and what the run tells the UI.
enum Event {
    Progress(u64, Box<Progress>),
    Finished(u64, Box<RunReport>),
    Failed(u64, String),
    Update(UpdateEvent),
}

/// Start one run on its own thread: its own tokio runtime, its own id.
fn spawn_run(id: u64, targets: Vec<Target>, options: Options, cancel: run::Cancel, events: mpsc::Sender<Event>) {
    thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => {
                let _ = events.send(Event::Failed(id, format!("cannot start the async runtime: {err}")));
                return;
            }
        };
        let sender = events.clone();
        let report = runtime.block_on(run::run(targets, options, cancel, move |progress| {
            let _ = sender.send(Event::Progress(id, Box::new(progress)));
        }));
        let _ = events.send(Event::Finished(id, Box::new(report)));
    });
}

/// Ask GitHub for the newest release on its own thread: the window never
/// waits for the network.
fn spawn_check(events: mpsc::Sender<Event>) {
    thread::spawn(move || {
        let result = update::check().map(|check| match check {
            update::Check::UpToDate => None,
            update::Check::Available(release) => Some(release),
        });
        let _ = events.send(Event::Update(UpdateEvent::Checked(result)));
    });
}

/// Download the release, check its signature, and put it in place on its own
/// thread. The progress comes back as it goes.
fn spawn_install(release: update::Release, events: mpsc::Sender<Event>) {
    thread::spawn(move || {
        let sender = events.clone();
        let result = update::install(&release, &move |fraction| {
            let _ = sender.send(Event::Update(UpdateEvent::Progress(fraction)));
        });
        let _ = events.send(Event::Update(UpdateEvent::Installed(result)));
    });
}

/// Seconds since the Unix epoch: the updater's clock.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// The desktop's "prefers reduced motion".
///
/// Slint 1.18 has no API for the setting, so the window reads it from the
/// environment: `OKO_REDUCED_MOTION` for the screenshots, and the GTK switch
/// the desktops actually flip. A desktop that says nothing keeps the motion.
fn reduced_motion() -> bool {
    if std::env::var_os("OKO_REDUCED_MOTION").is_some() {
        return true;
    }
    std::env::var("GTK_ENABLE_ANIMATIONS").is_ok_and(|value| value == "0")
}

/// Open the window and run it until it closes.
pub fn run() -> ExitCode {
    let ui = match AppWindow::new() {
        Ok(ui) => ui,
        Err(err) => {
            eprintln!("oko: cannot open the window: {err}");
            return ExitCode::FAILURE;
        }
    };
    let _ = slint::set_xdg_app_id("io.github.etherhaus.Oko");

    let (events, incoming) = mpsc::channel::<Event>();
    // The first launch follows the desktop's language; after that the file
    // decides.
    let config = Config::load().unwrap_or_else(|| Config {
        lang: Lang::from_env().code().to_string(),
        ..Config::default()
    });
    let app = Rc::new(RefCell::new(App::new(config, events)));

    {
        let state = app.borrow_mut();
        i18n::apply(&ui, state.lang);
        ui.set_lang(state.lang.code().into());
        ui.global::<Theme>().set_dark(state.dark);
        ui.global::<Theme>().set_reduced_motion(reduced_motion());
        ui.set_timeout_value(state.timeout as i32);
        ui.set_frame(state.frame);
        ui.set_socks5_text(state.socks5.clone().into());
        refresh(&ui, &state);
    }

    wire(&ui, &app);

    // The updater: where this binary lives decides whether it may replace
    // itself, and the file decides whether it is time to ask GitHub again.
    {
        let mut state = app.borrow_mut();
        state.update_managed = std::env::current_exe()
            .map(|exe| update::managed(&exe))
            .unwrap_or(false);
        if state.config.check_due(now_seconds()) {
            state.update = Update::Checking;
            spawn_check(state.events.clone());
        }
        refresh(&ui, &state);
    }

    // Development aids: the window can be driven without a mouse, which is the
    // only way to check it where no input-injection tool exists. Each one calls
    // the callback the button calls, so the path is the same.
    if std::env::var("OKO_THEME").as_deref() == Ok("light") {
        ui.invoke_pick_light();
    }
    if std::env::var("OKO_LANG").as_deref() == Ok("en") {
        ui.invoke_pick_en();
    }
    if let Ok(index) = std::env::var("OKO_SELECT").unwrap_or_default().parse::<i32>() {
        ui.invoke_select(index);
    }
    if let Ok(proxy) = std::env::var("OKO_SOCKS5") {
        app.borrow_mut().socks5 = proxy.clone();
        ui.set_socks5_text(proxy.into());
    }
    if std::env::var("OKO_FRAME").as_deref() == Ok("off") {
        ui.invoke_toggle_frame();
    }
    if let Ok(domain) = std::env::var("OKO_ADD") {
        let mut state = app.borrow_mut();
        state.add_text = domain;
        add_domain(&ui, &mut state);
    }
    if std::env::var("OKO_ADDING").is_ok() {
        ui.invoke_begin_add();
    }
    if std::env::var("OKO_SETTINGS").is_ok() {
        ui.invoke_open_settings();
    }
    // A debug aid: press the updater's button once the window is up, so the
    // manual check and its toast can be seen without a mouse. Pressing it here
    // would spend the toast's three seconds before the first frame is drawn.
    let mut check_at = std::env::var("OKO_UPDATE_CHECK")
        .ok()
        .map(|_| Instant::now() + Duration::from_millis(1500));
    if let Ok(group) = std::env::var("OKO_COLLAPSE").unwrap_or_default().parse::<i32>() {
        ui.invoke_toggle_collapse(group);
    }
    if let Ok(code) = std::env::var("OKO_FILTER").unwrap_or_default().parse::<i32>() {
        ui.invoke_pick_filter(code);
    }
    if let Ok(text) = std::env::var("OKO_SEARCH") {
        ui.invoke_search_edited(text.into());
    }

    // The engine's events land here, on the UI thread.
    // Three more aids need a finished run: the filter, the worst row's details
    // and the copy button's toast. All are applied once, when the first run
    // ends.
    let filter_after = std::env::var("OKO_FILTER_AFTER")
        .unwrap_or_default()
        .parse::<i32>()
        .ok();
    let select_worst = std::env::var_os("OKO_SELECT_WORST").is_some();
    let copy_after = std::env::var_os("OKO_COPY").is_some();
    // A debug aid: press the copy button again and again once a run is over, so
    // the toast stays on screen long enough to be photographed. It is the same
    // button the inspector's icon presses.
    let copy_every = std::env::var("OKO_COPY_EVERY")
        .unwrap_or_default()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.max(1));
    let copy_timer = slint::Timer::default();
    if let Some(seconds) = copy_every {
        copy_timer.start(slint::TimerMode::Repeated, Duration::from_secs(seconds), {
            let ui = ui.as_weak();
            let app = app.clone();
            move || {
                let Some(window) = ui.upgrade() else { return };
                let ready = {
                    let state = app.borrow();
                    state.selected.is_some() && !state.running
                };
                if ready {
                    copy(&window, &mut app.borrow_mut());
                }
            }
        });
    }
    // `OKO_UPDATE_AUTO=1` walks the whole chain; `=install` stops before the
    // restart, so the verified state can be looked at.
    let auto_update = std::env::var("OKO_UPDATE_AUTO").unwrap_or_default();
    let auto_restart = auto_update != "install";
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, TICK, {
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            while let Ok(event) = incoming.try_recv() {
                let finished = matches!(event, Event::Finished(..));
                handle(&ui, &mut app.borrow_mut(), event);
                if finished {
                    if let Some(code) = filter_after {
                        ui.invoke_pick_filter(code);
                    }
                    if select_worst {
                        let worst = app.borrow().order.first().copied();
                        if let Some(index) = worst {
                            ui.invoke_select(index as i32);
                        }
                    }
                    if copy_after {
                        ui.invoke_copy();
                    }
                }
                if finished && std::env::var_os("OKO_EXPORT_DIR").is_some() {
                    ui.invoke_export();
                }
            }
            // A debug aid: walk the updater's whole chain without a mouse —
            // check, download, restart — so the live path can be shown.
            if !auto_update.is_empty() {
                let ready = matches!(app.borrow().update, Update::Ready { .. });
                let available = matches!(app.borrow().update, Update::Available(_));
                if available || (ready && auto_restart) {
                    ui.invoke_update_pressed();
                }
            }
            // A debug aid: press the updater's button once the window is up.
            if let Some(at) = check_at {
                if Instant::now() >= at {
                    check_at = None;
                    ui.invoke_update_pressed();
                }
            }
            // A toast goes away on its own; the timer is the only clock here.
            let expired = app
                .borrow()
                .toast
                .as_ref()
                .is_some_and(|(_, until)| Instant::now() >= *until);
            if expired {
                app.borrow_mut().toast = None;
                toast(&ui, &app.borrow());
            }
        }
    });

    // A debug aid: start the run as soon as the window opens, so the window can
    // be checked without a mouse.
    if std::env::var("OKO_AUTOSTART").is_ok() {
        start(&ui, &mut app.borrow_mut());
    }

    // A debug aid: press the stop button after N seconds, so the stopped state
    // can be checked without a mouse.
    if let Ok(seconds) = std::env::var("OKO_STOP_AFTER").unwrap_or_default().parse::<u64>() {
        let ui = ui.as_weak();
        let app = app.clone();
        slint::Timer::single_shot(Duration::from_secs(seconds), move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            stop(&mut state);
            refresh(&window, &state);
        });
    }

    let result = ui.run();
    drop(timer);
    drop(copy_timer);
    app.borrow_mut().persist();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("oko: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Update a model in place: replacing it would rebuild every row of the list,
/// and the list would lose its scroll position on each verdict of a run.
macro_rules! set_rows {
    ($ui:expr, $get:ident, $set:ident, $rows:expr) => {{
        let rows = $rows;
        let model = $ui.$get();
        match model.as_any().downcast_ref::<VecModel<TargetRow>>() {
            Some(vec) if vec.row_count() == rows.len() => {
                for (index, row) in rows.into_iter().enumerate() {
                    vec.set_row_data(index, row);
                }
            }
            _ => $ui.$set(ModelRc::new(VecModel::from(rows))),
        }
    }};
}

/// Push the whole state into the window.
fn refresh(ui: &AppWindow, app: &App) {
    let strings = app.strings();
    set_rows!(ui, get_list, set_list, list_model(app, &strings));
    set_rows!(ui, get_rows, set_rows, table_model(app, &strings));
    ui.set_selected(app.selected.map(|index| index as i32).unwrap_or(-1));
    inspector(ui, app, &strings);
    ui.set_running(app.running);
    ui.set_progress(app.progress);
    ui.set_run_state(app.status.state(app, &strings).into());
    ui.set_run_sub(app.status.detail(app, &strings).into());
    ui.set_run_label(run_label(app, &strings).into());
    ui.set_adding(app.adding);
    ui.set_add_text(app.add_text.clone().into());
    ui.set_frame(app.frame);
    ui.set_settings_open(app.settings_open);
    ui.set_export_enabled(app.report.is_some());
    ui.set_lang(app.lang.code().into());
    ui.set_timeout_value(app.timeout as i32);
    ui.set_socks5_text(app.socks5.clone().into());
    filter_bar(ui, app);
    dashboard(ui, app, &strings);
    status_bar(ui, app);
    ui.set_update_status(update_status(app, &strings).into());
    ui.set_update_action(update_action(app, &strings).into());
    ui.set_update_busy(update_busy(app));
    ui.set_update_dot(update_dot(app));
    ui.set_update_hint(update_hint(app, &strings).into());
    toast(ui, app);
}

/// The filter chips, the counter beside them, and the row the arrows are on.
fn filter_bar(ui: &AppWindow, app: &App) {
    let mut counts = [0usize; 4];
    for row in app.rows.iter().filter(|row| row.checked) {
        counts[0] += 1;
        match Filter::of(row.kind()) {
            Some(Filter::Blocked) => counts[1] += 1,
            Some(Filter::Ok) => counts[2] += 1,
            Some(Filter::Unknown) => counts[3] += 1,
            _ => {}
        }
    }
    let visible = visible_rows(app);
    ui.set_filter(app.filter.code());
    ui.set_search_text(app.search.clone().into());
    ui.set_ticked_count(counts[0] as i32);
    ui.set_chip_all(counts[0].to_string().into());
    ui.set_chip_blocked(counts[1].to_string().into());
    ui.set_chip_ok(counts[2].to_string().into());
    ui.set_chip_unknown(counts[3].to_string().into());
    ui.set_shown_count(format!("{}/{}", visible.len(), counts[0]).into());
    ui.set_selected_row(
        app.selected
            .and_then(|selected| visible.iter().position(|index| *index == selected))
            .map(|at| at as i32)
            .unwrap_or(-1),
    );
}

/// The rows the table shows, in its order: the ticked ones the filter keeps.
fn visible_rows(app: &App) -> Vec<usize> {
    app.order
        .iter()
        .copied()
        .filter(|index| {
            app.rows
                .get(*index)
                .is_some_and(|row| row.checked && app.filter.keeps(row.kind()))
        })
        .collect()
}

/// The targets panel: a header per category, then the targets of that group.
/// The search narrows the list, and a group with no match loses its header.
fn list_model(app: &App, strings: &Strings) -> Vec<TargetRow> {
    let needle = app.search.trim().to_lowercase();
    let mut out = Vec::new();
    for (group, category) in Category::GROUPS.iter().enumerate() {
        let indices: Vec<usize> = app
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.target.category == *category)
            .filter(|(_, row)| needle.is_empty() || row.target.domain.to_lowercase().contains(&needle))
            .map(|(index, _)| index)
            .collect();
        if indices.is_empty() {
            continue;
        }
        let checked = indices.iter().all(|index| app.rows[*index].checked);
        let ticked = indices.iter().filter(|index| app.rows[**index].checked).count();
        let collapsed = app.collapsed.get(group).copied().unwrap_or(false);
        out.push(TargetRow {
            index: -1,
            group: group as i32,
            header: true,
            domain: strings.category(*category).into(),
            checked,
            verdict: "".into(),
            level: 4,
            why: "".into(),
            ms: "".into(),
            category: "".into(),
            pending: false,
            custom: false,
            count: format!("{ticked}/{}", indices.len()).into(),
            collapsed,
            // Header-only fields: a group has no verdict of its own.
            tip: "".into(),
            hollow: false,
            delta: 0,
            prev: "".into(),
        });
        if collapsed {
            continue;
        }
        for index in indices {
            out.push(app.rows[index].view(index, strings, false));
        }
    }
    out
}

/// The table: the ticked targets in the order the last run left them, worst
/// first, narrowed by the filter. A target the run has not reached yet is
/// dimmed.
fn table_model(app: &App, strings: &Strings) -> Vec<TargetRow> {
    visible_rows(app)
        .into_iter()
        .filter_map(|index| app.rows.get(index).map(|row| (index, row)))
        .map(|(index, row)| row.view(index, strings, app.running && row.report.is_none()))
        .collect()
}

/// Put the worst verdicts on top: the table answers "where are the walls".
fn sort_order(app: &mut App) {
    let mut order = app.order.clone();
    order.sort_by_key(|index| {
        let rank = match app.rows.get(*index).and_then(|row| row.report.as_ref()).map(display) {
            Some((_, Level::Bad)) => 0,
            Some((_, Level::Warn)) => 1,
            Some((_, Level::Undetermined)) => 2,
            Some((_, Level::Ok)) => 3,
            None => 4,
        };
        (rank, *index)
    });
    app.order = order;
}

/// The button's label: the one button of the window turns into the stop while
/// a run goes on.
fn run_label(app: &App, strings: &Strings) -> String {
    if app.running {
        strings.stop.to_string()
    } else {
        strings.check.to_string()
    }
}

/// The dashboard: the counters of the last run, the delta to the one before,
/// and the wall they add up to.
fn dashboard(ui: &AppWindow, app: &App, strings: &Strings) {
    let Some(last) = app.config.last() else {
        ui.set_dash_ok("0".into());
        ui.set_dash_blocked("0".into());
        ui.set_dash_unknown("0".into());
        ui.set_dash_ok_delta("".into());
        ui.set_dash_blocked_delta("".into());
        ui.set_dash_unknown_delta("".into());
        ui.set_dash_ok_count(0);
        ui.set_dash_blocked_count(0);
        ui.set_dash_unknown_count(0);
        return;
    };
    ui.set_dash_ok(last.ok.to_string().into());
    ui.set_dash_blocked(last.blocked.to_string().into());
    ui.set_dash_unknown(last.unknown.to_string().into());
    ui.set_dash_ok_count(last.ok as i32);
    ui.set_dash_blocked_count(last.blocked as i32);
    ui.set_dash_unknown_count(last.unknown as i32);
    match app.config.previous() {
        Some(previous) => {
            ui.set_dash_ok_delta(signed(last.ok, previous.ok).into());
            ui.set_dash_blocked_delta(signed(last.blocked, previous.blocked).into());
            ui.set_dash_unknown_delta(signed(last.unknown, previous.unknown).into());
        }
        None => {
            ui.set_dash_ok_delta("".into());
            ui.set_dash_blocked_delta("".into());
            ui.set_dash_unknown_delta("".into());
        }
    }
    let _ = strings;
}

/// The status bar: what the run was given, in the words of a boot log. The
/// keys ("tunnel", "timeout", …) are drawn by the window in the accent color;
/// here go the values, plus whether the tunnel is known to work.
fn status_bar(ui: &AppWindow, app: &App) {
    let proxy = app.socks5.trim();
    let tunnel_ok = app.report.as_ref().and_then(|report| report.tunnel.as_ref()).is_some();
    ui.set_sb_tunnel(if proxy.is_empty() {
        "—".into()
    } else if tunnel_ok {
        format!("{proxy} ok").into()
    } else {
        proxy.into()
    });
    ui.set_sb_tunnel_ok(!proxy.is_empty() && tunnel_ok);
    ui.set_sb_timeout(format!("{}s", app.timeout).into());
    ui.set_sb_probes(format!("{}/target", run::PROBES_PER_TARGET).into());
    ui.set_sb_run(
        match app.config.last() {
            Some(last) => format!("{}s", last.seconds),
            None => "—".to_string(),
        }
        .into(),
    );
    ui.set_sb_version(format!("oko {} · etherhaus", env!("CARGO_PKG_VERSION")).into());
}

/// The inspector of the chosen row: its probes, and the facts behind them.
fn inspector(ui: &AppWindow, app: &App, strings: &Strings) {
    let Some(row) = app.selected.and_then(|index| app.rows.get(index)) else {
        ui.set_steps(ModelRc::new(VecModel::from(Vec::<Step>::new())));
        ui.set_facts(ModelRc::new(VecModel::from(Vec::<SharedString>::new())));
        ui.set_detail_title("".into());
        ui.set_detail_badge("".into());
        ui.set_detail_level(4);
        return;
    };
    let steps = steps_for(row, strings);
    let facts: Vec<SharedString> = row
        .report
        .as_ref()
        .map(|report| report.verdict.facts.iter().map(|fact| fact.as_str().into()).collect())
        .unwrap_or_default();
    let shown = row.report.as_ref().map(display);
    let kind = shown.map(|(kind, _)| kind).unwrap_or("");
    ui.set_steps(ModelRc::new(VecModel::from(steps)));
    ui.set_facts(ModelRc::new(VecModel::from(facts)));
    // The mockup names the target the way the table does, without the port.
    ui.set_detail_title(row.target.domain.clone().into());
    // An unprobed target has no verdict word yet: only the plain fact.
    ui.set_detail_badge(if kind.is_empty() {
        why(kind, strings).into()
    } else {
        format!("{} — {}", badge(kind, strings), why(kind, strings)).into()
    });
    ui.set_detail_level(shown.map(|(_, level)| level_code(level)).unwrap_or(4));
}

/// The toast: a short message that goes away on its own.
fn toast(ui: &AppWindow, app: &App) {
    match &app.toast {
        Some((text, _)) => {
            ui.set_toast_text(text.clone().into());
            ui.set_toast_visible(true);
        }
        None => ui.set_toast_visible(false),
    }
}

/// `2026-11-14T17:24:45Z` as `2026-11-14 17:24`.
fn stamp(at: &str) -> String {
    at.trim_end_matches('Z').replace('T', " ").chars().take(16).collect()
}

/// The change of one counter, as the dashboard shows it. A zero is written
/// out: "nothing changed" is an answer, and an empty cell would read as "no
/// previous run".
fn signed(now: usize, before: usize) -> String {
    let delta = now as i64 - before as i64;
    match delta {
        0 => "·".to_string(),
        delta if delta > 0 => format!("+{delta}"),
        delta => format!("{delta}"),
    }
}

/// Apply one engine event. Events of a run the window is no longer waiting for
/// are dropped: the watchdog already reported that run.
fn handle(ui: &AppWindow, app: &mut App, event: Event) {
    match event {
        Event::Progress(id, progress) if id == app.run_id => apply_progress(app, *progress),
        Event::Finished(id, report) if id == app.run_id => finish(app, *report),
        Event::Failed(id, reason) if id == app.run_id => {
            app.running = false;
            app.status = Status::Failed(reason);
        }
        Event::Update(event) => {
            handle_update(ui, app, event);
            return;
        }
        _ => return,
    }
    refresh(ui, app);
}

/// The updater's events, on the UI thread.
///
/// A check the button asked for answers with a toast; the one the start asked
/// for stays quiet, because a machine that is offline should not be told about
/// it on every launch.
fn handle_update(ui: &AppWindow, app: &mut App, event: UpdateEvent) {
    let strings = app.strings();
    match event {
        UpdateEvent::Checked(result) => {
            let manual = std::mem::take(&mut app.update_manual);
            let now = now_seconds();
            let message = match result {
                Ok(Some(release)) => {
                    app.config.remember_check(now, "available", &release.version);
                    let message = format!("oko {} — {}", release.version, strings.update_on_github);
                    app.update = Update::Available(release.version.clone());
                    app.update_release = Some(release);
                    message
                }
                Ok(None) => {
                    app.config.remember_check(now, "up-to-date", "");
                    app.update = Update::UpToDate;
                    app.update_release = None;
                    strings.update_none.to_string()
                }
                Err(err) => {
                    app.config.remember_check(now, "failed", "");
                    let why = update_error(&err, &strings);
                    app.update = Update::Failed(why.clone());
                    format!("{}: {why}", strings.update_failed)
                }
            };
            app.persist();
            if manual {
                app.toast = Some((message, Instant::now() + TOAST));
            }
        }
        UpdateEvent::Progress(fraction) => {
            app.update = Update::Downloading(fraction);
        }
        UpdateEvent::Installed(result) => {
            let message = match result {
                Ok(exe) => {
                    let version = app
                        .update_release
                        .as_ref()
                        .map(|release| release.version.clone())
                        .unwrap_or_default();
                    app.update = Update::Ready { version, exe };
                    strings.update_ready.to_string()
                }
                Err(err) => {
                    let why = update_error(&err, &strings);
                    app.update = Update::Failed(why.clone());
                    format!("{}: {why}", strings.update_failed)
                }
            };
            app.toast = Some((message, Instant::now() + TOAST));
        }
    }
    refresh(ui, app);
}

/// Why the updater stopped, in the window's language.
///
/// The technical detail is kept where it names something the user can act on —
/// a host, a file, an OS error — and dropped where it would only repeat the
/// sentence: a signature that does not match needs no explanation.
fn update_error(err: &update::Error, strings: &Strings) -> String {
    match err {
        update::Error::Signature(_) => strings.update_failed_signature.to_string(),
        update::Error::TooLarge => strings.update_failed_large.to_string(),
        update::Error::TimedOut => strings.update_failed_timeout.to_string(),
        update::Error::NoAsset(name) => format!("{} {name}", strings.update_failed_asset),
        update::Error::Managed(_) => strings.update_managed.to_string(),
        update::Error::Network(detail) => format!("{}: {detail}", strings.update_failed_network),
        update::Error::Archive(detail) => format!("{}: {detail}", strings.update_failed_archive),
        update::Error::Install(detail) => format!("{}: {detail}", strings.update_failed_install),
    }
}

/// The updater's status line: what it is doing, in one sentence.
fn update_status(app: &App, strings: &Strings) -> String {
    match &app.update {
        Update::Idle => strings.update_idle.to_string(),
        Update::Checking => strings.update_checking.to_string(),
        Update::UpToDate => format!("{} — {}", strings.update_current, update::CURRENT),
        Update::Available(version) => format!("{} {version}", strings.update_available),
        // The percentage belongs to the button; the line keeps the fact.
        Update::Downloading(_) => match &app.update_release {
            Some(release) => format!("{} {}", strings.update_available, release.version),
            None => strings.update_checking.to_string(),
        },
        Update::Ready { version, .. } => format!("{} — {version}", strings.update_verified),
        Update::Failed(why) => format!("{}: {why}", strings.update_failed),
    }
}

/// The updater's button: check, download, restart.
fn update_action(app: &App, strings: &Strings) -> String {
    match &app.update {
        Update::Checking => strings.update_checking.to_string(),
        Update::Downloading(fraction) => {
            format!("{} {}%", strings.update_downloading, (fraction * 100.0).round() as i32)
        }
        Update::Ready { .. } => strings.update_restart.to_string(),
        Update::Available(version) => format!("{} {version}", strings.update_download),
        Update::Failed(_) => match &app.update_release {
            Some(release) => format!("{} {}", strings.update_download, release.version),
            None => strings.update_check.to_string(),
        },
        Update::Idle | Update::UpToDate => strings.update_check.to_string(),
    }
}

/// Whether the updater is busy: the button is a progress line then.
fn update_busy(app: &App) -> bool {
    matches!(app.update, Update::Checking | Update::Downloading(_))
}

/// The dot on the settings button: a release newer than this binary is
/// remembered, so the dot survives a restart and goes away once the new
/// version is the one running.
fn update_dot(app: &App) -> bool {
    update::is_newer(&app.config.last_version, update::CURRENT)
}

/// The line under the status: what the updater promises, or why it will not
/// replace this binary itself.
fn update_hint(app: &App, strings: &Strings) -> String {
    if app.update_managed {
        strings.update_managed.to_string()
    } else {
        strings.update_signature_hint.to_string()
    }
}

/// The row a run index stands for.
fn row_for(app: &mut App, index: usize) -> Option<&mut Row> {
    let row = *app.running_rows.get(index)?;
    app.rows.get_mut(row)
}

/// Apply one progress step to the state.
fn apply_progress(app: &mut App, progress: Progress) {
    match progress {
        Progress::Control(control) => {
            app.control_dead = !control.tcp.iter().any(|probe| probe.outcome.is_connected());
        }
        Progress::Started { index } => {
            if let Some(row) = row_for(app, index) {
                row.running = true;
                row.started = Some(Instant::now());
            }
        }
        Progress::Target { index, report } => {
            if let Some(row) = row_for(app, index) {
                row.running = false;
                row.ms = row.started.map(|started| started.elapsed().as_millis() as u64);
                row.report = Some(report);
            }
            let total = app.running_rows.len();
            app.status = Status::Checking {
                done: app.done(),
                total,
            };
            app.progress = app.done() as f32 / total.max(1) as f32;
        }
        Progress::Tunnel { index, report } => {
            if let Some(row) = row_for(app, index) {
                row.tunnel = Some(report);
            }
        }
        Progress::Diff { index, diff, verdict } => {
            if let Some(row) = row_for(app, index) {
                if let Some(report) = &mut row.report {
                    report.verdict = verdict;
                    report.diff = Some(diff);
                }
                // The tunnel run is part of the target's time.
                row.ms = row.started.map(|started| started.elapsed().as_millis() as u64);
            }
        }
    }
}

/// A run finished: remember it, say how it went, and let the window work again.
///
/// A stopped run is not remembered: the history and the verdicts of the last
/// full run stay as they were, so the delta always compares two complete runs.
fn finish(app: &mut App, report: RunReport) {
    app.running = false;
    app.progress = 1.0;
    let seconds = app
        .started
        .take()
        .map(|started| started.elapsed().as_secs())
        .unwrap_or(0);
    let stopped = app.stopping;
    app.stopping = false;
    if !stopped {
        app.config.remember(summarize(&report, seconds));
        app.remember_prev();
        app.persist();
    }
    app.status = match &report.interrupted {
        Some(interrupted) => Status::Interrupted(interrupted.target.clone()),
        None if stopped => Status::Stopped,
        None if app.control_dead => Status::ControlDead,
        None => Status::Done,
    };
    app.report = Some(report);
    sort_order(app);
}

/// The counters of one run, as the dashboard and the history keep them.
fn summarize(report: &RunReport, seconds: u64) -> RunSummary {
    let mut summary = RunSummary {
        at: report.generated_at.clone(),
        seconds,
        ok: 0,
        blocked: 0,
        unknown: 0,
    };
    for target in &report.targets {
        match display(target).1 {
            Level::Ok => summary.ok += 1,
            Level::Bad => summary.blocked += 1,
            Level::Warn | Level::Undetermined => summary.unknown += 1,
        }
    }
    summary
}

/// Start a run with the checked targets and the current settings.
fn start(ui: &AppWindow, app: &mut App) {
    if app.running {
        return;
    }
    let mut targets: Vec<Target> = Vec::new();
    let mut running_rows: Vec<usize> = Vec::new();
    for (index, row) in app.rows.iter().enumerate() {
        if row.checked {
            targets.push(row.target.clone());
            running_rows.push(index);
        }
    }
    if targets.is_empty() {
        app.toast = Some((app.strings().nothing_selected.to_string(), Instant::now() + TOAST));
        refresh(ui, app);
        return;
    }
    let socks5 = match parse_socks5(&app.socks5) {
        Ok(proxy) => proxy,
        Err(()) => {
            app.toast = Some((app.strings().bad_socks5.to_string(), Instant::now() + TOAST));
            refresh(ui, app);
            return;
        }
    };

    for row in &mut app.rows {
        row.prev = app.config.prev_of(&row.target.domain).map(str::to_string);
        row.report = None;
        row.tunnel = None;
        row.running = false;
        row.started = None;
        row.ms = None;
    }
    app.report = None;
    app.control_dead = false;
    app.running_rows = running_rows;
    app.running = true;
    app.stopping = false;
    app.cancel = run::Cancel::never();
    app.progress = 0.0;
    app.run_id += 1;
    app.started = Some(Instant::now());
    app.status = Status::Checking {
        done: 0,
        total: targets.len(),
    };
    app.persist();
    let options = Options {
        timeout: Duration::from_secs(app.timeout),
        socks5,
    };
    spawn_run(app.run_id, targets, options, app.cancel.clone(), app.events.clone());
    refresh(ui, app);
}

/// The stop button: the run stops asking after the target it is on. A probe in
/// flight ends on its own timeout, and the targets it never reached stay
/// unprobed.
fn stop(app: &mut App) {
    if !app.running {
        return;
    }
    app.stopping = true;
    app.cancel.cancel();
}

/// Move the choice up or down the visible rows, and open the details of the
/// row it lands on.
fn walk(app: &mut App, delta: i32) {
    let visible = visible_rows(app);
    if visible.is_empty() {
        return;
    }
    let at = app
        .selected
        .and_then(|selected| visible.iter().position(|index| *index == selected));
    let next = match at {
        Some(at) => (at as i32 + delta).clamp(0, visible.len() as i32 - 1) as usize,
        None if delta < 0 => visible.len() - 1,
        None => 0,
    };
    app.selected = Some(visible[next]);
}

/// The inspector's copy button: the target's result as text, for a chat or a
/// bug report. The ladder is written in words, not in glyphs.
fn copy(ui: &AppWindow, app: &mut App) {
    let strings = app.strings();
    let Some(row) = app.selected.and_then(|index| app.rows.get(index)) else {
        return;
    };
    let text = result_text(row, &strings);
    let message = match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(text)) {
        Ok(()) => format!("{} — {}", row.target.domain, strings.copied),
        Err(err) => format!("{}: {err}", strings.copy_failed),
    };
    app.toast = Some((message, Instant::now() + TOAST));
    refresh(ui, app);
}

/// One target's result as plain text: the domain, the verdict with its
/// meaning, the ladder of the probes, and the facts behind them.
fn result_text(row: &Row, strings: &Strings) -> String {
    let mut out = String::new();
    out.push_str(&row.target.domain);
    out.push('\n');
    let kind = row.kind();
    if kind.is_empty() {
        out.push_str(strings.why_not_probed);
    } else {
        out.push_str(&format!("{} — {}", badge(kind, strings), why(kind, strings)));
    }
    out.push('\n');
    for step in steps_for(row, strings) {
        out.push_str(&format!("{}  {}  {}\n", step.name, step.result, step.note));
    }
    if let Some(report) = &row.report {
        if !report.verdict.facts.is_empty() {
            out.push('\n');
            out.push_str(strings.facts_label);
            out.push('\n');
            for fact in &report.verdict.facts {
                out.push_str(&format!("· {fact}\n"));
            }
        }
    }
    out
}

/// An empty field means no tunnel; anything else has to be an address.
fn parse_socks5(text: &str) -> Result<Option<SocketAddr>, ()> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse::<SocketAddr>().map(Some).map_err(|_| ())
}

/// A bare domain, lowercased, without a trailing dot, or `None` when the text
/// is not one.
///
/// The window takes a domain, not a URL: a scheme or a path would silently
/// probe something other than what the user typed.
fn validate_domain(text: &str) -> Option<String> {
    let domain = text.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    if domain.contains("://")
        || domain.contains('/')
        || domain.contains(':')
        || domain.contains('@')
        || domain.contains(' ')
        || !domain.contains('.')
    {
        return None;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
    }
    Some(domain)
}

/// Add the domain in the field, or say why it cannot be added.
fn add_domain(ui: &AppWindow, app: &mut App) {
    let Some(domain) = validate_domain(&app.add_text) else {
        app.toast = Some((app.strings().bad_domain.to_string(), Instant::now() + TOAST));
        refresh(ui, app);
        return;
    };
    if app.rows.iter().any(|row| row.target.domain == domain) {
        app.toast = Some((app.strings().duplicate_domain.to_string(), Instant::now() + TOAST));
        refresh(ui, app);
        return;
    }
    app.rows.push(Row::new(target::ad_hoc(&domain), true));
    app.order.push(app.rows.len() - 1);
    app.selected = Some(app.rows.len() - 1);
    app.add_text.clear();
    app.adding = false;
    app.toast = Some((format!("{}: {domain}", app.strings().added), Instant::now() + TOAST));
    app.persist();
    refresh(ui, app);
}

/// Keep the timeout inside the range the stepper promises.
fn clamp_timeout(value: u64) -> u64 {
    value.clamp(config::MIN_TIMEOUT, config::MAX_TIMEOUT)
}

/// The default file name: the moment of the run, so two exports never collide.
/// The text report is written next to the JSON one, under the same stem.
fn export_name(report: &RunReport) -> String {
    let stamp: String = report
        .generated_at
        .chars()
        .map(|c| if c == ':' { '-' } else { c })
        .collect();
    format!("oko-{stamp}.json")
}

/// Wire the window's callbacks to the state.
fn wire(ui: &AppWindow, app: &Rc<RefCell<App>>) {
    ui.on_toggle({
        let ui = ui.as_weak();
        let app = app.clone();
        move |index| {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            if let Some(row) = state.rows.get_mut(index as usize) {
                row.checked = !row.checked;
            }
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_toggle_group({
        let ui = ui.as_weak();
        let app = app.clone();
        move |group| {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            let Some(category) = usize::try_from(group)
                .ok()
                .and_then(|index| Category::GROUPS.get(index).copied())
            else {
                return;
            };
            let all = state
                .rows
                .iter()
                .filter(|row| row.target.category == category)
                .all(|row| row.checked);
            for row in &mut state.rows {
                if row.target.category == category {
                    row.checked = !all;
                }
            }
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_toggle_collapse({
        let ui = ui.as_weak();
        let app = app.clone();
        move |group| {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            let Some(group) = usize::try_from(group)
                .ok()
                .filter(|group| *group < state.collapsed.len())
            else {
                return;
            };
            state.collapsed[group] = !state.collapsed[group];
            refresh(&window, &state);
        }
    });

    ui.on_open_settings({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.settings_open = true;
            refresh(&window, &state);
        }
    });

    ui.on_close_settings({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.settings_open = false;
            refresh(&window, &state);
        }
    });

    // The updater's one button: check, download, restart, in that order.
    ui.on_update_pressed({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            match state.update.clone() {
                Update::Checking | Update::Downloading(_) => {}
                Update::Ready { exe, .. } => {
                    // The new binary is in place: the config goes to disk
                    // first, because the process is about to be replaced.
                    state.persist();
                    drop(state);
                    match update::restart(&exe) {
                        // On Windows the new process is already running.
                        Ok(()) => std::process::exit(0),
                        Err(err) => {
                            let mut state = app.borrow_mut();
                            state.update = Update::Failed(err.to_string());
                            refresh(&window, &state);
                        }
                    }
                }
                Update::Available(_) | Update::Failed(_) if state.update_release.is_some() => {
                    let Some(release) = state.update_release.clone() else {
                        return;
                    };
                    state.update = Update::Downloading(0.0);
                    state.update_manual = true;
                    refresh(&window, &state);
                    spawn_install(release, state.events.clone());
                }
                _ => {
                    state.update = Update::Checking;
                    state.update_manual = true;
                    refresh(&window, &state);
                    spawn_check(state.events.clone());
                }
            }
        }
    });

    ui.on_select({
        let ui = ui.as_weak();
        let app = app.clone();
        move |index| {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.selected = usize::try_from(index).ok().filter(|index| *index < state.rows.len());
            refresh(&window, &state);
        }
    });

    ui.on_close_details({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.selected = None;
            refresh(&window, &state);
        }
    });

    ui.on_remove({
        let ui = ui.as_weak();
        let app = app.clone();
        move |index| {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            let Some(index) = usize::try_from(index).ok().filter(|index| *index < state.rows.len()) else {
                return;
            };
            if !state.rows[index].target.custom {
                return;
            }
            state.rows.remove(index);
            state.selected = None;
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_check_all({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            for row in &mut state.rows {
                row.checked = true;
            }
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_check_none({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            for row in &mut state.rows {
                row.checked = false;
            }
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_begin_add({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.adding = true;
            state.add_text.clear();
            refresh(&window, &state);
        }
    });

    ui.on_cancel_add({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.adding = false;
            state.add_text.clear();
            refresh(&window, &state);
        }
    });

    ui.on_add_text_edited({
        let app = app.clone();
        move |text| {
            app.borrow_mut().add_text = text.to_string();
        }
    });

    ui.on_add_domain({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            add_domain(&window, &mut app.borrow_mut());
        }
    });

    ui.on_start({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            start(&window, &mut app.borrow_mut());
        }
    });

    // The chips, the stats and the wall all ask for the same filter; a second
    // click on the one that is on turns it off.
    ui.on_pick_filter({
        let ui = ui.as_weak();
        let app = app.clone();
        move |code| {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            let filter = Filter::from_code(code);
            state.filter = if state.filter == filter { Filter::All } else { filter };
            refresh(&window, &state);
        }
    });

    ui.on_search_edited({
        let ui = ui.as_weak();
        let app = app.clone();
        move |text| {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.search = text.to_string();
            refresh(&window, &state);
        }
    });

    ui.on_walk({
        let ui = ui.as_weak();
        let app = app.clone();
        move |delta| {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            walk(&mut state, delta);
            refresh(&window, &state);
        }
    });

    ui.on_stop({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            stop(&mut state);
            refresh(&window, &state);
        }
    });

    ui.on_copy({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            copy(&window, &mut app.borrow_mut());
        }
    });

    ui.on_timeout_dec({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.timeout = clamp_timeout(state.timeout.saturating_sub(1));
            window.set_timeout_value(state.timeout as i32);
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_timeout_inc({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.timeout = clamp_timeout(state.timeout.saturating_add(1));
            window.set_timeout_value(state.timeout as i32);
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_toggle_frame({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.frame = !state.frame;
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_export({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            export(&window, &mut app.borrow_mut());
        }
    });

    // The field owns its text while the user types; the state mirrors it here.
    ui.on_socks5_edited({
        let app = app.clone();
        move |text| {
            let mut state = app.borrow_mut();
            state.socks5 = text.to_string();
            state.persist();
        }
    });

    ui.on_pick_dark({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.dark = true;
            window.global::<Theme>().set_dark(true);
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_pick_light({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.dark = false;
            window.global::<Theme>().set_dark(false);
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_pick_ru({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.lang = Lang::Ru;
            window.set_lang("ru".into());
            i18n::apply(&window, Lang::Ru);
            state.persist();
            refresh(&window, &state);
        }
    });

    ui.on_pick_en({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            state.lang = Lang::En;
            window.set_lang("en".into());
            i18n::apply(&window, Lang::En);
            state.persist();
            refresh(&window, &state);
        }
    });
}

/// Write the report: the dialog picks the place of the JSON, the text report
/// lands next to it under the same stem. One button, one dialog, two files.
fn export(ui: &AppWindow, app: &mut App) {
    let strings = app.strings();
    let Some(report) = &app.report else {
        app.toast = Some((strings.export_empty.to_string(), Instant::now() + TOAST));
        refresh(ui, app);
        return;
    };
    let json = match report::render_json(report) {
        Ok(json) => json,
        Err(err) => {
            app.toast = Some((format!("{}: {err}", strings.export_failed), Instant::now() + TOAST));
            refresh(ui, app);
            return;
        }
    };
    let text = report::render(report);
    let name = export_name(report);
    let path = match std::env::var_os("OKO_EXPORT_DIR") {
        Some(dir) => Some(std::path::PathBuf::from(dir).join(name)),
        None => rfd::FileDialog::new()
            .set_file_name(&name)
            .set_title(strings.export_title)
            .save_file(),
    };
    let Some(path) = path else {
        return;
    };
    let text_path = path.with_extension("txt");
    let message = match std::fs::write(&path, json).and_then(|()| std::fs::write(&text_path, text)) {
        Ok(()) => format!("{}: {}", strings.export_done, path.display()),
        Err(err) => format!("{}: {err}", strings.export_failed),
    };
    app.toast = Some((message, Instant::now() + TOAST));
    refresh(ui, app);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{ControlReport, Interrupted};
    use crate::verdict::{Diff, Verdict, VerdictKind};

    fn verdict(kind: VerdictKind) -> Verdict {
        Verdict {
            kind,
            level: kind.default_level(),
            reason: String::new(),
            facts: Vec::new(),
            address_source: None,
        }
    }

    fn report(kind: VerdictKind, diff: Option<DiffKind>) -> TargetReport {
        TargetReport {
            target: target::ad_hoc("example.org"),
            verdict: verdict(kind),
            dns: crate::probes::dns::DnsProbe::empty("example.org"),
            tcp: Vec::new(),
            tls: None,
            http: None,
            payload: None,
            quic: None,
            diff: diff.map(|kind| Diff {
                kind,
                direct: kind_of(kind),
                tunnel: VerdictKind::Ok,
                reason: String::new(),
            }),
        }
    }

    fn kind_of(kind: DiffKind) -> VerdictKind {
        match kind {
            DiffKind::BothOk => VerdictKind::Ok,
            _ => VerdictKind::DpiSni,
        }
    }

    fn run_report(targets: Vec<TargetReport>) -> RunReport {
        RunReport {
            tool: "oko",
            version: "test",
            generated_at: "2026-11-14T17:24:45Z".to_string(),
            targets,
            control: ControlReport {
                target: target::control(),
                tcp: Vec::new(),
            },
            tunnel: None,
            interrupted: None,
        }
    }

    #[test]
    fn a_bare_domain_is_accepted_and_normalised() {
        assert_eq!(validate_domain("Example.ORG"), Some("example.org".to_string()));
        assert_eq!(validate_domain("  example.org.  "), Some("example.org".to_string()));
        assert_eq!(
            validate_domain("store.steampowered.com"),
            Some("store.steampowered.com".to_string())
        );
    }

    #[test]
    fn a_url_is_not_a_domain() {
        for text in [
            "https://example.org",
            "example.org/path",
            "example.org:443",
            "user@example.org",
            "example org",
            "localhost",
            "",
            "-example.org",
            "example-.org",
            "example..org",
        ] {
            assert_eq!(validate_domain(text), None, "{text}");
        }
    }

    #[test]
    fn the_table_shows_the_diff_when_a_tunnel_ran() {
        let direct = report(VerdictKind::DpiSni, Some(DiffKind::PathBlock));
        assert_eq!(display(&direct), ("path_block", Level::Bad));
        let both = report(VerdictKind::Ok, Some(DiffKind::BothOk));
        assert_eq!(display(&both), ("both_ok", Level::Ok));
        let service = report(VerdictKind::DpiSni, Some(DiffKind::ServiceBlock));
        assert_eq!(display(&service), ("service_block", Level::Bad));
        let unknown = report(VerdictKind::DpiSni, Some(DiffKind::Unknown));
        assert_eq!(display(&unknown), ("unknown", Level::Undetermined));
    }

    #[test]
    fn without_a_tunnel_the_table_shows_the_direct_verdict() {
        let direct = report(VerdictKind::DpiSni, None);
        assert_eq!(display(&direct), ("dpi_sni", Level::Bad));
    }

    #[test]
    fn the_summary_counts_the_levels_the_table_shows() {
        let run = RunReport {
            tool: "oko",
            version: "test",
            generated_at: "2026-11-14T17:24:45Z".to_string(),
            targets: vec![
                report(VerdictKind::Ok, None),
                report(VerdictKind::DpiSni, None),
                report(VerdictKind::Unknown, None),
                report(VerdictKind::DpiSni, Some(DiffKind::PathBlock)),
                report(VerdictKind::Ok, Some(DiffKind::BothOk)),
            ],
            control: ControlReport {
                target: target::control(),
                tcp: Vec::new(),
            },
            tunnel: None,
            interrupted: None,
        };
        let summary = summarize(&run, 44);
        assert_eq!(summary.ok, 2);
        assert_eq!(summary.blocked, 2);
        assert_eq!(summary.unknown, 1);
        assert_eq!(summary.seconds, 44);
        assert_eq!(summary.at, "2026-11-14T17:24:45Z");
    }

    #[test]
    fn an_interrupted_run_is_summarised_from_what_finished() {
        let run = RunReport {
            tool: "oko",
            version: "test",
            generated_at: "2026-11-14T17:24:45Z".to_string(),
            targets: vec![report(VerdictKind::Ok, None)],
            control: ControlReport {
                target: target::control(),
                tcp: Vec::new(),
            },
            tunnel: None,
            interrupted: Some(Interrupted {
                target: "youtube.com".to_string(),
                budget_secs: 270,
            }),
        };
        let summary = summarize(&run, 12);
        assert_eq!(summary.ok, 1);
        assert_eq!(summary.blocked, 0);
    }

    #[test]
    fn a_verdict_lands_on_the_row_that_was_probed() {
        let (events, _incoming) = mpsc::channel();
        let mut app = App::new(Config::default(), events);
        // Only the sixth row was ticked, so the run numbers it zero.
        app.running_rows = vec![5];
        apply_progress(
            &mut app,
            Progress::Target {
                index: 0,
                report: report(VerdictKind::Ok, None),
            },
        );
        assert!(app.rows[5].report.is_some(), "the probed row got the report");
        assert!(app.rows[0].report.is_none(), "no other row did");
        assert_eq!(app.progress, 1.0);
    }

    #[test]
    fn the_dashboard_delta_is_signed_and_silent_at_zero() {
        assert_eq!(signed(3, 2), "+1");
        assert_eq!(signed(2, 3), "-1");
        assert_eq!(signed(2, 2), "·");
    }

    #[test]
    fn a_stamp_is_readable() {
        assert_eq!(stamp("2026-11-14T17:24:45Z"), "2026-11-14 17:24");
    }

    #[test]
    fn the_export_name_carries_the_moment_of_the_run() {
        let run = RunReport {
            tool: "oko",
            version: "test",
            generated_at: "2026-11-14T17:24:45Z".to_string(),
            targets: Vec::new(),
            control: ControlReport {
                target: target::control(),
                tcp: Vec::new(),
            },
            tunnel: None,
            interrupted: None,
        };
        assert_eq!(export_name(&run), "oko-2026-11-14T17-24-45Z.json");
    }

    #[test]
    fn the_timeout_stays_inside_the_range() {
        assert_eq!(clamp_timeout(0), config::MIN_TIMEOUT);
        assert_eq!(clamp_timeout(5000), config::MAX_TIMEOUT);
        assert_eq!(clamp_timeout(7), 7);
    }

    #[test]
    fn the_rows_are_grouped_by_category_with_a_header_each() {
        let (events, _incoming) = mpsc::channel();
        let app = App::new(Config::default(), events);
        let strings = Strings::new(Lang::En);
        let rows = list_model(&app, &strings);
        let headers: Vec<&str> = rows
            .iter()
            .filter(|row| row.header)
            .map(|row| row.domain.as_str())
            .collect();
        // The custom group has no targets yet, so it has no header either.
        assert_eq!(headers.len(), Category::GROUPS.len() - 1);
        assert_eq!(headers[0], "Video hosting");
        assert_eq!(headers[headers.len() - 1], "Development");
        assert_eq!(
            rows.iter().filter(|row| !row.header).count(),
            app.rows.len(),
            "every target appears once"
        );
    }

    #[test]
    fn a_custom_target_gets_its_own_group() {
        let (events, _incoming) = mpsc::channel();
        let config = Config {
            custom: vec!["example.org".to_string()],
            ..Config::default()
        };
        let app = App::new(config, events);
        let strings = Strings::new(Lang::Ru);
        let rows = list_model(&app, &strings);
        let custom = rows
            .iter()
            .find(|row| row.header && row.domain == "Пользовательские")
            .expect("the custom group is there");
        let after = rows
            .iter()
            .skip_while(|row| row.group != custom.group || !row.header)
            .nth(1)
            .expect("a row follows the header");
        assert_eq!(after.domain, "example.org");
        assert!(after.custom);
    }

    #[test]
    fn a_full_run_remembers_the_verdict_of_every_target() {
        let (events, _incoming) = mpsc::channel();
        let mut app = App::new(Config::default(), events);
        app.running = true;
        app.rows[0].report = Some(report(VerdictKind::Ok, None));
        app.rows[1].report = Some(report(VerdictKind::DpiSni, None));
        finish(&mut app, run_report(vec![report(VerdictKind::Ok, None)]));
        assert_eq!(app.config.history.len(), 1, "the run is in the history");
        assert_eq!(app.config.prev.len(), 2, "both probed targets are remembered");
        assert_eq!(app.config.prev[0].domain, app.rows[0].target.domain);
        assert_eq!(app.config.prev[0].verdict, "ok");
        assert_eq!(app.config.prev[1].verdict, "dpi_sni");
        assert!(matches!(app.status, Status::Done));
    }

    #[test]
    fn a_stopped_run_leaves_the_history_and_the_verdicts_alone() {
        let (events, _incoming) = mpsc::channel();
        let mut app = App::new(Config::default(), events);
        app.running = true;
        app.rows[0].report = Some(report(VerdictKind::Ok, None));
        stop(&mut app);
        assert!(app.stopping, "the stop button asks the run to end");
        assert!(app.cancel.is_cancelled(), "and the engine sees it");
        finish(&mut app, run_report(vec![report(VerdictKind::Ok, None)]));
        assert!(app.config.history.is_empty(), "a stopped run is not a run");
        assert!(app.config.prev.is_empty(), "and it remembers nothing");
        assert!(matches!(app.status, Status::Stopped));
        assert!(!app.stopping, "the next run starts clean");
    }

    #[test]
    fn the_stop_button_does_nothing_when_no_run_goes_on() {
        let (events, _incoming) = mpsc::channel();
        let mut app = App::new(Config::default(), events);
        stop(&mut app);
        assert!(!app.stopping);
        assert!(!app.cancel.is_cancelled());
    }

    #[test]
    fn the_filter_keeps_one_bucket_of_the_ticked_targets() {
        let (events, _incoming) = mpsc::channel();
        let mut app = App::new(Config::default(), events);
        app.rows[0].report = Some(report(VerdictKind::Ok, None));
        app.rows[1].report = Some(report(VerdictKind::DpiSni, None));
        app.rows[2].report = Some(report(VerdictKind::Unknown, None));
        app.rows[3].report = Some(report(VerdictKind::GeoBlockByService, None));

        app.filter = Filter::Blocked;
        assert_eq!(visible_rows(&app), vec![1, 3], "the provider and the service");
        app.filter = Filter::Ok;
        assert_eq!(visible_rows(&app), vec![0]);
        app.filter = Filter::Unknown;
        assert_eq!(visible_rows(&app), vec![2]);
        app.filter = Filter::All;
        assert_eq!(visible_rows(&app).len(), app.rows.len(), "everything is ticked");
    }

    #[test]
    fn an_unprobed_target_is_in_no_bucket() {
        assert_eq!(Filter::of(""), None);
        assert_eq!(Filter::of("ok"), Some(Filter::Ok));
        assert_eq!(Filter::of("both_ok"), Some(Filter::Ok));
        assert_eq!(Filter::of("unknown"), Some(Filter::Unknown));
        assert_eq!(Filter::of("service_block"), Some(Filter::Blocked));
        assert_eq!(Filter::of("dpi_sni"), Some(Filter::Blocked));
        assert!(Filter::All.keeps(""));
        assert!(!Filter::Ok.keeps(""));
    }

    #[test]
    fn the_search_hides_the_groups_without_a_match() {
        let (events, _incoming) = mpsc::channel();
        let mut app = App::new(Config::default(), events);
        let strings = Strings::new(Lang::En);
        app.search = "YouTube".to_string();
        let rows = list_model(&app, &strings);
        assert_eq!(rows.iter().filter(|row| row.header).count(), 1, "one group is left");
        assert!(
            rows.iter()
                .filter(|row| !row.header)
                .all(|row| row.domain == "youtube.com"),
            "and only the target that matched"
        );
        app.search = "nothing-like-this".to_string();
        assert!(list_model(&app, &strings).is_empty(), "no match, no list");
    }

    #[test]
    fn the_delta_points_up_when_the_verdict_improved() {
        let strings = Strings::new(Lang::En);
        let mut row = Row::new(target::ad_hoc("example.org"), true);
        row.prev = Some("dpi_sni".to_string());
        row.report = Some(report(VerdictKind::Ok, None));
        let view = row.view(0, &strings, false);
        assert_eq!(view.delta, 1, "the provider's cut became a clean target");
        assert!(view.tip.contains("last run"), "the tooltip says what it was");

        row.prev = Some("ok".to_string());
        row.report = Some(report(VerdictKind::DpiSni, None));
        assert_eq!(row.view(0, &strings, false).delta, 2, "and down when it got worse");

        // A definite answer beats an uncertain one, and the service's own
        // refusal beats the provider's cut.
        row.prev = Some("unknown".to_string());
        row.report = Some(report(VerdictKind::GeoBlockByService, None));
        assert_eq!(
            row.view(0, &strings, false).delta,
            2,
            "the ladder puts the uncertainty above the service's refusal"
        );
        row.prev = Some("dpi_sni".to_string());
        assert_eq!(
            row.view(0, &strings, false).delta,
            1,
            "the service is the better answer"
        );

        row.prev = Some("ok".to_string());
        row.report = Some(report(VerdictKind::Ok, None));
        assert_eq!(row.view(0, &strings, false).delta, 0, "no move, no triangle");
    }

    #[test]
    fn the_service_itself_draws_a_hollow_badge() {
        let strings = Strings::new(Lang::En);
        let mut row = Row::new(target::ad_hoc("example.org"), true);
        row.report = Some(report(VerdictKind::GeoBlockByService, None));
        assert!(row.view(0, &strings, false).hollow);
        row.report = Some(report(VerdictKind::DpiSni, None));
        assert!(!row.view(0, &strings, false).hollow);
    }

    #[test]
    fn the_arrows_walk_the_visible_rows() {
        let (events, _incoming) = mpsc::channel();
        let mut app = App::new(Config::default(), events);
        app.rows[0].report = Some(report(VerdictKind::Ok, None));
        app.rows[1].report = Some(report(VerdictKind::DpiSni, None));
        app.filter = Filter::Blocked;
        walk(&mut app, 1);
        assert_eq!(app.selected, Some(1), "the first visible row");
        walk(&mut app, 1);
        assert_eq!(app.selected, Some(1), "the last one holds");
        walk(&mut app, -1);
        assert_eq!(app.selected, Some(1), "and the first one holds going up");
        app.filter = Filter::All;
        walk(&mut app, -1);
        assert_eq!(app.selected, Some(0));
    }

    #[test]
    fn the_copy_text_carries_the_domain_the_verdict_the_ladder_and_the_facts() {
        let strings = Strings::new(Lang::Ru);
        let mut row = Row::new(target::ad_hoc("example.org"), true);
        let mut target_report = report(VerdictKind::DpiSni, None);
        target_report.verdict.facts = vec!["SNI: youtube.com".to_string()];
        row.report = Some(target_report);
        let text = result_text(&row, &strings);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "example.org");
        assert!(lines[1].starts_with(strings.badge_provider), "the verdict word");
        assert!(lines[1].contains(strings.why_dpi_sni), "and what it means");
        assert_eq!(lines.len(), 2 + 7 + 1 + 1 + 1, "the ladder, the facts, the fact");
        assert!(text.contains(strings.step_dns), "the ladder is there");
        assert!(text.contains("SNI: youtube.com"), "and the facts");
    }
}
