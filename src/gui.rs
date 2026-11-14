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
        }
    }

    /// The row as the list and the table show it.
    fn view(&self, index: usize, strings: &Strings, pending: bool) -> TargetRow {
        let shown = self.report.as_ref().map(display);
        let kind = shown.map(|(kind, _)| kind).unwrap_or("");
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
    ControlDead,
    Interrupted(String),
    Failed(String),
}

impl Status {
    /// The state, in one short line.
    fn state(&self, strings: &Strings) -> String {
        match self {
            Status::Ready => strings.ready.to_string(),
            // The counter lives on the button; the header only says what is going on.
            Status::Checking { .. } => strings.checking.to_string(),
            Status::Done => strings.done.to_string(),
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
}

/// What the UI asks a run to do, and what the run tells the UI.
enum Event {
    Progress(u64, Box<Progress>),
    Finished(u64, Box<RunReport>),
    Failed(u64, String),
}

/// Start one run on its own thread: its own tokio runtime, its own id.
fn spawn_run(id: u64, targets: Vec<Target>, options: Options, events: mpsc::Sender<Event>) {
    thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => {
                let _ = events.send(Event::Failed(id, format!("cannot start the async runtime: {err}")));
                return;
            }
        };
        let sender = events.clone();
        let report = runtime.block_on(run::run(targets, options, move |progress| {
            let _ = sender.send(Event::Progress(id, Box::new(progress)));
        }));
        let _ = events.send(Event::Finished(id, Box::new(report)));
    });
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
        ui.set_timeout_value(state.timeout as i32);
        ui.set_frame(state.frame);
        ui.set_socks5_text(state.socks5.clone().into());
        refresh(&ui, &state);
    }

    wire(&ui, &app);

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
    if let Ok(group) = std::env::var("OKO_COLLAPSE").unwrap_or_default().parse::<i32>() {
        ui.invoke_toggle_collapse(group);
    }

    // The engine's events land here, on the UI thread.
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, TICK, {
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            while let Ok(event) = incoming.try_recv() {
                let finished = matches!(event, Event::Finished(..));
                handle(&ui, &mut app.borrow_mut(), event);
                if finished && std::env::var_os("OKO_EXPORT_DIR").is_some() {
                    ui.invoke_export();
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

    let result = ui.run();
    drop(timer);
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
    ui.set_run_state(app.status.state(&strings).into());
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
    dashboard(ui, app, &strings);
    status_bar(ui, app);
    toast(ui, app);
}

/// The targets panel: a header per category, then the targets of that group.
fn list_model(app: &App, strings: &Strings) -> Vec<TargetRow> {
    let mut out = Vec::new();
    for (group, category) in Category::GROUPS.iter().enumerate() {
        let indices: Vec<usize> = app
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.target.category == *category)
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
/// first. A target the run has not reached yet is dimmed.
fn table_model(app: &App, strings: &Strings) -> Vec<TargetRow> {
    app.order
        .iter()
        .filter_map(|index| app.rows.get(*index).map(|row| (*index, row)))
        .filter(|(_, row)| row.checked)
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

/// The button's label: the run's progress while it goes on.
fn run_label(app: &App, strings: &Strings) -> String {
    match &app.status {
        Status::Checking { done, total } if app.running => {
            format!("{} {done}/{total}", strings.checking)
        }
        _ => strings.check.to_string(),
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
        _ => return,
    }
    refresh(ui, app);
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
fn finish(app: &mut App, report: RunReport) {
    app.running = false;
    app.progress = 1.0;
    let seconds = app
        .started
        .take()
        .map(|started| started.elapsed().as_secs())
        .unwrap_or(0);
    app.config.remember(summarize(&report, seconds));
    app.persist();
    app.status = match &report.interrupted {
        Some(interrupted) => Status::Interrupted(interrupted.target.clone()),
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
    spawn_run(app.run_id, targets, options, app.events.clone());
    refresh(ui, app);
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
}
