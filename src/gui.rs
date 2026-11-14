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

use slint::{ComponentHandle, ModelRc, VecModel};

use crate::config::{self, Config, RunSummary};
use crate::i18n::{self, Lang, Strings};
use crate::report::{self, RunReport, TargetReport};
use crate::run::{self, Options, Progress};
use crate::target::{self, Category, Target};
use crate::verdict::{DiffKind, Level};

slint::include_modules!();

/// How often the UI thread drains the engine's channel.
const TICK: Duration = Duration::from_millis(50);

/// One target in the table, with everything the details panel needs.
struct Row {
    target: Target,
    checked: bool,
    running: bool,
    report: Option<TargetReport>,
    tunnel: Option<TargetReport>,
}

impl Row {
    fn new(target: Target, checked: bool) -> Row {
        Row {
            target,
            checked,
            running: false,
            report: None,
            tunnel: None,
        }
    }

    /// The row as the table shows it.
    fn view(&self, index: usize, strings: &Strings) -> TargetRow {
        let shown = self.report.as_ref().map(display);
        TargetRow {
            index: index as i32,
            group: 0,
            header: false,
            domain: self.target.domain.clone().into(),
            checked: self.checked,
            verdict: shown.map(|(kind, _)| kind).unwrap_or("").into(),
            level: shown.map(|(_, level)| level_code(level)).unwrap_or(4),
            level_text: shown.map(|(_, level)| strings.level(level)).unwrap_or_default().into(),
            diff: self
                .report
                .as_ref()
                .and_then(|report| report.diff.as_ref())
                .map(|diff| diff.kind.as_str())
                .unwrap_or("")
                .into(),
            running: self.running,
            custom: self.target.custom,
        }
    }

    /// The details panel text: the direct report, the tunnel report and the
    /// diff, in the same words the CLI prints.
    fn detail(&self) -> String {
        match &self.report {
            Some(report) => report::render_target(report, self.tunnel.as_ref()),
            None => String::new(),
        }
    }
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

/// What the status line says.
enum Status {
    Ready,
    Checking { done: usize, total: usize },
    Done { total: usize },
    ControlDead,
    Interrupted(String),
    Failed(String),
    Message(Message),
}

/// A status line that is not about the run.
enum Message {
    NothingSelected,
    BadSocks5,
    BadDomain,
    DuplicateDomain,
}

impl Status {
    fn text(&self, strings: &Strings) -> String {
        match self {
            Status::Ready => strings.ready.to_string(),
            Status::Checking { done, total } => format!("{} {done}/{total}", strings.checking),
            Status::Done { total } => format!("{}: {total}", strings.done),
            Status::ControlDead => strings.control_dead.to_string(),
            Status::Interrupted(target) => format!("{}: {target}", strings.interrupted),
            Status::Failed(reason) => format!("{}: {reason}", strings.run_failed),
            Status::Message(Message::NothingSelected) => strings.nothing_selected.to_string(),
            Status::Message(Message::BadSocks5) => strings.bad_socks5.to_string(),
            Status::Message(Message::BadDomain) => strings.bad_domain.to_string(),
            Status::Message(Message::DuplicateDomain) => strings.duplicate_domain.to_string(),
        }
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
    export_status: String,
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
            running: false,
            run_id: 0,
            running_rows: Vec::new(),
            started: None,
            report: None,
            export_status: String::new(),
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
                    ui.invoke_export_text();
                    ui.invoke_export_json();
                }
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

/// Push the whole state into the window.
fn refresh(ui: &AppWindow, app: &App) {
    let strings = app.strings();
    ui.set_rows(ModelRc::new(VecModel::from(rows_model(app, &strings))));
    ui.set_selected(app.selected.map(|index| index as i32).unwrap_or(-1));
    ui.set_detail(
        app.selected
            .and_then(|index| app.rows.get(index))
            .map(Row::detail)
            .unwrap_or_default()
            .into(),
    );
    ui.set_running(app.running);
    ui.set_progress(app.progress);
    ui.set_status(app.status.text(&strings).into());
    ui.set_adding(app.adding);
    ui.set_add_text(app.add_text.clone().into());
    ui.set_frame(app.frame);
    dashboard(ui, app, &strings);
}

/// The table's model: a header per category, then the targets of that group.
fn rows_model(app: &App, strings: &Strings) -> Vec<TargetRow> {
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
        out.push(TargetRow {
            index: -1,
            group: group as i32,
            header: true,
            domain: strings.category(*category).into(),
            checked,
            verdict: "".into(),
            level: 4,
            level_text: "".into(),
            diff: "".into(),
            running: false,
            custom: false,
        });
        for index in indices {
            out.push(app.rows[index].view(index, strings));
        }
    }
    out
}

/// The dashboard: the counters of the last run and the delta to the one before.
fn dashboard(ui: &AppWindow, app: &App, strings: &Strings) {
    let Some(last) = app.config.last() else {
        ui.set_dash_empty(true);
        ui.set_dash_ok("0".into());
        ui.set_dash_blocked("0".into());
        ui.set_dash_unknown("0".into());
        ui.set_dash_ok_delta("".into());
        ui.set_dash_blocked_delta("".into());
        ui.set_dash_unknown_delta("".into());
        ui.set_dash_info("".into());
        ui.set_dash_delta("".into());
        return;
    };
    ui.set_dash_empty(false);
    ui.set_dash_ok(last.ok.to_string().into());
    ui.set_dash_blocked(last.blocked.to_string().into());
    ui.set_dash_unknown(last.unknown.to_string().into());
    ui.set_dash_info(format!("{} · {} {}", stamp(&last.at), last.seconds, strings.seconds).into());
    match app.config.previous() {
        Some(previous) => {
            ui.set_dash_ok_delta(signed(last.ok, previous.ok).into());
            ui.set_dash_blocked_delta(signed(last.blocked, previous.blocked).into());
            ui.set_dash_unknown_delta(signed(last.unknown, previous.unknown).into());
            ui.set_dash_delta(strings.dash_delta.into());
        }
        None => {
            ui.set_dash_ok_delta("".into());
            ui.set_dash_blocked_delta("".into());
            ui.set_dash_unknown_delta("".into());
            ui.set_dash_delta("".into());
        }
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
        0 => "0".to_string(),
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
            }
        }
        Progress::Target { index, report } => {
            if let Some(row) = row_for(app, index) {
                row.running = false;
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
        None => Status::Done {
            total: report.targets.len(),
        },
    };
    app.report = Some(report);
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
        app.status = Status::Message(Message::NothingSelected);
        refresh(ui, app);
        return;
    }
    let socks5 = match parse_socks5(&app.socks5) {
        Ok(proxy) => proxy,
        Err(()) => {
            app.status = Status::Message(Message::BadSocks5);
            refresh(ui, app);
            return;
        }
    };

    for row in &mut app.rows {
        row.report = None;
        row.tunnel = None;
        row.running = false;
    }
    app.report = None;
    app.export_status.clear();
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
        app.status = Status::Message(Message::BadDomain);
        refresh(ui, app);
        return;
    };
    if app.rows.iter().any(|row| row.target.domain == domain) {
        app.status = Status::Message(Message::DuplicateDomain);
        refresh(ui, app);
        return;
    }
    app.rows.push(Row::new(target::ad_hoc(&domain), true));
    app.selected = Some(app.rows.len() - 1);
    app.add_text.clear();
    app.adding = false;
    app.status = Status::Ready;
    app.persist();
    refresh(ui, app);
}

/// Keep the timeout inside the range the stepper promises.
fn clamp_timeout(value: u64) -> u64 {
    value.clamp(config::MIN_TIMEOUT, config::MAX_TIMEOUT)
}

/// What an export writes.
#[derive(Clone, Copy)]
enum Export {
    Text,
    Json,
}

impl Export {
    fn extension(self) -> &'static str {
        match self {
            Export::Text => "txt",
            Export::Json => "json",
        }
    }
}

/// The contents of an export, or the reason it cannot be made.
fn export_contents(report: &RunReport, kind: Export) -> Result<String, String> {
    match kind {
        Export::Text => Ok(report::render(report)),
        Export::Json => report::render_json(report).map_err(|err| err.to_string()),
    }
}

/// The default file name: the moment of the run, so two exports never collide.
fn export_name(report: &RunReport, kind: Export) -> String {
    let stamp: String = report
        .generated_at
        .chars()
        .map(|c| if c == ':' { '-' } else { c })
        .collect();
    format!("oko-{stamp}.{}", kind.extension())
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

    ui.on_export_text({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            export(&window, &mut app.borrow_mut(), Export::Text);
        }
    });

    ui.on_export_json({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            export(&window, &mut app.borrow_mut(), Export::Json);
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

/// Write one export: the dialog picks the place, the report is the contents.
fn export(ui: &AppWindow, app: &mut App, kind: Export) {
    let Some(report) = &app.report else {
        app.export_status = app.strings().export_empty.to_string();
        ui.set_export_status(app.export_status.clone().into());
        return;
    };
    let contents = match export_contents(report, kind) {
        Ok(contents) => contents,
        Err(reason) => {
            app.export_status = format!("{}: {reason}", app.strings().export_failed);
            ui.set_export_status(app.export_status.clone().into());
            return;
        }
    };
    let name = export_name(report, kind);
    let path = match std::env::var_os("OKO_EXPORT_DIR") {
        Some(dir) => Some(std::path::PathBuf::from(dir).join(name)),
        None => rfd::FileDialog::new()
            .set_file_name(&name)
            .set_title(app.strings().export_title)
            .save_file(),
    };
    let Some(path) = path else {
        return;
    };
    app.export_status = match std::fs::write(&path, contents) {
        Ok(()) => format!("{}: {}", app.strings().export_done, path.display()),
        Err(err) => format!("{}: {err}", app.strings().export_failed),
    };
    ui.set_export_status(app.export_status.clone().into());
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
        assert_eq!(signed(2, 2), "0");
    }

    #[test]
    fn a_stamp_is_readable() {
        assert_eq!(stamp("2026-11-14T17:24:45Z"), "2026-11-14 17:24");
    }

    #[test]
    fn the_export_name_carries_the_moment_and_the_extension() {
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
        assert_eq!(export_name(&run, Export::Text), "oko-2026-11-14T17-24-45Z.txt");
        assert_eq!(export_name(&run, Export::Json), "oko-2026-11-14T17-24-45Z.json");
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
        let rows = rows_model(&app, &strings);
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
        let rows = rows_model(&app, &strings);
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
