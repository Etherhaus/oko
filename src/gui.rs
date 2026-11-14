//! The window.
//!
//! The engine runs on its own thread with its own tokio runtime and sends
//! events over a channel; a timer on the UI thread drains them. Nothing the
//! probes do can block the window, and the table fills in target by target.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use slint::{ComponentHandle, ModelRc, VecModel};

use crate::i18n::{self, Lang, Strings};
use crate::report::{self, RunReport, TargetReport};
use crate::run::{self, Options, Progress};
use crate::target::{self, Role, Target};
use crate::verdict::Level;

slint::include_modules!();

/// The range the timeout stepper allows, in seconds.
const MIN_TIMEOUT: u64 = 1;
const MAX_TIMEOUT: u64 = 120;
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
    fn new(target: Target) -> Row {
        Row {
            target,
            checked: true,
            running: false,
            report: None,
            tunnel: None,
        }
    }

    /// The row as the table shows it.
    fn view(&self, index: usize, strings: &Strings) -> TargetRow {
        let verdict = self.report.as_ref().map(|report| &report.verdict);
        TargetRow {
            index: index as i32,
            domain: self.target.domain.clone().into(),
            checked: self.checked,
            verdict: verdict.map(|verdict| verdict.kind.as_str()).unwrap_or("").into(),
            level: verdict.map(|verdict| level_code(verdict.level)).unwrap_or(4),
            level_text: verdict
                .map(|verdict| strings.level(verdict.level))
                .unwrap_or_default()
                .into(),
            diff: self
                .report
                .as_ref()
                .and_then(|report| report.diff.as_ref())
                .map(|diff| diff.kind.as_str())
                .unwrap_or("")
                .into(),
            running: self.running,
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
    Failed(String),
    Message(Message),
}

/// A status line that is not about the run.
enum Message {
    NothingSelected,
    BadSocks5,
}

impl Status {
    fn text(&self, strings: &Strings) -> String {
        match self {
            Status::Ready => strings.ready.to_string(),
            Status::Checking { done, total } => format!("{} {done}/{total}", strings.checking),
            Status::Done { total } => format!("{}: {total}", strings.done),
            Status::ControlDead => strings.control_dead.to_string(),
            Status::Failed(reason) => format!("{}: {reason}", strings.run_failed),
            Status::Message(Message::NothingSelected) => strings.nothing_selected.to_string(),
            Status::Message(Message::BadSocks5) => strings.bad_socks5.to_string(),
        }
    }
}

/// What the UI thread owns.
struct App {
    rows: Vec<Row>,
    selected: Option<usize>,
    lang: Lang,
    dark: bool,
    timeout: u64,
    socks5: String,
    running: bool,
    report: Option<RunReport>,
    export_status: String,
    status: Status,
    progress: f32,
    control_dead: bool,
    engine: mpsc::Sender<Request>,
}

impl App {
    fn new(engine: mpsc::Sender<Request>) -> App {
        App {
            rows: target::builtin()
                .into_iter()
                .filter(|target| target.role == Role::Service)
                .map(Row::new)
                .collect(),
            selected: None,
            lang: Lang::En,
            dark: true,
            timeout: run::DEFAULT_TIMEOUT_SECS,
            socks5: String::new(),
            running: false,
            report: None,
            export_status: String::new(),
            status: Status::Ready,
            progress: 0.0,
            control_dead: false,
            engine,
        }
    }

    fn strings(&self) -> Strings {
        Strings::new(self.lang)
    }

    fn done(&self) -> usize {
        self.rows.iter().filter(|row| row.report.is_some()).count()
    }
}

/// What the UI asks the engine to do.
enum Request {
    Run { targets: Vec<Target>, options: Options },
}

/// What the engine tells the UI.
enum Event {
    Progress(Box<Progress>),
    Finished(Box<RunReport>),
    Failed(String),
}

/// The engine thread: one tokio runtime, one run at a time.
fn spawn_engine(events: mpsc::Sender<Event>) -> mpsc::Sender<Request> {
    let (requests, incoming) = mpsc::channel::<Request>();
    thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => {
                let _ = events.send(Event::Failed(format!("cannot start the async runtime: {err}")));
                return;
            }
        };
        while let Ok(Request::Run { targets, options }) = incoming.recv() {
            let sender = events.clone();
            let report = runtime.block_on(run::run(targets, options, move |progress| {
                let _ = sender.send(Event::Progress(Box::new(progress)));
            }));
            let _ = events.send(Event::Finished(Box::new(report)));
        }
    });
    requests
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
    let engine = spawn_engine(events);
    let app = Rc::new(RefCell::new(App::new(engine)));

    {
        let mut state = app.borrow_mut();
        state.lang = Lang::from_env();
        state.dark = true;
        i18n::apply(&ui, state.lang);
        ui.set_lang(state.lang.code().into());
        ui.global::<Theme>().set_dark(state.dark);
        ui.set_timeout_value(state.timeout as i32);
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

    // The engine's events land here, on the UI thread.
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, TICK, {
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            while let Ok(event) = incoming.try_recv() {
                let finished = matches!(event, Event::Finished(_));
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
    let rows: Vec<TargetRow> = app
        .rows
        .iter()
        .enumerate()
        .map(|(index, row)| row.view(index, &strings))
        .collect();
    ui.set_rows(ModelRc::new(VecModel::from(rows)));
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
    ui.set_status(app.status.text(&app.strings()).into());
    ui.set_export_status(app.export_status.clone().into());
    ui.set_timeout_value(app.timeout as i32);
}

/// Apply one engine event.
fn handle(ui: &AppWindow, app: &mut App, event: Event) {
    match event {
        Event::Progress(progress) => apply_progress(app, *progress),
        Event::Finished(report) => {
            app.running = false;
            app.report = Some(*report);
            app.progress = 1.0;
            app.status = if app.control_dead {
                Status::ControlDead
            } else {
                Status::Done { total: app.rows.len() }
            };
        }
        Event::Failed(reason) => {
            app.running = false;
            app.status = Status::Failed(reason);
        }
    }
    refresh(ui, app);
}

/// Apply one progress step to the state.
fn apply_progress(app: &mut App, progress: Progress) {
    match progress {
        Progress::Control(control) => {
            app.control_dead = !control.tcp.iter().any(|probe| probe.outcome.is_connected());
        }
        Progress::Started { index } => {
            if let Some(row) = app.rows.get_mut(index) {
                row.running = true;
            }
        }
        Progress::Target { index, report } => {
            if let Some(row) = app.rows.get_mut(index) {
                row.running = false;
                row.report = Some(report);
            }
            app.status = Status::Checking {
                done: app.done(),
                total: app.rows.len(),
            };
            app.progress = app.done() as f32 / app.rows.len().max(1) as f32;
        }
        Progress::Tunnel { index, report } => {
            if let Some(row) = app.rows.get_mut(index) {
                row.tunnel = Some(report);
            }
        }
        Progress::Diff { index, diff, verdict } => {
            if let Some(row) = app.rows.get_mut(index) {
                if let Some(report) = &mut row.report {
                    report.verdict = verdict;
                    report.diff = Some(diff);
                }
            }
        }
    }
}

/// Start a run with the checked targets and the current settings.
fn start(ui: &AppWindow, app: &mut App) {
    if app.running {
        return;
    }
    let strings = app.strings();
    let targets: Vec<Target> = app
        .rows
        .iter()
        .filter(|row| row.checked)
        .map(|row| row.target.clone())
        .collect();
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
    app.running = true;
    app.progress = 0.0;
    app.status = Status::Checking {
        done: 0,
        total: targets.len(),
    };
    let options = Options {
        timeout: Duration::from_secs(app.timeout),
        socks5,
    };
    let _ = app.engine.send(Request::Run { targets, options });
    let _ = strings;
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

/// Keep the timeout inside the range the stepper promises.
fn clamp_timeout(value: u64) -> u64 {
    value.clamp(MIN_TIMEOUT, MAX_TIMEOUT)
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

    ui.on_check_all({
        let ui = ui.as_weak();
        let app = app.clone();
        move || {
            let Some(window) = ui.upgrade() else { return };
            let mut state = app.borrow_mut();
            for row in &mut state.rows {
                row.checked = true;
            }
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
            refresh(&window, &state);
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
            app.borrow_mut().socks5 = text.to_string();
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
            i18n::apply(&window, state.lang);
            window.set_lang(state.lang.code().into());
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
            i18n::apply(&window, state.lang);
            window.set_lang(state.lang.code().into());
            refresh(&window, &state);
        }
    });
}

/// Ask where to save and write the report there.
fn export(ui: &AppWindow, app: &mut App, kind: Export) {
    let strings = app.strings();
    let Some(report) = &app.report else {
        app.export_status = strings.export_empty.to_string();
        refresh(ui, app);
        return;
    };
    let contents = match export_contents(report, kind) {
        Ok(contents) => contents,
        Err(err) => {
            app.export_status = format!("{}: {err}", strings.export_failed);
            refresh(ui, app);
            return;
        }
    };
    // A directory in the environment skips the dialog: the export can then be
    // checked, and scripted, without a mouse.
    let path = match std::env::var_os("OKO_EXPORT_DIR") {
        Some(dir) => std::path::PathBuf::from(dir).join(export_name(report, kind)),
        None => match rfd::FileDialog::new()
            .set_title(strings.export_title)
            .set_file_name(export_name(report, kind))
            .add_filter(kind.extension(), &[kind.extension()])
            .save_file()
        {
            Some(path) => path,
            None => return,
        },
    };
    app.export_status = match std::fs::write(&path, contents) {
        Ok(()) => format!("{}: {}", strings.export_done, path.display()),
        Err(err) => format!("{}: {err}", strings.export_failed),
    };
    refresh(ui, app);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_socks5_field_means_no_tunnel() {
        assert_eq!(parse_socks5(""), Ok(None));
        assert_eq!(parse_socks5("   "), Ok(None));
    }

    #[test]
    fn a_socks5_address_is_parsed() {
        let address: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        assert_eq!(parse_socks5("127.0.0.1:1080"), Ok(Some(address)));
        assert_eq!(parse_socks5(" 127.0.0.1:1080 "), Ok(Some(address)));
    }

    #[test]
    fn a_socks5_field_that_is_not_an_address_is_refused() {
        assert_eq!(parse_socks5("localhost:1080"), Err(()));
        assert_eq!(parse_socks5("127.0.0.1"), Err(()));
    }

    #[test]
    fn the_timeout_stays_inside_its_range() {
        assert_eq!(clamp_timeout(0), MIN_TIMEOUT);
        assert_eq!(clamp_timeout(5), 5);
        assert_eq!(clamp_timeout(500), MAX_TIMEOUT);
    }

    #[test]
    fn a_row_without_a_report_is_not_probed() {
        let row = Row::new(target::ad_hoc("github.com"));
        let view = row.view(3, &Strings::new(Lang::En));
        assert_eq!(view.index, 3);
        assert_eq!(view.domain, "github.com");
        assert!(view.checked);
        assert_eq!(view.verdict, "");
        assert_eq!(view.level, 4);
        assert_eq!(row.detail(), "");
    }

    #[test]
    fn the_levels_map_to_the_table_codes() {
        assert_eq!(level_code(Level::Ok), 0);
        assert_eq!(level_code(Level::Warn), 1);
        assert_eq!(level_code(Level::Bad), 2);
        assert_eq!(level_code(Level::Undetermined), 3);
    }

    #[test]
    fn the_status_line_speaks_both_languages() {
        let en = Strings::new(Lang::En);
        let ru = Strings::new(Lang::Ru);
        assert_eq!(Status::Ready.text(&en), "Ready to check");
        assert_eq!(Status::Ready.text(&ru), "Готов к проверке");
        assert_eq!(Status::Checking { done: 2, total: 6 }.text(&en), "Checking 2/6");
        assert_eq!(Status::Checking { done: 2, total: 6 }.text(&ru), "Проверка 2/6");
        assert_eq!(Status::Done { total: 6 }.text(&en), "Checked: 6");
        assert_eq!(
            Status::Message(Message::NothingSelected).text(&ru),
            "Не выбрано ни одной цели"
        );
        assert_eq!(
            Status::Message(Message::BadSocks5).text(&en),
            "The SOCKS5 address is not valid"
        );
    }

    #[test]
    fn an_export_name_carries_the_moment_and_the_extension() {
        let report = RunReport {
            tool: "oko",
            version: "0.1.0",
            generated_at: "2026-11-14T21:52:03Z".to_string(),
            targets: Vec::new(),
            control: crate::report::ControlReport {
                target: target::control(),
                tcp: Vec::new(),
            },
            tunnel: None,
        };
        assert_eq!(export_name(&report, Export::Text), "oko-2026-11-14T21-52-03Z.txt");
        assert_eq!(export_name(&report, Export::Json), "oko-2026-11-14T21-52-03Z.json");
        assert!(export_contents(&report, Export::Text).unwrap().contains("oko 0.1.0"));
        assert!(
            export_contents(&report, Export::Json)
                .unwrap()
                .contains("\"tool\": \"oko\"")
        );
    }
}
