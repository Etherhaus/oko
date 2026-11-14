//! One probe run: the control, DNS for every target, the probes per target,
//! and the tunnel comparison.
//!
//! The CLI and the GUI both call [`run`]. The GUI passes a progress callback so
//! the table fills in while the run goes; the CLI passes one that does nothing.
//!
//! The whole run sits under a watchdog: a probe that never returns would
//! otherwise leave the window waiting forever. When the budget runs out the
//! run ends with the reports it already has and says where it stopped.

use std::cell::RefCell;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use crate::probes::dns::IpSource;
use crate::probes::payload::PayloadProbe;
use crate::probes::tls::TlsOutcome;
use crate::probes::{dns, http, payload, quic, tcp, tls};
use crate::report::{self, ControlReport, Interrupted, RunReport, TargetReport, TunnelRun};
use crate::route::Route;
use crate::target::{self, Target};
use crate::verdict::{self, Diff, Verdict, VerdictInput};

/// The default for the probe timeout: how long one probe may take.
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;
/// The HTTP probe speaks plain HTTP, which lives on 80 whatever port the
/// service uses for TLS.
pub const HTTP_PORT: u16 = 80;

/// How many probe steps one target may spend a timeout on: the six probe kinds
/// plus a margin for the addresses a target can resolve to. The watchdog is a
/// net for a hang, not a performance limit, so the number is deliberately
/// generous.
const PROBES_PER_TARGET: u64 = 8;
/// The slack the watchdog adds on top of the sum.
const WATCHDOG_SLACK: Duration = Duration::from_secs(30);

/// What one run needs.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// The budget for one probe, including the connection and the handshake.
    pub timeout: Duration,
    /// The SOCKS5 proxy to repeat the probes through, when one was asked for.
    pub socks5: Option<SocketAddr>,
}

/// What the run reports while it goes.
///
/// The reports are owned: the GUI hands them to the UI thread, which outlives
/// the borrow the run holds.
#[derive(Debug, Clone)]
pub enum Progress {
    /// The control target answered or did not.
    Control(ControlReport),
    /// The probes for one target are about to start.
    Started { index: usize },
    /// One target's direct probes are done.
    Target { index: usize, report: TargetReport },
    /// One target's probes through the tunnel are done.
    Tunnel { index: usize, report: TargetReport },
    /// The comparison for one target, after the tunnel run.
    Diff { index: usize, diff: Diff, verdict: Verdict },
}

/// How long a whole run may take before the watchdog ends it.
///
/// The budget is the sum over the targets of the probe steps times the probe
/// timeout, plus a fixed slack. A tunnel run repeats the probes, so it doubles
/// the per-target part.
pub fn watchdog_budget(targets: &[Target], options: Options) -> Duration {
    let timeout = options.timeout.as_secs().max(1);
    let mut seconds = PROBES_PER_TARGET * timeout * targets.len() as u64;
    if options.socks5.is_some() {
        seconds *= 2;
    }
    Duration::from_secs(seconds) + WATCHDOG_SLACK
}

/// What the run has produced so far, so a watchdog trip can still report it.
#[derive(Debug, Default)]
struct Partial {
    control: Option<ControlReport>,
    reports: Vec<TargetReport>,
    /// The target whose probes were running when the budget ran out.
    current: Option<String>,
    tunnel: Option<TunnelRun>,
}

impl Partial {
    /// The report of a run the watchdog ended: everything that finished, plus
    /// the name of the target that did not.
    fn interrupted(&self, budget: Duration) -> RunReport {
        RunReport {
            tool: "oko",
            version: env!("CARGO_PKG_VERSION"),
            generated_at: report::now_utc(),
            targets: self.reports.clone(),
            control: self.control.clone().unwrap_or_else(|| ControlReport {
                target: target::control(),
                tcp: Vec::new(),
            }),
            tunnel: self.tunnel.clone(),
            interrupted: Some(Interrupted {
                target: self.current.clone().unwrap_or_default(),
                budget_secs: budget.as_secs(),
            }),
        }
    }
}

/// Probe every target, then repeat the probes through the proxy when one was
/// asked for, and compare the two paths.
pub async fn run(targets: Vec<Target>, options: Options, mut progress: impl FnMut(Progress)) -> RunReport {
    let budget = watchdog_budget(&targets, options);
    let state = Rc::new(RefCell::new(Partial::default()));
    let inner = run_inner(&targets, options, &mut progress, &state);
    guarded(budget, inner, &state).await
}

/// Run the probes under the watchdog. A future that never finishes ends the
/// run with what the state already holds.
async fn guarded<F>(budget: Duration, inner: F, state: &RefCell<Partial>) -> RunReport
where
    F: Future<Output = RunReport>,
{
    match tokio::time::timeout(budget, inner).await {
        Ok(report) => report,
        Err(_) => state.borrow().interrupted(budget),
    }
}

async fn run_inner(
    targets: &[Target],
    options: Options,
    progress: &mut impl FnMut(Progress),
    state: &RefCell<Partial>,
) -> RunReport {
    let route = Route::Direct;

    // The control runs first. If it cannot be reached, everything after it is
    // unreadable, and the report says so instead of blaming the services.
    let control = target::control();
    let control_report = probe_control(&control, route, options.timeout).await;
    let control_alive = control_report.tcp.iter().any(|probe| probe.outcome.is_connected());
    state.borrow_mut().control = Some(control_report.clone());
    progress(Progress::Control(control_report.clone()));

    // DNS for every target before anything else: the verdict engine needs the
    // whole run's system answers to spot a sinkhole pool handed to unrelated
    // services.
    let mut dns_results = Vec::with_capacity(targets.len());
    for target in targets {
        dns_results.push(dns::probe(&target.domain, options.timeout).await);
    }
    let system_pool: Vec<(String, Vec<IpAddr>)> = dns_results
        .iter()
        .map(|dns| (dns.domain.clone(), dns.system.ips().to_vec()))
        .collect();

    // Targets are probed one after another on purpose: concurrent probes share
    // the link and would make the timings meaningless.
    let mut reports = Vec::with_capacity(targets.len());
    for (index, (target, dns)) in targets.iter().zip(dns_results).enumerate() {
        state.borrow_mut().current = Some(target.domain.clone());
        progress(Progress::Started { index });
        let report = probe_target(
            target,
            dns,
            &system_pool,
            &control,
            control_alive,
            route,
            options.timeout,
        )
        .await;
        progress(Progress::Target {
            index,
            report: report.clone(),
        });
        state.borrow_mut().reports.push(report.clone());
        reports.push(report);
    }

    // The tunnel run repeats the probes through the proxy and the diff says
    // what the two paths mean together.
    let tunnel = match options.socks5 {
        Some(proxy) => {
            let tunnel = run_tunnel(targets, &reports, &control, proxy, options.timeout, progress).await;
            state.borrow_mut().tunnel = Some(tunnel.clone());
            Some(tunnel)
        }
        None => None,
    };
    if let Some(tunnel) = &tunnel {
        for (index, (direct, through)) in reports.iter_mut().zip(&tunnel.targets).enumerate() {
            let diff = verdict::diff(&direct.verdict, &through.verdict);
            verdict::apply_diff(&mut direct.verdict, &diff);
            progress(Progress::Diff {
                index,
                diff: diff.clone(),
                verdict: direct.verdict.clone(),
            });
            direct.diff = Some(diff);
        }
    }

    RunReport {
        tool: "oko",
        version: env!("CARGO_PKG_VERSION"),
        generated_at: report::now_utc(),
        targets: reports,
        control: control_report,
        tunnel,
        interrupted: None,
    }
}

/// The probes for one target on one route.
async fn probe_target(
    target: &Target,
    dns: dns::DnsProbe,
    system_pool: &[(String, Vec<IpAddr>)],
    control: &Target,
    control_alive: bool,
    route: Route,
    timeout: Duration,
) -> TargetReport {
    let (ips, source) = dns.addresses_for_tcp(&target.known_ips);
    let tcp = tcp::probe_all(&target.domain, &ips, target.port, source, timeout, route).await;

    // The later probes need one address: the one the TCP probe reached, IPv4
    // first.
    let address = verdict::pick_address(&tcp);
    let tls = match address {
        Some(ip) => Some(tls::probe(&target.domain, ip, target.port, &control.domain, timeout, route).await),
        None => None,
    };
    let http = match address {
        Some(ip) => Some(http::probe(&target.domain, ip, HTTP_PORT, &control.domain, timeout, route).await),
        None => None,
    };
    // The payload probe needs a completed handshake to speak over. When the
    // handshake did not complete, the report says so instead of waiting out
    // another timeout.
    let payload = match (address, &tls) {
        (Some(ip), Some(tls)) if matches!(tls.real.outcome, TlsOutcome::Ok { .. }) => {
            Some(payload::probe(&target.domain, ip, target.port, timeout, route).await)
        }
        (Some(ip), _) => Some(PayloadProbe::not_attempted(
            &target.domain,
            ip,
            target.port,
            "the TLS handshake did not complete",
        )),
        (None, _) => None,
    };
    let quic = match address {
        Some(ip) => Some(quic::probe(&target.domain, ip, target.port, timeout).await),
        None => None,
    };

    let verdict = verdict::classify(&VerdictInput {
        target,
        dns: &dns,
        tcp: &tcp,
        tls: tls.as_ref(),
        http: http.as_ref(),
        payload: payload.as_ref(),
        control_alive,
        system_pool,
    });

    TargetReport {
        target: target.clone(),
        verdict,
        dns,
        tcp,
        tls,
        http,
        payload,
        quic,
        diff: None,
    }
}

/// The control only has to prove the network is alive, so it skips the DoH
/// references and asks the system resolver alone.
async fn probe_control(target: &Target, route: Route, timeout: Duration) -> ControlReport {
    let system = dns::system_lookup(&target.domain).await;
    let (ips, source) = dns::addresses_for_tcp(&system, &target.known_ips);
    let tcp = tcp::probe_all(&target.domain, &ips, target.port, source, timeout, route).await;
    ControlReport {
        target: target.clone(),
        tcp,
    }
}

/// Repeat the probes through the proxy, on the addresses the direct run
/// resolved: the two runs then differ in the path and in nothing else.
async fn run_tunnel(
    targets: &[Target],
    direct: &[TargetReport],
    control: &Target,
    proxy: SocketAddr,
    timeout: Duration,
    progress: &mut impl FnMut(Progress),
) -> TunnelRun {
    let route = Route::Socks5(proxy);
    let control_report = probe_control(control, route, timeout).await;
    let control_alive = control_report.tcp.iter().any(|probe| probe.outcome.is_connected());

    let mut reports = Vec::with_capacity(targets.len());
    for (index, (target, direct_report)) in targets.iter().zip(direct).enumerate() {
        let Some(ip) = verdict::pick_address(&direct_report.tcp) else {
            reports.push(TargetReport {
                target: target.clone(),
                verdict: verdict::unknown("the direct run found no address to try"),
                dns: direct_report.dns.clone(),
                tcp: Vec::new(),
                tls: None,
                http: None,
                payload: None,
                quic: None,
                diff: None,
            });
            continue;
        };

        let source = direct_report
            .tcp
            .first()
            .map(|probe| probe.source)
            .unwrap_or(IpSource::Resolved);
        let tcp = tcp::probe_all(&target.domain, &[ip], target.port, source, timeout, route).await;
        let tls = Some(tls::probe(&target.domain, ip, target.port, &control.domain, timeout, route).await);
        let http = Some(http::probe(&target.domain, ip, HTTP_PORT, &control.domain, timeout, route).await);
        let payload = match &tls {
            Some(tls) if matches!(tls.real.outcome, TlsOutcome::Ok { .. }) => {
                Some(payload::probe(&target.domain, ip, target.port, timeout, route).await)
            }
            _ => Some(PayloadProbe::not_attempted(
                &target.domain,
                ip,
                target.port,
                "the TLS handshake did not complete",
            )),
        };

        let verdict = verdict::classify(&VerdictInput {
            target,
            dns: &direct_report.dns,
            tcp: &tcp,
            tls: tls.as_ref(),
            http: http.as_ref(),
            payload: payload.as_ref(),
            control_alive,
            system_pool: &[],
        });

        let report = TargetReport {
            target: target.clone(),
            verdict,
            dns: direct_report.dns.clone(),
            tcp,
            tls,
            http,
            payload,
            quic: None,
            diff: None,
        };
        progress(Progress::Tunnel {
            index,
            report: report.clone(),
        });
        reports.push(report);
    }

    TunnelRun {
        proxy,
        control: control_report,
        targets: reports,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::Category;

    fn target(domain: &str) -> Target {
        Target {
            domain: domain.to_string(),
            port: 443,
            role: target::Role::Service,
            known_ips: Vec::new(),
            category: Category::Custom,
            custom: true,
        }
    }

    fn options(timeout: u64, socks5: Option<SocketAddr>) -> Options {
        Options {
            timeout: Duration::from_secs(timeout),
            socks5,
        }
    }

    #[test]
    fn the_budget_grows_with_the_targets_and_the_timeout() {
        let one = watchdog_budget(&[target("a.example")], options(5, None));
        let two = watchdog_budget(&[target("a.example"), target("b.example")], options(5, None));
        let slow = watchdog_budget(&[target("a.example")], options(10, None));
        assert_eq!(one, Duration::from_secs(PROBES_PER_TARGET * 5) + WATCHDOG_SLACK);
        assert_eq!(two, Duration::from_secs(PROBES_PER_TARGET * 5 * 2) + WATCHDOG_SLACK);
        assert_eq!(slow, Duration::from_secs(PROBES_PER_TARGET * 10) + WATCHDOG_SLACK);
    }

    #[test]
    fn a_tunnel_run_doubles_the_budget() {
        let proxy: SocketAddr = "127.0.0.1:1080".parse().expect("a literal address");
        let direct = watchdog_budget(&[target("a.example")], options(5, None));
        let tunnel = watchdog_budget(&[target("a.example")], options(5, Some(proxy)));
        assert_eq!(tunnel, direct * 2 - WATCHDOG_SLACK);
    }

    #[test]
    fn a_hung_probe_ends_the_run_with_a_partial_report() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime");
        let state = RefCell::new(Partial::default());
        state.borrow_mut().current = Some("youtube.com".to_string());

        let report = runtime.block_on(async {
            let budget = Duration::from_millis(20);
            guarded(budget, std::future::pending::<RunReport>(), &state).await
        });

        assert!(report.targets.is_empty(), "nothing finished, nothing reported");
        let interrupted = report.interrupted.expect("the watchdog says so");
        assert_eq!(interrupted.target, "youtube.com");
        assert_eq!(interrupted.budget_secs, 0, "20 ms rounds down to zero seconds");
    }

    #[test]
    fn a_run_that_finishes_in_time_is_not_marked_interrupted() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime");
        let state = RefCell::new(Partial::default());
        let report = runtime.block_on(async {
            let finished = RunReport {
                tool: "oko",
                version: "test",
                generated_at: "2026-11-14T00:00:00Z".to_string(),
                targets: Vec::new(),
                control: ControlReport {
                    target: target::control(),
                    tcp: Vec::new(),
                },
                tunnel: None,
                interrupted: None,
            };
            guarded(Duration::from_secs(5), async { finished }, &state).await
        });
        assert!(report.interrupted.is_none());
    }
}
