//! One probe run: the control, DNS for every target, the probes per target,
//! and the tunnel comparison.
//!
//! The CLI and the GUI both call [`run`]. The GUI passes a progress callback so
//! the table fills in while the run goes; the CLI passes one that does nothing.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::probes::dns::IpSource;
use crate::probes::payload::PayloadProbe;
use crate::probes::tls::TlsOutcome;
use crate::probes::{dns, http, payload, quic, tcp, tls};
use crate::report::{self, ControlReport, RunReport, TargetReport, TunnelRun};
use crate::route::Route;
use crate::target::{self, Target};
use crate::verdict::{self, Diff, Verdict, VerdictInput};

/// The default for the probe timeout: how long one probe may take.
pub const DEFAULT_TIMEOUT_SECS: u64 = 5;
/// The HTTP probe speaks plain HTTP, which lives on 80 whatever port the
/// service uses for TLS.
pub const HTTP_PORT: u16 = 80;

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

/// Probe every target, then repeat the probes through the proxy when one was
/// asked for, and compare the two paths.
pub async fn run(targets: Vec<Target>, options: Options, mut progress: impl FnMut(Progress)) -> RunReport {
    let route = Route::Direct;

    // The control runs first. If it cannot be reached, everything after it is
    // unreadable, and the report says so instead of blaming the services.
    let control = target::control();
    let control_report = probe_control(&control, route, options.timeout).await;
    let control_alive = control_report.tcp.iter().any(|probe| probe.outcome.is_connected());
    progress(Progress::Control(control_report.clone()));

    // DNS for every target before anything else: the verdict engine needs the
    // whole run's system answers to spot a sinkhole pool handed to unrelated
    // services.
    let mut dns_results = Vec::with_capacity(targets.len());
    for target in &targets {
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
        reports.push(report);
    }

    // The tunnel run repeats the probes through the proxy and the diff says
    // what the two paths mean together.
    let tunnel = match options.socks5 {
        Some(proxy) => Some(run_tunnel(&targets, &reports, &control, proxy, options.timeout, &mut progress).await),
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
