//! Oko — a detector for DNS, DPI and IP-level blocking of online services.
//!
//! Oko measures and classifies. It does not circumvent anything: no ClientHello
//! fragmentation, no TCP segmentation, no proxy tricks. Every probe opens an
//! ordinary outbound socket, observes what comes back, and reports it.

mod format;
mod json;
mod probes;
mod report;
mod route;
mod target;
mod verdict;

use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use probes::dns::IpSource;
use probes::payload::PayloadProbe;
use probes::tls::TlsOutcome;
use probes::{dns, http, payload, quic, tcp, tls};
use report::{ControlReport, RunReport, TargetReport, TunnelRun};
use route::Route;
use target::{Role, Target};
use verdict::VerdictInput;

/// The default for `--timeout`: how long one probe may take.
const DEFAULT_TIMEOUT_SECS: u64 = 5;
/// The HTTP probe speaks plain HTTP, which lives on 80 whatever port the
/// service uses for TLS.
const HTTP_PORT: u16 = 80;

#[derive(Debug, Parser)]
#[command(
    name = "oko",
    version,
    about = "Detect and classify DNS, DPI and IP-level blocking of online services",
    long_about = "Oko probes a service from your network and reports what it observed: what the system \
                  resolver answered, what public DoH references answered, whether a TCP connection \
                  opens, whether a TLS handshake with the real name reaches the server, whether a \
                  plain HTTP request with the real Host header survives, how much of the body arrives \
                  before the connection ends, and whether the server answers QUIC on UDP 443.\n\n\
                  With --socks5 the same probes run through a SOCKS5 proxy and the report compares the \
                  two paths: a service that fails directly and works through the tunnel is blocked on \
                  the path, one that fails on both is refusing this network itself.\n\n\
                  Oko measures and classifies. It does not circumvent blocking."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Probe one domain, or every service in the built-in list.
    Probe(ProbeArgs),
}

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("what")
        .required(true)
        .multiple(false)
        .args(["domain", "all"])
))]
struct ProbeArgs {
    /// Domain to probe, for example github.com.
    domain: Option<String>,
    /// Probe every service in the built-in list.
    #[arg(long)]
    all: bool,
    /// Print the report as JSON instead of text.
    #[arg(long)]
    json: bool,
    /// How long one probe may take, in seconds.
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = DEFAULT_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..=120)
    )]
    timeout: u64,
    /// Run the same probes through a SOCKS5 proxy and compare the two paths.
    #[arg(long, value_name = "ADDR")]
    socks5: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Probe(args) => probe_command(args).await,
    }
}

async fn probe_command(args: ProbeArgs) -> ExitCode {
    let timeout = Duration::from_secs(args.timeout);
    let route = Route::Direct;

    let targets = if args.all {
        target::builtin()
            .into_iter()
            .filter(|target| target.role == Role::Service)
            .collect()
    } else {
        // clap's argument group guarantees exactly one of the two.
        let domain = args.domain.expect("clap requires a domain or --all");
        if domain.trim().is_empty() {
            eprintln!("oko: the domain is empty");
            return ExitCode::from(2);
        }
        vec![target::lookup(&domain).unwrap_or_else(|| target::ad_hoc(&domain))]
    };

    // The control runs first. If it cannot be reached, everything after it is
    // unreadable, and the report says so instead of blaming the services.
    let control = target::control();
    let control_report = probe_control(&control, route, timeout).await;
    let control_alive = control_report.tcp.iter().any(|probe| probe.outcome.is_connected());

    // DNS for every target before anything else: the verdict engine needs the
    // whole run's system answers to spot a sinkhole pool handed to unrelated
    // services.
    let mut dns_results = Vec::with_capacity(targets.len());
    for target in &targets {
        dns_results.push(dns::probe(&target.domain, timeout).await);
    }
    let system_pool: Vec<(String, Vec<IpAddr>)> = dns_results
        .iter()
        .map(|dns| (dns.domain.clone(), dns.system.ips().to_vec()))
        .collect();

    // Targets are probed one after another on purpose: concurrent probes share
    // the link and would make the timings meaningless.
    let mut reports = Vec::with_capacity(targets.len());
    for (target, dns) in targets.iter().zip(dns_results) {
        let (ips, source) = dns.addresses_for_tcp(&target.known_ips);
        let tcp = tcp::probe_all(&target.domain, &ips, target.port, source, timeout, route).await;

        // The later probes need one address: the one the TCP probe reached,
        // IPv4 first.
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
            system_pool: &system_pool,
        });

        reports.push(TargetReport {
            target: target.clone(),
            verdict,
            dns,
            tcp,
            tls,
            http,
            payload,
            quic,
            diff: None,
        });
    }

    // The tunnel run repeats the probes through the proxy and the diff says
    // what the two paths mean together.
    let tunnel = match args.socks5 {
        Some(proxy) => Some(run_tunnel(&targets, &reports, &control, proxy, timeout).await),
        None => None,
    };
    if let Some(tunnel) = &tunnel {
        for (direct, through) in reports.iter_mut().zip(&tunnel.targets) {
            let diff = verdict::diff(&direct.verdict, &through.verdict);
            verdict::apply_diff(&mut direct.verdict, &diff);
            direct.diff = Some(diff);
        }
    }

    let report = RunReport {
        tool: "oko",
        version: env!("CARGO_PKG_VERSION"),
        generated_at: report::now_utc(),
        targets: reports,
        control: control_report,
        tunnel,
    };

    if args.json {
        match report::render_json(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("oko: cannot write the JSON report: {err}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print!("{}", report::render(&report));
    }
    ExitCode::SUCCESS
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
) -> TunnelRun {
    let route = Route::Socks5(proxy);
    let control_report = probe_control(control, route, timeout).await;
    let control_alive = control_report.tcp.iter().any(|probe| probe.outcome.is_connected());

    let mut reports = Vec::with_capacity(targets.len());
    for (target, direct_report) in targets.iter().zip(direct) {
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

        reports.push(TargetReport {
            target: target.clone(),
            verdict,
            dns: direct_report.dns.clone(),
            tcp,
            tls,
            http,
            payload,
            quic: None,
            diff: None,
        });
    }

    TunnelRun {
        proxy,
        control: control_report,
        targets: reports,
    }
}
