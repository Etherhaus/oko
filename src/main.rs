//! Oko — a detector for DNS, DPI and IP-level blocking of online services.
//!
//! Oko measures and classifies. It does not circumvent anything: no ClientHello
//! fragmentation, no TCP segmentation, no proxy tricks. Every probe opens an
//! ordinary outbound socket, observes what comes back, and reports it.

mod format;
mod json;
mod probes;
mod report;
mod target;
mod verdict;

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use probes::{dns, http, tcp, tls};
use report::{ControlReport, RunReport, TargetReport};
use target::{Role, Target};
use verdict::VerdictInput;

/// How long one DNS exchange may take.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one TCP connect may take.
const TCP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one TLS handshake may take.
const TLS_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one HTTP exchange may take.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
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
                  opens, whether a TLS handshake with the real name reaches the server, and whether a \
                  plain HTTP request with the real Host header survives.\n\n\
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
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Probe(args) => probe_command(args).await,
    }
}

async fn probe_command(args: ProbeArgs) -> ExitCode {
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
    let control_report = probe_control(&control).await;
    let control_alive = control_report.tcp.iter().any(|probe| probe.outcome.is_connected());

    // DNS for every target before anything else: the verdict engine needs the
    // whole run's system answers to spot a sinkhole pool handed to unrelated
    // services.
    let mut dns_results = Vec::with_capacity(targets.len());
    for target in &targets {
        dns_results.push(dns::probe(&target.domain, DNS_TIMEOUT).await);
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
        let tcp = tcp::probe_all(&target.domain, &ips, target.port, source, TCP_TIMEOUT).await;

        // The TLS and HTTP probes need one address: the one the TCP probe
        // reached, IPv4 first.
        let address = verdict::pick_address(&tcp);
        let tls = match address {
            Some(ip) => Some(tls::probe(&target.domain, ip, target.port, &control.domain, TLS_TIMEOUT).await),
            None => None,
        };
        let http = match address {
            Some(ip) => Some(http::probe(&target.domain, ip, HTTP_PORT, &control.domain, HTTP_TIMEOUT).await),
            None => None,
        };

        let verdict = verdict::classify(&VerdictInput {
            target,
            dns: &dns,
            tcp: &tcp,
            tls: tls.as_ref(),
            http: http.as_ref(),
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
        });
    }

    let report = RunReport {
        tool: "oko",
        version: env!("CARGO_PKG_VERSION"),
        generated_at: report::now_utc(),
        targets: reports,
        control: control_report,
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
async fn probe_control(target: &Target) -> ControlReport {
    let system = dns::system_lookup(&target.domain).await;
    let (ips, source) = dns::addresses_for_tcp(&system, &target.known_ips);
    let tcp = tcp::probe_all(&target.domain, &ips, target.port, source, TCP_TIMEOUT).await;
    ControlReport {
        target: target.clone(),
        tcp,
    }
}
