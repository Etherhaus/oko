//! Oko — a detector for DNS, DPI and IP-level blocking of online services.
//!
//! Oko measures and classifies. It does not circumvent anything: no ClientHello
//! fragmentation, no TCP segmentation, no proxy tricks. Every probe opens an
//! ordinary outbound socket, observes what comes back, and reports it.

mod probes;
mod report;
mod target;

use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use probes::{dns, tcp};
use report::{ControlReport, RunReport, TargetReport};
use target::{Role, Target};

/// How long one DNS exchange may take.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one TCP connect may take.
const TCP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    name = "oko",
    version,
    about = "Detect and classify DNS, DPI and IP-level blocking of online services",
    long_about = "Oko probes a service from your network and reports what it observed: what the system \
                  resolver answered, what public DoH references answered, and whether a TCP connection \
                  to the service opens.\n\n\
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

    // Targets are probed one after another on purpose: concurrent probes share
    // the link and would make the timings meaningless.
    let mut reports = Vec::with_capacity(targets.len());
    for target in targets {
        reports.push(probe_target(&target).await);
    }

    let report = RunReport {
        generated_at: report::now_utc(),
        targets: reports,
        control: control_report,
    };
    print!("{}", report::render(&report));
    ExitCode::SUCCESS
}

async fn probe_target(target: &Target) -> TargetReport {
    let dns = dns::probe(&target.domain, DNS_TIMEOUT).await;
    let (ips, source) = dns.addresses_for_tcp(&target.known_ips);
    let tcp = tcp::probe_all(&target.domain, &ips, target.port, source, TCP_TIMEOUT).await;
    TargetReport {
        target: target.clone(),
        dns,
        tcp,
    }
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
