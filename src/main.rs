//! Oko — a detector for DNS, DPI and IP-level blocking of online services.
//!
//! Oko measures and classifies. It does not circumvent anything: no ClientHello
//! fragmentation, no TCP segmentation, no proxy tricks. Every probe opens an
//! ordinary outbound socket, observes what comes back, and reports it.
//!
//! Without a subcommand the binary opens the window; `oko probe` stays for
//! debugging and CI.

mod format;
mod gui;
mod i18n;
mod json;
mod probes;
mod report;
mod route;
mod run;
mod target;
mod verdict;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use run::{DEFAULT_TIMEOUT_SECS, Options};
use target::Role;

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
                  Oko measures and classifies. It does not circumvent blocking.\n\n\
                  Run without a subcommand to open the window."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Probe(args)) => {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(err) => {
                    eprintln!("oko: cannot start the async runtime: {err}");
                    return ExitCode::FAILURE;
                }
            };
            runtime.block_on(probe_command(args))
        }
        None => gui::run(),
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

    let options = Options {
        timeout: Duration::from_secs(args.timeout),
        socks5: args.socks5,
    };
    let report = run::run(targets, options, |_| {}).await;

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
