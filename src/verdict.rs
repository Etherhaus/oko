//! The verdict engine.
//!
//! Everything here is a pure function of the probe results: no sockets, no
//! clock, no environment. That is what makes the rules testable, and the rules
//! are the part of this tool that has to be right.
//!
//! The order of the rules matters. A spoofed DNS answer makes every later probe
//! meaningless, so DNS is judged first. A dead control target means the network
//! is the problem, not the service, so nothing is judged at all.

use std::net::IpAddr;

use serde::Serialize;

use crate::format;
use crate::probes::dns::{Comparison, DnsProbe, IpSource};
use crate::probes::http::HttpProbe;
use crate::probes::tcp::{TcpOutcome, TcpProbe};
use crate::probes::tls::{TlsOutcome, TlsProbe};
use crate::target::Target;

/// What the probes add up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictKind {
    /// Every probe reached the service.
    Ok,
    /// The system resolver's answer is not the service's answer.
    DnsSpoof,
    /// The handshake died on the real name and the same address answered a
    /// known-good one.
    DpiSni,
    /// No IPv4 address of the service accepted a connection while the control
    /// target did.
    IpBlock,
    /// The request died on the real `Host` header and the same address answered
    /// a known-good one.
    HostFilter,
    /// The evidence does not add up to any of the above. Always carries a
    /// reason.
    Unknown,
}

impl VerdictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            VerdictKind::Ok => "ok",
            VerdictKind::DnsSpoof => "dns_spoof",
            VerdictKind::DpiSni => "dpi_sni",
            VerdictKind::IpBlock => "ip_block",
            VerdictKind::HostFilter => "host_filter",
            VerdictKind::Unknown => "unknown",
        }
    }

    /// The level a verdict of this kind carries unless something raises it.
    pub fn default_level(self) -> Level {
        match self {
            VerdictKind::Ok => Level::Ok,
            VerdictKind::DnsSpoof | VerdictKind::DpiSni | VerdictKind::IpBlock | VerdictKind::HostFilter => Level::Bad,
            VerdictKind::Unknown => Level::Undetermined,
        }
    }
}

/// How alarming a verdict is, in the four steps NetCheck uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Everything works.
    Ok,
    /// The service works, but something about it is not right.
    Warn,
    /// The service is blocked.
    Bad,
    /// The probes could not tell.
    Undetermined,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Bad => "bad",
            Level::Undetermined => "undetermined",
        }
    }
}

/// The conclusion for one target, with the facts it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub kind: VerdictKind,
    pub level: Level,
    /// One sentence a reader can act on.
    pub reason: String,
    /// Every probe result the verdict was built from, in plain words.
    pub facts: Vec<String>,
    /// Where the address the TLS and HTTP probes used came from. `Builtin` means
    /// the system resolver returned nothing and the recorded addresses stood in,
    /// which the report has to say out loud.
    pub address_source: Option<IpSource>,
}

impl Verdict {
    /// True when the verdict rests on addresses recorded in the source rather
    /// than on a fresh resolve.
    pub fn used_recorded_addresses(&self) -> bool {
        self.address_source == Some(IpSource::Builtin)
    }
}

/// Everything the engine is allowed to look at.
pub struct VerdictInput<'a> {
    pub target: &'a Target,
    pub dns: &'a DnsProbe,
    pub tcp: &'a [TcpProbe],
    pub tls: Option<&'a TlsProbe>,
    pub http: Option<&'a HttpProbe>,
    /// Whether the control target answered at all.
    pub control_alive: bool,
    /// The system resolver's answer for every domain in the run, so a sinkhole
    /// pool handed to unrelated services can be spotted.
    pub system_pool: &'a [(String, Vec<IpAddr>)],
}

/// Turn probe results into a verdict.
pub fn classify(input: &VerdictInput<'_>) -> Verdict {
    let facts = facts(input);
    let address_source = input.tcp.first().map(|probe| probe.source);
    let make = |kind: VerdictKind, level: Level, reason: String| Verdict {
        kind,
        level,
        reason,
        facts: facts.clone(),
        address_source,
    };

    // 1. A dead control means the network is the problem, not the service.
    if !input.control_alive {
        return make(
            VerdictKind::Unknown,
            Level::Undetermined,
            "the control target did not answer, so no result here can be read as a block".to_string(),
        );
    }

    // 2. DNS first: a spoofed answer makes every later probe meaningless.
    if let Some(reason) = dns_spoof(input) {
        return make(VerdictKind::DnsSpoof, Level::Bad, reason);
    }

    // 3. TCP, on the IPv4 path only.
    if !input.tcp.iter().any(|probe| probe.outcome.is_connected()) {
        if let Some(reason) = ip_block(input) {
            return make(VerdictKind::IpBlock, Level::Bad, reason);
        }
        return make(VerdictKind::Unknown, Level::Undetermined, no_connection_reason(input));
    }

    // 4. TLS: did the server answer the real name?
    let Some(tls) = input.tls else {
        return make(
            VerdictKind::Unknown,
            Level::Undetermined,
            "a TCP connection opened but the TLS probe did not run".to_string(),
        );
    };
    match &tls.real.outcome {
        TlsOutcome::Ok { .. } | TlsOutcome::ServerResponded { .. } => {}
        TlsOutcome::TlsAlert { code, .. } => {
            return make(
                VerdictKind::Unknown,
                Level::Undetermined,
                format!("the server answered the handshake with TLS alert {code}"),
            );
        }
        TlsOutcome::RstAfterClientHello { .. } | TlsOutcome::Timeout { .. } => {
            if tls.control_reached_server() {
                return make(
                    VerdictKind::DpiSni,
                    Level::Bad,
                    "the handshake with the real name was killed, and the same address answered a known-good name"
                        .to_string(),
                );
            }
            return make(
                VerdictKind::Unknown,
                Level::Undetermined,
                "the handshake was killed with the real name and with a known-good name, so the name is not what the path objects to"
                    .to_string(),
            );
        }
        TlsOutcome::Failed { reason, .. } => {
            return make(
                VerdictKind::Unknown,
                Level::Undetermined,
                format!("the TLS probe could not run: {reason}"),
            );
        }
    }

    // 5. HTTP: did the request survive the real Host header?
    let Some(http) = input.http else {
        return make(
            VerdictKind::Unknown,
            Level::Undetermined,
            "TLS reached the server but the HTTP probe did not run".to_string(),
        );
    };
    if !http.real_responded() {
        if http.control_responded() {
            return make(
                VerdictKind::HostFilter,
                Level::Bad,
                "the request with the real Host header was killed, and the same address answered a known-good Host"
                    .to_string(),
            );
        }
        return make(
            VerdictKind::Unknown,
            Level::Undetermined,
            "the request failed with the real Host and with a known-good Host, so the Host header is not what the path objects to"
                .to_string(),
        );
    }

    // 6. Everything passed.
    match tls_caveat(tls) {
        Some(caveat) => make(
            VerdictKind::Ok,
            Level::Warn,
            format!("every probe reached the service, but {caveat}"),
        ),
        None => make(
            VerdictKind::Ok,
            Level::Ok,
            "every probe reached the service".to_string(),
        ),
    }
}

/// The DNS verdict, only on signals that mean something. A difference between
/// the system resolver and a reference is not one of them: CDN geo-DNS hands out
/// different addresses to different resolvers all day.
fn dns_spoof(input: &VerdictInput<'_>) -> Option<String> {
    let system = input.dns.system.ips();
    let doh = input.dns.doh_ips();

    // The references answered and the system resolver did not.
    if system.is_empty() && !doh.is_empty() {
        return Some("the DoH references resolved the name and the system resolver did not".to_string());
    }
    if system.is_empty() || doh.is_empty() {
        return None;
    }

    // A pool that no reference agrees with, handed to two unrelated services.
    // A shared CDN address would be in the references too, so it does not fire.
    if system.iter().any(|ip| doh.contains(ip)) {
        return None;
    }
    let (other, _) = input
        .system_pool
        .iter()
        .find(|(domain, ips)| domain != &input.target.domain && !ips.is_empty() && same_set(ips, system))?;
    Some(format!(
        "the system resolver returned the same addresses for {} and {other}, and no DoH reference returned any of them",
        input.target.domain
    ))
}

/// An IP block is only ever concluded on the IPv4 path. A host without an IPv6
/// route reports `NoRoute` for every IPv6 address, and that says nothing about
/// the service.
fn ip_block(input: &VerdictInput<'_>) -> Option<String> {
    let ipv4: Vec<&TcpProbe> = input.tcp.iter().filter(|probe| probe.ip.is_ipv4()).collect();
    if ipv4.is_empty() {
        return None;
    }
    if ipv4
        .iter()
        .all(|probe| matches!(probe.outcome, TcpOutcome::NoRoute { .. }))
    {
        return None;
    }
    Some(format!(
        "none of the {} accepted a TCP connection while the control target did",
        format::addresses(ipv4.len())
    ))
}

fn no_connection_reason(input: &VerdictInput<'_>) -> String {
    let ipv4 = input.tcp.iter().filter(|probe| probe.ip.is_ipv4()).count();
    if ipv4 == 0 {
        return "the service has no IPv4 address and no other address accepted a connection".to_string();
    }
    "the operating system has no route to any IPv4 address of this service".to_string()
}

/// A service that works but whose certificate does not cover its name is worth
/// a warning, not a block: the handshake did reach the server.
fn tls_caveat(tls: &TlsProbe) -> Option<&'static str> {
    match &tls.real.outcome {
        TlsOutcome::Ok { .. } => None,
        TlsOutcome::ServerResponded {
            cert_mismatch: true, ..
        } => Some("the certificate does not cover the service name"),
        TlsOutcome::ServerResponded { .. } => Some("the handshake did not complete, though the server answered"),
        _ => None,
    }
}

fn same_set(left: &[IpAddr], right: &[IpAddr]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_unstable();
    left.dedup();
    right.sort_unstable();
    right.dedup();
    left == right
}

/// Every probe result in plain words, so a reader can check the verdict against
/// the evidence without reading the code.
fn facts(input: &VerdictInput<'_>) -> Vec<String> {
    let mut facts = Vec::new();

    facts.push(format!("system resolver: {}", input.dns.system.describe()));
    for answer in &input.dns.doh {
        facts.push(format!("DoH {}: {}", answer.reference, answer.outcome.describe()));
    }
    facts.push(match &input.dns.comparison {
        Comparison::Identical => "the system resolver and the DoH references agree".to_string(),
        Comparison::Differ { .. } => {
            "the system resolver and the DoH references returned different addresses".to_string()
        }
        Comparison::Incomplete => {
            "at least one resolver gave no answer, so the DNS answers cannot be compared".to_string()
        }
    });

    for probe in input.tcp {
        facts.push(format!("TCP {}: {}", probe.label(), probe.outcome.describe()));
    }

    if let Some(tls) = input.tls {
        facts.push(format!(
            "TLS with SNI {}: {}",
            tls.real.sni,
            tls.real.outcome.describe()
        ));
        if let Some(control) = &tls.control {
            facts.push(format!("TLS with SNI {}: {}", control.sni, control.outcome.describe()));
        }
    }

    if let Some(http) = input.http {
        facts.push(format!(
            "HTTP with Host {}: {}",
            http.real.host,
            http.real.outcome.describe()
        ));
        if let Some(control) = &http.control {
            facts.push(format!(
                "HTTP with Host {}: {}",
                control.host,
                control.outcome.describe()
            ));
        }
    }

    facts
}

/// The addresses the TLS and HTTP probes should use: a connected IPv4 address
/// first, because that is the path the verdict is built on.
pub fn pick_address(tcp: &[TcpProbe]) -> Option<IpAddr> {
    tcp.iter()
        .find(|probe| probe.outcome.is_connected() && probe.ip.is_ipv4())
        .or_else(|| tcp.iter().find(|probe| probe.outcome.is_connected()))
        .map(|probe| probe.ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::dns::{DohAnswer, Rcode, ResolveFailure, ResolveOutcome, compare};
    use crate::probes::http::{HttpAttempt, HttpOutcome};
    use crate::probes::tls::TlsAttempt;
    use crate::target::Role;
    use std::time::Duration;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("a literal address")
    }

    fn target(domain: &str) -> Target {
        Target {
            domain: domain.to_string(),
            port: 443,
            role: Role::Service,
            known_ips: Vec::new(),
        }
    }

    fn resolved(ips: &[&str]) -> ResolveOutcome {
        ResolveOutcome::Resolved {
            ips: ips.iter().map(|text| ip(text)).collect(),
            elapsed: Duration::from_millis(10),
        }
    }

    fn doh_answer(reference: &'static str, ips: &[&str]) -> DohAnswer {
        DohAnswer {
            reference,
            outcome: resolved(ips),
        }
    }

    fn dns_probe(domain: &str, system: ResolveOutcome, doh: Vec<DohAnswer>) -> DnsProbe {
        let mut union = Vec::new();
        for answer in &doh {
            union.extend(answer.outcome.ips().iter().copied());
        }
        let comparison = compare(system.ips(), &union);
        DnsProbe {
            domain: domain.to_string(),
            system,
            doh,
            comparison,
        }
    }

    fn tcp(address: &str, outcome: TcpOutcome) -> TcpProbe {
        TcpProbe {
            domain: "github.com".to_string(),
            ip: ip(address),
            port: 443,
            source: IpSource::Resolved,
            outcome,
        }
    }

    fn connected(address: &str) -> TcpProbe {
        tcp(
            address,
            TcpOutcome::Connected {
                elapsed: Duration::from_millis(20),
            },
        )
    }

    fn timed_out(address: &str) -> TcpProbe {
        tcp(
            address,
            TcpOutcome::Timeout {
                elapsed: Duration::from_millis(5_000),
            },
        )
    }

    fn no_route(address: &str) -> TcpProbe {
        tcp(
            address,
            TcpOutcome::NoRoute {
                elapsed: Duration::ZERO,
            },
        )
    }

    fn server_responded() -> TlsOutcome {
        TlsOutcome::ServerResponded {
            cert_mismatch: true,
            detail: "certificate rejected: NotValidForName".to_string(),
            elapsed: Duration::from_millis(90),
        }
    }

    fn tls_ok(domain: &str) -> TlsProbe {
        TlsProbe {
            domain: domain.to_string(),
            ip: ip("140.82.121.4"),
            port: 443,
            real: TlsAttempt {
                sni: domain.to_string(),
                outcome: TlsOutcome::Ok {
                    elapsed: Duration::from_millis(120),
                },
            },
            control: None,
        }
    }

    fn tls_killed(domain: &str, control: Option<TlsOutcome>) -> TlsProbe {
        TlsProbe {
            domain: domain.to_string(),
            ip: ip("140.82.121.4"),
            port: 443,
            real: TlsAttempt {
                sni: domain.to_string(),
                outcome: TlsOutcome::RstAfterClientHello {
                    elapsed: Duration::from_millis(5),
                },
            },
            control: control.map(|outcome| TlsAttempt {
                sni: "yandex.ru".to_string(),
                outcome,
            }),
        }
    }

    fn http_ok(domain: &str) -> HttpProbe {
        HttpProbe {
            domain: domain.to_string(),
            ip: ip("140.82.121.4"),
            port: 80,
            real: HttpAttempt {
                host: domain.to_string(),
                outcome: HttpOutcome::Response {
                    status: 301,
                    elapsed: Duration::from_millis(85),
                },
            },
            control: None,
        }
    }

    fn http_killed(domain: &str, control: Option<HttpOutcome>) -> HttpProbe {
        HttpProbe {
            domain: domain.to_string(),
            ip: ip("140.82.121.4"),
            port: 80,
            real: HttpAttempt {
                host: domain.to_string(),
                outcome: HttpOutcome::Reset {
                    elapsed: Duration::from_millis(5),
                },
            },
            control: control.map(|outcome| HttpAttempt {
                host: "yandex.ru".to_string(),
                outcome,
            }),
        }
    }

    fn input<'a>(
        target: &'a Target,
        dns: &'a DnsProbe,
        tcp: &'a [TcpProbe],
        tls: Option<&'a TlsProbe>,
        http: Option<&'a HttpProbe>,
    ) -> VerdictInput<'a> {
        VerdictInput {
            target,
            dns,
            tcp,
            tls,
            http,
            control_alive: true,
            system_pool: &[],
        }
    }

    #[test]
    fn everything_passing_is_ok() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];
        let tls = tls_ok("github.com");
        let http = http_ok("github.com");

        let verdict = classify(&input(&target, &dns, &tcp, Some(&tls), Some(&http)));
        assert_eq!(verdict.kind, VerdictKind::Ok);
        assert_eq!(verdict.level, Level::Ok);
        assert_eq!(verdict.reason, "every probe reached the service");
    }

    #[test]
    fn a_system_resolver_that_answers_nothing_while_doh_does_is_dns_spoof() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            ResolveOutcome::Failed {
                failure: ResolveFailure::Rcode(Rcode::NameError),
                elapsed: Duration::from_millis(3),
            },
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];

        let verdict = classify(&input(&target, &dns, &tcp, None, None));
        assert_eq!(verdict.kind, VerdictKind::DnsSpoof);
        assert_eq!(verdict.level, Level::Bad);
        assert!(verdict.reason.contains("system resolver did not"), "{}", verdict.reason);
    }

    #[test]
    fn a_sinkhole_pool_shared_by_two_services_is_dns_spoof() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["10.0.0.1"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("10.0.0.1")];
        let pool = vec![
            ("github.com".to_string(), vec![ip("10.0.0.1")]),
            ("x.com".to_string(), vec![ip("10.0.0.1")]),
        ];
        let mut input = input(&target, &dns, &tcp, None, None);
        input.system_pool = &pool;

        let verdict = classify(&input);
        assert_eq!(verdict.kind, VerdictKind::DnsSpoof);
        assert!(verdict.reason.contains("x.com"), "{}", verdict.reason);
    }

    #[test]
    fn a_shared_cdn_address_that_the_references_also_return_is_not_dns_spoof() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["162.159.128.233"]),
            vec![doh_answer("dns.google", &["162.159.128.233"])],
        );
        let tcp = [connected("162.159.128.233")];
        let tls = tls_ok("github.com");
        let http = http_ok("github.com");
        let pool = vec![
            ("github.com".to_string(), vec![ip("162.159.128.233")]),
            ("discord.com".to_string(), vec![ip("162.159.128.233")]),
        ];
        let mut input = input(&target, &dns, &tcp, Some(&tls), Some(&http));
        input.system_pool = &pool;

        let verdict = classify(&input);
        assert_eq!(verdict.kind, VerdictKind::Ok);
    }

    #[test]
    fn a_real_name_killed_while_the_control_name_answers_is_dpi_sni() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];
        let tls = tls_killed("github.com", Some(server_responded()));

        let verdict = classify(&input(&target, &dns, &tcp, Some(&tls), None));
        assert_eq!(verdict.kind, VerdictKind::DpiSni);
        assert_eq!(verdict.level, Level::Bad);
    }

    #[test]
    fn no_ipv4_address_accepting_a_connection_is_ip_block() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4", "140.82.121.3"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [timed_out("140.82.121.4"), timed_out("140.82.121.3")];

        let verdict = classify(&input(&target, &dns, &tcp, None, None));
        assert_eq!(verdict.kind, VerdictKind::IpBlock);
        assert_eq!(verdict.level, Level::Bad);
        assert!(verdict.reason.contains("2 addresses"), "{}", verdict.reason);
    }

    #[test]
    fn a_real_host_killed_while_the_control_host_answers_is_host_filter() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];
        let tls = tls_ok("github.com");
        let http = http_killed(
            "github.com",
            Some(HttpOutcome::Response {
                status: 200,
                elapsed: Duration::from_millis(40),
            }),
        );

        let verdict = classify(&input(&target, &dns, &tcp, Some(&tls), Some(&http)));
        assert_eq!(verdict.kind, VerdictKind::HostFilter);
        assert_eq!(verdict.level, Level::Bad);
    }

    #[test]
    fn a_dead_control_makes_every_verdict_unknown() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [timed_out("140.82.121.4")];
        let mut input = input(&target, &dns, &tcp, None, None);
        input.control_alive = false;

        let verdict = classify(&input);
        assert_eq!(verdict.kind, VerdictKind::Unknown);
        assert_eq!(verdict.level, Level::Undetermined);
        assert!(verdict.reason.contains("control target"), "{}", verdict.reason);
    }

    #[test]
    fn a_kill_with_both_names_is_unknown() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];
        let tls = tls_killed(
            "github.com",
            Some(TlsOutcome::RstAfterClientHello {
                elapsed: Duration::from_millis(4),
            }),
        );

        let verdict = classify(&input(&target, &dns, &tcp, Some(&tls), None));
        assert_eq!(verdict.kind, VerdictKind::Unknown);
        assert!(verdict.reason.contains("known-good name"), "{}", verdict.reason);
    }

    #[test]
    fn an_ipv6_address_without_a_route_is_never_ip_block() {
        let target = target("youtube.com");
        let dns = dns_probe(
            "youtube.com",
            resolved(&["2a00:1450:400f:808::200e"]),
            vec![doh_answer("dns.google", &["2a00:1450:400f:808::200e"])],
        );
        let tcp = [no_route("2a00:1450:400f:808::200e")];

        let verdict = classify(&input(&target, &dns, &tcp, None, None));
        assert_eq!(verdict.kind, VerdictKind::Unknown);
        assert_ne!(verdict.kind, VerdictKind::IpBlock);
        assert!(verdict.reason.contains("no IPv4 address"), "{}", verdict.reason);
    }

    #[test]
    fn an_ipv4_address_without_a_route_is_not_ip_block_either() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [no_route("140.82.121.4")];

        let verdict = classify(&input(&target, &dns, &tcp, None, None));
        assert_eq!(verdict.kind, VerdictKind::Unknown);
        assert!(verdict.reason.contains("no route"), "{}", verdict.reason);
    }

    #[test]
    fn a_certificate_that_does_not_cover_the_name_is_ok_with_a_caveat() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];
        let tls = TlsProbe {
            domain: "github.com".to_string(),
            ip: ip("140.82.121.4"),
            port: 443,
            real: TlsAttempt {
                sni: "github.com".to_string(),
                outcome: server_responded(),
            },
            control: None,
        };
        let http = http_ok("github.com");

        let verdict = classify(&input(&target, &dns, &tcp, Some(&tls), Some(&http)));
        assert_eq!(verdict.kind, VerdictKind::Ok);
        assert_eq!(verdict.level, Level::Warn);
        assert!(verdict.reason.contains("certificate"), "{}", verdict.reason);
    }

    #[test]
    fn a_tls_alert_is_unknown() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];
        let tls = TlsProbe {
            domain: "github.com".to_string(),
            ip: ip("140.82.121.4"),
            port: 443,
            real: TlsAttempt {
                sni: "github.com".to_string(),
                outcome: TlsOutcome::TlsAlert {
                    code: 112,
                    elapsed: Duration::from_millis(30),
                },
            },
            control: None,
        };

        let verdict = classify(&input(&target, &dns, &tcp, Some(&tls), None));
        assert_eq!(verdict.kind, VerdictKind::Unknown);
        assert!(verdict.reason.contains("112"), "{}", verdict.reason);
    }

    #[test]
    fn a_host_that_fails_with_both_names_is_unknown() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];
        let tls = tls_ok("github.com");
        let http = http_killed(
            "github.com",
            Some(HttpOutcome::Reset {
                elapsed: Duration::from_millis(4),
            }),
        );

        let verdict = classify(&input(&target, &dns, &tcp, Some(&tls), Some(&http)));
        assert_eq!(verdict.kind, VerdictKind::Unknown);
        assert!(verdict.reason.contains("Host header"), "{}", verdict.reason);
    }

    #[test]
    fn a_verdict_built_on_recorded_addresses_says_so() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            ResolveOutcome::Failed {
                failure: ResolveFailure::Unreachable("resolver down".to_string()),
                elapsed: Duration::from_millis(3),
            },
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let mut probe = connected("140.82.121.4");
        probe.source = IpSource::Builtin;
        let tcp = [probe];

        let verdict = classify(&input(&target, &dns, &tcp, None, None));
        assert!(verdict.used_recorded_addresses());
        assert_eq!(verdict.address_source, Some(IpSource::Builtin));
    }

    #[test]
    fn the_facts_list_every_probe_that_ran() {
        let target = target("github.com");
        let dns = dns_probe(
            "github.com",
            resolved(&["140.82.121.4"]),
            vec![doh_answer("dns.google", &["140.82.121.4"])],
        );
        let tcp = [connected("140.82.121.4")];
        let tls = tls_ok("github.com");
        let http = http_ok("github.com");

        let verdict = classify(&input(&target, &dns, &tcp, Some(&tls), Some(&http)));
        let facts = verdict.facts.join("\n");
        assert!(facts.contains("system resolver:"), "{facts}");
        assert!(facts.contains("DoH dns.google:"), "{facts}");
        assert!(facts.contains("TCP 140.82.121.4:443:"), "{facts}");
        assert!(facts.contains("TLS with SNI github.com:"), "{facts}");
        assert!(facts.contains("HTTP with Host github.com:"), "{facts}");
    }

    #[test]
    fn the_address_for_the_later_probes_is_a_connected_ipv4_one() {
        let probes = [
            no_route("2a00:1450:400f:808::200e"),
            connected("2a00:1450:400f:808::200f"),
            connected("140.82.121.4"),
        ];
        assert_eq!(pick_address(&probes), Some(ip("140.82.121.4")));
        assert_eq!(pick_address(&[]), None);
    }

    #[test]
    fn a_verdict_kind_carries_its_default_level() {
        assert_eq!(VerdictKind::Ok.default_level(), Level::Ok);
        assert_eq!(VerdictKind::DpiSni.default_level(), Level::Bad);
        assert_eq!(VerdictKind::Unknown.default_level(), Level::Undetermined);
        assert_eq!(VerdictKind::DnsSpoof.as_str(), "dns_spoof");
        assert_eq!(Level::Undetermined.as_str(), "undetermined");
    }
}
