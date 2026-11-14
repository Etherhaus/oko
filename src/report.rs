//! The text and JSON reports.
//!
//! The report states what each probe observed, what the verdict rests on, and
//! where every address came from. It does not soften a failure and does not
//! promote a difference to a finding: the notes at the bottom say what a reader
//! must not conclude.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::probes::dns::{Comparison, DnsProbe, IpSource, ResolveOutcome};
use crate::probes::http::HttpProbe;
use crate::probes::payload::PayloadProbe;
use crate::probes::quic::QuicProbe;
use crate::probes::tcp::TcpProbe;
use crate::probes::tls::TlsProbe;
use crate::target::{KNOWN_IPS_RECORDED, Target};
use crate::verdict::{Diff, Verdict, VerdictKind};

/// Everything one run produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunReport {
    pub tool: &'static str,
    pub version: &'static str,
    pub generated_at: String,
    pub targets: Vec<TargetReport>,
    pub control: ControlReport,
    /// The same probes through a SOCKS5 proxy, when one was asked for.
    pub tunnel: Option<TunnelRun>,
    /// Set when the watchdog ended the run before every target was probed.
    pub interrupted: Option<Interrupted>,
}

/// The watchdog ended the run before every target was probed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interrupted {
    /// The target whose probes were running when the budget ran out.
    pub target: String,
    /// The budget the run was given, in seconds.
    pub budget_secs: u64,
}

/// The probes and the verdict for one service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetReport {
    pub target: Target,
    pub verdict: Verdict,
    pub dns: DnsProbe,
    pub tcp: Vec<TcpProbe>,
    pub tls: Option<TlsProbe>,
    pub http: Option<HttpProbe>,
    pub payload: Option<PayloadProbe>,
    pub quic: Option<QuicProbe>,
    /// The comparison with the tunnel run, when one ran.
    pub diff: Option<Diff>,
}

/// The probes for the control target, which only has to prove the network is
/// alive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlReport {
    pub target: Target,
    pub tcp: Vec<TcpProbe>,
}

/// The same probes through a SOCKS5 proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunnelRun {
    pub proxy: SocketAddr,
    pub control: ControlReport,
    pub targets: Vec<TargetReport>,
}

/// The current time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_utc() -> String {
    format_utc(SystemTime::now())
}

/// Format a moment as `YYYY-MM-DDTHH:MM:SSZ`. Times before the epoch clamp to
/// the epoch: a probe report is never dated 1969.
pub fn format_utc(moment: SystemTime) -> String {
    let seconds = moment
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = rest / 3_600;
    let minute = (rest % 3_600) / 60;
    let second = rest % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Days since 1970-01-01 to a civil date. Howard Hinnant's `civil_from_days`,
/// which is exact for every date the calendar has.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Render the whole run as text.
pub fn render(report: &RunReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{} {} — probe report", report.tool, report.version);
    let _ = writeln!(out, "{}", report.generated_at);
    if let Some(interrupted) = &report.interrupted {
        let _ = writeln!(
            out,
            "run interrupted by the watchdog at {} after {} s: the report below is partial",
            interrupted.target, interrupted.budget_secs
        );
    }

    for target in &report.targets {
        let _ = writeln!(out);
        out.push_str(&render_target(target, None));
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "control {}", report.control.target.label());
    let _ = writeln!(out);
    render_tcp(&mut out, &report.control.tcp);
    if !report.control.tcp.iter().any(|probe| probe.outcome.is_connected()) {
        let _ = writeln!(
            out,
            "    note: the control target did not answer. The network is down or filtered as a whole, so the results above say nothing about the services."
        );
    }

    if let Some(tunnel) = &report.tunnel {
        let _ = writeln!(out);
        render_tunnel(&mut out, tunnel);
        let _ = writeln!(out);
        render_diff(&mut out, &report.targets);
    }

    let _ = writeln!(out);
    render_notes(&mut out);
    out
}

/// Render one target's probes as text: the sections the full report prints,
/// plus the tunnel run and the diff when they exist.
///
/// The window shows this text in its details panel, so the panel and the CLI
/// never drift apart.
pub fn render_target(target: &TargetReport, tunnel: Option<&TargetReport>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "target {}", target.target.label());
    render_verdict(&mut out, &target.verdict);
    render_sections(&mut out, target);
    if target.verdict.kind != VerdictKind::Ok {
        let _ = writeln!(out);
        render_facts(&mut out, &target.verdict);
    }

    if let Some(tunnel) = tunnel {
        let _ = writeln!(out);
        let _ = writeln!(out, "tunnel");
        render_verdict(&mut out, &tunnel.verdict);
        render_sections(&mut out, tunnel);
    }

    if let Some(diff) = &target.diff {
        let _ = writeln!(out);
        let _ = writeln!(out, "diff");
        let _ = writeln!(out, "  direct  {}", diff.direct.as_str());
        let _ = writeln!(out, "  tunnel  {}", diff.tunnel.as_str());
        let _ = writeln!(out, "  result  {}: {}", diff.kind.describe(), diff.reason);
    }
    out
}

/// The probe sections of one target, without the verdict.
fn render_sections(out: &mut String, target: &TargetReport) {
    let _ = writeln!(out);
    render_dns(out, &target.dns);
    let _ = writeln!(out);
    render_tcp(out, &target.tcp);
    if let Some(tls) = &target.tls {
        let _ = writeln!(out);
        render_tls(out, tls);
    }
    if let Some(http) = &target.http {
        let _ = writeln!(out);
        render_http(out, http);
    }
    if let Some(payload) = &target.payload {
        let _ = writeln!(out);
        render_payload(out, payload);
    }
    if let Some(quic) = &target.quic {
        let _ = writeln!(out);
        render_quic(out, quic);
    }
}

/// Render the whole run as JSON.
pub fn render_json(report: &RunReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

fn render_verdict(out: &mut String, verdict: &Verdict) {
    if verdict.level == verdict.kind.default_level() {
        let _ = writeln!(out, "  verdict  {}", verdict.kind.as_str());
    } else {
        let _ = writeln!(
            out,
            "  verdict  {}  [{}]",
            verdict.kind.as_str(),
            verdict.level.as_str()
        );
    }
    let _ = writeln!(out, "    {}", verdict.reason);
    if verdict.used_recorded_addresses() {
        let _ = writeln!(
            out,
            "    address from the recorded set, not from a fresh resolve: the system resolver returned nothing"
        );
    }
}

fn render_dns(out: &mut String, dns: &DnsProbe) {
    let _ = writeln!(out, "  DNS");
    render_resolver(out, "system (getaddrinfo)", &dns.system);
    for answer in &dns.doh {
        render_resolver(out, &format!("DoH {}", answer.reference), &answer.outcome);
    }

    match &dns.comparison {
        Comparison::Identical => row(out, "comparison", "identical"),
        Comparison::Differ { system_only, doh_only } => {
            row(out, "comparison", "differ");
            if !system_only.is_empty() {
                let _ = writeln!(out, "      system-only: {}", join_ips(system_only));
            }
            if !doh_only.is_empty() {
                let _ = writeln!(out, "      doh-only: {}", join_ips(doh_only));
            }
        }
        Comparison::Incomplete => {
            row(out, "comparison", "incomplete");
            let _ = writeln!(
                out,
                "      note: at least one side gave no answer, so there is nothing to compare"
            );
        }
    }
}

fn render_resolver(out: &mut String, label: &str, outcome: &ResolveOutcome) {
    row(out, label, &outcome.describe());
    for ip in outcome.ips() {
        let _ = writeln!(out, "      {ip}");
    }
}

fn render_tcp(out: &mut String, probes: &[TcpProbe]) {
    let _ = writeln!(out, "  TCP");
    if probes.is_empty() {
        let _ = writeln!(out, "    no address to try");
        return;
    }
    for probe in probes {
        row(out, &probe.label(), &probe.outcome.describe());
    }
    if probes.iter().any(|probe| probe.source == IpSource::Builtin) {
        let _ = writeln!(
            out,
            "    note: these addresses come from the built-in list recorded on {KNOWN_IPS_RECORDED}; the system resolver returned nothing"
        );
    }
}

fn render_tls(out: &mut String, tls: &TlsProbe) {
    let _ = writeln!(out, "  TLS");
    row(out, &format!("SNI {}", tls.real.sni), &tls.real.outcome.describe());
    if let Some(control) = &tls.control {
        row(out, &format!("SNI {}", control.sni), &control.outcome.describe());
    }
}

fn render_http(out: &mut String, http: &HttpProbe) {
    let _ = writeln!(out, "  HTTP");
    row(out, &format!("Host {}", http.real.host), &http.real.outcome.describe());
    if let Some(control) = &http.control {
        row(out, &format!("Host {}", control.host), &control.outcome.describe());
    }
}

fn render_payload(out: &mut String, payload: &PayloadProbe) {
    let _ = writeln!(out, "  payload");
    row(out, "body", &payload.outcome.describe());
}

fn render_quic(out: &mut String, quic: &QuicProbe) {
    let _ = writeln!(out, "  QUIC");
    row(out, "UDP 443", &quic.outcome.describe());
    let _ = writeln!(out, "    note: {}", quic.outcome.note());
}

fn render_tunnel(out: &mut String, tunnel: &TunnelRun) {
    let _ = writeln!(out, "tunnel {}", tunnel.proxy);
    let _ = writeln!(out);
    let _ = writeln!(out, "  control {}", tunnel.control.target.label());
    render_tcp(out, &tunnel.control.tcp);
    if !tunnel.control.tcp.iter().any(|probe| probe.outcome.is_connected()) {
        let _ = writeln!(
            out,
            "    note: the tunnel did not carry the control target, so the tunnel run says nothing about the services"
        );
    }

    for target in &tunnel.targets {
        let _ = writeln!(out);
        let _ = writeln!(out, "  target {}", target.target.label());
        render_verdict(out, &target.verdict);
        let _ = writeln!(out);
        render_tcp(out, &target.tcp);
        if let Some(tls) = &target.tls {
            let _ = writeln!(out);
            render_tls(out, tls);
        }
        if let Some(http) = &target.http {
            let _ = writeln!(out);
            render_http(out, http);
        }
        if let Some(payload) = &target.payload {
            let _ = writeln!(out);
            render_payload(out, payload);
        }
    }
}

fn render_diff(out: &mut String, targets: &[TargetReport]) {
    let _ = writeln!(out, "diff");
    for target in targets {
        let Some(diff) = &target.diff else {
            continue;
        };
        let _ = writeln!(out, "  {}", target.target.label());
        let _ = writeln!(out, "    direct  {}", diff.direct.as_str());
        let _ = writeln!(out, "    tunnel  {}", diff.tunnel.as_str());
        let _ = writeln!(out, "    result  {}: {}", diff.kind.describe(), diff.reason);
    }
}

fn render_facts(out: &mut String, verdict: &Verdict) {
    let _ = writeln!(out, "  facts");
    for fact in &verdict.facts {
        let _ = writeln!(out, "    - {fact}");
    }
}

fn render_notes(out: &mut String) {
    let _ = writeln!(out, "notes");
    let _ = writeln!(
        out,
        "  - a difference between the system resolver and a DoH reference is not a verdict:"
    );
    let _ = writeln!(
        out,
        "    CDN geo-DNS legitimately returns different addresses to different resolvers"
    );
    let _ = writeln!(
        out,
        "  - a DoH reference that cannot be reached is reported as such, not as an error"
    );
    let _ = writeln!(
        out,
        "  - a handshake that reaches the server proves the path did not object to the name,"
    );
    let _ = writeln!(out, "    whatever the certificate says");
    let _ = writeln!(
        out,
        "  - the HTTP probe speaks plain HTTP on port 80; a server that does not answer there"
    );
    let _ = writeln!(out, "    says nothing about blocking");
    let _ = writeln!(
        out,
        "  - an address with no route from this host is never counted as a block"
    );
    let _ = writeln!(
        out,
        "  - a body that ends inside 16–20 KB or around 25 KB with the response still incomplete"
    );
    let _ = writeln!(
        out,
        "    is the l4-25 signature; a complete response that ends there is not"
    );
    let _ = writeln!(
        out,
        "  - QUIC silence is not a verdict: a NAT or a provider may drop UDP legitimately"
    );
    let _ = writeln!(
        out,
        "  - the tunnel run reuses the addresses the direct run resolved, so a spoofed DNS"
    );
    let _ = writeln!(out, "    answer poisons both runs and the comparison says nothing");
}

/// One `label   value` line, indented under a section.
fn row(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "    {label:<24} {value}");
}

fn join_ips(ips: &[IpAddr]) -> String {
    // The full lists are printed per resolver above; this summary only has to
    // stay readable, so it stops after a handful.
    const SHOWN: usize = 6;
    let mut text = ips
        .iter()
        .take(SHOWN)
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if ips.len() > SHOWN {
        let _ = write!(text, " and {} more", ips.len() - SHOWN);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::dns::{DohAnswer, Rcode, ResolveFailure};
    use crate::probes::http::{HttpAttempt, HttpOutcome};
    use crate::probes::payload::{DropRange, PayloadOutcome, PayloadProbe};
    use crate::probes::quic::{QuicOutcome, QuicProbe};
    use crate::probes::tcp::TcpOutcome;
    use crate::probes::tls::TlsAttempt;
    use crate::target::{Category, Role, ad_hoc};
    use crate::verdict::{Diff, DiffKind, Level};
    use std::time::Duration;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    fn resolved(ips: &[IpAddr]) -> ResolveOutcome {
        ResolveOutcome::Resolved {
            ips: ips.to_vec(),
            elapsed: Duration::from_millis(12),
        }
    }

    fn connected(address: IpAddr) -> TcpProbe {
        TcpProbe {
            domain: "github.com".to_string(),
            ip: address,
            port: 443,
            source: IpSource::Resolved,
            outcome: TcpOutcome::Connected {
                elapsed: Duration::from_millis(24),
            },
        }
    }

    fn ok_verdict() -> Verdict {
        Verdict {
            kind: VerdictKind::Ok,
            level: Level::Ok,
            reason: "every probe reached the service".to_string(),
            facts: vec!["system resolver: ok, 1 address (12 ms)".to_string()],
            address_source: Some(IpSource::Resolved),
        }
    }

    fn tls_probe() -> TlsProbe {
        TlsProbe {
            domain: "github.com".to_string(),
            ip: ip(140, 82, 121, 4),
            port: 443,
            real: TlsAttempt {
                sni: "github.com".to_string(),
                outcome: crate::probes::tls::TlsOutcome::Ok {
                    elapsed: Duration::from_millis(120),
                },
            },
            control: None,
        }
    }

    fn http_probe() -> HttpProbe {
        HttpProbe {
            domain: "github.com".to_string(),
            ip: ip(140, 82, 121, 4),
            port: 80,
            real: HttpAttempt {
                host: "github.com".to_string(),
                outcome: HttpOutcome::Response {
                    status: 301,
                    elapsed: Duration::from_millis(85),
                },
            },
            control: None,
        }
    }

    fn payload_probe() -> PayloadProbe {
        PayloadProbe {
            domain: "github.com".to_string(),
            ip: ip(140, 82, 121, 4),
            port: 443,
            outcome: PayloadOutcome::KbDrop {
                body: 17 * 1024,
                total: 22 * 1024,
                range: DropRange::SixteenToTwenty,
                elapsed: Duration::from_millis(900),
            },
        }
    }

    fn quic_probe() -> QuicProbe {
        QuicProbe {
            domain: "github.com".to_string(),
            ip: ip(140, 82, 121, 4),
            port: 443,
            outcome: QuicOutcome::Silent {
                elapsed: Duration::from_millis(5_000),
            },
        }
    }

    fn report_with(comparison: Comparison, tcp: Vec<TcpProbe>) -> RunReport {
        RunReport {
            tool: "oko",
            version: "0.1.0",
            generated_at: "2026-11-14T21:52:03Z".to_string(),
            targets: vec![TargetReport {
                target: ad_hoc("github.com"),
                verdict: ok_verdict(),
                dns: DnsProbe {
                    domain: "github.com".to_string(),
                    system: resolved(&[ip(140, 82, 121, 4)]),
                    doh: vec![DohAnswer {
                        reference: "dns.google",
                        outcome: resolved(&[ip(140, 82, 121, 4)]),
                    }],
                    comparison,
                },
                tcp,
                tls: Some(tls_probe()),
                http: Some(http_probe()),
                payload: None,
                quic: None,
                diff: None,
            }],
            control: ControlReport {
                target: Target {
                    domain: "yandex.ru".to_string(),
                    port: 443,
                    role: Role::Control,
                    known_ips: Vec::new(),
                    category: Category::Control,
                    custom: false,
                },
                tcp: vec![connected(ip(77, 88, 55, 88))],
            },
            tunnel: None,
            interrupted: None,
        }
    }

    #[test]
    fn the_epoch_formats_as_a_utc_timestamp() {
        assert_eq!(format_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_leap_day_formats_correctly() {
        assert_eq!(
            format_utc(UNIX_EPOCH + Duration::from_secs(1_709_164_800)),
            "2024-02-29T00:00:00Z"
        );
    }

    #[test]
    fn an_ordinary_moment_formats_correctly() {
        assert_eq!(
            format_utc(UNIX_EPOCH + Duration::from_secs(1_763_157_123)),
            "2025-11-14T21:52:03Z"
        );
    }

    #[test]
    fn a_moment_before_the_epoch_clamps_to_it() {
        assert_eq!(format_utc(UNIX_EPOCH - Duration::from_secs(60)), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_long_address_list_is_summarised() {
        let ips: Vec<IpAddr> = (1..=9).map(|last| ip(10, 0, 0, last)).collect();
        assert_eq!(
            join_ips(&ips),
            "10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5, 10.0.0.6 and 3 more"
        );
        assert_eq!(join_ips(&ips[..2]), "10.0.0.1, 10.0.0.2");
    }

    #[test]
    fn the_report_names_the_target_the_verdict_and_every_probe() {
        let text = render(&report_with(
            Comparison::Identical,
            vec![connected(ip(140, 82, 121, 4))],
        ));
        assert!(text.contains("target github.com:443"), "{text}");
        assert!(text.contains("verdict  ok\n"), "{text}");
        assert!(!text.contains("[ok]"), "{text}");
        assert!(text.contains("every probe reached the service"), "{text}");
        assert!(text.contains("system (getaddrinfo)"), "{text}");
        assert!(text.contains("DoH dns.google"), "{text}");
        assert!(text.contains("connected (24 ms)"), "{text}");
        assert!(text.contains("SNI github.com"), "{text}");
        assert!(text.contains("handshake completed (120 ms)"), "{text}");
        assert!(text.contains("Host github.com"), "{text}");
        assert!(text.contains("HTTP 301 (85 ms)"), "{text}");
        assert!(text.contains("control yandex.ru:443"), "{text}");
    }

    #[test]
    fn an_ok_verdict_does_not_repeat_the_facts() {
        let text = render(&report_with(
            Comparison::Identical,
            vec![connected(ip(140, 82, 121, 4))],
        ));
        assert!(!text.contains("  facts"), "{text}");
    }

    #[test]
    fn an_unknown_verdict_lists_its_facts() {
        let mut report = report_with(Comparison::Identical, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].verdict = Verdict {
            kind: VerdictKind::Unknown,
            level: Level::Undetermined,
            reason: "the handshake was killed with the real name and with a known-good name".to_string(),
            facts: vec![
                "TLS with SNI github.com: the connection ended after the ClientHello (5 ms)".to_string(),
                "TLS with SNI yandex.ru: the connection ended after the ClientHello (4 ms)".to_string(),
            ],
            address_source: Some(IpSource::Resolved),
        };
        let text = render(&report);
        assert!(text.contains("verdict  unknown\n"), "{text}");
        assert!(text.contains("  facts"), "{text}");
        assert!(text.contains("TLS with SNI yandex.ru"), "{text}");
    }

    #[test]
    fn a_verdict_on_recorded_addresses_says_so() {
        let mut report = report_with(Comparison::Incomplete, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].verdict.address_source = Some(IpSource::Builtin);
        report.targets[0].tcp[0].source = IpSource::Builtin;
        let text = render(&report);
        assert!(text.contains("address from the recorded set"), "{text}");
        assert!(text.contains("built-in list recorded on"), "{text}");
    }

    #[test]
    fn a_difference_is_shown_with_both_sides_and_a_caveat() {
        let text = render(&report_with(
            Comparison::Differ {
                system_only: vec![ip(1, 1, 1, 1)],
                doh_only: vec![ip(2, 2, 2, 2)],
            },
            vec![connected(ip(140, 82, 121, 4))],
        ));
        assert!(text.contains("differ"), "{text}");
        assert!(text.contains("system-only: 1.1.1.1"), "{text}");
        assert!(text.contains("doh-only: 2.2.2.2"), "{text}");
        assert!(text.contains("CDN geo-DNS"), "{text}");
    }

    #[test]
    fn an_unreachable_reference_is_reported_as_unreachable() {
        let mut report = report_with(Comparison::Incomplete, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].dns.doh.push(DohAnswer {
            reference: "dns.sb",
            outcome: ResolveOutcome::Failed {
                failure: ResolveFailure::Unreachable("timed out".to_string()),
                elapsed: Duration::from_millis(5_001),
            },
        });
        let text = render(&report);
        assert!(text.contains("DoH dns.sb"), "{text}");
        assert!(text.contains("unreachable: timed out (5.0 s)"), "{text}");
        assert!(text.contains("incomplete"), "{text}");
    }

    #[test]
    fn a_dead_control_says_the_results_mean_nothing() {
        let mut report = report_with(Comparison::Identical, vec![connected(ip(140, 82, 121, 4))]);
        report.control.tcp = vec![TcpProbe {
            domain: "yandex.ru".to_string(),
            ip: ip(77, 88, 55, 88),
            port: 443,
            source: IpSource::Resolved,
            outcome: TcpOutcome::Timeout {
                elapsed: Duration::from_millis(5_000),
            },
        }];
        let text = render(&report);
        assert!(text.contains("the control target did not answer"), "{text}");
    }

    #[test]
    fn a_target_without_addresses_says_so() {
        let text = render(&report_with(Comparison::Incomplete, Vec::new()));
        assert!(text.contains("no address to try"), "{text}");
    }

    #[test]
    fn an_error_rcode_is_named_in_the_report() {
        let mut report = report_with(Comparison::Incomplete, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].dns.system = ResolveOutcome::Failed {
            failure: ResolveFailure::Rcode(Rcode::NameError),
            elapsed: Duration::from_millis(3),
        };
        let text = render(&report);
        assert!(text.contains("answered NXDOMAIN (3 ms)"), "{text}");
    }

    #[test]
    fn the_json_report_carries_the_verdict_and_the_probes() {
        let json = render_json(&report_with(
            Comparison::Identical,
            vec![connected(ip(140, 82, 121, 4))],
        ))
        .expect("the report serializes");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["tool"], "oko");
        assert_eq!(parsed["targets"][0]["verdict"]["kind"], "ok");
        assert_eq!(parsed["targets"][0]["verdict"]["level"], "ok");
        assert_eq!(parsed["targets"][0]["tcp"][0]["outcome"]["connected"]["elapsed"], 24);
        assert_eq!(parsed["targets"][0]["tls"]["real"]["outcome"]["ok"]["elapsed"], 120);
        assert_eq!(
            parsed["targets"][0]["http"]["real"]["outcome"]["response"]["status"],
            301
        );
        assert_eq!(parsed["targets"][0]["dns"]["comparison"], "identical");
        assert_eq!(parsed["control"]["target"]["domain"], "yandex.ru");
    }

    #[test]
    fn a_payload_section_names_the_body_size() {
        let mut report = report_with(Comparison::Identical, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].payload = Some(payload_probe());
        let text = render(&report);
        assert!(text.contains("  payload"), "{text}");
        assert!(text.contains("inside the 16–20 KB range"), "{text}");
    }

    #[test]
    fn a_quic_section_says_silence_is_not_a_verdict() {
        let mut report = report_with(Comparison::Identical, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].quic = Some(quic_probe());
        let text = render(&report);
        assert!(text.contains("  QUIC"), "{text}");
        assert!(text.contains("no answer (5.0 s)"), "{text}");
        assert!(text.contains("not a verdict"), "{text}");
    }

    #[test]
    fn a_tunnel_run_renders_the_diff_table() {
        let mut report = report_with(Comparison::Identical, vec![connected(ip(140, 82, 121, 4))]);
        let dns = report.targets[0].dns.clone();
        report.targets[0].diff = Some(Diff {
            kind: DiffKind::PathBlock,
            direct: VerdictKind::DpiSni,
            tunnel: VerdictKind::Ok,
            reason: "the service works through the tunnel and not directly, so the block is on this path".to_string(),
        });
        report.tunnel = Some(TunnelRun {
            proxy: "127.0.0.1:10808".parse().unwrap(),
            control: ControlReport {
                target: Target {
                    domain: "yandex.ru".to_string(),
                    port: 443,
                    role: Role::Control,
                    known_ips: Vec::new(),
                    category: Category::Control,
                    custom: false,
                },
                tcp: vec![connected(ip(77, 88, 55, 88))],
            },
            targets: vec![TargetReport {
                target: ad_hoc("github.com"),
                verdict: ok_verdict(),
                dns,
                tcp: vec![connected(ip(140, 82, 121, 4))],
                tls: Some(tls_probe()),
                http: Some(http_probe()),
                payload: None,
                quic: None,
                diff: None,
            }],
        });

        let text = render(&report);
        assert!(text.contains("tunnel 127.0.0.1:10808"), "{text}");
        assert!(text.contains("\ndiff\n"), "{text}");
        assert!(text.contains("direct  dpi_sni"), "{text}");
        assert!(text.contains("tunnel  ok"), "{text}");
        assert!(text.contains("blocked on the path"), "{text}");
    }

    #[test]
    fn the_json_report_carries_the_payload_and_the_quic_probe() {
        let mut report = report_with(Comparison::Identical, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].payload = Some(payload_probe());
        report.targets[0].quic = Some(quic_probe());
        let json = render_json(&report).expect("the report serializes");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(
            parsed["targets"][0]["payload"]["outcome"]["kb_drop"]["range"],
            "sixteen_to_twenty"
        );
        assert_eq!(parsed["targets"][0]["quic"]["outcome"]["silent"]["elapsed"], 5000);
        assert!(parsed["tunnel"].is_null());
    }

    #[test]
    fn the_json_report_names_a_failed_resolve_by_its_code() {
        let mut report = report_with(Comparison::Incomplete, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].dns.system = ResolveOutcome::Failed {
            failure: ResolveFailure::Rcode(Rcode::NameError),
            elapsed: Duration::from_millis(3),
        };
        let json = render_json(&report).expect("the report serializes");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(
            parsed["targets"][0]["dns"]["system"]["failed"]["failure"]["rcode"],
            "NXDOMAIN"
        );
    }
}
