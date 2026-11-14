//! The text report.
//!
//! The report states what each probe observed and where every address came
//! from. It does not soften a failure and does not promote a difference to a
//! finding: the notes at the bottom say what a reader must not conclude.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::probes::dns::{Comparison, DnsProbe, IpSource, ResolveOutcome};
use crate::probes::tcp::{TcpOutcome, TcpProbe};
use crate::target::{KNOWN_IPS_RECORDED, Target};

/// Everything one run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub generated_at: String,
    pub targets: Vec<TargetReport>,
    pub control: ControlReport,
}

/// The probes for one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetReport {
    pub target: Target,
    pub dns: DnsProbe,
    pub tcp: Vec<TcpProbe>,
}

/// The probes for the control target, which only has to prove the network is
/// alive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlReport {
    pub target: Target,
    pub tcp: Vec<TcpProbe>,
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
    let _ = writeln!(out, "Oko {} — probe report", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "{}", report.generated_at);

    for target in &report.targets {
        let _ = writeln!(out);
        let _ = writeln!(out, "target {}", target.target.label());
        let _ = writeln!(out);
        render_dns(&mut out, &target.dns);
        let _ = writeln!(out);
        render_tcp(&mut out, &target.tcp);
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

    let _ = writeln!(out);
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
        "  - a successful TCP connect says the path to that address is open, nothing more"
    );

    out
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
    let elapsed = format_duration(outcome.elapsed());
    match outcome {
        ResolveOutcome::Resolved { ips, .. } => {
            let noun = if ips.len() == 1 { "address" } else { "addresses" };
            row(out, label, &format!("ok, {} {noun} ({elapsed})", ips.len()));
            for ip in ips {
                let _ = writeln!(out, "      {ip}");
            }
        }
        ResolveOutcome::Failed { failure, .. } => {
            row(out, label, &format!("{failure} ({elapsed})"));
        }
    }
}

fn render_tcp(out: &mut String, probes: &[TcpProbe]) {
    let _ = writeln!(out, "  TCP");
    if probes.is_empty() {
        let _ = writeln!(out, "    no address to try");
        return;
    }
    for probe in probes {
        let elapsed = format_duration(probe.outcome.elapsed());
        let status = match &probe.outcome {
            TcpOutcome::Connected { .. } => "connected".to_string(),
            TcpOutcome::Refused { .. } => "refused".to_string(),
            TcpOutcome::Timeout { .. } => "timed out".to_string(),
            TcpOutcome::NoRoute { .. } => "no route from this host".to_string(),
            TcpOutcome::Failed { reason, .. } => format!("failed: {reason}"),
        };
        row(out, &probe.label(), &format!("{status} ({elapsed})"));
    }
    if probes.iter().any(|probe| probe.source == IpSource::Builtin) {
        let _ = writeln!(
            out,
            "    note: these addresses come from the built-in list recorded on {KNOWN_IPS_RECORDED}; the system resolver returned nothing"
        );
    }
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

fn format_duration(elapsed: Duration) -> String {
    let millis = elapsed.as_millis();
    if millis < 1_000 {
        format!("{millis} ms")
    } else {
        format!("{:.1} s", elapsed.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::dns::{DohAnswer, Rcode, ResolveFailure};
    use crate::target::{Role, ad_hoc};
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn resolved(ips: &[IpAddr]) -> ResolveOutcome {
        ResolveOutcome::Resolved {
            ips: ips.to_vec(),
            elapsed: Duration::from_millis(12),
        }
    }

    fn connected(ip: IpAddr) -> TcpProbe {
        TcpProbe {
            domain: "github.com".to_string(),
            ip,
            port: 443,
            source: IpSource::Resolved,
            outcome: TcpOutcome::Connected {
                elapsed: Duration::from_millis(24),
            },
        }
    }

    fn report_with(comparison: Comparison, tcp: Vec<TcpProbe>) -> RunReport {
        RunReport {
            generated_at: "2026-11-14T21:52:03Z".to_string(),
            targets: vec![TargetReport {
                target: ad_hoc("github.com"),
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
            }],
            control: ControlReport {
                target: Target {
                    domain: "yandex.ru".to_string(),
                    port: 443,
                    role: Role::Control,
                    known_ips: Vec::new(),
                },
                tcp: vec![connected(ip(77, 88, 55, 88))],
            },
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
    fn durations_read_as_milliseconds_then_seconds() {
        assert_eq!(format_duration(Duration::from_millis(0)), "0 ms");
        assert_eq!(format_duration(Duration::from_millis(999)), "999 ms");
        assert_eq!(format_duration(Duration::from_millis(1_000)), "1.0 s");
        assert_eq!(format_duration(Duration::from_millis(5_001)), "5.0 s");
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
    fn the_report_names_the_target_and_every_resolver() {
        let text = render(&report_with(
            Comparison::Identical,
            vec![connected(ip(140, 82, 121, 4))],
        ));
        assert!(text.contains("target github.com:443"), "{text}");
        assert!(text.contains("system (getaddrinfo)"), "{text}");
        assert!(text.contains("DoH dns.google"), "{text}");
        assert!(text.contains("140.82.121.4"), "{text}");
        assert!(text.contains("connected (24 ms)"), "{text}");
        assert!(text.contains("control yandex.ru:443"), "{text}");
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
            reference: "dns.quad9.net",
            outcome: ResolveOutcome::Failed {
                failure: ResolveFailure::Unreachable("timed out".to_string()),
                elapsed: Duration::from_millis(5_001),
            },
        });
        let text = render(&report);
        assert!(text.contains("DoH dns.quad9.net"), "{text}");
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
    fn a_builtin_address_is_labelled_as_such() {
        let mut report = report_with(Comparison::Incomplete, vec![connected(ip(140, 82, 121, 4))]);
        report.targets[0].tcp[0].source = IpSource::Builtin;
        let text = render(&report);
        assert!(text.contains("built-in list recorded on"), "{text}");
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
}
