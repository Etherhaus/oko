//! DNS probe: what the system resolver says, and what public DoH references say.
//!
//! The probe reports both sets of addresses and whether they differ. It does
//! **not** turn a difference into a verdict: CDN geo-DNS legitimately hands out
//! different addresses to different resolvers, so "the addresses differ" is a
//! fact, not a finding. Stage 2 builds the DNS verdict on the signals that do
//! mean something — a reference that answers while the system resolver does not,
//! or a system resolver that returns the same pool for unrelated domains.

mod wire;

use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use wire::RecordData;

/// The response code a resolver answered with, re-exported because
/// [`ResolveFailure::Rcode`] carries it.
pub use wire::Rcode;

/// A DoH reference is a public resolver we can ask over HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DohReference {
    pub name: &'static str,
    pub url: &'static str,
}

/// The references the probe compares the system resolver against. Three of them,
/// because a single blocked reference must not leave the probe without a
/// baseline.
///
/// All three must answer over HTTP/1.1, which is all ureq speaks. Quad9's
/// endpoint (`dns.quad9.net`) answers HTTP/2 only and returns 505 to an HTTP/1.1
/// POST, so it cannot be a reference here.
pub const DOH_REFERENCES: &[DohReference] = &[
    DohReference {
        name: "dns.google",
        url: "https://dns.google/dns-query",
    },
    DohReference {
        name: "cloudflare-dns.com",
        url: "https://cloudflare-dns.com/dns-query",
    },
    DohReference {
        name: "dns.sb",
        url: "https://dns.sb/dns-query",
    },
];

/// A DNS message is small; anything larger is not an answer we asked for.
const MAX_DOH_BODY: u64 = 64 * 1024;

/// Why a resolver gave no addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveFailure {
    /// The resolver could not be reached: DNS, TCP, TLS or HTTP failed.
    Unreachable(String),
    /// The resolver answered with an error code.
    Rcode(Rcode),
    /// The resolver answered `NOERROR` but held no `A` or `AAAA` records.
    NoRecords,
}

impl std::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveFailure::Unreachable(reason) => write!(f, "unreachable: {reason}"),
            ResolveFailure::Rcode(rcode) => write!(f, "answered {rcode}"),
            ResolveFailure::NoRecords => f.write_str("answered with no A or AAAA records"),
        }
    }
}

/// What one resolver did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    Resolved { ips: Vec<IpAddr>, elapsed: Duration },
    Failed { failure: ResolveFailure, elapsed: Duration },
}

impl ResolveOutcome {
    pub fn ips(&self) -> &[IpAddr] {
        match self {
            ResolveOutcome::Resolved { ips, .. } => ips,
            ResolveOutcome::Failed { .. } => &[],
        }
    }

    pub fn elapsed(&self) -> Duration {
        match self {
            ResolveOutcome::Resolved { elapsed, .. } | ResolveOutcome::Failed { elapsed, .. } => *elapsed,
        }
    }
}

/// One DoH reference and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohAnswer {
    pub reference: &'static str,
    pub outcome: ResolveOutcome,
}

/// How the system resolver and the DoH references compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comparison {
    /// Every side that answered returned the same addresses.
    Identical,
    /// Both sides answered, and the sets differ. Normal for CDN geo-DNS.
    Differ {
        system_only: Vec<IpAddr>,
        doh_only: Vec<IpAddr>,
    },
    /// At least one side has no answer, so there is nothing to compare.
    Incomplete,
}

/// The whole DNS probe for one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProbe {
    pub domain: String,
    pub system: ResolveOutcome,
    pub doh: Vec<DohAnswer>,
    pub comparison: Comparison,
}

impl DnsProbe {
    /// The addresses the TCP probe should try: the system resolver's answer,
    /// falling back to the recorded ones when the resolver returns nothing.
    pub fn addresses_for_tcp(&self, known_ips: &[IpAddr]) -> (Vec<IpAddr>, IpSource) {
        addresses_for_tcp(&self.system, known_ips)
    }
}

/// The addresses to try for a target, and where they came from. A resolver that
/// returns nothing must not hide an IP-level block, so the recorded addresses
/// stand in for it.
pub fn addresses_for_tcp(outcome: &ResolveOutcome, known_ips: &[IpAddr]) -> (Vec<IpAddr>, IpSource) {
    let resolved = outcome.ips();
    if !resolved.is_empty() {
        return (resolved.to_vec(), IpSource::Resolved);
    }
    (known_ips.to_vec(), IpSource::Builtin)
}

/// Where the addresses the TCP probe used came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSource {
    /// The system resolver.
    Resolved,
    /// The list recorded in [`crate::target`], used because the resolver failed.
    Builtin,
}

/// Run the DNS probe for `domain`.
pub async fn probe(domain: &str, timeout: Duration) -> DnsProbe {
    let system = system_lookup(domain).await;
    let doh = doh_lookup_all(domain, timeout).await;
    let comparison = compare(system.ips(), &collect_ips(&doh));
    DnsProbe {
        domain: domain.to_string(),
        system,
        doh,
        comparison,
    }
}

/// Ask the system resolver. `getaddrinfo` is blocking, so it runs off the
/// runtime threads.
pub async fn system_lookup(domain: &str) -> ResolveOutcome {
    let domain = domain.to_string();
    let started = Instant::now();
    let joined = tokio::task::spawn_blocking(move || {
        // Port 443 is only a carrier for the address lookup; nothing connects.
        (domain.as_str(), crate::target::DEFAULT_PORT)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
    })
    .await;

    let elapsed = started.elapsed();
    match joined {
        Ok(Ok(ips)) => {
            let ips = dedupe(ips);
            if ips.is_empty() {
                ResolveOutcome::Failed {
                    failure: ResolveFailure::NoRecords,
                    elapsed,
                }
            } else {
                ResolveOutcome::Resolved { ips, elapsed }
            }
        }
        Ok(Err(err)) => ResolveOutcome::Failed {
            failure: ResolveFailure::Unreachable(err.to_string()),
            elapsed,
        },
        Err(err) => ResolveOutcome::Failed {
            failure: ResolveFailure::Unreachable(format!("lookup task failed: {err}")),
            elapsed,
        },
    }
}

/// Ask every DoH reference at once. A reference that cannot be reached is a
/// result, not an error: from inside a filtered network that is the honest
/// answer.
async fn doh_lookup_all(domain: &str, timeout: Duration) -> Vec<DohAnswer> {
    let mut tasks = Vec::with_capacity(DOH_REFERENCES.len());
    for reference in DOH_REFERENCES {
        let domain = domain.to_string();
        let handle = tokio::task::spawn_blocking(move || DohAnswer {
            reference: reference.name,
            outcome: doh_lookup(*reference, &domain, timeout),
        });
        tasks.push((reference.name, handle));
    }

    let mut answers = Vec::with_capacity(tasks.len());
    for (name, handle) in tasks {
        let outcome = match handle.await {
            Ok(answer) => answer.outcome,
            Err(err) => ResolveOutcome::Failed {
                failure: ResolveFailure::Unreachable(format!("probe task failed: {err}")),
                elapsed: Duration::ZERO,
            },
        };
        answers.push(DohAnswer {
            reference: name,
            outcome,
        });
    }
    answers
}

/// One reference, both address families. Blocking: ureq is a blocking client.
fn doh_lookup(reference: DohReference, domain: &str, timeout: Duration) -> ResolveOutcome {
    let started = Instant::now();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into();

    let mut ips = Vec::new();
    let mut answered = false;
    let mut first_failure = None;

    for qtype in [wire::TYPE_A, wire::TYPE_AAAA] {
        match doh_query(&agent, reference.url, domain, qtype) {
            Ok(mut found) => {
                answered = true;
                ips.append(&mut found);
            }
            Err(failure) => {
                if first_failure.is_none() {
                    first_failure = Some(failure);
                }
            }
        }
    }

    let elapsed = started.elapsed();
    if !answered {
        return ResolveOutcome::Failed {
            failure: first_failure.unwrap_or(ResolveFailure::NoRecords),
            elapsed,
        };
    }
    let ips = dedupe(ips);
    if ips.is_empty() {
        return ResolveOutcome::Failed {
            failure: ResolveFailure::NoRecords,
            elapsed,
        };
    }
    ResolveOutcome::Resolved { ips, elapsed }
}

/// One DoH exchange: build the query, POST it, parse the answer.
fn doh_query(agent: &ureq::Agent, url: &str, domain: &str, qtype: u16) -> Result<Vec<IpAddr>, ResolveFailure> {
    let id = query_id();
    let query = wire::build_query(id, domain, qtype)
        .map_err(|err| ResolveFailure::Unreachable(format!("cannot encode the query: {err}")))?;

    let mut response = agent
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .send(&query)
        .map_err(|err| ResolveFailure::Unreachable(describe(&err)))?;

    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_DOH_BODY)
        .read_to_vec()
        .map_err(|err| ResolveFailure::Unreachable(format!("cannot read the body: {err}")))?;

    let parsed = wire::parse_response(&body)
        .map_err(|err| ResolveFailure::Unreachable(format!("malformed DNS message: {err}")))?;
    if parsed.id != id {
        return Err(ResolveFailure::Unreachable(format!(
            "answer id {} does not match query id {id}",
            parsed.id
        )));
    }
    if parsed.rcode != Rcode::NoError {
        return Err(ResolveFailure::Rcode(parsed.rcode));
    }

    Ok(parsed
        .answers
        .iter()
        .filter_map(|record| match record.data {
            RecordData::A(ip) => Some(IpAddr::V4(ip)),
            RecordData::Aaaa(ip) => Some(IpAddr::V6(ip)),
            RecordData::Other => None,
        })
        .collect())
}

/// Compare the system answer with the union of the DoH answers.
pub fn compare(system: &[IpAddr], doh: &[IpAddr]) -> Comparison {
    if system.is_empty() || doh.is_empty() {
        return Comparison::Incomplete;
    }
    let system_set: BTreeSet<IpAddr> = system.iter().copied().collect();
    let doh_set: BTreeSet<IpAddr> = doh.iter().copied().collect();
    if system_set == doh_set {
        return Comparison::Identical;
    }
    Comparison::Differ {
        system_only: system_set.difference(&doh_set).copied().collect(),
        doh_only: doh_set.difference(&system_set).copied().collect(),
    }
}

fn collect_ips(answers: &[DohAnswer]) -> Vec<IpAddr> {
    let mut set = BTreeSet::new();
    for answer in answers {
        set.extend(answer.outcome.ips().iter().copied());
    }
    set.into_iter().collect()
}

fn dedupe(mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.sort_unstable();
    ips.dedup();
    ips
}

/// A query id only has to be unlikely to collide with a stale answer on the same
/// connection; `RandomState` is seeded per process.
fn query_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos() as u64)
            .unwrap_or(0),
    );
    hasher.finish() as u16
}

fn describe(err: &ureq::Error) -> String {
    match err {
        ureq::Error::StatusCode(code) => format!("HTTP {code}"),
        ureq::Error::Timeout(_) => "timed out".to_string(),
        ureq::Error::HostNotFound => "the DoH host does not resolve".to_string(),
        ureq::Error::Io(io) => format!("I/O error: {io}"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn resolved(ips: &[IpAddr]) -> ResolveOutcome {
        ResolveOutcome::Resolved {
            ips: ips.to_vec(),
            elapsed: Duration::from_millis(10),
        }
    }

    #[test]
    fn identical_answers_compare_as_identical() {
        let system = [ip(140, 82, 121, 4)];
        let doh = [ip(140, 82, 121, 4)];
        assert_eq!(compare(&system, &doh), Comparison::Identical);
    }

    #[test]
    fn a_different_answer_is_reported_as_a_difference_not_a_verdict() {
        let system = [ip(1, 1, 1, 1), ip(2, 2, 2, 2)];
        let doh = [ip(2, 2, 2, 2), ip(3, 3, 3, 3)];
        assert_eq!(
            compare(&system, &doh),
            Comparison::Differ {
                system_only: vec![ip(1, 1, 1, 1)],
                doh_only: vec![ip(3, 3, 3, 3)],
            }
        );
    }

    #[test]
    fn a_missing_side_makes_the_comparison_incomplete() {
        assert_eq!(compare(&[], &[ip(1, 1, 1, 1)]), Comparison::Incomplete);
        assert_eq!(compare(&[ip(1, 1, 1, 1)], &[]), Comparison::Incomplete);
        assert_eq!(compare(&[], &[]), Comparison::Incomplete);
    }

    #[test]
    fn the_doh_union_deduplicates_across_references() {
        let probe = DnsProbe {
            domain: "github.com".to_string(),
            system: resolved(&[ip(140, 82, 121, 4)]),
            doh: vec![
                DohAnswer {
                    reference: "dns.google",
                    outcome: resolved(&[ip(140, 82, 121, 4), ip(140, 82, 121, 3)]),
                },
                DohAnswer {
                    reference: "cloudflare-dns.com",
                    outcome: resolved(&[ip(140, 82, 121, 4)]),
                },
            ],
            comparison: Comparison::Identical,
        };
        assert_eq!(collect_ips(&probe.doh), vec![ip(140, 82, 121, 3), ip(140, 82, 121, 4)]);
    }

    #[test]
    fn tcp_uses_the_resolved_addresses_when_there_are_any() {
        let probe = DnsProbe {
            domain: "github.com".to_string(),
            system: resolved(&[ip(140, 82, 121, 4)]),
            doh: Vec::new(),
            comparison: Comparison::Incomplete,
        };
        let (ips, source) = probe.addresses_for_tcp(&[ip(9, 9, 9, 9)]);
        assert_eq!(ips, vec![ip(140, 82, 121, 4)]);
        assert_eq!(source, IpSource::Resolved);
    }

    #[test]
    fn tcp_falls_back_to_the_recorded_addresses_when_the_resolver_fails() {
        let probe = DnsProbe {
            domain: "github.com".to_string(),
            system: ResolveOutcome::Failed {
                failure: ResolveFailure::Rcode(Rcode::NameError),
                elapsed: Duration::from_millis(3),
            },
            doh: Vec::new(),
            comparison: Comparison::Incomplete,
        };
        let (ips, source) = probe.addresses_for_tcp(&[ip(9, 9, 9, 9)]);
        assert_eq!(ips, vec![ip(9, 9, 9, 9)]);
        assert_eq!(source, IpSource::Builtin);
    }

    #[test]
    fn a_failed_outcome_holds_no_addresses() {
        let outcome = ResolveOutcome::Failed {
            failure: ResolveFailure::Unreachable("connection refused".to_string()),
            elapsed: Duration::from_millis(1),
        };
        assert!(outcome.ips().is_empty());
        assert_eq!(outcome.elapsed(), Duration::from_millis(1));
    }

    #[test]
    fn a_failure_says_what_went_wrong() {
        assert_eq!(ResolveFailure::Rcode(Rcode::NameError).to_string(), "answered NXDOMAIN");
        assert_eq!(
            ResolveFailure::Unreachable("connection refused".to_string()).to_string(),
            "unreachable: connection refused"
        );
        assert_eq!(
            ResolveFailure::NoRecords.to_string(),
            "answered with no A or AAAA records"
        );
    }

    #[test]
    fn the_reference_list_has_at_least_two_https_endpoints() {
        assert!(DOH_REFERENCES.len() >= 2);
        for reference in DOH_REFERENCES {
            assert!(reference.url.starts_with("https://"), "{} is not HTTPS", reference.name);
            assert!(
                reference.url.ends_with("/dns-query"),
                "{} is not a DoH endpoint",
                reference.name
            );
        }
    }
}
