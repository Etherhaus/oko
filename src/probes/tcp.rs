//! TCP probe: can a connection be opened to the address, and how long does it
//! take.
//!
//! A successful connect says the path to that address is open. It says nothing
//! about TLS or HTTP, which is why the later probes exist: a middlebox that
//! resets a connection on a name still lets the TCP handshake through.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::task::JoinSet;

use super::dns::IpSource;

/// How many addresses of one target to try. A CDN can return a dozen; trying
/// every one of them turns a probe into a scan.
pub const MAX_ADDRESSES_PER_TARGET: usize = 4;

/// What happened when we tried to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOutcome {
    /// The handshake completed.
    Connected { elapsed: Duration },
    /// The peer answered with a reset.
    Refused { elapsed: Duration },
    /// Nothing came back before the timeout.
    Timeout { elapsed: Duration },
    /// The operating system has no route to this address. On a host without
    /// IPv6 this is what every IPv6 address reports, and it says nothing about
    /// blocking, so it is kept apart from a failure.
    NoRoute { elapsed: Duration },
    /// Anything else the operating system reported.
    Failed { reason: String, elapsed: Duration },
}

impl TcpOutcome {
    pub fn elapsed(&self) -> Duration {
        match self {
            TcpOutcome::Connected { elapsed }
            | TcpOutcome::Refused { elapsed }
            | TcpOutcome::Timeout { elapsed }
            | TcpOutcome::NoRoute { elapsed }
            | TcpOutcome::Failed { elapsed, .. } => *elapsed,
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, TcpOutcome::Connected { .. })
    }
}

/// One connect attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpProbe {
    pub domain: String,
    pub ip: IpAddr,
    pub port: u16,
    /// Where `ip` came from, so the report can say when it is not the resolver.
    pub source: IpSource,
    pub outcome: TcpOutcome,
}

impl TcpProbe {
    /// `address:port`, with an IPv6 address in brackets so the port stays
    /// readable.
    pub fn label(&self) -> String {
        match self.ip {
            IpAddr::V4(ip) => format!("{ip}:{}", self.port),
            IpAddr::V6(ip) => format!("[{ip}]:{}", self.port),
        }
    }
}

/// Try every address, up to [`MAX_ADDRESSES_PER_TARGET`], at once.
pub async fn probe_all(domain: &str, ips: &[IpAddr], port: u16, source: IpSource, timeout: Duration) -> Vec<TcpProbe> {
    let mut set = JoinSet::new();
    for ip in ips.iter().take(MAX_ADDRESSES_PER_TARGET).copied() {
        let domain = domain.to_string();
        set.spawn(async move { probe(&domain, ip, port, source, timeout).await });
    }

    let mut probes = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(probe) = joined {
            probes.push(probe);
        }
    }
    probes.sort_by_key(|probe| probe.ip);
    probes
}

/// One connect attempt to `ip:port`. The socket is closed as soon as it opens:
/// this probe measures reachability, not a session.
pub async fn probe(domain: &str, ip: IpAddr, port: u16, source: IpSource, timeout: Duration) -> TcpProbe {
    let started = Instant::now();
    let addr = SocketAddr::new(ip, port);

    let outcome = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let elapsed = started.elapsed();
            drop(stream);
            TcpOutcome::Connected { elapsed }
        }
        Ok(Err(err)) => {
            let elapsed = started.elapsed();
            match err.kind() {
                ErrorKind::ConnectionRefused => TcpOutcome::Refused { elapsed },
                ErrorKind::TimedOut => TcpOutcome::Timeout { elapsed },
                ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::AddrNotAvailable => {
                    TcpOutcome::NoRoute { elapsed }
                }
                _ => TcpOutcome::Failed {
                    reason: err.to_string(),
                    elapsed,
                },
            }
        }
        Err(_) => TcpOutcome::Timeout {
            elapsed: started.elapsed(),
        },
    };

    TcpProbe {
        domain: domain.to_string(),
        ip,
        port,
        source,
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn an_outcome_reports_its_own_timing() {
        let elapsed = Duration::from_millis(42);
        assert_eq!(TcpOutcome::Connected { elapsed }.elapsed(), elapsed);
        assert_eq!(TcpOutcome::Refused { elapsed }.elapsed(), elapsed);
        assert_eq!(TcpOutcome::Timeout { elapsed }.elapsed(), elapsed);
        assert_eq!(TcpOutcome::NoRoute { elapsed }.elapsed(), elapsed);
        assert_eq!(
            TcpOutcome::Failed {
                reason: "network unreachable".to_string(),
                elapsed
            }
            .elapsed(),
            elapsed
        );
    }

    #[test]
    fn only_a_completed_handshake_counts_as_connected() {
        let elapsed = Duration::from_millis(1);
        assert!(TcpOutcome::Connected { elapsed }.is_connected());
        assert!(!TcpOutcome::Refused { elapsed }.is_connected());
        assert!(!TcpOutcome::Timeout { elapsed }.is_connected());
        assert!(!TcpOutcome::NoRoute { elapsed }.is_connected());
    }

    #[test]
    fn a_probe_labels_itself_with_its_address() {
        let probe = TcpProbe {
            domain: "github.com".to_string(),
            ip: IpAddr::V4(Ipv4Addr::new(140, 82, 121, 4)),
            port: 443,
            source: IpSource::Resolved,
            outcome: TcpOutcome::Connected {
                elapsed: Duration::from_millis(20),
            },
        };
        assert_eq!(probe.label(), "140.82.121.4:443");
    }

    #[test]
    fn an_ipv6_address_is_bracketed_so_the_port_stays_readable() {
        let probe = TcpProbe {
            domain: "yandex.ru".to_string(),
            ip: "2a02:6b8:a::a".parse().unwrap(),
            port: 443,
            source: IpSource::Resolved,
            outcome: TcpOutcome::NoRoute {
                elapsed: Duration::ZERO,
            },
        };
        assert_eq!(probe.label(), "[2a02:6b8:a::a]:443");
    }

    #[tokio::test]
    async fn probing_no_addresses_yields_no_probes() {
        let probes = probe_all("github.com", &[], 443, IpSource::Resolved, Duration::from_millis(50)).await;
        assert!(probes.is_empty());
    }

    #[tokio::test]
    async fn a_closed_local_port_is_refused_or_timed_out_but_never_connected() {
        // Port 1 on loopback is closed on any sane machine. The point of the
        // test is that the probe returns a classified outcome instead of an
        // error, not which of the two it is.
        let probes = probe_all(
            "localhost",
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            1,
            IpSource::Resolved,
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(probes.len(), 1);
        assert!(!probes[0].outcome.is_connected());
    }
}
