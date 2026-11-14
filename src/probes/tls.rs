//! TLS probe: does the server answer a handshake, and does it answer when the
//! name in the ClientHello is a known-good one?
//!
//! The classification is deliberately not about certificate validity. A
//! certificate that does not cover the name still proves the handshake reached
//! the server, which is the only thing this probe asks. What matters is whether
//! the server said anything at all after the ClientHello: a middlebox that
//! objects to the name kills the connection before the server can speak.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::format;
use crate::route::Route;

/// How much of the server's answer to read in one go.
const READ_BUFFER: usize = 16 * 1024;

/// What the server did with our ClientHello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsOutcome {
    /// The handshake completed and the certificate covers the name.
    Ok {
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The server sent TLS records, so the handshake reached it, but it did not
    /// complete cleanly. `cert_mismatch` says the certificate does not cover the
    /// name we asked for, which is expected when that name is the control one.
    ServerResponded {
        cert_mismatch: bool,
        /// What rustls said about the answer, for the report.
        detail: String,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The connection ended after the ClientHello and before a single server
    /// record: a reset, or a close. Either way the server never spoke.
    RstAfterClientHello {
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// Nothing came back before the timeout.
    Timeout {
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The server answered with a TLS alert.
    TlsAlert {
        code: u8,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The probe could not run: a bad name, a failed connect, a broken record.
    Failed {
        reason: String,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
}

impl TlsOutcome {
    pub fn elapsed(&self) -> Duration {
        match self {
            TlsOutcome::Ok { elapsed }
            | TlsOutcome::ServerResponded { elapsed, .. }
            | TlsOutcome::RstAfterClientHello { elapsed }
            | TlsOutcome::Timeout { elapsed }
            | TlsOutcome::TlsAlert { elapsed, .. }
            | TlsOutcome::Failed { elapsed, .. } => *elapsed,
        }
    }

    /// True when the server itself answered, whatever it answered. This is the
    /// signal that separates a middlebox from a server.
    pub fn reached_server(&self) -> bool {
        matches!(
            self,
            TlsOutcome::Ok { .. } | TlsOutcome::ServerResponded { .. } | TlsOutcome::TlsAlert { .. }
        )
    }

    pub fn describe(&self) -> String {
        let elapsed = format::duration(self.elapsed());
        match self {
            TlsOutcome::Ok { .. } => format!("handshake completed ({elapsed})"),
            TlsOutcome::ServerResponded {
                cert_mismatch: true, ..
            } => format!("the server answered, the certificate does not cover the name ({elapsed})"),
            TlsOutcome::ServerResponded { detail, .. } => format!("the server answered: {detail} ({elapsed})"),
            TlsOutcome::RstAfterClientHello { .. } => {
                format!("the connection ended after the ClientHello ({elapsed})")
            }
            TlsOutcome::Timeout { .. } => format!("no answer ({elapsed})"),
            TlsOutcome::TlsAlert { code, .. } => format!("TLS alert {code} ({elapsed})"),
            TlsOutcome::Failed { reason, .. } => format!("failed: {reason} ({elapsed})"),
        }
    }
}

/// One handshake with one name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsAttempt {
    pub sni: String,
    pub outcome: TlsOutcome,
}

/// The handshake with the real name, and the retry with the control name when
/// the first one did not reach the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsProbe {
    pub domain: String,
    pub ip: IpAddr,
    pub port: u16,
    pub real: TlsAttempt,
    pub control: Option<TlsAttempt>,
}

impl TlsProbe {
    /// True when the control name got an answer on the same address.
    pub fn control_reached_server(&self) -> bool {
        self.control
            .as_ref()
            .is_some_and(|attempt| attempt.outcome.reached_server())
    }
}

/// Handshake with `domain` as the SNI. When that does not reach the server, try
/// again with `control_sni` on the same address: if the server answers the
/// control name, the name is what the path objects to.
pub async fn probe(
    domain: &str,
    ip: IpAddr,
    port: u16,
    control_sni: &str,
    timeout: Duration,
    route: Route,
) -> TlsProbe {
    let real = TlsAttempt {
        sni: domain.to_string(),
        outcome: attempt(ip, port, domain, timeout, route).await,
    };
    let control = if real.outcome.reached_server() {
        None
    } else {
        Some(TlsAttempt {
            sni: control_sni.to_string(),
            outcome: attempt(ip, port, control_sni, timeout, route).await,
        })
    };
    TlsProbe {
        domain: domain.to_string(),
        ip,
        port,
        real,
        control,
    }
}

/// The root store is built once: it holds every trust anchor webpki knows, and
/// rebuilding it per probe would cost more than the probe.
fn config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// A completed handshake, with the connection still open.
pub struct Handshake {
    pub stream: TcpStream,
    pub conn: ClientConnection,
    /// Bytes the server sent during the handshake. The payload probe adds them
    /// to the body to report the whole stream size.
    pub server_bytes: usize,
    pub elapsed: Duration,
}

/// Handshake with `sni` and hand the live connection back. The caller owns it
/// from here: the payload probe sends a request over it.
pub async fn handshake(
    ip: IpAddr,
    port: u16,
    sni: &str,
    timeout: Duration,
    route: Route,
) -> Result<Handshake, TlsOutcome> {
    let started = Instant::now();
    let deadline = started + timeout;

    let name = match ServerName::try_from(sni.to_owned()) {
        Ok(name) => name,
        Err(err) => {
            return Err(TlsOutcome::Failed {
                reason: format!("{sni} is not a usable server name: {err}"),
                elapsed: started.elapsed(),
            });
        }
    };
    let mut conn = match ClientConnection::new(config(), name) {
        Ok(conn) => conn,
        Err(err) => {
            return Err(TlsOutcome::Failed {
                reason: format!("cannot start the handshake: {err}"),
                elapsed: started.elapsed(),
            });
        }
    };

    let addr = SocketAddr::new(ip, port);
    let mut stream = match tokio::time::timeout_at(deadline.into(), route.connect(addr, timeout)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return Err(TlsOutcome::Failed {
                reason: format!("connect: {err}"),
                elapsed: started.elapsed(),
            });
        }
        Err(_) => {
            return Err(TlsOutcome::Timeout {
                elapsed: started.elapsed(),
            });
        }
    };

    let mut out = Vec::new();
    if let Err(err) = conn.write_tls(&mut out) {
        return Err(TlsOutcome::Failed {
            reason: format!("cannot build the ClientHello: {err}"),
            elapsed: started.elapsed(),
        });
    }
    if let Err(err) = stream.write_all(&out).await {
        return Err(TlsOutcome::Failed {
            reason: format!("cannot send the ClientHello: {err}"),
            elapsed: started.elapsed(),
        });
    }

    let mut buffer = vec![0u8; READ_BUFFER];
    let mut server_bytes = 0usize;

    loop {
        let read = match tokio::time::timeout_at(deadline.into(), stream.read(&mut buffer)).await {
            Ok(Ok(read)) => read,
            Ok(Err(err)) => return Err(read_failed(&err, server_bytes, started)),
            Err(_) => return Err(stalled(server_bytes, started)),
        };
        if read == 0 {
            return Err(closed(server_bytes, started));
        }
        server_bytes += read;

        // rustls reads into a bounded internal buffer, so one call can take
        // less than we offer. Feed the whole chunk, draining in between: a
        // dropped remainder would stall the handshake until the deadline.
        let mut chunk = &buffer[..read];
        while !chunk.is_empty() {
            match conn.read_tls(&mut chunk) {
                Ok(0) => {
                    return Err(TlsOutcome::Failed {
                        reason: "the TLS buffer is full and cannot be drained".to_string(),
                        elapsed: started.elapsed(),
                    });
                }
                Ok(_) => {
                    if let Err(err) = conn.process_new_packets() {
                        return Err(classify_error(err, started));
                    }
                }
                Err(err) => {
                    return Err(TlsOutcome::Failed {
                        reason: format!("cannot parse the server record: {err}"),
                        elapsed: started.elapsed(),
                    });
                }
            }
        }

        if let Err(err) = conn.process_new_packets() {
            return Err(classify_error(err, started));
        }

        let mut out = Vec::new();
        while conn.wants_write() {
            if conn.write_tls(&mut out).is_err() {
                break;
            }
        }
        if !out.is_empty() && stream.write_all(&out).await.is_err() {
            return Err(TlsOutcome::Failed {
                reason: "cannot send the handshake reply".to_string(),
                elapsed: started.elapsed(),
            });
        }
        if !conn.is_handshaking() {
            return Ok(Handshake {
                stream,
                conn,
                server_bytes,
                elapsed: started.elapsed(),
            });
        }
    }
}

/// One handshake, reduced to what the TLS probe reports.
async fn attempt(ip: IpAddr, port: u16, sni: &str, timeout: Duration, route: Route) -> TlsOutcome {
    match handshake(ip, port, sni, timeout, route).await {
        Ok(done) => TlsOutcome::Ok { elapsed: done.elapsed },
        Err(outcome) => outcome,
    }
}

/// The deadline passed. Whether the server had already spoken decides between
/// "the server answered" and "something killed the connection".
fn stalled(server_bytes: usize, started: Instant) -> TlsOutcome {
    let elapsed = started.elapsed();
    if server_bytes == 0 {
        TlsOutcome::Timeout { elapsed }
    } else {
        TlsOutcome::ServerResponded {
            cert_mismatch: false,
            detail: "the server answered, then the handshake stalled until the deadline".to_string(),
            elapsed,
        }
    }
}

/// The peer closed the connection. Same split as [`stalled`].
fn closed(server_bytes: usize, started: Instant) -> TlsOutcome {
    let elapsed = started.elapsed();
    if server_bytes == 0 {
        TlsOutcome::RstAfterClientHello { elapsed }
    } else {
        TlsOutcome::ServerResponded {
            cert_mismatch: false,
            detail: "the server answered, then closed the connection in the middle of the handshake".to_string(),
            elapsed,
        }
    }
}

fn read_failed(err: &std::io::Error, server_bytes: usize, started: Instant) -> TlsOutcome {
    let elapsed = started.elapsed();
    if server_bytes > 0 {
        return TlsOutcome::ServerResponded {
            cert_mismatch: false,
            detail: format!("the connection broke in the middle of the handshake: {err}"),
            elapsed,
        };
    }
    match err.kind() {
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof => TlsOutcome::RstAfterClientHello { elapsed },
        ErrorKind::TimedOut => TlsOutcome::Timeout { elapsed },
        _ => TlsOutcome::Failed {
            reason: err.to_string(),
            elapsed,
        },
    }
}

fn classify_error(err: rustls::Error, started: Instant) -> TlsOutcome {
    let elapsed = started.elapsed();
    match err {
        rustls::Error::AlertReceived(alert) => TlsOutcome::TlsAlert {
            code: u8::from(alert),
            elapsed,
        },
        rustls::Error::InvalidCertificate(cert) => {
            let cert_mismatch = matches!(
                cert,
                rustls::CertificateError::NotValidForName | rustls::CertificateError::NotValidForNameContext { .. }
            );
            TlsOutcome::ServerResponded {
                cert_mismatch,
                // The full rustls message lists every name in the certificate,
                // which buries the report. The mismatch case says it in one line.
                detail: if cert_mismatch {
                    "the certificate does not cover the name".to_string()
                } else {
                    format!("certificate rejected: {cert}")
                },
                elapsed,
            }
        }
        other => TlsOutcome::ServerResponded {
            cert_mismatch: false,
            detail: other.to_string(),
            elapsed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elapsed() -> Duration {
        Duration::from_millis(12)
    }

    #[test]
    fn a_completed_handshake_reached_the_server() {
        let outcome = TlsOutcome::Ok { elapsed: elapsed() };
        assert!(outcome.reached_server());
        assert_eq!(outcome.describe(), "handshake completed (12 ms)");
    }

    #[test]
    fn a_certificate_mismatch_still_reached_the_server() {
        let outcome = TlsOutcome::ServerResponded {
            cert_mismatch: true,
            detail: "certificate rejected: NotValidForName".to_string(),
            elapsed: elapsed(),
        };
        assert!(outcome.reached_server());
        assert_eq!(
            outcome.describe(),
            "the server answered, the certificate does not cover the name (12 ms)"
        );
    }

    #[test]
    fn an_alert_reached_the_server() {
        let outcome = TlsOutcome::TlsAlert {
            code: 112,
            elapsed: elapsed(),
        };
        assert!(outcome.reached_server());
        assert_eq!(outcome.describe(), "TLS alert 112 (12 ms)");
    }

    #[test]
    fn a_reset_after_the_client_hello_did_not_reach_the_server() {
        let outcome = TlsOutcome::RstAfterClientHello { elapsed: elapsed() };
        assert!(!outcome.reached_server());
        assert_eq!(outcome.describe(), "the connection ended after the ClientHello (12 ms)");
    }

    #[test]
    fn a_timeout_did_not_reach_the_server() {
        let outcome = TlsOutcome::Timeout { elapsed: elapsed() };
        assert!(!outcome.reached_server());
        assert_eq!(outcome.describe(), "no answer (12 ms)");
    }

    #[test]
    fn a_local_failure_is_neither_a_server_answer_nor_a_kill() {
        let outcome = TlsOutcome::Failed {
            reason: "connect: refused".to_string(),
            elapsed: elapsed(),
        };
        assert!(!outcome.reached_server());
        assert_eq!(outcome.describe(), "failed: connect: refused (12 ms)");
    }

    #[test]
    fn a_deadline_without_a_single_server_byte_is_a_timeout() {
        let outcome = stalled(0, Instant::now());
        assert!(!outcome.reached_server());
        assert!(matches!(outcome, TlsOutcome::Timeout { .. }));
    }

    #[test]
    fn a_deadline_after_the_server_spoke_is_a_server_answer() {
        let outcome = stalled(1200, Instant::now());
        assert!(outcome.reached_server());
        assert!(matches!(
            outcome,
            TlsOutcome::ServerResponded {
                cert_mismatch: false,
                ..
            }
        ));
    }

    #[test]
    fn a_close_without_a_single_server_byte_is_a_kill_after_the_client_hello() {
        let outcome = closed(0, Instant::now());
        assert!(!outcome.reached_server());
        assert!(matches!(outcome, TlsOutcome::RstAfterClientHello { .. }));
    }

    #[test]
    fn a_close_after_the_server_spoke_is_a_server_answer() {
        let outcome = closed(1200, Instant::now());
        assert!(outcome.reached_server());
        assert!(matches!(
            outcome,
            TlsOutcome::ServerResponded {
                cert_mismatch: false,
                ..
            }
        ));
    }

    #[test]
    fn a_probe_without_a_control_attempt_has_no_control_answer() {
        let probe = TlsProbe {
            domain: "github.com".to_string(),
            ip: "140.82.121.4".parse().unwrap(),
            port: 443,
            real: TlsAttempt {
                sni: "github.com".to_string(),
                outcome: TlsOutcome::Ok { elapsed: elapsed() },
            },
            control: None,
        };
        assert!(probe.real.outcome.reached_server());
        assert!(!probe.control_reached_server());
    }

    #[test]
    fn a_control_attempt_that_answered_is_visible() {
        let probe = TlsProbe {
            domain: "github.com".to_string(),
            ip: "140.82.121.4".parse().unwrap(),
            port: 443,
            real: TlsAttempt {
                sni: "github.com".to_string(),
                outcome: TlsOutcome::RstAfterClientHello { elapsed: elapsed() },
            },
            control: Some(TlsAttempt {
                sni: "yandex.ru".to_string(),
                outcome: TlsOutcome::ServerResponded {
                    cert_mismatch: true,
                    detail: "certificate rejected: NotValidForName".to_string(),
                    elapsed: elapsed(),
                },
            }),
        };
        assert!(!probe.real.outcome.reached_server());
        assert!(probe.control_reached_server());
    }
}
