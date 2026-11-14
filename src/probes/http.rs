//! HTTP probe: does a plain HTTP/1.1 request survive when the `Host` header
//! names the service, and does it survive when the header names a known-good
//! one?
//!
//! The request goes to port 80 on the address the TCP probe reached. A redirect
//! is a perfectly good answer: this probe asks whether the request got through,
//! not what the server decided to do with it.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::format;
use crate::route::Route;

/// Enough for a status line and the headers that follow it.
const MAX_RESPONSE: usize = 16 * 1024;
const READ_BUFFER: usize = 4 * 1024;

/// What came back for one `Host` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpOutcome {
    /// The server answered with a status line.
    Response {
        status: u16,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The connection ended before a single response byte.
    Reset {
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// Nothing came back before the timeout.
    Timeout {
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The probe could not run, or the answer was not HTTP.
    Failed {
        reason: String,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
}

impl HttpOutcome {
    pub fn elapsed(&self) -> Duration {
        match self {
            HttpOutcome::Response { elapsed, .. }
            | HttpOutcome::Reset { elapsed }
            | HttpOutcome::Timeout { elapsed }
            | HttpOutcome::Failed { elapsed, .. } => *elapsed,
        }
    }

    /// True when the server answered with a status line.
    pub fn responded(&self) -> bool {
        matches!(self, HttpOutcome::Response { .. })
    }

    pub fn describe(&self) -> String {
        let elapsed = format::duration(self.elapsed());
        match self {
            HttpOutcome::Response { status, .. } => format!("HTTP {status} ({elapsed})"),
            HttpOutcome::Reset { .. } => format!("the connection ended before a response ({elapsed})"),
            HttpOutcome::Timeout { .. } => format!("no answer ({elapsed})"),
            HttpOutcome::Failed { reason, .. } => format!("failed: {reason} ({elapsed})"),
        }
    }
}

/// One request with one `Host` header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpAttempt {
    pub host: String,
    pub outcome: HttpOutcome,
}

/// The request with the real `Host`, and the retry with the control one when
/// the first did not get an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpProbe {
    pub domain: String,
    pub ip: IpAddr,
    pub port: u16,
    pub real: HttpAttempt,
    pub control: Option<HttpAttempt>,
}

impl HttpProbe {
    pub fn real_responded(&self) -> bool {
        self.real.outcome.responded()
    }

    pub fn control_responded(&self) -> bool {
        self.control.as_ref().is_some_and(|attempt| attempt.outcome.responded())
    }
}

/// Request `domain` as the `Host`. When that gets no answer, try again with
/// `control_host` on the same address.
pub async fn probe(
    domain: &str,
    ip: IpAddr,
    port: u16,
    control_host: &str,
    timeout: Duration,
    route: Route,
) -> HttpProbe {
    let real = HttpAttempt {
        host: domain.to_string(),
        outcome: attempt(ip, port, domain, timeout, route).await,
    };
    let control = if real.outcome.responded() {
        None
    } else {
        Some(HttpAttempt {
            host: control_host.to_string(),
            outcome: attempt(ip, port, control_host, timeout, route).await,
        })
    };
    HttpProbe {
        domain: domain.to_string(),
        ip,
        port,
        real,
        control,
    }
}

async fn attempt(ip: IpAddr, port: u16, host: &str, timeout: Duration, route: Route) -> HttpOutcome {
    let started = Instant::now();
    let deadline = started + timeout;
    let addr = SocketAddr::new(ip, port);

    let mut stream = match tokio::time::timeout_at(deadline.into(), route.connect(addr, timeout)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            return HttpOutcome::Failed {
                reason: format!("connect: {err}"),
                elapsed: started.elapsed(),
            };
        }
        Err(_) => {
            return HttpOutcome::Timeout {
                elapsed: started.elapsed(),
            };
        }
    };

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: oko/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    if let Err(err) = stream.write_all(request.as_bytes()).await {
        return HttpOutcome::Failed {
            reason: format!("cannot send the request: {err}"),
            elapsed: started.elapsed(),
        };
    }

    let mut response = Vec::new();
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        let read = match tokio::time::timeout_at(deadline.into(), stream.read(&mut buffer)).await {
            Ok(Ok(read)) => read,
            Ok(Err(err)) => return read_failed(&err, &response, started),
            Err(_) => {
                return HttpOutcome::Timeout {
                    elapsed: started.elapsed(),
                };
            }
        };
        if read == 0 {
            return ended(&response, started);
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(status) = parse_status_line(&response) {
            return HttpOutcome::Response {
                status,
                elapsed: started.elapsed(),
            };
        }
        if response.len() >= MAX_RESPONSE {
            return HttpOutcome::Failed {
                reason: format!("no status line in {MAX_RESPONSE} bytes"),
                elapsed: started.elapsed(),
            };
        }
    }
}

fn ended(response: &[u8], started: Instant) -> HttpOutcome {
    let elapsed = started.elapsed();
    if response.is_empty() {
        HttpOutcome::Reset { elapsed }
    } else {
        HttpOutcome::Failed {
            reason: "the connection closed before a status line".to_string(),
            elapsed,
        }
    }
}

fn read_failed(err: &std::io::Error, response: &[u8], started: Instant) -> HttpOutcome {
    let elapsed = started.elapsed();
    if !response.is_empty() {
        return HttpOutcome::Failed {
            reason: format!("the connection broke after {} bytes", response.len()),
            elapsed,
        };
    }
    match err.kind() {
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof => HttpOutcome::Reset { elapsed },
        ErrorKind::TimedOut => HttpOutcome::Timeout { elapsed },
        _ => HttpOutcome::Failed {
            reason: err.to_string(),
            elapsed,
        },
    }
}

/// Read the status code out of `HTTP/1.x NNN ...`. Returns `None` while the
/// first line is still incomplete, or when the answer is not HTTP at all.
pub fn parse_status_line(response: &[u8]) -> Option<u16> {
    let end = response.windows(2).position(|window| window == b"\r\n")?;
    let line = std::str::from_utf8(&response[..end]).ok()?;
    let mut parts = line.split(' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    code.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_line_is_read() {
        assert_eq!(parse_status_line(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status_line(b"HTTP/1.0 301 Moved Permanently\r\n"), Some(301));
        assert_eq!(parse_status_line(b"HTTP/1.1 404 Not Found\r\nServer: x\r\n"), Some(404));
    }

    #[test]
    fn a_status_line_without_a_reason_phrase_is_read() {
        assert_eq!(parse_status_line(b"HTTP/1.1 204\r\n"), Some(204));
    }

    #[test]
    fn an_incomplete_status_line_is_not_read_yet() {
        assert_eq!(parse_status_line(b""), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 200"), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 2"), None);
    }

    #[test]
    fn something_that_is_not_http_is_not_read() {
        assert_eq!(parse_status_line(b"garbage\r\n"), None);
        assert_eq!(parse_status_line(b"\r\n"), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 abc OK\r\n"), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 2000 OK\r\n"), None);
        assert_eq!(parse_status_line(&[0xff, 0xfe, b'\r', b'\n']), None);
    }

    #[test]
    fn a_response_reached_the_server() {
        let outcome = HttpOutcome::Response {
            status: 301,
            elapsed: Duration::from_millis(85),
        };
        assert!(outcome.responded());
        assert_eq!(outcome.describe(), "HTTP 301 (85 ms)");
    }

    #[test]
    fn a_reset_did_not_reach_the_server() {
        let outcome = HttpOutcome::Reset {
            elapsed: Duration::from_millis(5),
        };
        assert!(!outcome.responded());
        assert_eq!(outcome.describe(), "the connection ended before a response (5 ms)");
    }

    #[test]
    fn a_timeout_did_not_reach_the_server() {
        let outcome = HttpOutcome::Timeout {
            elapsed: Duration::from_millis(5_000),
        };
        assert!(!outcome.responded());
        assert_eq!(outcome.describe(), "no answer (5.0 s)");
    }

    #[test]
    fn a_probe_without_a_control_attempt_has_no_control_answer() {
        let probe = HttpProbe {
            domain: "github.com".to_string(),
            ip: "140.82.121.4".parse().unwrap(),
            port: 80,
            real: HttpAttempt {
                host: "github.com".to_string(),
                outcome: HttpOutcome::Response {
                    status: 301,
                    elapsed: Duration::from_millis(85),
                },
            },
            control: None,
        };
        assert!(probe.real_responded());
        assert!(!probe.control_responded());
    }

    #[test]
    fn a_control_attempt_that_answered_is_visible() {
        let probe = HttpProbe {
            domain: "github.com".to_string(),
            ip: "140.82.121.4".parse().unwrap(),
            port: 80,
            real: HttpAttempt {
                host: "github.com".to_string(),
                outcome: HttpOutcome::Reset {
                    elapsed: Duration::from_millis(5),
                },
            },
            control: Some(HttpAttempt {
                host: "yandex.ru".to_string(),
                outcome: HttpOutcome::Response {
                    status: 200,
                    elapsed: Duration::from_millis(40),
                },
            }),
        };
        assert!(!probe.real_responded());
        assert!(probe.control_responded());
    }
}
