//! Payload probe: after a TLS handshake, how much of the body arrives before
//! the connection ends?
//!
//! The l4-25 family of blocks cuts a connection after a fixed amount of data.
//! The ranges this probe knows are 16–20 KB and around 25 KB. The probe asks
//! for a page, reads up to 64 KB, and records where the stream stopped.
//!
//! A stream that ends inside one of those ranges is only suspicious when the
//! response is still incomplete: a server that sent a 17 KB page and closed is
//! doing its job. That is why the probe reads the announced `Content-Length`
//! (or the chunked terminator) before it calls a drop a drop.

use std::io::{ErrorKind, Read, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::format;
use crate::probes::tls;
use crate::route::Route;

/// How much of the body to read before calling the path healthy.
pub const TARGET_BYTES: usize = 64 * 1024;

/// The ranges a l4-25 block cuts in, in bytes. The second one is approximate, so
/// it gets a margin on both sides.
pub const RANGE_16_20: (usize, usize) = (16 * 1024, 20 * 1024);
pub const RANGE_25: (usize, usize) = (24 * 1024, 26 * 1024);

/// How much to read from the socket in one go.
const READ_BUFFER: usize = 16 * 1024;

/// Which known range a stream size falls in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DropRange {
    /// 16–20 KB.
    SixteenToTwenty,
    /// Around 25 KB.
    TwentyFive,
}

impl DropRange {
    pub fn describe(self) -> &'static str {
        match self {
            DropRange::SixteenToTwenty => "16–20 KB",
            DropRange::TwentyFive => "around 25 KB",
        }
    }
}

/// Which known range a stream size falls in, if any.
///
/// Both the body alone and the body plus the handshake are checked: a middlebox
/// counts the whole stream, while the brief names the body, and the two differ
/// by the size of the certificate flight.
pub fn drop_range(body: usize, total: usize) -> Option<DropRange> {
    fn range(value: usize) -> Option<DropRange> {
        if (RANGE_16_20.0..=RANGE_16_20.1).contains(&value) {
            Some(DropRange::SixteenToTwenty)
        } else if (RANGE_25.0..=RANGE_25.1).contains(&value) {
            Some(DropRange::TwentyFive)
        } else {
            None
        }
    }
    range(body).or_else(|| range(total))
}

/// What the payload probe saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadOutcome {
    /// The probe read its whole target amount: the path carried it.
    Complete {
        body: usize,
        total: usize,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The stream ended inside a known l4-25 range with the response incomplete.
    KbDrop {
        body: usize,
        total: usize,
        range: DropRange,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The response arrived in full.
    Ended {
        body: usize,
        total: usize,
        /// How the stream ended, when it ended with something other than a
        /// clean close. A TLS record error after a complete response is a
        /// server or middlebox quirk, not a block, but it is worth keeping.
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The stream ended outside the known ranges with the response incomplete.
    Truncated {
        body: usize,
        total: usize,
        detail: String,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// Nothing more arrived before the deadline.
    Stalled {
        body: usize,
        total: usize,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The handshake did not complete, so there was no body to read.
    NotAttempted { reason: String },
    /// The probe could not run.
    Failed {
        reason: String,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
}

impl PayloadOutcome {
    pub fn describe(&self) -> String {
        match self {
            PayloadOutcome::Complete { body, total, elapsed } => format!(
                "the body arrived in full: {} ({} with the handshake) ({})",
                format::kilobytes(*body),
                format::kilobytes(*total),
                format::duration(*elapsed)
            ),
            PayloadOutcome::KbDrop {
                body,
                total,
                range,
                elapsed,
            } => format!(
                "the body ended after {} ({} with the handshake), inside the {} range ({})",
                format::kilobytes(*body),
                format::kilobytes(*total),
                range.describe(),
                format::duration(*elapsed)
            ),
            PayloadOutcome::Ended {
                body,
                total,
                note,
                elapsed,
            } => {
                let mut text = format!(
                    "the response arrived in full: {} ({} with the handshake) ({})",
                    format::kilobytes(*body),
                    format::kilobytes(*total),
                    format::duration(*elapsed)
                );
                if let Some(note) = note {
                    text.push_str(&format!(", then the stream ended: {note}"));
                }
                text
            }
            PayloadOutcome::Truncated {
                body,
                total,
                detail,
                elapsed,
            } => format!(
                "the body ended after {} ({} with the handshake), outside the known ranges: {detail} ({})",
                format::kilobytes(*body),
                format::kilobytes(*total),
                format::duration(*elapsed)
            ),
            PayloadOutcome::Stalled { body, total, elapsed } => format!(
                "the body stopped after {} ({} with the handshake) ({})",
                format::kilobytes(*body),
                format::kilobytes(*total),
                format::duration(*elapsed)
            ),
            PayloadOutcome::NotAttempted { reason } => format!("not attempted: {reason}"),
            PayloadOutcome::Failed { reason, elapsed } => {
                format!("failed: {reason} ({})", format::duration(*elapsed))
            }
        }
    }
}

/// One payload probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayloadProbe {
    pub domain: String,
    pub ip: IpAddr,
    pub port: u16,
    pub outcome: PayloadOutcome,
}

impl PayloadProbe {
    /// A probe that did not run, with the reason the report will show.
    pub fn not_attempted(domain: &str, ip: IpAddr, port: u16, reason: impl Into<String>) -> Self {
        PayloadProbe {
            domain: domain.to_string(),
            ip,
            port,
            outcome: PayloadOutcome::NotAttempted { reason: reason.into() },
        }
    }
}

/// Handshake, ask for the page, and read until the target amount, the end of
/// the stream, or the deadline.
pub async fn probe(domain: &str, ip: IpAddr, port: u16, timeout: Duration, route: Route) -> PayloadProbe {
    let started = Instant::now();
    let done = match tls::handshake(ip, port, domain, timeout, route).await {
        Ok(done) => done,
        Err(outcome) => return PayloadProbe::not_attempted(domain, ip, port, outcome.describe()),
    };
    let tls::Handshake {
        mut stream,
        mut conn,
        server_bytes,
        ..
    } = done;
    let deadline = started + timeout;

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: oko/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    if let Err(err) = send(&mut conn, &mut stream, request.as_bytes()).await {
        return PayloadProbe {
            domain: domain.to_string(),
            ip,
            port,
            outcome: PayloadOutcome::Failed {
                reason: format!("cannot send the request: {err}"),
                elapsed: started.elapsed(),
            },
        };
    }

    let outcome = read_body(&mut conn, &mut stream, server_bytes, deadline, started).await;
    PayloadProbe {
        domain: domain.to_string(),
        ip,
        port,
        outcome,
    }
}

/// Read the response until the target amount, the end of the stream, or the
/// deadline.
async fn read_body(
    conn: &mut rustls::ClientConnection,
    stream: &mut tokio::net::TcpStream,
    handshake: usize,
    deadline: Instant,
    started: Instant,
) -> PayloadOutcome {
    let mut response = Vec::new();
    let mut buffer = vec![0u8; READ_BUFFER];

    loop {
        // 1. Take whatever plaintext rustls already holds.
        match drain(conn, &mut response) {
            Ok(true) => {
                return ended(&response, handshake, false, "the server closed the session", started);
            }
            Ok(false) => {}
            Err(reason) => return after_tls_error(&response, handshake, reason, started),
        }
        if response.len() >= TARGET_BYTES {
            return PayloadOutcome::Complete {
                body: response.len(),
                total: handshake + response.len(),
                elapsed: started.elapsed(),
            };
        }

        // 2. No plaintext: read more records from the socket.
        let read = match tokio::time::timeout_at(deadline.into(), stream.read(&mut buffer)).await {
            Ok(Ok(read)) => read,
            Ok(Err(err)) => return ended(&response, handshake, true, &err.to_string(), started),
            Err(_) => return stalled(&response, handshake, started),
        };
        if read == 0 {
            return ended(
                &response,
                handshake,
                true,
                "the peer closed the connection without a TLS close_notify",
                started,
            );
        }
        match feed(conn, &buffer[..read], &mut response) {
            Ok(true) => {
                return ended(&response, handshake, false, "the server closed the session", started);
            }
            Ok(false) => {}
            Err(reason) => return after_tls_error(&response, handshake, reason, started),
        }
    }
}

/// Write plaintext through rustls and flush the records to the socket.
async fn send(
    conn: &mut rustls::ClientConnection,
    stream: &mut tokio::net::TcpStream,
    plaintext: &[u8],
) -> std::io::Result<()> {
    conn.writer().write_all(plaintext)?;
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out)?;
    }
    stream.write_all(&out).await
}

/// Feed one chunk of TLS records to rustls, taking the plaintext out after
/// every record.
///
/// rustls refuses to take more records once its plaintext buffer holds more
/// than 16 KB, and one 16 KB chunk can decrypt into slightly more than that, so
/// the buffer has to be drained as the chunk is consumed. Returns `true` when
/// the server closed the session with a `close_notify`.
fn feed(conn: &mut rustls::ClientConnection, chunk: &[u8], response: &mut Vec<u8>) -> Result<bool, String> {
    let mut chunk = chunk;
    while !chunk.is_empty() {
        match conn.read_tls(&mut chunk) {
            Ok(0) => return Ok(false),
            Ok(_) => {
                if let Err(err) = conn.process_new_packets() {
                    return Err(format!("the TLS session failed: {err}"));
                }
                if drain(conn, response)? {
                    return Ok(true);
                }
            }
            Err(err) => return Err(format!("cannot parse the server record: {err}")),
        }
    }
    Ok(false)
}

/// Take whatever plaintext rustls holds into the response. Returns `true` when
/// the server closed the session with a `close_notify`.
fn drain(conn: &mut rustls::ClientConnection, response: &mut Vec<u8>) -> Result<bool, String> {
    let mut buffer = [0u8; READ_BUFFER];
    loop {
        match conn.reader().read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(read) => response.extend_from_slice(&buffer[..read]),
            Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(err) => return Err(err.to_string()),
        }
    }
}

/// The stream ended. Whether that is a block depends on whether the response
/// was complete and where the stream stopped.
fn ended(response: &[u8], handshake: usize, abrupt: bool, detail: &str, started: Instant) -> PayloadOutcome {
    let body = response.len();
    let total = handshake + body;
    let elapsed = started.elapsed();
    let suspicious = match response_complete(response) {
        Some(true) => false,
        Some(false) => true,
        None => abrupt,
    };
    if suspicious {
        if let Some(range) = drop_range(body, total) {
            return PayloadOutcome::KbDrop {
                body,
                total,
                range,
                elapsed,
            };
        }
        return PayloadOutcome::Truncated {
            body,
            total,
            detail: detail.to_string(),
            elapsed,
        };
    }
    PayloadOutcome::Ended {
        body,
        total,
        note: None,
        elapsed,
    }
}

/// The TLS session failed mid-stream. A record that cannot be decrypted ends
/// the stream just like a reset does, so the same rules apply: a complete
/// response followed by a bad record is a quirk of the server or the path, not
/// a block, and nothing read at all is a failure.
fn after_tls_error(response: &[u8], handshake: usize, reason: String, started: Instant) -> PayloadOutcome {
    if response.is_empty() {
        return PayloadOutcome::Failed {
            reason,
            elapsed: started.elapsed(),
        };
    }
    let mut outcome = ended(response, handshake, true, &reason, started);
    if let PayloadOutcome::Ended { note, .. } = &mut outcome {
        *note = Some(reason);
    }
    outcome
}

/// Nothing more arrived before the deadline. A stall inside a known range is
/// the same signature as a reset there.
fn stalled(response: &[u8], handshake: usize, started: Instant) -> PayloadOutcome {
    let body = response.len();
    let total = handshake + body;
    let elapsed = started.elapsed();
    if let Some(range) = drop_range(body, total) {
        return PayloadOutcome::KbDrop {
            body,
            total,
            range,
            elapsed,
        };
    }
    PayloadOutcome::Stalled { body, total, elapsed }
}

/// Whether the received bytes hold a complete HTTP response.
///
/// `Some(true)` when the announced length arrived or the chunked terminator was
/// seen, `Some(false)` when the response announced more than arrived, `None`
/// when it announced no length at all.
pub fn response_complete(response: &[u8]) -> Option<bool> {
    let head_end = response.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&response[..head_end]).ok()?;
    let body = &response[head_end + 4..];

    let mut chunked = false;
    let mut length = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            length = value.parse::<usize>().ok();
        } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }

    if chunked {
        return Some(body.ends_with(b"0\r\n\r\n"));
    }
    length.map(|length| body.len() >= length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kb(count: usize) -> usize {
        count * 1024
    }

    fn response(length: usize, body: usize) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n").into_bytes();
        response.extend(std::iter::repeat_n(b'x', body));
        response
    }

    #[test]
    fn the_sixteen_to_twenty_range_is_recognised() {
        assert_eq!(drop_range(kb(16), kb(21)), Some(DropRange::SixteenToTwenty));
        assert_eq!(drop_range(kb(18), kb(23)), Some(DropRange::SixteenToTwenty));
        assert_eq!(drop_range(kb(20), kb(25)), Some(DropRange::SixteenToTwenty));
    }

    #[test]
    fn the_twenty_five_range_is_recognised() {
        assert_eq!(drop_range(kb(25), kb(30)), Some(DropRange::TwentyFive));
        assert_eq!(drop_range(kb(24), kb(29)), Some(DropRange::TwentyFive));
        assert_eq!(drop_range(kb(26), kb(31)), Some(DropRange::TwentyFive));
    }

    #[test]
    fn a_size_outside_the_ranges_is_not_a_drop() {
        assert_eq!(drop_range(kb(15), kb(15)), None);
        assert_eq!(drop_range(kb(30), kb(35)), None);
        assert_eq!(drop_range(0, 0), None);
    }

    #[test]
    fn the_whole_stream_size_can_carry_the_range() {
        // A middlebox that counts the handshake cuts the body earlier than the
        // brief's range; the total still lands in it.
        assert_eq!(drop_range(kb(11), kb(16)), Some(DropRange::SixteenToTwenty));
    }

    #[test]
    fn a_response_that_announced_its_length_and_delivered_it_is_complete() {
        assert_eq!(response_complete(&response(100, 100)), Some(true));
        assert_eq!(response_complete(&response(0, 0)), Some(true));
    }

    #[test]
    fn a_response_that_announced_more_than_it_delivered_is_incomplete() {
        assert_eq!(response_complete(&response(100, 40)), Some(false));
    }

    #[test]
    fn a_chunked_response_is_complete_only_with_its_terminator() {
        let mut complete = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        complete.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(response_complete(&complete), Some(true));

        let mut incomplete = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        incomplete.extend_from_slice(b"5\r\nhello\r\n");
        assert_eq!(response_complete(&incomplete), Some(false));
    }

    #[test]
    fn a_response_without_a_length_says_nothing() {
        let response = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody".to_vec();
        assert_eq!(response_complete(&response), None);
        assert_eq!(response_complete(b"HTTP/1.1 200"), None);
        assert_eq!(response_complete(b""), None);
    }

    #[test]
    fn a_complete_response_that_ends_inside_a_range_is_not_a_drop() {
        let response = response(kb(17), kb(17));
        let outcome = ended(&response, kb(5), false, "the server closed the session", Instant::now());
        assert!(matches!(outcome, PayloadOutcome::Ended { .. }), "{outcome:?}");
    }

    #[test]
    fn an_incomplete_response_that_ends_inside_a_range_is_a_drop() {
        let response = response(kb(40), kb(17));
        let head = response.len() - kb(17);
        let outcome = ended(&response, kb(5), true, "reset", Instant::now());
        match outcome {
            PayloadOutcome::KbDrop { body, total, range, .. } => {
                assert_eq!(body, kb(17) + head);
                assert_eq!(total, kb(22) + head);
                assert_eq!(range, DropRange::SixteenToTwenty);
            }
            other => panic!("expected a drop, got {other:?}"),
        }
    }

    #[test]
    fn an_incomplete_response_outside_the_ranges_is_truncated() {
        let response = response(kb(60), kb(30));
        let outcome = ended(&response, kb(5), true, "reset", Instant::now());
        assert!(matches!(outcome, PayloadOutcome::Truncated { .. }), "{outcome:?}");
    }

    #[test]
    fn a_tls_error_after_a_complete_response_is_not_a_failure() {
        let response = response(0, 0);
        let reason = "the TLS session failed: cannot decrypt peer's message".to_string();
        let outcome = after_tls_error(&response, kb(5), reason.clone(), Instant::now());
        match outcome {
            PayloadOutcome::Ended { note, .. } => assert_eq!(note, Some(reason)),
            other => panic!("expected the response to count as complete, got {other:?}"),
        }
    }

    #[test]
    fn a_tls_error_before_any_response_is_a_failure() {
        let outcome = after_tls_error(b"", kb(5), "the TLS session failed".to_string(), Instant::now());
        assert!(matches!(outcome, PayloadOutcome::Failed { .. }), "{outcome:?}");
    }

    #[test]
    fn a_tls_error_inside_a_range_with_an_incomplete_response_is_a_drop() {
        let response = response(kb(40), kb(17));
        let outcome = after_tls_error(&response, kb(5), "bad record".to_string(), Instant::now());
        assert!(matches!(outcome, PayloadOutcome::KbDrop { .. }), "{outcome:?}");
    }

    #[test]
    fn an_ended_stream_with_a_note_says_how_it_ended() {
        let outcome = PayloadOutcome::Ended {
            body: kb(2),
            total: kb(3),
            note: Some("the TLS session failed: cannot decrypt peer's message".to_string()),
            elapsed: Duration::from_millis(1400),
        };
        assert_eq!(
            outcome.describe(),
            "the response arrived in full: 2.0 KB (3.0 KB with the handshake) (1.4 s), \
             then the stream ended: the TLS session failed: cannot decrypt peer's message"
        );
    }

    #[test]
    fn a_stall_inside_a_range_is_a_drop() {
        let response = response(kb(40), kb(17));
        let outcome = stalled(&response, kb(5), Instant::now());
        assert!(matches!(outcome, PayloadOutcome::KbDrop { .. }), "{outcome:?}");
    }

    #[test]
    fn a_stall_outside_the_ranges_is_a_stall() {
        let response = response(kb(60), kb(8));
        let outcome = stalled(&response, kb(5), Instant::now());
        assert!(matches!(outcome, PayloadOutcome::Stalled { .. }), "{outcome:?}");
    }

    #[test]
    fn a_probe_that_did_not_run_says_why() {
        let probe = PayloadProbe::not_attempted(
            "youtube.com",
            "172.217.19.238".parse().unwrap(),
            443,
            "the handshake was killed",
        );
        assert_eq!(probe.outcome.describe(), "not attempted: the handshake was killed");
    }

    #[test]
    fn a_drop_reads_as_a_drop() {
        let outcome = PayloadOutcome::KbDrop {
            body: kb(17),
            total: kb(22),
            range: DropRange::SixteenToTwenty,
            elapsed: Duration::from_millis(900),
        };
        assert_eq!(
            outcome.describe(),
            "the body ended after 17.0 KB (22.0 KB with the handshake), inside the 16–20 KB range (900 ms)"
        );
    }
}
