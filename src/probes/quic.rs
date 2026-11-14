//! QUIC probe: does the server answer a QUIC packet on UDP 443?
//!
//! This is a research probe, not a verdict. A QUIC server that receives a
//! packet with a version it does not speak may answer with a Version
//! Negotiation packet; many do, some do not. Silence therefore proves nothing:
//! a NAT, a provider or the server itself may drop UDP with no blocking
//! involved. The report says so instead of calling silence a block.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::net::UdpSocket;

use crate::format;

/// A version no server speaks, from the range RFC 9000 reserves for exactly
/// this: exercising version negotiation.
pub const GREASE_VERSION: u32 = 0x1a2a_3a4a;

/// RFC 9000 asks for Initial datagrams of at least 1200 bytes.
pub const MIN_DATAGRAM: usize = 1200;

/// The connection ID length this probe uses.
const CONNECTION_ID_LEN: usize = 8;

/// A QUIC long-header packet with a version no server speaks.
///
/// The payload is not a valid Initial: the point is the header, which is all a
/// server needs to answer with a version negotiation. Nothing here is a
/// handshake, and nothing here tries to get through anything.
pub fn initial_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(MIN_DATAGRAM);
    // Long header, fixed bit, packet type Initial.
    packet.push(0xc0);
    packet.extend_from_slice(&GREASE_VERSION.to_be_bytes());
    packet.push(CONNECTION_ID_LEN as u8);
    packet.extend_from_slice(&[0x11; CONNECTION_ID_LEN]);
    packet.push(CONNECTION_ID_LEN as u8);
    packet.extend_from_slice(&[0x22; CONNECTION_ID_LEN]);
    // Token length 0.
    packet.push(0x00);
    let payload = MIN_DATAGRAM - packet.len() - 2;
    packet.extend_from_slice(&encode_varint(payload as u64));
    packet.resize(MIN_DATAGRAM, 0);
    packet
}

/// A QUIC variable-length integer in its two-byte form. Every value this probe
/// writes is below 16 KB, so the two-byte form is enough.
pub fn encode_varint(value: u64) -> [u8; 2] {
    let value = value as u16 & 0x3fff;
    [(0x40 | (value >> 8) as u8), (value & 0xff) as u8]
}

/// What the server answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicAnswer {
    /// A Version Negotiation packet: the server speaks QUIC and listed the
    /// versions it supports.
    VersionNegotiation { versions: Vec<u32> },
    /// Some other QUIC packet.
    Other,
}

/// Read a QUIC answer. A Version Negotiation packet has version 0 and a list of
/// four-byte versions after the connection IDs.
pub fn parse_answer(bytes: &[u8]) -> QuicAnswer {
    if bytes.len() < 5 || bytes[0] & 0x80 == 0 {
        return QuicAnswer::Other;
    }
    let version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if version != 0 {
        return QuicAnswer::Other;
    }

    let mut offset = 5;
    for _ in 0..2 {
        let Some(&len) = bytes.get(offset) else {
            return QuicAnswer::VersionNegotiation { versions: Vec::new() };
        };
        offset += 1 + len as usize;
    }
    let versions = bytes
        .get(offset..)
        .unwrap_or(&[])
        .chunks_exact(4)
        .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    QuicAnswer::VersionNegotiation { versions }
}

/// What the QUIC probe saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuicOutcome {
    /// The server answered with a QUIC packet.
    Answered {
        answer: QuicAnswer,
        bytes: usize,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// Nothing came back before the deadline. This is not a verdict.
    Silent {
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
    /// The probe could not run.
    Failed {
        reason: String,
        #[serde(serialize_with = "crate::json::millis")]
        elapsed: Duration,
    },
}

impl QuicOutcome {
    pub fn elapsed(&self) -> Duration {
        match self {
            QuicOutcome::Answered { elapsed, .. }
            | QuicOutcome::Silent { elapsed }
            | QuicOutcome::Failed { elapsed, .. } => *elapsed,
        }
    }

    pub fn describe(&self) -> String {
        let elapsed = format::duration(self.elapsed());
        match self {
            QuicOutcome::Answered {
                answer: QuicAnswer::VersionNegotiation { versions },
                ..
            } => {
                let versions = if versions.is_empty() {
                    "none listed".to_string()
                } else {
                    versions
                        .iter()
                        .map(|version| format!("{version:#010x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                format!("the server answered with a version negotiation (versions: {versions}) ({elapsed})")
            }
            QuicOutcome::Answered { .. } => format!("the server answered with a QUIC packet ({elapsed})"),
            QuicOutcome::Silent { .. } => format!("no answer ({elapsed})"),
            QuicOutcome::Failed { reason, .. } => format!("failed: {reason} ({elapsed})"),
        }
    }

    /// What a reader must not conclude from this outcome.
    pub fn note(&self) -> &'static str {
        match self {
            QuicOutcome::Answered { .. } => "the server speaks QUIC on this port",
            QuicOutcome::Silent { .. } => {
                "UDP silence is not a verdict: a NAT, a provider or the server itself may drop it legitimately"
            }
            QuicOutcome::Failed { .. } => "the probe could not run, so it says nothing about the path",
        }
    }
}

/// One QUIC probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuicProbe {
    pub domain: String,
    pub ip: IpAddr,
    pub port: u16,
    pub outcome: QuicOutcome,
}

/// Send one packet and wait for an answer from the target address.
pub async fn probe(domain: &str, ip: IpAddr, port: u16, timeout: Duration) -> QuicProbe {
    let started = Instant::now();
    let deadline = started + timeout;
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };

    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(err) => {
            return QuicProbe {
                domain: domain.to_string(),
                ip,
                port,
                outcome: QuicOutcome::Failed {
                    reason: format!("cannot open a UDP socket: {err}"),
                    elapsed: started.elapsed(),
                },
            };
        }
    };

    let target = SocketAddr::new(ip, port);
    if let Err(err) = socket.send_to(&initial_packet(), target).await {
        return QuicProbe {
            domain: domain.to_string(),
            ip,
            port,
            outcome: QuicOutcome::Failed {
                reason: format!("cannot send the packet: {err}"),
                elapsed: started.elapsed(),
            },
        };
    }

    let mut buffer = [0u8; 2048];
    loop {
        let received = match tokio::time::timeout_at(deadline.into(), socket.recv_from(&mut buffer)).await {
            Ok(Ok(received)) => received,
            Ok(Err(err)) => {
                return QuicProbe {
                    domain: domain.to_string(),
                    ip,
                    port,
                    outcome: QuicOutcome::Failed {
                        reason: err.to_string(),
                        elapsed: started.elapsed(),
                    },
                };
            }
            Err(_) => {
                return QuicProbe {
                    domain: domain.to_string(),
                    ip,
                    port,
                    outcome: QuicOutcome::Silent {
                        elapsed: started.elapsed(),
                    },
                };
            }
        };
        let (read, from) = received;
        if from.ip() != ip {
            // A datagram from somewhere else is not an answer from the target.
            continue;
        }
        return QuicProbe {
            domain: domain.to_string(),
            ip,
            port,
            outcome: QuicOutcome::Answered {
                answer: parse_answer(&buffer[..read]),
                bytes: read,
                elapsed: started.elapsed(),
            },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version_negotiation(versions: &[u32]) -> Vec<u8> {
        let mut packet = vec![0x80, 0x00, 0x00, 0x00, 0x00];
        packet.push(8);
        packet.extend_from_slice(&[0xaa; 8]);
        packet.push(8);
        packet.extend_from_slice(&[0xbb; 8]);
        for version in versions {
            packet.extend_from_slice(&version.to_be_bytes());
        }
        packet
    }

    #[test]
    fn the_packet_is_a_long_header_initial_of_the_minimum_size() {
        let packet = initial_packet();
        assert_eq!(packet.len(), MIN_DATAGRAM);
        assert_eq!(packet[0], 0xc0);
        assert_eq!(&packet[1..5], &GREASE_VERSION.to_be_bytes());
        assert_eq!(packet[5], CONNECTION_ID_LEN as u8);
        assert_eq!(packet[14], CONNECTION_ID_LEN as u8);
    }

    #[test]
    fn a_two_byte_varint_carries_the_payload_length() {
        assert_eq!(encode_varint(1174), [0x44, 0x96]);
        assert_eq!(encode_varint(0), [0x40, 0x00]);
        assert_eq!(encode_varint(16383), [0x7f, 0xff]);
    }

    #[test]
    fn a_version_negotiation_is_read_with_its_versions() {
        let answer = parse_answer(&version_negotiation(&[0x0000_0001, GREASE_VERSION]));
        assert_eq!(
            answer,
            QuicAnswer::VersionNegotiation {
                versions: vec![0x0000_0001, GREASE_VERSION]
            }
        );
    }

    #[test]
    fn a_version_negotiation_without_versions_is_still_one() {
        assert_eq!(
            parse_answer(&version_negotiation(&[])),
            QuicAnswer::VersionNegotiation { versions: Vec::new() }
        );
    }

    #[test]
    fn a_short_header_is_not_a_version_negotiation() {
        assert_eq!(parse_answer(&[0x40, 0x00, 0x00, 0x00, 0x00]), QuicAnswer::Other);
        assert_eq!(parse_answer(&[]), QuicAnswer::Other);
    }

    #[test]
    fn a_packet_with_a_real_version_is_not_a_version_negotiation() {
        let mut packet = version_negotiation(&[0x0000_0001]);
        packet[1..5].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        assert_eq!(parse_answer(&packet), QuicAnswer::Other);
    }

    #[test]
    fn an_answer_reads_as_an_answer() {
        let outcome = QuicOutcome::Answered {
            answer: QuicAnswer::VersionNegotiation {
                versions: vec![0x0000_0001],
            },
            bytes: 40,
            elapsed: Duration::from_millis(98),
        };
        assert!(matches!(outcome, QuicOutcome::Answered { .. }));
        assert_eq!(
            outcome.describe(),
            "the server answered with a version negotiation (versions: 0x00000001) (98 ms)"
        );
    }

    #[test]
    fn silence_reads_as_silence_and_says_what_it_is_not() {
        let outcome = QuicOutcome::Silent {
            elapsed: Duration::from_millis(5_000),
        };
        assert!(!matches!(outcome, QuicOutcome::Answered { .. }));
        assert_eq!(outcome.describe(), "no answer (5.0 s)");
        assert!(outcome.note().contains("not a verdict"));
    }
}
