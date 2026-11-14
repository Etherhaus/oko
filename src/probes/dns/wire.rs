//! Just enough of the DNS wire format to ask for `A` and `AAAA` records and to
//! read the answer section back.
//!
//! DoH carries these bytes unchanged inside an HTTPS body, so the codec is the
//! only part of the DNS probe that can be tested without a network. It is
//! deliberately small: no EDNS, no DNSSEC, no IDN. A name that is not ASCII is
//! rejected rather than sent as garbage.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

const CLASS_IN: u16 = 1;
const HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
/// A compression pointer must point backwards, so a walk cannot loop; the bound
/// is a second guard against a hostile message.
const MAX_POINTER_JUMPS: usize = 32;

/// The response code from the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Other(u8),
}

impl Rcode {
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            other => Rcode::Other(other),
        }
    }
}

impl serde::Serialize for Rcode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rcode::NoError => f.write_str("NOERROR"),
            Rcode::FormatError => f.write_str("FORMERR"),
            Rcode::ServerFailure => f.write_str("SERVFAIL"),
            Rcode::NameError => f.write_str("NXDOMAIN"),
            Rcode::NotImplemented => f.write_str("NOTIMP"),
            Rcode::Refused => f.write_str("REFUSED"),
            Rcode::Other(bits) => write!(f, "RCODE({bits})"),
        }
    }
}

/// Why a message could not be built or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The message ends in the middle of a field.
    Truncated,
    /// The QR bit is clear: this is a query, not a response.
    NotAResponse,
    /// A label is empty, too long, or not ASCII.
    BadLabel,
    /// The encoded name would exceed 255 bytes.
    NameTooLong,
    /// A compression pointer is malformed or points forwards.
    BadPointer,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => f.write_str("message is truncated"),
            WireError::NotAResponse => f.write_str("message is not a response"),
            WireError::BadLabel => f.write_str("label is empty, too long, or not ASCII (punycode IDN first)"),
            WireError::NameTooLong => f.write_str("name is longer than 255 bytes"),
            WireError::BadPointer => f.write_str("compression pointer is malformed"),
        }
    }
}

impl std::error::Error for WireError {}

/// The payload of one answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// A record type this codec does not decode, such as `CNAME`.
    Other,
}

/// One answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RecordData,
}

/// A parsed response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: u16,
    pub rcode: Rcode,
    pub truncated: bool,
    pub answers: Vec<Record>,
}

/// Build a recursive query for `name` and `qtype`.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    // RD: ask the resolver to recurse. Everything else stays zero.
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// Read a response. The caller is responsible for checking that [`Response::id`]
/// matches the query it sent.
pub fn parse_response(bytes: &[u8]) -> Result<Response, WireError> {
    if bytes.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    if flags & 0x8000 == 0 {
        return Err(WireError::NotAResponse);
    }
    let truncated = flags & 0x0200 != 0;
    let rcode = Rcode::from_bits((flags & 0x000f) as u8);
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);

    let mut pos = HEADER_LEN;
    for _ in 0..qdcount {
        let (_, next) = read_name(bytes, pos)?;
        // QTYPE and QCLASS follow the name.
        pos = next.checked_add(4).ok_or(WireError::Truncated)?;
        if pos > bytes.len() {
            return Err(WireError::Truncated);
        }
    }

    let mut answers = Vec::with_capacity(ancount as usize);
    for _ in 0..ancount {
        let (name, next) = read_name(bytes, pos)?;
        pos = next;
        let fixed = bytes.get(pos..pos + 10).ok_or(WireError::Truncated)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        pos += 10;
        let rdata = bytes.get(pos..pos + rdlen).ok_or(WireError::Truncated)?;
        let data = match (rtype, rdlen) {
            (TYPE_A, 4) => RecordData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            (TYPE_AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                RecordData::Aaaa(Ipv6Addr::from(octets))
            }
            _ => RecordData::Other,
        };
        answers.push(Record { name, rtype, ttl, data });
        pos += rdlen;
    }

    Ok(Response {
        id,
        rcode,
        truncated,
        answers,
    })
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), WireError> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        out.push(0);
        return Ok(());
    }
    let mut total = 1;
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_LABEL_LEN || !label.is_ascii() {
            return Err(WireError::BadLabel);
        }
        total += 1 + bytes.len();
        if total > MAX_NAME_LEN {
            return Err(WireError::NameTooLong);
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    Ok(())
}

/// Read a possibly compressed name at `start`. Returns the name and the offset
/// just past it in the original message.
fn read_name(bytes: &[u8], start: usize) -> Result<(String, usize), WireError> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut pos = start;
    let mut resume = None;
    let mut jumps = 0;
    let mut total = 1;

    loop {
        let len = *bytes.get(pos).ok_or(WireError::Truncated)?;
        match len & 0xc0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let len = len as usize;
                let label = bytes.get(pos + 1..pos + 1 + len).ok_or(WireError::Truncated)?;
                total += 1 + len;
                if total > MAX_NAME_LEN {
                    return Err(WireError::NameTooLong);
                }
                labels.push(label);
                pos += 1 + len;
            }
            0xc0 => {
                let low = *bytes.get(pos + 1).ok_or(WireError::Truncated)?;
                let target = (((len & 0x3f) as usize) << 8) | low as usize;
                if resume.is_none() {
                    resume = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS || target >= pos {
                    return Err(WireError::BadPointer);
                }
                pos = target;
            }
            _ => return Err(WireError::BadPointer),
        }
    }

    let name = labels
        .iter()
        .map(|label| String::from_utf8_lossy(label))
        .collect::<Vec<_>>()
        .join(".");
    Ok((name, resume.unwrap_or(pos)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response for `github.com A` with one answer, the name compressed to a
    /// pointer at offset 12.
    fn github_response() -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, // id
            0x81, 0x80, // QR, RD, RA, NOERROR
            0x00, 0x01, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        bytes.extend_from_slice(&[6, b'g', b'i', b't', b'h', b'u', b'b']);
        bytes.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        bytes.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to offset 12
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60
        bytes.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        bytes.extend_from_slice(&[140, 82, 121, 4]);
        bytes
    }

    #[test]
    fn a_query_is_a_header_a_name_and_a_question() {
        let query = build_query(0x1234, "github.com", TYPE_A).expect("a plain name encodes");
        assert_eq!(
            query,
            vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 6, b'g', b'i', b't', b'h',
                b'u', b'b', 3, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
            ]
        );
    }

    #[test]
    fn a_trailing_dot_encodes_the_same_as_no_dot() {
        assert_eq!(
            build_query(1, "github.com.", TYPE_A).unwrap(),
            build_query(1, "github.com", TYPE_A).unwrap()
        );
    }

    #[test]
    fn the_root_name_is_a_single_zero_byte() {
        let query = build_query(1, ".", TYPE_A).unwrap();
        assert_eq!(&query[12..13], &[0]);
    }

    #[test]
    fn a_bad_label_is_rejected() {
        assert_eq!(build_query(1, "a..b", TYPE_A), Err(WireError::BadLabel));
        assert_eq!(build_query(1, "пример.рф", TYPE_A), Err(WireError::BadLabel));
        let long = "a".repeat(64);
        assert_eq!(build_query(1, &long, TYPE_A), Err(WireError::BadLabel));
    }

    #[test]
    fn an_empty_name_is_the_root() {
        assert_eq!(
            build_query(1, "", TYPE_A).unwrap(),
            build_query(1, ".", TYPE_A).unwrap()
        );
    }

    #[test]
    fn an_overlong_name_is_rejected() {
        let name = vec!["abcdefghij"; 30].join(".");
        assert_eq!(build_query(1, &name, TYPE_A), Err(WireError::NameTooLong));
    }

    #[test]
    fn an_a_answer_is_read_back() {
        let response = parse_response(&github_response()).expect("the fixture is well formed");
        assert_eq!(response.id, 0x1234);
        assert_eq!(response.rcode, Rcode::NoError);
        assert!(!response.truncated);
        assert_eq!(response.answers.len(), 1);
        let answer = &response.answers[0];
        assert_eq!(answer.name, "github.com");
        assert_eq!(answer.rtype, TYPE_A);
        assert_eq!(answer.ttl, 60);
        assert_eq!(answer.data, RecordData::A(Ipv4Addr::new(140, 82, 121, 4)));
    }

    #[test]
    fn an_aaaa_answer_is_read_back() {
        let mut bytes = github_response();
        // Rewrite the answer as AAAA with 16 bytes of address.
        let answer_start = bytes.len() - 4 - 10 - 2;
        bytes.truncate(answer_start);
        bytes.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01]);
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c, 0x00, 0x10]);
        bytes.extend_from_slice(&[0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01]);
        bytes.extend_from_slice(&[0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46]);
        let response = parse_response(&bytes).expect("the fixture is well formed");
        assert_eq!(
            response.answers[0].data,
            RecordData::Aaaa("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap())
        );
    }

    #[test]
    fn a_name_without_compression_is_read_back() {
        let mut bytes = github_response();
        // Replace the pointer with the literal name, and fix nothing else: the
        // answer name is the only compressed field.
        let answer_start = bytes.len() - 4 - 10 - 2;
        bytes.truncate(answer_start);
        bytes.extend_from_slice(&[6, b'g', b'i', b't', b'h', b'u', b'b', 3, b'c', b'o', b'm', 0]);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04]);
        bytes.extend_from_slice(&[140, 82, 121, 4]);
        let response = parse_response(&bytes).expect("the fixture is well formed");
        assert_eq!(response.answers[0].name, "github.com");
    }

    #[test]
    fn a_cname_chain_keeps_the_addresses_and_marks_the_rest() {
        let mut bytes = github_response();
        let answer_start = bytes.len() - 4 - 10 - 2;
        bytes.truncate(answer_start);
        bytes[7] = 2; // ANCOUNT = 2
        // CNAME answer, name compressed, rdata is a literal name.
        bytes.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02]);
        bytes.extend_from_slice(&[0xc0, 0x0c]);
        // A answer for the same name.
        bytes.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04]);
        bytes.extend_from_slice(&[140, 82, 121, 4]);
        let response = parse_response(&bytes).expect("the fixture is well formed");
        assert_eq!(response.answers.len(), 2);
        assert_eq!(response.answers[0].data, RecordData::Other);
        assert_eq!(response.answers[1].data, RecordData::A(Ipv4Addr::new(140, 82, 121, 4)));
    }

    #[test]
    fn an_error_response_carries_its_code_and_no_answers() {
        let mut bytes = github_response();
        bytes[3] = 0x83; // rcode 3, NXDOMAIN
        bytes[7] = 0; // ANCOUNT = 0
        bytes.truncate(HEADER_LEN + 17);
        let response = parse_response(&bytes).expect("the fixture is well formed");
        assert_eq!(response.rcode, Rcode::NameError);
        assert!(response.answers.is_empty());
        assert_eq!(Rcode::NameError.to_string(), "NXDOMAIN");
    }

    #[test]
    fn a_truncated_message_is_an_error_not_a_panic() {
        let bytes = github_response();
        for cut in 0..bytes.len() {
            // Every prefix either parses or fails; none may panic.
            let _ = parse_response(&bytes[..cut]);
        }
        assert_eq!(parse_response(&bytes[..HEADER_LEN - 1]), Err(WireError::Truncated));
    }

    #[test]
    fn a_query_is_not_a_response() {
        let query = build_query(1, "github.com", TYPE_A).unwrap();
        assert_eq!(parse_response(&query), Err(WireError::NotAResponse));
    }

    #[test]
    fn a_forward_pointer_is_rejected() {
        let mut bytes = github_response();
        // Point the answer name at itself: a pointer must go backwards.
        let answer_start = bytes.len() - 4 - 10 - 2;
        bytes[answer_start] = 0xc0;
        bytes[answer_start + 1] = answer_start as u8;
        assert_eq!(parse_response(&bytes), Err(WireError::BadPointer));
    }

    #[test]
    fn a_reserved_label_type_is_rejected() {
        let mut bytes = github_response();
        let answer_start = bytes.len() - 4 - 10 - 2;
        bytes[answer_start] = 0x80;
        assert_eq!(parse_response(&bytes), Err(WireError::BadPointer));
    }
}
