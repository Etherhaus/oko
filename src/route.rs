//! How a probe reaches a target: directly, or through a SOCKS5 proxy.
//!
//! The proxy exists for one reason: comparing what the same probe sees on two
//! paths. A service that fails directly and works through a tunnel is blocked
//! on the path; a service that fails on both is refusing this network itself.
//! Oko never uses the tunnel to get around a block — it only measures the
//! difference.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The SOCKS version this client speaks.
const SOCKS5: u8 = 0x05;
/// "No authentication required".
const METHOD_NONE: u8 = 0x00;
/// The CONNECT command.
const CMD_CONNECT: u8 = 0x01;
/// Address types.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// The reply code that means the proxy opened the connection.
const REPLY_SUCCEEDED: u8 = 0x00;

/// Where a probe sends its packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Straight from this host.
    Direct,
    /// Through a SOCKS5 proxy at this address.
    Socks5(SocketAddr),
}

impl Route {
    /// Open a TCP connection to `addr`, directly or through the proxy.
    ///
    /// The proxy is asked to connect to the address, not to the name: the
    /// tunnel run reuses the addresses the direct run resolved, so that the two
    /// runs differ in the path and in nothing else.
    pub async fn connect(self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        match self {
            Route::Direct => tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| timed_out("the connection timed out"))?,
            Route::Socks5(proxy) => {
                let mut stream = tokio::time::timeout(timeout, TcpStream::connect(proxy))
                    .await
                    .map_err(|_| timed_out("the proxy did not accept the connection"))??;
                socks5_connect(&mut stream, addr).await?;
                Ok(stream)
            }
        }
    }
}

/// The greeting: version 5, one method offered, no authentication.
pub fn greeting() -> [u8; 3] {
    [SOCKS5, 0x01, METHOD_NONE]
}

/// A CONNECT request for `addr`.
pub fn connect_request(addr: SocketAddr) -> Vec<u8> {
    let mut out = vec![SOCKS5, CMD_CONNECT, 0x00];
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// Read the method selection reply: the version and the chosen method.
pub fn parse_method_reply(bytes: &[u8]) -> Result<u8, String> {
    if bytes.len() < 2 {
        return Err("the proxy sent a short method reply".to_string());
    }
    if bytes[0] != SOCKS5 {
        return Err(format!("the proxy answered SOCKS version {}", bytes[0]));
    }
    Ok(bytes[1])
}

/// Read the reply code out of a CONNECT reply.
pub fn parse_connect_reply(bytes: &[u8]) -> Result<u8, String> {
    if bytes.len() < 4 {
        return Err("the proxy sent a short reply".to_string());
    }
    if bytes[0] != SOCKS5 {
        return Err(format!("the proxy answered SOCKS version {}", bytes[0]));
    }
    Ok(bytes[1])
}

/// What a CONNECT reply code means, in the words of RFC 1928.
pub fn reply_description(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown reply code",
    }
}

async fn socks5_connect(stream: &mut TcpStream, addr: SocketAddr) -> io::Result<()> {
    stream.write_all(&greeting()).await?;

    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    let method = parse_method_reply(&method).map_err(refused)?;
    if method != METHOD_NONE {
        return Err(refused(format!(
            "the proxy requires authentication method {method:#04x}, which oko does not speak"
        )));
    }

    stream.write_all(&connect_request(addr)).await?;
    let code = read_connect_reply(stream).await?;
    if code != REPLY_SUCCEEDED {
        return Err(refused(format!(
            "the proxy refused: {} ({code:#04x})",
            reply_description(code)
        )));
    }
    Ok(())
}

/// Read a CONNECT reply: four fixed bytes, the bound address, the bound port.
async fn read_connect_reply(stream: &mut TcpStream) -> io::Result<u8> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let code = parse_connect_reply(&head).map_err(refused)?;

    let address_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        other => {
            return Err(refused(format!(
                "the proxy answered address type {other:#04x}, which is not in RFC 1928"
            )));
        }
    };
    let mut rest = vec![0u8; address_len + 2];
    stream.read_exact(&mut rest).await?;
    Ok(code)
}

fn timed_out(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

fn refused(message: String) -> io::Error {
    io::Error::other(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("a literal socket address")
    }

    #[test]
    fn the_greeting_offers_no_authentication() {
        assert_eq!(greeting(), [0x05, 0x01, 0x00]);
    }

    #[test]
    fn an_ipv4_connect_request_carries_the_address_and_the_port() {
        let request = connect_request(addr("140.82.121.4:443"));
        assert_eq!(request, vec![0x05, 0x01, 0x00, 0x01, 140, 82, 121, 4, 0x01, 0xbb]);
    }

    #[test]
    fn an_ipv6_connect_request_carries_sixteen_address_bytes() {
        let request = connect_request(addr("[2a00:1450:400f:808::200e]:443"));
        assert_eq!(request.len(), 4 + 16 + 2);
        assert_eq!(request[3], ATYP_IPV6);
        assert_eq!(
            &request[4..20],
            &[
                0x2a, 0x00, 0x14, 0x50, 0x40, 0x0f, 0x08, 0x08, 0, 0, 0, 0, 0, 0, 0x20, 0x0e
            ]
        );
        assert_eq!(&request[20..], &[0x01, 0xbb]);
    }

    #[test]
    fn a_method_reply_names_the_chosen_method() {
        assert_eq!(parse_method_reply(&[0x05, 0x00]), Ok(0x00));
        assert_eq!(parse_method_reply(&[0x05, 0x02]), Ok(0x02));
    }

    #[test]
    fn a_method_reply_from_another_protocol_is_rejected() {
        assert!(parse_method_reply(&[0x04, 0x00]).is_err());
        assert!(parse_method_reply(&[0x05]).is_err());
    }

    #[test]
    fn a_connect_reply_names_its_code() {
        assert_eq!(parse_connect_reply(&[0x05, 0x00, 0x00, 0x01]), Ok(0x00));
        assert_eq!(parse_connect_reply(&[0x05, 0x05, 0x00, 0x01]), Ok(0x05));
        assert!(parse_connect_reply(&[0x05, 0x00]).is_err());
        assert!(parse_connect_reply(&[0x04, 0x00, 0x00, 0x01]).is_err());
    }

    #[test]
    fn every_reply_code_has_words() {
        assert_eq!(reply_description(0x05), "connection refused");
        assert_eq!(reply_description(0x03), "network unreachable");
        assert_eq!(reply_description(0x7f), "unknown reply code");
    }
}
