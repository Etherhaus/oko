//! The built-in list of targets.
//!
//! A target is a domain plus the port the probes talk to. Services are the
//! point of the measurement; controls are expected to be reachable from the
//! user's network, so they prove the network is alive and give the probes a
//! known-good name to compare against.

use std::net::{IpAddr, Ipv4Addr};

use serde::Serialize;

/// Every probe in this tool speaks to 443 unless a target says otherwise.
pub const DEFAULT_PORT: u16 = 443;

/// When the built-in addresses below were recorded. They are a fallback for a
/// broken system resolver, not a source of truth: CDN addresses move.
pub const KNOWN_IPS_RECORDED: &str = "2026-11-14";

/// What a target is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// A service whose reachability is the point of the measurement.
    Service,
    /// A target that is expected to be reachable from the user's network.
    Control,
}

/// One thing to probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    pub domain: String,
    pub port: u16,
    pub role: Role,
    /// Addresses recorded when the list was written. Used only when the system
    /// resolver returns nothing, so that a broken resolver does not hide an
    /// IP-level block. The report always says where an address came from.
    pub known_ips: Vec<IpAddr>,
}

impl Target {
    /// `domain:port`, the way the report names a target.
    pub fn label(&self) -> String {
        format!("{}:{}", self.domain, self.port)
    }
}

const fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// The starting list: six services that are commonly blocked or throttled in
/// Russia, and three controls that are not.
pub fn builtin() -> Vec<Target> {
    vec![
        Target {
            domain: "youtube.com".to_string(),
            port: DEFAULT_PORT,
            role: Role::Service,
            known_ips: vec![ip(172, 217, 19, 238)],
        },
        Target {
            domain: "discord.com".to_string(),
            port: DEFAULT_PORT,
            role: Role::Service,
            known_ips: vec![ip(162, 159, 128, 233)],
        },
        Target {
            domain: "github.com".to_string(),
            port: DEFAULT_PORT,
            role: Role::Service,
            known_ips: vec![ip(140, 82, 121, 4)],
        },
        Target {
            domain: "x.com".to_string(),
            port: DEFAULT_PORT,
            role: Role::Service,
            known_ips: vec![ip(162, 159, 140, 229)],
        },
        Target {
            domain: "facebook.com".to_string(),
            port: DEFAULT_PORT,
            role: Role::Service,
            known_ips: vec![ip(31, 13, 72, 36)],
        },
        Target {
            domain: "wikipedia.org".to_string(),
            port: DEFAULT_PORT,
            role: Role::Service,
            known_ips: vec![ip(185, 15, 59, 224)],
        },
        Target {
            domain: "yandex.ru".to_string(),
            port: DEFAULT_PORT,
            role: Role::Control,
            known_ips: vec![ip(77, 88, 55, 88)],
        },
        Target {
            domain: "vk.com".to_string(),
            port: DEFAULT_PORT,
            role: Role::Control,
            known_ips: vec![ip(87, 240, 129, 133)],
        },
        Target {
            domain: "mail.ru".to_string(),
            port: DEFAULT_PORT,
            role: Role::Control,
            known_ips: vec![ip(185, 180, 201, 1)],
        },
    ]
}

/// The built-in target for `domain`, if the list has one. Matching ignores case
/// and a trailing dot, because both are legal in a domain name.
pub fn lookup(domain: &str) -> Option<Target> {
    let wanted = normalise(domain);
    builtin().into_iter().find(|target| target.domain == wanted)
}

/// A target for a domain that is not in the built-in list. It has no recorded
/// addresses, so the probes rely on the system resolver alone.
pub fn ad_hoc(domain: &str) -> Target {
    Target {
        domain: normalise(domain),
        port: DEFAULT_PORT,
        role: Role::Service,
        known_ips: Vec::new(),
    }
}

/// The name the probes use as a known-good SNI and `Host` header.
pub fn control() -> Target {
    builtin()
        .into_iter()
        .find(|target| target.role == Role::Control)
        .expect("the built-in list always holds at least one control")
}

fn normalise(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_list_holds_services_and_controls() {
        let targets = builtin();
        let services = targets.iter().filter(|t| t.role == Role::Service).count();
        let controls = targets.iter().filter(|t| t.role == Role::Control).count();
        assert_eq!(services, 6, "the brief asks for six services");
        assert!(controls >= 2, "the brief asks for two or three controls");
    }

    #[test]
    fn every_builtin_target_has_a_unique_domain_and_a_port() {
        let targets = builtin();
        let mut domains: Vec<&str> = targets.iter().map(|t| t.domain.as_str()).collect();
        domains.sort_unstable();
        let unique = domains.len();
        domains.dedup();
        assert_eq!(domains.len(), unique, "duplicate domain in the built-in list");
        assert!(targets.iter().all(|t| t.port == DEFAULT_PORT));
    }

    #[test]
    fn lookup_ignores_case_and_a_trailing_dot() {
        assert_eq!(lookup("GitHub.com").map(|t| t.domain), Some("github.com".to_string()));
        assert_eq!(lookup("github.com.").map(|t| t.domain), Some("github.com".to_string()));
        assert_eq!(
            lookup("  github.com  ").map(|t| t.domain),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn lookup_returns_nothing_for_an_unknown_domain() {
        assert!(lookup("example.invalid").is_none());
    }

    #[test]
    fn an_ad_hoc_target_carries_no_recorded_addresses() {
        let target = ad_hoc("Example.ORG.");
        assert_eq!(target.domain, "example.org");
        assert_eq!(target.port, DEFAULT_PORT);
        assert_eq!(target.role, Role::Service);
        assert!(target.known_ips.is_empty());
    }

    #[test]
    fn the_control_is_a_control() {
        assert_eq!(control().role, Role::Control);
    }

    #[test]
    fn a_target_labels_itself_with_its_port() {
        assert_eq!(ad_hoc("github.com").label(), "github.com:443");
    }
}
