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

/// What kind of service a target is. The window groups the list by this, and
/// the JSON carries it, so a reader can tell a video host from a messenger
/// without knowing the domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    VideoHosting,
    VideoStreaming,
    AudioStreaming,
    Social,
    Messenger,
    News,
    Search,
    Ai,
    Games,
    Encyclopedia,
    Development,
    /// A target the user added: it has no built-in entry and no recorded
    /// addresses.
    Custom,
    /// A control target. Controls are service-side plumbing, not something the
    /// window lists.
    Control,
}

impl Category {
    /// The order the window lists the groups in: media first, then the ways
    /// people talk, then the places they read, then the rest. Controls are not
    /// here: they are not shown at all.
    pub const GROUPS: [Category; 12] = [
        Category::VideoHosting,
        Category::VideoStreaming,
        Category::AudioStreaming,
        Category::Social,
        Category::Messenger,
        Category::News,
        Category::Search,
        Category::Ai,
        Category::Games,
        Category::Encyclopedia,
        Category::Development,
        Category::Custom,
    ];
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
    pub category: Category,
    /// True for a target the user added in the window. Custom targets have no
    /// recorded addresses: the probes rely on the resolvers alone.
    pub custom: bool,
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

/// One service of the built-in list.
fn service(domain: &str, category: Category, known: IpAddr) -> Target {
    Target {
        domain: domain.to_string(),
        port: DEFAULT_PORT,
        role: Role::Service,
        known_ips: vec![known],
        category,
        custom: false,
    }
}

/// One control of the built-in list.
fn control_target(domain: &str, known: IpAddr) -> Target {
    Target {
        domain: domain.to_string(),
        port: DEFAULT_PORT,
        role: Role::Control,
        known_ips: vec![known],
        category: Category::Control,
        custom: false,
    }
}

/// The starting list: twenty-four services that are commonly blocked or
/// throttled in Russia, and three controls that are not.
///
/// The recorded addresses were resolved on 2026-11-14 from this network. They
/// are a fallback for a broken resolver, nothing more.
pub fn builtin() -> Vec<Target> {
    vec![
        // Video hosting.
        service("youtube.com", Category::VideoHosting, ip(172, 217, 19, 238)),
        // Video streaming.
        service("www.twitch.tv", Category::VideoStreaming, ip(146, 75, 122, 214)),
        service("netflix.com", Category::VideoStreaming, ip(207, 45, 73, 1)),
        // Audio streaming.
        service("open.spotify.com", Category::AudioStreaming, ip(146, 75, 123, 42)),
        // Social networks.
        service("x.com", Category::Social, ip(162, 159, 140, 229)),
        service("facebook.com", Category::Social, ip(31, 13, 72, 36)),
        service("instagram.com", Category::Social, ip(31, 13, 72, 174)),
        // Messengers.
        service("discord.com", Category::Messenger, ip(162, 159, 128, 233)),
        service("web.telegram.org", Category::Messenger, ip(149, 154, 167, 99)),
        service("web.whatsapp.com", Category::Messenger, ip(57, 144, 245, 32)),
        // News.
        service("bbc.com", Category::News, ip(151, 101, 0, 81)),
        service("dw.com", Category::News, ip(194, 55, 26, 46)),
        service("meduza.io", Category::News, ip(104, 18, 1, 79)),
        // Search.
        service("google.com", Category::Search, ip(142, 251, 13, 100)),
        service("duckduckgo.com", Category::Search, ip(52, 142, 124, 215)),
        // AI assistants.
        service("chatgpt.com", Category::Ai, ip(104, 18, 32, 47)),
        service("claude.ai", Category::Ai, ip(160, 79, 104, 10)),
        service("gemini.google.com", Category::Ai, ip(142, 251, 153, 2)),
        // Games.
        service("store.steampowered.com", Category::Games, ip(23, 197, 162, 109)),
        service("store.epicgames.com", Category::Games, ip(104, 18, 2, 64)),
        // Encyclopedias.
        service("wikipedia.org", Category::Encyclopedia, ip(185, 15, 59, 224)),
        // Development.
        service("github.com", Category::Development, ip(140, 82, 121, 4)),
        service("gitlab.com", Category::Development, ip(172, 65, 251, 78)),
        service("stackoverflow.com", Category::Development, ip(198, 252, 206, 1)),
        // Controls: expected to answer from this network.
        control_target("yandex.ru", ip(77, 88, 55, 88)),
        control_target("vk.com", ip(87, 240, 129, 133)),
        control_target("mail.ru", ip(185, 180, 201, 1)),
    ]
}

/// The built-in target for `domain`, if the list has one. Matching ignores case
/// and a trailing dot, because both are legal in a domain name.
pub fn lookup(domain: &str) -> Option<Target> {
    let wanted = normalise(domain);
    builtin().into_iter().find(|target| target.domain == wanted)
}

/// A target for a domain that is not in the built-in list. It has no recorded
/// addresses, so the probes rely on the resolvers alone.
pub fn ad_hoc(domain: &str) -> Target {
    Target {
        domain: normalise(domain),
        port: DEFAULT_PORT,
        role: Role::Service,
        known_ips: Vec::new(),
        category: Category::Custom,
        custom: true,
    }
}

/// The name the probes use as a known-good SNI and `Host` header.
pub fn control() -> Target {
    builtin()
        .into_iter()
        .find(|target| target.role == Role::Control)
        .expect("the built-in list always holds at least one control")
}

/// The services of the built-in list, in the order the window shows them.
pub fn services() -> Vec<Target> {
    builtin()
        .into_iter()
        .filter(|target| target.role == Role::Service)
        .collect()
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
        assert_eq!(services, 24, "the stage-7 brief asks for twenty-four services");
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
    fn every_service_has_a_category_and_every_control_is_a_control() {
        for target in builtin() {
            match target.role {
                Role::Service => assert_ne!(
                    target.category,
                    Category::Control,
                    "{} is a service with the control category",
                    target.domain
                ),
                Role::Control => assert_eq!(target.category, Category::Control),
            }
            assert!(!target.custom, "{} is built in", target.domain);
        }
    }

    #[test]
    fn the_brief_categories_are_all_used() {
        let used: Vec<Category> = builtin()
            .iter()
            .filter(|target| target.role == Role::Service)
            .map(|target| target.category)
            .collect();
        for category in Category::GROUPS {
            if category == Category::Custom {
                continue;
            }
            assert!(
                used.contains(&category),
                "no built-in service in the {category:?} group"
            );
        }
    }

    #[test]
    fn the_new_services_are_in_the_list_with_recorded_addresses() {
        for domain in [
            "web.telegram.org",
            "web.whatsapp.com",
            "chatgpt.com",
            "claude.ai",
            "gemini.google.com",
            "bbc.com",
            "dw.com",
            "meduza.io",
            "google.com",
            "duckduckgo.com",
            "netflix.com",
            "gitlab.com",
            "stackoverflow.com",
        ] {
            let target = lookup(domain).unwrap_or_else(|| panic!("{domain} is missing"));
            assert!(!target.known_ips.is_empty(), "{domain} has no recorded address");
        }
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
        assert_eq!(target.category, Category::Custom);
        assert!(target.custom);
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

    #[test]
    fn the_services_helper_skips_the_controls() {
        let services = services();
        assert_eq!(services.len(), 24);
        assert!(services.iter().all(|target| target.role == Role::Service));
    }
}
