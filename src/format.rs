//! Small formatting helpers shared by the text report and the verdict facts.

use std::time::Duration;

/// A duration as `12 ms` or `1.4 s`.
pub fn duration(elapsed: Duration) -> String {
    let millis = elapsed.as_millis();
    if millis < 1_000 {
        format!("{millis} ms")
    } else {
        format!("{:.1} s", elapsed.as_secs_f64())
    }
}

/// `1 address` or `2 addresses`.
pub fn addresses(count: usize) -> String {
    if count == 1 {
        "1 address".to_string()
    } else {
        format!("{count} addresses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_milliseconds_then_seconds() {
        assert_eq!(duration(Duration::from_millis(0)), "0 ms");
        assert_eq!(duration(Duration::from_millis(999)), "999 ms");
        assert_eq!(duration(Duration::from_millis(1_000)), "1.0 s");
        assert_eq!(duration(Duration::from_millis(5_001)), "5.0 s");
    }

    #[test]
    fn addresses_agree_with_their_count() {
        assert_eq!(addresses(0), "0 addresses");
        assert_eq!(addresses(1), "1 address");
        assert_eq!(addresses(2), "2 addresses");
    }
}
