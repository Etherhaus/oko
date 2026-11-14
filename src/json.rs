//! Helpers for the JSON report.

use std::time::Duration;

/// Serialize a [`Duration`] as whole milliseconds.
///
/// JSON has no duration type. Milliseconds as an integer are easier to read and
/// to compare than a float of seconds, and sub-millisecond precision means
/// nothing for a network probe.
pub fn millis<S: serde::Serializer>(elapsed: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(elapsed.as_millis() as u64)
}
