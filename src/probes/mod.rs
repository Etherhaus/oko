//! The probes.
//!
//! Each probe answers one narrow question about a target and returns a plain
//! data structure. None of them decides what a result means: that is the job of
//! the verdict engine, which is fed these structures and can be tested without a
//! network.

pub mod dns;
pub mod tcp;
