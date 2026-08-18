//! HTTP request smuggling subcommands and transport.
//!
//! Subcommands:
//! - [`smuggle_cmd`]: top-level `wafrift smuggle` dispatcher
//! - [`smuggle_fire_cmd`]: fire smuggle probes against a live target
//! - [`smuggle_emit_cmd`]: emit smuggle probes as curl reproducer
//! - [`smuggle_cross_cmd`]: cross-origin smuggling composition
//! - [`smuggle_chain_cmd`]: chained smuggling sequences
//! - [`smuggle_stats_cmd`]: campaign statistics
//!
//! Transport:
//! - [`smuggle_transport`]: wire-level smuggle request firing

pub mod smuggle_chain_cmd;
pub mod smuggle_cmd;
pub mod smuggle_cross_cmd;
pub mod smuggle_emit_cmd;
pub mod smuggle_fire_cmd;
pub mod smuggle_stats_cmd;
pub mod smuggle_transport;
