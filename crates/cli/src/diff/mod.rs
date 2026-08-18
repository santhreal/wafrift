//! HTTP request/response differential probing subcommands.
//!
//! Each module implements one `wafrift *-diff` subcommand that fires
//! paired requests (baseline vs. evasion) and compares the origin's
//! response to detect WAF-vs-origin parsing divergences.
//!
//! Shared utilities live in [`parser_diff_common`].

pub mod body_diff_cmd;
pub mod cache_diff_cmd;
pub mod cors_diff_cmd;
pub mod diff_cmd;
pub mod gql_diff_cmd;
pub mod h2_diff_cmd;
pub mod header_diff_cmd;
#[cfg(feature = "tls-impersonate")]
pub mod ja3_diff_cmd;
pub mod jwt_diff_cmd;
pub mod method_diff_cmd;
pub mod parser_diff_cmd;
pub mod parser_diff_common;
pub mod query_diff_cmd;
pub mod trailer_diff_cmd;
