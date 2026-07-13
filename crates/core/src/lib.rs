//! wafrift-core: Façade crate re-exporting all WAF Rift modules.
//!
//! This crate is a convenience umbrella. Each module lives in its own
//! focused crate; this crate re-exports them all under a single namespace
//! so existing consumers (`wafrift-cli`, `wafrift-transport`, integration
//! tests) can continue using `wafrift_core::*`.
//!
//! # Examples
//!
//! Use the umbrella to drive a payload through three subsystems
//! without depending on each subcrate by name:
//!
//! ```
//! use wafrift_core::{encoding, grammar};
//!
//! // Classify, mutate, encode (three lego-blocks, one façade).
//! let p = "' OR 1=1 --";
//! assert_eq!(grammar::classify(p), grammar::PayloadType::Sql);
//!
//! let mutations = grammar::mutate(p, 3);
//! assert!(!mutations.is_empty());
//!
//! let encoded = encoding::encode(p, encoding::Strategy::UrlEncode).unwrap();
//! assert!(encoded.contains("%27"));
//! ```
//!
//! Use the re-exported types to build a request without naming
//! `wafrift_types`:
//!
//! ```
//! use wafrift_core::{Method, Request};
//!
//! let r = Request::get("https://example.com").header("X-Test", "1");
//! assert_eq!(r.method(), &Method::Get);
//! assert_eq!(r.headers().len(), 1);
//! ```
//!
//! # Crate structure
//!
//! ## Re-exported crates
//!
//! | Crate                   | Re-exported as              | Purpose                                             |
//! |-------------------------|-----------------------------|-----------------------------------------------------|
//! | `wafrift-types`         | (crate root via `*`)        | Core types: Request, Technique, EvasionResult       |
//! | `wafrift-encoding`      | `encoding`, `header`        | Payload encoding + header obfuscation               |
//! | `wafrift-grammar`       | `grammar`                   | Grammar-aware payload mutations                     |
//! | `wafrift-content-type`  | `content_type`              | WAFFLED Content-Type switching                      |
//! | `wafrift-smuggling`     | `smuggling`, `h2_evasion`   | HTTP smuggling + HTTP/2 frame-level evasion         |
//! | `wafrift-fingerprint`   | `fingerprint`, `tls_fingerprint` | Browser + TLS JA3/JA4 fingerprint profiles   |
//! | `wafrift-detect`        | `waf_detect`, `response_fingerprint` | WAF detection (HTTP headers, DNS CNAME, BGP ASN) |
//! | `wafrift-evolution`     | `evolution`, `advisor`, `differential`, `custom_rules`, `intelligence` | Genetic algorithm + MCTS + advisor |
//! | `wafrift-oracle`        | `oracle`                    | Payload validity oracles (SQL, XSS, SSTI, …)        |
//! | `wafrift-strategy`      | `host_state`, `strategy`    | Evasion pipeline + gene bank + adaptive host state  |
//! | `wafrift-transport`     | `transport`                 | Evasion-aware HTTP client + stealth profiles         |
//! | `proxywire`             | `pool`                      | Canonical proxy substrate (routing, rotation, auth) |
//! | `wafrift-recon`         | `recon`                     | Origin discovery via CT logs + DNS history           |
//!
//! ### NOT re-exported by this crate
//!
//! These crates are part of the workspace but are not included in `wafrift-core`
//! to avoid the associated heavy dependencies (wasmtime, ed25519-dalek, etc.)
//! in consumers that don't need them. Use the sub-crates directly:
//!
//! - `wafrift-wafmodel`: L* WAF decompiler + offline SFA bypass mining
//! - `wafrift-genome-registry`: ed25519 genome signing + trust-list management
//! - `wafrift-plugin-api`: TOML + WASM external tamper SDK
//! - `wafrift-graphql`: GraphQL-specific evasion payloads
//! - `wafrift-grpc-evasion`: gRPC opaque-payload bypass
//! - `wafrift-captchaforge-bridge`: headless Chromium challenge solver

// ── Foundation types ──
pub use wafrift_types::*;

// ── Technique modules (re-exported as submodules) ──
pub use wafrift_content_type as content_type;
pub use wafrift_encoding::encoding;
pub use wafrift_encoding::header;
pub use wafrift_fingerprint::fingerprint;
pub use wafrift_fingerprint::tls_fingerprint;
pub use wafrift_grammar::grammar;
pub use wafrift_http3_evasion as http3_evasion;
pub use wafrift_smuggling::h2_evasion;
pub use wafrift_smuggling::smuggling;

// ── Cross-family smuggle aggregator (every probe, one iterator) ──
pub mod probe_aggregator;

// ── Intelligence modules ──
pub use wafrift_detect::response_fingerprint;
pub use wafrift_detect::waf_detect;
pub use wafrift_evolution::advisor;
pub use wafrift_evolution::custom_rules;
pub use wafrift_evolution::differential;
pub use wafrift_evolution::evolution;
pub use wafrift_evolution::intelligence;

// ── Pipeline ──
pub use wafrift_strategy::host_state;
pub use wafrift_strategy::strategy;

// ── Validation / oracle layer ──
pub use wafrift_oracle as oracle;

// ── Transport / network ──
// `pool` is the canonical proxy substrate. wafrift's naive round-robin
// `wafrift-pool` was consolidated onto `proxywire` (strict URL validation +
// health-aware rotation); this alias keeps the `wafrift_core::pool` path stable.
pub use proxywire as pool;
pub use wafrift_transport as transport;

// ── Discovery ──
pub use wafrift_recon as recon;

// Re-export `HostState` for integration-test ergonomics.
//
// R75 pass-21 §8 ARCHITECTURE: pre-fix this block also re-exported
// `CalibrationResult`, `EscalationLevel`, `EvasionConfig` via the
// `wafrift_strategy::strategy::*` path, but those are already
// available at this crate's root via `pub use wafrift_types::*` on
// line 59 (each is defined in `wafrift_types`, NOT in
// `wafrift_strategy`). Two valid import paths for the same symbol
// (`wafrift_core::EvasionConfig` AND `wafrift_core::strategy::
// EvasionConfig`) caused grep-confusion during refactors, half the
// usages would be missed. One canonical path now.
pub use wafrift_strategy::host_state::HostState;
