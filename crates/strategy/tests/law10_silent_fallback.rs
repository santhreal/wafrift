//! Regression tests for Law-10 silent-fallback defects (BACKLOG rows 21-23).
//!
//! Three defects in `crates/strategy/src/strategy.rs` caused evasion steps
//! to silently degrade — the operator saw a "sent" request with no signal
//! that the encoding/mutation step never applied:
//!
//! - Row 21: `evade_adaptive` payload-encoding mutator used `.ok()` and
//!   skipped the block on error, leaving the raw payload with no
//!   `PayloadEncoding` technique recorded.
//! - Row 22: `apply_layered_encoding` used `unwrap_or_else(|_| v.clone())`,
//!   silently substituting the original unencoded value on encode error.
//! - Row 23: `apply_layered_encoding` and `apply_grammar_mutations` did
//!   `match std::str::from_utf8(body) { Err(_) => return }`, silently
//!   skipping every form-parameter evasion technique on non-UTF-8 bodies.
//!
//! All three now surface a `warnings` entry on the `EvasionResult` so the
//! operator can distinguish "encoding applied" from "encoding failed /
//! skipped" and a WAF pass on the unencoded payload is not miscredited.

use wafrift_strategy::{HostState, strategy::evade};
use wafrift_types::{EvasionConfig, Request};

/// A non-UTF-8 body (raw bytes 0xFF 0xFE) must produce a warning, not
/// silently skip grammar mutation and layered encoding. The body is
/// small enough to pass the grammar-mutation budget check.
#[test]
fn non_utf8_body_surfaces_warning() {
    let req = Request::post(
        "https://example.com/api",
        vec![0xFF, 0xFE, 0x41, 0x42, 0x43],
    )
    .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    state.record_block();
    state.record_block();

    let config = EvasionConfig {
        fingerprint_rotation: false,
        grammar_mutations: true,
        encoding_enabled: true,
        ..EvasionConfig::default()
    };

    let result = evade(&req, &state, &config);

    assert!(
        !result.warnings.is_empty(),
        "non-UTF-8 body must produce at least one warning, got: {:?}",
        result.warnings
    );

    let has_skip_warning = result
        .warnings
        .iter()
        .any(|w| w.contains("UTF-8") || w.contains("utf-8"));
    assert!(
        has_skip_warning,
        "warnings should mention non-UTF-8 body, got: {:?}",
        result.warnings
    );
}

/// A valid UTF-8 body with a normal payload should produce no warnings
/// when encoding and grammar mutations are enabled.
#[test]
fn valid_utf8_body_produces_no_skip_warning() {
    let req = Request::post("https://example.com/api", b"q=union+select+1".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    state.record_block();
    state.record_block();

    let config = EvasionConfig {
        fingerprint_rotation: false,
        grammar_mutations: true,
        encoding_enabled: true,
        ..EvasionConfig::default()
    };

    let result = evade(&req, &state, &config);

    let has_skip_warning = result
        .warnings
        .iter()
        .any(|w| w.contains("UTF-8") || w.contains("utf-8"));
    assert!(
        !has_skip_warning,
        "valid UTF-8 body should not produce a non-UTF-8 skip warning, got: {:?}",
        result.warnings
    );
}

/// The `warnings` field on `EvasionResult` must be empty by default
/// (no silent-fallback events on a clean evasion path).
#[test]
fn clean_evasion_has_no_warnings() {
    let req = Request::post("https://example.com/api", b"q=hello".to_vec())
        .header("Content-Type", "application/x-www-form-urlencoded");

    let state = HostState::default();
    let config = EvasionConfig::default();

    let result = evade(&req, &state, &config);
    assert!(
        result.warnings().is_empty(),
        "clean evasion should have no warnings, got: {:?}",
        result.warnings
    );
}

/// The `warnings()` accessor returns the warning slice.
#[test]
fn warnings_accessor_returns_slice() {
    let req = Request::post("https://example.com/api", vec![0xFF, 0xFE])
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    state.record_block();
    state.record_block();

    let config = EvasionConfig {
        fingerprint_rotation: false,
        grammar_mutations: true,
        encoding_enabled: true,
        ..EvasionConfig::default()
    };

    let result = evade(&req, &state, &config);
    assert!(!result.warnings().is_empty());
}

/// The `Display` impl shows a warning count when warnings are present.
#[test]
fn display_shows_warning_count() {
    let req = Request::post("https://example.com/api", vec![0xFF, 0xFE])
        .header("Content-Type", "application/x-www-form-urlencoded");

    let mut state = HostState::default();
    state.record_block();
    state.record_block();

    let config = EvasionConfig {
        fingerprint_rotation: false,
        grammar_mutations: true,
        encoding_enabled: true,
        ..EvasionConfig::default()
    };

    let result = evade(&req, &state, &config);
    if !result.warnings().is_empty() {
        let s = result.to_string();
        assert!(
            s.contains("warning"),
            "Display should mention warnings when present, got: {s}"
        );
    }
}
