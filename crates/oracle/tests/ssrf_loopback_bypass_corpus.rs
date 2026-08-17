//! Loopback-bypass URL corpus for SsrfOracle.
//!
//! Each fixture is a known WAF/SSRF-allowlist bypass shape that
//! resolves to 127.0.0.1 when the URL parser is permissive (browsers
//! and many backend HTTP clients are). The oracle's job is to flag
//! these as semantically-valid SSRF payloads, accepting a
//! same-target rewrite means the evasion engine's mutators can
//! safely emit them without losing exploit semantics.
//!
//! These fixtures previously lived in an orphan `oracle/src/test_url.rs`
//! that wasn't even declared as a module, it printed parse results
//! with no assertions. Converting to a real integration test means a
//! regression in url::Url parsing, in `has_ssrf_structure`, or in
//! `has_valid_url_syntax` will fire a CI signal instead of silently
//! degrading the bypass corpus.

use wafrift_oracle::ssrf::SsrfOracle;
use wafrift_oracle::traits::PayloadOracle;

#[test]
fn loopback_bypass_shapes_are_valid_ssrf_payloads() {
    // Each bypass URL must preserve SSRF semantics against the
    // canonical loopback original. Covers hex, NUL-in-authority
    // (encoded and literal), empty userinfo, shorthand, IPv6-mapped,
    // and octal forms.
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/";
    let cases: &[(&str, &str)] = &[
        ("http://0x7f000001/", "hex-form loopback"),
        ("http://127.0.0.1%00.evil.com/", "%00-in-host bypass"),
        ("http://127.0.0.1\0.evil.com/", "literal-NUL-in-host bypass"),
        ("http://@127.0.0.1/", "empty-userinfo bypass"),
        ("http://127.1/", "shorthand loopback"),
        ("http://[::ffff:127.0.0.1]/", "IPv6-mapped loopback"),
        ("http://0177.0.0.1/", "octal-form loopback"),
    ];
    for (bypass, label) in cases {
        assert!(
            oracle.is_semantically_valid(original, bypass),
            "{label} {bypass} should preserve SSRF semantics vs {original}"
        );
    }
}

#[test]
fn nul_in_non_ssrf_host_is_still_rejected() {
    // Negative twin: the salvage fallback must not start accepting
    // arbitrary NUL-bearing URLs as SSRF, only those whose pre-NUL
    // prefix is itself an SSRF target.
    let oracle = SsrfOracle;
    let original = "http://127.0.0.1/";
    let bypass = "http://example.com%00.evil.com/";
    assert!(
        !oracle.is_semantically_valid(original, bypass),
        "{bypass} has a public-host prefix, salvage should not promote it"
    );
}
