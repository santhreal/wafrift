//! Regression coverage for the 2026-05-10 swarm-audit HIGH:
//!   `xss::mutate` had a `has_xss_signals` gate that fired on benign
//!   substrings: `confirm(...)` in API docs, `window.onerror` in
//!   security write-ups, `<select>` HTML dropdowns. The mutator then
//!   emitted XSS variants from non-XSS input, wasted work the
//!   scanner reported as a real probe.
//!
//! Replaced with a 2-point threshold scoring scheme. Bare `confirm(`
//! or `alert(` no longer triggers; combination with a `<` tag or
//! `javascript:` URL does.

use wafrift_grammar::grammar::xss;

// ── Pre-fix FPs that must NOT generate XSS variants now ─────────────

#[test]
fn does_not_fire_on_benign_input() {
    let benign = [
        "calling alert(message) shows a popup",
        "confirm() requires user interaction",
        "the window.onerror handler is global",
        "<select><option>foo</option></select>",
        "This page uses javascript",
    ];
    for input in benign {
        let out = xss::mutate(input, 10);
        assert!(
            out.is_empty(),
            "benign input {input:?} must not trigger XSS mutations: {out:?}"
        );
    }
}

// ── Real XSS payloads MUST still generate variants ──────────────────

#[test]
fn fires_on_real_xss_payloads() {
    let attacks = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "alert(document.cookie)",
    ];
    for input in attacks {
        let out = xss::mutate(input, 10);
        assert!(
            !out.is_empty(),
            "real XSS payload {input:?} must still mutate"
        );
    }
}
