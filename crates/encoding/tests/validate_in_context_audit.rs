//! Regression coverage for the 2026-05-10 credibility audit finding:
//!   MEDIUM: `validate_in_context()` in encoding/contextual.rs had four
//!     `// TODO: validate ...` arms (`XmlCdata`, `XmlText`, `HtmlAttribute`,
//!     `HtmlText`) that were no-op stubs. A direct caller of
//!     `validate_in_context` (not via `encode_in_context`) would receive
//!     Ok(()) for clearly-broken payloads, the function pretended to
//!     validate but did nothing. For a public crate that ships an
//!     `escape_for_context` + `validate_in_context` pair, that's a
//!     credibility hole: the validator was a smoke alarm wired to
//!     nothing.
//!
//! Pre-fix all of these tests would have passed `Ok()` instead of
//! returning the explicit Err.

use wafrift_encoding::contextual::validate_in_context;
use wafrift_types::injection_context::InjectionContext;

// ── Rejection: each context must reject its structurally dangerous chars ──

#[test]
fn validate_rejects_structurally_dangerous_input_per_context() {
    // Each (input, context) pair must be rejected. When an expected
    // substring is given, the error message must mention it.
    let cases: &[(&str, InjectionContext, Option<&str>)] = &[
        ("safe ]]> evil", InjectionContext::XmlCdata, Some("]]>")),
        ("a < b", InjectionContext::XmlText, Some("<")),
        ("rock & roll", InjectionContext::XmlText, None),
        ("a < b", InjectionContext::HtmlAttribute, Some("<")),
        (
            "hello \"world\"",
            InjectionContext::HtmlAttribute,
            Some("\""),
        ),
        ("don't", InjectionContext::HtmlAttribute, Some("'")),
        ("a & b", InjectionContext::HtmlAttribute, None),
        ("<script>", InjectionContext::HtmlText, Some("<")),
        ("AT&T", InjectionContext::HtmlText, None),
    ];
    for (input, ctx, expected) in cases {
        let err = validate_in_context(input, *ctx).expect_err("{ctx:?}: must reject {input:?}");
        if let Some(ch) = expected {
            assert!(
                format!("{err}").contains(ch),
                "{ctx:?}: error for {input:?} must contain {ch:?}, got {err}"
            );
        }
    }
}

#[test]
fn xml_cdata_accepts_clean_payload() {
    validate_in_context("clean cdata content", InjectionContext::XmlCdata)
        .expect("clean payload must pass");
}

#[test]
fn xml_text_accepts_proper_entity_references() {
    validate_in_context("&amp; and &lt;", InjectionContext::XmlText)
        .expect("named entities must pass");
    validate_in_context("&#65; and &#x41;", InjectionContext::XmlText)
        .expect("numeric and hex entities must pass");
}

#[test]
fn html_attribute_accepts_clean_value() {
    validate_in_context("clean value", InjectionContext::HtmlAttribute)
        .expect("clean payload must pass");
    validate_in_context("with &amp; entity", InjectionContext::HtmlAttribute)
        .expect("entity references must pass");
}

#[test]
fn html_text_accepts_clean_text_and_entities() {
    validate_in_context("plain text only", InjectionContext::HtmlText)
        .expect("clean text must pass");
    validate_in_context(
        "AT&amp;T and &lt;br&gt; and &#x2014;",
        InjectionContext::HtmlText,
    )
    .expect("entity-encoded text must pass");
}

// ── Round-trip with escape_for_context ──────────────────────────────

#[test]
fn escape_then_validate_round_trip_html_attr() {
    use wafrift_encoding::contextual::escape_for_context;
    // The contract: escape_for_context output must always pass
    // validate_in_context. If this regresses, the whole pair is a
    // smoke alarm wired to nothing.
    let dangerous = r#"<script>alert("xss")</script> & 'oops'"#;
    let escaped =
        escape_for_context(dangerous, InjectionContext::HtmlAttribute).expect("escape ok");
    validate_in_context(&escaped, InjectionContext::HtmlAttribute)
        .expect("escape output must pass validate");
}

#[test]
fn escape_then_validate_round_trip_html_text() {
    use wafrift_encoding::contextual::escape_for_context;
    let dangerous = "<a>AT&T</a>";
    let escaped = escape_for_context(dangerous, InjectionContext::HtmlText).expect("escape ok");
    validate_in_context(&escaped, InjectionContext::HtmlText)
        .expect("escape output must pass validate");
}

#[test]
fn escape_then_validate_round_trip_xml_text() {
    use wafrift_encoding::contextual::escape_for_context;
    let dangerous = "<root>a & b</root>";
    let escaped = escape_for_context(dangerous, InjectionContext::XmlText).expect("escape ok");
    validate_in_context(&escaped, InjectionContext::XmlText)
        .expect("escape output must pass validate");
}
