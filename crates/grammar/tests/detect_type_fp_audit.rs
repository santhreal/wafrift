//! Regression coverage for the 2026-05-10 swarm-audit findings:
//!   CRITICAL `ssrf::detect_type` fired on `// TODO`, `Chapter 127.5`,
//!     `Java 10.0`, `Version 192.168.something`, anything with `127.`
//!     inside a benign substring.
//!   CRITICAL `template::detect_type` fired on JSON, CSS, C, Python,
//!     Markdown, any string containing `{`, `}`, `#`, or `$` because
//!     Smarty / Velocity declare 1-char delimiters.
//!
//! Pre-fix every `assert!(!detect_type(...))` would have returned true.

use wafrift_grammar::grammar::{ssrf, template};

// ── ssrf detect_type FP fixes ───────────────────────────────────────

#[test]
fn ssrf_does_not_fire_on_benign_input() {
    let benign = [
        "// TODO: refactor",
        "// fix me later",
        "Chapter 127.5: how to scan",
        "Section 10.4 and 10.5",
        "Java 10.0 release notes",
        "Build 127.0 of nginx",
        "Python 192.168.something",
        "localhost-builds.example.com",
        "my-localhost-mirror.io",
    ];
    for input in benign {
        assert!(
            !ssrf::detect_type(input),
            "benign input {input:?} must not trigger SSRF detection"
        );
    }
}

#[test]
fn ssrf_still_fires_on_real_ssrf_payloads() {
    // Negative twin (the precision fix must not regress recall).
    assert!(ssrf::detect_type("http://127.0.0.1/admin"));
    assert!(ssrf::detect_type("http://localhost/internal"));
    assert!(ssrf::detect_type("http://169.254.169.254/latest/meta-data"));
    assert!(ssrf::detect_type("https://metadata.google.internal/"));
    assert!(ssrf::detect_type("//127.0.0.1/x"));
    assert!(ssrf::detect_type("file:///etc/passwd"));
    assert!(ssrf::detect_type("gopher://127.0.0.1:6379/_test"));
    assert!(ssrf::detect_type("127.0.0.1"));
}

// ── template detect_type FP fixes ───────────────────────────────────

#[test]
fn template_does_not_fire_on_benign_input() {
    let benign = [
        r#"{"name": "alice", "id": 42}"#,
        r#"{"items":[{"x":1}]}"#,
        "body { color: red; }",
        ".btn { background: #fff; }",
        "if (x) { return 1; }",
        "def foo(): return {'a': 1}",
        "# Heading\nSome text $var",
        "$ ls /tmp/$user/",
    ];
    for input in benign {
        assert!(
            !template::detect_type(input),
            "benign input {input:?} must not trigger template detection"
        );
    }
}

#[test]
fn template_still_fires_on_real_ssti_payloads() {
    // Negative twin (recall preserved on real SSTI).
    assert!(template::detect_type("{{7*7}}"), "jinja2 / twig");
    assert!(template::detect_type("{% if user %}{{ user }}{% endif %}"));
    assert!(template::detect_type("${7*7}"), "freemarker");
    assert!(template::detect_type("<%= 7*7 %>"), "erb");
    assert!(template::detect_type("{$smarty.version}"));
    assert!(template::detect_type("{php}phpinfo();{/php}"));
}
