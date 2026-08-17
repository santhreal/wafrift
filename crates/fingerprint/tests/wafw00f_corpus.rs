//! Vendored HTTP fingerprints (see `tests/data/*.txt`) exercised against the
//! live `wafrift-detect` rule pack. Every must-detect has a twin fixture
//! that must not register a hit for the same WAF.

mod common;

use std::path::PathBuf;

use common::parse_response_spec;
use wafrift_detect::detect;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn load(name: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let path = data_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Fix: ensure fixture exists at {} ({e})", path.display()));
    parse_response_spec(&raw)
}

#[test]
fn corpus_fixtures_detect_correct_vendor() {
    // Each vendored fingerprint fixture must produce the expected WAF
    // name as the top detection hit.
    let cases: &[(&str, &str)] = &[
        ("cloudflare.txt", "Cloudflare"),
        ("akamai.txt", "Kona SiteDefender"),
        ("aws-waf.txt", "AWS Elastic Load Balancer"),
        ("sucuri.txt", "Sucuri CloudProxy"),
        ("imperva.txt", "Incapsula"),
        ("f5-big-ip.txt", "BIG-IP AppSec Manager"),
        ("fortinet.txt", "FortiGate"),
        ("barracuda.txt", "Barracuda"),
        ("cloudfront.txt", "Cloudfront"),
    ];
    for (fixture, expected) in cases {
        let (st, h, b) = load(fixture);
        let hits = detect(st, &h, &b);
        let top = hits
            .first()
            .unwrap_or_else(|| panic!("Fix: {fixture} corpus must detect {expected}"));
        assert_eq!(top.name, *expected, "{fixture}: wrong top detection");
    }
}

/// Each positive fingerprint file `X.txt` has `X.twin.txt` with banners
/// scrubbed so the specific WAF must not appear as the top hit.
#[test]
fn twins_do_not_emit_matching_vendor() {
    let pairs = [
        ("cloudflare.twin.txt", "Cloudflare"),
        ("akamai.twin.txt", "Kona SiteDefender"),
        ("aws-waf.twin.txt", "AWS Elastic Load Balancer"),
        ("sucuri.twin.txt", "Sucuri CloudProxy"),
        ("imperva.twin.txt", "Incapsula"),
        ("f5-big-ip.twin.txt", "BIG-IP AppSec Manager"),
        ("fortinet.twin.txt", "FortiGate"),
        ("barracuda.twin.txt", "Barracuda"),
        ("cloudfront.twin.txt", "Cloudfront"),
    ];

    for (file, forbidden) in pairs {
        let (st, h, b) = load(file);
        let hits = detect(st, &h, &b);
        if let Some(top) = hits.first() {
            assert_ne!(
                top.name, forbidden,
                "Fix: twin {file} must not classify as {forbidden}, got indicators {:?}",
                top.indicators
            );
        }
    }
}
