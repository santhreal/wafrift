//! Plain origin stacks must not trip WAF detectors.

mod common;

use std::path::PathBuf;

use common::parse_response_spec;
use wafrift_detect::detect;

fn read_fixture(name: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Fix: read {} ({e})", path.display()));
    parse_response_spec(&raw)
}

#[test]
fn plain_origins_trigger_no_detection() {
    // Plain origin stacks (nginx, Apache, S3) must not trip WAF detectors.
    for fixture in ["plain-nginx.txt", "plain-apache.txt", "plain-s3.txt"] {
        let (st, h, b) = read_fixture(fixture);
        let hits = detect(st, &h, &b);
        assert!(
            hits.is_empty(),
            "Fix: {fixture} must not classify as a WAF; got {hits:?}"
        );
    }
}
