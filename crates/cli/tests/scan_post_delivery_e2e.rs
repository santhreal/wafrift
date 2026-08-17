//! POST form injection delivery (variants fire as POST body (not ?param=)).

use serial_test::serial;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::wafrift;

const FORM_HTML: &[u8] =
    br#"<html><form method="post" action="/register.php"><input name="username"></form></html>"#;

/// Same selective WAF as `scan_surface_probe_e2e`, but the guarded sink is POST form.
async fn spawn_post_register_mock() -> std::net::SocketAddr {
    let handler: MockHandler = Arc::new(|req| {
        let req = String::from_utf8_lossy(req);
        if req.starts_with("GET / ") || req.starts_with("GET / HTTP") {
            return (200, FORM_HTML.to_vec());
        }
        if req.contains("/register.php") {
            if req.contains("wafrift_benign_probe0") {
                return (200, b"REGISTER_BENIGN".to_vec());
            }
            if req.contains("SqlKeyword")
                || req.contains("XssTag")
                || req.contains("XssEvent")
                || req.contains("SqlTautology")
            {
                return (403, b"blocked by waf".to_vec());
            }
            return (200, b"REGISTER_ATTACK_BODY".to_vec());
        }
        (200, b"STATIC_SHELL".to_vec())
    });
    spawn_handler(handler).await
}

type MockHandler = common::MockHttpHandler;

#[allow(dead_code)]
fn status_line(code: u16) -> &'static str {
    common::status_line(code)
}

#[allow(dead_code)]
async fn spawn_handler(handler: MockHandler) -> std::net::SocketAddr {
    common::spawn_mock_http_server(handler).await
}

#[test]
#[serial]
fn scan_post_delivery_confirms_waf_bypass_on_form_surface() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let addr = rt.block_on(spawn_post_register_mock());
    let url = format!("http://{addr}/");

    let (code, stdout, stderr) = wafrift(&[
        "scan",
        url.as_str(),
        "--payload",
        "' OR 1=1--",
        "--param",
        "q",
        "--payload-class",
        "sql",
        "--level",
        "light",
        "--format",
        "json",
        "--quiet",
        "--delay-ms",
        "0",
        "--max-fires",
        "200",
        "--auto-escalate",
        "--probe-surfaces",
    ]);
    assert_eq!(code, 0, "POST form WAF bypass; stderr: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["injection_delivery"].as_str().unwrap(),
        "post_form",
        "{v}"
    );
    assert!(
        v["effective_url"]
            .as_str()
            .unwrap()
            .contains("register.php"),
        "{v}"
    );
    assert_eq!(v["effective_param"].as_str().unwrap(), "username");
    assert_eq!(
        v["waf_bypass"]["verdict"].as_str().unwrap(),
        "bypass_confirmed"
    );
    let repro = v["bypass_variants"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|r| r["repro_curl"].as_str())
        .unwrap_or("");
    assert!(
        repro.contains("-X POST") || repro.to_ascii_uppercase().contains("POST"),
        "repro must be POST: {repro}"
    );
}
