//! `wafrift cors-diff`: CORS misconfiguration scanner.
//!
//! Cross-Origin Resource Sharing (CORS) is one of the most
//! commonly misconfigured browser security controls. A target that
//! reflects an arbitrary `Origin` header into `Access-Control-Allow-
//! Origin` AND advertises `Access-Control-Allow-Credentials: true`
//! is a 1-line exploit: the attacker hosts a page at evil.example,
//! the page's `fetch(target, { credentials: 'include' })` succeeds,
//! and the attacker reads the response (cookies + session-protected
//! data).
//!
//! Probes vary the `Origin` header across known WAF/origin
//! validation pitfalls (suffix confusion, prefix confusion, scheme
//! stripping, null origin, subdomain dot-segment) and observe the
//! `Access-Control-Allow-*` response headers.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::Args;
use colored::Colorize;
use reqwest::{Client, Method, header::HeaderMap};
use serde_json::json;
use tokio::sync::Semaphore;

#[derive(Args, Debug)]
pub(crate) struct CorsDiffArgs {
    /// Target URL, typically an API endpoint that returns sensitive
    /// data when the operator's browser session is authenticated.
    pub url: String,

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

    /// Extra headers (carry the auth cookie / bearer token).
    #[arg(long, short = 'H', value_name = "HEADER", num_args = 0..)]
    pub header: Vec<String>,

    /// Output format: `text` (default) or `json`.
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    /// Quiet mode.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,
}

/// One CORS-misconfiguration probe.
#[derive(Debug, Clone)]
pub(crate) struct CorsProbe {
    pub kind: &'static str,
    pub description: &'static str,
    /// HTTP method to send. GET for most probes; OPTIONS for
    /// preflight-specific tests.
    pub method: &'static str,
    /// Value to set in the `Origin` header. None = don't send Origin
    /// (baseline reference).
    pub origin: Option<String>,
    /// Extra headers for preflight probes (Access-Control-Request-*).
    pub extra_headers: Vec<(String, String)>,
}

/// Result of one CORS probe, what the target sent back in the
/// CORS-related response headers.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct CorsDiffResult {
    pub kind: &'static str,
    pub description: &'static str,
    pub probe_origin: Option<String>,
    pub probe_status: u16,
    pub allow_origin: Option<String>,
    pub allow_credentials: Option<String>,
    pub allow_methods: Option<String>,
    pub allow_headers: Option<String>,
    pub curl_cmd: String,
    pub severity: &'static str,
    pub finding: &'static str,
}

/// Generate the CORS probe set. Pure function. `target_host` is
/// extracted from the URL and used to build suffix/prefix-confusion
/// Origins.
#[must_use]
pub(crate) fn generate_cors_variants(target_host: &str) -> Vec<CorsProbe> {
    let mut out = Vec::new();

    // ── Plain attacker.example reflection ──
    out.push(CorsProbe {
        kind: "origin-reflects-arbitrary",
        description: "Send Origin: https://attacker.example. If the server reflects \
             it into Access-Control-Allow-Origin AND sets Allow-Credentials: \
             true, attacker can read response from a malicious page",
        method: "GET",
        origin: Some("https://attacker.example".into()),
        extra_headers: Vec::new(),
    });

    // ── Origin: null ──
    out.push(CorsProbe {
        kind: "origin-null-accepted",
        description: "Send Origin: null, file://, sandboxed iframes, redirected \
             requests send this; servers that allowlist `null` open CORS \
             to attacker sandboxed iframes",
        method: "GET",
        origin: Some("null".into()),
        extra_headers: Vec::new(),
    });

    // ── Subdomain suffix confusion ──
    out.push(CorsProbe {
        kind: "subdomain-suffix-confusion",
        description: "Origin: https://{target}.attacker.example, the allowlisted \
             host sits as a LEADING label of an attacker-owned domain (real \
             registrable domain: attacker.example). Catches servers that \
             PREFIX-match or substring-test the Origin \
             (origin.starts_with(\"https://\"+host) / origin.contains(host)) \
             instead of comparing the full host: the check passes, the page \
             is the attacker's",
        method: "GET",
        origin: Some(format!("https://{target_host}.attacker.example")),
        extra_headers: Vec::new(),
    });

    // ── Subdomain prefix confusion ──
    out.push(CorsProbe {
        kind: "subdomain-prefix-confusion",
        description: "Origin: https://attacker.{target}, an attacker-controlled \
             label PREPENDED to the allowlisted host. Catches servers that \
             SUFFIX-match (origin.ends_with(host)) to wave through 'any \
             subdomain'; exploitable when the attacker controls a subdomain \
             under that host (dangling-DNS / subdomain takeover)",
        method: "GET",
        origin: Some(format!("https://attacker.{target_host}")),
        extra_headers: Vec::new(),
    });

    // ── Trailing-dot subdomain ──
    out.push(CorsProbe {
        kind: "trailing-dot-host",
        description: "Origin: https://{target}. (trailing dot). DNS-equivalent but \
             string-different; some allowlists miss",
        method: "GET",
        origin: Some(format!("https://{target_host}.")),
        extra_headers: Vec::new(),
    });

    // ── HTTP downgrade ──
    out.push(CorsProbe {
        kind: "http-downgrade-origin",
        description: "Origin: http://{target} (downgrade from HTTPS), servers that \
             allowlist by host (ignoring scheme) leak cookies over plaintext",
        method: "GET",
        origin: Some(format!("http://{target_host}")),
        extra_headers: Vec::new(),
    });

    // ── Subdomain via @ trick ──
    out.push(CorsProbe {
        kind: "userinfo-injection",
        description: "Origin: https://attacker.example@{target}. URL parsers vary; \
             some interpret the userinfo `attacker.example@` and treat host \
             as {target} (allowed), but the actual loading origin is \
             attacker.example",
        method: "GET",
        origin: Some(format!("https://attacker.example@{target_host}")),
        extra_headers: Vec::new(),
    });

    // ── Wildcard match check ──
    out.push(CorsProbe {
        kind: "wildcard-origin-reflection",
        description: "Origin: *, server should NOT reflect this verbatim; if it \
             does AND credentials are allowed, browsers will reject, but \
             some servers do anyway, breaking SOP for non-credentialed \
             attackers",
        method: "GET",
        origin: Some("*".into()),
        extra_headers: Vec::new(),
    });

    // ── Preflight: arbitrary header allowed? ──
    out.push(CorsProbe {
        kind: "preflight-arbitrary-header",
        description: "OPTIONS preflight asking permission for X-Wafrift-Probe header. \
             Server that allows ANY requested header (no whitelist) is \
             over-permissive",
        method: "OPTIONS",
        origin: Some("https://attacker.example".into()),
        extra_headers: vec![
            ("Access-Control-Request-Method".into(), "GET".into()),
            (
                "Access-Control-Request-Headers".into(),
                "X-Wafrift-Probe".into(),
            ),
        ],
    });

    // ── Preflight: DELETE method ──
    out.push(CorsProbe {
        kind: "preflight-delete-method",
        description: "OPTIONS preflight asking permission for DELETE method. \
             Server that allows DELETE from an attacker origin is a \
             destructive CORS hole",
        method: "OPTIONS",
        origin: Some("https://attacker.example".into()),
        extra_headers: vec![("Access-Control-Request-Method".into(), "DELETE".into())],
    });

    out
}

pub(crate) async fn run_cors_diff(mut args: CorsDiffArgs) -> ExitCode {
    args.url = crate::helpers::normalize_target_url(&args.url);
    let http = match crate::parser_diff_common::build_diff_http_client_for(&args) {
        Ok(c) => c,
        Err(code) => return code,
    };

    let target_host = extract_host(&args.url).unwrap_or_else(|| "target.example".into());

    if !args.quiet && args.format == "text" {
        eprintln!(
            "{} probing CORS surface against {} (assumed host: {})",
            "[wafrift cors-diff]".bright_cyan().bold(),
            args.url.bright_white(),
            target_host.bright_black()
        );
    }

    let variants = generate_cors_variants(&target_host);
    let sem = Arc::new(Semaphore::new(args.concurrency.max(1)));
    let http_arc = Arc::new(http);
    let url_arc = Arc::new(args.url.clone());
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
        let counter = counter.clone();
        let delay = Duration::from_millis(args.delay_ms);
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let result =
                fire_cors(&http, v.method, &url, v.origin.as_deref(), &v.extra_headers).await;
            counter.fetch_add(1, Ordering::SeqCst);
            (v, result)
        }));
    }

    let mut results: Vec<CorsDiffResult> = Vec::new();
    let mut errors = 0u32;
    for h in handles {
        let (variant, outcome) = h.await.unwrap_or_else(|e| {
            (
                CorsProbe {
                    kind: "join-error",
                    description: "tokio join failed",
                    method: "GET",
                    origin: None,
                    extra_headers: Vec::new(),
                },
                Err(format!("{e}")),
            )
        });
        match outcome {
            Ok((status, response_headers)) => {
                let allow_origin = response_headers
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let allow_credentials = response_headers
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let allow_methods = response_headers
                    .get("access-control-allow-methods")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let allow_headers = response_headers
                    .get("access-control-allow-headers")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let (severity, finding) = classify_cors(
                    variant.origin.as_deref(),
                    allow_origin.as_deref(),
                    allow_credentials.as_deref(),
                );
                let curl_cmd = render_curl(
                    variant.method,
                    &args.url,
                    variant.origin.as_deref(),
                    &variant.extra_headers,
                );
                results.push(CorsDiffResult {
                    kind: variant.kind,
                    description: variant.description,
                    probe_origin: variant.origin.clone(),
                    probe_status: status,
                    allow_origin,
                    allow_credentials,
                    allow_methods,
                    allow_headers,
                    curl_cmd,
                    severity,
                    finding,
                });
            }
            Err(_) => errors += 1,
        }
    }

    emit_output(&args, &results, errors);
    ExitCode::SUCCESS
}

/// Decide severity + finding label from CORS response shape.
/// `"high"` when the server reflects the attacker's Origin AND
/// allows credentials (=== exploit). `"medium"` for reflection
/// without credentials (still leaks non-credentialed data).
/// `"none"` otherwise.
fn classify_cors(
    sent_origin: Option<&str>,
    allow_origin: Option<&str>,
    allow_credentials: Option<&str>,
) -> (&'static str, &'static str) {
    let sent = match sent_origin {
        Some(s) => s,
        None => return ("none", "baseline (no origin sent)"),
    };
    let allow = match allow_origin {
        Some(a) => a,
        None => return ("none", "ACAO header absent, no CORS exposure"),
    };
    let creds_true = matches!(allow_credentials, Some(c) if c.eq_ignore_ascii_case("true"));
    if allow == sent {
        if creds_true {
            (
                "high",
                "ACAO reflects Origin AND ACAC:true, credentials leak",
            )
        } else {
            ("medium", "ACAO reflects Origin, non-credentialed data leak")
        }
    } else if allow == "*" && creds_true {
        // Browsers reject this combo, but the server emitting it is
        // misconfigured and informative.
        (
            "medium",
            "ACAO:* AND ACAC:true: RFC violation (informative)",
        )
    } else {
        ("none", "ACAO did not reflect attacker origin, safe")
    }
}

async fn fire_cors(
    http: &Client,
    method_str: &str,
    url: &str,
    origin: Option<&str>,
    extra_headers: &[(String, String)],
) -> Result<(u16, HeaderMap), String> {
    let method = Method::from_bytes(method_str.as_bytes())
        .map_err(|e| format!("invalid method {method_str:?}: {e}"))?;
    let mut req = http.request(method, url);
    if let Some(o) = origin {
        req = req.header("Origin", o);
    }
    for (n, v) in extra_headers {
        req = req.header(n.as_str(), v);
    }
    let resp = req.send().await.map_err(|e| format!("{e}"))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    // Drain body to free the connection: §15 OOM: use bounded drain
    // so a gzip bomb can't run the draining loop to exhaustion.
    let _ =
        crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES).await;
    Ok((status, headers))
}

crate::impl_parser_diff_http_args!(CorsDiffArgs);

fn render_curl(
    method: &str,
    url: &str,
    origin: Option<&str>,
    extra_headers: &[(String, String)],
) -> String {
    // Prepend the optional Origin header then delegate to the canonical helper.
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(o) = origin {
        headers.push(("Origin".to_string(), o.to_string()));
    }
    headers.extend_from_slice(extra_headers);
    crate::helpers::render_simple_curl(Some(method), url, &headers, None)
}

fn extract_host(url: &str) -> Option<String> {
    // Shared canonical impl in wafrift_transport, handles IPv6
    // brackets + userinfo + lowercase + port strip + scheme-optional.
    wafrift_transport::host_from_url(url)
}

fn emit_output(args: &CorsDiffArgs, results: &[CorsDiffResult], errors: u32) {
    let (high, medium) = crate::parser_diff_common::count_high_medium(results, |r| r.severity);

    if args.format == "json" {
        let out = json!({
            "target": args.url,
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
            "cors-diff",
            "CORS issue(s)",
            high,
            medium,
            errors,
        );
        // Pentest-dogfood UX (2026-05): when ZERO issues fire AND the
        // target never returned an Access-Control-* header on any
        // probe, "0 CORS issues" looks like wafrift's verdict on
        // "no CORS bugs" (but it actually means "no CORS surface").
        // Spell out the difference so an operator doesn't mistake
        // a non-CORS endpoint for a hardened one.
        let any_cors_header_seen = results.iter().any(|r| r.allow_origin.is_some());
        if (high + medium) == 0 && !any_cors_header_seen && !results.is_empty() {
            println!(
                "  {} no Access-Control-* header observed on any probe. \
                 this target may not have a CORS surface at all (i.e. it's not \
                 a browser-accessed API). Not the same as 'CORS hardened'.",
                "note:".bright_cyan().bold()
            );
        }
    }

    for r in results.iter().filter(|r| r.severity != "none") {
        let badge = crate::parser_diff_common::severity_badge(r.severity);
        println!();
        println!("  [{badge}] {}: {}", r.kind.bold(), r.description);
        println!("    {} {}", "↘".bright_black(), r.finding.bright_white());
        if let Some(o) = &r.allow_origin {
            println!("    Access-Control-Allow-Origin: {o}");
        }
        if let Some(c) = &r.allow_credentials {
            println!("    Access-Control-Allow-Credentials: {c}");
        }
        println!("    {}", r.curl_cmd);
    }
}

#[cfg(test)]
#[path = "cors_diff_cmd_tests.rs"]
mod tests;
