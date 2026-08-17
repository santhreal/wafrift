//! Cloudflare-specific WAF response parser.
//!
//! Cloudflare leaks several signals across headers and body that let us
//! attribute a block to a specific rule or mitigation class:
//!
//! | Source    | Field              | Example value                          |
//! |-----------|--------------------|----------------------------------------|
//! | Header    | `cf-ray`           | `8a1b2c3d4e5f6a7b-SJC`                 |
//! | Header    | `cf-mitigated`     | `challenge`, `block`                   |
//! | Header    | `cf-cache-status`  | `BYPASS`, `MISS`, `HIT`                |
//! | Header    | `server`           | `cloudflare`                           |
//! | Header    | `retry-after`      | `30` (rate-limit)                      |
//! | Body HTML | Ray ID footer      | `Cloudflare Ray ID: 8a1b2c3d4e5f6a7b`  |
//! | Body HTML | Old rule comment   | `<!-- 9512XX -->`                      |
//! | Body HTML | Error code comment | `<!-- error code: 1020 -->`            |
//! | Body HTML | Blocked phrase     | `Sorry, you have been blocked`         |
//! | Body HTML | JS challenge token | `challenge-platform`, `jschl`          |
//! | Body HTML | Turnstile          | `turnstile`, `cf-turnstile`            |
//! | Body HTML | Ruleset group      | `owasp`, `wordpress`, CVE IDs          |

use std::str;

// ── Public types ─────────────────────────────────────────────────────────────

/// Classification of what CF mitigation class fired.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BlockClass {
    /// CF Managed Ruleset (OWASP CRS, CF-specific, Wordpress, CVE rules, …).
    ManagedRulesetBlock,
    /// Bot Management JS/Managed challenge.
    BotChallenge,
    /// CAPTCHA / Turnstile challenge.
    Captcha,
    /// CF Browser Integrity Check / "Under Attack" mode.
    BrowserCheck,
    /// Manual IP/ASN/country block in Firewall Rules or WAF Custom Rules.
    ManualReview,
    /// Rate limiting action (429 / Retry-After).
    RateLimited,
    /// Not enough signal to classify.
    Unknown,
}

/// Extracted Cloudflare-specific signals from a response.
///
/// All `Option` fields are `None` when the signal was absent. Callers must
/// not treat `None` as an error, only as missing evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfBlockSignal {
    /// The `cf-ray` header value: `<hex>-<POP>` (e.g. `8a1b2c3d-SJC`).
    pub cf_ray: Option<String>,
    /// Three-letter IATA airport code of the edge PoP (e.g. `SJC`, `LHR`).
    /// Extracted from the suffix of the `cf-ray` value.
    pub edge_pop: Option<String>,
    /// Value of the `cf-mitigated` header, lower-cased.
    pub mitigated_reason: Option<String>,
    /// Ruleset group hint extracted from the body
    /// (e.g. `owasp`, `wordpress`, `cf`, a CVE ID like `CVE-2021-44228`).
    pub ruleset_hint: Option<String>,
    /// Which kind of mitigation CF applied.
    pub block_class: BlockClass,
    /// Composite rule-attribution string for `OracleVerdict.rule_id`:
    /// `cf:<edge_pop>:<ruleset_hint>`: absent components become `?`.
    /// Example: `cf:SJC:owasp`.
    pub rule_attribution: String,
}

impl CfBlockSignal {
    /// Returns `true` when the response definitely came from a CF edge node.
    #[must_use]
    pub fn is_cloudflare_response(&self) -> bool {
        self.cf_ray.is_some() || self.mitigated_reason.is_some()
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse Cloudflare-specific block signals from response headers and body.
///
/// Pure and allocation-bounded (never blocks on I/O).
///
/// # Arguments
///
/// * `response_headers`: All response headers as `(name, value)` pairs.
///   Header names are matched case-insensitively.
/// * `body`: Raw (possibly HTML) response body bytes.
#[must_use]
pub fn parse_cf_block(response_headers: &[(String, String)], body: &[u8]) -> CfBlockSignal {
    let body_str = str::from_utf8(body).unwrap_or("").to_ascii_lowercase();

    // ── Header extraction ─────────────────────────────────────────────────
    let mut cf_ray_raw: Option<String> = None;
    let mut edge_pop: Option<String> = None;
    let mut mitigated_reason: Option<String> = None;
    let mut has_retry_after = false;
    let mut is_cloudflare_server = false;

    for (name, value) in response_headers {
        let name_lc = name.to_ascii_lowercase();
        let value_lc = value.to_ascii_lowercase();

        match name_lc.as_str() {
            "cf-ray" => {
                // Format: "<16-hex-chars>-<IATA>" e.g. "8a1b2c3d4e5f6a7b-SJC"
                let pop = value
                    .rsplit('-')
                    .next()
                    .map(|s| s.trim().to_uppercase())
                    .filter(|p| p.len() == 3 && p.chars().all(|c| c.is_ascii_alphabetic()));
                edge_pop = pop;
                cf_ray_raw = Some(value.clone());
            }
            "cf-mitigated" => {
                mitigated_reason = Some(value_lc.trim().to_string());
            }
            "server" if value_lc.contains("cloudflare") => {
                is_cloudflare_server = true;
            }
            "retry-after" => {
                has_retry_after = true;
            }
            _ => {}
        }
    }
    let _ = is_cloudflare_server; // available for future extension

    // ── Body-level signal extraction ──────────────────────────────────────
    let error_code = extract_cf_error_code(&body_str);
    let rule_comment_id = extract_rule_comment_id(&body_str);
    let ruleset_hint = extract_ruleset_hint(&body_str, &rule_comment_id, &error_code);

    let body_has_jschl = body_str.contains("jschl") || body_str.contains("jschl_vc");
    let body_has_challenge_platform = body_str.contains("challenge-platform");
    let body_has_turnstile = body_str.contains("turnstile") || body_str.contains("cf-turnstile");
    let body_has_under_attack =
        body_str.contains("under attack") || body_str.contains("ddos protection");
    let body_has_blocked_phrase = body_str.contains("sorry, you have been blocked")
        || body_str.contains("access denied")
        || body_str.contains("you have been blocked");
    let body_has_manual_review = body_str.contains("manual review")
        || matches!(
            error_code.as_deref(),
            Some("1010") | Some("1011") | Some("1012")
        );
    let body_has_rate_limit = body_str.contains("too many requests")
        || body_str.contains("rate limit")
        || body_str.contains("rate-limit");
    let body_has_browser_check = body_str.contains("browser integrity check")
        || body_str.contains("checking your browser")
        || body_str.contains("one more step");

    // ── Block class decision tree ─────────────────────────────────────────
    let block_class = classify_block_class(
        &mitigated_reason,
        has_retry_after,
        body_has_jschl,
        body_has_challenge_platform,
        body_has_turnstile,
        body_has_under_attack,
        body_has_browser_check,
        body_has_blocked_phrase,
        body_has_manual_review,
        body_has_rate_limit,
    );

    // ── Rule attribution ──────────────────────────────────────────────────
    let pop_str = edge_pop.as_deref().unwrap_or("?");
    let ruleset_str = ruleset_hint.as_deref().unwrap_or("?");
    let rule_attribution = format!("cf:{pop_str}:{ruleset_str}");

    CfBlockSignal {
        cf_ray: cf_ray_raw,
        edge_pop,
        mitigated_reason,
        ruleset_hint,
        block_class,
        rule_attribution,
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extract the CF error code from body HTML.
///
/// Matches patterns:
/// - `<!-- error code: 1020 -->`
/// - `error code: 1020`
/// - `data-translate="error_code">1020<`
/// - `::ERRORPAGESSTATUS::1020`
fn extract_cf_error_code(body_lc: &str) -> Option<String> {
    for prefix in &["<!-- error code: ", "error code: ", "errorcode: "] {
        if let Some(pos) = body_lc.find(prefix) {
            let after = &body_lc[pos + prefix.len()..];
            let code: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if code.len() >= 3 {
                return Some(code);
            }
        }
    }

    let translate_needle = "data-translate=\"error_code\">";
    if let Some(pos) = body_lc.find(translate_needle) {
        let after = &body_lc[pos + translate_needle.len()..];
        let code: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if code.len() >= 3 {
            return Some(code);
        }
    }

    let status_needle = "::errorpagesstatus::";
    if let Some(pos) = body_lc.find(status_needle) {
        let after = &body_lc[pos + status_needle.len()..];
        let code: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
        if code.len() >= 3 {
            return Some(code);
        }
    }

    None
}

/// Extract old-style CF rule IDs embedded as HTML comments.
///
/// CF Managed Ruleset older blocks emitted comments like `<!-- 951220 -->`.
/// We match 4–8 digit sequences inside HTML comments.
fn extract_rule_comment_id(body_lc: &str) -> Option<String> {
    let mut search = body_lc;
    while let Some(start) = search.find("<!--") {
        let after_open = &search[start + 4..];
        if let Some(end) = after_open.find("-->") {
            let comment = after_open[..end].trim();
            if comment.len() >= 4
                && comment.len() <= 8
                && comment.chars().all(|c| c.is_ascii_digit())
            {
                return Some(comment.to_string());
            }
            search = &after_open[end + 3..];
        } else {
            break;
        }
    }
    None
}

/// Derive the ruleset hint from body text and extracted IDs.
///
/// Priority:
/// 1. Rule comment ID (actual rule number, most specific)
/// 2. CVE ID in body (highly specific, beats generic error codes)
/// 3. CF error code mapped to known ruleset groups
/// 4. Named ruleset group text patterns in body
fn extract_ruleset_hint(
    body_lc: &str,
    rule_comment_id: &Option<String>,
    error_code: &Option<String>,
) -> Option<String> {
    if let Some(id) = rule_comment_id {
        return Some(id.clone());
    }

    // CVE IDs are maximally specific (check before generic error code mapping).
    if let Some(cve) = extract_cve_id(body_lc) {
        return Some(cve);
    }

    if let Some(code) = error_code {
        let mapped = match code.as_str() {
            "1000" | "1001" | "1002" => "dns-resolution",
            "1003" | "1004" | "1014" => "cname-cross-user",
            "1006" | "1007" | "1008" | "1009" => "ip-banned",
            "1010" => "browser-integrity",
            "1011" => "hotlinking",
            "1012" => "access-denied",
            "1013" => "http-https-mismatch",
            "1015" => "rate-limited",
            "1016" => "origin-dns",
            "1018" => "host-not-found",
            "1019" | "1021" | "1022" | "1033" | "1038" | "1042" => "cf-worker-error",
            "1020" => "waf-managed-rule",
            "1023" | "1024" => "challenge-verification",
            "1025" => "challenge-loop",
            "1034" => "ip-restricted",
            "1035" | "1036" => "invalid-request",
            "1037" => "redirect-loop",
            _ => return extract_ruleset_from_body(body_lc),
        };
        return Some(mapped.to_string());
    }

    extract_ruleset_from_body(body_lc)
}

/// Scan body text for ruleset group identifiers.
fn extract_ruleset_from_body(body_lc: &str) -> Option<String> {
    if let Some(cve) = extract_cve_id(body_lc) {
        return Some(cve);
    }

    let patterns: &[(&str, &str)] = &[
        ("log4j", "log4shell"),
        ("log4shell", "log4shell"),
        ("spring4shell", "spring4shell"),
        ("shellshock", "shellshock"),
        ("heartbleed", "heartbleed"),
        ("struts2", "apache-struts2"),
        ("struts", "apache-struts"),
        ("wordpress", "wordpress"),
        ("drupal", "drupal"),
        ("joomla", "joomla"),
        ("magento", "magento"),
        ("phpbb", "phpbb"),
        ("nextcloud", "nextcloud"),
        ("sql injection", "sqli"),
        ("cross-site scripting", "xss"),
        ("xss", "xss"),
        ("command injection", "cmdi"),
        ("path traversal", "path-traversal"),
        ("local file inclusion", "lfi"),
        ("remote file inclusion", "rfi"),
        ("server-side template", "ssti"),
        ("ssrf", "ssrf"),
        ("owasp", "owasp"),
        ("modsecurity", "modsecurity"),
        ("cloudflare managed", "cf-managed"),
        ("cloudflare specials", "cf-specials"),
    ];

    for (needle, group) in patterns {
        if body_lc.contains(needle) {
            return Some(group.to_string());
        }
    }

    None
}

/// Extract the first CVE identifier from body text (case-insensitive input).
fn extract_cve_id(body_lc: &str) -> Option<String> {
    let mut search = body_lc;
    while let Some(pos) = search.find("cve-") {
        let after = &search[pos..];
        let candidate: String = after
            .chars()
            .take(16)
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        let parts: Vec<&str> = candidate.split('-').collect();
        if parts.len() == 3
            && parts[0] == "cve"
            && parts[1].len() == 4
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && parts[2].len() >= 4
            && parts[2].chars().all(|c| c.is_ascii_digit())
        {
            return Some(candidate.to_ascii_uppercase());
        }
        // Advance past this match to search for next
        search = &search[pos + 4..];
    }
    None
}

/// Determine the block class from all available signals.
#[allow(clippy::too_many_arguments)]
fn classify_block_class(
    mitigated_reason: &Option<String>,
    has_retry_after: bool,
    body_has_jschl: bool,
    body_has_challenge_platform: bool,
    body_has_turnstile: bool,
    body_has_under_attack: bool,
    body_has_browser_check: bool,
    body_has_blocked_phrase: bool,
    body_has_manual_review: bool,
    body_has_rate_limit: bool,
) -> BlockClass {
    // `Retry-After` header is the strongest unambiguous rate-limit signal
    // it wins over everything, even an explicit cf-mitigated header, because
    // a cf-mitigated:block response that ALSO carries Retry-After is CF's
    // way of combining a temporary ban with a structured retry directive.
    if has_retry_after {
        return BlockClass::RateLimited;
    }

    if let Some(reason) = mitigated_reason {
        return match reason.as_str() {
            "block" => {
                // cf-mitigated: block is a strong explicit signal that takes
                // priority over weak body-text rate-limit patterns.  A block
                // page that mentions "rate limit" in its footer (e.g. CF's own
                // "your IP was rate-limited and then blocked" copy) must NOT
                // be reclassified, only an explicit header or a body-only
                // rate-limit page without cf-mitigated should trigger
                // RateLimited.
                BlockClass::ManagedRulesetBlock
            }
            "challenge" => {
                if body_has_turnstile {
                    BlockClass::Captcha
                } else if body_has_under_attack || body_has_browser_check {
                    BlockClass::BrowserCheck
                } else {
                    BlockClass::BotChallenge
                }
            }
            "jschallenge" | "managed_challenge" => BlockClass::BotChallenge,
            "rate-limit" => BlockClass::RateLimited,
            _ => {
                // Unknown mitigated value: fall back to body signals, including
                // weak body-text rate-limit patterns.
                if body_has_rate_limit {
                    return BlockClass::RateLimited;
                }
                classify_from_body(
                    body_has_jschl,
                    body_has_challenge_platform,
                    body_has_turnstile,
                    body_has_under_attack,
                    body_has_browser_check,
                    body_has_blocked_phrase,
                    body_has_manual_review,
                )
            }
        };
    }

    // No cf-mitigated header: body-text rate-limit patterns are the only
    // signal available, so they're authoritative in this branch.
    if body_has_rate_limit {
        return BlockClass::RateLimited;
    }

    classify_from_body(
        body_has_jschl,
        body_has_challenge_platform,
        body_has_turnstile,
        body_has_under_attack,
        body_has_browser_check,
        body_has_blocked_phrase,
        body_has_manual_review,
    )
}

fn classify_from_body(
    body_has_jschl: bool,
    body_has_challenge_platform: bool,
    body_has_turnstile: bool,
    body_has_under_attack: bool,
    body_has_browser_check: bool,
    body_has_blocked_phrase: bool,
    body_has_manual_review: bool,
) -> BlockClass {
    if body_has_jschl || body_has_challenge_platform {
        BlockClass::BotChallenge
    } else if body_has_turnstile {
        BlockClass::Captcha
    } else if body_has_under_attack || body_has_browser_check {
        BlockClass::BrowserCheck
    } else if body_has_blocked_phrase {
        BlockClass::ManagedRulesetBlock
    } else if body_has_manual_review {
        BlockClass::ManualReview
    } else {
        BlockClass::Unknown
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "cloudflare_tests.rs"]
mod tests;
