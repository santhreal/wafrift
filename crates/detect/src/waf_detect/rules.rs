//! Runtime-loaded WAF detection rules from `rules/detect/*.toml`.
//!
//! # Performance architecture
//!
//! All body-regex patterns from all 160+ WAFs are compiled into a single
//! [`regex::RegexSet`].  When a response arrives, the body is scanned
//! **once** against the entire set. O(n) in body length regardless of
//! pattern count.  The set returns which pattern indices matched, and
//! we map those back to their owning WAF rules to accumulate scores.
//!
//! Header and cookie patterns remain per-signature `Regex` objects
//! because the scan input is small (a few header values) and pattern
//! count per-header is low.
//!
//! # Signature provenance
//!
//! The catalog under `rules/detect/*.toml` is derived from the
//! [wafw00f](https://github.com/EnableSecurity/wafw00f) project
//! (BSD-3-Clause) plus selective contributions from
//! [identYwaf](https://github.com/stamparm/identYwaf) (MIT) and
//! locally researched additions. Every rule carries a `source`
//! field (`WAFW00F:<plugin>`, `IDENTYWAF:<probe>`, or
//! `wafrift:<context>`) that points back at the originating
//! plugin/probe so signature provenance is auditable.

use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::RwLock;

/// Maximum length of an individual regex pattern (bytes). Patterns
/// exceeding this are skipped to mitigate `ReDoS` and pathological
/// compilation times from malicious or corrupted rule files.
const MAX_REGEX_PATTERN_LEN: usize = 4096;

/// Maximum number of body-regex patterns compiled into the global
/// `RegexSet`. Excess patterns are dropped with a warning.
const MAX_BODY_REGEX_PATTERNS: usize = 2000;

/// Minimum confidence required for detections based only on body text.
///
/// Body-only matches are easier to spoof with generic wording (for example
/// benign 404 pages containing "forbidden"), so require stronger evidence.
const BODY_ONLY_MIN_CONFIDENCE: f64 = 0.5;

/// Take up to `max` bytes of `s` starting at byte offset `start`,
/// snapping both ends to UTF-8 character boundaries so the slice can
/// never panic.
///
/// `Regex::find` returns char-boundary-aligned `start`/`end`, but the
/// previous code computed the end as `m.end().min(m.start() + 40)`
/// `m.start() + 40` is an arbitrary byte offset that lands mid-codepoint
/// whenever a multibyte character (any non-ASCII byte in a WAF block
/// page or header value: `é`, `”`, `→`, NBSP, …) straddles it. That
/// slice panicked the whole detector on attacker-influenced response
/// text. This helper is the bounded, boundary-safe replacement.
/// Compile a WAF-detection regex with case-insensitive matching forced
/// on by default. Detection patterns come from a heterogenous catalog
/// (wafw00f, identYwaf, locally researched) and authors routinely write
/// the literal vendor banner they see. `Cloudflare`, `BinarySec`,
/// `KEMP-LM`, `cache-[a-z]{3}[0-9]+-[A-Z]{3}`: without an explicit
/// `(?i)` flag.  Meanwhile the public CLI entry point
/// (`classifier::detect`) historically lowercased every header value
/// before passing it to the engine, so any uppercase character class
/// (`[A-Z]`) or capitalized literal silently failed to match real
/// traffic.  Forcing `(?i)` at compile time means the rule body says
/// what the author meant ("match this token") and case is irrelevant.
/// Authors who genuinely need case-sensitive matching can opt out with
/// an inline `(?-i)` flag, preserved verbatim because we only prepend
/// when the pattern doesn't already declare an outer case flag.
/// Compilation size cap, workspace-canonical value from
/// [`wafrift_types::REGEX_NFA_SIZE_LIMIT`].
///
/// `Regex::new` (and `RegexSet::new`) are linear-time at *match* time but
/// have no built-in bound on *compile* time.  A pattern like `(a?){200}`,
/// which is only 10 bytes and trivially passes `MAX_REGEX_PATTERN_LEN`,
/// causes O(2^N) NFA expansion during `RegexBuilder::build()`.
/// `size_limit` caps the compiled NFA byte-size and converts the
/// exponential-compile-time attack into a fast, controlled error.
const REGEX_COMPILE_SIZE_LIMIT: usize = wafrift_types::REGEX_NFA_SIZE_LIMIT;

fn compile_ci_regex(pattern: &str, kind: &str) -> Result<Regex, String> {
    // Look for an `i` flag (positive or negated) anywhere in the
    // first `(?FLAGS)` or `(?FLAGS:...)` group, not just at exact
    // prefix positions. Pre-fix this only matched the four exact
    // strings `(?i)`, `(?-i)`, `(?i-`, `(?-i-`: a rule author
    // writing `(?si)` (dotall + case-insensitive), `(?mi)`, or
    // `(?-si)` (which EXPLICITLY disables `i`) tripped the wrap.
    // The `(?-si)` case was the worst: the engine prepended `(?i)`
    // over the author's explicit case-sensitive intent.
    //
    // Important: the flag chars are between `(?` and the FIRST
    // `:` or `)`: not just up to the first `)`. A non-capturing
    // group like `(?:F5\-TrafficShield)` has no flags; the colon
    // delimits the "flags" from the pattern body, and anything
    // after the `:` (even a literal `i`) is regex syntax, not a
    // flag.
    let has_outer_case_flag = pattern.starts_with("(?")
        && pattern[2..]
            .split([':', ')'])
            .next()
            .is_some_and(|flags| flags.contains('i'));
    let full = if has_outer_case_flag {
        pattern.to_string()
    } else {
        format!("(?i){pattern}")
    };
    // Use RegexBuilder with size_limit to cap compile-time NFA explosion.
    // A length-bounded pattern (MAX_REGEX_PATTERN_LEN = 4096 bytes) can
    // still cause O(2^N) NFA expansion (e.g. `(a?){200}`). size_limit
    // converts that into a fast Err rather than a hang.
    regex::RegexBuilder::new(&full)
        .size_limit(REGEX_COMPILE_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("bad {kind} regex '{pattern}': {e}"))
}

/// Strip a leading `(?...)` inline-flag group from a regex source.
/// Used by catalog-walking tests that need to see the author's
/// LITERAL pattern after the engine's auto-`(?i)` wrap.  Returns the
/// original string when no outer flag group is present.  Does not
/// attempt to parse nested flag groups (only the outermost one).
#[cfg(test)]
fn strip_outer_flag_group(src: &str) -> &str {
    if !src.starts_with("(?") {
        return src;
    }
    // Find the matching ')' that closes the flag group.  Flag
    // groups don't nest (regex syntax forbids it) so a linear
    // scan from byte 2 to the first ')' is safe.
    let bytes = src.as_bytes();
    let mut i = 2;
    while i < bytes.len() && bytes[i] != b')' {
        // A `:` inside the flag group means it's a NON-capturing
        // group with flag scope (e.g. `(?i:foo)`), we don't want
        // to strip the inner content.
        if bytes[i] == b':' {
            return src;
        }
        i += 1;
    }
    if i < bytes.len() { &src[i + 1..] } else { src }
}

fn clamped_snippet(s: &str, start: usize, max: usize) -> &str {
    if start >= s.len() {
        return "";
    }
    // Snap `start` down to a char boundary (it should already be one
    // from a regex match, but never trust the offset).
    let mut lo = start;
    while lo > 0 && !s.is_char_boundary(lo) {
        lo -= 1;
    }
    // Snap the desired end up/down to a char boundary within bounds.
    let mut hi = lo.saturating_add(max).min(s.len());
    while hi > lo && !s.is_char_boundary(hi) {
        hi -= 1;
    }
    &s[lo..hi]
}

/// Global in-memory rule database.
static RULE_DB: Lazy<RwLock<RuleEngine>> = Lazy::new(|| {
    let engine = RuleEngine::load_embedded().unwrap_or_else(|e| {
        tracing::warn!("Failed to load embedded WAF rules: {e}");
        RuleEngine::default()
    });
    RwLock::new(engine)
});

/// A loaded and compiled WAF rule engine.
///
/// Contains both per-rule compiled signatures (for headers/cookies/status)
/// and a global `RegexSet` that batches all body patterns for O(n) scanning.
#[derive(Debug, Default, Clone)]
pub struct RuleEngine {
    /// All compiled WAF rules, keyed by normalized name.
    pub rules: HashMap<String, CompiledWafRule>,
    /// Ordered list of rule names for deterministic iteration.
    pub names: Vec<String>,

    /// All body-regex patterns compiled into a single `RegexSet`.
    /// Each pattern index maps to an entry in `body_pattern_map`.
    body_regex_set: Option<RegexSet>,

    /// Maps each `RegexSet` pattern index → `(waf_name, signature_index, weight)`.
    ///
    /// When the `RegexSet` reports pattern `i` matched, we look up
    /// `body_pattern_map[i]` to find which WAF rule and signature
    /// produced the hit.
    body_pattern_map: Vec<BodyPatternRef>,

    /// Individual body regexes (same order as `body_pattern_map`) used
    /// to extract match snippets for indicator messages.  The `RegexSet`
    /// tells us *which* patterns matched; these tell us *where*.
    body_regexes: Vec<Regex>,
}

/// Reference from a body pattern index back to its owning WAF rule.
#[derive(Debug, Clone)]
struct BodyPatternRef {
    /// WAF rule name (key into `RuleEngine::rules`).
    waf_name: String,
    /// Weight of this signature.
    weight: f64,
}

/// A WAF rule with compiled regex patterns.
#[derive(Debug, Clone)]
pub struct CompiledWafRule {
    pub name: String,
    pub vendor: String,
    pub confidence_threshold: f64,
    pub evasions: Vec<String>,
    pub source: String,
    pub signatures: Vec<CompiledSignature>,
}

/// A compiled signature ready for matching.
///
/// `body_regex` is `None` after engine finalization, body matching is
/// delegated to the global `RegexSet`.  The field is kept for the
/// compilation phase only.
#[derive(Debug, Clone)]
pub struct CompiledSignature {
    pub header_name: Option<String>,
    pub header_regex: Option<Regex>,
    pub cookie_regex: Option<Regex>,
    /// Kept for backward compatibility but body matching uses the
    /// engine-level `RegexSet` + `body_regexes` instead.
    pub body_regex: Option<Regex>,
    pub status_code: Option<u16>,
    pub weight: f64,
}

/// Raw TOML rule database structure.
#[derive(Debug, Clone, Deserialize)]
struct RawRuleDb {
    #[serde(default)]
    waf: Vec<RawWafRule>,
}

/// Raw TOML WAF rule.
#[derive(Debug, Clone, Deserialize)]
struct RawWafRule {
    name: String,
    vendor: String,
    #[serde(default = "default_threshold")]
    confidence_threshold: f64,
    #[serde(default)]
    evasions: Vec<String>,
    #[serde(default)]
    source: String,
    #[serde(default)]
    signature: Vec<RawSignature>,
}

/// Raw TOML signature.
#[derive(Debug, Clone, Deserialize)]
struct RawSignature {
    header_name: Option<String>,
    header_regex: Option<String>,
    cookie_regex: Option<String>,
    body_regex: Option<String>,
    status_code: Option<u16>,
    #[serde(default = "default_weight")]
    weight: f64,
}

fn default_threshold() -> f64 {
    0.3
}

fn default_weight() -> f64 {
    0.4
}

/// Compile-time embedded detection rules, generated by `build.rs`.
///
/// This is the concatenation of all `rules/detect/*.toml` files,
/// baked into the binary so `cargo install wafrift` produces a
/// standalone executable with no runtime filesystem dependency.
const EMBEDDED_RULES_TOML: &str =
    include_str!(concat!(env!("OUT_DIR"), "/embedded_detect_rules.toml"));

impl RuleEngine {
    /// Load WAF detection rules.
    ///
    /// **Loading order** (first success wins):
    ///
    /// 1. **Compile-time embedded**: `build.rs` concatenates all
    ///    `rules/detect/*.toml` into the binary.  This is the
    ///    production path for `cargo install` users.
    /// 2. **Filesystem fallback**: walks `rules/detect/` at relative
    ///    paths.  Used during development when you want hot-reload
    ///    via [`reload`].
    pub fn load_embedded() -> Result<Self, DetectRulesError> {
        let mut engine = RuleEngine {
            rules: HashMap::new(),
            names: Vec::new(),
            body_regex_set: None,
            body_pattern_map: Vec::new(),
            body_regexes: Vec::new(),
        };

        // Tier 1: Try compile-time embedded rules.
        let embedded_ok =
            engine.load_from_str(EMBEDDED_RULES_TOML).is_ok() && !engine.rules.is_empty();

        // Tier 2: Filesystem fallback (development, or if embedded is empty).
        if !embedded_ok {
            let candidates = [
                std::path::PathBuf::from("rules/detect"),
                std::path::PathBuf::from("../rules/detect"),
                std::path::PathBuf::from("../../rules/detect"),
            ];

            let mut loaded = false;
            for dir in &candidates {
                if dir.is_dir() {
                    engine.load_directory(dir)?;
                    loaded = true;
                    break;
                }
            }

            if !loaded {
                return Err(DetectRulesError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "rules/detect directory not found and no embedded rules available",
                )));
            }
        }

        // Finalize: compile the global body RegexSet.
        engine.compile_body_regex_set()?;

        Ok(engine)
    }

    /// Parse a TOML string containing `[[waf]]` entries.
    ///
    /// Used by both the compile-time embedded path and hot-reload.
    pub fn load_from_str(&mut self, toml_content: &str) -> Result<(), DetectRulesError> {
        let raw: RawRuleDb = toml::from_str(toml_content)
            .map_err(|e| DetectRulesError::Parse(format!("embedded rules: {e}")))?;
        for waf in raw.waf {
            let compiled = Self::compile_waf(waf)
                .map_err(|e| DetectRulesError::Parse(format!("embedded rules: {e}")))?;
            let key = compiled.name.clone();
            if !self.rules.contains_key(&key) {
                self.names.push(key.clone());
            }
            self.rules.insert(key, compiled);
        }
        Ok(())
    }

    /// Load all `.toml` files from a directory.
    ///
    /// Strict: I/O errors bubble up via `?`; per-file parse and
    /// compile errors abort the whole load. Iteration + sort + read
    /// is shared with `ResponseProfileDb::load_dir` via
    /// [`wafrift_types::loaders`].
    pub fn load_directory(&mut self, path: &std::path::Path) -> Result<(), DetectRulesError> {
        for (entry, content) in wafrift_types::loaders::read_toml_files_strict(path)? {
            let raw: RawRuleDb = toml::from_str(&content)
                .map_err(|e| DetectRulesError::Parse(format!("{}: {e}", entry.display())))?;
            for waf in raw.waf {
                let compiled = Self::compile_waf(waf)
                    .map_err(|e| DetectRulesError::Parse(format!("{}: {e}", entry.display())))?;
                let key = compiled.name.clone();
                if !self.rules.contains_key(&key) {
                    self.names.push(key.clone());
                }
                self.rules.insert(key, compiled);
            }
        }
        Ok(())
    }

    fn compile_waf(raw: RawWafRule) -> Result<CompiledWafRule, String> {
        let mut signatures = Vec::with_capacity(raw.signature.len());
        for sig in raw.signature {
            let header_regex = sig
                .header_regex
                .as_ref()
                .filter(|p| {
                    if p.len() > MAX_REGEX_PATTERN_LEN {
                        tracing::warn!(
                            waf = %raw.name,
                            pattern_len = p.len(),
                            max = MAX_REGEX_PATTERN_LEN,
                            "skipping oversized header regex"
                        );
                        false
                    } else {
                        true
                    }
                })
                .map(|p| compile_ci_regex(p, "header"))
                .transpose()?;
            let cookie_regex = sig
                .cookie_regex
                .as_ref()
                .filter(|p| {
                    if p.len() > MAX_REGEX_PATTERN_LEN {
                        tracing::warn!(
                            waf = %raw.name,
                            pattern_len = p.len(),
                            max = MAX_REGEX_PATTERN_LEN,
                            "skipping oversized cookie regex"
                        );
                        false
                    } else {
                        true
                    }
                })
                .map(|p| compile_ci_regex(p, "cookie"))
                .transpose()?;
            let body_regex = sig
                .body_regex
                .as_ref()
                .filter(|p| {
                    if p.len() > MAX_REGEX_PATTERN_LEN {
                        tracing::warn!(
                            waf = %raw.name,
                            pattern_len = p.len(),
                            max = MAX_REGEX_PATTERN_LEN,
                            "skipping oversized body regex"
                        );
                        false
                    } else {
                        true
                    }
                })
                .map(|p| compile_ci_regex(p, "body"))
                .transpose()?;
            signatures.push(CompiledSignature {
                header_name: sig.header_name.map(|s| s.to_ascii_lowercase()),
                header_regex,
                cookie_regex,
                body_regex,
                status_code: sig.status_code,
                weight: sig.weight,
            });
        }
        Ok(CompiledWafRule {
            name: raw.name,
            vendor: raw.vendor,
            confidence_threshold: raw.confidence_threshold,
            evasions: raw.evasions,
            source: raw.source,
            signatures,
        })
    }

    /// Compile all body-regex patterns across all rules into a single
    /// `RegexSet` for batch scanning.
    ///
    /// Must be called after all rules are loaded.  Populates
    /// `body_regex_set`, `body_pattern_map`, and `body_regexes`.
    pub fn compile_body_regex_set(&mut self) -> Result<(), DetectRulesError> {
        let mut patterns: Vec<String> = Vec::new();
        let mut map: Vec<BodyPatternRef> = Vec::new();
        let mut regexes: Vec<Regex> = Vec::new();

        for name in &self.names {
            let rule = &self.rules[name];
            for sig in &rule.signatures {
                if let Some(ref re) = sig.body_regex {
                    if patterns.len() >= MAX_BODY_REGEX_PATTERNS {
                        // Name the WAF being truncated so the
                        // operator can see exactly which family
                        // lost coverage, pre-fix this was a
                        // bare "some signatures will not match"
                        // warning with no indication of which.
                        tracing::warn!(
                            limit = MAX_BODY_REGEX_PATTERNS,
                            waf_truncation_started_at = %name,
                            "body regex set hit cap; signatures for this WAF \
                             and every WAF after it in iteration order will \
                             NOT match on body text. Consider raising \
                             MAX_BODY_REGEX_PATTERNS or pruning low-weight \
                             rules."
                        );
                        break;
                    }
                    patterns.push(re.as_str().to_string());
                    map.push(BodyPatternRef {
                        waf_name: name.clone(),
                        weight: sig.weight,
                    });
                    regexes.push(re.clone());
                }
            }
            if patterns.len() >= MAX_BODY_REGEX_PATTERNS {
                break;
            }
        }

        if !patterns.is_empty() {
            // Apply the same NFA-explosion guard used by individual regexes.
            // RegexSetBuilder::size_limit caps the *total* NFA byte size
            // across all patterns in the set, preventing a crafted rule file
            // from causing compile-time hang via deeply-nested alternation.
            let set = regex::RegexSetBuilder::new(&patterns)
                .size_limit(REGEX_COMPILE_SIZE_LIMIT)
                .build()
                .map_err(|e| {
                    DetectRulesError::Parse(format!("failed to compile body RegexSet: {e}"))
                })?;
            self.body_regex_set = Some(set);
        }

        self.body_pattern_map = map;
        self.body_regexes = regexes;
        Ok(())
    }

    /// Run detection against all rules and return scored matches.
    ///
    /// Body scanning is performed once via the compiled `RegexSet`,
    /// then header/cookie/status checks run per-rule only for WAFs
    /// that have non-body signatures.
    pub fn detect(
        &self,
        status: u16,
        headers: &[(String, String)],
        body: &str,
    ) -> Vec<DetectedWaf> {
        // ── Phase 1: Batch body scan ──
        //
        // Single-pass scan of the body against ALL body patterns.
        // Returns the set of pattern indices that matched.
        let body_hits: Vec<usize> = self
            .body_regex_set
            .as_ref()
            .map(|set| set.matches(body).into_iter().collect())
            .unwrap_or_default();

        // Accumulate body-hit scores per WAF.
        let mut waf_scores: HashMap<&str, (f64, Vec<String>)> = HashMap::new();

        for &pattern_idx in &body_hits {
            let pref = &self.body_pattern_map[pattern_idx];
            let entry = waf_scores
                .entry(&pref.waf_name)
                .or_insert_with(|| (0.0, Vec::new()));
            entry.0 += pref.weight;

            // Extract match snippet for the indicator message.
            if let Some(m) = self.body_regexes[pattern_idx].find(body) {
                let snippet = clamped_snippet(body, m.start(), 40);
                entry.1.push(format!("body: {snippet}"));
            }
        }

        // ── Phase 2: Per-rule header/cookie/status scoring ──
        //
        // Only iterate signatures that have non-body matchers.
        for name in &self.names {
            let rule = &self.rules[name];
            for sig in &rule.signatures {
                // Skip body-only signatures (already handled by RegexSet).
                if sig.header_regex.is_none()
                    && sig.cookie_regex.is_none()
                    && sig.status_code.is_none()
                {
                    continue;
                }

                let mut matched = false;
                let entry = waf_scores.entry(name).or_insert_with(|| (0.0, Vec::new()));

                if let Some(expected) = sig.status_code
                    && status == expected
                {
                    matched = true;
                    entry.1.push(format!("status: {status}"));
                }

                if let Some(ref re) = sig.header_regex {
                    let hname = sig.header_name.as_deref().unwrap_or("");
                    for (k, v) in headers {
                        if (hname.is_empty() || k.eq_ignore_ascii_case(hname))
                            && let Some(m) = re.find(v)
                        {
                            matched = true;
                            entry
                                .1
                                .push(format!("header {k}: {}", clamped_snippet(v, m.start(), 40)));
                            break;
                        }
                    }
                }

                if let Some(ref re) = sig.cookie_regex {
                    for (k, v) in headers {
                        if k.eq_ignore_ascii_case("set-cookie") && re.is_match(v) {
                            matched = true;
                            entry.1.push(format!("cookie: {k}"));
                            break;
                        }
                    }
                }

                if matched {
                    entry.0 += sig.weight;
                }
            }
        }

        // ── Phase 3: Filter and sort ──
        let mut results: Vec<DetectedWaf> = waf_scores
            .into_iter()
            .filter_map(|(name, (score, indicators))| {
                let rule = &self.rules[name];
                let has_non_body_indicator = indicators
                    .iter()
                    .any(|indicator| !indicator.starts_with("body: "));
                let effective_threshold = if has_non_body_indicator {
                    rule.confidence_threshold
                } else {
                    rule.confidence_threshold.max(BODY_ONLY_MIN_CONFIDENCE)
                };
                if score >= effective_threshold {
                    Some(DetectedWaf {
                        name: name.to_string(),
                        confidence: score.min(1.0),
                        indicators,
                    })
                } else {
                    None
                }
            })
            .collect();

        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });
        results
    }

    /// Lookup evasion techniques for a detected WAF name.
    #[must_use]
    pub fn evasions_for(&self, name: &str) -> Vec<&str> {
        self.rules
            .get(name)
            .map(|r| r.evasions.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Number of loaded rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Result of WAF detection.
#[derive(Debug, Clone)]
pub struct DetectedWaf {
    pub name: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
}

/// Errors that can occur while loading rules.
#[derive(Debug, thiserror::Error)]
pub enum DetectRulesError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
}

/// Access the global rule engine (read lock).
pub fn with_engine<F, R>(f: F) -> R
where
    F: FnOnce(&RuleEngine) -> R,
{
    let guard = RULE_DB
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&guard)
}

/// Reload the global rule engine from disk.
pub fn reload() -> Result<(), DetectRulesError> {
    let new_engine = RuleEngine::load_embedded()?;
    let mut guard = RULE_DB
        .write()
        .map_err(|e| DetectRulesError::Parse(format!("RULE_DB poisoned: {e}")))?;
    *guard = new_engine;
    Ok(())
}

/// Detect WAFs using the global rule engine.
#[must_use]
pub fn detect(status: u16, headers: &[(String, String)], body: &str) -> Vec<DetectedWaf> {
    with_engine(|engine| engine.detect(status, headers, body))
}

/// Returns the names of all supported WAF detectors.
#[must_use]
pub fn supported_wafs() -> Vec<String> {
    with_engine(|engine| engine.names.clone())
}

/// Suggest evasions for a WAF name using the global rule engine.
///
/// Returns owned `String`s so callers can keep them past the engine's
/// `RwLock` guard. The previous version returned `&'static str` via
/// `Box::leak` on every call, at sustained proxy traffic that leaked
/// ~100 KB/sec (4 strings × ~25 chars × 1000 req/s) and ~360 MB/hour.
/// The leaked-string optimisation was wrong: `suggest_evasion` runs in
/// the per-response hot path, not once at startup.
#[must_use]
pub fn suggest_evasion(waf_name: &str) -> Vec<String> {
    with_engine(|engine| {
        engine.rules.get(waf_name).map_or_else(
            || {
                vec![
                    "CaseAlternation".into(),
                    "SqlCommentInsertion".into(),
                    "DoubleUrlEncode".into(),
                    "ContentTypeSwitch".into(),
                ]
            },
            |r| r.evasions.clone(),
        )
    })
}

/// Configuration for ambiguity reporting.
#[derive(Debug, Clone, Copy)]
pub struct DetectConfig {
    /// Minimum confidence for a WAF to be reported.
    pub threshold: f64,
    /// If top-2 confidence delta is smaller than this, report both.
    pub ambiguity_delta: f64,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            threshold: 0.3,
            ambiguity_delta: 0.15,
        }
    }
}

/// Detect with ambiguity filtering.
#[must_use]
pub fn detect_with_config(
    status: u16,
    headers: &[(String, String)],
    body: &str,
    config: DetectConfig,
) -> Vec<DetectedWaf> {
    let mut results = detect(status, headers, body);
    results.retain(|r| r.confidence >= config.threshold);

    if results.len() >= 2 {
        let delta = results[0].confidence - results[1].confidence;
        if delta < config.ambiguity_delta {
            // Keep top N until delta exceeds threshold
            let mut keep = 2;
            for window in results.windows(2) {
                if window[0].confidence - window[1].confidence < config.ambiguity_delta {
                    keep += 1;
                } else {
                    break;
                }
            }
            results.truncate(keep);
        } else {
            results.truncate(1);
        }
    }
    results
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;
