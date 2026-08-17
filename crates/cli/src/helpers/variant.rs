//! Strategy selection, confidence scoring, and variant building.

use colored::Colorize;
use std::collections::HashSet;

use wafrift_encoding::encoding::{self, Strategy};
use wafrift_evolution::differential::ProbeTarget;
use wafrift_grammar::grammar::{self, PayloadType};

use crate::Level;
use crate::explain::{ExplainTrace, Outcome};
use crate::target_context::{TargetContext, context_applicability};

pub const LIGHT_VARIANTS: usize = 4;

pub const MEDIUM_VARIANTS: usize = 12;

pub const HEAVY_VARIANTS: usize = 50;

/// Confidence thresholds for the colour-coded badge (§6 NO HARDCODING).
/// At or above HIGH_CONFIDENCE_THRESHOLD → bright-green; at or above
/// MED_CONFIDENCE_THRESHOLD → yellow; below → red. Named here so a
/// change to the badge ranges requires editing one place, not grepping
/// for the raw float literals.
pub const HIGH_CONFIDENCE_THRESHOLD: f64 = 0.9;

pub const MED_CONFIDENCE_THRESHOLD: f64 = 0.75;

/// Grammar bonus per rule applied (additive, capped at GRAMMAR_BONUS_CAP).
/// Extracted from `variant_confidence` so the growth rate and ceiling are
/// visible in one place, previously both were magic float literals
/// embedded inside the scoring function (§6).
pub const GRAMMAR_BONUS_PER_RULE: f64 = 0.04;

pub const GRAMMAR_BONUS_CAP: f64 = 0.12;

pub struct Variant {
    pub payload: String,
    pub techniques: Vec<String>,
    pub confidence: f64,
}

pub fn strategies_for_level(level: Level) -> Vec<Strategy> {
    let all = encoding::all_strategies();
    match level {
        Level::Light => all.iter().copied().take(3).collect(),
        Level::Medium => all.iter().copied().take(6).collect(),
        Level::Heavy => all.to_vec(),
    }
}

/// Strategy pool for a `--level`, widened to the full set when the user
/// has named techniques explicitly via `--only`. Rationale: a user who
/// types `--only encoding/base64/standard --level light` expects base64
/// to run, not be silently dropped because base64 sits above the
/// light-level aggressiveness cut. `--level` still bounds the variant
/// count via `max_mutations_for_level`.
pub fn strategy_pool(level: Level, explicit_selection: bool) -> Vec<Strategy> {
    if explicit_selection {
        encoding::all_strategies().to_vec()
    } else {
        strategies_for_level(level)
    }
}

pub fn max_mutations_for_level(level: Level) -> usize {
    match level {
        Level::Light => LIGHT_VARIANTS,
        Level::Medium => MEDIUM_VARIANTS,
        Level::Heavy => HEAVY_VARIANTS,
    }
}

pub fn payload_type_label(payload_type: PayloadType) -> &'static str {
    match payload_type {
        PayloadType::Sql => "SQL Injection",
        PayloadType::Xss => "XSS",
        PayloadType::CommandInjection => "Command Injection",
        PayloadType::Ldap => "LDAP Injection",
        PayloadType::Ssrf => "SSRF",
        PayloadType::PathTraversal => "Path Traversal",
        PayloadType::TemplateInjection => "Template Injection",
        _ => "Unknown",
    }
}

pub fn variant_confidence(
    payload_type: PayloadType,
    grammar_rule_count: usize,
    encoding_only: bool,
    strategy: Strategy,
) -> f64 {
    let type_score = match payload_type {
        PayloadType::Unknown => 0.45,
        PayloadType::Ldap
        | PayloadType::Ssrf
        | PayloadType::PathTraversal
        | PayloadType::TemplateInjection
        | PayloadType::Ssi => 0.72,
        PayloadType::Sql | PayloadType::Xss | PayloadType::CommandInjection => 0.82,
        _ => 0.45,
    };

    let grammar_bonus = if encoding_only {
        0.0
    } else {
        (grammar_rule_count as f64 * GRAMMAR_BONUS_PER_RULE).min(GRAMMAR_BONUS_CAP)
    };

    let strategy_score = match strategy {
        Strategy::CaseAlternation => 0.03,
        Strategy::WhitespaceInsertion => 0.05,
        Strategy::SqlCommentInsertion => 0.07,
        Strategy::UrlEncode => 0.05,
        Strategy::DoubleUrlEncode => 0.07,
        Strategy::UnicodeEncode => 0.06,
        Strategy::HtmlEntityEncode => 0.06,
        Strategy::NullByte => 0.08,
        Strategy::TripleUrlEncode => 0.09,
        Strategy::ChunkedSplit => 0.1,
        Strategy::ParameterPollution => 0.08,
        Strategy::OverlongUtf8 => 0.11,
        Strategy::Base64Encode => 0.05,
        Strategy::HexEncode => 0.05,
        Strategy::Utf7Encode => 0.07,
        _ => 0.05,
    };

    (type_score + grammar_bonus + strategy_score).min(0.99)
}

pub fn confidence_badge(confidence: f64) -> colored::ColoredString {
    let label = format!("confidence {:.0}%", (confidence * 100.0).round());
    if confidence >= HIGH_CONFIDENCE_THRESHOLD {
        label.bright_green().bold()
    } else if confidence >= MED_CONFIDENCE_THRESHOLD {
        label.yellow().bold()
    } else {
        label.red().bold()
    }
}

pub fn probe_target_label(target: &ProbeTarget) -> String {
    match target {
        ProbeTarget::SqlKeyword(value) => format!("sql_keyword:{value}"),
        ProbeTarget::SqlOperator(value) => format!("sql_operator:{value}"),
        ProbeTarget::SqlComment(value) => format!("sql_comment:{value}"),
        ProbeTarget::SqlQuote => "sql_quote".to_string(),
        ProbeTarget::SqlTautology(value) => format!("sql_tautology:{value}"),
        ProbeTarget::XssTag(value) => format!("xss_tag:{value}"),
        ProbeTarget::XssEvent(value) => format!("xss_event:{value}"),
        ProbeTarget::XssExecFunction(value) => format!("xss_exec_function:{value}"),
        ProbeTarget::CmdSeparator(value) => format!("cmd_separator:{value}"),
        ProbeTarget::CmdCommand(value) => format!("cmd_command:{value}"),
        ProbeTarget::CmdPath(value) => format!("cmd_path:{value}"),
        ProbeTarget::Baseline => "baseline".to_string(),
    }
}

/// Build encoding × grammar variants for a given payload.
///
/// Backwards-compatible wrapper around `build_variants_explained` for
/// callers (bench_waf, scan) that don't need context filtering or a
/// trace. Behavior is identical to the pre-explain implementation:
/// no applicability filtering, no per-strategy logging.
pub fn build_variants(
    payload: &str,
    payload_type: PayloadType,
    encoding_only: bool,
    strategies: &[Strategy],
    max_mutations: usize,
) -> Vec<Variant> {
    build_variants_explained(
        payload,
        payload_type,
        encoding_only,
        strategies,
        max_mutations,
        None,
        None,
    )
}

/// Like `build_variants` but optionally filters strategies by target
/// context and records per-strategy outcomes into an `ExplainTrace`.
///
/// Pass `target_context = None` to skip applicability filtering. Pass
/// `trace = None` to disable trace collection (then the result is
/// equivalent to `build_variants`, modulo context filtering).
pub fn build_variants_explained(
    payload: &str,
    payload_type: PayloadType,
    encoding_only: bool,
    strategies: &[Strategy],
    max_mutations: usize,
    target_context: Option<TargetContext>,
    mut trace: Option<&mut ExplainTrace>,
) -> Vec<Variant> {
    let applicable: Vec<Strategy> = strategies
        .iter()
        .copied()
        .filter(|s| match target_context {
            None => true,
            Some(ctx) => match context_applicability(*s, ctx) {
                Ok(()) => true,
                Err(reason) => {
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*s, Outcome::NotApplicableToContext(reason));
                    }
                    false
                }
            },
        })
        .collect();

    let mut seen = HashSet::new();
    let mut variants = Vec::new();

    let grammar_mutations = if encoding_only {
        Vec::new()
    } else {
        grammar::mutate_as(payload, payload_type, max_mutations)
    };

    for mutation in &grammar_mutations {
        if seen.insert(mutation.payload.clone()) {
            let techniques: Vec<String> = mutation
                .rules_applied
                .iter()
                .map(|rule| (*rule).to_string())
                .collect();
            variants.push(Variant {
                payload: mutation.payload.clone(),
                techniques,
                confidence: variant_confidence(
                    payload_type,
                    mutation.rules_applied.len(),
                    false,
                    Strategy::CaseAlternation,
                ),
            });
        }
    }

    for mutation in &grammar_mutations {
        for strategy in &applicable {
            match encoding::encode(&mutation.payload, *strategy) {
                Ok(encoded) => {
                    if seen.insert(encoded.clone()) {
                        let mut techniques: Vec<String> = mutation
                            .rules_applied
                            .iter()
                            .map(|rule| (*rule).to_string())
                            .collect();
                        // Issue-9 fix (dogfood R29 cohort): emit the canonical `encoding/url/single`
                        // path that `--only` accepts, not the Strategy debug name. Old form was
                        // `encoding::UrlEncode` which mismatched `wafrift techniques list` output
                        // and confused operators copy-pasting back into `--only`.
                        techniques
                            .push(crate::technique_filter::strategy_path(*strategy).to_string());
                        variants.push(Variant {
                            payload: encoded,
                            techniques,
                            confidence: variant_confidence(
                                payload_type,
                                mutation.rules_applied.len(),
                                false,
                                *strategy,
                            ),
                        });
                        if let Some(t) = trace.as_deref_mut() {
                            t.record(*strategy, Outcome::Applied { variant_count: 1 });
                        }
                    } else if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::AllDuplicates);
                    }
                }
                Err(e) => {
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::EncodingError(format!("{e:?}")));
                    }
                }
            }
        }
    }

    for strategy in &applicable {
        match encoding::encode(payload, *strategy) {
            Ok(encoded) => {
                if seen.insert(encoded.clone()) {
                    variants.push(Variant {
                        payload: encoded,
                        techniques: vec![
                            crate::technique_filter::strategy_path(*strategy).to_string(),
                        ],
                        confidence: variant_confidence(payload_type, 0, encoding_only, *strategy),
                    });
                    if let Some(t) = trace.as_deref_mut() {
                        t.record(*strategy, Outcome::Applied { variant_count: 1 });
                    }
                } else if let Some(t) = trace.as_deref_mut() {
                    t.record(*strategy, Outcome::AllDuplicates);
                }
            }
            Err(e) => {
                if let Some(t) = trace.as_deref_mut() {
                    t.record(*strategy, Outcome::EncodingError(format!("{e:?}")));
                }
            }
        }
    }

    if !encoding_only && seen.insert(payload.to_string()) {
        variants.insert(
            0,
            Variant {
                payload: payload.to_string(),
                techniques: vec!["original".to_string()],
                confidence: variant_confidence(payload_type, 0, false, Strategy::CaseAlternation),
            },
        );
    }

    if let Some(t) = trace {
        t.finalize();
    }

    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategies_for_level_scales_with_aggressiveness() {
        let light = strategies_for_level(Level::Light);
        let medium = strategies_for_level(Level::Medium);
        let heavy = strategies_for_level(Level::Heavy);

        assert_eq!(light.len(), 3);
        assert_eq!(medium.len(), 6);
        assert!(heavy.len() >= medium.len());
        assert!(heavy.contains(&Strategy::OverlongUtf8));
    }

    #[test]
    fn mutation_budget_matches_level() {
        assert_eq!(max_mutations_for_level(Level::Light), LIGHT_VARIANTS);
        assert_eq!(max_mutations_for_level(Level::Medium), MEDIUM_VARIANTS);
        assert_eq!(max_mutations_for_level(Level::Heavy), HEAVY_VARIANTS);
    }

    #[test]
    fn variant_confidence_rewards_stronger_strategies() {
        let light = variant_confidence(PayloadType::Sql, 1, false, Strategy::CaseAlternation);
        let heavy = variant_confidence(PayloadType::Sql, 3, false, Strategy::OverlongUtf8);

        assert!(heavy > light);
        assert!(heavy <= 0.99);
    }

    #[test]
    fn probe_target_label_formats_variants() {
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlKeyword("union".into())),
            "sql_keyword:union"
        );
        assert_eq!(probe_target_label(&ProbeTarget::Baseline), "baseline");
    }

    #[test]
    fn strategy_pool_widens_only_on_explicit_selection() {
        let default_light = strategy_pool(Level::Light, false);
        assert_eq!(default_light.len(), 3);

        let explicit_light = strategy_pool(Level::Light, true);
        let all = encoding::all_strategies();
        assert_eq!(explicit_light.len(), all.len());
        assert!(explicit_light.contains(&Strategy::Base64Encode));
        assert!(explicit_light.contains(&Strategy::OverlongUtf8));
    }

    #[test]
    fn build_variants_explained_filters_by_context() {
        let mut trace = ExplainTrace::default();
        let variants = build_variants_explained(
            "SELECT 1",
            PayloadType::Sql,
            true,
            &[Strategy::GzipEncode, Strategy::Base64Encode],
            4,
            Some(TargetContext::Header),
            Some(&mut trace),
        );
        let payloads: Vec<&str> = variants.iter().map(|v| v.payload.as_str()).collect();
        assert!(
            payloads.iter().any(|p| p.contains("U0VMRUNUIDE=")),
            "base64 variant should appear: {payloads:?}"
        );
        let recorded_paths: Vec<&str> = trace
            .entries
            .iter()
            .map(|e| crate::technique_filter::strategy_path(e.strategy))
            .collect();
        assert!(
            recorded_paths.contains(&"encoding/compression/gzip"),
            "gzip should be in the trace as not_applicable: {recorded_paths:?}"
        );
    }

    #[test]
    fn build_variants_unchanged_signature_still_works() {
        let variants = build_variants(
            "hello",
            PayloadType::Unknown,
            true,
            &[Strategy::Base64Encode],
            4,
        );
        assert!(
            variants.iter().any(|v| v.payload == "aGVsbG8="),
            "base64 of 'hello' should appear"
        );
    }

    #[test]
    fn payload_type_label_covers_every_known_class() {
        // A new PayloadType variant added without updating
        // payload_type_label silently falls into "Unknown", locks
        // every named variant in.
        assert_eq!(payload_type_label(PayloadType::Sql), "SQL Injection");
        assert_eq!(payload_type_label(PayloadType::Xss), "XSS");
        assert_eq!(
            payload_type_label(PayloadType::CommandInjection),
            "Command Injection"
        );
        assert_eq!(payload_type_label(PayloadType::Ldap), "LDAP Injection");
        assert_eq!(payload_type_label(PayloadType::Ssrf), "SSRF");
        assert_eq!(
            payload_type_label(PayloadType::PathTraversal),
            "Path Traversal"
        );
        assert_eq!(
            payload_type_label(PayloadType::TemplateInjection),
            "Template Injection"
        );
    }

    #[test]
    fn payload_type_label_unknown_falls_through_to_unknown_string() {
        assert_eq!(payload_type_label(PayloadType::Unknown), "Unknown");
    }

    #[test]
    fn variant_confidence_is_never_above_ninety_nine_percent() {
        // The closed-form sum bumps against the .min(0.99) clamp
        // for the strongest combination. Anti-rig against a refactor
        // that bumped the ceiling.
        let max = variant_confidence(PayloadType::Sql, 100, false, Strategy::OverlongUtf8);
        assert!(max <= 0.99);
        assert!(max >= 0.9);
    }

    #[test]
    fn variant_confidence_encoding_only_drops_grammar_bonus() {
        let with_grammar = variant_confidence(PayloadType::Sql, 3, false, Strategy::Base64Encode);
        let encoding_only = variant_confidence(PayloadType::Sql, 3, true, Strategy::Base64Encode);
        assert!(
            with_grammar > encoding_only,
            "grammar bonus must add: {with_grammar} > {encoding_only}"
        );
    }

    #[test]
    fn variant_confidence_unknown_payload_type_gets_lower_base() {
        let unknown = variant_confidence(PayloadType::Unknown, 0, false, Strategy::Base64Encode);
        let sql = variant_confidence(PayloadType::Sql, 0, false, Strategy::Base64Encode);
        assert!(sql > unknown, "Sql base > Unknown base: {sql} vs {unknown}");
    }

    #[test]
    fn variant_confidence_grammar_bonus_caps_at_grammar_bonus_cap() {
        // Per GRAMMAR_BONUS_PER_RULE / GRAMMAR_BONUS_CAP: at 100 rules
        // (100 * 0.04 = 4.0) the cap (0.12) kicks in, same as at 3
        // rules (3 * 0.04 = 0.12, exactly at cap). Both must be equal
        // up to floating-point precision (§6: magic literals replaced by
        // the named consts so drift is caught here).
        let a = variant_confidence(PayloadType::Sql, 100, false, Strategy::CaseAlternation);
        let b = variant_confidence(PayloadType::Sql, 3, false, Strategy::CaseAlternation);
        assert!((a - b).abs() < 1e-9, "grammar cap must hold: {a} vs {b}");
        // Pin the cap value itself so a GRAMMAR_BONUS_CAP change shows here.
        let max_bonus = variant_confidence(PayloadType::Sql, 100, false, Strategy::CaseAlternation)
            - variant_confidence(PayloadType::Sql, 0, false, Strategy::CaseAlternation);
        assert!(
            (max_bonus - GRAMMAR_BONUS_CAP).abs() < 1e-9,
            "grammar bonus cap must equal GRAMMAR_BONUS_CAP={GRAMMAR_BONUS_CAP}: measured {max_bonus}"
        );
    }

    #[test]
    fn strategies_for_level_each_returns_non_empty() {
        for level in [Level::Light, Level::Medium, Level::Heavy] {
            assert!(
                !strategies_for_level(level).is_empty(),
                "{level:?} must yield ≥1 strategy"
            );
        }
    }

    #[test]
    fn strategies_for_level_is_monotone_in_aggressiveness() {
        // light ⊆ medium ⊆ heavy in terms of set size.
        let l = strategies_for_level(Level::Light).len();
        let m = strategies_for_level(Level::Medium).len();
        let h = strategies_for_level(Level::Heavy).len();
        assert!(l <= m, "light <= medium: {l} <= {m}");
        assert!(m <= h, "medium <= heavy: {m} <= {h}");
    }

    #[test]
    fn max_mutations_for_level_is_monotone() {
        let l = max_mutations_for_level(Level::Light);
        let m = max_mutations_for_level(Level::Medium);
        let h = max_mutations_for_level(Level::Heavy);
        assert!(l < m, "light < medium: {l} < {m}");
        assert!(m < h, "medium < heavy: {m} < {h}");
    }

    #[test]
    fn probe_target_label_covers_every_variant() {
        // If a new ProbeTarget is added without a probe_target_label
        // arm, this fails to compile (exhaustive match in the impl).
        // Run a representative case from every family to ensure no
        // arm got silently changed.
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlOperator("AND".into())),
            "sql_operator:AND"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlComment("--".into())),
            "sql_comment:--"
        );
        assert_eq!(probe_target_label(&ProbeTarget::SqlQuote), "sql_quote");
        assert_eq!(
            probe_target_label(&ProbeTarget::SqlTautology("1=1".into())),
            "sql_tautology:1=1"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::XssEvent("onerror".into())),
            "xss_event:onerror"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::XssExecFunction("eval".into())),
            "xss_exec_function:eval"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdSeparator(";".into())),
            "cmd_separator:;"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdCommand("whoami".into())),
            "cmd_command:whoami"
        );
        assert_eq!(
            probe_target_label(&ProbeTarget::CmdPath("/etc/passwd".into())),
            "cmd_path:/etc/passwd"
        );
    }

    #[test]
    fn confidence_badge_thresholds_are_pinned() {
        // §6 NO HARDCODING: HIGH_CONFIDENCE_THRESHOLD / MED_CONFIDENCE_THRESHOLD
        // drive the badge colour. Pin them so a refactor that slides the
        // values doesn't silently change the UX for operators who read the
        // badge to decide whether to trust a bypass.
        assert!(
            (HIGH_CONFIDENCE_THRESHOLD - 0.9).abs() < 1e-10,
            "HIGH_CONFIDENCE_THRESHOLD must remain 0.9: got {HIGH_CONFIDENCE_THRESHOLD}"
        );
        assert!(
            (MED_CONFIDENCE_THRESHOLD - 0.75).abs() < 1e-10,
            "MED_CONFIDENCE_THRESHOLD must remain 0.75: got {MED_CONFIDENCE_THRESHOLD}"
        );
        // Structural: a score at or above HIGH → green path; between MED and HIGH → yellow;
        // below MED → red. The thresholds must maintain MED < HIGH.
        assert!(
            MED_CONFIDENCE_THRESHOLD < HIGH_CONFIDENCE_THRESHOLD,
            "MED threshold must be below HIGH: {MED_CONFIDENCE_THRESHOLD} < {HIGH_CONFIDENCE_THRESHOLD}"
        );
    }

    #[test]
    fn grammar_bonus_constants_are_pinned() {
        // §6 pin: GRAMMAR_BONUS_PER_RULE and GRAMMAR_BONUS_CAP were previously
        // magic float literals. Pin their values so a refactor that changes
        // scoring must explicitly update the constants AND this test.
        assert!(
            (GRAMMAR_BONUS_PER_RULE - 0.04).abs() < 1e-10,
            "GRAMMAR_BONUS_PER_RULE must be 0.04: got {GRAMMAR_BONUS_PER_RULE}"
        );
        assert!(
            (GRAMMAR_BONUS_CAP - 0.12).abs() < 1e-10,
            "GRAMMAR_BONUS_CAP must be 0.12: got {GRAMMAR_BONUS_CAP}"
        );
        // Structural: cap must be reachable (i.e. ceiling > one step).
        assert!(
            GRAMMAR_BONUS_CAP > GRAMMAR_BONUS_PER_RULE,
            "cap must be above one step: {GRAMMAR_BONUS_CAP} > {GRAMMAR_BONUS_PER_RULE}"
        );
    }
}
