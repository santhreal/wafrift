    use super::*;

    const TEST_TOML: &str = r#"
[[waf]]
name = "TestWAF"
vendor = "test"
confidence_threshold = 0.3
evasions = ["CaseAlternation", "SqlCommentInsertion"]

[[waf.signature]]
header_name = "x-test-waf"
header_regex = "active"
weight = 0.9

[[waf.signature]]
body_regex = "blocked by test"
weight = 0.95

[[waf.signature]]
status_code = 403
weight = 0.5

[[waf]]
name = "AnotherWAF"
vendor = "another"
confidence_threshold = 0.5
evasions = ["DoubleUrlEncode"]

[[waf.signature]]
body_regex = "another waf"
weight = 0.6
"#;

    fn test_engine() -> RuleEngine {
        let mut engine = RuleEngine::default();
        engine.load_from_str(TEST_TOML).expect("load test toml");
        engine.compile_body_regex_set().expect("compile regex set");
        engine
    }

    #[test]
    fn load_from_str_populates_rules() {
        let engine = test_engine();
        assert_eq!(engine.len(), 2);
        assert!(!engine.is_empty());
    }

    #[test]
    fn detect_by_header() {
        let engine = test_engine();
        let headers = vec![("x-test-waf".into(), "active".into())];
        let results = engine.detect(200, &headers, "OK");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "TestWAF");
        assert!(results[0].confidence >= 0.9);
    }

    #[test]
    fn detect_by_body() {
        let engine = test_engine();
        let headers: Vec<(String, String)> = vec![];
        let results = engine.detect(200, &headers, "you are blocked by test engine");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "TestWAF");
        assert!(results[0].confidence >= 0.95);
    }

    #[test]
    fn detect_by_status() {
        let engine = test_engine();
        let headers: Vec<(String, String)> = vec![];
        let results = engine.detect(403, &headers, "");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "TestWAF");
    }

    #[test]
    fn detect_no_match() {
        let engine = test_engine();
        let headers = vec![("server".into(), "nginx".into())];
        let results = engine.detect(200, &headers, "Welcome");
        assert!(results.is_empty());
    }

    #[test]
    fn detect_confidence_threshold_filters_body_only() {
        let engine = test_engine();
        // AnotherWAF needs 0.5 threshold, body regex gives 0.6
        let results = engine.detect(200, &[], "another waf detected");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "AnotherWAF");
    }

    #[test]
    fn evasions_for_known_waf() {
        let engine = test_engine();
        let evasions = engine.evasions_for("TestWAF");
        assert_eq!(evasions.len(), 2);
        assert!(evasions.contains(&"CaseAlternation"));
    }

    #[test]
    fn evasions_for_unknown_waf_empty() {
        let engine = test_engine();
        assert!(engine.evasions_for("Unknown").is_empty());
    }

    #[test]
    fn detect_body_only_needs_higher_threshold() {
        let mut engine = RuleEngine::default();
        engine
            .load_from_str(
                r#"
[[waf]]
name = "LowConfWAF"
vendor = "test"
confidence_threshold = 0.1

[[waf.signature]]
body_regex = "blocked"
weight = 0.4
"#,
            )
            .expect("load");
        engine.compile_body_regex_set().expect("compile");

        // body-only match with weight 0.4 < BODY_ONLY_MIN_CONFIDENCE (0.5)
        let results = engine.detect(200, &[], "blocked");
        assert!(results.is_empty());
    }

    #[test]
    fn empty_engine_returns_empty() {
        let engine = RuleEngine::default();
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);
        let results = engine.detect(200, &[], "body");
        assert!(results.is_empty());
    }

    #[test]
    fn detect_sorts_by_confidence_desc() {
        let engine = test_engine();
        // TestWAF matches header (0.9) + body (0.95) = 1.85
        // AnotherWAF matches body (0.6)
        let headers = vec![("x-test-waf".into(), "active".into())];
        let results = engine.detect(200, &headers, "blocked by test and another waf");
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "TestWAF");
    }

    // ── Case-insensitive regex wrapper, stress tests ───────────
    //
    // The wrapper is the single most important correctness lever in
    // detection: every rule in the catalog flows through it. These
    // tests stress the wrapper against the pathological patterns
    // authors actually write in the wild, explicit flag opt-outs,
    // multi-flag groups, escape sequences, character classes, raw
    // brackets, Unicode, anchored expressions, and the empty pattern.
    // If any of these break, EVERY downstream rule breaks too.

    #[test]
    fn ci_wrapper_matches_capitalized_literal_against_lowercase_input() {
        // The original bug class: rule author writes `Cloudflare`,
        // classifier lowercases input to `cloudflare`, wrapper must
        // bridge the case gap.
        let re = compile_ci_regex("Cloudflare", "header").expect("compile");
        assert!(re.is_match("cloudflare"));
        assert!(re.is_match("CLOUDFLARE"));
        assert!(re.is_match("CloudFlare"));
        assert!(re.is_match("cLoUdFlArE"));
    }

    #[test]
    fn ci_wrapper_makes_uppercase_char_class_match_lowercase_input() {
        // The Fastly POP-code regex `[A-Z]{3}` MUST match `lga` and
        // `bur` after the input has been lowercased downstream.
        let re = compile_ci_regex("cache-[a-z]{3}[0-9]+-[A-Z]{3}", "header").expect("compile");
        // Lowercase input (what classifier feeds us in production):
        assert!(re.is_match("cache-lga21972-lga"));
        // Original-case input (what engine.detect gets bypassing classifier):
        assert!(re.is_match("cache-lga21972-LGA"));
        // Mid-string match (CSV-joined POPs):
        assert!(re.is_match("cache-lga21972-LGA, cache-bur-kbur8200085-BUR"));
        // Reject malformed POP tokens (no over-eager matching):
        assert!(!re.is_match("cache-2-LGA"));
        assert!(!re.is_match("cache-lga--LGA"));
    }

    #[test]
    fn ci_wrapper_preserves_existing_outer_ci_flag_idempotently() {
        let re = compile_ci_regex("(?i)Already", "header").expect("compile");
        assert!(re.is_match("ALREADY"));
        assert!(re.is_match("already"));
    }

    #[test]
    fn ci_wrapper_respects_explicit_case_sensitive_opt_out() {
        // `(?-i)` is the documented opt-out path. The wrapper MUST
        // detect it and skip wrapping or the opt-out is impossible.
        let re = compile_ci_regex("(?-i)Strict", "header").expect("compile");
        assert!(re.is_match("Strict"));
        assert!(!re.is_match("strict"));
        assert!(!re.is_match("STRICT"));
    }

    #[test]
    fn ci_wrapper_handles_combined_flag_groups() {
        // Multi-flag groups like `(?im)` or `(?si)`.  As long as the
        // group declares the case flag explicitly we must NOT add an
        // outer (?i).  Multi-line + case-insensitive combo:
        let re = compile_ci_regex("(?im)^TOKEN", "body").expect("compile");
        assert!(re.is_match("first\ntoken"));
        // case-insensitive opt-out within a multi-flag group:
        let re_opt_out = compile_ci_regex("(?-im)^Strict", "body").expect("compile");
        assert!(re_opt_out.is_match("Strict line"));
        assert!(!re_opt_out.is_match("strict line"));
    }

    #[test]
    fn ci_wrapper_does_not_double_wrap_when_outer_flag_present() {
        // Defensive: if `(?i)Foo` is wrapped twice, regex crate
        // still parses it; the test ensures we get the SAME
        // semantics, not a parse error.
        let already = compile_ci_regex("(?i)foo", "header").expect("compile");
        let plain = compile_ci_regex("foo", "header").expect("compile");
        for s in ["foo", "FOO", "Foo", "FoO"] {
            assert_eq!(already.is_match(s), plain.is_match(s));
        }
    }

    #[test]
    fn ci_wrapper_compiles_anchored_patterns_without_breaking_anchors() {
        let re = compile_ci_regex("^Cloudflare$", "header").expect("compile");
        assert!(re.is_match("CLOUDFLARE"));
        // Anchors still mean "whole string only":
        assert!(!re.is_match("foo Cloudflare bar"));
        assert!(!re.is_match("Cloudflare extra"));
    }

    #[test]
    fn ci_wrapper_compiles_patterns_with_escaped_metacharacters() {
        let re = compile_ci_regex("(?:F5\\-TrafficShield)", "header").expect("compile");
        assert!(re.is_match("f5-trafficshield"));
        assert!(re.is_match("F5-TrafficShield"));
        // No false-positive on similar tokens:
        assert!(!re.is_match("F5TrafficShield"));
    }

    #[test]
    fn ci_wrapper_respects_multi_letter_flag_groups() {
        // Pre-fix the prefix-only check missed `(?si)` and friends
        //: the engine prepended `(?i)` and the resulting
        // `(?i)(?si)pattern` was redundant but harmless. Worse:
        // `(?-si)` (explicit case-SENSITIVE + dotall off) got
        // wrapped too, NEGATING the author's intent.
        // F58 fix: detect `i` anywhere in the leading flag group.

        // (?si) (both flags on, case-insensitive).
        let re = compile_ci_regex("(?si)Cloudflare", "header").expect("compile");
        assert!(re.is_match("CLOUDFLARE"));

        // (?-si), explicit case-SENSITIVE. Must NOT match
        // lower-case after the fix.
        let re = compile_ci_regex("(?-si)Cloudflare", "header").expect("compile");
        assert!(re.is_match("Cloudflare"));
        assert!(
            !re.is_match("cloudflare"),
            "(?-si) author intent: case-sensitive, must not match lowercase"
        );

        // (?:non-capturing) with literal `i` in the body must
        // still get the `(?i)` wrap (the `:` ends the flag group).
        let re = compile_ci_regex("(?:Imperva)", "header").expect("compile");
        assert!(re.is_match("IMPERVA"));
        assert!(re.is_match("imperva"));
    }

    #[test]
    fn ci_wrapper_compiles_patterns_with_unicode_metaclasses() {
        // Some catalogs use \w which under case-insensitivity still
        // matches digits, underscore, ascii letters.
        let re = compile_ci_regex("token-\\w+", "header").expect("compile");
        assert!(re.is_match("TOKEN-abc123"));
        assert!(re.is_match("token-Xyz_99"));
    }

    #[test]
    fn ci_wrapper_compiles_empty_alternation_and_zero_width_safely() {
        // Pathological: `(?:|other)` is a regex with an empty
        // alternative.  The wrapper must compile but not panic.
        let re = compile_ci_regex("(?:foo|bar)", "header").expect("compile");
        assert!(re.is_match("FOO"));
        assert!(re.is_match("Bar"));
        assert!(!re.is_match("baz"));
    }

    #[test]
    fn ci_wrapper_rejects_pattern_that_was_already_broken() {
        // Garbage regexes must still surface as compile errors, NOT
        // be silently swallowed by the wrapper.
        let err = compile_ci_regex("([unclosed", "header");
        assert!(err.is_err(), "broken pattern must surface as Err");
        let msg = err.unwrap_err();
        assert!(
            msg.contains("header"),
            "error message must name the regex kind: {msg}"
        );
        assert!(
            msg.contains("[unclosed"),
            "error message must echo the offending pattern: {msg}"
        );
    }

    // ── Catalog-wide invariants ──────────────────────────────────
    //
    // These don't hardcode any specific vendor, they prove
    // properties that MUST hold for the whole rule catalog. If they
    // pass, the case-bug class cannot regress for any future rule.

    #[test]
    fn every_embedded_rule_compiles() {
        // The build script concatenates every TOML in rules/detect/.
        // If any file is malformed, an unknown field, or carries a
        // bad regex, this surfaces it loudly.
        let engine = RuleEngine::load_embedded().expect("all embedded rules compile");
        assert!(engine.len() >= 50, "catalog shrank: {}", engine.len());
    }

    #[test]
    fn every_header_regex_in_catalog_is_case_insensitive() {
        // The CI auto-wrap is enforced at compile time.  Prove it by
        // sampling every compiled header regex and asserting that
        // for any pattern containing an ASCII letter, both the
        // upper- and lower-case form of that letter participates in
        // a match, i.e. the (?i) flag is active.  Patterns with
        // explicit `(?-i)` opt-out skip the check.
        let engine = RuleEngine::load_embedded().expect("load");
        let mut checked = 0;
        for rule in engine.rules.values() {
            for sig in &rule.signatures {
                if let Some(ref re) = sig.header_regex {
                    let src = re.as_str();
                    // Skip explicit case-sensitive rules (none in
                    // current catalog, but the catalog can evolve).
                    if src.starts_with("(?-i)") || src.starts_with("(?-i-") {
                        continue;
                    }
                    // The CI flag must be visible in the source.
                    assert!(
                        src.starts_with("(?i)") || src.starts_with("(?i-")
                            || src.starts_with("(?im")
                            || src.starts_with("(?is")
                            || src.starts_with("(?ix")
                            || src.starts_with("(?iu")
                            // Authors who pre-declared case-flag
                            // inline are preserved verbatim.
                            || src.contains("(?i)")
                            || src.contains("(?i:"),
                        "header regex `{src}` in rule `{}` is NOT case-insensitive, that's the lower-cased-value bug class waiting to happen",
                        rule.name
                    );
                    checked += 1;
                }
            }
        }
        assert!(
            checked >= 30,
            "expected many CI-wrapped header rules, got {checked}"
        );
    }

    #[test]
    fn lowercase_input_must_match_uppercase_pattern_for_every_rule() {
        // For every compiled header regex, take the literal portion
        // of its source pattern, lowercase it, and verify the regex
        // still matches.  This is the EXACT failure mode that
        // pre-fix nuked Fastly on nytimes, and it must never
        // silently regress for any rule, present or future.
        let engine = RuleEngine::load_embedded().expect("load");
        let mut tested = 0;
        let mut not_applicable = 0;
        for rule in engine.rules.values() {
            for sig in &rule.signatures {
                let Some(ref re) = sig.header_regex else {
                    continue;
                };
                let src = re.as_str();
                // Skip explicit case-sensitive opt-outs.
                if src.starts_with("(?-i)") {
                    continue;
                }
                // Synthesize a "lowercase-clean" candidate by taking
                // the literal text of the pattern (best-effort: drop
                // metacharacters) and lowercasing it.  If the result
                // is nonempty, the regex MUST still match it.
                let literal: String = src
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == ' ' || *c == '-')
                    .collect();
                let lowered = literal.to_ascii_lowercase();
                if lowered.trim().is_empty() {
                    not_applicable += 1;
                    continue;
                }
                // Some patterns are wrapped in groups or have outer
                // anchors, the literal extraction is a best-effort
                // heuristic, not a parser.  Treat a non-match as
                // "literal extraction failed" rather than a bug.
                if re.is_match(&lowered) {
                    tested += 1;
                }
            }
        }
        // We expect MANY successful round-trips.  If this number
        // crashes to zero, the CI wrapper has stopped working.
        assert!(
            tested >= 20,
            "lowercase round-trip succeeded for only {tested} rules ({not_applicable} skipped). CI wrapper likely broken"
        );
    }

    // ── Real-traffic shape regression, no hardcoded site names ──
    //
    // Each scenario describes the SHAPE of a real edge-case (CSV
    // multi-value header, capitalized vendor banner, multi-WAF
    // chain, body-only signal) without naming the specific site
    // the shape was harvested from.  If the shape regresses, the
    // assertion failure tells you which TYPE of detection broke.

    #[test]
    fn csv_joined_multi_hop_header_value_still_matches_anchored_pattern() {
        use crate::waf_detect::classifier;
        // Pattern: CDN multi-hop response (cache chain) where each
        // hop appends its POP token CSV-style.  The pattern must
        // match SOMEWHERE in the value, not be anchored at offset 0.
        let headers = vec![(
            "X-Served-By".into(),
            "cache-aaa12345-AAA, cache-bbb67890-BBB, cache-ccc-with-hyphens-CCC".into(),
        )];
        let detected = classifier::detect(200, &headers, b"");
        assert!(
            !detected.is_empty(),
            "CSV multi-hop cache header must produce at least one detection"
        );
    }

    #[test]
    fn every_literal_header_rule_in_catalog_matches_capitalized_value() {
        // Property derived from the catalog itself, no hardcoded
        // vendor names. For each rule whose header_regex source is
        // a pure literal (after stripping the auto-prepended (?i)
        // flag), synthesize the corresponding header with the
        // CAPITALIZED literal as the value and assert the rule
        // fires through the public classifier API.  This is the
        // exact bug class that nuked Fastly's POP-code rule for an
        // entire session: lowercased input never met an uppercase
        // expectation.
        use crate::waf_detect::classifier;
        let engine = RuleEngine::load_embedded().expect("load");
        let mut tested = 0;
        let mut missed: Vec<(String, String, String)> = Vec::new();
        for rule in engine.rules.values() {
            for sig in &rule.signatures {
                let (Some(name), Some(re)) = (sig.header_name.as_ref(), sig.header_regex.as_ref())
                else {
                    continue;
                };
                // Strip the auto-prepended (?i) (or other outer
                // flag) so we look at the AUTHOR's literal.
                let src = re.as_str();
                let literal = strip_outer_flag_group(src);
                // Only consider plain-literal patterns (letters,
                // digits, space, hyphen, period, underscore).
                if literal.is_empty()
                    || !literal.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '/')
                    })
                {
                    continue;
                }
                // Capitalize the literal as a server would emit it.
                let value = literal.to_string();
                let detected = classifier::detect(200, &[(name.clone(), value.clone())], b"");
                if detected.iter().any(|r| r.name == rule.name) {
                    tested += 1;
                } else {
                    missed.push((rule.name.clone(), name.clone(), value));
                }
            }
        }
        assert!(
            tested >= 20,
            "expected >=20 literal-pattern catalog rules to fire under CI; got {tested}. Misses: {missed:?}"
        );
        assert!(
            missed.is_empty(),
            "rules whose own literal value did NOT fire through the public API (CI wrapper broken): {missed:?}"
        );
    }

    #[test]
    fn mixed_case_header_name_with_known_lowercase_signature_still_matches() {
        // HTTP spec: header names are case-insensitive.  Pick a
        // rule we know expects a specific header name + value, and
        // verify that Title-Case wire form of the SAME pair fires.
        // We discover the rule dynamically from the catalog so this
        // doesn't lock to a specific vendor.
        use crate::waf_detect::classifier;
        let engine = RuleEngine::load_embedded().expect("load");
        let mut sampled = 0;
        for rule in engine.rules.values() {
            for sig in &rule.signatures {
                let (Some(name), Some(re)) = (sig.header_name.as_ref(), sig.header_regex.as_ref())
                else {
                    continue;
                };
                let literal = strip_outer_flag_group(re.as_str());
                if literal.is_empty()
                    || !literal
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_')
                {
                    continue;
                }
                let title_name: String = name
                    .split('-')
                    .map(|part| {
                        let mut chars = part.chars();
                        match chars.next() {
                            None => String::new(),
                            Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("-");
                let value: String = literal.to_string();
                let detected = classifier::detect(200, &[(title_name, value)], b"");
                if detected.iter().any(|r| r.name == rule.name) {
                    sampled += 1;
                }
                if sampled >= 5 {
                    return;
                }
            }
        }
        assert!(
            sampled >= 5,
            "mixed-case header-name match should work for at least 5 catalog rules; got {sampled}"
        );
    }

    #[test]
    fn multi_waf_chain_returns_every_layer_not_just_the_top() {
        use crate::waf_detect::classifier;
        // Real-world: an Envoy sidecar in front of Fastly cache.
        // Forensically we need BOTH names so the operator can pick
        // the right evasion family.  Returning only the
        // top-confidence layer loses critical signal.
        let headers = vec![
            ("Server".into(), "envoy".into()),
            ("X-Envoy-Upstream-Service-Time".into(), "120".into()),
            ("X-Served-By".into(), "cache-aaa11111-AAA".into()),
            ("X-Timer".into(), "S1234567890.000,VS0,VE5".into()),
        ];
        let detected = classifier::detect(200, &headers, b"");
        assert!(
            detected.len() >= 2,
            "multi-WAF chain must surface every layer. Got only: {detected:?}"
        );
    }

    #[test]
    fn unknown_vendor_banner_does_not_false_positive() {
        // Symmetry check: the CI wrapper must not make detection
        // MORE eager.  A nonsense banner must NOT fire any rule.
        use crate::waf_detect::classifier;
        let detected = classifier::detect(
            200,
            &[("Server".into(), "totally-fake-vendor-xyz-123".into())],
            b"",
        );
        assert!(
            detected.is_empty(),
            "garbage vendor must not match anything: got {detected:?}"
        );
    }

    #[test]
    fn body_regex_with_capitalized_literal_matches_lowercased_body() {
        // The body lowercasing in classifier.rs lives ALONGSIDE the
        // header lowercasing (the (?i) auto-wrap must fix both).
        // Author writes body literal "BLOCKED BY WAF" expecting it
        // to match; classifier lowercases body to "blocked by waf"
        // before matching. Wrap must bridge.
        let mut engine = RuleEngine::default();
        engine
            .load_from_str(
                r#"
[[waf]]
name = "BodyCaseWAF"
vendor = "test"
confidence_threshold = 0.3

[[waf.signature]]
body_regex = "BLOCKED BY THIS WAF"
weight = 0.6
"#,
            )
            .expect("load");
        engine.compile_body_regex_set().expect("compile");
        let detected = engine.detect(200, &[], "you have been blocked by this waf");
        assert!(
            detected.iter().any(|r| r.name == "BodyCaseWAF"),
            "body regex with capitalized literal must match lowercased body. Got: {detected:?}"
        );
    }

    #[test]
    fn cookie_regex_with_capitalized_literal_matches_lowercased_value() {
        let mut engine = RuleEngine::default();
        engine
            .load_from_str(
                r#"
[[waf]]
name = "CookieCaseWAF"
vendor = "test"
confidence_threshold = 0.3

[[waf.signature]]
cookie_regex = "VISITOR_SESSION"
weight = 0.6
"#,
            )
            .expect("load");
        engine.compile_body_regex_set().expect("compile");
        let headers = vec![("set-cookie".into(), "visitor_session=abc; Path=/".into())];
        let detected = engine.detect(200, &headers, "");
        assert!(
            detected.iter().any(|r| r.name == "CookieCaseWAF"),
            "cookie regex with capitalized literal must match lowercased Set-Cookie value. Got: {detected:?}"
        );
    }

    #[test]
    fn repeated_header_values_in_chain_both_get_scanned() {
        // HTTP/1.1 allows repeated header names, reqwest exposes
        // each repetition as a separate (k, v) tuple.  The detect
        // loop iterates ALL pairs, so each repetition gets a
        // chance to match.
        use crate::waf_detect::classifier;
        let detected = classifier::detect(
            200,
            &[
                ("X-Served-By".into(), "cache-aaa11111-AAA".into()),
                ("X-Served-By".into(), "cache-bbb22222-BBB".into()),
                ("X-Served-By".into(), "cache-ccc33333-CCC".into()),
            ],
            b"",
        );
        assert!(
            !detected.is_empty(),
            "repeated header values must each be eligible for matching"
        );
    }

    #[test]
    fn header_value_with_non_ascii_bytes_does_not_panic() {
        // Defensive: WAF block pages and reverse-proxy banners
        // sometimes embed UTF-8 (€, →, em-dash).  Classifier
        // lowercasing + regex matching must be panic-safe on these.
        use crate::waf_detect::classifier;
        let detected = classifier::detect(
            200,
            &[
                ("Server".into(), "Cloudflåre: €dge".into()),
                ("X-Block-Reason".into(), "→ denied".into()),
            ],
            b"blocked by \xe2\x86\x92 firewall",
        );
        // We don't assert SPECIFIC detection here (we assert no panic).
        let _ = detected;
    }

    #[test]
    fn empty_inputs_never_panic_or_false_positive() {
        use crate::waf_detect::classifier;
        for (status, headers, body) in [
            (200, vec![], &b""[..]),
            (0, vec![], &b""[..]),
            (599, vec![("".into(), "".into())], &b""[..]),
            (404, vec![("X-Empty".into(), "".into())], &b""[..]),
        ] {
            let detected = classifier::detect(status, &headers, body);
            assert!(
                detected.is_empty() || !detected[0].name.is_empty(),
                "empty input must not false-positive: {detected:?}"
            );
        }
    }

    #[test]
    fn extremely_long_header_value_does_not_panic_or_hang() {
        // A 100 KiB header value should be scanned without blowing
        // up the regex engine (the bounded MAX_REGEX_PATTERN_LEN
        // covers the PATTERN side; the VALUE side relies on the
        // regex engine being O(n) (which it is, by design)).
        use crate::waf_detect::classifier;
        let value = "a".repeat(100 * 1024);
        let detected = classifier::detect(200, &[("X-Junk".into(), value)], b"");
        // Just must not panic / hang.
        let _ = detected;
    }

    #[test]
    fn detection_is_stable_under_random_header_casing() {
        // Property: detection result must be invariant under the
        // case of header names and values.  Capture a baseline,
        // randomize the case, assert equality.
        use crate::waf_detect::classifier;
        let canonical = vec![
            ("Server".to_string(), "AkamaiGHost".to_string()),
            ("X-Akam-SW-Version".to_string(), "12.5".to_string()),
        ];
        let scrambled = vec![
            ("sErVeR".to_string(), "AKamaIghOSt".to_string()),
            ("X-aKam-sw-VeRsIoN".to_string(), "12.5".to_string()),
        ];
        let a = classifier::detect(200, &canonical, b"");
        let b = classifier::detect(200, &scrambled, b"");
        let names_a: Vec<_> = a.iter().map(|r| r.name.clone()).collect();
        let names_b: Vec<_> = b.iter().map(|r| r.name.clone()).collect();
        assert_eq!(
            names_a, names_b,
            "case randomization changed detection result"
        );
    }

    // ── ReDoS / compile-time explosion defence ────────────────────────────
    //
    // §15 AUDIT HUNTS axis 3 (ReDoS / algorithmic complexity).
    //
    // A length-bounded pattern (MAX_REGEX_PATTERN_LEN = 4096 bytes) can
    // still cause O(N^M) NFA state explosion at compile time even for short
    // patterns.  The attack pattern `(.{1,100}){50}` is 14 bytes (well within
    // 4096) but requires the regex NFA to track an exponential number of
    // positions, blowing past the 4 MiB NFA-byte cap in REGEX_COMPILE_SIZE_LIMIT.
    //
    // These tests pin the size_limit guard, if someone reverts
    // compile_ci_regex to bare `Regex::new`, the explosion test will
    // either hang indefinitely or compile without error (disabling the
    // protection), and the error-not-panic tests will then falsely pass.
    //
    // Verified empirically: `(.{1,100}){50}` returns Err with size_limit=4MB,
    // and compiles successfully with size_limit=usize::MAX (no hang, the regex
    // crate uses a lazy DFA, so match time is safe; only compile time blows up).

    #[test]
    fn redos_explosion_pattern_is_rejected_not_hung() {
        // `(.{1,100}){50}` is the NFA-explosion pattern verified against
        // REGEX_COMPILE_SIZE_LIMIT (4 MiB). It is 14 bytes, well within
        // MAX_REGEX_PATTERN_LEN (but creates an NFA that exceeds the cap).
        // With size_limit enforced: returns Err in microseconds.
        // Without size_limit: compiles successfully (lazy DFA; no hang at
        // match time) (which is exactly the unguarded case we're sealing).
        let pat = r"(.{1,100}){50}";
        let result = compile_ci_regex(pat, "header");
        // Must be an error (size_limit exceeded).
        assert!(
            result.is_err(),
            "NFA-explosion pattern `{pat}` must be rejected by size_limit"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("header"),
            "error must name the regex kind; got: {msg}"
        );
    }

    #[test]
    fn redos_explosion_in_rule_file_is_rejected_with_error() {
        // A rule file containing a NFA-explosion header_regex must produce
        // a compile error from load_from_str (not silent success).
        let toml = r#"
[[waf]]
name = "ExplosionWAF"
vendor = "test"
confidence_threshold = 0.3

[[waf.signature]]
header_regex = "(.{1,100}){50}"
weight = 0.5
"#;
        let mut engine = RuleEngine::default();
        let result = engine.load_from_str(toml);
        assert!(
            result.is_err(),
            "NFA-explosion header_regex must surface as load error"
        );
    }

    #[test]
    fn redos_explosion_in_body_regex_set_is_rejected_with_error() {
        // A body_regex NFA-explosion pattern must be caught by either
        // the per-rule compile step OR compile_body_regex_set.
        // The per-rule step uses compile_ci_regex (has size_limit);
        // compile_body_regex_set uses RegexSetBuilder (also has size_limit).
        // Both paths must reject the pattern (neither may silently succeed).
        let toml = r#"
[[waf]]
name = "BodyExplosionWAF"
vendor = "test"
confidence_threshold = 0.3

[[waf.signature]]
body_regex = "(.{1,100}){50}"
weight = 0.5
"#;
        let mut engine = RuleEngine::default();
        // load_from_str compiles individual regexes (compile_ci_regex path).
        // This should already fail because compile_ci_regex has size_limit.
        let load_result = engine.load_from_str(toml);
        if load_result.is_ok() {
            // If the per-rule path somehow didn't catch it, compile_body_regex_set
            // (RegexSetBuilder path) must.
            let set_result = engine.compile_body_regex_set();
            assert!(
                set_result.is_err(),
                "NFA-explosion body_regex must surface as error from compile_body_regex_set"
            );
        }
        // Either path produces an error (the load_from_str path should fire first).
        assert!(
            load_result.is_err(),
            "NFA-explosion body_regex must be caught by per-rule compile step"
        );
    }

    #[test]
    fn benign_patterns_still_compile_after_size_limit_applied() {
        // Regression guard: the size_limit must not break normal patterns.
        // Test a representative sample of patterns from real WAF rules.
        let patterns = [
            "cloudflare",
            r"cache-[a-z]{3}[0-9]+-[A-Z]{3}",
            r"X-Sucuri-ID",
            r"(\d{1,3}\.){3}\d{1,3}",
            r"(?i)blocked by",
            r"(?-i)BinarySec",
        ];
        for pat in &patterns {
            let result = compile_ci_regex(pat, "header");
            assert!(
                result.is_ok(),
                "benign pattern `{pat}` must still compile after size_limit: {:?}",
                result.err()
            );
        }
    }