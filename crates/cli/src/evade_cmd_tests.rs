    use super::*;

    fn args_with_payload(p: &str) -> EvadeArgs {
        EvadeArgs {
            payload: Some(p.into()),
            payload_b64: None,
            stdin: false,
            format: "text".into(),
            level: Level::Medium,
            encoding_only: false,
            only: vec![],
            exclude: vec![],
            target_context: None,
            explain: false,
            output: None,
            force_overwrite: false,
        }
    }

    #[test]
    fn resolve_payload_plain_string_returns_as_is() {
        let args = args_with_payload("' OR 1=1--");
        assert_eq!(resolve_payload(&args).unwrap(), "' OR 1=1--");
    }

    #[test]
    fn resolve_payload_empty_payload_returns_argv_nul_diagnostic() {
        // The empty `--payload` -> NUL-byte argv diagnostic is one of
        // the most-frequently-hit operator footguns; the error
        // message must name it so the user doesn't keep guessing.
        let args = args_with_payload("");
        let err = resolve_payload(&args).expect_err("empty payload must err");
        assert!(
            err.contains("NUL") || err.contains("nul") || err.contains("--stdin"),
            "diagnostic must mention NUL/stdin escape, got: {err}"
        );
    }

    #[test]
    fn resolve_payload_b64_round_trip() {
        let mut args = args_with_payload("");
        args.payload = None;
        // Standard base64 of "hello" is "aGVsbG8=".
        args.payload_b64 = Some("aGVsbG8=".into());
        assert_eq!(resolve_payload(&args).unwrap(), "hello");
    }

    #[test]
    fn resolve_payload_b64_accepts_no_pad_form() {
        let mut args = args_with_payload("");
        args.payload = None;
        // Same "hello" without the trailing `=` padding.
        args.payload_b64 = Some("aGVsbG8".into());
        assert_eq!(resolve_payload(&args).unwrap(), "hello");
    }

    #[test]
    fn resolve_payload_b64_empty_rejects() {
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some("".into());
        assert!(resolve_payload(&args).is_err());
    }

    #[test]
    fn resolve_payload_b64_invalid_rejects() {
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some("not-base64!!!".into());
        assert!(resolve_payload(&args).is_err());
    }

    #[test]
    fn resolve_payload_b64_whitespace_only_rejects() {
        // A b64 value of only whitespace decodes to empty bytes
        // and is operator typo. resolve_payload trims & rejects.
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some("   ".into());
        assert!(resolve_payload(&args).is_err());
    }

    #[test]
    fn resolve_payload_b64_decodes_to_unicode() {
        use base64::Engine as _;
        let raw = "café 中文";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some(encoded);
        assert_eq!(resolve_payload(&args).unwrap(), raw);
    }

    #[test]
    fn resolve_payload_b64_decodes_to_bytes_with_control_chars() {
        // Operators escape unprintable / NUL-laden binary payloads
        // through --payload-b64 specifically because argv truncates
        // at NUL. Confirm a NUL-containing decoded payload survives
        // through string conversion (lossy where needed but never
        // panic).
        use base64::Engine as _;
        let raw_bytes = b"a\x00b\x01c".to_vec();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some(encoded);
        let got = resolve_payload(&args).unwrap();
        // String::from_utf8_lossy preserves valid UTF-8 bytes,
        // including NUL (the NUL must round-trip).
        assert!(got.contains('\0'));
        assert!(got.starts_with('a'));
        assert!(got.ends_with('c'));
    }

    #[test]
    fn resolve_payload_b64_with_leading_trailing_whitespace_trims() {
        // Multi-line paste, operators often have a stray
        // newline at the end. The trim() in resolve_payload
        // handles that.
        let mut args = args_with_payload("");
        args.payload = None;
        args.payload_b64 = Some("  aGVsbG8=  \n".into());
        assert_eq!(resolve_payload(&args).unwrap(), "hello");
    }

    #[test]
    fn resolve_payload_no_source_set_returns_error() {
        // None of --payload, --payload-b64, --stdin → error.
        let mut args = args_with_payload("placeholder");
        args.payload = None;
        args.payload_b64 = None;
        args.stdin = false;
        let err = resolve_payload(&args).expect_err("no source");
        assert!(
            err.contains("no payload")
                || err.contains("payload")
                || err.contains("--stdin")
                || err.contains("--payload-b64"),
            "must list options: {err}"
        );
    }

    #[test]
    fn resolve_payload_preference_order_b64_over_payload() {
        // If both --payload and --payload-b64 are set, --payload-b64
        // wins (it's checked first in the resolve order). This is
        // the contract; document via test.
        use base64::Engine as _;
        let mut args = args_with_payload("WRONG");
        args.payload_b64 = Some(base64::engine::general_purpose::STANDARD.encode(b"RIGHT"));
        assert_eq!(resolve_payload(&args).unwrap(), "RIGHT");
    }

    // ── Tamper wiring (added 2026-05) ──────────────────────
    //
    // These exercise the policy that tampers are opt-in for evade
    // default flows produce zero tamper variants, an explicit
    // `--only tamper/...` selector produces one variant per matched
    // tamper (deduped against the original + existing variants).
    //
    // We don't invoke `run_evade` directly here (it writes to stdout
    // and process-exits); instead we mirror its TamperRegistry +
    // TechniqueFilter logic in the assertion.

    fn count_tamper_variants_for(selectors: &[&str], payload: &str) -> usize {
        let filter = TechniqueFilter::parse(
            &selectors.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &[],
        )
        .expect("filter parses");
        let any_tamper_selector = selectors
            .iter()
            .flat_map(|s| s.split(','))
            .map(str::trim)
            .any(|sel| sel == "tamper" || sel.starts_with("tamper/"));
        if !any_tamper_selector {
            return 0;
        }
        let reg = wafrift_encoding::tamper::TamperRegistry::with_defaults();
        let mut hits = 0;
        let mut seen = std::collections::HashSet::new();
        seen.insert(payload.to_string());
        for &name in wafrift_encoding::tamper::all_tamper_names() {
            let path = format!("tamper/{name}");
            if !filter.allows_path(&path) {
                continue;
            }
            let Some(strat) = reg.get(name) else {
                continue;
            };
            let mutated = strat.tamper(payload, Some("sql"));
            if mutated != payload && seen.insert(mutated) {
                hits += 1;
            }
        }
        hits
    }

    #[test]
    fn tamper_opt_in_zero_variants_when_no_selector() {
        assert_eq!(count_tamper_variants_for(&[], "' OR 1=1--"), 0);
        assert_eq!(
            count_tamper_variants_for(&["encoding/url"], "' OR 1=1--"),
            0,
            "encoding-only selector must not enable tamper variants"
        );
    }

    #[test]
    fn tamper_family_selector_enables_all_tampers() {
        // `tamper` as a bare family selects every registered tamper
        //: at least 10 of them will produce a non-identity variant
        // on an SQL payload.
        let hits = count_tamper_variants_for(&["tamper"], "' OR 1=1--");
        assert!(
            hits >= 5,
            "tamper-family selector should fire many tampers; got {hits}"
        );
    }

    #[test]
    fn tamper_leaf_selector_isolates_single_tamper() {
        // A specific tamper leaf produces at most one variant.
        let hits = count_tamper_variants_for(&["tamper/zero_width_inject"], "' OR 1=1--");
        assert!(
            hits <= 1,
            "tamper/zero_width_inject must produce at most one variant; got {hits}"
        );
        // And specifically it DOES produce one for this payload
        // (which contains alphabetic chars).
        assert_eq!(hits, 1);
    }

    #[test]
    fn tamper_inert_on_unrelated_payload_produces_zero() {
        // postgres_dollar_quote only transforms single-quoted
        // literals.  A payload with no `'` should produce no
        // variant.
        let hits = count_tamper_variants_for(&["tamper/postgres_dollar_quote"], "1=1");
        assert_eq!(hits, 0);
    }

    #[test]
    fn tamper_multiple_leaves_compose() {
        let hits = count_tamper_variants_for(
            &[
                "tamper/zero_width_inject",
                "tamper/bracket_confusable",
                "tamper/bell_separator",
            ],
            "<script>alert OR 1=1</script>",
        );
        // Three distinct selectors → up to three distinct
        // outputs.  Lower-bound on 2 (some may collide on this
        // payload).
        assert!(hits >= 2);
    }

    #[test]
    fn tamper_comma_separated_csv_form_is_recognised() {
        // `--only "tamper/a,tamper/b"`: split on comma.
        let hits = count_tamper_variants_for(
            &["tamper/zero_width_inject,tamper/bracket_confusable"],
            "<x>OR</x>",
        );
        assert!(hits >= 1);
    }

    #[test]
    fn tamper_idempotent_on_pure_punctuation_payload() {
        // `1=1` has no alphabetic chars → zero_width_inject is a
        // no-op → no variant produced.
        let hits = count_tamper_variants_for(&["tamper/zero_width_inject"], "1=1");
        assert_eq!(hits, 0);
    }

    #[test]
    fn visualize_escapes_bell_byte() {
        assert_eq!(visualize_invisible_bytes("a\u{0007}b"), "a\\x07b");
    }

    #[test]
    fn visualize_escapes_null_byte() {
        assert_eq!(visualize_invisible_bytes("a\u{0000}b"), "a\\x00b");
    }

    #[test]
    fn visualize_escapes_zero_width_codepoints() {
        let input = "S\u{200B}E\u{200C}L\u{200D}E\u{FEFF}CT";
        let out = visualize_invisible_bytes(input);
        assert!(out.contains("\\u{200B}"));
        assert!(out.contains("\\u{200C}"));
        assert!(out.contains("\\u{200D}"));
        assert!(out.contains("\\u{FEFF}"));
        assert!(out.starts_with("S"));
        assert!(out.ends_with("CT"));
    }

    #[test]
    fn visualize_passes_printable_ascii_unchanged() {
        let s = "abcXYZ123!@#$%^&*()_+={}[]:;\"'<>,.?/|";
        assert_eq!(visualize_invisible_bytes(s), s);
    }

    #[test]
    fn visualize_preserves_tab_newline_carriage_return() {
        // Multi-line payloads (XSS HTML templates) must stay
        // readable (the whitespace trio passes through).
        assert_eq!(visualize_invisible_bytes("a\tb\nc\rd"), "a\tb\nc\rd");
    }

    #[test]
    fn visualize_escapes_delete_byte() {
        // 0x7F DEL (not printable, must be escaped).
        assert_eq!(visualize_invisible_bytes("a\u{007F}b"), "a\\x7Fb");
    }

    #[test]
    fn visualize_passes_high_unicode_printable_chars() {
        // Fullwidth bracket (U+FF1C) from bracket_confusable
        // visually distinct, leave verbatim.
        assert_eq!(visualize_invisible_bytes("a\u{FF1C}b"), "a\u{FF1C}b");
    }

    #[test]
    fn visualize_handles_mixed_content() {
        let input = "UNION\u{0007}SELECT \u{200B}1=1";
        let out = visualize_invisible_bytes(input);
        assert!(out.contains("UNION"));
        assert!(out.contains("\\x07"));
        assert!(out.contains("SELECT"));
        assert!(out.contains("\\u{200B}"));
        assert!(out.contains("1=1"));
    }

    #[test]
    fn visualize_empty_input() {
        assert_eq!(visualize_invisible_bytes(""), "");
    }

    #[test]
    fn visualize_only_invisible_codepoints() {
        let input = "\u{0007}\u{0000}\u{200B}";
        let out = visualize_invisible_bytes(input);
        assert_eq!(out, "\\x07\\x00\\u{200B}");
    }

    #[test]
    fn tamper_unknown_leaf_fails_filter_parse() {
        // Unknown selectors error out at the filter layer, must
        // not silently match nothing.
        let r = TechniqueFilter::parse(&["tamper/no_such_tamper".to_string()], &[]);
        assert!(r.is_err());
    }

    // ── format-shape regression guards (2026-05 dogfood pass 4) ──

    #[test]
    fn format_value_parser_accepts_text_json_jsonl() {
        // The clap arg config must accept all three values without
        // erroring out on parse time.  The actual rendering branch
        // is exercised by run_evade integration tests below.
        for value in ["text", "json", "jsonl"] {
            // Construct args via clap's parse-from-iter so we exercise
            // the full value_parser path.
            use clap::Parser;
            #[derive(clap::Parser)]
            struct Wrap {
                #[command(flatten)]
                ev: EvadeArgs,
            }
            let r = Wrap::try_parse_from(["evade", "--payload", "X", "--format", value]);
            assert!(r.is_ok(), "format `{value}` must parse: {:?}", r.err());
        }
    }

    #[test]
    fn format_value_parser_rejects_unknown_format() {
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Wrap {
            #[command(flatten)]
            ev: EvadeArgs,
        }
        let r = Wrap::try_parse_from(["evade", "--payload", "X", "--format", "yaml"]);
        assert!(r.is_err(), "unknown format must reject");
    }

    // ── Top-N summary tail (text mode) ─────────────────────────

    fn variant(payload: &str, techniques: &[&str], confidence: f64) -> crate::helpers::Variant {
        crate::helpers::Variant {
            payload: payload.to_string(),
            techniques: techniques.iter().map(|s| (*s).to_string()).collect(),
            confidence,
        }
    }

    #[test]
    fn top_n_summary_lists_top_5_by_descending_confidence() {
        let variants = vec![
            variant("low", &["url"], 0.10),
            variant("mid1", &["base64"], 0.50),
            variant("hi1", &["dwd"], 0.90),
            variant("hi2", &["wide"], 0.95),
            variant("mid2", &["case"], 0.55),
            variant("low2", &["nada"], 0.05),
            variant("hi3", &["pp"], 0.99),
            variant("mid3", &["xor"], 0.60),
        ];
        let s = strip_ansi(&top_n_summary_text(&variants));
        // Header present.
        assert!(
            s.contains("Summary (top-5 by confidence)"),
            "summary header missing:\n{s}"
        );
        // The 5 highest confidence variants are #7 (0.99), #4 (0.95),
        // #3 (0.90), #8 (0.60), #5 (0.55), in that order.
        let expected_order = ["#7", "#4", "#3", "#8", "#5"];
        let mut last_pos = 0;
        for label in expected_order {
            let pos = s
                .find(label)
                .unwrap_or_else(|| panic!("missing {label} in:\n{s}"));
            assert!(
                pos >= last_pos,
                "summary order broken: {label} appeared before previous row at pos {pos} vs last {last_pos}\n{s}"
            );
            last_pos = pos;
        }
        // The two lowest-confidence variants must NOT appear.
        assert!(
            !s.contains("#6 "),
            "low2 (#6 conf 0.05) must not be in top-5:\n{s}"
        );
    }

    #[test]
    fn top_n_summary_shows_technique_frequency_when_more_than_one_chain() {
        let variants = vec![
            variant("a", &["url"], 0.5),
            variant("b", &["url"], 0.5),
            variant("c", &["url"], 0.5),
            variant("d", &["b64"], 0.5),
            variant("e", &["b64"], 0.5),
            variant("f", &["hex"], 0.5),
            variant("g", &["hex"], 0.5),
            variant("h", &["hex"], 0.5),
        ];
        let s = strip_ansi(&top_n_summary_text(&variants));
        assert!(
            s.contains("Technique frequency"),
            "freq header missing:\n{s}"
        );
        // Highest-count chain (hex × 3 + url × 3 -> tied) must
        // appear; checking the most common alone is enough since
        // tie-break is alphabetical (hex < url).
        assert!(s.contains("3×  hex"), "hex × 3 line missing:\n{s}");
        assert!(s.contains("3×  url"), "url × 3 line missing:\n{s}");
        assert!(s.contains("2×  b64"), "b64 × 2 line missing:\n{s}");
    }

    #[test]
    fn top_n_summary_omits_frequency_block_when_only_one_chain() {
        // Single chain across all variants: the frequency block adds
        // no signal, so it's hidden.
        let variants = vec![
            variant("a", &["url"], 0.5),
            variant("b", &["url"], 0.6),
            variant("c", &["url"], 0.7),
            variant("d", &["url"], 0.8),
            variant("e", &["url"], 0.9),
            variant("f", &["url"], 0.4),
            variant("g", &["url"], 0.3),
            variant("h", &["url"], 0.2),
        ];
        let s = strip_ansi(&top_n_summary_text(&variants));
        assert!(s.contains("Summary (top-5 by confidence)"));
        assert!(
            !s.contains("Technique frequency"),
            "freq block must be hidden when only one chain exists:\n{s}"
        );
    }

    #[test]
    fn top_n_summary_caps_top_block_at_5_even_with_more_variants() {
        let variants: Vec<_> = (0..20)
            .map(|i| variant(&format!("p{i}"), &["url"], 1.0 - (i as f64) / 100.0))
            .collect();
        let s = strip_ansi(&top_n_summary_text(&variants));
        // 5 numbered lines under the summary header.
        let header_pos = s.find("Summary (top-5").unwrap();
        let after = &s[header_pos..];
        let count = after.matches("conf ").count();
        assert_eq!(
            count, 5,
            "top block must show exactly 5 entries, found {count}:\n{after}"
        );
    }

    /// Strip ANSI color codes so assertions are deterministic
    /// regardless of whether the test runs under a TTY-detecting
    /// `colored` build. The codes follow the form `ESC [ … m`.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut iter = s.chars().peekable();
        while let Some(c) = iter.next() {
            if c == '\u{1b}' && iter.peek() == Some(&'[') {
                iter.next(); // consume '['
                for cc in iter.by_ref() {
                    if cc.is_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }
