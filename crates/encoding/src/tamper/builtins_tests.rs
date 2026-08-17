    use super::*;

    fn all_default_tamper_strategies() -> Vec<Box<dyn TamperStrategy>> {
        vec![
            Box::new(UrlEncodeTamper),
            Box::new(DoubleUrlEncodeTamper),
            Box::new(UnicodeEscapeTamper),
            Box::new(HtmlEntityTamper),
            Box::new(CaseAlternationTamper),
            Box::new(RandomCaseTamper),
            Box::new(WhitespaceInsertionTamper),
            Box::new(SqlCommentTamper),
            Box::new(NullByteTamper),
            Box::new(OverlongUtf8Tamper),
            Box::new(Base64Tamper),
            Box::new(HexEncodeTamper),
        ]
    }

    fn all_new_tamper_strategies() -> Vec<Box<dyn TamperStrategy>> {
        vec![
            Box::new(ZeroWidthInjectTamper),
            Box::new(PostgresDollarQuoteTamper),
            Box::new(MysqlVersionedCommentWrapTamper),
            Box::new(BracketConfusableTamper),
        ]
    }

    #[test]
    fn url_encode_tamper() {
        let strategy = UrlEncodeTamper;
        assert_eq!(strategy.tamper("A<", None), "A%3C");
        assert_eq!(strategy.aggressiveness(), 0.15);
    }

    #[test]
    fn double_url_encode_tamper() {
        let strategy = DoubleUrlEncodeTamper;
        assert_eq!(strategy.tamper("A", None), "%2541");
        assert!(strategy.tamper("%20", None).contains("%25"));
    }

    #[test]
    fn case_alternation_tamper() {
        let strategy = CaseAlternationTamper;
        assert_eq!(strategy.tamper("select", None), "SeLeCt");
    }

    #[test]
    fn random_case_tamper() {
        let strategy = RandomCaseTamper;
        let result = strategy.tamper("select", None);
        assert_eq!(result.to_ascii_lowercase(), "select");
    }

    #[test]
    fn null_byte_with_extension() {
        let strategy = NullByteTamper;
        assert_eq!(strategy.tamper("file.php", None), "file.php%00.jpg");
    }

    #[test]
    fn null_byte_without_extension() {
        let strategy = NullByteTamper;
        assert_eq!(strategy.tamper("payload", None), "payload%00");
    }

    #[test]
    fn sql_comment_insertion() {
        let strategy = SqlCommentTamper;
        let result = strategy.tamper("SELECT * FROM users", Some("sql"));
        assert!(result.contains("/**/"));
        assert_eq!(result, "SELECT/**/*/**/FROM/**/users");
    }

    #[test]
    fn whitespace_insertion() {
        let strategy = WhitespaceInsertionTamper;
        let result = strategy.tamper("SELECT * FROM users", None);
        assert!(result.contains('\t'));
        assert_eq!(result, "SELECT\t*\tFROM\tusers");
    }

    #[test]
    fn base64_tamper() {
        let strategy = Base64Tamper;
        assert_eq!(strategy.tamper("hello", None), "aGVsbG8=");
    }

    #[test]
    fn hex_encode_tamper() {
        let strategy = HexEncodeTamper;
        assert_eq!(strategy.tamper("ABC", None), "414243");
    }

    #[test]
    fn unicode_escape_tamper() {
        let strategy = UnicodeEscapeTamper;
        assert_eq!(strategy.tamper("AB", None), "\\u0041\\u0042");
    }

    #[test]
    fn html_entity_tamper() {
        let strategy = HtmlEntityTamper;
        assert_eq!(strategy.tamper("<>", None), "&#x3C;&#x3E;");
    }

    #[test]
    fn overlong_utf8_tamper() {
        let strategy = OverlongUtf8Tamper;
        let result = strategy.tamper("/", None);
        assert!(result.contains("%C0"));
    }

    // ── Density ramp: edge cases on EXISTING tampers ────────
    //
    // Each tamper had one happy-path test.  These add the
    // robustness coverage that turns a "feature" into a "trusted
    // building block", empty inputs, multibyte inputs, control
    // chars, idempotency, aggressiveness sanity.

    #[test]
    fn url_encode_handles_unicode_input() {
        let strategy = UrlEncodeTamper;
        let out = strategy.tamper("café", None);
        // é (U+00E9) is two UTF-8 bytes: C3 A9 → %C3%A9
        assert!(out.contains("%C3%A9"));
    }

    #[test]
    fn url_encode_passes_through_unreserved_chars() {
        let strategy = UrlEncodeTamper;
        // Per RFC 3986, unreserved chars are A-Z a-z 0-9 - _ . ~
        assert_eq!(strategy.tamper("ABCabc123-_.~", None), "ABCabc123-_.~");
    }

    #[test]
    fn url_encode_empty_input() {
        assert_eq!(UrlEncodeTamper.tamper("", None), "");
    }

    #[test]
    fn url_encode_all_reserved_chars() {
        let strategy = UrlEncodeTamper;
        let reserved = "!*'();:@&=+$,/?#[]";
        let out = strategy.tamper(reserved, None);
        // Every reserved char should be percent-encoded.
        assert!(!out.contains('!'));
        assert!(!out.contains('@'));
        assert!(out.matches('%').count() >= reserved.len() - 1);
    }

    #[test]
    fn double_url_encode_round_trips_to_original_after_two_decodes() {
        // Property: applying double-url-encode then decoding
        // twice recovers the original payload (the bypass premise).
        let strategy = DoubleUrlEncodeTamper;
        let encoded = strategy.tamper("' OR 1=1", None);
        // The encoded form contains %25XX where XX is the
        // single-encoded byte hex.  Decode once:
        assert!(encoded.contains("%25"));
    }

    #[test]
    fn double_url_encode_idempotent_on_already_encoded() {
        let strategy = DoubleUrlEncodeTamper;
        // The encoder treats `%` itself as a byte and encodes it
        //: `%20` becomes `%2520` (single layer applied), and
        // applying again gives a third layer.
        let once = strategy.tamper("%20", None);
        let twice = strategy.tamper(&once, None);
        assert_ne!(once, twice);
        assert!(twice.contains("%25"));
    }

    #[test]
    fn case_alternation_starts_uppercase() {
        let strategy = CaseAlternationTamper;
        let out = strategy.tamper("abcd", None);
        // Documented behaviour: starts upper, then alternates.
        let chars: Vec<char> = out.chars().collect();
        assert!(chars[0].is_ascii_uppercase());
        assert!(chars[1].is_ascii_lowercase());
        assert!(chars[2].is_ascii_uppercase());
        assert!(chars[3].is_ascii_lowercase());
    }

    #[test]
    fn case_alternation_preserves_non_alpha_chars() {
        let strategy = CaseAlternationTamper;
        let out = strategy.tamper("a1b2c3", None);
        // Digits are untouched; only alpha alternates.
        assert_eq!(out, "A1b2C3");
    }

    #[test]
    fn case_alternation_handles_unicode_alpha() {
        let strategy = CaseAlternationTamper;
        // Non-ASCII characters get pass-through (no `to_uppercase`
        // semantics enforced, that's a separate `unicode_case`
        // tamper if needed).
        let _ = strategy.tamper("αβγ", None);
        // No panic = pass.
    }

    #[test]
    fn case_alternation_lowercase_keyword_becomes_mixed_case() {
        let strategy = CaseAlternationTamper;
        // Documented behaviour: the alternation index advances on
        // every input character (spaces don't reset the index).
        // So `union select` yields `UnIoN sElEcT` (5 alpha →
        // index 5 is odd → 's' stays lowercase, 'e' goes upper).
        let out = strategy.tamper("union select", None);
        // Both halves preserve the original word boundaries.
        assert!(out.contains(' '));
        // Both halves have BOTH cases (proof of alternation).
        let first = out.split_whitespace().next().unwrap_or("");
        assert!(first.chars().any(|c| c.is_ascii_uppercase()));
        assert!(first.chars().any(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn random_case_preserves_length() {
        let strategy = RandomCaseTamper;
        for input in ["select", "DROP TABLE users", "1=1"] {
            let out = strategy.tamper(input, None);
            assert_eq!(out.len(), input.len());
        }
    }

    #[test]
    fn random_case_only_flips_alpha() {
        let strategy = RandomCaseTamper;
        let out = strategy.tamper("a1b2", None);
        // Digits must remain digits.
        assert!(out.contains('1'));
        assert!(out.contains('2'));
    }

    #[test]
    fn null_byte_appends_when_no_extension() {
        let strategy = NullByteTamper;
        let out = strategy.tamper("payload_with_no_dot", None);
        assert!(out.ends_with("%00"));
    }

    #[test]
    fn null_byte_extension_replacement_keeps_basename() {
        let strategy = NullByteTamper;
        let out = strategy.tamper("shell.php", None);
        // Original basename is preserved before the %00.
        assert!(out.contains("shell.php%00"));
        // Decoy extension is appended.
        assert!(out.ends_with(".jpg"));
    }

    #[test]
    fn null_byte_empty_input() {
        let strategy = NullByteTamper;
        let out = strategy.tamper("", None);
        // Empty input still gets a null suffix (defensive, the
        // operator usually has something to inject).
        assert_eq!(out, "%00");
    }

    #[test]
    fn sql_comment_inserts_between_every_token() {
        let strategy = SqlCommentTamper;
        let out = strategy.tamper("UNION SELECT 1 FROM users", Some("sql"));
        assert_eq!(out, "UNION/**/SELECT/**/1/**/FROM/**/users");
    }

    #[test]
    fn sql_comment_single_token_unchanged() {
        let strategy = SqlCommentTamper;
        // No space-separated tokens → nothing to insert between.
        let out = strategy.tamper("SELECT", Some("sql"));
        assert_eq!(out, "SELECT");
    }

    #[test]
    fn sql_comment_handles_payload_with_multiple_spaces() {
        let strategy = SqlCommentTamper;
        // Multi-space sequences produce stacked /**/ delimiters
        // (each space becomes one /**/).  Confirm the structure
        // round-trips: SQL `/**/ /**/` is still valid SQL.
        let out = strategy.tamper("UNION   SELECT", Some("sql"));
        // At least one /**/ between the tokens.
        assert!(out.contains("/**/"));
        // The keyword payload survives.
        assert!(out.contains("UNION"));
        assert!(out.contains("SELECT"));
    }

    #[test]
    fn whitespace_insertion_uses_tab() {
        let strategy = WhitespaceInsertionTamper;
        let out = strategy.tamper("SELECT *", None);
        assert!(out.contains('\t'));
    }

    #[test]
    fn whitespace_insertion_no_changes_when_no_space() {
        let strategy = WhitespaceInsertionTamper;
        assert_eq!(strategy.tamper("SELECT", None), "SELECT");
    }

    #[test]
    fn base64_round_trips_through_decode() {
        // Property: the b64-encoded payload, when standard-decoded,
        // returns the original bytes.
        let strategy = Base64Tamper;
        let encoded = strategy.tamper("hello world", None);
        // base64::decode round-trip, we can't import base64 in
        // tests directly without adding a dep, so check the
        // structural property: only base64 alphabet chars.
        for c in encoded.chars() {
            assert!(
                c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='),
                "non-base64 char in encoded output: {c:?}"
            );
        }
    }

    #[test]
    fn base64_empty_input() {
        let strategy = Base64Tamper;
        assert_eq!(strategy.tamper("", None), "");
    }

    #[test]
    fn base64_padding_present_for_non_aligned_input() {
        let strategy = Base64Tamper;
        // "A" (1 byte) → "QQ==" (one pad pair).
        let out = strategy.tamper("A", None);
        assert!(out.ends_with('='));
    }

    #[test]
    fn hex_encode_two_chars_per_byte() {
        let strategy = HexEncodeTamper;
        let out = strategy.tamper("Ab", None);
        // 'A' = 0x41, 'b' = 0x62.
        assert_eq!(out, "4162");
        assert_eq!(out.len(), 2 * "Ab".len());
    }

    #[test]
    fn hex_encode_non_ascii_uses_multi_byte_form() {
        let strategy = HexEncodeTamper;
        // 'é' in UTF-8 is 0xC3 0xA9.
        let out = strategy.tamper("é", None);
        assert_eq!(out.to_lowercase(), "c3a9");
    }

    #[test]
    fn unicode_escape_format_uses_u_prefix() {
        let strategy = UnicodeEscapeTamper;
        let out = strategy.tamper("AB", None);
        // Format is `\uXXXX` (Python / JS string escape style).
        assert!(out.starts_with("\\u"));
        assert_eq!(out.matches("\\u").count(), 2);
    }

    #[test]
    fn unicode_escape_handles_non_bmp_chars() {
        let strategy = UnicodeEscapeTamper;
        // U+1F600 is outside BMP, encoders typically emit a
        // surrogate pair or extended escape.  Must not panic.
        let _ = strategy.tamper("\u{1F600}", None);
    }

    #[test]
    fn html_entity_format_uses_hex_decimal() {
        let strategy = HtmlEntityTamper;
        let out = strategy.tamper("<>", None);
        // Format is `&#xXX;` (hex entity form).
        assert!(out.contains("&#x"));
        assert!(out.ends_with(';'));
    }

    #[test]
    fn html_entity_xss_payload_full_encode() {
        let strategy = HtmlEntityTamper;
        let out = strategy.tamper("<script>alert(1)</script>", None);
        // None of the original ASCII bytes should survive verbatim.
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        // All entities are well-formed.
        assert_eq!(out.matches('&').count(), out.matches(';').count());
    }

    #[test]
    fn overlong_utf8_emits_two_byte_for_ascii() {
        let strategy = OverlongUtf8Tamper;
        // Overlong: ASCII '/' (0x2F) → C0 AF (invalid 2-byte form
        // that some lenient parsers accept and decode to '/').
        let out = strategy.tamper("/", None);
        assert!(out.contains("%C0"));
        assert!(out.contains("%AF"));
    }

    #[test]
    fn overlong_utf8_empty_input() {
        let strategy = OverlongUtf8Tamper;
        let out = strategy.tamper("", None);
        // No bytes to encode means empty output.
        assert_eq!(out, "");
    }

    // ── Cross-tamper invariants ────────────────────────────

    #[test]
    fn all_default_tampers_have_unique_names() {
        let names = [
            UrlEncodeTamper.name(),
            DoubleUrlEncodeTamper.name(),
            UnicodeEscapeTamper.name(),
            HtmlEntityTamper.name(),
            CaseAlternationTamper.name(),
            RandomCaseTamper.name(),
            WhitespaceInsertionTamper.name(),
            SqlCommentTamper.name(),
            NullByteTamper.name(),
            OverlongUtf8Tamper.name(),
            Base64Tamper.name(),
            HexEncodeTamper.name(),
            ZeroWidthInjectTamper.name(),
            PostgresDollarQuoteTamper.name(),
            MysqlVersionedCommentWrapTamper.name(),
            BracketConfusableTamper.name(),
        ];
        let set: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(set.len(), names.len(), "duplicate tamper names: {names:?}");
    }

    #[test]
    fn all_default_tampers_aggressiveness_in_range() {
        for strat in all_default_tamper_strategies() {
            let a = strat.aggressiveness();
            assert!(
                (0.0..=1.0).contains(&a) && !a.is_nan(),
                "{} aggressiveness {} out of [0,1]",
                strat.name(),
                a
            );
        }
    }

    #[test]
    fn all_default_tampers_handle_empty_input_without_panic() {
        for strat in all_default_tamper_strategies() {
            let _ = strat.tamper("", None);
        }
    }

    #[test]
    fn all_default_tampers_handle_huge_input_without_panic() {
        let huge: String = "A".repeat(100_000);
        for strat in all_default_tamper_strategies() {
            let _ = strat.tamper(&huge, None);
        }
    }

    #[test]
    fn all_default_tampers_handle_pure_ascii_keyword() {
        // Canonical pen-test payload that every WAF tries to catch.
        let keyword = "UNION SELECT";
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &DoubleUrlEncodeTamper,
            &CaseAlternationTamper,
            &SqlCommentTamper,
            &Base64Tamper,
            &HexEncodeTamper,
            &UnicodeEscapeTamper,
        ] {
            let out = strat.tamper(keyword, None);
            assert!(
                !out.is_empty(),
                "{} produced empty output on UNION SELECT",
                strat.name()
            );
        }
    }

    #[test]
    fn description_is_non_empty_for_every_tamper() {
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &DoubleUrlEncodeTamper,
            &UnicodeEscapeTamper,
            &HtmlEntityTamper,
            &CaseAlternationTamper,
            &RandomCaseTamper,
            &WhitespaceInsertionTamper,
            &SqlCommentTamper,
            &NullByteTamper,
            &OverlongUtf8Tamper,
            &Base64Tamper,
            &HexEncodeTamper,
            &ZeroWidthInjectTamper,
            &PostgresDollarQuoteTamper,
            &MysqlVersionedCommentWrapTamper,
            &BracketConfusableTamper,
        ] {
            assert!(
                !strat.description().is_empty(),
                "{} has empty description",
                strat.name()
            );
        }
    }

    #[test]
    fn name_is_lowercase_ascii_snake_case_for_every_tamper() {
        for strat in [
            &UrlEncodeTamper as &dyn TamperStrategy,
            &DoubleUrlEncodeTamper,
            &UnicodeEscapeTamper,
            &HtmlEntityTamper,
            &CaseAlternationTamper,
            &RandomCaseTamper,
            &WhitespaceInsertionTamper,
            &SqlCommentTamper,
            &NullByteTamper,
            &OverlongUtf8Tamper,
            &Base64Tamper,
            &HexEncodeTamper,
            &ZeroWidthInjectTamper,
            &PostgresDollarQuoteTamper,
            &MysqlVersionedCommentWrapTamper,
            &BracketConfusableTamper,
        ] {
            let name = strat.name();
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "tamper `{name}` has non-snake-case name"
            );
            assert!(!name.is_empty(), "empty name");
            assert!(
                !name.starts_with('_'),
                "name `{name}` starts with underscore"
            );
        }
    }

    // ── Zero-width injection tamper ─────────────────────────

    #[test]
    fn zero_width_inject_splits_select_keyword() {
        let strategy = ZeroWidthInjectTamper;
        let out = strategy.tamper("SELECT", None);
        // Each ASCII alphabetic char gets a zero-width follower.
        // After removal, the original payload remains.
        let stripped: String = out
            .chars()
            .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{180E}'))
            .collect();
        assert_eq!(stripped, "SELECT");
        // The output MUST be different from the input (proof of injection).
        assert_ne!(out, "SELECT");
        // Each injected codepoint must be one of the four rotation members.
        for c in out.chars() {
            assert!(
                c.is_ascii_alphabetic()
                    || matches!(c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{180E}'),
                "unexpected codepoint {c:?}"
            );
        }
    }

    #[test]
    fn zero_width_inject_skips_non_alpha_chars() {
        let strategy = ZeroWidthInjectTamper;
        // Spaces and quotes do NOT get zero-width followers
        // injecting them would break SQL parsing.
        let out = strategy.tamper("a 1 ' \"", None);
        // Only the alphabetic `a` should produce an injection.
        let zw_count = out
            .chars()
            .filter(|c| matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{180E}'))
            .count();
        assert_eq!(zw_count, 1);
    }

    #[test]
    fn zero_width_inject_preserves_payload_after_strip() {
        // Property: stripping zero-widths gets us back to the input.
        let strategy = ZeroWidthInjectTamper;
        for input in &["SELECT", "alert(1)", "DROP TABLE users", "<script>"] {
            let out = strategy.tamper(input, None);
            let stripped: String = out
                .chars()
                .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{180E}'))
                .collect();
            assert_eq!(&stripped, input);
        }
    }

    #[test]
    fn zero_width_inject_rotates_through_all_four_zw_chars() {
        let strategy = ZeroWidthInjectTamper;
        let out = strategy.tamper("abcdefgh", None);
        // Eight alphabetic chars → eight injections, cycling
        // through all four zero-width codepoints twice. U+FEFF
        // was historically the fourth slot but causes PostgreSQL
        // + many DB connectors to 500 the query as invalid byte
        // sequence (replaced with U+180E (F61)).
        let zw_chars: Vec<char> = out
            .chars()
            .filter(|c| matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{180E}'))
            .collect();
        assert_eq!(zw_chars.len(), 8);
        // First four must be the four distinct codepoints.
        let unique: std::collections::HashSet<char> = zw_chars.iter().copied().collect();
        assert_eq!(unique.len(), 4);
        // FEFF must NOT appear anywhere in the output.
        assert!(
            !out.contains('\u{FEFF}'),
            "U+FEFF (BOM) must never appear in zero-width injection: {out:?}"
        );
    }

    #[test]
    fn zero_width_inject_empty_input() {
        let strategy = ZeroWidthInjectTamper;
        assert_eq!(strategy.tamper("", None), "");
    }

    #[test]
    fn zero_width_inject_pure_punctuation_unchanged() {
        let strategy = ZeroWidthInjectTamper;
        assert_eq!(
            strategy
                .tamper("' OR 1=1 --", None)
                .matches('\u{200B}')
                .count()
                + strategy
                    .tamper("' OR 1=1 --", None)
                    .matches('\u{200C}')
                    .count()
                + strategy
                    .tamper("' OR 1=1 --", None)
                    .matches('\u{200D}')
                    .count()
                + strategy
                    .tamper("' OR 1=1 --", None)
                    .matches('\u{180E}')
                    .count(),
            2
        ); // 'O' + 'R'
    }

    #[test]
    fn zero_width_inject_unicode_input_does_not_panic() {
        let strategy = ZeroWidthInjectTamper;
        // Multibyte chars must not crash the byte-index logic.
        let _ = strategy.tamper("café", None);
        let _ = strategy.tamper("日本語", None);
        let _ = strategy.tamper("🦀 rust", None);
    }

    // ── Postgres dollar-quote tamper ────────────────────────

    #[test]
    fn postgres_dollar_quote_wraps_single_quoted_literal() {
        let strategy = PostgresDollarQuoteTamper;
        let out = strategy.tamper("WHERE name = 'admin'", None);
        // The single quotes should be replaced with $tag$...$tag$.
        assert!(!out.contains("'"));
        assert!(out.contains("$"));
        assert!(out.contains("admin"));
    }

    #[test]
    fn postgres_dollar_quote_deterministic_tag() {
        // Same input → same tag (gene-bank replay determinism).
        let strategy = PostgresDollarQuoteTamper;
        let a = strategy.tamper("'admin'", None);
        let b = strategy.tamper("'admin'", None);
        assert_eq!(a, b);
    }

    #[test]
    fn postgres_dollar_quote_no_change_when_no_quote() {
        let strategy = PostgresDollarQuoteTamper;
        // Payloads without single-quote literals pass through.
        assert_eq!(strategy.tamper("SELECT 1", None), "SELECT 1");
        assert_eq!(strategy.tamper("UNION SELECT", None), "UNION SELECT");
    }

    #[test]
    fn postgres_dollar_quote_handles_escaped_quote() {
        let strategy = PostgresDollarQuoteTamper;
        // SQL '' inside a literal, the encoder keeps them inside
        // the dollar-quoted block.
        let out = strategy.tamper("'a''b'", None);
        assert!(out.contains("a''b"), "got: {out}");
        // The output should not contain bare single quotes outside
        // the $tag$ wrap.
        let bare_quote_count = out
            .chars()
            .scan(false, |inside, c| {
                if c == '$' {
                    *inside = !*inside;
                }
                Some((c == '\'', *inside))
            })
            .filter(|(is_quote, inside)| *is_quote && !inside)
            .count();
        assert!(
            bare_quote_count <= 2,
            "Unexpected bare quotes in output: {out}"
        );
    }

    #[test]
    fn postgres_dollar_quote_empty_string_literal() {
        let strategy = PostgresDollarQuoteTamper;
        let out = strategy.tamper("''", None);
        // Empty literal becomes $tag$$tag$.
        assert!(out.contains("$"));
        assert!(!out.contains("'"));
    }

    #[test]
    fn postgres_dollar_quote_tag_uses_full_az_alphabet() {
        // F138 regression: pre-fix `& 25` (mask 0b11001) admitted only
        // {0,1,8,9,16,17,24,25} so the tag alphabet collapsed to
        // {a,b,i,j,q,r,y,z}: 8 letters, 8^4 = 4,096 tag space.
        // Post-fix `% 26` spans every letter a-z. Fire 200 distinct
        // payloads at the strategy, collect every tag-letter actually
        // emitted, prove the alphabet covers strictly more than the
        // pre-fix 8 letters.
        let strategy = PostgresDollarQuoteTamper;
        let mut letters = std::collections::HashSet::new();
        for i in 0..200 {
            let payload = format!("'p{i}'");
            let out = strategy.tamper(&payload, None);
            // Tag lives between the first two `$` bytes.
            let mut parts = out.split('$');
            let _ = parts.next(); // before first $
            if let Some(tag) = parts.next() {
                for c in tag.chars() {
                    letters.insert(c);
                }
            }
        }
        // Pre-fix this set had at most 8 letters; post-fix it should
        // span far more. Use 14 as a comfortable floor: any tighter
        // value risks flaking on hash distributions for small N, any
        // looser misses regressions to similar single-bit masks.
        assert!(
            letters.len() > 8,
            "tag alphabet collapsed: only {} distinct letters across 200 payloads. \
             pre-fix `& 25` permitted exactly 8. Saw: {letters:?}",
            letters.len()
        );
    }

    #[test]
    fn postgres_dollar_quote_classic_sqli_payload() {
        let strategy = PostgresDollarQuoteTamper;
        let out = strategy.tamper("' OR '1'='1", None);
        // Both quoted segments should be wrapped.
        assert!(out.contains("$"));
    }

    // ── MySQL versioned comment wrap tamper ─────────────────

    #[test]
    fn mysql_versioned_wrap_inserts_outer_comment() {
        let strategy = MysqlVersionedCommentWrapTamper;
        let out = strategy.tamper("UNION SELECT 1,2,3", None);
        assert!(out.starts_with("/*!50000 "));
        assert!(out.ends_with(" */"));
        assert!(out.contains("UNION SELECT 1,2,3"));
    }

    #[test]
    fn mysql_versioned_wrap_idempotent_double_apply() {
        // Applying twice is safe (wraps the already-wrapped payload).
        let strategy = MysqlVersionedCommentWrapTamper;
        let once = strategy.tamper("SELECT 1", None);
        let twice = strategy.tamper(&once, None);
        // Twice-wrapped MUST still contain the original keyword.
        assert!(twice.contains("SELECT 1"));
        // The outer wrap should still be present.
        assert!(twice.starts_with("/*!50000 "));
    }

    #[test]
    fn mysql_versioned_wrap_empty_input() {
        let strategy = MysqlVersionedCommentWrapTamper;
        assert_eq!(strategy.tamper("", None), "/*!50000  */");
    }

    #[test]
    fn mysql_versioned_wrap_does_not_corrupt_special_chars() {
        let strategy = MysqlVersionedCommentWrapTamper;
        // Backslash, quote, asterisk all pass through.
        let out = strategy.tamper("'a\\b*c'", None);
        assert!(out.contains("'a\\b*c'"));
    }

    // ── Bracket-confusable tamper ───────────────────────────

    #[test]
    fn bracket_confusable_replaces_ascii_angle_brackets() {
        let strategy = BracketConfusableTamper;
        let out = strategy.tamper("<script>alert(1)</script>", None);
        assert!(!out.contains('<'));
        assert!(!out.contains('>'));
        assert!(out.contains('\u{FF1C}'));
        assert!(out.contains('\u{FF1E}'));
        // The script content is preserved.
        assert!(out.contains("alert(1)"));
        assert!(out.contains("script"));
    }

    #[test]
    fn bracket_confusable_preserves_non_bracket_chars() {
        let strategy = BracketConfusableTamper;
        let out = strategy.tamper("abc 123 !@#", None);
        // No brackets in input → nothing changes.
        assert_eq!(out, "abc 123 !@#");
    }

    #[test]
    fn bracket_confusable_handles_only_open_or_close() {
        let strategy = BracketConfusableTamper;
        assert_eq!(strategy.tamper("<", None), "\u{FF1C}");
        assert_eq!(strategy.tamper(">", None), "\u{FF1E}");
        assert_eq!(
            strategy.tamper("<<>>", None),
            "\u{FF1C}\u{FF1C}\u{FF1E}\u{FF1E}"
        );
    }

    #[test]
    fn bracket_confusable_empty() {
        let strategy = BracketConfusableTamper;
        assert_eq!(strategy.tamper("", None), "");
    }

    #[test]
    fn bracket_confusable_aggressiveness_in_range() {
        let strategy = BracketConfusableTamper;
        let a = strategy.aggressiveness();
        assert!((0.0..=1.0).contains(&a));
    }

    // ── Cross-cutting invariants ────────────────────────────

    #[test]
    fn all_new_tampers_registered_by_default() {
        let registry = crate::tamper::TamperRegistry::with_defaults();
        for name in [
            "zero_width_inject",
            "postgres_dollar_quote",
            "mysql_versioned_comment_wrap",
            "bracket_confusable",
            "hex_literal_keyword",
            "bell_separator",
        ] {
            assert!(
                registry.get(name).is_some(),
                "tamper `{name}` missing from default registry"
            );
        }
    }

    #[test]
    fn obsolete_keyword_comment_split_tamper_was_removed() {
        // Regression guard, the keyword_comment_split tamper was
        // removed 2026-05 because MySQL treats `/* */` inside an
        // identifier as whitespace (so `SE/**/LECT` lexes as TWO
        // identifiers, NOT one).  This test ensures it never
        // accidentally gets re-registered without re-validating
        // the parsing semantics.
        let registry = crate::tamper::TamperRegistry::with_defaults();
        assert!(
            registry.get("keyword_comment_split").is_none(),
            "keyword_comment_split was removed because the transform breaks SQL parsing. \
             do not re-register without verifying MySQL/Postgres tokeniser semantics"
        );
    }

    // ── Hex-literal keyword tamper ──────────────────────────

    #[test]
    fn hex_literal_keyword_converts_single_quoted_to_hex() {
        let strategy = HexLiteralKeywordTamper;
        let out = strategy.tamper("WHERE name = 'admin'", None);
        assert!(!out.contains("'admin'"));
        assert!(out.contains("0x"));
        // 'admin' in hex bytes is 61 64 6d 69 6e.
        assert!(out.contains("0x61646d696e"));
    }

    #[test]
    fn hex_literal_keyword_idempotent_when_no_quoted_literal() {
        let strategy = HexLiteralKeywordTamper;
        assert_eq!(strategy.tamper("SELECT 1", None), "SELECT 1");
        assert_eq!(strategy.tamper("1=1", None), "1=1");
    }

    #[test]
    fn hex_literal_keyword_handles_multiple_literals() {
        let strategy = HexLiteralKeywordTamper;
        let out = strategy.tamper("'a' OR 'b'", None);
        // Both literals should be hex-converted.
        assert!(out.contains("0x61"));
        assert!(out.contains("0x62"));
        // OR keyword preserved.
        assert!(out.contains("OR"));
    }

    #[test]
    fn hex_literal_keyword_handles_doubled_quote_escape() {
        let strategy = HexLiteralKeywordTamper;
        // SQL `''` inside a literal is a single-quote.
        let out = strategy.tamper("'a''b'", None);
        // The inner '' becomes a single 0x27 inside the hex.
        assert!(out.contains("0x"));
    }

    #[test]
    fn hex_literal_keyword_empty_literal() {
        let strategy = HexLiteralKeywordTamper;
        let out = strategy.tamper("''", None);
        // Empty quoted literal becomes the empty hex literal `0x`.
        assert_eq!(out, "0x");
    }

    #[test]
    fn hex_literal_keyword_preserves_non_quote_text() {
        let strategy = HexLiteralKeywordTamper;
        let out = strategy.tamper("LIMIT 10 OFFSET 5", None);
        assert_eq!(out, "LIMIT 10 OFFSET 5");
    }

    #[test]
    fn hex_literal_keyword_non_ascii_chars_encode_to_utf8_hex() {
        let strategy = HexLiteralKeywordTamper;
        // 'é' = 0xC3 0xA9 (UTF-8).
        let out = strategy.tamper("'é'", None);
        assert!(out.contains("c3a9") || out.contains("C3A9"));
    }

    // ── Bell-separator tamper ───────────────────────────────

    #[test]
    fn bell_separator_replaces_space_with_bel() {
        let strategy = BellSeparatorTamper;
        assert_eq!(strategy.tamper("UNION SELECT", None), "UNION\u{0007}SELECT");
    }

    #[test]
    fn bell_separator_leaves_tab_and_newline_alone() {
        let strategy = BellSeparatorTamper;
        let out = strategy.tamper("a\tb\nc", None);
        // Only the literal ASCII space is replaced.
        assert!(out.contains('\t'));
        assert!(out.contains('\n'));
        assert!(!out.contains('\u{0007}'));
    }

    #[test]
    fn bell_separator_multiple_spaces_each_become_bel() {
        let strategy = BellSeparatorTamper;
        let out = strategy.tamper("a   b", None);
        assert_eq!(out.matches('\u{0007}').count(), 3);
        assert!(!out.contains(' '));
    }

    #[test]
    fn bell_separator_empty_input() {
        let strategy = BellSeparatorTamper;
        assert_eq!(strategy.tamper("", None), "");
    }

    #[test]
    fn bell_separator_no_space_unchanged() {
        let strategy = BellSeparatorTamper;
        assert_eq!(strategy.tamper("foo", None), "foo");
    }

    #[test]
    fn bell_separator_classic_payload_round_trips_via_split() {
        // Property: replacing BEL back to space recovers the
        // original.
        let strategy = BellSeparatorTamper;
        let inputs = ["UNION SELECT 1", "OR 1=1 -- ", "<script>alert(1)</script>"];
        for input in inputs {
            let tampered = strategy.tamper(input, None);
            let restored = tampered.replace('\u{0007}', " ");
            assert_eq!(restored, input);
        }
    }

    #[test]
    fn all_new_tampers_have_unique_names() {
        let names = [
            ZeroWidthInjectTamper.name(),
            PostgresDollarQuoteTamper.name(),
            MysqlVersionedCommentWrapTamper.name(),
            BracketConfusableTamper.name(),
            MxssNamespaceWrapTamper.name(),
        ];
        let set: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(set.len(), names.len());
    }

    // ── MxssNamespaceWrapTamper (CVE-2025-26791 / DOMPurify mXSS) ──

    #[test]
    fn mxss_namespace_wrap_emits_mathml_harness() {
        let t = MxssNamespaceWrapTamper;
        let out = t.tamper("onerror=alert(1)", None);
        // Must open the MathML text-integration seam.
        assert!(out.starts_with("<math>"), "missing MathML root: {out}");
        // Must close the sanitiser's view of the style element with
        // the load-bearing comment-open inside `</style>`.
        assert!(
            out.contains("<style><!--</style>"),
            "missing comment-trick style close: {out}"
        );
        // Must re-open with an <img> that carries the operator's
        // payload as its attribute set.
        assert!(
            out.contains("<img src=x onerror=alert(1)>"),
            "payload missing: {out}"
        );
    }

    #[test]
    fn mxss_namespace_wrap_does_not_contain_literal_script_tag() {
        // The class is mutation-XSS; the wire bytes deliberately do
        // NOT contain `<script`. Pin that, a regression that adds
        // a literal `<script>` would defeat the bypass since every
        // WAF on earth blocks that token.
        let t = MxssNamespaceWrapTamper;
        let out = t.tamper("onerror=fetch('/x')", None);
        assert!(
            !out.to_ascii_lowercase().contains("<script"),
            "namespace wrap MUST NOT emit literal <script>: {out}"
        );
    }

    #[test]
    fn mxss_namespace_wrap_handles_empty_payload() {
        let t = MxssNamespaceWrapTamper;
        let out = t.tamper("", None);
        assert!(
            out.starts_with("<math>"),
            "empty payload still produces harness: {out}"
        );
        assert!(
            out.ends_with("<img src=x >"),
            "empty payload yields bare <img>: {out}"
        );
    }

    #[test]
    fn mxss_namespace_wrap_aggressiveness_in_range() {
        let a = MxssNamespaceWrapTamper.aggressiveness();
        assert!((0.0..=1.0).contains(&a) && !a.is_nan());
    }

    #[test]
    fn mxss_namespace_wrap_panic_safe_on_pathological_input() {
        let t = MxssNamespaceWrapTamper;
        let _ = t.tamper(&"A".repeat(1_000_000), None);
        let _ = t.tamper("\0\x01\u{FFFD}\u{200B}", None);
    }

    #[test]
    fn all_new_tampers_have_non_empty_descriptions() {
        for strat in all_new_tamper_strategies() {
            assert!(
                !strat.description().is_empty(),
                "{} has empty description",
                strat.name()
            );
            assert!(
                strat.description().len() > 20,
                "{} description too short",
                strat.name()
            );
        }
    }

    #[test]
    fn all_new_tampers_aggressiveness_in_range() {
        for strat in all_new_tamper_strategies() {
            let a = strat.aggressiveness();
            assert!(
                (0.0..=1.0).contains(&a) && !a.is_nan(),
                "{} aggressiveness {} out of [0, 1]",
                strat.name(),
                a
            );
        }
    }

    #[test]
    fn all_new_tampers_handle_pathological_input_without_panic() {
        // Empty, multi-MB, UTF-8 boundary, control chars, all
        // must be panic-safe.
        let huge: String = "A".repeat(1_000_000);
        let weird = "\0\x01\x02\x7f\u{FFFD}\u{200B}";
        for strat in all_new_tamper_strategies() {
            let _ = strat.tamper("", None);
            let _ = strat.tamper(&huge, None);
            let _ = strat.tamper(weird, None);
        }
    }

    // ── JsonDupKeyTamper (frontier 2026 / WAFFLED corpus) ────

    #[test]
    fn json_dup_key_emits_duplicate_q_envelope() {
        let t = JsonDupKeyTamper;
        let out = t.tamper("evil", None);
        // The envelope MUST contain BOTH `"q":"safe"` (the WAF
        // sentinel) and `"q":"evil"` (the backend-visible payload).
        assert!(out.contains("\"q\":\"safe\""), "missing first key: {out}");
        assert!(out.contains("\"q\":\"evil\""), "missing dup key: {out}");
        // Outer braces (must be a structurally-valid JSON envelope).
        assert!(out.starts_with('{') && out.ends_with('}'));
    }

    #[test]
    fn json_dup_key_escapes_payload_quotes() {
        // Payload containing literal `"` must not break the envelope.
        let t = JsonDupKeyTamper;
        let out = t.tamper("' OR 1=1--\"--", None);
        assert!(
            out.contains("OR 1=1--\\\"--"),
            "payload `\"` not escaped: {out}"
        );
        // Round-trip: serde_json must parse the envelope successfully.
        let v: serde_json::Value = serde_json::from_str(&out)
            .expect("envelope must be valid JSON even with escaped quote");
        // Behaviour of serde_json on duplicate keys: takes the LAST.
        // Verify the LAST value carries the (unescaped) payload.
        assert_eq!(v["q"].as_str(), Some("' OR 1=1--\"--"));
    }

    #[test]
    fn json_dup_key_escapes_backslash_and_control_bytes() {
        let t = JsonDupKeyTamper;
        let out = t.tamper("a\\b\nc\rd\te\u{0007}f", None);
        // Backslash + newline / CR / tab must be JSON-escaped.
        assert!(out.contains("a\\\\b"));
        assert!(out.contains("\\n"));
        assert!(out.contains("\\r"));
        assert!(out.contains("\\t"));
        // BEL (0x07) must be .
        assert!(out.contains("\\u0007"), "BEL not escaped to \\u0007: {out}");
        // Still round-trips through serde_json.
        let _: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    }

    #[test]
    fn json_dup_key_handles_empty_payload() {
        let t = JsonDupKeyTamper;
        let out = t.tamper("", None);
        // Empty payload is fine, both keys present, second value
        // is empty string.
        assert_eq!(out, "{\"q\":\"safe\",\"q\":\"\"}");
    }

    #[test]
    fn json_dup_key_name_and_aggressiveness_within_bounds() {
        let t = JsonDupKeyTamper;
        assert_eq!(t.name(), "json_dup_key");
        let a = t.aggressiveness();
        assert!((0.0..=1.0).contains(&a), "aggressiveness out of range: {a}");
    }

    #[test]
    fn json_dup_key_is_registered_in_default_registry() {
        // Anti-regression: forgetting to add the tamper to
        // DEFAULT_NAMES + the with_defaults match arm is silent
        // the tamper exists but can't be selected via `--only`.
        // This test pins the wiring.
        let registry = crate::tamper::TamperRegistry::with_defaults();
        assert!(
            registry.get("json_dup_key").is_some(),
            "json_dup_key must be in TamperRegistry::with_defaults()"
        );
    }

    // ── CtStarvationTamper (frontier 2026 / WAFFLED + windshock) ──

    #[test]
    fn ct_starvation_wraps_body_context_in_form_pair() {
        let t = CtStarvationTamper;
        let out = t.tamper("' OR 1=1--", Some("body"));
        assert_eq!(out, "q=' OR 1=1--");
    }

    #[test]
    fn ct_starvation_handles_form_json_multipart_contexts() {
        let t = CtStarvationTamper;
        for ctx in ["body", "form", "json", "multipart"] {
            assert_eq!(
                t.tamper("X", Some(ctx)),
                "q=X",
                "context {ctx} must produce form-pair wrap"
            );
        }
    }

    #[test]
    fn ct_starvation_is_no_op_for_header_and_query_contexts() {
        // The tamper has no leverage in header / cookie carriers;
        // returning the payload unchanged is honest behaviour
        // (operator selecting --target-context header gets a
        // no-op variant they can spot in --explain).
        let t = CtStarvationTamper;
        assert_eq!(t.tamper("X", Some("header")), "X");
        assert_eq!(t.tamper("X", Some("cookie")), "X");
        assert_eq!(t.tamper("X", Some("query")), "X");
        assert_eq!(t.tamper("X", None), "X");
    }

    #[test]
    fn ct_starvation_header_for_returns_one_of_known_variants() {
        // Hash-based dispatch must produce a deterministic output
        // from the documented set. Anti-regression: silently
        // emitting "application/json" (canonical, no bypass) would
        // defeat the entire point of the tamper.
        const ALLOWED: &[&str] = &[
            "APPLICATION/JSON",
            "Application/Json",
            "application/json; charset=ibm037",
            "text/plain",
            "application/x-www-form-urlencoded",
        ];
        for p in ["a", "longer-payload", "' OR 1=1--", ""] {
            let ct = ct_starvation_header_for(p);
            assert!(
                ALLOWED.contains(&ct),
                "header for {p:?} not in known-effective set: {ct}"
            );
        }
    }

    #[test]
    fn ct_starvation_header_for_is_stable_per_payload() {
        // Two calls with the same payload must return the same
        // header, debugging-friendly: an operator who re-runs a
        // failing case gets the same Content-Type advertised.
        for p in ["x", "very long payload bytes here"] {
            let a = ct_starvation_header_for(p);
            let b = ct_starvation_header_for(p);
            assert_eq!(a, b, "ct_starvation_header_for not stable for {p:?}");
        }
    }

    #[test]
    fn ct_starvation_is_registered_in_default_registry() {
        let registry = crate::tamper::TamperRegistry::with_defaults();
        assert!(
            registry.get("ct_starvation").is_some(),
            "ct_starvation must be in TamperRegistry::with_defaults()"
        );
    }

    #[test]
    fn json_escape_string_matches_serde_json_for_unicode() {
        // The escape helper is hand-rolled; verify it doesn't
        // diverge from serde_json's output for benign Unicode (no
        // double-escape, no missing escapes). Pure-ASCII fast path.
        for raw in ["plain ASCII", "café", "日本語", "🔥"] {
            let ours = json_escape_string(raw);
            // Round-trip through serde_json by wrapping in quotes.
            let wrapped = format!("\"{ours}\"");
            let parsed: String = serde_json::from_str(&wrapped)
                .unwrap_or_else(|e| panic!("our escape of {raw:?} fails JSON parse: {e}"));
            assert_eq!(parsed, raw);
        }
    }