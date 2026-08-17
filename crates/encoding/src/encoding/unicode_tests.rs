    use super::*;

    #[test]
    fn unicode_encode_basic() {
        assert_eq!(unicode_encode("A"), "\\u0041");
        assert_eq!(unicode_encode("AB"), "\\u0041\\u0042");
    }

    #[test]
    fn json_unicode_alnum_keyword_split() {
        // "UNION" becomes 5 `\uXXXX` sequences, ASCII bytes nowhere.
        let out = json_unicode_alnum("UNION");
        assert_eq!(out, "\\u0055\\u004E\\u0049\\u004F\\u004E");
        assert!(!out.contains("UNION"));
    }

    // ── json_unicode_full / mixed_case tests ──────────────────────────

    #[test]
    fn json_unicode_full_escapes_every_char() {
        let out = json_unicode_full("a' b");
        // Every char including space and quote escaped.
        assert!(out.contains("\\u0061")); // a
        assert!(out.contains("\\u0027")); // '
        assert!(out.contains("\\u0020")); // space
        assert!(out.contains("\\u0062")); // b
        // No literal input char remains as plain (input letters 'a' and 'b'
        // appear only inside hex of escapes; the literal 'a' standalone
        // boundary should NOT be present as a runnable token).
        // Simpler check: every output codepoint is either backslash, 'u',
        // or hex digit.
        for c in out.chars() {
            assert!(
                c == '\\' || c == 'u' || c.is_ascii_hexdigit(),
                "unexpected raw char {c:?} in {out}"
            );
        }
    }

    #[test]
    fn json_unicode_full_idempotent_on_pre_escaped() {
        let already = "\\u0073elect";
        let out = json_unicode_full(already);
        // Pre-existing s stays unchanged; "elect" gets escaped.
        assert!(out.starts_with("\\u0073"));
        assert!(out.contains("\\u0065")); // e
    }

    #[test]
    fn json_unicode_full_handles_non_bmp_via_surrogate_pair() {
        // U+1F600 GRINNING FACE → 😀
        let out = json_unicode_full("😀");
        assert_eq!(out, "\\uD83D\\uDE00");
    }

    #[test]
    fn json_unicode_mixed_case_alternates_forms() {
        let out = json_unicode_mixed_case("abcd");
        // 4 chars → 4 different forms.
        assert!(out.contains("\\u0061")); // i=0 lowercase
        assert!(out.contains("\\U0062")); // i=1 uppercase U
        assert!(out.contains("\\u0063")); // i=2 lower u, upper hex
        assert!(out.contains("\\U0064")); // i=3 upper U, lower hex
    }

    #[test]
    fn json_unicode_alnum_leaves_punctuation() {
        // SQLi shape: keywords escaped, structural delimiters bare.
        let out = json_unicode_alnum("' OR 1=1--");
        assert_eq!(out, "' \\u004F\\u0052 \\u0031=\\u0031--");
        let out2 = json_unicode_alnum("AB CD");
        assert_eq!(out2, "\\u0041\\u0042 \\u0043\\u0044");
    }

    #[test]
    fn json_unicode_alnum_idempotent_skip_pass() {
        // Second pass MUST be a no-op, already-escaped \uXXXX
        // sequences are detected and passed through.
        let once = json_unicode_alnum("UNION SELECT");
        let twice = json_unicode_alnum(&once);
        assert_eq!(once, twice, "tamper must stabilize");
    }

    #[test]
    fn json_unicode_alnum_preserves_quote_unencoded() {
        // ' is U+0027: NOT alphanumeric, so must stay literal.
        let out = json_unicode_alnum("'");
        assert_eq!(out, "'");
    }

    #[test]
    fn json_unicode_alnum_xss_keyword_split() {
        // <script>alert: `<`, `>`, `(`, `)` stay bare; letters/digits escape.
        let out = json_unicode_alnum("<script>alert(1)</script>");
        assert!(!out.contains("script"));
        assert!(!out.contains("alert"));
        assert!(out.contains('<'));
        assert!(out.contains('>'));
        assert!(out.contains('('));
    }

    #[test]
    fn json_unicode_alnum_empty_input() {
        assert_eq!(json_unicode_alnum(""), "");
    }

    #[test]
    fn sql_adjacent_string_concat_basic() {
        // 'admin' (len 5) → 5 single-char adjacent literals.
        assert_eq!(sql_adjacent_string_concat("'admin'"), "'a' 'd' 'm' 'i' 'n'");
    }

    #[test]
    fn sql_adjacent_string_concat_short_literal_unchanged() {
        // Length-1 literals must pass through (already minimum).
        assert_eq!(sql_adjacent_string_concat("'a'"), "'a'");
        assert_eq!(sql_adjacent_string_concat("''"), "''");
    }

    #[test]
    fn sql_adjacent_string_concat_idempotent() {
        // Well-formed (balanced quotes) payload, the literals 'admin'
        // and 'root' each shatter into single-char adjacent literals.
        let once = sql_adjacent_string_concat("WHERE x='admin' OR y='root'");
        let twice = sql_adjacent_string_concat(&once);
        assert_eq!(once, twice, "tamper must stabilize on second pass");
        assert!(once.contains("'a' 'd' 'm' 'i' 'n'"));
        assert!(once.contains("'r' 'o' 'o' 't'"));
    }

    #[test]
    fn sql_adjacent_string_concat_preserves_outside_literal() {
        // No quoted literal in payload (must be a no-op).
        assert_eq!(sql_adjacent_string_concat("1 OR 1=1--"), "1 OR 1=1--");
    }

    #[test]
    fn sql_adjacent_string_concat_handles_escaped_quote() {
        // SQL '' escape inside a literal: the position holding `'` is
        // emitted as the four-quote form `''''`: opening, escaped pair,
        // closing (which parses as a length-1 literal containing `'`).
        // The database reassembles "O" + "'" + "B" + "r" + "i" + "e" + "n".
        let out = sql_adjacent_string_concat("'O''Brien'");
        assert_eq!(out, "'O' '''' 'B' 'r' 'i' 'e' 'n'");
    }

    #[test]
    fn sql_adjacent_string_concat_escaped_quote_idempotent() {
        // Second pass: the `''''` token is a length-1 literal containing
        // `'` (below split threshold). It must pass through unchanged
        // (via the length-1 branch with the escaped-quote sub-case).
        let once = sql_adjacent_string_concat("'O''Brien'");
        let twice = sql_adjacent_string_concat(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn sql_adjacent_string_concat_single_quote_literal_emits_four_quotes() {
        // A literal of length 1 containing only `'` (source: `''''`)
        // must output the same `''''` (passthrough form).
        let out = sql_adjacent_string_concat("''''");
        assert_eq!(out, "''''");
    }

    #[test]
    fn sql_adjacent_string_concat_its_a_test_shatters_correctly() {
        // The dogfood agent's B5 reproducer.
        let out = sql_adjacent_string_concat("'it''s a test'");
        // Literal content: "it's a test" (11 chars). Each char emits
        // its own single-char literal; the `'` becomes `''''`.
        assert_eq!(out, "'i' 't' '''' 's' ' ' 'a' ' ' 't' 'e' 's' 't'");
    }

    #[test]
    fn sql_adjacent_string_concat_unterminated_quote_passthrough() {
        // Defensive: an unclosed quote must not crash and must not
        // wrap-then-mistakenly-close. Output should preserve the bytes
        // verbatim except for the unmatched-quote tail.
        let out = sql_adjacent_string_concat("'unclosed");
        assert_eq!(out, "'unclosed");
    }

    #[test]
    fn sql_adjacent_string_concat_path_literal_split() {
        // /etc/passwd path literal is a high-fidelity LFI fingerprint.
        // 11 chars → 11 single-char literals; the byte sequence
        // `/etc/passwd` no longer appears contiguously.
        let out = sql_adjacent_string_concat("'/etc/passwd'");
        assert_eq!(out, "'/' 'e' 't' 'c' '/' 'p' 'a' 's' 's' 'w' 'd'");
        assert!(!out.contains("/etc/passwd"));
    }

    #[test]
    fn json_unicode_alnum_unicode_input_passes_through() {
        // Non-ASCII chars (日本語) are NOT ascii_alphanumeric (left bare).
        // This keeps the function focused on the keyword-bypass mission.
        let out = json_unicode_alnum("日本");
        assert_eq!(out, "日本");
    }

    #[test]
    fn unicode_encode_special_chars() {
        let encoded = unicode_encode("' OR 1=1--");
        assert!(encoded.contains("\\u0027")); // '
        assert!(encoded.contains("\\u003D")); // =
    }

    #[test]
    fn unicode_encode_unicode() {
        let encoded = unicode_encode("日本語");
        assert_eq!(encoded, "\\u65E5\\u672C\\u8A9E");
    }

    #[test]
    fn iis_unicode_encode_basic() {
        assert_eq!(iis_unicode_encode("A"), "%u0041");
        assert_eq!(iis_unicode_encode("AB"), "%u0041%u0042");
    }

    #[test]
    fn iis_unicode_encode_bmp_only_for_3byte_utf8() {
        // U+65E5 (日) is BMP, emits as a single %uXXXX, no
        // surrogate. This is the existing happy path.
        assert_eq!(iis_unicode_encode("日"), "%u65E5");
    }

    #[test]
    fn iis_unicode_encode_non_bmp_emits_surrogate_pair() {
        // U+1F600 (😀) is supplementary plane. Pre-fix this emitted
        // `%u1F600` (5 hex digits, invalid IIS %u, silently
        // unencodable, bypass-rate killer). Post-fix it MUST emit a
        // UTF-16 surrogate pair `%uD83D%uDE00`.
        assert_eq!(iis_unicode_encode("😀"), "%uD83D%uDE00");
    }

    #[test]
    fn iis_unicode_encode_mixed_bmp_and_non_bmp() {
        // Adversarial: a mix of plain ASCII + BMP + supplementary
        // must produce exactly one %uXXXX or %uXXXX%uXXXX per char.
        // No 5-digit %u sequences anywhere (pin the regression).
        let out = iis_unicode_encode("A日😀");
        assert_eq!(out, "%u0041%u65E5%uD83D%uDE00");
        // Anti-regression: scan for any 5-hex-digit %u sequence.
        // The fix would silently regress if someone widened the
        // format string to %u{:05X} thinking it "supports" non-BMP.
        for hex_run in out.split("%u").skip(1) {
            let hex_part: String = hex_run
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            assert!(
                hex_part.len() == 4,
                "every %u sequence must be exactly 4 hex digits (IIS spec); \
                 got {hex_part:?} in output {out:?}"
            );
        }
    }

    #[test]
    fn json_encode_basic() {
        // F67: encoder produces escaped CONTENT only (no
        // surrounding double-quotes). Callers inject into an
        // existing JSON string field; wrapping our own quotes
        // would break the host JSON document.
        assert_eq!(json_string_encode("A"), "A");
        assert_eq!(json_string_encode("A\\B"), "A\\\\B");
        assert_eq!(json_string_encode("A\"B"), "A\\\"B");
        assert_eq!(json_string_encode("A\nB"), "A\\nB");
    }

    #[test]
    fn json_encode_control_chars() {
        assert_eq!(json_string_encode("\x01"), "\\u0001");
    }

    #[test]
    fn html_entity_encode_basic() {
        assert_eq!(html_entity_encode("A"), "&#x41;");
        assert_eq!(html_entity_encode("AB"), "&#x41;&#x42;");
    }

    #[test]
    fn html_entity_encode_special_chars() {
        let encoded = html_entity_encode("<script>");
        assert_eq!(encoded, "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;");
    }

    #[test]
    fn html_entity_decimal_encode_basic() {
        assert_eq!(html_entity_decimal_encode("A"), "&#65;");
        assert_eq!(html_entity_decimal_encode("<"), "&#60;");
    }

    #[test]
    fn html_entity_encode_empty() {
        assert_eq!(html_entity_encode(""), "");
    }

    // ── html_entity_zero_pad tests (CVE-2025-27110) ────────────────────

    #[test]
    fn html_entity_zero_pad_hex_width_4_matches_cve_advisory_example() {
        // Pinned to the exact form the CVE-2025-27110 advisory uses
        // as its smoking gun: `&#x003C;` for `<`. If this drifts
        // (someone "tidies" the formatter), every libmodsecurity
        // 3.0.13 bypass stops working.
        assert_eq!(html_entity_zero_pad("<", 4, true), "&#x003C;");
    }

    #[test]
    fn html_entity_zero_pad_decimal_width_4_matches_cve_advisory_example() {
        // The decimal counterpart from the same advisory: `&#0060;`
        // for `<`. Same bypass mechanism, different radix.
        assert_eq!(html_entity_zero_pad("<", 4, false), "&#0060;");
    }

    #[test]
    fn html_entity_zero_pad_width_1_is_unpadded() {
        // width=1 means "pad to at least 1" which for any code point
        // > 0 is a no-op. Anti-rig: the function must not insert
        // leading zeros at width=1, otherwise it becomes equivalent
        // to width=2 and the "no-padding" form is unreachable.
        assert_eq!(html_entity_zero_pad("A", 1, true), "&#x41;");
        assert_eq!(html_entity_zero_pad("A", 1, false), "&#65;");
    }

    #[test]
    fn html_entity_zero_pad_width_0_is_coerced_to_1() {
        // Boundary: pad=0 is a contract-violating input. We coerce
        // to 1 (the "no-padding" form) rather than emit `&#x;` (a
        // malformed entity). Catches a future refactor that uses
        // `pad.min(16)` only and forgets the `.max(1)` lower bound.
        assert_eq!(html_entity_zero_pad("A", 0, true), "&#x41;");
    }

    #[test]
    fn html_entity_zero_pad_width_above_cap_is_clamped() {
        // Boundary: pad=100 is an anti-DoS concern. We clamp at 16.
        // The result for 'A' (0x41 = 2 hex digits) padded to 16 is
        // `&#x0000000000000041;`: 14 leading zeros. Pin the exact
        // byte sequence so a future change to the cap is visible
        // (and intentional).
        assert_eq!(html_entity_zero_pad("A", 100, true), "&#x0000000000000041;");
    }

    #[test]
    fn html_entity_zero_pad_empty_input_produces_empty_output() {
        // Anti-rig: empty input must produce empty output (the
        // identity element of concatenation). A naive `for ch in
        // ""` does the right thing today; this test pins that the
        // result is exactly "" rather than e.g. "&#x;" from a
        // single dangling write.
        assert_eq!(html_entity_zero_pad("", 4, true), "");
        assert_eq!(html_entity_zero_pad("", 4, false), "");
    }

    #[test]
    fn html_entity_zero_pad_xss_payload_round_trip_browser_equivalent() {
        // CVE-2025-27110 exploit-path smoke: a `<script>` payload
        // routed through width-4 hex must produce the exact byte
        // sequence that the CVE write-up shows as bypassing
        // libmodsecurity 3.0.13. If this changes, we're not
        // shipping the documented bypass anymore.
        let out = html_entity_zero_pad("<script>", 4, true);
        assert_eq!(
            out,
            "&#x003C;&#x0073;&#x0063;&#x0072;&#x0069;&#x0070;&#x0074;&#x003E;"
        );
    }

    // ── html_entity_variants tests ─────────────────────────────────────

    #[test]
    fn html_entity_variants_cycles_four_forms() {
        // 'A'=0x41=65, verify each of the four rotation slots
        let encoded = html_entity_variants("AAAA");
        assert_eq!(encoded, "&#x41;&#X41;&#65;&#00065;");
    }

    #[test]
    fn html_entity_variants_continues_rotation() {
        // 'A'=65, fifth char returns to slot 0 (lowercase-x hex)
        let encoded = html_entity_variants("AAAAA");
        assert_eq!(encoded, "&#x41;&#X41;&#65;&#00065;&#x41;");
    }

    #[test]
    fn html_entity_variants_empty() {
        assert_eq!(html_entity_variants(""), "");
    }

    #[test]
    fn html_entity_variants_xss_payload() {
        // '<' = 0x3C = 60, 's'=0x73=115, '>'=0x3E=62
        // First three chars use slots 0, 1, 2:
        let encoded = html_entity_variants("<s>");
        assert_eq!(encoded, "&#x3c;&#X73;&#62;");
    }

    #[test]
    fn html_entity_variants_unicode_codepoint() {
        // emoji U+1F600 ('😀'), codepoint 128512, exercises higher-bit chars
        let encoded = html_entity_variants("\u{1F600}");
        assert_eq!(encoded, "&#x1f600;");
    }

    #[test]
    fn html_entity_variants_distinct_from_canonical() {
        // 4+ char payload MUST differ from canonical html_entity_encode
        // (canonical is always lowercase-x hex with semicolon)
        let canon = html_entity_encode("ABCD");
        let var = html_entity_variants("ABCD");
        assert_ne!(canon, var);
    }

    #[test]
    fn html_entity_variants_deterministic() {
        // Same input → same output (no randomness; rotation is by index)
        assert_eq!(
            html_entity_variants("hello world"),
            html_entity_variants("hello world")
        );
    }

    // ── math_bold_encode tests ─────────────────────────────────────────

    #[test]
    fn math_bold_encode_uppercase() {
        assert_eq!(math_bold_encode("A"), "\u{1D400}"); // 𝐀
        assert_eq!(math_bold_encode("Z"), "\u{1D419}"); // 𝐙
    }

    #[test]
    fn math_bold_encode_lowercase() {
        assert_eq!(math_bold_encode("a"), "\u{1D41A}"); // 𝐚
        assert_eq!(math_bold_encode("z"), "\u{1D433}"); // 𝐳
    }

    #[test]
    fn math_bold_encode_digits() {
        assert_eq!(math_bold_encode("0"), "\u{1D7CE}"); // 𝟎
        assert_eq!(math_bold_encode("9"), "\u{1D7D7}"); // 𝟗
    }

    #[test]
    fn math_bold_encode_sql_keyword() {
        // SELECT → 𝐒𝐄𝐋𝐄𝐂𝐓
        let encoded = math_bold_encode("SELECT");
        assert_eq!(encoded.chars().count(), 6);
        for ch in encoded.chars() {
            assert!(
                (0x1D400..=0x1D419).contains(&(ch as u32)),
                "expected math bold capital, got U+{:04X}",
                ch as u32
            );
        }
    }

    #[test]
    fn math_bold_encode_preserves_punctuation() {
        // ' OR 1=1--, only letters/digits transform; punctuation stays
        let encoded = math_bold_encode("' OR 1=1--");
        // ' space = = - - all unchanged
        assert!(encoded.starts_with('\''));
        assert!(encoded.contains('='));
        assert!(encoded.ends_with("--"));
    }

    #[test]
    fn math_bold_encode_mixed_alphanumeric() {
        let encoded = math_bold_encode("Aa0");
        // A → 𝐀, a → 𝐚, 0 → 𝟎
        let chars: Vec<char> = encoded.chars().collect();
        assert_eq!(chars.len(), 3);
        assert_eq!(chars[0] as u32, 0x1D400);
        assert_eq!(chars[1] as u32, 0x1D41A);
        assert_eq!(chars[2] as u32, 0x1D7CE);
    }

    #[test]
    fn math_bold_encode_distinct_from_fullwidth() {
        // Fullwidth uses U+FF00 block; math bold uses U+1D400 block
        // The same input must produce different bytes (proving they're not equivalent).
        assert_ne!(math_bold_encode("SELECT"), fullwidth_encode("SELECT"));
    }

    #[test]
    fn math_bold_encode_empty() {
        assert_eq!(math_bold_encode(""), "");
    }

    // ── math_italic / script / fraktur / double_struck tests ────────────

    #[test]
    fn math_italic_encode_uppercase() {
        assert_eq!(math_italic_encode("A"), "\u{1D434}"); // 𝐴
        assert_eq!(math_italic_encode("Z"), "\u{1D44D}"); // 𝑍
    }

    #[test]
    fn math_italic_encode_handles_h_hole() {
        // U+1D455 is reserved (the hole); we substitute U+210E.
        assert_eq!(math_italic_encode("h"), "\u{210E}");
    }

    #[test]
    fn math_italic_encode_is_distinct_from_bold() {
        assert_ne!(math_italic_encode("SELECT"), math_bold_encode("SELECT"));
    }

    #[test]
    fn math_script_encode_fills_all_holes() {
        // Every uppercase letter must map to SOMETHING (no panic, no
        // fall-through to ASCII).
        for c in 'A'..='Z' {
            let s: String = c.to_string();
            let enc = math_script_encode(&s);
            assert!(
                enc != s,
                "math_script_encode left {c} unchanged, hole not filled"
            );
        }
    }

    #[test]
    fn math_fraktur_encode_fills_chizr_holes() {
        for c in &['C', 'H', 'I', 'R', 'Z'] {
            let s: String = c.to_string();
            assert!(
                math_fraktur_encode(&s) != s,
                "math_fraktur_encode left {c} unchanged"
            );
        }
    }

    #[test]
    fn math_double_struck_encode_digits_distinct_from_bold() {
        // double-struck 0 = U+1D7D8 ≠ bold 0 = U+1D7CE
        assert_ne!(math_double_struck_encode("0"), math_bold_encode("0"));
    }

    #[test]
    fn math_double_struck_encode_fills_letter_holes() {
        for c in &['C', 'H', 'N', 'P', 'Q', 'R', 'Z'] {
            let s: String = c.to_string();
            assert!(math_double_struck_encode(&s) != s);
        }
    }

    #[test]
    fn letterlike_encode_select_payload_uses_letterlike_block() {
        let encoded = letterlike_encode("SELECT");
        // L → U+2112 SCRIPT CAPITAL L (the headline letterlike sub).
        assert!(encoded.contains('\u{2112}'));
        // S has no letterlike-block equivalent; falls back to circled
        // Latin (U+24CE).
        assert!(
            encoded
                .chars()
                .any(|c| c as u32 >= 0x24B6 && c as u32 <= 0x24E9)
        );
    }

    #[test]
    fn letterlike_encode_preserves_non_letters() {
        assert_eq!(letterlike_encode(" ' = "), " ' = ");
    }

    #[test]
    fn all_new_encoders_preserve_pure_punctuation() {
        // Pure punctuation, no letters, no digits, must round-trip
        // through every encoder unchanged. (Digits ARE transformed
        // by math_double_struck_encode, so we exclude them.)
        for f in [
            math_italic_encode,
            math_script_encode,
            math_fraktur_encode,
            math_double_struck_encode,
            letterlike_encode,
        ] {
            assert_eq!(f("' = -- /* */ ;"), "' = -- /* */ ;");
        }
    }

    #[test]
    fn all_new_encoders_distinct_from_each_other() {
        let s = "SELECT";
        let bold = math_bold_encode(s);
        let italic = math_italic_encode(s);
        let script = math_script_encode(s);
        let fraktur = math_fraktur_encode(s);
        let dstruck = math_double_struck_encode(s);
        let letter = letterlike_encode(s);
        let outputs = [bold, italic, script, fraktur, dstruck, letter];
        let set: std::collections::BTreeSet<&String> = outputs.iter().collect();
        assert_eq!(
            set.len(),
            outputs.len(),
            "two encoders produced identical output"
        );
    }

    // ── zero-width + combining-mark injection tests ────────────────────

    #[test]
    fn zero_width_inject_adds_chars_between_letters() {
        let out = zero_width_inject("script", '\u{200B}');
        assert!(out.contains("scr\u{200B}ipt") || out.contains("s\u{200B}c"));
        // Length grows by N-1 codepoints (one between each pair).
        assert_eq!(out.chars().count(), 6 + 5);
    }

    #[test]
    fn zero_width_inject_preserves_non_alnum() {
        // Insert only between alnum chars, not punctuation.
        let out = zero_width_inject("' OR '1'='1", '\u{200C}');
        // The lone `'` chars don't trigger insertion before them.
        assert!(!out.starts_with('\u{200C}'));
    }

    #[test]
    fn zero_width_defaults_count_correct() {
        // Five-element cycle so rotation covers ZWSP/ZWNJ/ZWJ/BOM/CGJ.
        assert_eq!(ZERO_WIDTH_DEFAULTS.len(), 5);
    }

    #[test]
    fn combining_mark_inject_only_after_letters() {
        let out = combining_mark_inject("a1b2", '\u{0308}');
        // 'a' + ̈ + '1' + 'b' + ̈ + '2' (digits don't get marks).
        assert_eq!(out, "a\u{0308}1b\u{0308}2");
    }

    // ── script_homoglyph_encode tests ──────────────────────────────────

    #[test]
    fn script_homoglyph_select_uses_cyrillic_letters() {
        let out = script_homoglyph_encode("SELECT");
        // S → Cyrillic (no Cyrillic S, falls through to itself OR
        // gets mapped to one of the upper substitutions). E → U+0415.
        assert!(out.contains('\u{0415}'));
        // T → U+0422
        assert!(out.contains('\u{0422}'));
        // Output is byte-distinct from input.
        assert_ne!(out, "SELECT");
    }

    #[test]
    fn script_homoglyph_preserves_punctuation() {
        assert_eq!(script_homoglyph_encode("' = -- ;"), "' = -- ;");
    }

    // ── turkish_i + sharp_s tests ──────────────────────────────────────

    #[test]
    fn turkish_i_encode_replaces_only_i() {
        assert_eq!(turkish_i_encode("script"), "scr\u{0131}pt");
        assert_eq!(turkish_i_encode("INSERT"), "\u{0130}NSERT");
        // 'a', 'b' etc. unchanged.
        assert_eq!(turkish_i_encode("abcdefg"), "abcdefg");
    }

    #[test]
    fn sharp_s_encode_replaces_only_s() {
        assert_eq!(sharp_s_encode("select"), "\u{00DF}elect");
        assert_eq!(sharp_s_encode("SELECT"), "\u{00DF}ELECT");
    }

    // ── json_key_unicode_escape tests ──────────────────────────────────

    #[test]
    fn json_key_escape_full_id_payload() {
        let s = json_key_unicode_escape("id", "1 OR 1=1--");
        // Each char of "id" becomes \uXXXX.
        assert!(s.contains("\\u0069")); // i
        assert!(s.contains("\\u0064")); // d
        // Value JSON-encoded.
        assert!(s.contains("1 OR 1=1--"));
    }

    #[test]
    fn json_key_escape_round_trips_through_serde() {
        let s = json_key_unicode_escape("admin", "true");
        let parsed: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        // After parsing, the key decodes back to "admin".
        assert!(parsed.get("admin").is_some(), "decoded key missing: {s}");
    }

    #[test]
    fn json_key_escape_preserves_value_quotes() {
        let s = json_key_unicode_escape("k", "v\"q");
        // serde_json escapes the inner quote.
        assert!(s.contains("v\\\"q"));
    }

    // ── overlong_utf8_path tests ───────────────────────────────────────

    #[test]
    fn overlong_utf8_2byte_dot_slash_replaces() {
        assert_eq!(
            overlong_utf8_path("../etc/passwd", 2),
            "%c0%ae%c0%ae%c0%afetc%c0%afpasswd"
        );
    }

    #[test]
    fn overlong_utf8_3byte_dot_slash() {
        let out = overlong_utf8_path("..", 3);
        assert_eq!(out, "%e0%80%ae%e0%80%ae");
    }

    #[test]
    fn overlong_utf8_4byte_default() {
        let out = overlong_utf8_path(".", 4);
        assert_eq!(out, "%f0%80%80%ae");
    }

    #[test]
    fn overlong_utf8_preserves_non_traversal_chars() {
        let out = overlong_utf8_path("../etc/passwd", 2);
        assert!(out.contains("etc"));
        assert!(out.contains("passwd"));
    }

    #[test]
    fn overlong_utf8_handles_backslash() {
        assert_eq!(
            overlong_utf8_path("..\\windows", 2),
            "%c0%ae%c0%ae%c0%5cwindows"
        );
    }

    // ── bidi_inject tests ──────────────────────────────────────────────

    #[test]
    fn bidi_inject_wraps_with_rlo_and_pdf() {
        let out = bidi_inject("tceleS");
        assert!(out.starts_with('\u{202E}'));
        assert!(out.ends_with('\u{202C}'));
        // 1 RLO + 6 letters + 1 PDF.
        assert_eq!(out.chars().count(), 8);
    }

    // ── sql_concat_split tests ─────────────────────────────────────────

    #[test]
    fn sql_concat_split_admin() {
        assert_eq!(sql_concat_split("'admin'"), "CONCAT('a','d','m','i','n')");
    }

    #[test]
    fn sql_concat_split_password() {
        assert_eq!(
            sql_concat_split("'password'"),
            "CONCAT('p','a','s','s','w','o','r','d')"
        );
    }

    #[test]
    fn sql_concat_split_in_clause() {
        assert_eq!(
            sql_concat_split("WHERE u='admin'"),
            "WHERE u=CONCAT('a','d','m','i','n')"
        );
    }

    #[test]
    fn sql_concat_split_no_quotes_passthrough() {
        // No single quotes → input unchanged
        assert_eq!(sql_concat_split("SELECT 1"), "SELECT 1");
    }

    #[test]
    fn sql_concat_split_multiple_literals() {
        // Two separate strings get independent CONCAT calls
        assert_eq!(sql_concat_split("'a' OR 'b'"), "CONCAT('a') OR CONCAT('b')");
    }

    #[test]
    fn sql_concat_split_empty_literal() {
        assert_eq!(sql_concat_split("''"), "CONCAT('')");
    }

    #[test]
    fn sql_concat_split_unbalanced_quote_passthrough() {
        // Lone opening quote with no closer → output preserves it
        assert_eq!(sql_concat_split("'unclosed"), "'unclosed");
    }

    #[test]
    fn sql_concat_split_preserves_non_quote_chars() {
        // SQL keywords, operators, whitespace all unchanged
        let payload = "1=1; SELECT 'x', 'y' FROM dual";
        let out = sql_concat_split(payload);
        assert!(out.contains("SELECT"));
        assert!(out.contains("FROM dual"));
        assert!(out.contains("CONCAT('x')"));
        assert!(out.contains("CONCAT('y')"));
    }

    #[test]
    fn sql_concat_split_real_injection_payload() {
        // Classic UNION SELECT extraction
        let payload = "' UNION SELECT 'admin','password' FROM users--";
        let out = sql_concat_split(payload);
        // Outer ' is unbalanced; collects up to ' before admin then closes there.
        // The first CONCAT contains the OR/UNION/SELECT keywords as char args
        // not a useful execution path, but it demonstrates the tamper is
        // applied uniformly. The point is: every single-quoted region becomes
        // CONCAT, so a downstream layer can compose this with other tampers.
        assert!(out.contains("CONCAT("));
        // Real payloads that benefit start the quote OPEN and close it
        // before the SQL keywords, e.g. "1' UNION SELECT 'admin'--" where
        // the embedded 'admin' is the bypass target.
    }

    // ── sql_char_decompose tests ───────────────────────────────────────

    #[test]
    fn sql_char_decompose_admin() {
        // 'a'=97 'd'=100 'm'=109 'i'=105 'n'=110
        assert_eq!(sql_char_decompose("'admin'"), "CHAR(97,100,109,105,110)");
    }

    #[test]
    fn sql_char_decompose_password() {
        assert_eq!(
            sql_char_decompose("'password'"),
            "CHAR(112,97,115,115,119,111,114,100)"
        );
    }

    #[test]
    fn sql_char_decompose_path_literal() {
        // '/etc/passwd', every byte represented numerically
        // '/'=47 'e'=101 't'=116 'c'=99 '/'=47 'p'=112 'a'=97 's'=115 's'=115 'w'=119 'd'=100
        assert_eq!(
            sql_char_decompose("'/etc/passwd'"),
            "CHAR(47,101,116,99,47,112,97,115,115,119,100)"
        );
    }

    #[test]
    fn sql_char_decompose_no_quotes_passthrough() {
        assert_eq!(sql_char_decompose("SELECT 1"), "SELECT 1");
    }

    #[test]
    fn sql_char_decompose_empty_literal_preserves_empty_string() {
        // F60 regression: pre-fix `''` produced `CHAR()` which is
        // NULL in MySQL, breaking `pass='' OR 1=1` auth bypass
        // (`= NULL` is never TRUE). Post-fix the empty literal
        // round-trips unchanged.
        assert_eq!(sql_char_decompose("''"), "''");
        // Embedded in a longer payload too.
        assert_eq!(
            sql_char_decompose("WHERE pass='' OR 1=1"),
            "WHERE pass='' OR 1=1"
        );
    }

    // sql_char_decompose_empty_literal_preserves_empty_string above
    // supersedes the pre-fix test that asserted CHAR(), kept as a
    // marker rather than re-asserting the buggy old contract.

    #[test]
    fn sql_char_decompose_unbalanced_passthrough() {
        assert_eq!(sql_char_decompose("'unclosed"), "'unclosed");
    }

    #[test]
    fn sql_char_decompose_multiple_literals() {
        // 'a'=97  'b'=98
        assert_eq!(sql_char_decompose("'a' OR 'b'"), "CHAR(97) OR CHAR(98)");
    }

    #[test]
    fn sql_char_decompose_distinct_from_concat_split() {
        // CONCAT uses single-char strings; CHAR uses ints. Outputs differ.
        assert_ne!(sql_char_decompose("'admin'"), sql_concat_split("'admin'"));
    }

    #[test]
    fn sql_char_decompose_real_injection() {
        let payload = "1 OR username='admin'--";
        let out = sql_char_decompose(payload);
        assert_eq!(out, "1 OR username=CHAR(97,100,109,105,110)--");
    }

    // ── pg_chr_decompose tests ─────────────────────────────────────────

    #[test]
    fn pg_chr_decompose_admin() {
        assert_eq!(
            pg_chr_decompose("'admin'"),
            "(CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110))"
        );
    }

    #[test]
    fn pg_chr_decompose_empty_literal() {
        assert_eq!(pg_chr_decompose("''"), "('')");
    }

    #[test]
    fn pg_chr_decompose_in_where_clause() {
        assert_eq!(pg_chr_decompose("WHERE u='a'"), "WHERE u=(CHR(97))");
    }

    #[test]
    fn pg_chr_decompose_distinct_from_char_decompose() {
        // CHR() is unary + pipe-concat; CHAR() is variadic. Different shapes.
        assert_ne!(pg_chr_decompose("'admin'"), sql_char_decompose("'admin'"));
    }

    #[test]
    fn pg_chr_decompose_unbalanced_passthrough() {
        assert_eq!(pg_chr_decompose("'unclosed"), "'unclosed");
    }

    #[test]
    fn sql_concat_split_isolated_literal_keeps_other_tokens() {
        // From a real payload: id=1 AND username = 'admin' AND status = 1
        let payload = "id=1 AND username='admin' AND status=1";
        let out = sql_concat_split(payload);
        assert_eq!(
            out,
            "id=1 AND username=CONCAT('a','d','m','i','n') AND status=1"
        );
    }

    #[test]
    fn unicode_encode_empty() {
        assert_eq!(unicode_encode(""), "");
    }

    // ── Fullwidth encoding tests ───────────────────────────────────────

    #[test]
    fn fullwidth_encode_sql_keywords() {
        let encoded = fullwidth_encode("SELECT");
        assert_eq!(encoded, "ＳＥＬＥＣＴ");
        // Every ASCII letter should be in fullwidth range
        for ch in encoded.chars() {
            assert!(
                ch as u32 >= 0xFF01,
                "expected fullwidth char, got {ch} (U+{:04X})",
                ch as u32
            );
        }
    }

    #[test]
    fn fullwidth_encode_spaces() {
        let encoded = fullwidth_encode("A B");
        assert!(
            encoded.contains('\u{3000}'),
            "space should become ideographic space"
        );
    }

    #[test]
    fn fullwidth_encode_preserves_non_ascii() {
        let encoded = fullwidth_encode("日本語");
        assert_eq!(encoded, "日本語", "non-ASCII should pass through unchanged");
    }

    #[test]
    fn fullwidth_encode_operators() {
        let encoded = fullwidth_encode("1=1");
        assert_eq!(encoded, "１＝１");
    }

    #[test]
    fn fullwidth_encode_sqli_payload() {
        let encoded = fullwidth_encode("' OR 1=1--");
        // Should contain fullwidth equivalents, not ASCII
        assert!(!encoded.contains("OR"), "should not contain ASCII 'OR'");
        assert!(encoded.contains("ＯＲ"), "should contain fullwidth 'ＯＲ'");
    }

    #[test]
    fn fullwidth_encode_empty() {
        assert_eq!(fullwidth_encode(""), "");
    }

    // ── Homoglyph encoding tests ───────────────────────────────────────

    #[test]
    fn homoglyph_preserves_sql_string_delimiters() {
        // Regression for F56: pre-fix `'` was mapped to U+2019,
        // destroying the SQL context-break the payload depends on.
        // U+2019 is not a SQL string delimiter, the host query's
        // string literal never closes and the injection becomes
        // inert. Verify the delimiters survive verbatim.
        let encoded = homoglyph_encode("' OR '1'='1");
        // Single + double quotes pass through unchanged.
        assert!(
            encoded.contains('\''),
            "ASCII single quote MUST be preserved for SQL: {encoded}"
        );
        assert!(
            !encoded.contains('\u{2019}'),
            "U+2019 right-single-quote must NOT appear: {encoded}"
        );
        // But the equals sign (non-delimiter) still gets mutated
        // proves the function isn't a complete no-op.
        assert!(
            encoded.contains('\u{FF1D}'),
            "equals sign should still mutate to fullwidth: {encoded}"
        );
    }

    #[test]
    fn homoglyph_preserves_ascii_double_quote() {
        let encoded = homoglyph_encode(r#""admin" OR "1"="1""#);
        assert!(
            encoded.contains('"'),
            "ASCII double quote MUST be preserved: {encoded}"
        );
        assert!(
            !encoded.contains('\u{201D}'),
            "U+201D right-double-quote must NOT appear: {encoded}"
        );
    }

    #[test]
    fn homoglyph_replaces_angle_brackets() {
        let encoded = homoglyph_encode("<script>");
        assert!(!encoded.contains('<'), "ASCII < should be replaced");
        assert!(!encoded.contains('>'), "ASCII > should be replaced");
        assert!(encoded.contains('\u{FF1C}'), "should contain fullwidth <");
        assert!(encoded.contains('\u{FF1E}'), "should contain fullwidth >");
    }

    #[test]
    fn homoglyph_replaces_equals() {
        let encoded = homoglyph_encode("1=1");
        assert!(!encoded.contains('='), "ASCII = should be replaced");
        assert!(encoded.contains('\u{FF1D}'), "should contain fullwidth =");
    }

    #[test]
    fn homoglyph_preserves_letters() {
        let encoded = homoglyph_encode("SELECT");
        assert_eq!(encoded, "SELECT", "letters should be preserved");
    }

    #[test]
    fn homoglyph_encode_empty() {
        assert_eq!(homoglyph_encode(""), "");
    }

    #[test]
    fn homoglyph_replaces_parens() {
        let encoded = homoglyph_encode("fn()");
        assert!(encoded.contains('\u{FF08}'), "should contain fullwidth (");
        assert!(encoded.contains('\u{FF09}'), "should contain fullwidth )");
    }

    // ── Bug 2 regression: iis_unicode_encode non-BMP adversarial twins ──
    //
    // PRE-FIX BUG: the loop body cast `ch as u32` into a %uXXXX format
    // without checking whether `code > 0xFFFF`. For supplementary-plane
    // characters (U+10000 and above) this produced a 5-digit hex sequence
    // like `%u1F600`, which IIS's %u decoder rejects (its format is
    // strictly 4 hex digits). The bypass looked encoded but was actually
    // undecodable on any real IIS target (a silent bypass-rate killer).
    // Fixed: emit a UTF-16 surrogate pair `%uHIGH%uLOW` for non-BMP chars.

    #[test]
    fn iis_unicode_encode_lowest_non_bmp_u10000() {
        // U+10000 is the very first supplementary-plane codepoint (LINEAR B
        // SYLLABLE B008 A). Pre-fix: emitted `%u10000` (5 hex digits
        // invalid IIS format). Post-fix: must emit the surrogate pair
        // %uD800%uDC00 (high=0xD800, low=0xDC00 for U+10000).
        let ch = '\u{10000}'; // U+10000
        let encoded = iis_unicode_encode(&ch.to_string());
        assert_eq!(
            encoded, "%uD800%uDC00",
            "U+10000 (lowest non-BMP) must encode as surrogate pair %uD800%uDC00, \
             not the invalid %u10000"
        );
        // Anti-regression: no 5-digit %u sequence.
        for hex_run in encoded.split("%u").skip(1) {
            let hex_part: String = hex_run
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            assert_eq!(
                hex_part.len(),
                4,
                "every %u sequence must be exactly 4 hex digits (IIS spec); \
                 got {hex_part:?} in {encoded:?}"
            );
        }
    }

    #[test]
    fn iis_unicode_encode_high_cjk_supplement_u20000() {
        // U+20000 is the first codepoint in CJK Unified Ideographs Extension
        // B (𠀀). Pre-fix: emitted `%u20000` (5 hex digits. IIS rejects).
        // Post-fix: surrogate pair calculation:
        //   surrogate_base = 0x20000 - 0x10000 = 0x10000
        //   high = 0xD800 + (0x10000 >> 10) = 0xD800 + 0x40 = 0xD840
        //   low  = 0xDC00 + (0x10000 & 0x3FF) = 0xDC00 + 0x00 = 0xDC00
        let ch = '\u{20000}';
        let encoded = iis_unicode_encode(&ch.to_string());
        assert_eq!(
            encoded, "%uD840%uDC00",
            "U+20000 (CJK Supplement) must encode as %uD840%uDC00"
        );
        for hex_run in encoded.split("%u").skip(1) {
            let hex_part: String = hex_run
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            assert_eq!(
                hex_part.len(),
                4,
                "each %u group must be 4 hex digits; got {hex_part:?}"
            );
        }
    }

    // ── §1 SPEED regression pins: byte-slice lookahead in json_unicode_alnum
    // and json_unicode_full (replacing Vec<char> collect). These tests pin
    // the observable contract so a revert to Vec<char> (or a bad rewrite
    // that breaks the ASCII-byte-boundary assumption) is caught immediately.

    #[test]
    fn json_unicode_alnum_idempotency_multi_pre_escaped() {
        // A payload with TWO pre-escaped sequences back-to-back. The
        // byte-slice lookahead must advance the iterator correctly for
        // each and not double-count the second `\u`.
        let p = "\\u0041\\u0042"; // Already-escaped A, B
        let once = json_unicode_alnum(p);
        let twice = json_unicode_alnum(&once);
        // Both passes: no change (the sequences are already `\uXXXX`).
        assert_eq!(once, p, "first pass on pre-escaped must be a no-op");
        assert_eq!(twice, p, "second pass must also be a no-op");
    }

    #[test]
    fn json_unicode_alnum_incomplete_escape_not_skipped() {
        // `\u004` (5 chars total but only 3 hex digits after `u`) must NOT
        // be treated as a pre-escaped sequence (the 4th hex digit is absent).
        // The `\` gets escaped (it's not alnum), `u` and `0`, `0`, `4` are
        // alnum and each get their own `\uXXXX`. This confirms the lookahead
        // correctly requires exactly 4 hex digits.
        let out = json_unicode_alnum("\\u004");
        // `\` → not alnum → bare `\`; `u`,`0`,`0`,`4` → each `\uXXXX`.
        // Net: the string is NOT passed through as-is.
        assert_ne!(out, "\\u004", "incomplete escape must not be skipped");
    }

    #[test]
    fn json_unicode_full_idempotency_multi_pre_escaped() {
        // Same as alnum variant but for json_unicode_full.
        let p = "\\u0041\\u0042";
        let once = json_unicode_full(p);
        let twice = json_unicode_full(&once);
        assert_eq!(once, p, "first pass: pre-escaped must survive");
        assert_eq!(twice, p, "second pass: still a no-op");
    }

    #[test]
    fn json_unicode_full_escapes_non_alnum_too() {
        // json_unicode_full escapes EVERY char, verify a space (U+0020)
        // and apostrophe (U+0027) are escaped, unlike json_unicode_alnum
        // which leaves punctuation bare.
        let out = json_unicode_full("' '");
        assert!(out.contains("\\u0027"), "apostrophe must be escaped");
        assert!(out.contains("\\u0020"), "space must be escaped");
    }

    #[test]
    fn overlong_utf8_path_speed_opt_preserves_passthrough_chars() {
        // §1 SPEED: the push-loop rewrite must leave non-special chars
        // unchanged. Mix of alphabetic, digit, and special chars.
        let out = overlong_utf8_path("admin/../secret.txt", 2);
        assert!(out.contains("admin"));
        assert!(out.contains("secret"));
        assert!(out.contains("txt"));
        assert!(!out.contains('.')); // dots replaced
        assert!(!out.contains('/')); // slashes replaced
    }

    #[test]
    fn overlong_utf8_path_empty_input_empty_output() {
        assert_eq!(overlong_utf8_path("", 2), "");
    }