//! Shell quoting primitives for safe curl command emission.


pub fn sh_ansi_c_quote_bytes(b: &[u8]) -> String {
    let mut out = String::from("$'");
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x00..=0x1F | 0x7F => {
                out.push_str(&format!("\\x{byte:02x}"));
            }
            _ => out.push(byte as char),
        }
    }
    out.push('\'');
    out
}

pub fn sh_quote(s: &str) -> String {
    shell_single_quote(s)
}

/// Single-quote a string for safe interpolation into a Bourne-shell
/// command. Returns the FULLY wrapped form `'…'` so callers do not
/// add their own quotes. A literal `'` inside the input becomes
/// `'\''` (close-quote, escape, open-quote); every other byte rides
/// verbatim.
///
/// This is the canonical shell escape used by the curl reproducer in
/// [`crate::raw_request::RawRequest::to_curl`] and the `wafrift replay`
/// reproducer in `report::render_*`. Centralised so a single
/// round-trip-through-bash test exercises every caller.
pub fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        match ch {
            // `'` is the standard close-and-reopen escape.
            '\'' => out.push_str("'\\''"),
            // NUL inside a single-quoted shell token would
            // terminate the C string in libc and silently
            // truncate the argument. CR resets the terminal
            // cursor and can hide preceding output (operator
            // copies a curl from logs that looks shorter than
            // it is). Bash's `$'\\x00'` / `$'\\r'` ANSI-C
            // quoting is the safe form, fall out of the
            // single-quote run, splice the ANSI-C literal,
            // reopen the run.
            '\0' => out.push_str("'$'\\x00''"),
            '\r' => out.push_str("'$'\\r''"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_single_quote_wraps_safe_string_in_quotes() {
        assert_eq!(shell_single_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_single_quote_escapes_internal_apostrophes() {
        // Bourne escape: 'don'\''t'
        assert_eq!(shell_single_quote("don't"), "'don'\\''t'");
    }

    #[test]
    fn shell_single_quote_handles_empty_string() {
        assert_eq!(shell_single_quote(""), "''");
    }

    #[test]
    fn shell_single_quote_passes_dangerous_metacharacters_verbatim() {
        // Single-quoting means metacharacters lose meaning: `$`, `;`,
        // backticks, parens all ride through as bytes.
        assert_eq!(
            shell_single_quote("$(rm -rf /); `whoami`"),
            "'$(rm -rf /); `whoami`'"
        );
    }

    #[test]
    fn shell_single_quote_escapes_nul_byte() {
        // Regression for F72: NUL inside a single-quoted shell
        // token silently truncates the argument at the libc layer.
        // Use bash ANSI-C quoting to splice the NUL safely.
        let out = shell_single_quote("a\0b");
        // Output must not contain a raw NUL, every byte must be
        // representable in a shell here-doc / copy-paste.
        assert!(!out.contains('\0'), "raw NUL must be escaped, got: {out:?}");
        // Bash form: `'a'$'\x00''b'` (close + ANSI-C + reopen).
        assert!(out.contains("$'\\x00'"), "got: {out:?}");
    }

    #[test]
    fn shell_single_quote_escapes_carriage_return() {
        // Regression for F72: CR resets the terminal cursor and
        // can hide preceding output when the operator copies a
        // curl from logs. Escape via ANSI-C `\r`.
        let out = shell_single_quote("a\rb");
        assert!(!out.contains('\r'), "raw CR must be escaped: {out:?}");
        assert!(out.contains("$'\\r'"), "got: {out:?}");
    }

    #[test]
    fn sh_quote_delegates_to_hardened_single_quote() {
        // §7: sh_quote is an alias for the one canonical single-quoter,
        // so it MUST be byte-identical to shell_single_quote, including
        // the NUL/CR neutralisation that the pre-dedup naive `'…'` wrap
        // lacked.
        for s in ["safe", "it's", "$(whoami)", "a\rb", "a\0b", ""] {
            assert_eq!(sh_quote(s), shell_single_quote(s), "diverged on {s:?}");
        }
        let out = sh_quote("X-Smuggle: a\rb");
        assert!(!out.contains('\r'), "raw CR leaked: {out:?}");
        assert!(out.contains("$'\\r'"), "got: {out:?}");
    }

    #[test]
    fn shell_single_quote_round_trips_through_bash() {
        // Single canonical shell escape, round-tripped through bash
        // to confirm both halves (wrap + apostrophe escape) are wire-
        // compatible. Replaces the bash round-trip previously in
        // report.rs (one source of truth for the escape).
        let inputs = [
            "hello world",
            "it's working",
            "'\''",
            "foo;bar|baz",
            "$(danger)",
            "`backtick`",
            "emoji: 🚀",
        ];
        for raw in &inputs {
            let escaped = shell_single_quote(raw);
            let script = format!("echo {escaped}");
            let output = std::process::Command::new("bash")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("bash must be available");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                stdout.trim_end(),
                *raw,
                "shell_single_quote round-trip failed for {raw:?}: script={script:?}"
            );
        }
    }

    #[test]
    fn shell_single_quote_with_apostrophe_in_url_path_is_valid_shell() {
        // A URL path containing a single quote: `/admin'path`
        // Pre-fix: this would appear as `'/admin'path'` which is syntactically
        // broken (the third `'` is an unclosed string). Post-fix: `'/admin'\''path'`.
        let url = "http://target.example.com/admin'path?id=1";
        let quoted = shell_single_quote(url);

        // The output must start and end with a single quote.
        assert!(quoted.starts_with('\''), "must be single-quoted: {quoted}");
        assert!(quoted.ends_with('\''), "must be single-quoted: {quoted}");

        // The interior must not contain a bare `'` (only the escaped form `'\''`).
        // Strip the outer quotes and check:
        let inner = &quoted[1..quoted.len() - 1];
        // Bare `'` in the interior means the quoting is broken.
        // The only allowed `'` sequences in a correctly Bourne-escaped
        // string interior are `'\''` (or empty). We check that
        // there's no isolated `'` that doesn't form `'\''`.
        let mut i = 0;
        let chars: Vec<char> = inner.chars().collect();
        while i < chars.len() {
            if chars[i] == '\'' {
                // A `'` in the interior must be followed by `\''`: that's
                // the close-escape-reopen sequence.
                assert!(
                    i + 3 < chars.len()
                        && chars[i + 1] == '\\'
                        && chars[i + 2] == '\''
                        && chars[i + 3] == '\'',
                    "bare apostrophe in shell_single_quote output interior \
Should be '\\''  (the standard Bourne escape).\n\
                     input={url:?}\noutput={quoted:?}\nposition={i}"
                );
                i += 4;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn shell_single_quote_header_value_with_apostrophe_is_valid() {
        // X-Original-URL probe value: `/path?q=it's`
        // Pre-fix: curl reproducer `'X-Original-URL: /path?q=it's'` is broken.
        // Post-fix: `'X-Original-URL: /path?q=it'\''s'`.
        let header_val = "X-Original-URL: /path?q=it's";
        let quoted = shell_single_quote(header_val);

        // Round-trip: splitting on `'\''` and reassembling gives back the original.
        // Simplified check: the quoted form, when unescaped by the Bourne rules,
        // yields the original string. We implement that manually.
        let reconstructed = quoted.trim_matches('\'').replace("'\\''", "'");
        assert_eq!(
            reconstructed, header_val,
            "shell_single_quote must round-trip: input={header_val:?}, \
             quoted={quoted:?}, reconstructed={reconstructed:?}"
        );
    }
}
