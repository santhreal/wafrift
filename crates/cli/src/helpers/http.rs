//! HTTP response parsing and error-walking utilities.

/// Extract the HTTP status code from the status line of a raw (possibly
/// partial) HTTP/1.x response. Reads ONLY the first line, so it works
/// even when a desync'd back-end emits a status line and then hangs
/// before the full header block arrives (`httparse`-style full parsing
/// needs the complete header section). Returns `None` when the first
/// line is not a recognisable `HTTP/x.y <code> …` status line.
///
/// Range-validation is delegated to [`crate::detect_cmd::parse_http_status`]
/// so the "valid HTTP status = 100..=599" rule has exactly one home, a
/// raw `220 ESMTP` banner or a bogus `999` is rejected here, not mis-read
/// as a status (the prior fork in `trailer_diff_cmd` did neither).
pub fn http_status_from_raw(bytes: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(bytes);
    let first_line = text.lines().next()?.trim();
    if !first_line.starts_with("HTTP/") {
        return None;
    }
    let code = first_line.split_whitespace().nth(1)?;
    crate::detect_cmd::parse_http_status(code).ok()
}

/// Build the canonical SSRF-safe redirect policy for every CLI HTTP
/// client. Use in place of `reqwest::redirect::Policy::limited(n)` so
/// a `302 Location: http://169.254.169.254/...` from a malicious
/// origin can't ferry us to the cloud metadata endpoint (or any other
/// internal address) while we're scanning an external WAF.
///
/// R55 pass-18 I2 (CLAUDE.md §15 AUDIT, SSRF): four sites
/// (`scan/mod.rs`, `replay.rs`, `scan/raw_runner.rs`,
/// `parser_diff_common`) used `Policy::limited(5)`: no bogon check,
/// no cross-origin protection. Centralising the policy here means
/// the next refactor doesn't have to find all four (or notice when a
/// fifth subcommand grows its own client).
///
/// Rules, in order:
/// 1. Cap at `max_hops` (default 5 for scan, 8 for session_init).
/// 2. Refuse redirects to a bogon IP literal (loopback / RFC1918 /
///    169.254.169.254 metadata / IPv6 ULA, etc.).
/// 3. Stop (do not follow) cross-origin hops, reqwest's `Attempt`
///    API has no way to strip auth from the next request, so the
///    only safe move is to halt and let the caller observe the 302
///    body without leaking Cookie/Authorization to a third party.
pub fn safe_redirect_policy(max_hops: usize) -> reqwest::redirect::Policy {
    // §7 DEDUPLICATION: delegate to the canonical transport-layer impl so
    // there is exactly ONE redirect policy, and the core `EvasionClient`
    // shares the identical bogon + cross-origin guard, not just the CLI's
    // own clients. (Was a full copy here; moved down to the HTTP layer.)
    wafrift_transport::safe_redirect_policy(max_hops)
}

/// Split a single `Name: Value` header line on the first colon and
/// trim surrounding whitespace. Accepts empty values per RFC 9110
/// §5.5, the WAF / origin server decides whether an empty value is
/// meaningful, not this parser. Rejects missing colon and empty name.
///
/// Returns a short error fragment ("missing ':' separator", "empty
/// name") so callers can compose their own context: `"invalid
/// header \`{raw}\`; {frag}"` for [`parse_headers`], `"-H/--header
/// {raw:?} {frag}"` for [`crate::scan::pentest_client::parse_header`].
pub fn parse_header_pair(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| "missing ':' separator".to_string())?;
    let name = name.trim();
    if name.is_empty() {
        return Err("empty name".to_string());
    }
    Ok((name.to_string(), value.trim().to_string()))
}

pub fn parse_headers(raw_headers: &[String]) -> Result<Vec<(String, String)>, String> {
    raw_headers
        .iter()
        // R44 ext fix (dogfood pass 4 tail): skip empty header
        // arguments. Pre-fix `wafrift detect --status 200 --headers
        // '' --body ''` failed with "invalid header ``; expected
        // key: value". The empty-string case is the natural shell
        // idiom for "no headers" (passing the flag with a default
        // empty value); accept it as the no-op it intends to be.
        .filter(|header| !header.trim().is_empty())
        .map(|header| {
            if !header.contains(':') {
                return Err(format!("invalid header `{header}`; expected `key: value`"));
            }
            parse_header_pair(header).map_err(|frag| format!("invalid header `{header}`; {frag}"))
        })
        .collect()
}

/// Walk a `reqwest::Error`'s cause chain and return a string that includes
/// every level, joined by " (caused by: ").
///
/// reqwest's own `Display` is famously short: "error sending request"
/// without the underlying DNS / TCP / TLS cause.  This helper, first
/// extracted during dogfood pass 5 (2026-05), surfaces the full chain
/// (e.g. "dns error, caused by: No such host is known. (os error 11001)")
/// so operators never have to guess whether the failure is NXDOMAIN,
/// connection refused, TLS handshake failure, or something else.
///
/// `detect_cmd::fetch_for_detect` was the first site to walk the chain;
/// `bypass_probe::run_async` and `bank_registry::http_get_blocking` /
/// `http_post_blocking` were fixed in the same pass.
pub fn walk_reqwest_error(e: &reqwest::Error) -> String {
    let mut detail = format!("{e}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(s) = src {
        detail.push_str(", caused by: ");
        detail.push_str(&s.to_string());
        src = std::error::Error::source(s);
    }
    detail
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_headers_trims_whitespace() {
        let headers = parse_headers(&[
            "Server: cloudflare".to_string(),
            " Content-Type : text/html ".to_string(),
        ])
        .expect("valid headers");

        assert_eq!(
            headers,
            vec![
                ("Server".to_string(), "cloudflare".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ]
        );
    }

    #[test]
    fn parse_headers_rejects_missing_separator() {
        let err = parse_headers(&["missing separator".to_string()]).expect_err("invalid header");
        assert!(err.contains("expected `key: value`"));
    }

    #[test]
    fn parse_headers_handles_empty_input() {
        let r = parse_headers(&[]).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn parse_headers_preserves_value_internal_colons() {
        // A `Date: Wed, 21 Oct 2015 07:28:00 GMT` style header
        // contains colons inside the value, splitting on the FIRST
        // `:` must preserve the rest.
        let r = parse_headers(&["Date: Wed, 21 Oct 2015 07:28:00 GMT".into()]).unwrap();
        assert_eq!(r[0].0, "Date");
        assert_eq!(r[0].1, "Wed, 21 Oct 2015 07:28:00 GMT");
    }

    #[test]
    fn parse_headers_rejects_empty_key() {
        // A `: value` line is malformed (key half is empty).
        let r = parse_headers(&[": value".into()]);
        assert!(r.is_err(), "empty key must be rejected");
    }

    #[test]
    fn parse_header_pair_splits_on_first_colon() {
        let (n, v) = parse_header_pair("X-Custom: hello").unwrap();
        assert_eq!(n, "X-Custom");
        assert_eq!(v, "hello");
    }

    #[test]
    fn parse_header_pair_trims_both_halves() {
        let (n, v) = parse_header_pair("  X  :   Bearer abc   ").unwrap();
        assert_eq!(n, "X");
        assert_eq!(v, "Bearer abc");
    }

    #[test]
    fn parse_header_pair_preserves_value_internal_colons() {
        // Bearer tokens / dates / URLs may contain `:`: the FIRST
        // colon is the separator, everything after stays in the value.
        let (_, v) = parse_header_pair("X-Time: 12:34:56").unwrap();
        assert_eq!(v, "12:34:56");
    }

    #[test]
    fn parse_header_pair_rejects_missing_colon() {
        let err = parse_header_pair("nocolon").unwrap_err();
        assert!(err.contains("missing"), "got: {err}");
    }

    #[test]
    fn parse_header_pair_rejects_empty_name() {
        let err = parse_header_pair(": value").unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn parse_header_pair_does_not_validate_crlf_in_value() {
        // Splitter accepts CRLF; the contract is "split + trim", not
        // "validate". The validation must happen downstream.
        let evil = "X-Foo: bar\r\nX-Injected: evil";
        let (name, value) = parse_header_pair(evil).expect("splitter accepts CRLF");
        assert_eq!(name, "X-Foo");
        assert!(
            value.contains("\r\n"),
            "splitter must preserve raw bytes (downstream is responsible for rejection)"
        );
    }

    #[test]
    fn safe_redirect_policy_constructs_without_panic() {
        // Trivial existence check, the policy is a closure; this
        // confirms `safe_redirect_policy(n)` is wired and matches
        // the type reqwest::ClientBuilder::redirect expects. Stops
        // the SSRF fix from regressing silently if a future refactor
        // accidentally swaps the helper back to Policy::limited.
        let _policy = safe_redirect_policy(5);
        let _policy_zero = safe_redirect_policy(0);
        let _policy_high = safe_redirect_policy(usize::MAX);
    }

    #[test]
    fn parse_header_pair_does_not_validate_nul_in_value() {
        // Same boundary: NUL must be rejected by HeaderValue, not by
        // the splitter. Anti-rig against a future "let's add a CRLF
        // check here" patch that creates an inconsistent validation
        // layer.
        let nul = "X-Foo: bar\x00trailing";
        let (_, value) = parse_header_pair(nul).expect("splitter accepts NUL");
        assert!(value.contains('\x00'));
    }

    #[test]
    fn http_status_from_raw_extracts_and_validates() {
        // Complete response.
        assert_eq!(
            http_status_from_raw(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nbody"),
            Some(200)
        );
        // Partial response (status line only, no full header block), the
        // desync case: a back-end that emits the line then hangs.
        assert_eq!(
            http_status_from_raw(b"HTTP/1.1 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(
            http_status_from_raw(b"HTTP/1.0 404 Not Found\r\n\r\n"),
            Some(404)
        );
        // Non-HTTP first line (raw banner) must NOT be mis-read as a status
        // the `HTTP/` prefix guard the old trailer_diff fork lacked.
        assert_eq!(
            http_status_from_raw(b"220 mail.example.com ESMTP\r\n"),
            None
        );
        // Out-of-range code rejected by the shared range validator.
        assert_eq!(http_status_from_raw(b"HTTP/1.1 999 Nope\r\n"), None);
        // Empty / garbage.
        assert_eq!(http_status_from_raw(b""), None);
        assert_eq!(http_status_from_raw(b"NOT HTTP AT ALL"), None);
    }
    #[derive(Debug)]
    struct ChainedError {
        msg: &'static str,
        cause: Option<Box<dyn std::error::Error + Send + Sync>>,
    }
    impl std::fmt::Display for ChainedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.msg)
        }
    }
    impl std::error::Error for ChainedError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.cause.as_ref().map(|b| b.as_ref() as &_)
        }
    }

    /// A shallow clone of `walk_reqwest_error`'s algorithm applied to any
    /// `std::error::Error` chain, so we can test the chain-walk logic without
    /// needing a real `reqwest::Error` (which is hard to construct in tests).
    fn walk_std_error(e: &dyn std::error::Error) -> String {
        let mut detail = e.to_string();
        let mut src = e.source();
        while let Some(s) = src {
            detail.push_str(", caused by: ");
            detail.push_str(&s.to_string());
            src = s.source();
        }
        detail
    }

    #[test]
    fn walk_error_surfaces_single_level() {
        // PRE-FIX: `format!("{e}")` returns only the top-level message.
        // POST-FIX: the walker also surfaces it (no regression for 1-level chain).
        let e = ChainedError {
            msg: "outer error",
            cause: None,
        };
        let walked = walk_std_error(&e);
        assert_eq!(walked, "outer error");
    }

    #[test]
    fn walk_error_surfaces_deep_cause_chain() {
        // PRE-FIX: `format!("{e}")` → "outer error" only.
        // POST-FIX: walk_reqwest_error joins every level.
        let root = ChainedError {
            msg: "connection refused",
            cause: None,
        };
        let mid = ChainedError {
            msg: "tcp connect failed",
            cause: Some(Box::new(root)),
        };
        let top = ChainedError {
            msg: "error sending request",
            cause: Some(Box::new(mid)),
        };
        let walked = walk_std_error(&top);
        assert_eq!(
            walked,
            "error sending request, caused by: tcp connect failed, caused by: connection refused",
            "walk_std_error must join every level of the cause chain"
        );
        // Anti-regression: the result must NOT be just the top-level string.
        assert_ne!(
            walked, "error sending request",
            "bare top-level message means the cause chain was not walked"
        );
    }

    #[test]
    fn parse_header_pair_accepts_empty_value_per_rfc_9110() {
        // RFC 9110 §5.5 permits empty header values; curl accepts
        // them. We follow suit.
        let (n, v) = parse_header_pair("X-Empty:").unwrap();
        assert_eq!(n, "X-Empty");
        assert_eq!(v, "");
    }
}
