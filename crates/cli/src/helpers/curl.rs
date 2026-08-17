//! Curl command rendering for probe reproducers.

use super::shell::{sh_ansi_c_quote_bytes, sh_quote, shell_single_quote};
use super::url::splice_path;

pub fn render_artifact_as_curl(
    artifact: &wafrift_types::probe::SmuggleArtifact,
    url: &str,
    extra_headers: &[(String, String)],
) -> Option<String> {
    use wafrift_types::probe::SmuggleArtifact;
    let method;
    let mut headers: Vec<(String, String)> = Vec::new();
    let body: Option<&[u8]>;
    match artifact {
        SmuggleArtifact::Headers(hs) => {
            method = "GET";
            headers.extend(hs.iter().cloned());
            body = None;
        }
        SmuggleArtifact::BodyWithContentType {
            content_type,
            body: b,
        } => {
            method = "POST";
            headers.push(("Content-Type".to_string(), content_type.clone()));
            body = Some(b.as_slice());
        }
        SmuggleArtifact::Frames(_) => return None,
    }
    headers.extend(extra_headers.iter().cloned());
    // `:path` splicing + quoting live in the shared core so this and
    // `smuggle_cross_cmd::render_composed_curl` cannot diverge.
    Some(render_curl_parts(method, url, &headers, body))
}

pub fn render_curl_parts(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> String {
    let mut effective_url = url.to_string();
    let mut wire_headers: Vec<(&str, &str)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if name == ":path" {
            effective_url = splice_path(url, value);
            continue;
        }
        wire_headers.push((name.as_str(), value.as_str()));
    }
    let mut s = format!("curl -X {method} {}", sh_quote(&effective_url));
    for (n, v) in &wire_headers {
        s.push_str(" -H ");
        s.push_str(&sh_quote(&format!("{n}: {v}")));
    }
    if let Some(b) = body {
        s.push_str(" --data-binary ");
        s.push_str(&sh_ansi_c_quote_bytes(b));
    }
    s
}

pub fn url_query_repro_curl(target: &str, param: &str, payload: &str) -> String {
    // `--data-urlencode <param>=<value>` is the wire-correct way to
    // express "this exact byte sequence in this exact param" without
    // letting the shell or curl re-encode anything. -G promotes
    // the data to the query string, matching `wafrift scan`'s actual
    // probe shape. The whole `param=payload` literal becomes one
    // single-quoted shell token so an embedded `&` or `=` in the
    // payload doesn't terminate the argument early.
    format!(
        "curl -G --data-urlencode {arg} {target}",
        arg = shell_single_quote(&format!("{param}={payload}")),
        target = shell_single_quote(target),
    )
}

pub fn render_simple_curl(
    method: Option<&str>,
    url: &str,
    headers: &[(String, String)],
    body: Option<(&str, &[u8])>,
) -> String {
    let effective_method = method.unwrap_or(if body.is_some() { "POST" } else { "GET" });
    let mut out = String::from("curl -i");
    if effective_method != "GET" {
        out.push_str(" -X ");
        out.push_str(effective_method);
    }
    if let Some((content_type, _)) = body {
        out.push(' ');
        out.push_str("-H ");
        out.push_str(&shell_single_quote(&format!(
            "Content-Type: {content_type}"
        )));
    }
    for (name, value) in headers {
        out.push(' ');
        out.push_str("-H ");
        out.push_str(&shell_single_quote(&format!("{name}: {value}")));
    }
    if let Some((_, bytes)) = body {
        out.push_str(" --data-binary ");
        out.push_str(&shell_single_quote(&String::from_utf8_lossy(bytes)));
    }
    out.push(' ');
    out.push_str(&shell_single_quote(url));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_artifact_as_curl_escapes_apostrophe_in_header_value() {
        use wafrift_types::probe::SmuggleArtifact;
        let art = SmuggleArtifact::Headers(vec![("X-Test".to_string(), "val'ue".to_string())]);
        let curl = render_artifact_as_curl(&art, "https://t.example/", &[])
            .expect("headers artifact renders");
        // The apostrophe is Bourne-escaped so a paste can't break the
        // token boundary: 'X-Test: val'\''ue'.
        assert!(curl.contains("'X-Test: val'\\''ue'"), "got: {curl}");
    }

    #[test]
    fn render_artifact_as_curl_neutralizes_cr_in_header_value() {
        use wafrift_types::probe::SmuggleArtifact;
        // LWS / CRLF-smuggle probes carry a raw CR in the value. The
        // emitted reproducer must not contain a bare CR (a pasted CR
        // hides part of the command); the hardened sh_quote splices
        // `$'\r'`. This is the security pin for the dedup+harden.
        let art = SmuggleArtifact::Headers(vec![("X-Smuggle".to_string(), "a\rb".to_string())]);
        let curl = render_artifact_as_curl(&art, "https://t.example/", &[])
            .expect("headers artifact renders");
        assert!(
            !curl.contains('\r'),
            "raw CR leaked into reproducer: {curl:?}"
        );
        assert!(curl.contains("$'\\r'"), "got: {curl}");
    }

    #[test]
    fn render_artifact_as_curl_splices_path_pseudo_header_into_url() {
        use wafrift_types::probe::SmuggleArtifact;
        // A `:path` pseudo-header splices into the URL path, NOT emitted
        // as a literal `-H ':path: …'` (which would not match what the
        // fire path sends).
        let art = SmuggleArtifact::Headers(vec![(":path".to_string(), "/admin?x=1".to_string())]);
        let curl = render_artifact_as_curl(&art, "https://t.example/old", &[])
            .expect("headers artifact renders");
        assert!(curl.contains("https://t.example/admin?x=1"), "got: {curl}");
        assert!(
            !curl.contains(":path"),
            "pseudo-header leaked as -H: {curl}"
        );
    }

    #[test]
    fn render_artifact_as_curl_returns_none_for_frames() {
        use wafrift_types::probe::SmuggleArtifact;
        let art = SmuggleArtifact::Frames(vec![vec![0u8, 1, 2]]);
        assert!(render_artifact_as_curl(&art, "https://t.example/", &[]).is_none());
    }

    #[test]
    fn url_query_repro_curl_wraps_param_value_pair_in_single_quotes() {
        let curl = url_query_repro_curl("https://x/y", "q", "abc");
        assert!(curl.starts_with("curl -G --data-urlencode "));
        assert!(curl.contains("'q=abc'"));
        assert!(curl.contains("'https://x/y'"));
    }

    #[test]
    fn url_query_repro_curl_protects_metacharacters_in_payload() {
        // `$(rm -rf /)` is the classic shell-injection canary. After
        // single-quoting it must appear verbatim, no expansion.
        let curl = url_query_repro_curl("https://target", "q", "$(rm -rf /); `whoami`");
        assert!(curl.contains("'q=$(rm -rf /); `whoami`'"));
    }

    #[test]
    fn url_query_repro_curl_handles_apostrophe_in_payload() {
        // The canonical SQLi `' OR 1=1--` contains the same quote
        // character we use to wrap the arg. shell_single_quote
        // escapes it via '\'', the curl must still be parseable
        // by bash.
        let curl = url_query_repro_curl("https://x", "q", "' OR 1=1--");
        // Resulting form: 'q='\'' OR 1=1--', the '\'' is the close-
        // escape-open sequence.
        assert!(curl.contains("'\\''"), "apostrophe not escaped: {curl}");
        // The literal payload bytes must appear unmangled across
        // the escape boundary.
        assert!(curl.contains("OR 1=1--"));
    }

    #[test]
    fn url_query_repro_curl_handles_empty_payload() {
        let curl = url_query_repro_curl("https://x", "q", "");
        // 'q=' is the right wire form for an empty value.
        assert!(curl.contains("'q='"));
    }

    #[test]
    fn url_query_repro_curl_handles_ampersand_in_payload_without_breaking_arg() {
        // & inside the payload must NOT split into a second curl
        // argument (single-quoting protects it).
        let curl = url_query_repro_curl("https://x", "q", "a&b=c");
        assert!(
            curl.contains("'q=a&b=c'"),
            "ampersand split arg or was re-encoded: {curl}"
        );
    }

    #[test]
    fn render_simple_curl_no_body_no_method_emits_curl_i() {
        let out = render_simple_curl(None, "http://x/", &[], None);
        assert_eq!(out, "curl -i 'http://x/'");
    }

    #[test]
    fn render_simple_curl_body_with_content_type_emits_post() {
        let out = render_simple_curl(
            None,
            "http://x/",
            &[],
            Some(("application/json", b"{\"k\":1}")),
        );
        assert!(out.contains("-X POST"), "must emit POST: {out}");
        assert!(
            out.contains("-H 'Content-Type: application/json'"),
            "got: {out}"
        );
        assert!(out.contains("--data-binary"), "got: {out}");
    }

    #[test]
    fn render_simple_curl_method_override_omits_x_for_get() {
        let out = render_simple_curl(Some("GET"), "http://x/", &[], None);
        assert!(!out.contains("-X"), "GET must not emit -X: {out}");
    }

    #[test]
    fn render_simple_curl_method_override_emits_x_for_patch() {
        let out = render_simple_curl(Some("PATCH"), "http://x/", &[], None);
        assert!(out.contains("-X PATCH"), "got: {out}");
    }

    #[test]
    fn render_simple_curl_header_array_emits_dash_h_per_entry() {
        let headers = vec![
            ("X-A".to_string(), "1".to_string()),
            ("X-B".to_string(), "2".to_string()),
        ];
        let out = render_simple_curl(None, "http://x/", &headers, None);
        assert!(out.contains("-H 'X-A: 1'"), "got: {out}");
        assert!(out.contains("-H 'X-B: 2'"), "got: {out}");
    }

    #[test]
    fn render_simple_curl_special_chars_in_url_are_shell_escaped() {
        // single-quote, dollar, backtick (all must survive round-trip).
        // shell_single_quote escapes ' → '\'' (Bourne close-escape-reopen).
        let out = render_simple_curl(
            None,
            "http://x/p?q=it's+/usr/bin/bash+uid=197609(mukun) gid=197609 groups=197609",
            &[],
            None,
        );
        // The ' in "it's" must be escaped as '\''. NOT triple-quote.
        assert!(
            out.contains("it'\\''s+"),
            "apostrophe in URL must be Bourne-escaped as '\\'': got: {out}"
        );
        // The rest of the URL (dollars, parens etc.) rides verbatim inside single-quotes.
        assert!(
            out.contains("uid=197609(mukun)"),
            "parens must survive as-is inside single-quotes: got: {out}"
        );
    }
}
