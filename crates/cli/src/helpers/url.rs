//! URL and form-parsing utilities.

pub fn splice_path(base_url: &str, new_path: &str) -> String {
    match reqwest::Url::parse(base_url) {
        Ok(mut u) => {
            let (path_only, query) = match new_path.split_once('?') {
                Some((p, q)) => (p, Some(q)),
                None => (new_path, None),
            };
            u.set_path(path_only);
            if let Some(q) = query {
                u.set_query(Some(q));
            }
            u.to_string()
        }
        Err(_) => base_url.to_string(),
    }
}

pub fn parse_form_pairs(s: &str) -> Vec<(String, String)> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k.is_empty() {
                None
            } else {
                Some((k.to_string(), v.to_string()))
            }
        })
        .collect()
}

pub fn normalize_target_url(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.contains("://") {
        trimmed.to_string()
    } else if let Some(rest) = trimmed.strip_prefix("//") {
        format!("https://{rest}")
    } else {
        format!("https://{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splice_path_replaces_path_keeps_host() {
        let s = splice_path("https://target.example.com/old/path", "/new/path");
        assert_eq!(s, "https://target.example.com/new/path");
    }

    #[test]
    fn splice_path_preserves_query() {
        let s = splice_path("https://target.example.com/", "/admin?id=1");
        assert_eq!(s, "https://target.example.com/admin?id=1");
    }

    #[test]
    fn splice_path_invalid_base_returns_original() {
        let s = splice_path("not-a-url", "/admin");
        assert_eq!(s, "not-a-url");
    }

    #[test]
    fn normalize_bare_hostname_prepends_https() {
        assert_eq!(normalize_target_url("example.com"), "https://example.com");
    }

    #[test]
    fn normalize_http_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("http://example.com"),
            "http://example.com"
        );
    }

    #[test]
    fn normalize_https_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("https://example.com"),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_ws_scheme_passes_through() {
        assert_eq!(normalize_target_url("ws://example.com"), "ws://example.com");
    }

    #[test]
    fn normalize_wss_scheme_passes_through() {
        assert_eq!(
            normalize_target_url("wss://example.com"),
            "wss://example.com"
        );
    }

    #[test]
    fn normalize_whitespace_stripped() {
        assert_eq!(
            normalize_target_url("  example.com  "),
            "https://example.com"
        );
    }

    #[test]
    fn normalize_host_with_port_prepends_https() {
        assert_eq!(
            normalize_target_url("example.com:8080"),
            "https://example.com:8080"
        );
    }

    #[test]
    fn normalize_host_with_path_prepends_https() {
        assert_eq!(
            normalize_target_url("example.com/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn normalize_localhost_prepends_https() {
        assert_eq!(normalize_target_url("localhost"), "https://localhost");
    }

    #[test]
    fn normalize_localhost_with_port() {
        assert_eq!(
            normalize_target_url("localhost:3000"),
            "https://localhost:3000"
        );
    }

    #[test]
    fn normalize_protocol_relative_promotes_to_https() {
        assert_eq!(normalize_target_url("//example.com"), "https://example.com");
    }

    #[test]
    fn normalize_scheme_typo_passes_through_for_caller_error() {
        // A misspelled scheme like "htps://example.com" still contains "://"
        // so it passes through unchanged (reqwest will surface the parse error).
        let out = normalize_target_url("htps://example.com");
        assert_eq!(out, "htps://example.com");
    }

    #[test]
    fn normalize_empty_input_prepends_https() {
        // Empty string → "https://" (reqwest will error, which is correct).
        assert_eq!(normalize_target_url(""), "https://");
    }

    #[test]
    fn normalize_whitespace_only_becomes_https_empty() {
        assert_eq!(normalize_target_url("   "), "https://");
    }

    #[test]
    fn normalize_host_with_query_string() {
        assert_eq!(
            normalize_target_url("example.com/search?q=test"),
            "https://example.com/search?q=test"
        );
    }

    #[test]
    fn normalize_ftp_scheme_passes_through() {
        // Any declared scheme passes through (caller decides if it's valid).
        assert_eq!(
            normalize_target_url("ftp://files.example.com"),
            "ftp://files.example.com"
        );
    }

    #[test]
    fn normalize_ipv4_literal_prepends_https() {
        assert_eq!(normalize_target_url("192.168.1.1"), "https://192.168.1.1");
    }

    #[test]
    fn normalize_ipv4_with_port_and_path() {
        assert_eq!(
            normalize_target_url("127.0.0.1:8080/admin"),
            "https://127.0.0.1:8080/admin"
        );
    }
}
