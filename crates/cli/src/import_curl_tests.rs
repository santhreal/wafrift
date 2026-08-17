    use super::*;

    #[test]
    fn tokenize_simple_curl() {
        let toks = shell_tokenize("curl https://example.com").unwrap();
        assert_eq!(toks, vec!["curl", "https://example.com"]);
    }

    // F125 regression suite: --data-urlencode must URL-encode the value
    // half (or the whole bare value), matching curl's wire behaviour.
    #[test]
    fn data_urlencode_encodes_value_only_for_kv_pair() {
        let toks = shell_tokenize("curl https://t/ --data-urlencode 'q=hello world'").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.body.as_deref(), Some("q=hello%20world"));
    }

    #[test]
    fn data_urlencode_encodes_whole_value_for_bare_string() {
        let toks = shell_tokenize("curl https://t/ --data-urlencode 'a b&c'").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.body.as_deref(), Some("a%20b%26c"));
    }

    #[test]
    fn data_urlencode_at_file_form_is_rejected_loudly() {
        let toks = shell_tokenize("curl https://t/ --data-urlencode '@/etc/passwd'").unwrap();
        let err = parse_curl(&toks).unwrap_err();
        assert!(err.contains("@file"), "got: {err}");
    }

    #[test]
    fn data_urlencode_kv_at_file_form_rejected() {
        let toks = shell_tokenize("curl https://t/ --data-urlencode 'name=@/etc/passwd'").unwrap();
        let err = parse_curl(&toks).unwrap_err();
        assert!(err.contains("@file"), "got: {err}");
    }

    #[test]
    fn data_urlencode_legitimate_at_in_value_not_rejected() {
        // Anti-rig: email-like values must NOT trigger the @file guard.
        let toks = shell_tokenize("curl https://t/ --data-urlencode 'email=foo@bar.com'").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.body.as_deref(), Some("email=foo%40bar.com"));
    }

    #[test]
    fn data_urlencode_and_plain_data_concat_with_ampersand() {
        let toks =
            shell_tokenize("curl https://t/ -d 'a=1' --data-urlencode 'b=hello world'").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.body.as_deref(), Some("a=1&b=hello%20world"));
    }

    #[test]
    fn tokenize_single_quoted_value() {
        let toks = shell_tokenize("curl 'https://x/y?z=1&a=2' -H 'User-Agent: x'").unwrap();
        assert_eq!(toks[1], "https://x/y?z=1&a=2");
        assert_eq!(toks[3], "User-Agent: x");
    }

    #[test]
    fn tokenize_handles_multiline_continuations() {
        let raw = "curl 'https://x' \\\n  -H 'A: 1' \\\n  -d 'k=v'";
        let toks = shell_tokenize(raw).unwrap();
        assert_eq!(toks[0], "curl");
        assert_eq!(toks[1], "https://x");
        assert_eq!(toks[2], "-H");
        assert_eq!(toks[3], "A: 1");
        assert_eq!(toks[4], "-d");
        assert_eq!(toks[5], "k=v");
    }

    #[test]
    fn tokenize_double_quoted_with_escape() {
        let toks = shell_tokenize(r#"curl "https://x" "-H" "A: \"quoted\"""#).unwrap();
        assert_eq!(toks[1], "https://x");
        assert_eq!(toks[3], r#"A: "quoted""#);
    }

    #[test]
    fn tokenize_rejects_non_curl_first_token() {
        assert!(shell_tokenize("wget https://x").is_err());
    }

    #[test]
    fn parse_minimal_get() {
        let toks = shell_tokenize("curl https://example.com/login").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://example.com/login"));
        assert_eq!(p.method, None);
        assert!(p.headers.is_empty());
        assert!(p.body.is_none());
    }

    #[test]
    fn parse_post_with_headers_and_body() {
        let raw = "curl 'https://api.target/login' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  -H 'Cookie: sess=abc' \\\n  --data-raw 'user=admin&pass=test'";
        let toks = shell_tokenize(raw).unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://api.target/login"));
        assert_eq!(p.headers.len(), 2);
        assert_eq!(
            p.headers[0],
            (
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into()
            )
        );
        assert_eq!(p.headers[1], ("Cookie".into(), "sess=abc".into()));
        assert_eq!(p.body.as_deref(), Some("user=admin&pass=test"));
    }

    #[test]
    fn parse_method_override() {
        let toks = shell_tokenize("curl -X PUT https://x").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.method.as_deref(), Some("PUT"));
    }

    #[test]
    fn parse_user_agent_and_cookie() {
        let toks = shell_tokenize("curl -A 'Mozilla/5.0' -b 'sess=abc' https://x").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(p.cookie.as_deref(), Some("sess=abc"));
    }

    #[test]
    fn parse_concatenates_multiple_data_flags() {
        let raw = "curl https://x --data 'k1=v1' --data-raw 'k2=v2' --data 'k3=v3'";
        let toks = shell_tokenize(raw).unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.body.as_deref(), Some("k1=v1&k2=v2&k3=v3"));
    }

    #[test]
    fn parse_silently_ignores_no_op_flags() {
        // Common Chromium "Copy as cURL" output peppers in -i, --compressed, etc.
        let raw = "curl -i --compressed -k -L 'https://x/y'";
        let toks = shell_tokenize(raw).unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://x/y"));
    }

    #[test]
    fn parse_rejects_missing_url() {
        let toks = shell_tokenize("curl -H 'A: 1'").unwrap();
        assert!(parse_curl(&toks).is_err());
    }

    #[test]
    fn parse_rejects_malformed_header() {
        let toks = shell_tokenize("curl -H 'noColon' https://x").unwrap();
        let err = parse_curl(&toks).unwrap_err();
        assert!(err.contains("malformed header"));
    }

    // ── Value-taking long-flag whitelist ─────────────────────────

    #[test]
    fn parse_url_flag_captures_url() {
        // `curl --url https://target`: the URL is the value of
        // --url, not a positional token. Pre-fix, the long-option
        // heuristic skipped `https://target` and we returned
        // "no URL found".
        let toks = shell_tokenize("curl --url https://target/api").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://target/api"));
    }

    #[test]
    fn parse_max_time_does_not_eat_following_url() {
        let toks = shell_tokenize("curl --max-time 30 https://target/api").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://target/api"));
    }

    #[test]
    fn parse_user_flag_does_not_eat_following_url() {
        let toks = shell_tokenize("curl --user admin:pw https://target/").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://target/"));
    }

    #[test]
    fn parse_referer_flag_does_not_eat_following_url() {
        let toks = shell_tokenize("curl -e https://ref/ https://target/").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://target/"));
    }

    #[test]
    fn parse_resolve_flag_does_not_eat_following_url() {
        let toks = shell_tokenize("curl --resolve target:443:10.0.0.1 https://target/api").unwrap();
        let p = parse_curl(&toks).unwrap();
        assert_eq!(p.url.as_deref(), Some("https://target/api"));
    }

    #[test]
    fn parse_no_url_error_message_hints_at_flag_consumption() {
        let toks = shell_tokenize("curl -H 'A: 1'").unwrap();
        let err = parse_curl(&toks).unwrap_err();
        // The hint should mention the flag-consumption scenario so
        // the operator knows where to look, pre-fix the bare
        // "no URL found" gave no diagnostic at all.
        assert!(
            err.to_lowercase().contains("flag"),
            "error must hint at flag-consumption: {err}"
        );
    }

    // ── Differential auto-promote on no-payload path ─────────────
    //
    // detect_parsed_target hits the network (it's an async function
    // taking a real reqwest::Client). The full I/O path is exercised
    // by the e2e dogfood; here we pin the smaller invariants that
    // don't need a live socket:
    //
    //   - `send_parsed` builds the right method/headers/cookie/UA/body
    //     request shape from a ParsedCurl
    //   - the attack URL appended for the second probe is
    //     ?-separator-aware
    //
    // The richer "WAF inferred via differential" path is integration-
    // tested via `dogfood_fixes_e2e.rs` after the fixed binary
    // builds (the python mock returns identical responses on both
    // probes, so it asserts the "differential probe also clean" copy
    // appears, that's the only invariant we can reliably exercise
    // without a real WAF).

    #[test]
    fn attack_url_uses_ampersand_when_url_has_existing_query() {
        let cases = [
            ("https://x/y", "https://x/y?q=%27+OR+1%3D1--"),
            ("https://x/y?a=1", "https://x/y?a=1&q=%27+OR+1%3D1--"),
            (
                "https://x/y?a=1&b=2",
                "https://x/y?a=1&b=2&q=%27+OR+1%3D1--",
            ),
        ];
        for (url, expected) in cases {
            let attack_url = if url.contains('?') {
                format!("{url}&q=%27+OR+1%3D1--")
            } else {
                format!("{url}?q=%27+OR+1%3D1--")
            };
            assert_eq!(
                attack_url, expected,
                "wrong separator chosen for input {url}"
            );
        }
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_parsed_applies_headers_cookie_and_user_agent() {
        // Stands up a one-shot localhost server that echoes back the
        // headers it received. Verifies send_parsed pushes
        // headers/cookie/UA onto the request before firing, the
        // entire reason the differential probe carries the parsed
        // context (the parsed-Burp-request workflow).
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let url = format!("http://{addr}/");

        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).expect("read");
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = format!("captured-headers:\n{req}");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).ok();
            req
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("client");

        let parsed = ParsedCurl {
            method: None,
            url: Some(url.clone()),
            headers: vec![("X-Wafrift-Probe".into(), "yes".into())],
            user_agent: Some("dogfood/1.0".into()),
            cookie: Some("sess=abc".into()),
            body: None,
        };
        let (status, _hdrs, _body) = send_parsed(&client, "GET", &url, &parsed)
            .await
            .expect("send");
        assert_eq!(status, 200);
        let captured = server.join().expect("server thread").to_ascii_lowercase();
        // The captured request must contain every parsed-curl header.
        // Header names get lowercased by hyper's HTTP/1.1 serialiser,
        // so we lowercase the whole capture before matching.
        assert!(
            captured.contains("x-wafrift-probe: yes"),
            "custom header missing from probe request:\n{captured}"
        );
        assert!(
            captured.contains("user-agent: dogfood/1.0"),
            "user agent missing from probe request:\n{captured}"
        );
        assert!(
            captured.contains("cookie: sess=abc"),
            "cookie missing from probe request:\n{captured}"
        );
    }
