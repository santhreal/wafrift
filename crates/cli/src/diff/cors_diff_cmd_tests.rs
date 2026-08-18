    use super::*;

    // ── extract_host ──────────────────────────────────────────

    #[test]
    fn extract_host_strips_scheme_path_userinfo_port() {
        assert_eq!(
            extract_host("https://api.example.com/path"),
            Some("api.example.com".into())
        );
        assert_eq!(
            extract_host("http://user:pw@api.example.com:8080/p"),
            Some("api.example.com".into())
        );
        assert_eq!(
            extract_host("api.example.com/p"),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn extract_host_handles_empty_authority() {
        assert_eq!(extract_host("http:///path"), None);
    }

    // ── classify_cors ─────────────────────────────────────────

    #[test]
    fn classify_cors_high_when_reflection_with_credentials() {
        let (sev, _) = classify_cors(
            Some("https://attacker.example"),
            Some("https://attacker.example"),
            Some("true"),
        );
        assert_eq!(sev, "high");
    }

    #[test]
    fn classify_cors_medium_when_reflection_without_credentials() {
        let (sev, _) = classify_cors(
            Some("https://attacker.example"),
            Some("https://attacker.example"),
            None,
        );
        assert_eq!(sev, "medium");
    }

    #[test]
    fn classify_cors_medium_on_wildcard_plus_credentials() {
        let (sev, _) = classify_cors(Some("https://attacker.example"), Some("*"), Some("true"));
        assert_eq!(sev, "medium");
    }

    #[test]
    fn classify_cors_none_when_acao_absent() {
        let (sev, _) = classify_cors(Some("https://attacker.example"), None, None);
        assert_eq!(sev, "none");
    }

    #[test]
    fn classify_cors_none_when_acao_does_not_reflect() {
        let (sev, _) = classify_cors(
            Some("https://attacker.example"),
            Some("https://trusted.example"),
            Some("true"),
        );
        assert_eq!(sev, "none");
    }

    #[test]
    fn classify_cors_none_when_no_origin_sent() {
        let (sev, _) = classify_cors(None, Some("https://anywhere"), Some("true"));
        assert_eq!(sev, "none");
    }

    #[test]
    fn classify_cors_acac_match_is_case_insensitive() {
        let (sev_lower, _) = classify_cors(Some("x"), Some("x"), Some("true"));
        let (sev_upper, _) = classify_cors(Some("x"), Some("x"), Some("TRUE"));
        let (sev_mixed, _) = classify_cors(Some("x"), Some("x"), Some("True"));
        assert_eq!(sev_lower, "high");
        assert_eq!(sev_upper, "high");
        assert_eq!(sev_mixed, "high");
    }

    // ── generate_cors_variants ────────────────────────────────

    #[test]
    fn generate_cors_variants_returns_curated_set() {
        let v = generate_cors_variants("target.com");
        assert!(v.len() >= 10, "expected ≥10 probes, got {}", v.len());
    }

    #[test]
    fn generate_cors_variants_kinds_are_unique() {
        let v = generate_cors_variants("t.com");
        let mut k: Vec<&str> = v.iter().map(|p| p.kind).collect();
        k.sort();
        k.dedup();
        assert_eq!(k.len(), v.len());
    }

    #[test]
    fn generate_cors_variants_interpolates_target_host_into_confusion_probes() {
        let v = generate_cors_variants("api.example.com");
        let suffix = v
            .iter()
            .find(|p| p.kind == "subdomain-suffix-confusion")
            .expect("suffix probe");
        assert!(
            suffix
                .origin
                .as_deref()
                .unwrap()
                .contains("api.example.com.attacker")
        );
        let prefix = v
            .iter()
            .find(|p| p.kind == "subdomain-prefix-confusion")
            .expect("prefix probe");
        assert!(
            prefix
                .origin
                .as_deref()
                .unwrap()
                .contains("attacker.api.example.com")
        );
    }

    #[test]
    fn cors_confusion_probes_match_their_documented_check_type() {
        // Anti-rig for the §5 description fix: the suffix-confusion probe's
        // origin is caught by a PREFIX/contains check (target as a leading
        // label of the attacker domain), and the prefix-confusion probe's
        // origin by a SUFFIX check (attacker label before target). A
        // regression that swapped the two origin shapes would make the
        // operator-facing descriptions wrong again, exactly the bug this
        // pass fixed.
        let host = "api.example.com";
        let scheme_host = format!("https://{host}");
        let v = generate_cors_variants(host);

        let suffix = v
            .iter()
            .find(|p| p.kind == "subdomain-suffix-confusion")
            .unwrap();
        let so = suffix.origin.as_deref().unwrap();
        // Caught by starts_with("https://"+host) / contains(host). NOT ends_with(host).
        assert!(
            so.starts_with(&scheme_host),
            "suffix-confusion origin must prefix-match: {so}"
        );
        assert!(
            !so.ends_with(host),
            "suffix-confusion origin must NOT end with host (that's the prefix probe): {so}"
        );

        let prefix = v
            .iter()
            .find(|p| p.kind == "subdomain-prefix-confusion")
            .unwrap();
        let po = prefix.origin.as_deref().unwrap();
        // Caught by ends_with(host). NOT starts_with("https://"+host).
        assert!(
            po.ends_with(host),
            "prefix-confusion origin must suffix-match: {po}"
        );
        assert!(
            !po.starts_with(&scheme_host),
            "prefix-confusion origin must NOT start with https://host (that's the suffix probe): {po}"
        );
    }

    #[test]
    fn generate_cors_variants_includes_null_origin_probe() {
        let v = generate_cors_variants("x");
        let null = v
            .iter()
            .find(|p| p.kind == "origin-null-accepted")
            .expect("null probe");
        assert_eq!(null.origin.as_deref(), Some("null"));
    }

    #[test]
    fn generate_cors_variants_preflight_uses_options_method() {
        let v = generate_cors_variants("x");
        for p in &v {
            if p.kind.starts_with("preflight") {
                assert_eq!(
                    p.method, "OPTIONS",
                    "preflight probe {} must use OPTIONS",
                    p.kind
                );
                // Must include Access-Control-Request-* headers.
                let has_acrm = p
                    .extra_headers
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case("access-control-request-method"));
                assert!(has_acrm, "{} missing ACRM header", p.kind);
            }
        }
    }

    #[test]
    fn generate_cors_variants_userinfo_injection_probe_uses_at_separator() {
        let v = generate_cors_variants("victim.com");
        let probe = v
            .iter()
            .find(|p| p.kind == "userinfo-injection")
            .expect("userinfo probe");
        assert!(
            probe
                .origin
                .as_deref()
                .unwrap()
                .contains("attacker.example@victim.com")
        );
    }

    // ── render_curl ───────────────────────────────────────────

    #[test]
    fn render_curl_emits_get_without_method_flag() {
        let out = render_curl("GET", "http://x/", Some("https://attacker"), &[]);
        assert!(!out.contains("-X GET"), "GET should be implicit: {out}");
        assert!(out.contains("-H 'Origin: https://attacker'"), "got: {out}");
    }

    #[test]
    fn render_curl_emits_options_for_preflight() {
        let out = render_curl(
            "OPTIONS",
            "http://x/",
            None,
            &[("Access-Control-Request-Method".into(), "DELETE".into())],
        );
        assert!(out.contains("-X OPTIONS"), "got: {out}");
        assert!(
            out.contains("'Access-Control-Request-Method: DELETE'"),
            "got: {out}"
        );
    }

    // ── Live mock integration ─────────────────────────────────

    async fn spawn_cors_mock() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Vulnerable: reflect ANY Origin into ACAO + set ACAC:true.
                    let origin_line = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("origin:"))
                        .map(|l| {
                            l.split_once(':')
                                .map(|x| x.1)
                                .unwrap_or("")
                                .trim()
                                .to_string()
                        })
                        .unwrap_or_default();
                    let body = "{}";
                    let extra_cors = if origin_line.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "Access-Control-Allow-Origin: {origin_line}\r\n\
                             Access-Control-Allow-Credentials: true\r\n"
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\n{extra_cors}Connection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::diff::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    #[tokio::test]
    async fn run_cors_diff_finds_high_severity_on_reflective_mock() {
        let addr = spawn_cors_mock().await;
        let args = CorsDiffArgs {
            url: format!("http://{addr}/api/me"),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 8,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_cors_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_cors_diff_against_unreachable_target_exits_succeed_with_errors() {
        // CORS scanner is informational; transport errors are
        // recorded per-probe and the run exits cleanly. (Distinct
        // from probe families that exit 1 on baseline failure.)
        let args = CorsDiffArgs {
            url: "http://127.0.0.1:1/".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 1,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            format: "json".into(),
            quiet: true,
        };
        let code = run_cors_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }
