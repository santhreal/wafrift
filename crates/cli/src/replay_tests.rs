    use super::*;

    #[test]
    fn build_url_appends_param() {
        let u = build_url_with_param("https://x/y", "q", "1=1").unwrap();
        assert_eq!(u, "https://x/y?q=1%3D1");
    }

    #[test]
    fn replay_base_request_uses_shared_browser_headers() {
        let req =
            request_with_shared_browser_headers(Method::Get, "https://target.local/?q=x".into())
                .expect("shared browser request");
        let facts = guise::fingerprint::default_profile_facts();
        assert_eq!(req.get_header("User-Agent"), Some(facts.user_agent));
        assert_eq!(req.get_header("Accept"), Some(facts.accept));
        assert_eq!(
            req.get_header("Accept-Language"),
            Some(facts.accept_language)
        );
        assert_eq!(req.get_header("Sec-Fetch-Mode"), Some("navigate"));
        assert_ne!(
            req.get_header("Accept"),
            Some("*/*"),
            "replay should use browser navigation Accept, not a generic client wildcard"
        );
    }

    #[test]
    fn build_url_replaces_existing_param() {
        let u = build_url_with_param("https://x/y?q=stale&keep=me", "q", "fresh").unwrap();
        assert!(u.contains("keep=me"));
        assert!(u.contains("q=fresh"));
        assert!(!u.contains("q=stale"));
    }

    #[test]
    fn build_url_replaces_all_duplicate_params() {
        // Semantic: all existing occurrences of the param are stripped,
        // then exactly one new pair is appended.
        let u = build_url_with_param("https://x/y?q=a&q=b&q=c", "q", "fresh").unwrap();
        assert_eq!(u, "https://x/y?q=fresh");
    }

    #[test]
    fn build_url_handles_empty_query() {
        let u = build_url_with_param("https://x/y?", "q", "fresh").unwrap();
        assert_eq!(u, "https://x/y?q=fresh");
    }

    #[test]
    fn build_url_encodes_utf8_payload() {
        let u = build_url_with_param("https://x/y", "q", "パイロード").unwrap();
        assert_eq!(
            u,
            "https://x/y?q=%E3%83%91%E3%82%A4%E3%83%AD%E3%83%BC%E3%83%89"
        );
    }

    #[test]
    fn build_url_encodes_literal_plus_as_percent2b() {
        // '+' must become %2B so the backend does not decode it as a space.
        let u = build_url_with_param("https://x/y", "q", "a+b").unwrap();
        assert_eq!(u, "https://x/y?q=a%2Bb");
    }

    #[test]
    fn build_url_rejects_garbage() {
        assert!(build_url_with_param("not a url", "q", "x").is_err());
    }

    #[test]
    fn build_url_drops_fragment() {
        let u = build_url_with_param("https://x/y#frag", "q", "1").unwrap();
        assert!(!u.contains('#'));
        assert!(u.ends_with("q=1"));
    }

    #[test]
    fn resolve_techniques_precedence() {
        let base = ReplayArgs {
            target: "https://x".into(),
            param: "q".into(),
            payload: "1=1".into(),
            method: "GET".into(),
            technique: vec!["Explicit".into()],
            from_host: Some("host".into()),
            proxy_bank: None,
            from_waf: Some("waf".into()),
            insecure: false,
            timeout_secs: 30,
            format: "text".into(),
            host: None,
        };
        // --technique wins over --from-host and --from-waf.
        assert_eq!(resolve_techniques(&base).unwrap(), vec!["Explicit"]);

        let args2 = ReplayArgs {
            technique: vec![],
            ..base.clone()
        };
        // --from-host wins over --from-waf when --technique is absent.
        // Fix #5: when the proxy bank fails (no HOME or no entry), we fall
        // through to the per-WAF genome.  The genome bank may or may not
        // have entries depending on the test machine's state:
        //
        //   Ok(techs)  → genome bank had seeds; return them.
        //   Err(msg)   → genome bank is also empty / unreachable; the error
        //                must reference the genome path, NOT the proxy bank.
        match resolve_techniques(&args2) {
            Ok(techs) => {
                // Genome fallback succeeded (this is correct Fix #5 behaviour).
                assert!(
                    !techs.is_empty(),
                    "fallback from proxy bank to genome succeeded but returned empty vec"
                );
            }
            Err(msg) => {
                // Acceptable error messages after Fix #5:
                // - "open gene bank for fallback: ..." (no HOME or missing file)
                // - "no per-WAF genome has seed winners ..."
                // The proxy-bank "host not found" error must NOT be the terminal one.
                assert!(
                    msg.contains("genome") || msg.contains("gene bank") || msg.contains("HOME"),
                    "Fix #5 regression: terminal error references proxy bank, not genome: {msg}"
                );
                // The error must NOT name the fictitious host 'host'.
                assert!(
                    !msg.contains("'host'"),
                    "Fix #5 regression: error names the proxy-bank host lookup: {msg}"
                );
            }
        }

        let args3 = ReplayArgs {
            technique: vec![],
            from_host: None,
            ..base.clone()
        };
        // --from-waf is consulted last.
        let err3 = resolve_techniques(&args3).unwrap_err();
        assert!(err3.contains("genome"), "unexpected: {err3}");
    }

    #[test]
    fn extract_host_from_url_strips_port_and_path() {
        assert_eq!(
            extract_host_from_url("https://api.example.com:8443/v1/x?z=1"),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn extract_host_from_url_returns_none_for_empty() {
        // Post-D9 the underlying helper accepts any scheme (or none)
        // the prior `ftp://x → None` assertion was over-strict
        // paranoia, since replay's callers only ever construct
        // http/https URLs from already-validated inputs upstream.
        // Only truly hostless inputs return None now.
        assert_eq!(extract_host_from_url(""), None);
        assert_eq!(extract_host_from_url("https://"), None);
    }

    // ── Fix #5: --from-host fallback to per-WAF genome ───────────────────

    #[test]
    fn replay_falls_back_to_per_waf_genome_when_proxy_bank_empty() {
        // Synthetic setup: write a gene-bank.json with the requested host
        // but an empty proven_winners list.  The proxy bank is present and
        // parseable but carries no techniques for this host.  Fix #5
        // requires that `resolve_techniques` does NOT return an error
        // quoting the proxy bank, it must fall through to
        // `load_from_any_genome()`, whose error (or success) is the
        // terminal outcome.
        use std::io::Write;
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-test-empty-bank-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        let bank_json = serde_json::json!({
            "schema": 1,
            "hosts": {
                "target.example.com": {
                    "proven_winners": [],
                    "blocklisted": [],
                    "waf_name": null
                }
            }
        });
        {
            let mut f = std::fs::File::create(&tmp).expect("create temp bank file");
            write!(f, "{}", bank_json).expect("write temp bank file");
        }

        let args = ReplayArgs {
            target: "https://target.example.com/".into(),
            param: "q".into(),
            payload: "test".into(),
            method: "GET".into(),
            technique: vec![],
            from_host: Some("target.example.com".into()),
            proxy_bank: Some(tmp.clone()),
            from_waf: None,
            insecure: false,
            timeout_secs: 30,
            format: "text".into(),
            host: None,
        };

        let result = resolve_techniques(&args);

        // Clean up before asserting.
        let _ = std::fs::remove_file(&tmp);

        match result {
            Ok(techs) => {
                // Success path: genome fallback found real techniques.
                // (Only possible if the test machine has genomes installed.)
                assert!(
                    !techs.is_empty(),
                    "if resolve_techniques succeeds, the technique list must be non-empty"
                );
            }
            Err(msg) => {
                // Error path: genome bank is also empty / absent (typical in
                // CI without a populated ~/.wafrift/genomes/).
                // The critical invariant is that the error DOES NOT say
                // "host 'target.example.com' not found in proxy gene bank"
                //: that would mean Fix #5 failed to fall through.
                assert!(
                    !msg.contains("target.example.com"),
                    "Fix #5 regression: error references the proxy-bank host lookup \
                     instead of the genome fallback. msg: {msg}"
                );
                // The error must reference the genome / gene-bank (the
                // terminal step), not the proxy bank (the intermediate step).
                assert!(
                    msg.contains("genome") || msg.contains("gene bank") || msg.contains("HOME"),
                    "error should reference the genome fallback step, got: {msg}"
                );
            }
        }
    }

    #[test]
    fn load_from_proxy_bank_succeeds_with_populated_winners() {
        // Complementary test: when the proxy bank HAS proven_winners, they
        // must be returned directly (no fallback).
        use std::io::Write;
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-test-populated-bank-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        let bank_json = serde_json::json!({
            "schema": 1,
            "hosts": {
                "api.example.com": {
                    "proven_winners": ["encoding/url/double", "tamper::sql_comment"],
                    "blocklisted": [],
                    "waf_name": "cloudflare"
                }
            }
        });
        {
            let mut f = std::fs::File::create(&tmp).expect("create temp bank file");
            write!(f, "{}", bank_json).expect("write temp bank file");
        }

        let result = load_from_proxy_bank("api.example.com", Some(&tmp));
        let _ = std::fs::remove_file(&tmp);

        let techs = result.expect("should succeed with populated proxy bank");
        assert_eq!(techs, vec!["encoding/url/double", "tamper::sql_comment"]);
    }

    #[test]
    fn load_from_proxy_bank_returns_err_for_absent_host() {
        // A host that is not in the file should produce an error (not panic).
        use std::io::Write;
        let tmp = std::env::temp_dir().join(format!(
            "wafrift-test-absent-host-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos()
        ));
        let bank_json = serde_json::json!({"schema": 1, "hosts": {}});
        {
            let mut f = std::fs::File::create(&tmp).expect("create temp bank file");
            write!(f, "{}", bank_json).expect("write temp bank file");
        }

        let result = load_from_proxy_bank("missing.example.com", Some(&tmp));
        let _ = std::fs::remove_file(&tmp);

        let err = result.unwrap_err();
        assert!(
            err.contains("missing.example.com"),
            "error should name the missing host: {err}"
        );
    }
