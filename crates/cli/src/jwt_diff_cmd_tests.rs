    use super::*;

    // ── b64url round-trips ────────────────────────────────────

    #[test]
    fn b64url_encode_decode_round_trips_known_payloads() {
        for input in [&b""[..], b"a", b"ab", b"abc", b"abcd", b"hello world"] {
            let enc = b64url_encode(input);
            let dec = b64url_decode(&enc).expect("decode");
            assert_eq!(dec, input, "round-trip failed for {input:?}");
        }
    }

    #[test]
    fn b64url_encode_uses_no_padding_or_plus_or_slash() {
        let enc = b64url_encode(b"\x00\x10\x83\xfb\xff?");
        assert!(!enc.contains('='), "no padding: {enc}");
        assert!(!enc.contains('+'), "url-safe + → -: {enc}");
        assert!(!enc.contains('/'), "url-safe / → _: {enc}");
    }

    // ── decode_b64url_json ────────────────────────────────────

    #[test]
    fn decode_b64url_json_parses_real_jwt_header() {
        // Standard HS256 header.
        let header_b64 = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let v = decode_b64url_json(&header_b64).expect("decode");
        assert_eq!(v["alg"], "HS256");
        assert_eq!(v["typ"], "JWT");
    }

    #[test]
    fn decode_b64url_json_returns_none_on_garbage() {
        assert!(decode_b64url_json("!!!not-base64!!!").is_none());
    }

    // ── with_alg / with_field ─────────────────────────────────

    #[test]
    fn with_alg_replaces_existing_alg_field() {
        let h = json!({"alg":"HS256","typ":"JWT"});
        let h2 = with_alg(&h, "none");
        assert_eq!(h2["alg"], "none");
        assert_eq!(h2["typ"], "JWT", "other fields preserved");
    }

    #[test]
    fn with_field_adds_new_key_when_missing() {
        let h = json!({"alg":"HS256"});
        let h2 = with_field(&h, "kid", json!("attacker"));
        assert_eq!(h2["alg"], "HS256");
        assert_eq!(h2["kid"], "attacker");
    }

    #[test]
    fn with_field_handles_non_object_input_by_creating_empty() {
        let arr = json!([1, 2, 3]);
        let out = with_field(&arr, "alg", json!("none"));
        // The non-object input is dropped; the field-set yields a
        // fresh object with just the new key.
        assert_eq!(out["alg"], "none");
    }

    // ── build_jwt ─────────────────────────────────────────────

    #[test]
    fn build_jwt_concatenates_three_segments() {
        let header = json!({"alg":"none"});
        let payload = json!({"sub":"x"});
        let jwt = build_jwt(&header, &payload, "");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "must have header.payload.sig: {jwt}");
        assert_eq!(parts[2], "", "empty sig as requested");
    }

    #[test]
    fn build_jwt_round_trip_through_decode_recovers_fields() {
        let header = json!({"alg":"HS256","typ":"JWT"});
        let payload = json!({"sub":"alice","exp":1234567890u64});
        let jwt = build_jwt(&header, &payload, "fakesig");
        let parts: Vec<&str> = jwt.split('.').collect();
        let h = decode_b64url_json(parts[0]).expect("header decode");
        let p = decode_b64url_json(parts[1]).expect("payload decode");
        assert_eq!(h["alg"], "HS256");
        assert_eq!(p["sub"], "alice");
        assert_eq!(p["exp"], 1234567890u64);
    }

    // ── generate_jwt_variants ─────────────────────────────────

    fn valid_baseline_jwt() -> String {
        let header = json!({"alg":"HS256","typ":"JWT"});
        let payload = json!({"sub":"alice","exp":1900000000u64});
        build_jwt(&header, &payload, "AAAA-realsig")
    }

    #[test]
    fn generate_jwt_variants_returns_empty_for_non_jwt_input() {
        assert!(generate_jwt_variants("not-a-jwt").is_empty());
        assert!(generate_jwt_variants("only.two").is_empty());
        assert!(generate_jwt_variants("one.two.three.four").is_empty());
    }

    #[test]
    fn generate_jwt_variants_returns_curated_set_for_valid_baseline() {
        let v = generate_jwt_variants(&valid_baseline_jwt());
        assert!(v.len() >= 10, "expected ≥10 probes, got {}", v.len());
    }

    #[test]
    fn generate_jwt_variants_covers_alg_none_case_family() {
        let kinds: Vec<&str> = generate_jwt_variants(&valid_baseline_jwt())
            .iter()
            .map(|p| p.kind)
            .collect();
        for needed in [
            "alg-none-lowercase",
            "alg-none-capital",
            "alg-none-allcaps",
            "alg-none-mixed",
        ] {
            assert!(
                kinds.contains(&needed),
                "missing alg-none variant: {needed}, set: {kinds:?}"
            );
        }
    }

    #[test]
    fn generate_jwt_variants_covers_kid_traversal_and_sql() {
        let kinds: Vec<&str> = generate_jwt_variants(&valid_baseline_jwt())
            .iter()
            .map(|p| p.kind)
            .collect();
        assert!(kinds.contains(&"kid-path-traversal"));
        assert!(kinds.contains(&"kid-sql-injection"));
    }

    #[test]
    fn generate_jwt_variants_alg_none_probes_have_empty_signature() {
        for p in generate_jwt_variants(&valid_baseline_jwt()) {
            if p.kind.starts_with("alg-none") {
                let parts: Vec<&str> = p.mutated_token.split('.').collect();
                assert_eq!(parts.len(), 3);
                assert_eq!(parts[2], "", "alg-none probe {} sig must be empty", p.kind);
            }
        }
    }

    #[test]
    fn generate_jwt_variants_role_elevation_carries_admin_claims() {
        let v = generate_jwt_variants(&valid_baseline_jwt());
        let probe = v
            .iter()
            .find(|p| p.kind == "role-elevation")
            .expect("probe");
        let parts: Vec<&str> = probe.mutated_token.split('.').collect();
        let payload = decode_b64url_json(parts[1]).expect("decode");
        assert_eq!(payload["role"], "admin");
        assert_eq!(payload["is_admin"], true);
    }

    #[test]
    fn generate_jwt_variants_expired_exp_sets_past_timestamp() {
        let v = generate_jwt_variants(&valid_baseline_jwt());
        let probe = v.iter().find(|p| p.kind == "expired-exp").expect("probe");
        let parts: Vec<&str> = probe.mutated_token.split('.').collect();
        let payload = decode_b64url_json(parts[1]).expect("decode");
        let exp = payload["exp"].as_u64().expect("u64");
        assert!(exp < 1_700_000_000, "exp must be in the past: {exp}");
    }

    #[test]
    fn generate_jwt_variants_jku_attacker_url_uses_attacker_domain() {
        let v = generate_jwt_variants(&valid_baseline_jwt());
        let probe = v
            .iter()
            .find(|p| p.kind == "jku-attacker-url")
            .expect("probe");
        let parts: Vec<&str> = probe.mutated_token.split('.').collect();
        let header = decode_b64url_json(parts[0]).expect("decode");
        let jku = header["jku"].as_str().expect("jku");
        assert!(jku.contains("attacker"), "got: {jku}");
    }

    // ── render_curl ───────────────────────────────────────────

    #[test]
    fn render_curl_emits_bearer_authorization_header() {
        let out = render_curl("http://x/api", "eyJ.eyJ.sig");
        assert!(out.starts_with("curl -i "), "got: {out}");
        assert!(
            out.contains("'Authorization: Bearer eyJ.eyJ.sig'"),
            "got: {out}"
        );
    }

    // ── Validation gate ───────────────────────────────────────

    #[tokio::test]
    async fn run_jwt_diff_rejects_non_jwt_token_with_exit_2() {
        let args = JwtDiffArgs {
            url: "http://127.0.0.1:65500/".into(),
            token: "not.a.jwt.has.too.many.parts".into(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 1,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            method: "GET".into(),
            body: None,
            format: "json".into(),
            quiet: true,
        };
        let code = run_jwt_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(2)));
    }

    // ── Live mock integration ─────────────────────────────────

    async fn spawn_jwt_mock() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Simulate a VULNERABLE server that accepts ANY
                    // bearer token containing `"alg":"none"` in the
                    // decoded header (i.e. fails to validate).
                    let auth = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                        .unwrap_or("");
                    let permissive = auth.contains("eyJ") && auth.matches('.').count() == 2;
                    let body = if permissive {
                        r#"{"data":"sensitive admin payload"}"#
                    } else {
                        r#"{"data":"baseline"}"#
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_jwt_diff_against_permissive_mock_succeeds() {
        let addr = spawn_jwt_mock().await;
        let args = JwtDiffArgs {
            url: format!("http://{addr}/api/me"),
            token: valid_baseline_jwt(),
            delay_ms: 0,
            concurrency: 4,
            // 30s: Windows loopback + starved current_thread runtime.
            timeout_secs: wafrift_types::DEFAULT_REQUEST_TIMEOUT_SECS,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            method: "GET".into(),
            body: None,
            format: "json".into(),
            quiet: true,
        };
        let code = run_jwt_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn run_jwt_diff_against_unreachable_target_exits_1() {
        let args = JwtDiffArgs {
            url: "http://127.0.0.1:1/".into(),
            token: valid_baseline_jwt(),
            delay_ms: 0,
            concurrency: 4,
            timeout_secs: 2,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            method: "GET".into(),
            body: None,
            format: "json".into(),
            quiet: true,
        };
        let code = run_jwt_diff(args).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
    }
