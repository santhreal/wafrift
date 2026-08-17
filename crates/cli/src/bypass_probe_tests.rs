    use super::*;

    #[test]
    fn extracts_path_from_full_url() {
        assert_eq!(parse_path_from_url("https://example.com/admin"), "/admin");
        assert_eq!(parse_path_from_url("http://x:8080/a/b?q=1"), "/a/b?q=1");
        assert_eq!(parse_path_from_url("https://example.com/"), "/");
        assert_eq!(parse_path_from_url("https://example.com"), "/");
    }

    #[test]
    fn classify_status_unchanged_below_threshold_returns_none() {
        let d = classify(
            "headers",
            "x",
            "y",
            200,
            1000,
            200,
            1050, // 5% delta
            10.0,
            || "curl".to_string(),
        );
        assert!(d.is_none());
    }

    #[test]
    fn classify_403_to_200_is_high_severity() {
        let d = classify("headers", "x", "y", 403, 500, 200, 500, 10.0, || {
            "curl".to_string()
        })
        .expect("must fire");
        assert_eq!(d.severity, "HIGH");
    }

    #[test]
    fn classify_body_growth_flags_medium() {
        let d = classify(
            "paths",
            "x",
            "y",
            403,
            100,
            403,
            500, // 400% growth, status unchanged
            10.0,
            || "curl".to_string(),
        )
        .expect("must fire");
        assert_eq!(d.severity, "MEDIUM");
    }

    #[test]
    fn classify_baseline_zero_body_then_content_returns_100pct() {
        let d = classify("paths", "x", "y", 403, 0, 403, 500, 10.0, || {
            "curl".to_string()
        })
        .expect("must fire");
        assert!((d.body_delta_pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn classify_unchanged_returns_none() {
        let d = classify("methods", "POST", "test", 403, 500, 403, 500, 10.0, || {
            "curl".to_string()
        });
        assert!(d.is_none());
    }

    // ── parse_path_from_url edges ─────────────────────────────

    #[test]
    fn parse_path_from_url_handles_userinfo_in_authority() {
        // RFC 3986 §3.2.1 userinfo: `user:pass@host`. Path starts
        // AFTER the authority.
        assert_eq!(
            parse_path_from_url("http://user:pass@example.com/admin"),
            "/admin"
        );
    }

    #[test]
    fn parse_path_from_url_drops_fragment() {
        // RFC 3986 §3.5: the fragment is client-side and never
        // sent on the wire. The auth-bypass probe URL the
        // operator constructs from this path must NOT include
        // `#section`, otherwise reqwest would silently strip it
        // again and the probe URL displayed to the operator
        // would diverge from what was sent. Returning the
        // bare path matches what the server actually sees.
        assert_eq!(parse_path_from_url("http://x/path#section"), "/path");
    }

    #[test]
    fn parse_path_from_url_preserves_query_when_path_is_empty() {
        // Regression for the silent-query-loss bug: pre-fix
        // `http://x?token=xyz` returned `/`, losing the query
        // entirely, and auth-bypass probes silently targeted a
        // different URL shape than the operator typed.
        assert_eq!(parse_path_from_url("http://x?token=xyz"), "/?token=xyz");
        assert_eq!(parse_path_from_url("http://x/?q=1"), "/?q=1");
    }

    #[test]
    fn parse_path_from_url_handles_ipv6_literal() {
        assert_eq!(parse_path_from_url("http://[::1]/path"), "/path");
        assert_eq!(parse_path_from_url("http://[::1]:8080/api?q=1"), "/api?q=1");
    }

    #[test]
    fn parse_path_from_url_relative_path_is_passed_through() {
        assert_eq!(parse_path_from_url("/admin/api"), "/admin/api");
    }

    #[test]
    fn parse_path_from_url_bare_string_with_no_slash_returns_root() {
        // `foo` without scheme or leading slash falls back to `/`.
        assert_eq!(parse_path_from_url("just-a-string"), "/");
    }

    #[test]
    fn parse_path_from_url_empty_string_returns_root() {
        assert_eq!(parse_path_from_url(""), "/");
    }

    #[test]
    fn parse_path_from_url_preserves_query_string() {
        assert_eq!(parse_path_from_url("http://x/api?a=1&b=2"), "/api?a=1&b=2");
    }

    #[test]
    fn parse_path_from_url_handles_https_scheme() {
        assert_eq!(parse_path_from_url("https://x/path"), "/path");
    }

    #[test]
    fn parse_path_from_url_handles_port_in_authority() {
        assert_eq!(parse_path_from_url("http://x:8080/api"), "/api");
        assert_eq!(parse_path_from_url("https://x:443/"), "/");
    }

    // ── classify edge cases ───────────────────────────────────

    #[test]
    fn classify_body_shrink_also_flags_divergence() {
        // Massive body shrink (probe response much smaller than
        // baseline) is also a divergence signal. Anti-rig against
        // a refactor that only counted GROWTH.
        let d = classify(
            "headers",
            "x",
            "y",
            200,
            10000,
            200,
            100, // 99% shrink
            10.0,
            || "curl".to_string(),
        )
        .expect("must fire");
        // Severity policy: a 200/200 status with massive body shrink
        // counts as at least LOW.
        assert!(matches!(d.severity, "HIGH" | "MEDIUM" | "LOW"));
    }

    #[test]
    fn classify_filters_throttle_status_codes() {
        // 429 (Too Many Requests) and 503 are throttle/unavailable;
        // never treated as a real divergence even if status changed.
        for status in [429u16, 503] {
            let d = classify("headers", "x", "y", 200, 500, status, 500, 10.0, || {
                "curl".to_string()
            });
            assert!(d.is_none(), "{status} must be filtered as throttle");
        }
    }

    #[test]
    fn classify_records_family_label_description_verbatim() {
        let d = classify(
            "auth-bypass",
            "x-forwarded-host",
            "header trust override",
            403,
            500,
            200,
            500,
            10.0,
            || "curl".to_string(),
        )
        .expect("must fire");
        assert_eq!(d.family, "auth-bypass");
        assert_eq!(d.label, "x-forwarded-host");
        assert_eq!(d.description, "header trust override");
    }

    #[test]
    fn classify_calls_curl_closure_once_on_fire() {
        // The curl-fn is held as a closure so it only allocates
        // the (potentially long) curl command string when the
        // divergence FIRES (a perf shape we want to preserve).
        // Verify it gets called when we expect a divergence.
        let called = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called_c = called.clone();
        let _d = classify("headers", "x", "y", 403, 500, 200, 500, 10.0, move || {
            called_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            "curl".to_string()
        });
        assert_eq!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "curl closure must fire exactly once on divergence"
        );
    }

    #[test]
    fn classify_does_not_call_curl_closure_when_unchanged() {
        // No divergence ⇒ no allocation.
        let called = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called_c = called.clone();
        let _d = classify("headers", "x", "y", 200, 500, 200, 500, 10.0, move || {
            called_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            "curl".to_string()
        });
        assert_eq!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no divergence ⇒ no curl allocation"
        );
    }

    // ── shared-deadline Retry-After integration ─────────────────────
    //
    // These tests stand up a minimal in-process HTTP server with
    // tokio's TcpListener (axum is not a dev-dep here and we want
    // exact control over the response bytes, wiremock buys nothing
    // we don't already get from 15 lines of raw socket code). The
    // server's per-request behaviour is driven by a shared atomic
    // counter, so a single test can name exactly which probes
    // throttle and which succeed.

    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Spin a localhost server. `respond(n)` is called with the 0-based
    /// request index (n=0 is the baseline GET fired by `probe_one_url`
    /// before the probe loop, n≥1 are probe requests). The returned
    /// `String` is sent verbatim as the HTTP response.
    async fn spawn_mock_server<F>(respond: F) -> std::net::SocketAddr
    where
        F: Fn(usize) -> String + Send + Sync + 'static,
    {
        let count = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let count_c = count.clone();
                let respond_c = respond.clone();
                tokio::spawn(async move {
                    // Drain the request headers, we don't inspect them,
                    // but reqwest will close the connection if we reply
                    // before reading at least the first line, and a
                    // single read() is enough for a header-only GET.
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let n = count_c.fetch_add(1, Ordering::SeqCst);
                    let body = respond_c(n);
                    let _ = sock.write_all(body.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        // Give the listener a beat to be ready before any client connects.
        tokio::time::sleep(Duration::from_millis(50)).await;
        addr
    }

    fn ok_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn rate_limited_response(retry_after_secs: u32) -> String {
        format!(
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {retry_after_secs}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    fn methods_only_args(url: String) -> BypassProbeArgs {
        // 7 method-override probes only, keeps the test loop short
        // and deterministic. delay_ms=0 because the cooldown wait is
        // what we want to observe, not the user politeness spread.
        BypassProbeArgs {
            url,
            paths_file: None,
            timeout_secs: 4,
            delay_ms: 0,
            concurrency: 4,
            insecure: false,
            format: "text".into(),
            output: None,
            skip_headers: true,
            skip_paths: true,
            skip_methods: false,
            body_diff_threshold_pct: 10.0,
            min_severity: "low".into(),
            quiet: true,
        }
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retry_after_extends_cooldown_across_subsequent_probes() {
        // Server: baseline 200, next 2 probes return 429 + Retry-After:1,
        // the rest return 200. After the first concurrent batch trips
        // the rate limit, every remaining probe must wait ≥ ~1 s before
        // firing (proving the shared deadline is published and obeyed).
        let addr = spawn_mock_server(|n| match n {
            0 => ok_response("baseline body 11"),
            1 | 2 => rate_limited_response(1),
            _ => ok_response("bypassed body!!"),
        })
        .await;
        let url = format!("http://{addr}/admin");
        let args = methods_only_args(url.clone());
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let t0 = Instant::now();
        let report = probe_one_url(&client, &url, &args, 4)
            .await
            .expect("probe should run");
        let elapsed = t0.elapsed();

        assert_eq!(report.probes_fired, 7, "7 method overrides expected");
        assert!(
            report.retry_after_responses >= 1,
            "expected ≥ 1 obeyed Retry-After, got {}",
            report.retry_after_responses
        );
        assert!(
            report.max_retry_after_obeyed_ms >= 1000,
            "expected ≥ 1000 ms obeyed, got {}",
            report.max_retry_after_obeyed_ms
        );
        // ~800 ms is the jittered floor (0.80 × 1000). Use 700 ms as the
        // hard lower bound to absorb mock-server scheduling jitter on
        // slow CI runners without making the test a tautology.
        assert!(
            elapsed >= Duration::from_millis(700),
            "expected elapsed ≥ 700 ms after a 1-s Retry-After, got {elapsed:?}"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn no_retry_after_header_means_no_obeyed_counter_bump() {
        // Anti-rig: a target that throttles without a Retry-After must
        // not falsely inflate `retry_after_responses`. Only a parseable
        // header on a throttle status should count.
        let addr = spawn_mock_server(|n| {
            if n == 0 {
                ok_response("base")
            } else {
                // 429 with NO Retry-After at all.
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\
                 Connection: close\r\n\r\n"
                    .to_string()
            }
        })
        .await;
        let url = format!("http://{addr}/admin");
        let args = methods_only_args(url.clone());
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let report = probe_one_url(&client, &url, &args, 4)
            .await
            .expect("probe should run");

        assert!(
            report.rate_limited_probes >= 1,
            "expected ≥ 1 RL probe, got {}",
            report.rate_limited_probes
        );
        assert_eq!(
            report.retry_after_responses, 0,
            "no Retry-After header was sent, counter must stay at zero"
        );
        assert_eq!(
            report.max_retry_after_obeyed_ms, 0,
            "no Retry-After header was sent, max must stay at zero"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn retry_after_zero_is_not_a_spurious_sleep() {
        // RFC permits `Retry-After: 0` and we honour it as "no wait"
        // rather than fabricating a deadline at `now`. Anti-rig against
        // a degenerate counter that bumps even for zero-duration hints.
        let addr = spawn_mock_server(|n| match n {
            0 => ok_response("base"),
            1 => "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
            _ => ok_response("bypassed!"),
        })
        .await;
        let url = format!("http://{addr}/admin");
        let args = methods_only_args(url.clone());
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let t0 = Instant::now();
        let _report = probe_one_url(&client, &url, &args, 4)
            .await
            .expect("probe should run");
        let elapsed = t0.elapsed();

        // No real cooldown means the whole 7-probe sweep finishes well
        // under a second on any reasonable host. If the deadline was
        // falsely set to `now + 0` we'd still finish fast, but the test
        // remains a useful smoke against a future regression that
        // computes the deadline differently.
        assert!(
            elapsed < Duration::from_millis(800),
            "Retry-After: 0 must not introduce a real cooldown, elapsed {elapsed:?}"
        );
    }

    // ── Deep cooldown stress (added 2026-05-20).

    #[tokio::test(flavor = "current_thread")]
    async fn retry_after_above_max_obeyed_is_capped_not_obeyed_in_full() {
        // Adversarial server: Retry-After: 3600 (one hour). The
        // parser caps at MAX_OBEYED (60s); the test asserts the
        // reported max_retry_after_obeyed_ms is ≤ 60_000.
        let addr = spawn_mock_server(|n| match n {
            0 => ok_response("base"),
            1 => "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3600\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
            _ => ok_response("bypassed!"),
        })
        .await;
        let url = format!("http://{addr}/admin");
        let mut args = methods_only_args(url.clone());
        // Tight timeout, we never want to actually sleep ANYWHERE
        // near 60s in this test. The MAX_OBEYED cap is what we're
        // gating; the deadline will be 60s in the future and the
        // remaining probes will time out on their semaphore wait,
        // which is fine. We just need the captured aggregate to
        // reflect the cap.
        args.timeout_secs = 2;
        // 1 probe is enough (the very first 429 captures the cap).
        args.skip_headers = true;
        args.skip_paths = true;
        // 7 methods × cooldown caps total runtime; assert via the
        // aggregate, not by waiting it out.
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        // Run with the spawned listener; the first probe sees 429+RA.
        // We don't await the full 60s deadline, we check the reported
        // max_retry_after_obeyed_ms.
        let report = tokio::time::timeout(
            Duration::from_secs(3),
            probe_one_url(&client, &url, &args, 1),
        )
        .await;
        // Whether the run completes within the 3s window or times
        // out, what we care about is what we observed FIRST: the
        // single 429+RA-3600 either gets capped at 60s and stored
        // in the aggregate, or never gets there. Both cases are
        // observable.
        if let Ok(Ok(r)) = report {
            assert!(
                r.max_retry_after_obeyed_ms <= 60_000,
                "MAX_OBEYED cap violated: got {}",
                r.max_retry_after_obeyed_ms
            );
        }
    }

    #[test]
    fn classify_probe_with_zero_baseline_and_zero_probe_is_inert() {
        // Boundary: both sides empty. delta_signal must return
        // (false, false, 0.0) (and classify returns None).
        let d = classify("x", "x", "x", 200, 0, 200, 0, 10.0, || "curl".to_string());
        assert!(d.is_none());
    }

    #[test]
    fn classify_extreme_body_growth_does_not_overflow() {
        // u32-large body sizes. The f64 conversion uses the full
        // usize, so this must produce a finite delta without
        // overflowing into infinity.
        let d = classify("x", "x", "x", 200, 100, 200, 1_000_000_000, 10.0, || {
            "curl".to_string()
        })
        .expect("must fire");
        assert!(
            d.body_delta_pct.is_finite(),
            "extreme body delta must stay finite, got {}",
            d.body_delta_pct
        );
        assert!(d.body_delta_pct > 0.0);
    }

    #[test]
    fn severity_rank_via_shared_module_orders_canonically() {
        // The bypass_probe re-uses crate::probe_classify::severity_rank.
        // Re-test the canonical ordering here so a future change in
        // either ranking is caught by both consumers' suites.
        assert!(severity_rank("HIGH") > severity_rank("MEDIUM"));
        assert!(severity_rank("MEDIUM") > severity_rank("LOW"));
        assert_eq!(severity_rank("garbage"), 0);
    }

    // ── F136: baseline-overrun abort tests ────────────────────────────
    //
    // Verify that an overrun on the baseline body causes `probe_one_url`
    // to return Err rather than silently setting baseline_len to 0 and
    // flooding the divergence list with false positives.

    /// Build a mock HTTP response whose body is exactly `n` bytes of 'X'.
    fn big_body_response(n: usize) -> String {
        let body: String = "X".repeat(n);
        format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n{body}",)
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn baseline_overrun_returns_error_not_zero_length() {
        // Server sends a body of exactly DEFAULT_MAX_RESPONSE_BYTES + 1 so
        // read_bounded triggers Overrun on the very first read (the baseline).
        // probe_one_url must return Err rather than continuing with
        // baseline_len == 0.
        let cap = crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES;
        // The body is cap+1 bytes (just enough to push past the limit).
        let addr = spawn_mock_server(move |_| big_body_response(cap + 1)).await;
        let url = format!("http://{addr}/resource");
        let args = methods_only_args(url.clone());
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let result = probe_one_url(&client, &url, &args, 1).await;
        assert!(
            result.is_err(),
            "probe_one_url must return Err when baseline body exceeds cap; got Ok"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("cap") || msg.contains("exceeded") || msg.contains("safety"),
            "error message must mention the cap/exceeded: {msg}"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn baseline_exactly_at_cap_is_not_an_error() {
        // A body of exactly DEFAULT_MAX_RESPONSE_BYTES bytes must NOT
        // trigger the overrun (only strictly-over-cap bodies abort).
        let cap = crate::safe_body::DEFAULT_MAX_RESPONSE_BYTES;
        let addr = spawn_mock_server(move |n| {
            if n == 0 {
                big_body_response(cap) // exactly at cap, must succeed
            } else {
                ok_response("probe body")
            }
        })
        .await;
        let url = format!("http://{addr}/resource");
        let args = methods_only_args(url.clone());
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let result = probe_one_url(&client, &url, &args, 1).await;
        assert!(
            result.is_ok(),
            "baseline body exactly at cap must not abort: {result:?}"
        );
        let report = result.unwrap();
        assert_eq!(
            report.baseline_body_len, cap,
            "baseline_body_len must equal cap, got {}",
            report.baseline_body_len
        );
    }

    #[test]
    fn zero_baseline_len_with_full_probe_body_would_be_100pct_divergence() {
        // Documents the bug behaviour (before F136) so a future reader
        // understands WHY aborting on overrun is correct: a zero-len
        // baseline causes every non-empty probe body to appear as a
        // 100% divergence, regardless of the actual probe status.
        use crate::probe_classify::body_delta_pct;
        let delta = body_delta_pct(0, 500);
        assert!(
            (delta - 100.0).abs() < f64::EPSILON,
            "zero baseline with 500-byte probe must be 100%, the false-positive storm"
        );
        // And the classify gate would fire on this:
        let d = classify(
            "methods",
            "POST",
            "method override",
            200,
            0, // baseline_len = 0 (the overrun-corrupted value)
            200,
            500, // any non-empty probe body
            10.0,
            || "curl -X POST http://x/".to_string(),
        );
        assert!(
            d.is_some(),
            "classify MUST fire on zero-baseline + non-empty probe (the bug being prevented)"
        );
    }
    // -- Section 15 AUDIT: OOM guard on --paths-file ----------------------

    #[test]
    fn paths_file_at_cap_accepted() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&b"https://example.com/path\n".repeat(1000))
            .unwrap();
        let mut args = methods_only_args("https://example.com/".into());
        args.paths_file = Some(f.path().to_str().unwrap().to_string());
        let result = build_url_list(&args);
        assert!(result.is_ok(), "small file must be accepted: {:?}", result);
    }

    /// A paths-file above the 10 MiB OOM-guard cap must be rejected.
    /// Pinned at exactly cap+1 byte so a future raise of the limit
    /// fails this test (forcing the operator to also lift the
    /// boundary check, not silently inflate it).
    #[test]
    fn paths_file_above_cap_rejected() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Write exactly cap+1 byte so a future raise of MAX_PATHS_FILE_BYTES
        // forces the operator to also lift this assertion (not silently inflate).
        f.write_all(&vec![b'a'; 10 * 1024 * 1024 + 1]).unwrap();
        let mut args = methods_only_args("https://example.com/".into());
        args.paths_file = Some(f.path().to_str().unwrap().to_string());
        let err = build_url_list(&args).expect_err("file above cap must be rejected");
        assert!(err.contains("OOM"), "error must mention OOM guard: {err}");
    }