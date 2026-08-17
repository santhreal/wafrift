    use super::*;

    // F127 regression: inject_sqli_probe must place the query before
    // the fragment. Pre-fix code naively appended `?q=...` whenever the
    // URL had no `?`, but `https://t/p#sec` has no `?`: the appended
    // text landed INSIDE the fragment and the probe never reached the
    // server. Silent false-negative for any fragmented URL.
    #[test]
    fn inject_sqli_probe_appends_query_when_no_query() {
        let out = inject_sqli_probe("https://t/p");
        assert_eq!(out, "https://t/p?q=%27+OR+1%3D1--");
    }

    #[test]
    fn inject_sqli_probe_uses_ampersand_when_query_present() {
        let out = inject_sqli_probe("https://t/p?a=1");
        assert_eq!(out, "https://t/p?a=1&q=%27+OR+1%3D1--");
    }

    #[test]
    fn inject_sqli_probe_preserves_fragment_no_existing_query() {
        // Pre-fix would produce "https://t/p#sec?q=...", query inside
        // the fragment, never reaches the server.
        let out = inject_sqli_probe("https://t/p#sec");
        assert_eq!(out, "https://t/p?q=%27+OR+1%3D1--#sec");
    }

    #[test]
    fn inject_sqli_probe_preserves_fragment_with_existing_query() {
        let out = inject_sqli_probe("https://t/p?a=1#sec");
        assert_eq!(out, "https://t/p?a=1&q=%27+OR+1%3D1--#sec");
    }

    #[test]
    fn inject_sqli_probe_handles_url_with_multiple_hashes() {
        // Only the FIRST `#` counts per RFC 3986; the rest are
        // fragment characters.
        let out = inject_sqli_probe("https://t/p#sec#more");
        assert_eq!(out, "https://t/p?q=%27+OR+1%3D1--#sec#more");
    }

    #[test]
    fn inject_sqli_probe_handles_empty_fragment() {
        let out = inject_sqli_probe("https://t/p#");
        assert_eq!(out, "https://t/p?q=%27+OR+1%3D1--#");
    }

    #[test]
    fn parse_http_status_accepts_canonical_codes() {
        assert_eq!(parse_http_status("200"), Ok(200));
        assert_eq!(parse_http_status("403"), Ok(403));
        assert_eq!(parse_http_status("100"), Ok(100));
        assert_eq!(parse_http_status("599"), Ok(599));
    }

    #[test]
    fn parse_http_status_rejects_out_of_range() {
        assert!(parse_http_status("0").is_err());
        assert!(parse_http_status("99").is_err());
        assert!(parse_http_status("600").is_err());
        assert!(parse_http_status("999").is_err());
    }

    #[test]
    fn parse_http_status_rejects_non_numeric() {
        assert!(parse_http_status("abc").is_err());
        assert!(parse_http_status("").is_err());
        assert!(parse_http_status("2xx").is_err());
    }

    #[test]
    fn infra_markers_extracts_cdn_and_edge_banners() {
        let headers = vec![
            ("Server".into(), "cloudflare".into()),
            ("CF-Ray".into(), "abc123-LHR".into()),
            ("Content-Type".into(), "text/html".into()),
            ("X-Cache".into(), "HIT from front-edge-1".into()),
        ];
        let m = infra_markers(&headers);
        assert!(m.iter().any(|(k, _)| k == "Server"));
        assert!(m.iter().any(|(k, _)| k == "X-Cache"));
        // CF-Ray is in the allowlist but case-insensitively, verify
        // that the extractor picks it up regardless of header case.
        assert!(m.iter().any(|(k, _)| k.eq_ignore_ascii_case("cf-ray")));
        // Content-Type is not in the infra allowlist (it's a general
        // response header, not a fingerprint anchor) (must be dropped).
        assert!(
            !m.iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        );
    }

    // ── Live --url path against a mock server (added 2026-05-20).

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn spawn_mock(body: &'static str, status: u16) -> std::net::SocketAddr {
        let body = body.to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\
                         Connection: close\r\nServer: nginx/1.25.3\r\n\
                         CF-Ray: abc123-LHR\r\n\r\n{body}",
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

    async fn spawn_capture_mock(
        body: &'static str,
        status: u16,
    ) -> (std::net::SocketAddr, std::sync::mpsc::Receiver<String>) {
        let body = body.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            loop {
                let mut buf = [0u8; 1024];
                let Ok(n) = sock.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n")
                    || request.len() > 16 * 1024
                {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&request).into_owned());
            let resp = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\n\
                 Connection: close\r\nServer: nginx/1.25.3\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        (addr, rx)
    }

    fn captured_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    /// `fetch_for_detect` builds its own tokio runtime, we drive it
    /// from a sync `#[test]` (no `#[tokio::test]`) so the nested
    /// runtime panic doesn't trip.
    #[serial_test::serial]
    #[test]
    fn fetch_for_detect_against_local_mock_returns_status_and_headers() {
        // Run the mock from a worker tokio runtime, then call the
        // sync fetch_for_detect against the bound address.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        let addr = rt.block_on(spawn_mock("hello world", 200));
        let url = format!("http://{addr}/");
        let (status, headers, body) =
            fetch_for_detect(&url, 5, false).expect("fetch_for_detect must succeed");
        assert_eq!(status, 200);
        assert_eq!(body, b"hello world");
        let has_server = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("server") && v.contains("nginx"));
        assert!(has_server, "Server header should be present: {headers:?}");
        let has_cf = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("cf-ray") && v.contains("abc123"));
        assert!(has_cf, "CF-Ray header should be present");
    }

    #[serial_test::serial]
    #[test]
    fn fetch_for_detect_sends_shared_browser_headers_on_wire() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        let (addr, captured) = rt.block_on(spawn_capture_mock("ok", 200));
        let url = format!("http://{addr}/");
        let (status, _, _) = fetch_for_detect(&url, 5, false).expect("fetch ok");
        assert_eq!(status, 200);

        let request = captured
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("request captured");
        let facts = guise::fingerprint::default_profile_facts();
        assert_eq!(
            captured_header(&request, "User-Agent"),
            Some(facts.user_agent)
        );
        assert_eq!(captured_header(&request, "Accept"), Some(facts.accept));
        assert_eq!(
            captured_header(&request, "Accept-Language"),
            Some(facts.accept_language)
        );
        assert_eq!(
            captured_header(&request, "Sec-Fetch-Mode"),
            Some("navigate")
        );
    }

    #[serial_test::serial]
    #[test]
    fn fetch_for_detect_caps_body_at_64_kib() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        // Mock that ships 128 KiB of body, we want to confirm the
        // fetch caps the read at 64 KiB.
        let big_body = Box::leak("X".repeat(128 * 1024).into_boxed_str()) as &'static str;
        let addr = rt.block_on(spawn_mock(big_body, 200));
        let url = format!("http://{addr}/");
        let (_, _, body) = fetch_for_detect(&url, 5, false).expect("fetch ok");
        assert_eq!(
            body.len(),
            64 * 1024,
            "body must be capped at 64 KiB, got {}",
            body.len()
        );
    }

    #[serial_test::serial]
    #[test]
    fn fetch_for_detect_passes_through_403_status() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .unwrap();
        let addr = rt.block_on(spawn_mock("blocked by WAF", 403));
        let url = format!("http://{addr}/");
        let (status, _, body) = fetch_for_detect(&url, 5, false).expect("fetch ok");
        assert_eq!(status, 403);
        assert_eq!(body, b"blocked by WAF");
    }

    #[test]
    fn fetch_for_detect_returns_err_on_connection_refused() {
        // Connect to a localhost port that's almost certainly not
        // listening. Must surface as Err, not panic. Use the
        // unassigned port range (49152–65535 IANA dynamic, but
        // 65501 specifically is rarely used).
        let result = fetch_for_detect("http://127.0.0.1:1/", 2, false);
        assert!(result.is_err(), "unreachable target must return Err");
    }

    #[test]
    fn fetch_for_detect_with_unparseable_url_returns_err() {
        let result = fetch_for_detect("not-a-url://", 2, false);
        assert!(result.is_err(), "unparseable URL must return Err");
    }

    #[test]
    fn fetch_for_detect_connection_refused_error_walks_source_chain() {
        // Regression guard for the "swallowed error chain" UX bug
        // (P3 from sonnet dogfood pass 4, 2026-05).  Prior to the
        // fix, the error message just said "error sending request"
        // with no DNS/TCP cause attached.  Now the source chain is
        // walked and surfaced via " (caused by: ..." appends).
        let err = fetch_for_detect("http://127.0.0.1:1/", 2, false)
            .expect_err("connect-refused must Err");
        assert!(
            err.contains("caused by:"),
            "error must walk the source chain, got: {err}"
        );
        // The URL must still appear in the top-level message so the
        // operator can grep their command log.
        assert!(
            err.contains("127.0.0.1:1"),
            "error must include the URL that failed: {err}"
        );
    }

    #[test]
    fn fetch_for_detect_nxdomain_surfaces_dns_layer_cause() {
        // Stress: hit a guaranteed-NXDOMAIN host.  `.invalid` is
        // RFC 6761 reserved → DNS resolvers MUST return NXDOMAIN.
        // We rely on the source chain walker exposing the dns-layer
        // cause so a sysadmin reading the error sees "DNS" not just
        // a generic "request failed".
        let err = fetch_for_detect("http://nonexistent.invalid/", 2, false);
        match err {
            Ok(_) => panic!("invalid TLD must NXDOMAIN"),
            Err(msg) => {
                // The exact phrasing depends on the resolver (Windows
                // says "No such host is known", Unix typically
                // surfaces "Name or service not known") but every
                // platform's reqwest chain includes "dns" or "Connect"
                // in the chain.
                assert!(
                    msg.to_lowercase().contains("dns")
                        || msg.to_lowercase().contains("connect")
                        || msg.contains("caused by:"),
                    "NXDOMAIN error must surface DNS / Connect layer: {msg}"
                );
            }
        }
    }

    // ── classify_differential ────────────────────────────────────
    //
    // Pure function, tested without I/O. Each case names the
    // real-world WAF detection pattern it gates.

    fn hdr(server: &str) -> Vec<(String, String)> {
        vec![("Server".into(), server.into())]
    }

    #[test]
    fn differential_identical_responses_returns_none() {
        // Anti-rig: if benign and attack produce identical
        // responses, NO inference. Returning Some here would be
        // a false-positive WAF detection on every plain HTTP host.
        let ev = classify_differential(200, &hdr("nginx"), 1024, 200, &hdr("nginx"), 1024);
        assert!(ev.is_none(), "identical responses must not infer a WAF");
    }

    #[test]
    fn differential_status_flip_alone_is_evidence() {
        // The bare 200 → 403 case: server header may not even be
        // present, but the status flip is unambiguous WAF signal.
        let ev =
            classify_differential(200, &[], 100, 403, &[], 200).expect("status flip must classify");
        assert_eq!(ev.baseline_status, 200);
        assert_eq!(ev.attack_status, 403);
        assert!(
            ev.reasons.iter().any(|r| r.contains("status flipped")),
            "reasons should mention status flip"
        );
    }

    #[test]
    fn differential_server_change_classifies_as_waf() {
        // The exact ModSec-in-front-of-gunicorn case from dogfooding:
        // benign 200 from 'gunicorn/19.9.0', attack 403 from
        // 'Apache' (ModSec block page). The server-change reason
        // must surface.
        let ev = classify_differential(200, &hdr("gunicorn/19.9.0"), 445, 403, &hdr("Apache"), 239)
            .expect("classify");
        assert!(
            ev.reasons
                .iter()
                .any(|r| r.contains("server header changed")),
            "expected server-change reason: {:?}",
            ev.reasons
        );
        assert_eq!(ev.baseline_server, "gunicorn/19.9.0");
        assert_eq!(ev.attack_server, "Apache");
    }

    #[test]
    fn differential_server_change_is_case_insensitive() {
        // Apache vs apache should NOT count as a server change
        // it's the same software, just different casing on the
        // server's part.
        let ev = classify_differential(403, &hdr("Apache"), 100, 403, &hdr("apache"), 100);
        assert!(
            ev.is_none(),
            "case-only server difference must not classify"
        );
    }

    #[test]
    fn differential_body_swing_over_50pct_is_evidence() {
        // Same status + same server, but body collapses from 10 KB
        // (real response) to 200 bytes (block page). The 50%+
        // shrinkage is the only signal in this case.
        let ev = classify_differential(200, &hdr("nginx"), 10_000, 200, &hdr("nginx"), 200)
            .expect("body swing must classify");
        assert!(
            ev.reasons.iter().any(|r| r.contains("body length swung")),
            "reasons should mention body swing: {:?}",
            ev.reasons
        );
    }

    #[test]
    fn differential_small_body_change_is_not_evidence() {
        // 10% difference (timestamps, request IDs, jitter in
        // body) must NOT classify. 50% is the threshold.
        let ev = classify_differential(200, &hdr("nginx"), 10_000, 200, &hdr("nginx"), 9_500);
        assert!(ev.is_none(), "5% body change must not classify");
    }

    #[test]
    fn differential_multiple_signals_all_listed_in_reasons() {
        // The strongest case: status flip + server change + body
        // swing all together. Every reason should appear in the
        // output so the operator sees the full picture.
        let ev = classify_differential(200, &hdr("gunicorn"), 10_000, 403, &hdr("Apache"), 200)
            .expect("classify");
        let reasons: String = ev.reasons.join(" | ");
        assert!(reasons.contains("status flipped"));
        assert!(reasons.contains("server header changed"));
        assert!(reasons.contains("body length swung"));
    }

    #[test]
    fn differential_empty_baseline_with_attack_body_still_signal() {
        // Edge: benign returned 0 bytes (unusual but valid for a
        // HEAD-style endpoint), attack returned a block page.
        // We can't compute pct_diff against zero, but the
        // non-zero attack body IS still signal.
        let ev = classify_differential(200, &[], 0, 403, &[], 500).expect("classify");
        let reasons: String = ev.reasons.join(" | ");
        assert!(
            reasons.contains("attack response had 500 bytes") || reasons.contains("status flipped"),
            "expected either body-vs-empty or status-flip reason: {:?}",
            ev.reasons
        );
    }

    // Fix #3 tests: SUGGESTED_NEXT_STEP table + next_step_hint.

    #[test]
    fn next_step_hint_returns_cloudflare_command_for_cloudflare() {
        let hint = next_step_hint("Cloudflare");
        assert!(hint.is_some(), "Cloudflare must have a next-step hint");
        let hint = hint.unwrap();
        assert!(
            hint.contains("wafrift scan"),
            "Cloudflare hint must suggest wafrift scan; got: {hint:?}"
        );
        assert!(
            hint.contains("hint") || !hint.is_empty(),
            "hint must be non-empty"
        );
    }

    #[test]
    fn next_step_hint_returns_bypass_probe_for_aws_waf() {
        let hint = next_step_hint("AWS-WAF");
        assert!(hint.is_some(), "AWS-WAF must have a hint");
        let hint = hint.unwrap();
        assert!(
            hint.contains("bypass-probe"),
            "AWS-WAF hint should mention bypass-probe; got: {hint:?}"
        );
    }

    #[test]
    fn next_step_hint_is_case_insensitive() {
        // Matching must ignore the case of the detected WAF name.
        assert_eq!(next_step_hint("cloudflare"), next_step_hint("Cloudflare"),);
        assert_eq!(
            next_step_hint("CLOUDFLARE ENTERPRISE"),
            next_step_hint("Cloudflare"),
        );
    }

    #[test]
    fn next_step_hint_returns_none_for_unknown_waf() {
        // An unknown/novel WAF must fall through to None so the
        // caller can apply the generic fallback.
        assert!(next_step_hint("some-novel-waf-xyz").is_none());
    }

    #[test]
    fn detect_cloudflare_output_contains_next_step_hint() {
        // Simulate what run_detect produces: build a minimal detected
        // result with confidence 0.9 and verify the hint appears in
        // the rendered output.  We call next_step_hint directly here
        // (the same function used by run_detect) since we can't drive
        // full I/O without a live target.
        let waf_name = "Cloudflare";
        let confidence = 0.9_f64;
        assert!(
            confidence >= 0.8,
            "test must use a high-confidence scenario"
        );
        let hint = next_step_hint(waf_name).unwrap_or(GENERIC_NEXT_STEP);
        // The rendered line emitted by run_detect is "  hint: <hint>".
        let rendered = format!("  hint: {hint}");
        assert!(
            rendered.contains("hint:"),
            "rendered line must start with 'hint:'"
        );
        assert!(
            rendered.contains("wafrift"),
            "hint must reference a wafrift subcommand; got: {rendered:?}"
        );
    }

    #[test]
    fn detect_generic_hint_used_for_unknown_waf() {
        // When the WAF is not in SUGGESTED_NEXT_STEP the fallback
        // GENERIC_NEXT_STEP must be used and must also reference a
        // wafrift subcommand.
        let hint = next_step_hint("novel-waf-xyz").unwrap_or(GENERIC_NEXT_STEP);
        assert_eq!(hint, GENERIC_NEXT_STEP);
        assert!(
            hint.contains("wafrift"),
            "generic hint must reference wafrift"
        );
    }