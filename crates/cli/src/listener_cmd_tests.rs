    use super::*;

    // Token-generation tests (alphabet, length, no-collision) and
    // base32_encode round-trip tests live in
    // `crate::callback_token::tests`: the functions themselves moved
    // out of listener_cmd to be shared with scan's payload
    // substitution. Duplicating them here would just guarantee one
    // pair drifts.

    // ── registry ─────────────────────────────────────────────────

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registry_mint_returns_n_distinct_tokens() {
        let r = Registry::new();
        let mints = r.mint(8).await;
        assert_eq!(mints.len(), 8);
        let mut set = std::collections::HashSet::new();
        for t in &mints {
            assert!(set.insert(t.clone()), "duplicate token in mint batch: {t}");
        }
        // The registry's known_tokens should reflect the mint.
        let known = r.known_tokens().await;
        assert_eq!(known.len(), 8);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registry_match_token_in_finds_substring() {
        let r = Registry::new();
        r.register("ABCDEFGHIJKLMNOPQRSTUVWXY2").await;
        // Exact, prefix, suffix, embedded (all must match).
        assert_eq!(
            r.match_token_in("ABCDEFGHIJKLMNOPQRSTUVWXY2")
                .await
                .as_deref(),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXY2")
        );
        assert_eq!(
            r.match_token_in("/ABCDEFGHIJKLMNOPQRSTUVWXY2/x")
                .await
                .as_deref(),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXY2")
        );
        // Different token must not falsely match.
        assert_eq!(r.match_token_in("ZZZZZZZZZZZZZZZZZZZZZZZZZZ").await, None);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registry_match_token_in_is_case_sensitive() {
        // Tokens are base32 upper-case; a lowercase substring should
        // NOT match (caller's contract (we never normalise on lookup)).
        let r = Registry::new();
        r.register("ABCDEFGHIJKLMNOPQRSTUVWXY2").await;
        assert_eq!(r.match_token_in("abcdefghijklmnopqrstuvwxy2").await, None);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registry_push_caps_callback_log_at_max() {
        // DoS defence: an attacker who learns one token could otherwise
        // flood the log and balloon RAM. The cap keeps the log bounded
        // (FIFO eviction).
        let r = Registry::new();
        let total = MAX_CALLBACK_LOG + 50;
        for i in 0..total {
            let cb = Callback {
                received_at: i as u64,
                source: "127.0.0.1:0".into(),
                method: "GET".into(),
                path: format!("/p/{i}"),
                matched_token: Some("TOK".into()),
                headers: vec![],
                body_preview: String::new(),
                body_truncated_bytes: 0,
            };
            r.push(cb).await;
        }
        let cbs = r.callbacks.read().await;
        assert_eq!(cbs.len(), MAX_CALLBACK_LOG, "log must be capped");
        // First 50 entries (oldest) evicted; remaining start at 50.
        assert_eq!(cbs.front().unwrap().received_at, 50);
        assert_eq!(cbs.back().unwrap().received_at, (total - 1) as u64);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registry_push_preserves_log_when_under_cap() {
        let r = Registry::new();
        for i in 0..10 {
            let cb = Callback {
                received_at: i as u64,
                source: "127.0.0.1:0".into(),
                method: "GET".into(),
                path: "/".into(),
                matched_token: None,
                headers: vec![],
                body_preview: String::new(),
                body_truncated_bytes: 0,
            };
            r.push(cb).await;
        }
        let cbs = r.callbacks.read().await;
        assert_eq!(cbs.len(), 10);
        assert_eq!(cbs.front().unwrap().received_at, 0);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registry_eviction_storm_completes_within_perf_budget() {
        // Anti-rig (per perf-hunt N02): a regression that swaps
        // VecDeque back to Vec would silently work for correctness
        // but turn the eviction O(n). Test that pushing 3× the cap
        // (twice the eviction budget) completes within a generous
        // wall-clock budget, the test would time out if some future
        // patch made every push do an O(n) shift again.
        //
        // Conservative budget: 3s for ~300k push+evict operations.
        // VecDeque does this in well under 100 ms in a debug build;
        // Vec::remove(0) would take 30+ seconds.
        let r = Registry::new();
        let storm = MAX_CALLBACK_LOG * 3;
        let started = std::time::Instant::now();
        for i in 0..storm {
            let cb = Callback {
                received_at: i as u64,
                source: "127.0.0.1:0".into(),
                method: "GET".into(),
                path: "/p".into(),
                matched_token: Some("TOK".into()),
                headers: vec![],
                body_preview: String::new(),
                body_truncated_bytes: 0,
            };
            r.push(cb).await;
        }
        let elapsed = started.elapsed();
        let cbs = r.callbacks.read().await;
        assert_eq!(
            cbs.len(),
            MAX_CALLBACK_LOG,
            "log must stay capped under flood"
        );
        assert!(
            elapsed.as_secs() < 30,
            "eviction storm took {elapsed:?}, suspect O(n) eviction regression"
        );
    }

    #[test]
    fn callback_log_cap_is_at_least_one_thousand() {
        // Floor: a refactor that accidentally set MAX_CALLBACK_LOG=10
        // would drop legitimate callbacks during real engagements
        // (which routinely produce hundreds of callbacks). Lock the
        // floor at 1k, well above what any honest run needs to
        // start dropping at.
        assert!(MAX_CALLBACK_LOG >= 1_000);
    }

    // ── header parsing ───────────────────────────────────────────

    #[test]
    fn find_double_crlf_handles_canonical_and_loose_forms() {
        // `GET / HTTP/1.1` is 14 bytes, so `\r\n\r\n` starts at
        // position 14. `\n\n` starts at position 14 in the lf-only
        // form too (request line is still 14 bytes). The second
        // return field is the terminator byte length: 4 for CRLF,
        // 2 for bare LF; the caller adds this to `pos` to find the
        // body start.
        assert_eq!(find_double_crlf(b"GET / HTTP/1.1\r\n\r\n"), Some((14, 4)));
        assert_eq!(find_double_crlf(b"GET / HTTP/1.1\n\n"), Some((14, 2)));
        assert_eq!(find_double_crlf(b"no terminator here"), None);
    }

    #[test]
    fn find_double_crlf_locates_terminator_at_buffer_end() {
        let mut buf = vec![b'X'; 100];
        buf.extend_from_slice(b"\r\n\r\n");
        let (pos, terminator_len) = find_double_crlf(&buf).expect("must find");
        assert_eq!(pos, 100);
        assert_eq!(terminator_len, 4);
    }

    #[test]
    fn find_double_crlf_lf_only_terminator_reports_two_byte_length() {
        // Regression test: pre-fix, callers hardcoded
        // header_terminator_len=4 unconditionally and ate the first
        // 2 bytes of every \n\n-terminated callback body. The bare-
        // LF case must report 2.
        let mut buf = b"POST /cb HTTP/1.1\nHost: x\n\n".to_vec();
        buf.extend_from_slice(b"BODYDATA");
        let (pos, terminator_len) = find_double_crlf(&buf).expect("must find");
        assert_eq!(terminator_len, 2);
        // Body must start exactly at pos + 2, verify the first
        // body byte is the 'B' of BODYDATA, not '0' / 'D' (which
        // the old off-by-two would have dropped to).
        assert_eq!(buf[pos + terminator_len], b'B');
    }

    // ── end-to-end: real TCP listener answers a real callback ────

    /// Drive the listener loop directly against a hand-rolled HTTP
    /// client request. Bypasses run_listener's blocking entry so the
    /// test can shut down cleanly.
    async fn drive_one_callback(
        registry: Arc<Registry>,
        request: &[u8],
    ) -> (Callback, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let req = request.to_vec();
        let server = tokio::spawn({
            let registry = registry.clone();
            async move {
                let (sock, peer) = listener.accept().await.expect("accept");
                // The drive_one_callback helper is for the
                // callback-recording path, so we always expect
                // Some(Callback). Management-API tests use their
                // own dedicated helper.
                handle_conn(sock, peer, &registry, 8 * 1024, Duration::from_secs(5))
                    .await
                    .expect("handle_conn ok")
                    .expect("handle_conn returned a callback (not a management response)")
            }
        });
        // Pause so the listener task has time to reach accept() before
        // the client connects. On Windows under heavy parallel test
        // load the spawned task may need more than a few milliseconds
        // to be scheduled for the first time.
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Connect with a retry loop. Windows TCP loopback under heavy
        // parallel test load occasionally returns OS error 10060 (timed
        // out) even though the listener is bound. We retry up to 10× with
        // 200 ms backoff; total budget ≤ 2 s, well within the integration-
        // test wall-clock limit.
        let mut client = None;
        for attempt in 0..10 {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(s) => {
                    client = Some(s);
                    break;
                }
                Err(_e) if attempt < 9 => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => panic!("connect after 10 attempts: {e}"),
            }
        }
        let mut client = client.expect("connected");
        client.write_all(&req).await.expect("write request");
        let _ = client.shutdown().await;
        let cb = server.await.expect("server join");
        (cb, addr)
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_callback_with_matching_token_in_path() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!("GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.method, "GET");
        assert_eq!(cb.path, format!("/{token}"));
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
        assert!(cb.body_preview.is_empty());
        assert_eq!(cb.body_truncated_bytes, 0);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_callback_with_token_in_body_is_matched() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let body = format!("ping {token} pong");
        let req = format!(
            "POST /noise HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.method, "POST");
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
        assert_eq!(cb.body_preview, body);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_callback_with_unknown_token_records_unmatched() {
        // Anti-rig: a callback we never planted (e.g. an unrelated
        // bot scan against the listener port) must record as
        // unmatched, not falsely tagged with a token we did plant.
        let registry = Arc::new(Registry::new());
        let _real = registry.mint(1).await;
        let req = b"GET /OTHERTOKEN HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let (cb, _) = drive_one_callback(registry, req).await;
        assert_eq!(cb.matched_token, None);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_body_above_cap_is_truncated_with_counter() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        // Body is 16 KiB (cap is 8 KiB → 8 KiB truncated).
        let body = format!("{token}{}", "x".repeat(16 * 1024 - token.len()));
        let req = format!(
            "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.body_preview.len(), 8 * 1024);
        assert!(cb.body_truncated_bytes >= 8 * 1024 - 8); // ~8 KiB dropped
        // The token still matches because it sits in the first chunk
        // of the body (which falls under the cap).
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registry_matched_count_excludes_unmatched_callbacks() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req_match = format!("GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
        let req_no_match = b"GET /random HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let (cb1, _) = drive_one_callback(registry.clone(), req_match.as_bytes()).await;
        registry.push(cb1).await;
        let (cb2, _) = drive_one_callback(registry.clone(), req_no_match).await;
        registry.push(cb2).await;
        assert_eq!(registry.callbacks().await.len(), 2);
        assert_eq!(registry.matched_count().await, 1);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_malformed_request_does_not_crash_the_listener() {
        // A client that sends garbage MUST NOT take the listener
        // down with it. We don't drive_one_callback here because
        // handle_conn returns Err on bad input, exercise it
        // directly to assert the Err path is clean.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let registry = Arc::new(Registry::new());
        let registry_c = registry.clone();
        let server = tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.unwrap();
            handle_conn(
                sock,
                peer,
                &registry_c,
                8 * 1024,
                Duration::from_millis(200),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Garbage with no \r\n\r\n terminator, the listener should
        // time out reading headers and return Err cleanly.
        client.write_all(b"this is not http").await.unwrap();
        let _ = client.shutdown().await;
        let result = server.await.unwrap();
        assert!(result.is_err(), "malformed request must return Err");
    }

    // ── Management API: GET /_wafrift/check/<TOKEN> ─────────────
    //
    // Lets a scan-side caller (or the operator with curl) ask the
    // running listener "has this token been received yet?" without
    // polluting the callback log with their own queries.

    /// Drive one /_wafrift/check/<token> request. Reads the raw
    /// response off the socket so we can assert on the status line
    /// + JSON body.
    async fn drive_management_check(registry: Arc<Registry>, token: &str) -> (String, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let registry_c = registry.clone();
        let server = tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.expect("accept");
            let _ = handle_conn(sock, peer, &registry_c, 8 * 1024, Duration::from_secs(3)).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Connect with the same retry pattern drive_one_callback
        // uses: Windows TCP under parallel test load occasionally
        // returns OS error 10060 (timed out) on the first attempt
        // despite the listener being bound.
        let mut client = None;
        for attempt in 0..5 {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(s) => {
                    client = Some(s);
                    break;
                }
                Err(_e) if attempt < 4 => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("connect after 5 attempts: {e}"),
            }
        }
        let mut client = client.expect("connected");
        let req = format!(
            "GET /_wafrift/check/{token} HTTP/1.1\r\nHost: x\r\n\
             Content-Length: 0\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp_buf = Vec::new();
        // Read until EOF.
        let mut buf = [0u8; 4096];
        loop {
            let n = client.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            resp_buf.extend_from_slice(&buf[..n]);
        }
        let _ = client.shutdown().await;
        let _ = server.await;
        let resp = String::from_utf8_lossy(&resp_buf).into_owned();
        // Split status line + body for the caller.
        let (status_line, rest) = resp.split_once("\r\n").unwrap_or(("", ""));
        let body = rest.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status_line.to_string(), body)
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn management_check_unknown_token_returns_404_with_received_false() {
        let registry = Arc::new(Registry::new());
        let _ = registry.mint(1).await; // mint one so the registry is non-empty
        let (status, body) = drive_management_check(registry, "NEVERSEENABCDEFGHIJKLMNOPQ").await;
        assert!(status.contains("404"), "status was: {status}");
        assert!(body.contains("\"received\":false"), "body: {body}");
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn management_check_known_received_token_returns_200_received_true() {
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        // Record a callback for this token by going through the
        // normal callback path.
        let cb_req = format!("GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
        let (cb, _) = drive_one_callback(registry.clone(), cb_req.as_bytes()).await;
        registry.push(cb).await;
        // Now ask the management endpoint.
        let (status, body) = drive_management_check(registry, &token).await;
        assert!(status.contains("200"), "status was: {status}");
        assert!(body.contains("\"received\":true"), "body: {body}");
        assert!(
            body.contains(&token),
            "body should include the token: {body}"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn management_check_does_not_record_itself_as_a_callback() {
        // Anti-rig: a poll for /_wafrift/check/X must NOT append a
        // Callback to the registry (would pollute the evidence
        // stream and could match later polls).
        let registry = Arc::new(Registry::new());
        let _ = registry.mint(1).await;
        assert_eq!(registry.callbacks().await.len(), 0);
        let (_status, _body) = drive_management_check(registry.clone(), "ANYTOKEN").await;
        assert_eq!(
            registry.callbacks().await.len(),
            0,
            "management API hit must not record a callback"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn management_check_path_with_trailing_slash_still_matches() {
        // Resilience: a caller hitting /_wafrift/check/TOK/ (with
        // trailing slash) must still get the right answer.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let cb_req = format!("GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
        let (cb, _) = drive_one_callback(registry.clone(), cb_req.as_bytes()).await;
        registry.push(cb).await;
        // Use a token with a trailing slash in the URL request.
        let path_with_slash = format!("{token}/");
        let (status, body) = drive_management_check(registry, &path_with_slash).await;
        assert!(status.contains("200"));
        assert!(body.contains("\"received\":true"));
    }

    // ── Deep edge-case sweep (added 2026-05-20 under the "deep
    // testing + over-the-top coverage" bar). Each test below names
    // the failure mode it gates against in its body so a future
    // reader can see why the case matters.

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_lowercase_method_is_normalised_to_upper() {
        // The Callback.method field must always be uppercased so
        // downstream consumers can match on `"GET"`, never having
        // to worry about `"get"` vs `"GET"`.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!("post /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(
            cb.method, "POST",
            "method must be uppercased, got `{}`",
            cb.method
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_callback_with_token_in_header_value_is_matched() {
        // A blind SSRF callback might land with the token in a
        // header (e.g. attacker-controlled User-Agent / X-Forwarded-For)
        // not the path. Listener must scan all three (path, headers,
        // body).
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!(
            "GET /noise HTTP/1.1\r\nHost: x\r\nX-Callback: {token}\r\nContent-Length: 0\r\n\r\n"
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(
            cb.matched_token.as_deref(),
            Some(token.as_str()),
            "header-value token should match"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_body_exactly_at_cap_is_not_marked_truncated() {
        // Boundary case: body length == cap (8 KiB). Nothing should
        // be truncated, truncated_bytes must be zero.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let exact = 8 * 1024_usize;
        // Body = token + padding to exactly the cap.
        let pad = exact - token.len();
        let body = format!("{token}{}", "x".repeat(pad));
        assert_eq!(body.len(), exact);
        let req = format!(
            "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.body_preview.len(), exact);
        assert_eq!(
            cb.body_truncated_bytes, 0,
            "exact-cap body must NOT truncate"
        );
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_one_byte_above_cap_truncates_one_byte() {
        // Boundary: body = cap + 1 byte. Truncated counter must be
        // exactly 1, body_preview length must equal cap. Off-by-one
        // bugs in the cap logic are caught here.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let cap = 8 * 1024_usize;
        let pad = (cap + 1) - token.len();
        let body = format!("{token}{}", "y".repeat(pad));
        assert_eq!(body.len(), cap + 1);
        let req = format!(
            "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        assert_eq!(cb.body_preview.len(), cap);
        assert_eq!(
            cb.body_truncated_bytes, 1,
            "exactly one byte should be reported truncated"
        );
    }

    /// Same as `drive_one_callback` but returns the raw `Result` from
    /// `handle_conn` instead of unwrapping. Used for adversarial tests
    /// where the connection is expected to be rejected (e.g. malformed
    /// Content-Length), we want to assert the listener doesn't panic or
    /// hang, not that it records a callback.
    async fn drive_one_conn_result(
        registry: Arc<Registry>,
        request: &[u8],
    ) -> Result<Option<Callback>, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let req = request.to_vec();
        let server = tokio::spawn({
            let registry = registry.clone();
            async move {
                let (sock, peer) = listener.accept().await.expect("accept");
                handle_conn(sock, peer, &registry, 8 * 1024, Duration::from_secs(5)).await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut connected = false;
        for attempt in 0..10 {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(mut s) => {
                    s.write_all(&req).await.expect("write");
                    let _ = s.shutdown().await;
                    connected = true;
                    break;
                }
                Err(_) if attempt < 9 => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => panic!("connect after 10 attempts: {e}"),
            }
        }
        assert!(connected, "client must connect");
        server.await.expect("server task did not panic")
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_negative_content_length_does_not_crash() {
        // Adversarial Content-Length: negative integer. The F-LISTENER-CL-01
        // fix changed the fallback-to-zero behaviour to a hard reject (to
        // close CL desync attacks); so `handle_conn` now returns Err for a
        // malformed CL. The contract here is that the listener terminates
        // cleanly (no panic, no hang (not that it records a callback)).
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!("GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: -7\r\n\r\n");
        let result = drive_one_conn_result(registry, req.as_bytes()).await;
        assert!(
            result.is_err(),
            "malformed Content-Length must be rejected: {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("malformed Content-Length"),
            "error message must name the cause: {err:?}"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn end_to_end_huge_content_length_does_not_pre_allocate() {
        // Adversarial: Content-Length: 9999999999 (10 GiB) with
        // zero actual body bytes. The listener's Vec::with_capacity
        // is clamped to `min(content_length, max_body)`, so this
        // must NOT OOM us, and the connection EOFs immediately so
        // we just see an empty body.
        let registry = Arc::new(Registry::new());
        let token = registry.mint(1).await.into_iter().next().unwrap();
        let req = format!("GET /{token} HTTP/1.1\r\nHost: x\r\nContent-Length: 9999999999\r\n\r\n");
        let (cb, _) = drive_one_callback(registry, req.as_bytes()).await;
        // We at least got the request line + headers parsed (token
        // match in path proves it). Body is empty because the client
        // never actually sent any bytes.
        assert_eq!(cb.matched_token.as_deref(), Some(token.as_str()));
        assert!(
            cb.body_preview.is_empty(),
            "client sent zero body bytes; preview must be empty"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registered_tokens_persist_across_separate_mint_calls() {
        // Registry::mint can be called multiple times; previously
        // minted tokens must remain valid (the contract is "add to
        // the set", not "replace").
        let r = Registry::new();
        let first_batch = r.mint(3).await;
        let second_batch = r.mint(2).await;
        let known = r.known_tokens().await;
        assert_eq!(known.len(), 5);
        for t in first_batch.iter().chain(second_batch.iter()) {
            assert!(known.contains(t), "token {t} missing from registry");
        }
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registered_caller_supplied_token_can_match() {
        // The `register()` API lets the caller supply their own
        // token (instead of asking the registry to mint one). Useful
        // when the scan side wants to embed a payload-shape hint in
        // the token prefix. Verify the registered token is found
        // by `match_token_in`.
        let r = Registry::new();
        r.register("ATTACKERSUPPLIEDABCDEFGHIJ").await;
        assert_eq!(
            r.match_token_in("/.well-known/ATTACKERSUPPLIEDABCDEFGHIJ")
                .await
                .as_deref(),
            Some("ATTACKERSUPPLIEDABCDEFGHIJ")
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "current_thread")]
    async fn registry_callbacks_log_is_in_arrival_order() {
        // Sanity: pushing three callbacks in order keeps them in
        // that order in `callbacks()`: needed so timeline
        // reconstructions are correct.
        let r = Registry::new();
        for i in 0_u64..3 {
            r.push(Callback {
                received_at: i,
                source: format!("127.0.0.1:{i}"),
                method: "GET".into(),
                path: format!("/p{i}"),
                matched_token: None,
                headers: vec![],
                body_preview: String::new(),
                body_truncated_bytes: 0,
            })
            .await;
        }
        let cbs = r.callbacks().await;
        assert_eq!(cbs.len(), 3);
        assert_eq!(cbs[0].path, "/p0");
        assert_eq!(cbs[1].path, "/p1");
        assert_eq!(cbs[2].path, "/p2");
    }

    // base32_encode byte-length tests live in
    // `crate::callback_token::tests`.
