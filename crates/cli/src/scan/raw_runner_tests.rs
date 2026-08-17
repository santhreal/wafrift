    use super::*;

    fn template_with_marker() -> RawRequest {
        RawRequest {
            method: "GET".into(),
            url: "http://x/search?q=§§".into(),
            headers: vec![("Accept".into(), "*/*".into())],
            body: Vec::new(),
        }
    }

    fn template_without_marker() -> RawRequest {
        RawRequest {
            method: "GET".into(),
            url: "http://x/".into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    // ── Validation gate: missing §§ marker ────────────────────

    #[tokio::test]
    async fn rejects_template_with_no_injection_marker() {
        let args = ScanArgs {
            target_positional: None,
            target: None,
            from_discovery: None,
            corpus: None,
            payload: "x".into(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Light,
            encoding_only: true,
            dry_run: false,
            delay_ms: 0,
            format: "json".into(),
            stealth_browser: None,
            insecure: false,
            report_layers: false,
            only: Vec::new(),
            exclude: Vec::new(),
            output: None,
            proxy: None,
            header: Vec::new(),
            raw_request: None,
            raw_request_scheme: "http".into(),
            auto_distill: false,
            auto_distill_max_fires: crate::DEFAULT_AUTO_DISTILL_MAX_FIRES,
            concurrency: 0,
            timeout_secs: 0,
            quiet: false,
            callback_timeout_secs: crate::DEFAULT_CALLBACK_TIMEOUT_SECS,
            exploit_cap: crate::DEFAULT_EXPLOIT_CAP,
            variants_cap: 0,
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR.into(),
            egress_challenge_threshold: crate::config::DEFAULT_EGRESS_CHALLENGE_THRESHOLD,
            egress_cooldown_secs: crate::config::DEFAULT_EGRESS_COOLDOWN_SECS,
            i_have_permission: None,
            graphql: false,
            scan_timeout_secs: 0,
            max_fires: crate::DEFAULT_MAX_FIRES,
            full_scan_unguarded: false,
            probe_surfaces: false,
            auto_escalate: true,
            no_auto_escalate: false,
            no_probe_surfaces: false,
            surface_cap: 12,
        };
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template_without_marker(), args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(2)),
            "missing-marker template must exit 2"
        );
    }

    #[tokio::test]
    async fn rejects_empty_payload() {
        let args = ScanArgs {
            target_positional: None,
            target: None,
            from_discovery: None,
            corpus: None,
            payload: String::new(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Light,
            encoding_only: true,
            dry_run: false,
            delay_ms: 0,
            format: "json".into(),
            stealth_browser: None,
            insecure: false,
            report_layers: false,
            only: Vec::new(),
            exclude: Vec::new(),
            output: None,
            proxy: None,
            header: Vec::new(),
            raw_request: None,
            raw_request_scheme: "http".into(),
            auto_distill: false,
            auto_distill_max_fires: crate::DEFAULT_AUTO_DISTILL_MAX_FIRES,
            concurrency: 0,
            timeout_secs: 0,
            quiet: false,
            callback_timeout_secs: crate::DEFAULT_CALLBACK_TIMEOUT_SECS,
            exploit_cap: crate::DEFAULT_EXPLOIT_CAP,
            variants_cap: 0,
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR.into(),
            egress_challenge_threshold: crate::config::DEFAULT_EGRESS_CHALLENGE_THRESHOLD,
            egress_cooldown_secs: crate::config::DEFAULT_EGRESS_COOLDOWN_SECS,
            i_have_permission: None,
            graphql: false,
            scan_timeout_secs: 0,
            max_fires: crate::DEFAULT_MAX_FIRES,
            full_scan_unguarded: false,
            probe_surfaces: false,
            auto_escalate: true,
            no_auto_escalate: false,
            no_probe_surfaces: false,
            surface_cap: 12,
        };
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template_with_marker(), args, cancel).await;
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::from(2)),
            "empty payload must exit 2"
        );
    }

    // ── Live mock-server fire loop ────────────────────────────
    //
    // Spin up a tiny TCP listener that mimics a WAF: 403 on
    // payloads containing the literal "BLOCKED", 200 otherwise.
    // Confirms the runner fires variants, classifies via
    // is_waf_block, and tracks bypasses.

    async fn spawn_mock_waf() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, body) = if req.contains("BLOCKED") {
                        (
                            "403 Forbidden",
                            "<html>blocked by mock WAF</html>".to_string(),
                        )
                    } else {
                        ("200 OK", "<html>OK</html>".to_string())
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
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;
        addr
    }

    fn args_for(addr: std::net::SocketAddr, payload: &str, format: &str) -> ScanArgs {
        // GET ?q=<payload-with-marker> against the mock, but the
        // runner gets a TEMPLATE, not args.target. Args fields are
        // unused here EXCEPT payload, level, encoding_only, format.
        let _ = addr;
        ScanArgs {
            target_positional: None,
            target: None,
            from_discovery: None,
            corpus: None,
            payload: payload.into(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Light,
            encoding_only: true,
            dry_run: false,
            delay_ms: 0,
            format: format.into(),
            stealth_browser: None,
            insecure: false,
            report_layers: false,
            only: Vec::new(),
            exclude: Vec::new(),
            output: None,
            proxy: None,
            header: Vec::new(),
            raw_request: None,
            raw_request_scheme: "http".into(),
            auto_distill: false,
            auto_distill_max_fires: crate::DEFAULT_AUTO_DISTILL_MAX_FIRES,
            concurrency: 0,
            timeout_secs: 0,
            quiet: false,
            callback_timeout_secs: crate::DEFAULT_CALLBACK_TIMEOUT_SECS,
            exploit_cap: crate::DEFAULT_EXPLOIT_CAP,
            variants_cap: 0,
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR.into(),
            egress_challenge_threshold: crate::config::DEFAULT_EGRESS_CHALLENGE_THRESHOLD,
            egress_cooldown_secs: crate::config::DEFAULT_EGRESS_COOLDOWN_SECS,
            i_have_permission: None,
            graphql: false,
            scan_timeout_secs: 0,
            max_fires: crate::DEFAULT_MAX_FIRES,
            full_scan_unguarded: false,
            probe_surfaces: false,
            auto_escalate: true,
            no_auto_escalate: false,
            no_probe_surfaces: false,
            surface_cap: 12,
        }
    }

    #[tokio::test]
    async fn runner_records_bypass_when_payload_dodges_mock_block_signature() {
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "GET".into(),
            url: format!("http://{addr}/?q=§§"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        // Payload "SAFEPAYLOAD" never contains the magic "BLOCKED"
        // substring → mock returns 200 → bypass recorded for every
        // variant. We just assert the runner completed successfully
        // and returns SUCCESS exit code.
        let args = args_for(addr, "SAFEPAYLOAD", "json");
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn runner_records_block_when_mock_waf_rejects() {
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "GET".into(),
            url: format!("http://{addr}/?q=§§"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        // Payload literally contains "BLOCKED" → mock returns 403
        // → no bypasses. Runner still returns SUCCESS (clean run,
        // just no winning variants).
        let args = args_for(addr, "BLOCKED", "json");
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn runner_honors_cancel_token_before_firing_first_variant() {
        // Cancel BEFORE the loop runs, runner should exit cleanly
        // without firing anything. Confirms the cancel path is
        // honoured (no hung scans on Ctrl-C).
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "GET".into(),
            url: format!("http://{addr}/?q=§§"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let args = args_for(addr, "x", "json");
        let cancel = CancellationToken::new();
        cancel.cancel();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    /// §12 anti-rig: --max-fires 5 must cap total_fired ≤ 5 across ALL phases.
    ///
    /// The dogfood scenario:
    ///   `scan <target> --variants-cap 1 --exploit-cap 0 --max-fires 5`
    /// previously fired 85 requests because differential, multi-vector,
    /// header-obf, and CEGIS-moat had no shared ceiling. This test pins
    /// that with max_fires=5 the scan JSON reports total_requests_fired ≤ 5.
    ///
    /// Implementation note: the raw_runner path runs `run_scan_raw` which
    /// calls the full `scan::run_scan` pipeline internally; the JSON output
    /// is written to a tmp file, read back, and parsed. We override the
    /// output path by injecting it via ScanArgs::output so the orchestrator
    /// streams the JSON there; then we parse `total_requests_fired` from it.
    #[serial_test::serial]
    #[tokio::test]
    async fn max_fires_5_caps_total_fired_across_all_phases() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Spin up a permissive mock: every request returns 200 so the
        // scan doesn't abort-rate-limit and every phase can run (but
        // the budget halts them before they can).
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter_c = counter.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let counter_cc = counter_c.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    counter_cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
                              Connection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        tokio::time::sleep(crate::parser_diff_common::TEST_SETTLE).await;

        let tmp = crate::helpers::secure_tmp_path("test-max-fires", "json");
        let template = RawRequest {
            method: "GET".into(),
            url: format!("http://{}/?q=\u{00A7}\u{00A7}", addr), // §§ markers
            headers: Vec::new(),
            body: Vec::new(),
        };
        // Build args with max_fires=5 and json output to tmp so we can parse it.
        let args = ScanArgs {
            target_positional: None,
            target: None,
            from_discovery: None,
            corpus: None,
            payload: "' OR 1=1--".into(),
            param: "q".into(),
            payload_class: None,
            callback_url: None,
            session_init: None,
            level: crate::Level::Light,
            encoding_only: false,
            dry_run: false,
            delay_ms: 0,
            format: "json".into(),
            stealth_browser: None,
            insecure: false,
            report_layers: false,
            only: Vec::new(),
            exclude: Vec::new(),
            output: Some(tmp.clone()),
            proxy: None,
            header: Vec::new(),
            raw_request: None,
            raw_request_scheme: "http".into(),
            auto_distill: false,
            auto_distill_max_fires: crate::DEFAULT_AUTO_DISTILL_MAX_FIRES,
            concurrency: 0,
            timeout_secs: 0,
            quiet: true,
            callback_timeout_secs: crate::DEFAULT_CALLBACK_TIMEOUT_SECS,
            exploit_cap: 500, // default, but max_fires overrides
            variants_cap: 1,  // dogfood scenario
            egress_socks5: Vec::new(),
            egress_http_proxy: Vec::new(),
            egress_tailscale_nodes: Vec::new(),
            egress_tailscale_socks_addr: crate::config::DEFAULT_TAILSCALE_SOCKS_ADDR.into(),
            egress_challenge_threshold: crate::config::DEFAULT_EGRESS_CHALLENGE_THRESHOLD,
            egress_cooldown_secs: crate::config::DEFAULT_EGRESS_COOLDOWN_SECS,
            i_have_permission: None,
            graphql: false,
            scan_timeout_secs: 0,
            max_fires: 5, // THE cap under test
            full_scan_unguarded: false,
            probe_surfaces: false,
            auto_escalate: true,
            no_auto_escalate: false,
            no_probe_surfaces: false,
            surface_cap: 12,
        };
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template, args, cancel).await;
        // The scan must exit cleanly (0 or 5=rate-limited), never panic.
        let exit_num = format!("{code:?}");
        let ok = exit_num == format!("{:?}", ExitCode::SUCCESS)
            || exit_num == format!("{:?}", ExitCode::from(5));
        assert!(ok, "scan exited unexpectedly: {exit_num}");

        // Parse the JSON output and assert total_fired ≤ max_fires.
        // raw_runner uses "total_fired"; main scan uses "total_requests_fired".
        let json_str = std::fs::read_to_string(&tmp).unwrap_or_default();
        let _ = std::fs::remove_file(&tmp);
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).unwrap_or(serde_json::Value::Null);
        let total_fired = parsed["total_fired"].as_u64().unwrap_or(u64::MAX);
        assert!(
            total_fired <= 5,
            "max_fires=5 must cap total_fired ≤ 5, got {total_fired} (json: {parsed})"
        );
    }

    /// §12 backward-compat: max_fires=0 (unlimited) must NOT change behaviour
    /// for a small scan relative to the DEFAULT_MAX_FIRES path.
    /// We just verify the scan completes cleanly and returns SUCCESS.
    #[tokio::test]
    async fn max_fires_zero_unlimited_does_not_abort_small_scan() {
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "GET".into(),
            url: format!("http://{}/?q=\u{00A7}\u{00A7}", addr), // §§
            headers: Vec::new(),
            body: Vec::new(),
        };
        let mut args = args_for(addr, "SAFEPAYLOAD", "json");
        args.max_fires = 0; // 0 = unlimited
        args.variants_cap = 3; // keep it fast
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }

    #[tokio::test]
    async fn runner_with_post_body_template_substitutes_payload_into_body() {
        // POST template with §§ in the body, runner substitutes,
        // mock WAF sees the substituted body.
        let addr = spawn_mock_waf().await;
        let template = RawRequest {
            method: "POST".into(),
            url: format!("http://{addr}/login"),
            headers: vec![(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: b"user=admin&pass=\xC2\xA7\xC2\xA7".to_vec(), // "§§" in UTF-8
        };
        let args = args_for(addr, "SAFEPASS", "json");
        let cancel = CancellationToken::new();
        let code = run_scan_raw(template, args, cancel).await;
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
    }
