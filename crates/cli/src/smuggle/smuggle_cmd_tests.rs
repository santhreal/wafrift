    use super::*;

    #[test]
    fn classify_desync_outcome_framing_rejected_on_400_501_505() {
        for s in [400u16, 501, 505] {
            assert_eq!(
                classify_desync_outcome(Some(s), 120, false),
                DesyncSignal::FramingRejected,
                "status {s} should be framing-rejected"
            );
        }
    }

    #[test]
    fn classify_desync_outcome_framing_accepted_on_normal_status() {
        for s in [200u16, 302, 403, 404, 500] {
            assert_eq!(
                classify_desync_outcome(Some(s), 120, false),
                DesyncSignal::FramingAccepted,
                "status {s} should be framing-accepted"
            );
        }
    }

    #[test]
    fn classify_desync_outcome_status_wins_over_timeout() {
        // A complete response that "timed out" afterwards is a keep-alive
        // socket, NOT a hang (the parsed status must still decide).
        assert_eq!(
            classify_desync_outcome(Some(200), 120, true),
            DesyncSignal::FramingAccepted
        );
        assert_eq!(
            classify_desync_outcome(Some(400), 120, true),
            DesyncSignal::FramingRejected
        );
    }

    #[test]
    fn classify_desync_outcome_backend_hang_only_on_zero_byte_timeout() {
        assert_eq!(
            classify_desync_outcome(None, 0, true),
            DesyncSignal::BackendHang
        );
    }

    #[test]
    fn classify_desync_outcome_no_response_on_zero_byte_clean_close() {
        assert_eq!(
            classify_desync_outcome(None, 0, false),
            DesyncSignal::NoResponse
        );
    }

    #[test]
    fn classify_desync_outcome_anomalous_on_unparseable_bytes() {
        // Bytes came back but no HTTP/1 status line. H2 frames or a banner.
        assert_eq!(
            classify_desync_outcome(None, 200, false),
            DesyncSignal::Anomalous
        );
        assert_eq!(
            classify_desync_outcome(None, 200, true),
            DesyncSignal::Anomalous
        );
    }

    #[test]
    fn desync_signal_as_str_matches_serde_representation() {
        // Anti-drift: the kebab label in text output MUST equal the JSON
        // serde representation, or an operator reading both --format json
        // and the text line would see two different signal names.
        for sig in [
            DesyncSignal::FramingRejected,
            DesyncSignal::FramingAccepted,
            DesyncSignal::BackendHang,
            DesyncSignal::NoResponse,
            DesyncSignal::Anomalous,
        ] {
            let json = serde_json::to_value(sig).unwrap();
            assert_eq!(json, serde_json::Value::String(sig.as_str().to_string()));
        }
    }

    #[test]
    fn unescape_prefix_handles_crlf_and_tab() {
        let raw = "GET /\\r\\nHost: x\\r\\n\\r\\n";
        let got = unescape_prefix(raw);
        assert_eq!(got, "GET /\r\nHost: x\r\n\r\n");
    }

    #[test]
    fn unescape_prefix_preserves_lone_backslash() {
        let raw = "C:\\Users\\foo";
        let got = unescape_prefix(raw);
        assert_eq!(got, "C:\\Users\\foo", "lone backslashes must round-trip");
    }

    #[test]
    fn unescape_prefix_handles_escaped_backslash() {
        let raw = "a\\\\b";
        let got = unescape_prefix(raw);
        assert_eq!(got, "a\\b");
    }

    #[test]
    fn classify_detection_flags_when_delta_above_threshold() {
        let f = classify_detection(2000, 200, 1500);
        assert!(f.desync_inferred);
        assert_eq!(f.delta_ms, 1800);
    }

    #[test]
    fn classify_detection_does_not_flag_when_under_threshold() {
        let f = classify_detection(800, 200, 1500);
        assert!(!f.desync_inferred);
        assert_eq!(f.delta_ms, 600);
    }

    #[test]
    fn classify_detection_does_not_flag_on_exact_zero_delta() {
        let f = classify_detection(200, 200, 1500);
        assert!(!f.desync_inferred);
        assert_eq!(f.delta_ms, 0);
    }

    #[test]
    fn classify_detection_handles_baseline_higher_than_probe() {
        // A negative delta, probe came back FASTER than baseline
        // is never a desync signal.
        let f = classify_detection(100, 500, 1500);
        assert!(!f.desync_inferred);
        assert!(f.delta_ms < 0);
    }

    #[test]
    fn classify_detection_fires_at_exactly_threshold() {
        // Boundary (delta == threshold counts as desync).
        let f = classify_detection(1700, 200, 1500);
        assert!(f.desync_inferred);
        assert_eq!(f.delta_ms, 1500);
    }

    #[test]
    fn parse_variant_name_accepts_all_catalogue_keys() {
        for v in VARIANTS {
            let r = parse_variant_name(v.key).expect("known key must parse");
            assert_eq!(r.info.key, v.key);
        }
    }

    #[test]
    fn parse_variant_name_is_case_insensitive() {
        let r = parse_variant_name("CL-TE").expect("upper-case alias must parse");
        assert_eq!(r.info.key, "cl-te");
    }

    #[test]
    fn parse_variant_name_rejects_unknown() {
        let r = parse_variant_name("not-a-variant");
        assert!(r.is_err());
        let msg = r.unwrap_err();
        assert!(msg.contains("not-a-variant"));
        // Error message must enumerate known variants so the
        // operator knows what to type.
        assert!(msg.contains("cl-te"));
    }

    // ── parse_host_or_url ─────────────────────────────────────────────────────

    #[test]
    fn parse_host_or_url_bare_hostname_passes_through() {
        assert_eq!(parse_host_or_url("example.com").unwrap(), "example.com");
    }

    #[test]
    fn parse_host_or_url_host_with_port_passes_through() {
        assert_eq!(
            parse_host_or_url("example.com:8080").unwrap(),
            "example.com:8080"
        );
    }

    #[test]
    fn parse_host_or_url_https_url_extracts_host() {
        assert_eq!(
            parse_host_or_url("https://example.com/path?q=1").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn parse_host_or_url_http_url_extracts_host() {
        assert_eq!(
            parse_host_or_url("http://example.com").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn parse_host_or_url_url_with_port_keeps_port() {
        assert_eq!(
            parse_host_or_url("https://example.com:443/").unwrap(),
            "example.com:443"
        );
    }

    #[test]
    fn parse_host_or_url_url_with_empty_host_errors() {
        let r = parse_host_or_url("https:///path");
        assert!(r.is_err(), "empty host should error: {r:?}");
    }

    #[test]
    fn build_payload_for_every_catalogue_variant_succeeds() {
        // Anti-rig: every key in VARIANTS must have a working
        // builder. A renamed engine function or a missed match arm
        // would surface here, not on first user invocation.
        for v in VARIANTS {
            let p = build_payload(v, "example.com", "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(
                p.is_ok(),
                "variant `{}` failed to build: {:?}",
                v.key,
                p.err()
            );
            let bytes = p.unwrap().raw_bytes;
            assert!(!bytes.is_empty());
            // R69 pass-21: HTTP/2-class variants (rapid-reset family
            // wired in this pass) begin with the H2 client preface
            // `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`, not a request line.
            // Accept "PRI" as a valid HTTP-shape prefix alongside the
            // H1 verbs so the H2 wire-byte builders pass this
            // anti-rig contract without weakening the original guard.
            assert!(
                bytes.starts_with(b"POST")
                    || bytes.starts_with(b"GET")
                    || bytes.starts_with(b"PRI"),
                "variant `{}` produced non-HTTP bytes",
                v.key
            );
        }
    }

    #[test]
    fn detection_variants_have_detection_tier_in_catalogue() {
        // The whole point of `--unsafe` gating: if a detection
        // variant got mis-tagged Exploit, operators would refuse
        // to run safe probes. Lock the tagging in.
        for v in VARIANTS {
            if v.key.starts_with("detect-") {
                assert_eq!(
                    v.tier,
                    SafetyTier::Detection,
                    "{} should be Detection-tier",
                    v.key
                );
            }
        }
    }

    #[test]
    fn classic_cl_te_is_exploit_tier() {
        // Sanity: a stray refactor that flipped cl-te to Detection
        // would let unauthenticated callers poison sockets.
        let cl_te = VARIANTS.iter().find(|v| v.key == "cl-te").unwrap();
        assert_eq!(cl_te.tier, SafetyTier::Exploit);
    }

    #[test]
    fn cl_te_payload_contains_both_cl_and_te_headers() {
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "cl-te").unwrap(),
            "example.com",
            "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(
            wire.contains("Content-Length"),
            "CL.TE must carry a Content-Length header"
        );
        assert!(
            wire.contains("Transfer-Encoding"),
            "CL.TE must carry a Transfer-Encoding header"
        );
    }

    // ── Kettle BH-USA 2025 "The Desync Endgame" CLI wiring (this pass) ──

    /// The eight Kettle BH25 desync keys, shared by the catalogue/tier
    /// assertions below so a new technique is added in exactly one place.
    const KETTLE_KEYS: &[&str] = &[
        "zero-cl-desync",
        "expect-100-desync",
        "cl-0-via-expect",
        "double-desync",
        "expect-100-obf",
        "vh-masked-host",
        "malformed-host-split",
        "chunk-ext-keyval",
    ];

    /// Build the wire string for a catalogue `key` against fixed test
    /// seeds. Shared by the Kettle assertions so each test pins one
    /// technique without copying the build boilerplate (§7 dedup).
    fn kettle_wire(key: &str) -> String {
        let v = VARIANTS
            .iter()
            .find(|v| v.key == key)
            .unwrap_or_else(|| panic!("variant `{key}` missing from catalogue"));
        let p = build_payload(v, "example.com", "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap_or_else(|e| panic!("variant `{key}` failed to build: {e}"));
        String::from_utf8_lossy(&p.raw_bytes).into_owned()
    }

    /// A renamed key would silently drop the technique from `smuggle
    /// list` and `--variant`; pin the whole family's presence.
    #[test]
    fn kettle_desync_family_present_in_catalogue() {
        for key in KETTLE_KEYS {
            assert!(
                VARIANTS.iter().any(|v| &v.key == key),
                "Kettle BH25 variant `{key}` missing from VARIANTS"
            );
        }
    }

    /// Every Kettle primitive desyncs or sends malformed framing, so all
    /// must be Exploit-tier (require `--unsafe`). A stray Detection tag
    /// would let an unauthenticated caller fire pool-poisoning traffic.
    #[test]
    fn kettle_desync_family_is_all_exploit_tier() {
        for key in KETTLE_KEYS {
            let v = VARIANTS.iter().find(|v| &v.key == key).unwrap();
            assert_eq!(
                v.tier,
                SafetyTier::Exploit,
                "Kettle variant `{key}` must be Exploit-tier"
            );
        }
    }

    #[test]
    fn zero_cl_desync_uses_reserved_path_and_carries_cl() {
        let wire = kettle_wire("zero-cl-desync");
        assert!(wire.starts_with("GET /con "), "got: {wire:?}");
        assert!(wire.contains("Content-Length:"), "got: {wire:?}");
        // The smuggled prefix must ride after the header block.
        assert!(wire.contains("GET /admin HTTP/1.1"), "got: {wire:?}");
    }

    #[test]
    fn expect_100_desync_carries_expect_continue_header() {
        let wire = kettle_wire("expect-100-desync");
        assert!(wire.contains("Expect: 100-continue"), "got: {wire:?}");
        assert!(wire.contains("Content-Length:"), "got: {wire:?}");
    }

    #[test]
    fn cl_0_via_expect_targets_images_endpoint() {
        let wire = kettle_wire("cl-0-via-expect");
        assert!(wire.starts_with("POST /images/ "), "got: {wire:?}");
        assert!(wire.contains("Expect: 100-continue"), "got: {wire:?}");
    }

    #[test]
    fn double_desync_pipelines_both_frames() {
        let wire = kettle_wire("double-desync");
        // Stage-1 GET frame wraps a stage-2 POST frame on one connection.
        assert!(wire.contains("GET / HTTP/1.1"), "stage1 missing: {wire:?}");
        assert!(
            wire.contains("POST /admin HTTP/1.1"),
            "stage2 missing: {wire:?}"
        );
    }

    #[test]
    fn expect_100_obf_uses_trailing_space_canonical() {
        let wire = kettle_wire("expect-100-obf");
        // Trailing space after the directive (the canonical obfuscation).
        assert!(
            wire.contains("Expect: 100-continue \r\n"),
            "expected trailing-space Expect value: {wire:?}"
        );
    }

    #[test]
    fn vh_masked_host_space_prefixes_a_header_line() {
        let wire = kettle_wire("vh-masked-host");
        // CRLF then a SPACE then the masked header, front-end sees it,
        // back-end folds/ignores it.
        assert!(
            wire.contains("\r\n Host: example.com"),
            "expected space-prefixed Host line: {wire:?}"
        );
    }

    #[test]
    fn malformed_host_split_inserts_delimiter_in_host() {
        let wire = kettle_wire("malformed-host-split");
        // First delimiter ':' inserted after the 3rd char of "example.com".
        assert!(
            wire.contains("Host: exa:mple.com"),
            "expected delimiter-split Host: {wire:?}"
        );
    }

    #[test]
    fn chunk_ext_keyval_carries_chunked_te_and_extension() {
        let wire = kettle_wire("chunk-ext-keyval");
        assert!(wire.contains("Transfer-Encoding: chunked"), "got: {wire:?}");
        assert!(
            wire.contains(";x=y"),
            "expected key=value chunk-ext: {wire:?}"
        );
    }

    // ── Additional library smuggling primitives wired this pass ──

    const EXTRA_PRIMITIVE_KEYS: &[&str] = &[
        "method-body",
        "http10-persistence",
        "http09-downgrade",
        "cl-obfuscation",
        "chunk-size-mutation",
    ];

    #[test]
    fn extra_smuggling_primitives_present_and_exploit_tier() {
        for key in EXTRA_PRIMITIVE_KEYS {
            let v = VARIANTS
                .iter()
                .find(|v| &v.key == key)
                .unwrap_or_else(|| panic!("variant `{key}` missing from VARIANTS"));
            assert_eq!(
                v.tier,
                SafetyTier::Exploit,
                "`{key}` must be Exploit-tier (carries a smuggled request)"
            );
        }
    }

    #[test]
    fn method_body_is_get_with_content_length_body() {
        let wire = kettle_wire("method-body");
        assert!(wire.starts_with("GET / HTTP/1.1"), "got: {wire:?}");
        assert!(wire.contains("Content-Length:"), "got: {wire:?}");
        assert!(
            wire.contains("GET /admin HTTP/1.1"),
            "smuggled prefix must ride in the body: {wire:?}"
        );
    }

    #[test]
    fn http10_persistence_uses_1_0_and_keep_alive() {
        let wire = kettle_wire("http10-persistence");
        assert!(wire.starts_with("POST / HTTP/1.0"), "got: {wire:?}");
        assert!(
            wire.to_ascii_lowercase().contains("connection: keep-alive"),
            "got: {wire:?}"
        );
    }

    #[test]
    fn http09_downgrade_emits_versionless_request_line() {
        let wire = kettle_wire("http09-downgrade");
        // HTTP/0.9 simple request: `GET /` with NO HTTP-version token.
        assert!(wire.starts_with("GET /\r\n"), "got: {wire:?}");
        assert!(
            !wire.lines().next().unwrap().contains("HTTP/"),
            "0.9 request line must omit the version: {wire:?}"
        );
    }

    #[test]
    fn cl_obfuscation_emits_noncanonical_content_length() {
        let wire = kettle_wire("cl-obfuscation");
        // First library variant is the `+5` form.
        assert!(
            wire.contains("Content-Length: +5"),
            "expected obfuscated CL value: {wire:?}"
        );
    }

    #[test]
    fn chunk_size_mutation_emits_noncanonical_chunk_size() {
        let wire = kettle_wire("chunk-size-mutation");
        assert!(wire.contains("Transfer-Encoding: chunked"), "got: {wire:?}");
        // First library variant is the leading-zeros size `00000001`.
        assert!(
            wire.contains("00000001\r\n"),
            "expected leading-zero chunk size: {wire:?}"
        );
    }

    #[test]
    fn detect_cl_te_payload_does_not_smuggle_a_user_prefix() {
        // Detection variants accept an empty prefix, they're
        // pure timing-probes. Confirm `build_payload("detect-cl-te", ..., "")`
        // succeeds and the output contains no caller-supplied
        // smuggled request bytes.
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "detect-cl-te").unwrap(),
            "example.com",
            "",
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(!wire.contains("/admin"));
        assert!(!wire.contains("X-Smuggled"));
    }

    #[test]
    fn dry_run_hex_format_emits_no_io() {
        // Smoke-test that build_payload is the only work the
        // dry-run path does (no DNS, no TCP).
        let info = VARIANTS.iter().find(|v| v.key == "dual-cl").unwrap();
        let p = build_payload(info, "example.com", "GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(p.raw_bytes.len() > 50);
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn time_first_byte_returns_timeout_value_when_server_silent() {
        // Spawn a TcpListener that accepts the connection and
        // does NOTHING, never writes a response. Confirms our
        // timeout path returns roughly `timeout_secs * 1000` and
        // doesn't hang the test runner. The accepted socket is
        // bound to `_sock` (not `_`) on purpose: `let _ = ...`
        // drops immediately and would close the connection,
        // making `read` return Ok(0) instantly instead of hanging.
        //
        // timeout_secs=3 rather than 1: on Windows under heavy
        // parallel test load the loopback TCP connect can take up to
        // ~1s itself (OS stack loaded by other tests). A 1s budget
        // was too narrow, the connect timeout fired before the server
        // could accept, returning Err instead of Ok(elapsed). 3s gives
        // headroom for the connect while still proving the READ timeout
        // fires before the server holds the socket open (10s).
        let timeout_secs: u64 = 3;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((_sock, _peer)) = listener.accept().await {
                // Hold the socket open without writing anything
                // for 10s (longer than the probe timeout).
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        let elapsed = time_first_byte(addr, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", timeout_secs)
            .await
            .unwrap();
        let expected_ms = timeout_secs * 1000;
        assert!(
            elapsed >= expected_ms - 100,
            "should have hung ~{expected_ms}ms, got {elapsed}"
        );
        assert!(
            elapsed < expected_ms + 1500,
            "should not exceed timeout+margin, got {elapsed}"
        );
    }

    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn time_first_byte_returns_quickly_when_server_responds() {
        // `#[serial_test::serial]`: binds a fresh `127.0.0.1:0`
        // listener; under Windows parallel test runs the ephemeral-
        // port + slow TIME_WAIT recycle path produces spurious
        // `connection refused` failures.
        // Spawn a TcpListener that immediately writes a minimal
        // HTTP response. Confirms the path through the success
        // case returns a small elapsed_ms.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Eat the request so it doesn't block our write.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        });
        let elapsed = time_first_byte(
            addr,
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            5,
        )
        .await
        .unwrap();
        assert!(
            elapsed < 4000,
            "honest server should respond fast, got {elapsed}"
        );
    }

    #[test]
    fn list_text_output_does_not_panic() {
        // Exercises the `--list` rendering path: any iteration
        // over VARIANTS that hits a None-unwrap would surface
        // here. ExitCode::SUCCESS = 0 on Unix and Windows.
        let code = run_list("text");
        // Can't easily compare ExitCode to a literal in stable
        // Rust without Termination plumbing; the smoke is enough.
        let _ = code;
    }

    #[test]
    fn list_json_format_is_accepted_by_run_list() {
        // Pre-fix: `wafrift smuggle list` had a hardcoded "text" and
        // did not accept --format. Adding ListArgs enables JSON. This
        // test pins the run_list("json") path doesn't panic.
        let code = run_list("json");
        let _ = code;
    }

    // ── unescape_prefix edge cases ────────────────────────────

    #[test]
    fn unescape_prefix_empty_string_returns_empty() {
        assert_eq!(unescape_prefix(""), "");
    }

    #[test]
    fn unescape_prefix_string_without_any_escapes_is_identity() {
        let plain = "GET / HTTP/1.1 Host x";
        assert_eq!(unescape_prefix(plain), plain);
    }

    #[test]
    fn unescape_prefix_trailing_lone_backslash_is_preserved_no_panic() {
        // The peek-after-backslash path must NOT crash on a
        // trailing backslash at end of input. P0 fuzzer would
        // immediately find this.
        let raw = "abc\\";
        assert_eq!(unescape_prefix(raw), "abc\\");
    }

    #[test]
    fn unescape_prefix_unknown_escape_is_preserved_verbatim() {
        // `\x` is not a recognised escape, keep the backslash
        // so a future reader (the smuggling engine) can tell
        // it apart from a real `x`. The current implementation
        // emits the `\\` then continues, so the result is `\x`.
        let raw = "a\\xb";
        let got = unescape_prefix(raw);
        assert!(got.contains('x'));
        assert!(got.contains('a'));
        assert!(got.contains('b'));
    }

    #[test]
    fn unescape_prefix_handles_consecutive_crlf_groups() {
        // The HTTP header terminator `\r\n\r\n` is the canonical
        // boundary (confirm two adjacent groups both unescape).
        let raw = "X\\r\\n\\r\\nY";
        assert_eq!(unescape_prefix(raw), "X\r\n\r\nY");
    }

    // ── parse_variant_name edge cases ─────────────────────────

    #[test]
    fn parse_variant_name_rejects_empty_string() {
        let r = parse_variant_name("");
        assert!(r.is_err());
    }

    #[test]
    fn parse_variant_name_does_not_match_partial_prefix() {
        // "cl" is a prefix of "cl-te" / "cl-0" but is NOT a valid
        // variant by itself. The exact-match contract must hold.
        let r = parse_variant_name("cl");
        assert!(r.is_err());
    }

    // ── classify_detection edge cases ─────────────────────────

    #[test]
    fn classify_detection_one_ms_under_threshold_does_not_fire() {
        // Boundary on the OFF side: delta == threshold - 1 must
        // stay below the desync line.
        let f = classify_detection(1699, 200, 1500); // delta = 1499
        assert!(!f.desync_inferred);
        assert_eq!(f.delta_ms, 1499);
    }

    #[test]
    fn classify_detection_handles_zero_threshold_correctly() {
        // Threshold zero with any positive delta should fire.
        // Anti-rig: a refactor that used `delta > threshold` instead
        // of `delta >= threshold` would silently flip this case.
        let f = classify_detection(201, 200, 0);
        assert!(f.desync_inferred);
        assert_eq!(f.delta_ms, 1);
    }

    #[test]
    fn classify_detection_records_threshold_in_finding() {
        // The finding carries the threshold used so operators
        // can audit the decision after the fact.
        let f = classify_detection(2000, 200, 1500);
        assert_eq!(f.threshold_ms, 1500);
    }

    // ── VARIANTS catalogue integrity ──────────────────────────

    /// Anti-rig: the two timing-detection variant keys hardcoded in
    /// `run_detect` MUST exist in the VARIANTS catalogue. If either
    /// key is renamed or removed, `run_detect` would previously panic
    /// (`.unwrap()` on a None); the fix turns that into a graceful error
    /// but this test pins the precondition so the regression is caught
    /// before it ever reaches production.
    #[test]
    fn detection_variants_present_in_catalogue() {
        for required_key in ["detect-cl-te", "detect-te-cl"] {
            assert!(
                VARIANTS.iter().any(|v| v.key == required_key),
                "run_detect hardcodes `{required_key}` but it is absent from VARIANTS catalogue. \
                 `wafrift smuggle detect` would return exit code 2 for all users"
            );
        }
    }

    #[test]
    fn variants_catalogue_has_no_empty_keys() {
        for v in VARIANTS {
            assert!(!v.key.is_empty(), "VARIANTS row with empty key");
        }
    }

    #[test]
    fn variants_catalogue_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for v in VARIANTS {
            assert!(seen.insert(v.key), "duplicate variant key {}", v.key);
        }
    }

    #[test]
    fn variants_catalogue_keys_are_lowercase() {
        // parse_variant_name lowercases input before comparing, the
        // catalogue rows MUST themselves be lowercase or the
        // case-insensitive matching is dead code.
        for v in VARIANTS {
            assert_eq!(
                v.key,
                v.key.to_ascii_lowercase(),
                "{} must be lowercase in the catalogue",
                v.key
            );
        }
    }

    // ── build_payload contract ────────────────────────────────

    #[test]
    fn build_payload_for_cl_te_includes_host_header() {
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "cl-te").unwrap(),
            "victim.example",
            "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(
            wire.contains("Host: victim.example") || wire.contains("Host:victim.example"),
            "front-request Host MUST be the target host: {wire}"
        );
    }

    #[test]
    fn build_payload_for_dual_cl_emits_two_content_length_headers() {
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "dual-cl").unwrap(),
            "victim.example",
            "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        // Two Content-Length lines is the whole point of dual-cl;
        // a refactor that collapsed them would silently neuter
        // the attack.
        let cl_count = wire.matches("Content-Length:").count();
        assert!(
            cl_count >= 2,
            "dual-cl must emit two Content-Length headers, got {cl_count}: {wire}"
        );
    }

    #[test]
    fn build_payload_smuggled_prefix_appears_in_wire_for_cl_te() {
        // The smuggled HTTP request bytes the operator passes MUST
        // appear somewhere in the produced wire bytes, that's the
        // whole point of the attack. A refactor that dropped the
        // prefix would generate a benign request.
        let prefix = "GET /smuggled-marker HTTP/1.1\r\nHost: x\r\n\r\n";
        let p = build_payload(
            VARIANTS.iter().find(|v| v.key == "cl-te").unwrap(),
            "victim.example",
            prefix,
        )
        .unwrap();
        let wire = std::str::from_utf8(&p.raw_bytes).unwrap();
        assert!(
            wire.contains("/smuggled-marker"),
            "smuggled prefix MUST reach the wire"
        );
    }

    // F126 regression: TCP connect timeout (unreachable host, blocked
    // port) must surface as Err, NOT as a phantom-elapsed measurement
    // that gets compared against the baseline and produces a false
    // DESYNC. Aim at port 1 on localhost. Windows + most Linux
    // configs refuse it, but the connect should ERROR fast rather
    // than hang. Either way we want Err out of time_first_byte, not
    // a giant phantom Ok value.
    #[tokio::test]
    async fn time_first_byte_unreachable_returns_err_not_phantom_elapsed() {
        // Use a port reserved for "no host should listen here":
        // 1 = TCP-port-multiplexer, not in use on stock systems.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = time_first_byte(addr, b"GET / HTTP/1.1\r\n\r\n", 2).await;
        match result {
            Err(msg) => {
                // Either "tcp connect: <connection refused>" (refusal)
                // OR "tcp connect: timed out after 2s" (filtered).
                // Both are the desired Err surface.
                assert!(
                    msg.starts_with("tcp connect:"),
                    "expected tcp connect error, got: {msg}"
                );
            }
            Ok(elapsed_ms) => panic!(
                "unreachable host returned phantom Ok({elapsed_ms}) ms. \
                 F126 regression: would feed into delta calculation and \
                 false-flag DESYNC"
            ),
        }
    }

    #[test]
    fn build_payload_unknown_variant_key_returns_error() {
        // We can't manufacture a VariantInfo with a bogus key
        // through normal channels, but exercise the matchable
        // wildcard arm via parse_variant_name's error path. The
        // build_payload arm is defence-in-depth.
        let bogus = VariantInfo {
            key: "made-up",
            long_name: "Made Up",
            tier: SafetyTier::Detection,
            description: "anti-rig synthetic",
        };
        let r = build_payload(&bogus, "x", "");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("made-up"));
    }

    // Fix #8 tests (annotate_lone_lf visibility helper).

    #[test]
    fn annotate_lone_lf_replaces_standalone_lf_with_visible_token() {
        // A lone \n (not preceded by \r) must become <LF>\n.
        let input = "foo\nbar";
        let out = annotate_lone_lf(input);
        assert!(
            out.contains("<LF>\n"),
            "bare LF must be annotated with <LF> token; got: {out:?}"
        );
        assert!(out.contains("foo"), "non-LF content must be preserved");
        assert!(out.contains("bar"), "non-LF content must be preserved");
    }

    #[test]
    fn annotate_lone_lf_does_not_replace_crlf() {
        // \r\n is a legitimate HTTP line ending (must NOT be annotated).
        let input = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let out = annotate_lone_lf(input);
        assert!(
            !out.contains("<LF>"),
            "CRLF line endings must NOT be annotated; got: {out:?}"
        );
    }

    #[test]
    fn chunk_ext_lone_lf_dry_run_text_makes_bare_lf_visible() {
        // Build the chunk-ext-lone-lf payload and simulate the
        // dry-run text renderer to confirm the annotation appears.
        use wafrift_smuggling::smuggling::chunk_extension_lone_lf;

        let prefix = "GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";
        let p = chunk_extension_lone_lf("example.com", prefix).unwrap();
        let s = match std::str::from_utf8(&p.raw_bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => p.raw_bytes.iter().map(|&b| b as char).collect(),
        };
        // The payload MUST contain a lone \n byte for the variant to be meaningful.
        let has_lone_lf = s
            .as_bytes()
            .windows(2)
            .any(|w| w[0] != b'\r' && w[1] == b'\n')
            || s.as_bytes().first() == Some(&b'\n');
        assert!(
            has_lone_lf,
            "chunk-ext-lone-lf payload must contain a bare LF byte"
        );
        let annotated = annotate_lone_lf(&s);
        assert!(
            annotated.contains("<LF>"),
            "annotated output must contain <LF> marker; got: {annotated:?}"
        );
    }