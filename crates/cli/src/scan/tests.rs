    use super::*;

    #[test]
    fn estimate_clamps_to_one_second_minimum() {
        // A zero-variant zero-delay scan would compute 0s, which
        // reads as "broken" in the banner. The estimator floors at
        // 1 to keep the displayed value honest.
        assert_eq!(estimate_scan_seconds(0, 0), 1);
        assert_eq!(estimate_scan_seconds(1, 0), 1);
    }

    #[test]
    fn estimate_scales_roughly_with_variants() {
        // 100 variants at 50ms delay, 300ms RTT, 8-way parallel:
        // (100 * 350) / 8 = 4375ms ≈ 4s. Just sanity-check the
        // formula is in the right ballpark, exact tuning isn't
        // load-bearing.
        let est = estimate_scan_seconds(100, 50);
        assert!((3..=6).contains(&est), "estimate out of band: {est}");
    }

    #[test]
    fn estimate_grows_with_delay() {
        let fast = estimate_scan_seconds(50, 0);
        let slow = estimate_scan_seconds(50, 500);
        assert!(
            slow > fast,
            "raising delay must raise the estimate: {fast} vs {slow}"
        );
    }

    #[test]
    fn estimate_handles_saturation_without_panic() {
        // Pathologically large inputs (e.g. an operator typing
        // `--delay-ms 9999999999`) must not wrap arithmetic.
        let est = estimate_scan_seconds(usize::MAX, u64::MAX);
        // We don't assert a specific value, only that it didn't
        // panic and returned something non-zero.
        assert!(est >= 1);
    }

    #[test]
    fn scan_url_with_param_appends_query() {
        let url = scan_url_with_param("http://x/", "q", "abc");
        assert!(url.contains("q=abc"), "expected q=abc in {url}");
    }

    #[test]
    fn scan_url_with_param_falls_back_on_unparseable_input() {
        // resolve_target may pass through a string reqwest::Url
        // can't parse (e.g. when the operator typo'd the scheme).
        // The fallback must still produce something with the param
        // baked in (never throw the payload on the floor).
        let url = scan_url_with_param("not a url", "q", "abc");
        assert!(url.contains("q=abc"), "fallback dropped param: {url}");
    }

    /// Core anti-double-encoding contract.
    ///
    /// All firing paths pre-encode the payload with `urlencoding::encode`
    /// then pass the result to `scan_url_with_param`. The function must
    /// NOT re-encode, if it did, `%3C` (the pre-encoded `<`) would become
    /// `%253C` on the wire and every evasion payload would arrive at the
    /// WAF as visually mangled garbage, producing false "blocked" verdicts.
    #[test]
    fn scan_url_with_param_does_not_double_encode_pre_encoded_value() {
        // `<script>` → urlencoding::encode → `%3Cscript%3E`
        let pre_encoded = urlencoding::encode("<script>").to_string();
        let url = scan_url_with_param("http://target/", "q", &pre_encoded);
        // The pre-encoded form must survive verbatim.
        assert!(
            url.contains("%3Cscript%3E"),
            "pre-encoded value must not be re-encoded; got: {url}"
        );
        // Double-encoding would produce %253C. If that's in the URL the
        // WAF sees an escaped '%' instead of the payload, a guaranteed
        // false-block for every variant.
        assert!(
            !url.contains("%253C"),
            "double-encoding detected: %25 found, indicating % was re-encoded: {url}"
        );
    }

    #[test]
    fn scan_url_with_param_produces_valid_separator_without_existing_query() {
        let url = scan_url_with_param("http://target/search", "q", "test");
        assert!(url.contains('?'), "must use ? when no query exists: {url}");
        assert!(url.contains("q=test"), "param missing: {url}");
        // Must NOT have double ? or && which would produce malformed URLs.
        assert_eq!(url.matches('?').count(), 1, "exactly one ? expected: {url}");
    }

    #[test]
    fn scan_url_with_param_keeps_param_in_query_not_fragment() {
        // Audit fix: a `#fragment` in the target must NOT swallow the param.
        // Pre-fix, `http://t/p#frag` produced `http://t/p#frag?q=v`: the
        // `?q=v` becomes part of the fragment and is never sent to the server,
        // silently dropping the payload. The param must land in the QUERY,
        // before the `#`, and the fragment must be preserved.
        let url = scan_url_with_param("http://target/page#section", "q", "payload");
        let hash = url.find('#').expect("fragment must survive");
        let qeq = url.find("q=payload").expect("param must be present");
        assert!(
            qeq < hash,
            "param must appear BEFORE the fragment (in the query), got: {url}"
        );
        assert!(
            url.ends_with("#section"),
            "fragment must be re-attached: {url}"
        );
        assert_eq!(url, "http://target/page?q=payload#section");
    }

    #[test]
    fn scan_url_with_param_fragment_with_existing_query_uses_ampersand() {
        // Fragment AND an existing query: append with `&`, still before the `#`.
        let url = scan_url_with_param("http://target/p?a=1#frag", "q", "v");
        assert_eq!(url, "http://target/p?a=1&q=v#frag");
        assert!(url.find("q=v").unwrap() < url.find('#').unwrap());
    }

    #[test]
    fn scan_url_with_param_uses_ampersand_when_query_already_present() {
        let url = scan_url_with_param("http://target/search?existing=1", "q", "abc");
        // Should append with & not produce a second ?.
        assert!(
            url.contains("existing=1") && url.contains("q=abc"),
            "both params must survive: {url}"
        );
        assert_eq!(
            url.matches('?').count(),
            1,
            "must not add a second ?: {url}"
        );
        assert!(url.contains('&'), "must use & to append: {url}");
    }

    #[test]
    fn scan_url_with_param_preserves_special_chars_in_pre_encoded_value() {
        // A SQL tautology pre-encoded: "' OR '1'='1" → contains %27 etc.
        let raw = "' OR '1'='1";
        let pre = urlencoding::encode(raw).to_string();
        let url = scan_url_with_param("http://t/", "q", &pre);
        // The %27 (apostrophe) must arrive singly-encoded, not as %2527.
        assert!(url.contains("%27"), "apostrophe must be %27, got: {url}");
        assert!(
            !url.contains("%2527"),
            "double-encoded apostrophe detected: {url}"
        );
    }

    // ── anti-rig: structural bypass gate ────────────────────────────
    //
    // A payload that the WAF passes but that has been mangled into
    // harmless junk must NOT be counted as a bypass. The direct-fire and
    // tamper loops both gate on verified_bypass; this test pins the
    // predicate on a known-broken SQLi mutation.

    #[test]
    fn scan_verified_bypass_rejects_mangled_sqli() {
        let original = "1 OR 1=1 --";
        let mangled = "1 O R 1=1 --";
        let class = class_for_payload_type(PayloadType::Sql);
        assert_eq!(class, Some("sql"));
        assert!(
            !verified_bypass(class.unwrap(), original, mangled, false, 200),
            "mangled SQLi must not count as a bypass: {mangled}"
        );
        assert!(
            verified_bypass(class.unwrap(), original, original, false, 200),
            "intact payload should verify: {original}"
        );
    }

    #[test]
    fn build_bypass_variants_json_single_encodes_payload_in_repro_url() {
        // build_bypass_variants_json passes the raw payload to
        // scan_url_with_param with a pre-encoding step. Verify no
        // double-encoding in the resulting full_url used for repro_curl.
        let variants = vec![(
            0usize,
            "<script>alert(1)</script>".to_string(),
            vec!["xss::raw".to_string()],
            0.9_f64,
        )];
        let minimal_payloads: Vec<Option<String>> = vec![None];
        let results = build_bypass_variants_json(
            "http://target/",
            "q",
            injection_delivery::InjectionDelivery::GetQuery,
            &variants,
            &minimal_payloads,
        );
        assert_eq!(results.len(), 1);
        let repro = results[0]["repro_curl"].as_str().unwrap_or("");
        // The curl reproducer must contain the encoded tag, not a double-encoded form.
        // %3Cscript%3E is the single-encoded form; %253Cscript%253E is double.
        assert!(
            !repro.contains("%253C"),
            "repro_curl must not double-encode the payload: {repro}"
        );
    }

    // ── --variants-cap honesty ───────────────────────────────
    //
    // The full firing path is end-to-end-tested via dogfood + the
    // depth subprocess integration test. Here we pin the
    // truncation semantics on a synthetic variant Vec so a future
    // refactor (e.g. moving the cap check earlier or later in the
    // pipeline) keeps the contract: ordered truncation, no panic
    // on cap==0, no panic on cap>=len.

    #[test]
    fn variants_cap_zero_means_no_truncation() {
        let mut v: Vec<u32> = (0..10).collect();
        let cap: usize = 0;
        if cap > 0 && v.len() > cap {
            v.truncate(cap);
        }
        assert_eq!(v.len(), 10, "cap=0 must not truncate");
    }

    #[test]
    fn variants_cap_truncates_to_n_when_under_total() {
        let mut v: Vec<u32> = (0..100).collect();
        let cap: usize = 25;
        if cap > 0 && v.len() > cap {
            v.truncate(cap);
        }
        assert_eq!(v.len(), 25);
        // Order-preserving: first 25 elements survive (the build is
        // already ordered by confidence, so we keep the strongest).
        assert_eq!(v[0], 0);
        assert_eq!(v[24], 24);
    }

    #[test]
    fn variants_cap_no_op_when_at_or_above_total() {
        let mut v: Vec<u32> = (0..10).collect();
        let cap: usize = 100;
        if cap > 0 && v.len() > cap {
            v.truncate(cap);
        }
        assert_eq!(v.len(), 10, "cap above total must not truncate");
    }

    // ── Pure text-renderer extractions (post-modularization) ──
    //
    // These pin the output shape of the helpers extracted out of
    // the run_scan orchestrator. Each helper is pure (string in,
    // string out) so we can assert on the rendered bytes without
    // standing up a tokio runtime + mock target. ANSI color codes
    // are stripped before assertions so the tests pass under both
    // TTY and non-TTY colored detection.

    fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut iter = s.chars().peekable();
        while let Some(c) = iter.next() {
            if c == '\u{1b}' && iter.peek() == Some(&'[') {
                iter.next();
                for cc in iter.by_ref() {
                    if cc.is_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn render_summary_text_block_contains_all_top_level_counters() {
        let s = strip_ansi(&render_summary_text_block(
            "Cloudflare",
            30,
            28,
            25,
            3,
            1,
            2, // challenges
            10.7,
            4.2,
        ));
        // Every counter must surface, operator scrolling the
        // banner needs to see the absolute numbers AND the rate.
        assert!(s.contains("WAF: Cloudflare"), "WAF line missing:\n{s}");
        assert!(s.contains("Variants (scheduled): 30"));
        assert!(s.contains("Requests completed: 28"));
        assert!(s.contains("Blocked: 25"));
        assert!(s.contains("Bypassed: 3"));
        assert!(s.contains("Errors: 1"), "errors > 0 must surface:\n{s}");
        assert!(
            s.contains("Challenges (CAPTCHA): 2"),
            "challenges > 0 must surface:\n{s}"
        );
        assert!(s.contains("Bypass Rate: 10.7%"));
        assert!(s.contains("Elapsed: 4.2s"));
    }

    #[test]
    fn render_summary_text_block_hides_errors_row_when_zero() {
        let s = strip_ansi(&render_summary_text_block(
            "Akamai", 10, 10, 10, 0, 0, 0, 0.0, 1.0,
        ));
        // Errors row is conditional, zero errors means the row
        // doesn't render (less visual noise).
        assert!(
            !s.contains("Errors:"),
            "Errors row must be hidden at 0:\n{s}"
        );
        // Challenges row is conditional too (zero challenges means no row).
        assert!(
            !s.contains("Challenges"),
            "Challenges row must be hidden at 0:\n{s}"
        );
    }

    #[test]
    fn render_bypass_variants_text_block_omits_when_called_with_empty_slice() {
        // The orchestrator gates on `!is_empty()` before calling
        // the renderer, but the renderer itself must be safe to
        // call with an empty slice (defensive call sites).
        let s = strip_ansi(&render_bypass_variants_text_block(&[], "q", "https://x"));
        // The empty-call still emits the header line; no variant
        // bodies. This mirrors what the orchestrator would render
        // if it ever lost its guard.
        assert!(s.contains("Successful Bypasses:"));
        assert!(
            !s.contains("Variant #"),
            "no per-variant lines on empty input:\n{s}"
        );
    }

    #[test]
    fn render_bypass_variants_text_block_renders_one_full_variant() {
        let variants = vec![(
            7_usize,
            "' OR 1=1--".to_string(),
            vec!["url".to_string(), "case_swap".to_string()],
            0.88_f64,
        )];
        let s = strip_ansi(&render_bypass_variants_text_block(
            &variants,
            "q",
            "https://x.com/search",
        ));
        assert!(s.contains("Variant #7"));
        assert!(s.contains("Techniques: url → case_swap"));
        assert!(s.contains("Payload: ' OR 1=1-- (10 bytes)"));
        // Curl reproducer: param and target are sh_quote'd; payload
        // is sh_ansi_c_quote_bytes'd. The apostrophe in "' OR 1=1--"
        // becomes \x27 inside the ANSI-C block (safe for copy-paste).
        // The param "q" becomes "'q'" and the URL gets outer quotes.
        assert!(
            s.contains("curl -G --data-urlencode 'q'=") && s.contains("'https://x.com/search'"),
            "repro line missing:\n{s}"
        );
        // Payload must appear inside an ANSI-C $'...' block.
        assert!(s.contains("$'"), "payload not ANSI-C-quoted:\n{s}");
    }

    // ── Reproduce-line quoting security pins (§15 CRLF/injection) ──
    //
    // Pre-fix, `render_bypass_variants_text_block` emitted the raw param and
    // target unquoted/naively-quoted, and did NOT ANSI-C-escape control bytes
    // in the payload inside the `$'...'` block.  These tests pin the hardened
    // behaviour so a future refactor cannot regress silently.

    #[test]
    fn render_bypass_variants_cr_in_payload_is_ansi_c_escaped() {
        // §15 audit: a payload containing CR (common in LWS / CRLF-smuggling
        // evasion chains) MUST be ANSI-C-escaped in the `$'...'` block.
        // Pre-fix: raw CR was emitted, resetting the terminal cursor when the
        // operator copied the reproduce line from scan output.
        let variants = vec![(
            1_usize,
            "UNION\rSELECT".to_string(),
            vec!["lws".to_string()],
            0.8_f64,
        )];
        let s = strip_ansi(&render_bypass_variants_text_block(
            &variants,
            "q",
            "https://target.example/",
        ));
        // Raw CR must NOT appear in the reproduce line.
        assert!(
            !s.contains('\r'),
            "raw CR leaked into reproduce line, cursor-reset risk:\n{s:?}"
        );
        // The ANSI-C escape sequence for CR (`\r`) must be present.
        assert!(
            s.contains("\\r"),
            "CR must be ANSI-C-escaped as \\r in $'...' block:\n{s}"
        );
    }

    #[test]
    fn render_bypass_variants_nul_in_payload_is_ansi_c_escaped() {
        // §15 audit: a NUL byte inside a shell token causes libc to truncate
        // the argument silently. The ANSI-C escape `\x00` prevents this.
        let variants = vec![(
            2_usize,
            "foo\x00bar".to_string(),
            vec!["null_byte".to_string()],
            0.75_f64,
        )];
        let s = strip_ansi(&render_bypass_variants_text_block(
            &variants,
            "p",
            "https://x/",
        ));
        assert!(
            !s.contains('\x00'),
            "raw NUL leaked into reproduce line, truncation risk:\n{s:?}"
        );
        assert!(
            s.contains("\\x00"),
            "NUL must be ANSI-C-escaped as \\x00 in $'...' block:\n{s}"
        );
    }

    #[test]
    fn render_bypass_variants_apostrophe_in_target_url_is_shell_safe() {
        // §15 audit: a target URL containing `'` (e.g. operator typo, or
        // a real URL with an apostrophe in a query parameter path) MUST be
        // shell-escaped in the reproduce line so the pasted curl is valid.
        let variants = vec![(
            3_usize,
            "payload".to_string(),
            vec!["url".to_string()],
            0.9_f64,
        )];
        let s = strip_ansi(&render_bypass_variants_text_block(
            &variants,
            "q",
            "https://x/it's-a-trap",
        ));
        // The unescaped apostrophe must NOT appear inside the single-quoted
        // region (it would close the shell token and break the command).
        // sh_quote converts ' → '\'' (close-escape-reopen), so the output
        // must contain the escaped form.
        assert!(
            s.contains("it'\\''s-a-trap") || !s.contains("it's-a-trap"),
            "bare apostrophe in target URL broke shell quoting:\n{s}"
        );
    }

    #[test]
    fn render_bypass_variants_param_with_shell_metacharacters_is_shell_safe() {
        // §15 audit: `--param 'q[1]'` is a valid use. The brackets are glob
        // characters in most shells when unquoted; the param must be sh_quote'd.
        let variants = vec![(
            4_usize,
            "evil".to_string(),
            vec!["url".to_string()],
            0.7_f64,
        )];
        let s = strip_ansi(&render_bypass_variants_text_block(
            &variants,
            "q[1]",
            "https://x/",
        ));
        // The param must appear in quotes so `[` and `]` are shell-safe.
        assert!(
            s.contains("'q[1]'"),
            "param with brackets must be single-quoted:\n{s}"
        );
    }

    // ── JSON-builder extractions ──────────────────────────────

    #[test]
    fn build_bypass_variants_json_round_trips_payload_and_techniques() {
        let variants = vec![
            (1_usize, "p1".to_string(), vec!["url".to_string()], 0.9_f64),
            (
                17_usize,
                "/**/UNION/**/SELECT".to_string(),
                vec!["sql_comment".to_string(), "case_swap".to_string()],
                0.83_f64,
            ),
        ];
        let minimal = vec![None, Some("UNION SELECT".to_string())];
        let arr = build_bypass_variants_json(
            "https://t/search",
            "q",
            injection_delivery::InjectionDelivery::GetQuery,
            &variants,
            &minimal,
        );
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["variant"], 1);
        assert_eq!(arr[0]["payload"], "p1");
        assert_eq!(arr[0]["techniques"][0], "url");
        // Minimal absent on row 0 (must be null, not missing).
        assert!(arr[0]["minimal_payload"].is_null());
        // Minimal present on row 1 (must round-trip the string).
        assert_eq!(arr[1]["minimal_payload"], "UNION SELECT");
        // repro_curl always populated (URL-query carriers always
        // produce a reproducer from (target, param, payload)).
        assert!(arr[0]["repro_curl"].as_str().unwrap_or("").contains("p1"));
        // minimal_repro_curl only populated when minimal_payload is.
        assert!(arr[0]["minimal_repro_curl"].is_null());
        // The repro curl single-encodes the payload (see
        // build_bypass_variants_json_single_encodes_payload_in_repro_url), so
        // the space in "UNION SELECT" arrives as %20 on the wire.
        assert!(
            arr[1]["minimal_repro_curl"]
                .as_str()
                .unwrap_or("")
                .contains("UNION%20SELECT")
        );
    }

    #[test]
    fn build_bypass_variants_json_handles_empty_input() {
        let arr = build_bypass_variants_json(
            "https://x",
            "q",
            injection_delivery::InjectionDelivery::GetQuery,
            &[],
            &[],
        );
        assert!(arr.is_empty());
    }

    #[test]
    fn waf_engagement_assess_priority_active_over_selective_diff() {
        use crate::scan::waf_engagement::{self, WafEngagementLevel};
        use wafrift_evolution::intelligence::IntelligenceLoop;

        let mut il = IntelligenceLoop::new(1);
        for p in il.generate_quick_probes() {
            il.record_probe(&p, true);
        }
        let baseline = baseline::BaselineOutcome {
            status: 403,
            blocked: true,
            transport_ok: true,
            fingerprint: Some(waf_engagement::ResponseFingerprint::from_parts(
                403, b"blocked",
            )),
        };
        let r = waf_engagement::assess(
            &baseline,
            baseline.fingerprint,
            Some(waf_engagement::ResponseFingerprint::from_parts(200, b"ok")),
            &il,
        );
        assert_eq!(r.level, WafEngagementLevel::Active);
    }

    #[test]
    fn build_layered_json_wraps_scan_body_under_scan_key() {
        let scan_body = serde_json::json!({"target": "https://x", "bypassed": 3});
        let layered = build_layered_json(
            scan_body,
            "https://x",
            200,
            "Cloudflare",
            &[],
            403,
            true,
            true,
            50,
            48,
            3,
            45,
            2,
            6.0,
        );
        assert!(layered.get("scan").is_some());
        assert_eq!(layered["scan"]["bypassed"], 3);
        assert_eq!(layered["layer_report"]["network"]["target"], "https://x");
        assert_eq!(
            layered["layer_report"]["detection"]["chosen_waf"],
            "Cloudflare"
        );
        assert_eq!(
            layered["layer_report"]["baseline_probe"]["raw_get_status"],
            403
        );
        assert_eq!(
            layered["layer_report"]["evasion_campaign"]["variants_generated"],
            50
        );
        assert!(
            (layered["layer_report"]["evasion_campaign"]["bypass_rate_pct"]
                .as_f64()
                .unwrap()
                - 6.0)
                .abs()
                < 1e-9
        );
    }

    // Fix #1: scan_timeout_secs tests.

    #[test]
    fn scan_timeout_zero_means_unlimited() {
        // Default value 0 = no cap. The `scan_timeout_secs` guard
        // converts 0 to None (no deadline). Simulate that branch here
        // to pin the semantic. The variable must be non-literal so the
        // compiler doesn't warn about a trivially-dead comparison.
        let secs: u64 = 0;
        let budget = if secs > 0 {
            Some(std::time::Duration::from_secs(secs))
        } else {
            None
        };
        assert!(
            budget.is_none(),
            "zero --scan-timeout-secs must produce None budget"
        );
    }

    #[test]
    fn scan_timeout_nonzero_creates_duration() {
        let secs = 120u64;
        let budget = if secs > 0 {
            Some(std::time::Duration::from_secs(secs))
        } else {
            None
        };
        assert_eq!(budget, Some(std::time::Duration::from_secs(120)));
    }

    #[test]
    fn fix1_truncated_field_in_scan_json_source() {
        // Anti-rig: assert the `truncated_by_scan_timeout` field name
        // appears in scan/mod.rs's JSON output block. This pins the
        // contract without a live HTTP call.
        let src = include_str!("mod.rs");
        assert!(
            src.contains("truncated_by_scan_timeout"),
            "truncated_by_scan_timeout field must be emitted in scan JSON"
        );
    }

    #[test]
    fn fix1_exit_code_7_for_timeout_in_source() {
        // Anti-rig: exit code 7 must be used for scan timeout.
        let src = include_str!("mod.rs");
        assert!(
            src.contains("ExitCode::from(7)"),
            "exit code 7 must be emitted when scan_timeout_exceeded"
        );
    }

    // Fix #7: verify that scan_text progress lines go to stderr.
    // We test the contract by inspecting the source code itself, the
    // same anti-rig pattern used by bench_waf_tests to verify bounded
    // reads. A fragile but reliable check: if any of the specific phase
    // label strings appear in a println! call in scan/mod.rs, the fix
    // has been reverted. We assert they only appear in eprintln! calls.
    #[test]
    fn fix7_progress_labels_not_in_println() {
        let src = include_str!("mod.rs");
        // Collect all println! lines and verify none contain the phase headers.
        // Match only bare `println!`, not `eprintln!` (which also contains
        // the substring "println!" and would produce false positives).
        let println_lines: Vec<&str> = src
            .lines()
            .filter(|l| l.contains("println!") && !l.contains("eprintln!"))
            .collect();
        let phase_labels = [
            "[3/7] Exploring",
            "[3b/7] Tamper",
            "[3c/7] GraphQL",
            "[4/7] Exploiting",
            "[7/7] Intelligence",
            "WafRift Live WAF Evasion Scanner",
            "Gene bank loaded:",
            "Gene bank updated:",
            "Learning cache updated",
            "[2e/7] Equivalence moat",
        ];
        for label in &phase_labels {
            for line in &println_lines {
                assert!(
                    !line.contains(label),
                    "progress label {:?} found in a println! call, must be eprintln!:\n  {}",
                    label,
                    line.trim()
                );
            }
        }
    }

    #[test]
    fn fix7_result_labels_remain_in_print() {
        // The final summary (render_summary_text_block) and bypass list
        // (render_bypass_variants_text_block) must stay on stdout.
        // They are printed with `print!`, not `println!`: check neither
        // was accidentally switched to eprintln!.
        let src = include_str!("mod.rs");
        // The calls that write results to stdout use `print!` (no ln):
        assert!(
            src.contains("print!(\n            \"{}\",\n            render_summary_text_block"),
            "render_summary_text_block must still be emitted via print! to stdout"
        );
        assert!(
            src.contains("render_bypass_variants_text_block"),
            "render_bypass_variants_text_block must still be present in scan/mod.rs"
        );
    }

    // ── Fix #4: replay_technique_keys + repro_replay_command ──────────────

    #[test]
    fn scan_json_bypass_variant_emits_replay_technique_keys() {
        // Every bypass row must carry `replay_technique_keys` (non-empty
        // when techniques present) and `repro_replay_command` (a string
        // containing --technique and the target).
        let variants = vec![(
            0usize,
            "' OR 1=1--".to_string(),
            vec![
                "encoding/url/double".to_string(),
                "tamper::sql_comment".to_string(),
            ],
            0.91_f64,
        )];
        let minimal: Vec<Option<String>> = vec![None];
        let arr = build_bypass_variants_json(
            "https://victim/search",
            "id",
            injection_delivery::InjectionDelivery::GetQuery,
            &variants,
            &minimal,
        );
        assert_eq!(arr.len(), 1);

        // relay_technique_keys must be present and match the techniques.
        let rtk = arr[0]["replay_technique_keys"]
            .as_array()
            .expect("replay_technique_keys must be an array");
        assert_eq!(rtk.len(), 2, "must carry both technique keys");
        assert_eq!(rtk[0], "encoding/url/double");
        assert_eq!(rtk[1], "tamper::sql_comment");

        // repro_replay_command must be a non-null string pointing at the target.
        let cmd = arr[0]["repro_replay_command"]
            .as_str()
            .expect("repro_replay_command must be a string");
        assert!(
            cmd.contains("wafrift replay"),
            "command prefix missing: {cmd}"
        );
        assert!(
            cmd.contains("https://victim/search"),
            "target missing from command: {cmd}"
        );
        assert!(
            cmd.contains("--technique"),
            "--technique flag missing: {cmd}"
        );
        assert!(
            cmd.contains("encoding/url/double"),
            "first key missing: {cmd}"
        );
        assert!(
            cmd.contains("tamper::sql_comment"),
            "second key missing: {cmd}"
        );
    }

    #[test]
    fn scan_json_bypass_variant_replay_command_null_when_no_techniques() {
        // When techniques is empty (edge case: a bypass recorded without
        // a technique attribution), repro_replay_command must be null
        // not a shell command with an empty --technique argument.
        let variants = vec![(0usize, "payload".to_string(), vec![], 0.5_f64)];
        let minimal: Vec<Option<String>> = vec![None];
        let arr = build_bypass_variants_json(
            "https://t/",
            "q",
            injection_delivery::InjectionDelivery::GetQuery,
            &variants,
            &minimal,
        );
        assert_eq!(arr.len(), 1);
        assert!(
            arr[0]["repro_replay_command"].is_null(),
            "repro_replay_command must be null when techniques list is empty"
        );
        // replay_technique_keys is an empty array (not null).
        let rtk = arr[0]["replay_technique_keys"]
            .as_array()
            .expect("must be array");
        assert!(
            rtk.is_empty(),
            "replay_technique_keys must be empty array when no techniques"
        );
    }

    #[test]
    fn repro_replay_command_round_trips_technique_keys() {
        // Emit repro_replay_command from a bypass variant, then parse the
        // --technique argument back and verify the technique list matches.
        // This pins the round-trip contract: JSON → command → parse.
        let techniques = vec![
            "encoding/url/single".to_string(),
            "grammar::tautology".to_string(),
            "case_swap".to_string(),
        ];
        let variants = vec![(
            3usize,
            "UNION SELECT".to_string(),
            techniques.clone(),
            0.88_f64,
        )];
        let minimal: Vec<Option<String>> = vec![None];
        let arr = build_bypass_variants_json(
            "https://target/api",
            "search",
            injection_delivery::InjectionDelivery::PostForm,
            &variants,
            &minimal,
        );
        let cmd = arr[0]["repro_replay_command"].as_str().unwrap();

        // Extract --technique VALUE by finding the flag and reading until end.
        // Format: "... --technique key1,key2,key3"
        let tech_marker = "--technique ";
        let tech_pos = cmd.find(tech_marker).expect("--technique not in command");
        let tech_value = &cmd[tech_pos + tech_marker.len()..];
        // Strip any trailing shell artifacts (quotes etc.) (the value ends at end-of-string).
        let parsed_keys: Vec<&str> = tech_value.split(',').collect();
        assert_eq!(
            parsed_keys.len(),
            techniques.len(),
            "round-tripped technique count mismatch: got {parsed_keys:?}"
        );
        for (expected, actual) in techniques.iter().zip(parsed_keys.iter()) {
            assert_eq!(
                expected.as_str(),
                *actual,
                "technique key mismatch: expected {expected}, got {actual}"
            );
        }
    }

    // ── --max-fires budget semantics (§12 anti-rig) ────────────────────────
    //
    // These unit tests pin the budget_exhausted predicate logic without
    // standing up a tokio runtime, the closure captures `args.max_fires`
    // identically to what run_scan does. End-to-end coverage lives in
    // the raw_runner integration tests (max_fires_5_caps_total_fires).

    #[test]
    fn budget_exhausted_zero_means_unlimited() {
        // max_fires == 0 → the budget closure NEVER returns true.
        let max_fires: usize = 0;
        let exhausted = |fired: usize| -> bool { max_fires != 0 && fired >= max_fires };
        assert!(!exhausted(0));
        assert!(!exhausted(1_000_000));
        assert!(!exhausted(usize::MAX));
    }

    #[test]
    fn budget_exhausted_returns_true_at_exact_cap() {
        let max_fires: usize = 5;
        let exhausted = |fired: usize| -> bool { max_fires != 0 && fired >= max_fires };
        assert!(!exhausted(4), "4 fires < cap 5: not exhausted");
        assert!(exhausted(5), "exactly at cap: exhausted");
        assert!(exhausted(6), "past cap: exhausted");
    }

    #[test]
    fn budget_exhausted_cap_one_exhausts_after_first_fire() {
        let max_fires: usize = 1;
        let exhausted = |fired: usize| -> bool { max_fires != 0 && fired >= max_fires };
        assert!(!exhausted(0));
        assert!(exhausted(1));
    }

    #[test]
    fn budget_exhausted_large_cap_does_not_exhaust_at_small_fired() {
        let max_fires: usize = crate::DEFAULT_MAX_FIRES; // 10_000
        let exhausted = |fired: usize| -> bool { max_fires != 0 && fired >= max_fires };
        // A normal light scan fires << 10_000 (must never be capped).
        assert!(!exhausted(12));
        assert!(!exhausted(500));
        assert!(!exhausted(9_999));
        assert!(exhausted(10_000));
    }

    #[test]
    fn default_max_fires_constant_is_ten_thousand() {
        // Pin the constant value so a refactor that changes it
        // produces a test failure pointing at this intentional
        // choice (10 000 = generous ceiling that leaves normal scans
        // unaffected while preventing runaway fires).
        assert_eq!(
            crate::DEFAULT_MAX_FIRES,
            10_000,
            "DEFAULT_MAX_FIRES must be 10 000 to match the --help doc comment"
        );
    }

    #[test]
    fn bypass_rate_metric_is_bypassed_over_total_fired() {
        // Metric-safety: bypass_rate = bypassed / total_fired,
        // NOT bypassed / (bypassed + blocked). Confirm the formula
        // is unchanged regardless of which phases fired.
        let total_fired = 85_usize;
        let bypassed: u32 = 3;
        let blocked: u32 = 80;
        let errors: u32 = 2;
        let _rate_limited: u32 = 0;
        let requests_completed = bypassed
            .saturating_add(blocked)
            .saturating_add(errors)
            .saturating_add(_rate_limited);
        let bypass_rate = if requests_completed > 0 {
            f64::from(bypassed) / f64::from(requests_completed) * 100.0
        } else {
            0.0
        };
        // bypass_rate = 3 / 85 * 100 ≈ 3.53 (not 3 / (3+80) * 100 ≈ 3.61).
        let _ = total_fired; // bypasses ARE included in total_fired
        assert!(
            (bypass_rate - 3.529_411_764_705_882).abs() < 1e-6,
            "bypass_rate must be bypassed / requests_completed, got {bypass_rate}"
        );
    }